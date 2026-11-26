"""Wave A — the customer-cloud-posture MINT seam + the sovereign orchestrator that gates it.

Proves (against real code, not mocks of our own units):

  * ``AwsStsConnectFetcher.mint_read_only_session`` re-``AssumeRole``s the customer's read-only role under VIGIL's
    connector identity and returns a SHORT-LIVED read-only ``MintedSession`` carrying real STS temp credentials —
    and fails CLOSED on a role that no longer trusts VIGIL (AccessDenied → reconnect), on account drift (the role
    was re-pointed at another account), and on a non-aws target;
  * the minted session never renders a secret in ``repr`` (no credential in a log / trace / error);
  * ``governor.cloud_posture_launch.open_posture_session`` enforces the fail-closed order
    default-deny grant → ``VIGIL_CUSTOMER_PROD_EXECUTION`` owner gate → Cloudflare-stored-grant refusal → mint,
    returning a usable session ONLY when every rung passes.

The STS transport is a FAKE that answers ``AssumeRole`` / ``GetCallerIdentity`` by Action (it ignores the SigV4
signature — we test the mint's decision logic + the account-drift guard, not the signer, which
``test_cloud_fetch.py`` already covers end-to-end through the real ``FakeSts``)."""
from __future__ import annotations

from urllib.parse import parse_qs

import pytest

from sigil.governor.cloud_connect import CloudAssumeTarget
from sigil.governor.cloud_posture_launch import PostureDenied, open_posture_session
from sigil.ui.cloud_fetch import AwsStsConnectFetcher, CloudFetchError
from vigil_core.cloud_session import MintedSession

ACCT = "123456789012"
OTHER = "999999999999"
ROLE = f"arn:aws:iam::{ACCT}:role/VigilSecurityAudit"
EXT = "EXT-GRANT-0001"
_NS = "https://sts.amazonaws.com/doc/2011-06-15/"
_CLOCK = 1_000_000.0
_FRESH_UNTIL = _CLOCK + 900.0  # _DURATION_S


def _assume_xml() -> bytes:
    return (f'<AssumeRoleResponse xmlns="{_NS}"><AssumeRoleResult><Credentials>'
            f"<AccessKeyId>ASIATEMPKEY</AccessKeyId><SecretAccessKey>temp-secret-value</SecretAccessKey>"
            f"<SessionToken>temp-session-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration>"
            f"</Credentials></AssumeRoleResult></AssumeRoleResponse>").encode()


def _caller_xml(account: str) -> bytes:
    return (f'<GetCallerIdentityResponse xmlns="{_NS}"><GetCallerIdentityResult>'
            f"<Account>{account}</Account><Arn>arn:aws:sts::{account}:assumed-role/x/y</Arn>"
            f"</GetCallerIdentityResult></GetCallerIdentityResponse>").encode()


def _err_xml(code: str) -> bytes:
    return (f'<ErrorResponse xmlns="{_NS}"><Error><Type>Sender</Type><Code>{code}</Code>'
            f"<Message>m</Message></Error></ErrorResponse>").encode()


class _FakeSts:
    """Answers AssumeRole + GetCallerIdentity by Action. ``accept_ext``: external ids the role's trust policy allows;
    ``lands_in``: the account the temp creds report back (set it to another account to simulate a re-pointed role)."""

    def __init__(self, *, accept_ext: tuple[str, ...] = (EXT,), lands_in: str = ACCT) -> None:
        self.accept_ext, self.lands_in = accept_ext, lands_in

    def __call__(self, url, headers, body, timeout):
        form = {k: v[0] for k, v in parse_qs(bytes(body).decode()).items()}
        action = form.get("Action")
        if action == "AssumeRole":
            if form.get("ExternalId") not in self.accept_ext:
                return 403, _err_xml("AccessDenied")
            return 200, _assume_xml()
        if action == "GetCallerIdentity":
            return 200, _caller_xml(self.lands_in)
        return 400, _err_xml("InvalidAction")


def _fetcher(sts: _FakeSts) -> AwsStsConnectFetcher:
    return AwsStsConnectFetcher(access_key_id="AKIA" + "0" * 16, secret_access_key="s" * 40,
                                transport=sts, clock=lambda: _CLOCK)


def _target(*, provider: str = "aws", account_id: str = ACCT, role_ref: str = ROLE,
            external_id: str = EXT) -> CloudAssumeTarget:
    return CloudAssumeTarget(org_id="acme", provider=provider, account_id=account_id, role_ref=role_ref,
                             external_id=external_id, expires_at=9e9)


# --- the AWS re-mint: happy path -----------------------------------------------------------------
def test_aws_mint_returns_a_scoped_short_lived_read_only_session() -> None:
    s = _fetcher(_FakeSts()).mint_read_only_session(_target(), now=_CLOCK)
    assert isinstance(s, MintedSession)
    assert s.provider == "aws" and s.account_id == ACCT
    assert s.access_key_id == "ASIATEMPKEY"
    assert s.secret_access_key == "temp-secret-value"
    assert s.session_token == "temp-session-token"
    assert s.has_credential()
    assert s.is_fresh(_CLOCK) and not s.is_fresh(_FRESH_UNTIL)  # expires at clock()+900, exclusive


def test_aws_minted_session_never_renders_a_secret() -> None:
    s = _fetcher(_FakeSts()).mint_read_only_session(_target(), now=_CLOCK)
    blob = repr(s)
    assert "temp-secret-value" not in blob
    assert "temp-session-token" not in blob
    assert "ASIATEMPKEY" not in blob


# --- the AWS re-mint: fail-closed rungs ----------------------------------------------------------
def test_aws_mint_fails_closed_when_the_role_no_longer_trusts_vigil() -> None:
    with pytest.raises(CloudFetchError, match="reconnect"):
        _fetcher(_FakeSts(accept_ext=())).mint_read_only_session(_target(), now=_CLOCK)


def test_aws_mint_fails_closed_on_account_drift() -> None:
    # the role still assumes, but the temp creds land in a DIFFERENT account than the grant claims → refuse.
    with pytest.raises(CloudFetchError, match="different AWS account"):
        _fetcher(_FakeSts(lands_in=OTHER)).mint_read_only_session(_target(account_id=ACCT), now=_CLOCK)


def test_aws_mint_refuses_a_non_aws_target() -> None:
    with pytest.raises(CloudFetchError):
        _fetcher(_FakeSts()).mint_read_only_session(_target(provider="gcp"), now=_CLOCK)


def test_aws_mint_refuses_a_malformed_role_arn() -> None:
    with pytest.raises(CloudFetchError):
        _fetcher(_FakeSts()).mint_read_only_session(_target(role_ref="not-an-arn"), now=_CLOCK)


# --- the sovereign orchestrator: fail-closed order -----------------------------------------------
class _Registry:
    """A stand-in CloudConnectRegistry: ``assume_target`` returns a fixed grant (or None for default-deny)."""

    def __init__(self, target: CloudAssumeTarget | None) -> None:
        self._target = target

    def assume_target(self, org_id: str, provider: str, account_id: str, *, now: float):
        return self._target


def _mint_fetcher(aws: AwsStsConnectFetcher | None = None):
    return lambda prov: aws if prov == "aws" else None


_ON = {"VIGIL_CUSTOMER_PROD_EXECUTION": "1"}


def test_orchestrator_default_deny_without_an_active_grant() -> None:
    with pytest.raises(PostureDenied, match="no active read-only connection"):
        open_posture_session(registry=_Registry(None), mint_fetcher=_mint_fetcher(_fetcher(_FakeSts())),
                             org_id="acme", provider="aws", account_id=ACCT, now=_CLOCK, env=_ON)


def test_orchestrator_refuses_when_owner_gate_off() -> None:
    # a grant exists, but VIGIL_CUSTOMER_PROD_EXECUTION is not enabled → refuse BEFORE any mint.
    with pytest.raises(PostureDenied, match="not enabled"):
        open_posture_session(registry=_Registry(_target()), mint_fetcher=_mint_fetcher(_fetcher(_FakeSts())),
                             org_id="acme", provider="aws", account_id=ACCT, now=_CLOCK, env={})


def test_orchestrator_refuses_a_stored_grant_cloudflare_target() -> None:
    # Cloudflare's secret is never stored, so a stored grant cannot re-credential it: refuse, ask for a per-run token.
    cf = _target(provider="cloudflare", account_id="a" * 32, role_ref="b" * 32)
    with pytest.raises(PostureDenied, match="fresh read-only API token"):
        open_posture_session(registry=_Registry(cf), mint_fetcher=_mint_fetcher(), org_id="acme",
                             provider="cloudflare", account_id="a" * 32, now=_CLOCK, env=_ON)


def test_orchestrator_refuses_when_connector_not_provisioned() -> None:
    # grant + owner gate pass, provider is mintable, but no fetcher is wired for it → refuse.
    with pytest.raises(PostureDenied, match="not provisioned"):
        open_posture_session(registry=_Registry(_target()), mint_fetcher=_mint_fetcher(None), org_id="acme",
                             provider="aws", account_id=ACCT, now=_CLOCK, env=_ON)


def test_orchestrator_surfaces_a_mint_failure_as_posture_denied() -> None:
    # the grant is active and the gate is open, but the role no longer trusts VIGIL → PostureDenied, not a raw error.
    with pytest.raises(PostureDenied):
        open_posture_session(registry=_Registry(_target()),
                             mint_fetcher=_mint_fetcher(_fetcher(_FakeSts(accept_ext=()))), org_id="acme",
                             provider="aws", account_id=ACCT, now=_CLOCK, env=_ON)


def test_orchestrator_mints_an_aws_session_end_to_end() -> None:
    s = open_posture_session(registry=_Registry(_target()), mint_fetcher=_mint_fetcher(_fetcher(_FakeSts())),
                             org_id="acme", provider="aws", account_id=ACCT, now=_CLOCK, env=_ON)
    assert isinstance(s, MintedSession)
    assert s.provider == "aws" and s.account_id == ACCT
    assert s.has_credential() and s.is_fresh(_CLOCK)


# --- the MintedSession data contract (the FATAL-2 crossing object) -------------------------------
def test_minted_session_is_frozen() -> None:
    import dataclasses
    s = MintedSession(provider="aws", account_id=ACCT, expires_at=_FRESH_UNTIL,
                      access_key_id="k", secret_access_key="s", session_token="t")
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.account_id = OTHER  # type: ignore[misc]


def test_minted_session_rejects_a_non_mintable_provider() -> None:
    # Cloudflare is excluded by design — its secret is never stored, so it can never be re-minted from a grant.
    with pytest.raises(ValueError):
        MintedSession(provider="cloudflare", account_id=ACCT, bearer_token="x")
    with pytest.raises(ValueError):
        MintedSession(provider="", account_id=ACCT)


def test_minted_session_requires_an_account() -> None:
    with pytest.raises(ValueError):
        MintedSession(provider="aws", account_id="")


def test_minted_session_freshness_is_fail_closed() -> None:
    assert not MintedSession(provider="gcp", account_id="p", bearer_token="b").is_fresh(0.0)  # expiry 0 → never fresh
    live = MintedSession(provider="gcp", account_id="p", expires_at=100.0, bearer_token="b")
    assert live.is_fresh(99.999) and not live.is_fresh(100.0)


def test_minted_session_has_credential_per_provider() -> None:
    # AWS needs all three STS parts; a missing one is inert, never 'clean'.
    assert MintedSession(provider="aws", account_id=ACCT, access_key_id="k",
                         secret_access_key="s", session_token="t").has_credential()
    assert not MintedSession(provider="aws", account_id=ACCT, access_key_id="k",
                             secret_access_key="s").has_credential()  # no session_token
    # GCP / Azure need a bearer token.
    assert MintedSession(provider="gcp", account_id="proj", bearer_token="b").has_credential()
    assert MintedSession(provider="azure", account_id="sub", bearer_token="b").has_credential()
    assert not MintedSession(provider="azure", account_id="sub").has_credential()
