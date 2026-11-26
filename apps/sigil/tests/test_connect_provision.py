"""Consumer PR-C — the provisioner's unified connect actions, their admit gates, the automatic ownership RE-CHECK, the
cloud leg, and the SELF-RED-PEN.

Vault-backed harness (one persisted owner key throughout, faithful to production). Runs with the integration
PYTHONPATH (the authority broker lives in vigil_integration).

Load-bearing invariants:
  * the READS (overview, poll) are gated on ``view_assessments``; the WRITES (re-check, cloud challenge / verify /
    disconnect) on ``run_engagement`` — a billing-only ``org_admin`` is DENIED both (registering/paying != testing);
  * the overview says what THIS deployment can really do (``available``), shows the repo leg only to a requester the
    Code screen itself admits (``manage_code`` + Red-Pen on), and the cloud leg only while its flag is on;
  * the automatic re-check RUNS THE EXISTING ``target_verify`` (same fetch, verdict, proof and authority) at most once
    per (org, host) per 10 s (extra polls are answered from state, not fetched), within a per-org ceiling, only with
    the inline authorization affirmation, and FAILS CLOSED without its fetcher or limiters; a check that does not
    pass mints NOTHING, and a passing one flips the host to Verified without any other request;
  * the cloud challenge hands back the exact trust policy (VIGIL's principal + the external id); a correct
    observation with the negative control DENIED records an owner-signed READ-ONLY grant; a role that admits any
    external id (the confused deputy), a wrong account, or a fetcher failure records nothing; the leg fails closed
    until the owner provisions VIGIL's connector identity, and is absent while its own flag is off;
  * a half-finished cloud connection RESUMES (the same external id, no new challenge — a role already created keeps
    working) and is listed as pending; cancelling it retires the id; a stale step-up is refused BEFORE the re-check
    or the cloud verify spends a limiter slot or a fetch;
  * CROSS-TENANT isolation (org B cannot read or disconnect org A's grant) and CONNECT != OFFENSE (a cloud grant mints
    no EngagementAuthority, leaves the live-offense owner gate untouched, never unlocks a host launch).
"""
from __future__ import annotations

import itertools
import tempfile
import time

import pytest

from sigil.ui.provision import ProvisionDenied, ProvisionError, ProvisionRateLimited

_iss = itertools.count(1)
ACCT = "123456789012"
ROLE = "arn:aws:iam::123456789012:role/VigilReadOnly"
PRINCIPAL = "arn:aws:iam::111122223333:role/vigil-connector"
GCP_PROJECT = "my-company-prod"
GCP_CONNECTOR_SA = "vigil-connector@vigil-sovereign-prod.iam.gserviceaccount.com"
HOST = "app.acme-test.com"


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared authority seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")             # the PR-C surface ON
    monkeypatch.setenv("VIGIL_CUSTOMER_CLOUD_CONNECT", "1")       # ... and its cloud leg
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_GITHUB_APP_SLUG", raising=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)   # the live-offense owner gate stays OFF


class _StubCloudFetcher:
    """Stands in for ``ui.cloud_fetch.AwsStsConnectFetcher``: ``account_seen`` decides what GetCallerIdentity would
    return, ``control_denied`` what the negative control saw, ``error`` a failure to raise. Records each call."""

    def __init__(self, *, account_seen=None, control_denied=True, error=None):
        self.account_seen, self.control_denied, self.error = account_seen, control_denied, error
        self.calls: list = []

    def assume(self, *, provider, account_id, role_ref, external_id, control_external_id, now=None):
        self.calls.append({"external_id": external_id, "control_external_id": control_external_id, "role": role_ref})
        if self.error is not None:
            raise self.error
        return {"assumed_with_external_id": external_id,
                "account": self.account_seen if self.account_seen is not None else account_id,
                "control_external_id": control_external_id, "control_denied": self.control_denied}


class _StubGcpFetcher:
    """Stands in for ``ui.cloud_fetch.GcpImpersonationConnectFetcher`` (NAME-bound): it impersonates the
    challenge-named SA and reports ``{impersonated, expected_email, project, external_id}``. ``project_seen`` overrides
    the observed project, ``impersonated`` the 200 flag, ``error`` a failure to raise. Records each call (SAME
    ``assume`` signature as the AWS stub)."""

    def __init__(self, *, project_seen=None, impersonated=True, error=None):
        self.project_seen, self.impersonated, self.error = project_seen, impersonated, error
        self.calls: list = []

    def assume(self, *, provider, account_id, role_ref, external_id, control_external_id="", now=None):
        self.calls.append({"external_id": external_id, "role": role_ref})
        if self.error is not None:
            raise self.error
        from sigil.governor import cloud_connect as cc
        return {"impersonated": self.impersonated,
                "expected_email": cc._gcp_expected_sa_email(account_id, external_id),
                "project": self.project_seen if self.project_seen is not None else account_id,
                "external_id": external_id}


class _StubOwnershipFetcher:
    """Stands in for the trusted ownership reader: until ``published`` the token is not there (the fetcher's own
    404 wording); afterwards it returns exactly what the customer published for the CURRENT challenge."""

    def __init__(self, store, org):
        self.store, self.org, self.published, self.calls = store, org, False, []

    def fetch(self, method, host, *, now=None):
        from sigil.governor import asset_ownership as ao
        from sigil.ui.ownership_fetch import OwnershipFetchError
        self.calls.append((method, host))
        if not self.published:
            raise OwnershipFetchError("homepage returned HTTP 404")
        tok = ao.AssetOwnershipRegistry(self.store, owner_key=None).challenge(self.org, host).token
        if method == ao.METHOD_META_TAG:
            return "<html><head>" + ao.meta_tag(tok) + "</head></html>"
        if method == ao.METHOD_DNS_TXT:
            return ["unrelated", ao.expected_marker(tok)]
        return ao.expected_marker(tok)


def _limiter(max_fails, window):
    from sigil.ui.login_ratelimit import LoginRateLimiter
    return LoginRateLimiter(tempfile.mkdtemp(), max_fails=max_fails, window_s=window, base_lock_s=window,
                            max_lock_s=window)


def _prov(*, cloud_fetcher=None, principal=PRINCIPAL, gcp_fetcher=None, gcp_connector_sa=GCP_CONNECTOR_SA,
          target_fetcher=None, limiters=True, org_max=240, cloud_max=10):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    ensure_owner_keypair()
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    orgs = OrgRegistry(s)
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=orgs, wallet=WalletRegistry(s),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4, base_lock_s=1.0),
                    email_sender=NullEmailSender(), cloud_fetcher=cloud_fetcher, cloud_principal_arn=principal,
                    cloud_gcp_fetcher=gcp_fetcher,
                    cloud_gcp_connector_sa=(gcp_connector_sa if gcp_fetcher is not None else ""),
                    target_fetcher=target_fetcher,
                    connect_check_limiter=_limiter(1, 10.0) if limiters else None,
                    connect_org_limiter=_limiter(org_max, 3600.0) if limiters else None,
                    cloud_connect_limiter=_limiter(cloud_max, 600.0) if limiters else None,
                    now_fn=time.time)
    return p, s, orgs


def _seat(orgs, org, user, role):
    orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


def _connect_cloud(p, user, org, *, account=ACCT):
    p.cloud_connect_challenge(user, org, "aws", account)
    return p.cloud_connect_verify(user, org, "aws", account, ROLE)


# ---- admit gates ---------------------------------------------------------------------------------------------
def test_reads_need_view_assessments_writes_need_run_engagement():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_admin", "org_admin")     # billing admin: NO view_assessments, NO run_engagement
    for call in (
        lambda: p.customer_connect_overview("u_admin", "org_a"),
        lambda: p.customer_ownership_poll("u_admin", "org_a", HOST),
        lambda: p.customer_ownership_poll("u_admin", "org_a", HOST, recheck=True, authorized=True),
        lambda: p.cloud_connect_challenge("u_admin", "org_a", "aws", ACCT),
        lambda: p.cloud_disconnect("u_admin", "org_a", "aws", ACCT),
    ):
        with pytest.raises(ProvisionDenied):
            call()


# ---- the overview ----------------------------------------------------------------------------------------------
def test_overview_says_what_this_deployment_can_do():
    p, s, orgs = _prov()                              # nothing provisioned (no fetchers)
    _seat(orgs, "org_a", "u_f", "operator")
    ov = p.customer_connect_overview("u_f", "org_a")
    assert ov["org_id"] == "org_a" and ov["sites"] == [] and ov["cloud"] == [] and "repos" not in ov
    assert ov["available"] == {"site_check": False, "site_auto_recheck": False, "repos": False,
                               "repo_connect": False, "cloud_connect": False}
    p2, _, orgs2 = _prov(cloud_fetcher=_StubCloudFetcher(), target_fetcher=object())
    _seat(orgs2, "org_a", "u_f", "operator")
    av = p2.customer_connect_overview("u_f", "org_a")["available"]
    assert av["site_check"] is True and av["site_auto_recheck"] is True and av["cloud_connect"] is True
    p3, _, orgs3 = _prov(cloud_fetcher=_StubCloudFetcher(), target_fetcher=object(), limiters=False)
    _seat(orgs3, "org_a", "u_f", "operator")
    av = p3.customer_connect_overview("u_f", "org_a")["available"]
    assert av["site_check"] is True and av["site_auto_recheck"] is False and av["cloud_connect"] is False


def test_the_overview_has_no_cloud_leg_while_its_flag_is_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_CLOUD_CONNECT")
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    ov = p.customer_connect_overview("u_f", "org_a")
    assert "cloud" not in ov and ov["available"]["cloud_connect"] is False


def test_the_repo_leg_follows_the_code_screens_own_gate(monkeypatch):
    from sigil.governor.connected_repos import ConnectedRepoRegistry
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    ConnectedRepoRegistry(s).connect("org_a", 42, "github.com/acme/widgets", issued_at=float(next(_iss)))
    assert "repos" not in p.customer_connect_overview("u_f", "org_a")        # Red-Pen off: no repo leg at all
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    ov = p.customer_connect_overview("u_f", "org_a")
    assert [r["repo"] for r in ov["repos"]] == ["github.com/acme/widgets"]
    assert ov["available"]["repos"] is True and ov["available"]["repo_connect"] is False   # no GitHub App slug
    monkeypatch.setenv("VIGIL_GITHUB_APP_SLUG", "vigil-red-pen")
    assert p.customer_connect_overview("u_f", "org_a")["available"]["repo_connect"] is True


# ---- the single-host poll + the automatic re-check ---------------------------------------------------------------
def test_the_poll_read_resumes_a_half_finished_proof_and_auto_selects():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    p.target_challenge("u_f", "org_a", "acme-test.com")
    st = p.customer_ownership_poll("u_f", "org_a", "acme-test.com")
    assert st["status"] == "pending" and st["selected_method"] == "dns-txt" and set(st["methods"]) == {
        "meta-tag", "dns-txt", "well-known"}
    assert "checked" not in st                         # a read: nothing was checked


def test_the_recheck_runs_the_existing_verify_on_a_cadence_and_flips_to_verified():
    from sigil.governor.asset_ownership import AssetOwnershipRegistry
    from sigil.ui.target_authorization import list_targets
    p, s, orgs = _prov()
    fetcher = _StubOwnershipFetcher(s, "org_a")
    p.target_fetcher = fetcher
    _seat(orgs, "org_a", "u_f", "operator")
    p.target_challenge("u_f", "org_a", HOST)
    t0 = time.time()
    r1 = p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True, now=t0)
    assert r1["status"] == "pending" and r1["checked"]["ran"] is True and r1["checked"]["ok"] is False
    assert "HTTP 404" in r1["checked"]["reason"] and r1["recheck"]["next_in"] == 10.0
    assert fetcher.calls == [("meta-tag", HOST)]                # the auto-selected method (a subdomain: meta tag)
    assert AssetOwnershipRegistry(s, owner_key=None).proof("org_a", HOST) is None   # a failed check mints NOTHING
    assert list_targets()["targets"] == []
    # a second poll inside the window is answered from state — no fetch
    r2 = p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True, now=t0 + 1)
    assert r2["checked"] == {"ran": False, "deferred": True} and 0 < r2["recheck"]["next_in"] <= 10
    assert len(fetcher.calls) == 1
    # the customer publishes; the next poll after the window verifies — the proof AND the target authority exist
    fetcher.published = True
    r3 = p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True, now=t0 + 11)
    assert r3["status"] == "verified" and r3["checked"] == {"ran": True, "ok": True, "method": "meta-tag"}
    assert AssetOwnershipRegistry(s, owner_key=None).has_current_proof("org_a", HOST, now=t0 + 12)
    assert len(list_targets()["targets"]) == 1
    # verified: nothing left to check, no further fetch
    r4 = p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True, now=t0 + 30)
    assert r4["checked"] == {"ran": False} and len(fetcher.calls) == 2


def test_the_recheck_uses_the_method_the_customer_picked():
    p, s, orgs = _prov()
    fetcher = _StubOwnershipFetcher(s, "org_a")
    fetcher.published = True
    p.target_fetcher = fetcher
    _seat(orgs, "org_a", "u_f", "operator")
    p.target_challenge("u_f", "org_a", HOST)
    r = p.customer_ownership_poll("u_f", "org_a", HOST, method="well-known", recheck=True, authorized=True)
    assert r["status"] == "verified" and fetcher.calls == [("well-known", HOST)]
    p.target_challenge("u_f", "org_a", "other.acme-test.com")              # pending: a method now matters
    with pytest.raises(ProvisionDenied, match="method must be"):
        p.customer_ownership_poll("u_f", "org_a", "other.acme-test.com", method="ftp", recheck=True,
                                  authorized=True)
    assert len(fetcher.calls) == 1                                           # refused before any fetch


def test_the_recheck_needs_the_affirmation_and_never_fetches_without_it():
    p, s, orgs = _prov()
    fetcher = _StubOwnershipFetcher(s, "org_a")
    p.target_fetcher = fetcher
    _seat(orgs, "org_a", "u_f", "operator")
    p.target_challenge("u_f", "org_a", HOST)
    with pytest.raises(ProvisionDenied, match="authorized"):
        p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=False)
    assert fetcher.calls == []


def test_a_stale_step_up_is_refused_before_the_recheck_spends_its_window(monkeypatch):
    # with step-up enforcement on, target_verify demands a fresh second factor; the re-check must ask for it BEFORE it
    # charges the per-host cadence (else the step-up's one retry would land inside the window and check nothing)
    from sigil.ui.provision import ProvisionStepUpRequired
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    p, s, orgs = _prov(org_max=1)
    fetcher = _StubOwnershipFetcher(s, "org_a")
    fetcher.published = True
    p.target_fetcher = fetcher
    _seat(orgs, "org_a", "u_f", "operator")
    p.target_challenge("u_f", "org_a", HOST)
    t0 = time.time()
    with pytest.raises(ProvisionStepUpRequired):
        p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True, mfa_at=0.0, now=t0)
    assert fetcher.calls == []
    r = p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True, mfa_at=t0, now=t0 + 1)
    assert r["status"] == "verified" and r["checked"]["ok"] is True and len(fetcher.calls) == 1


def test_the_recheck_fails_closed_without_its_fetcher_or_limiters():
    p, s, orgs = _prov()                               # no ownership fetcher
    _seat(orgs, "org_a", "u_f", "operator")
    p.target_challenge("u_f", "org_a", HOST)
    with pytest.raises(ProvisionError, match="not enabled"):
        p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True)
    p2, s2, orgs2 = _prov(limiters=False)
    fetcher = _StubOwnershipFetcher(s2, "org_a")
    p2.target_fetcher = fetcher
    _seat(orgs2, "org_a", "u_f", "operator")
    p2.target_challenge("u_f", "org_a", HOST)
    with pytest.raises(ProvisionError, match="automatic re-checking is not enabled"):
        p2.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True)
    assert fetcher.calls == []                         # an unwired limiter never means "unlimited"


def test_the_per_org_ceiling_bounds_fetches_across_hosts():
    p, s, orgs = _prov(org_max=1)
    fetcher = _StubOwnershipFetcher(s, "org_a")
    p.target_fetcher = fetcher
    _seat(orgs, "org_a", "u_f", "operator")
    for h in (HOST, "b.acme-test.com"):
        p.target_challenge("u_f", "org_a", h)
    t0 = time.time()
    p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True, now=t0)
    with pytest.raises(ProvisionRateLimited):
        p.customer_ownership_poll("u_f", "org_a", "b.acme-test.com", recheck=True, authorized=True, now=t0 + 1)
    assert len(fetcher.calls) == 1


def test_a_recheck_with_nothing_to_check_runs_nothing():
    p, s, orgs = _prov()
    fetcher = _StubOwnershipFetcher(s, "org_a")
    p.target_fetcher = fetcher
    _seat(orgs, "org_a", "u_f", "operator")
    assert p.customer_ownership_poll("u_f", "org_a", HOST, recheck=True, authorized=True)["checked"] == {"ran": False}
    bad = p.customer_ownership_poll("u_f", "org_a", "https://x", recheck=True, authorized=True)
    assert bad["status"] == "invalid" and bad["checked"] == {"ran": False}
    assert fetcher.calls == []


def test_the_poll_is_a_pure_read_and_mints_nothing():
    from sigil.governor.asset_ownership import AssetOwnershipRegistry
    from sigil.ui.target_authorization import list_targets
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    p.customer_ownership_poll("u_f", "org_a", "apme.cm")
    p.customer_ownership_poll("u_f", "org_a", "apme.cm")
    assert AssetOwnershipRegistry(s, owner_key=None).proof("org_a", "apme.cm") is None
    assert AssetOwnershipRegistry(s, owner_key=None).challenge("org_a", "apme.cm") is None
    assert list_targets()["targets"] == []


# ---- the cloud leg -----------------------------------------------------------------------------------------------
def test_the_cloud_challenge_hands_back_the_exact_trust_policy():
    import json
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    assert ch["provider"] == "aws" and ch["account_id"] == ACCT and ch["principal_arn"] == PRINCIPAL
    stmt = json.loads(ch["trust_policy"])["Statement"][0]
    assert stmt["Principal"] == {"AWS": PRINCIPAL}
    assert stmt["Condition"] == {"StringEquals": {"sts:ExternalId": ch["external_id"]}}
    assert ch["permissions_policy_arn"] == "arn:aws:iam::aws:policy/SecurityAudit"


def test_cloud_challenge_then_verify_records_a_read_only_grant():
    f = _StubCloudFetcher()
    p, s, orgs = _prov(cloud_fetcher=f)
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    res = p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    assert res["access"] == "read-only" and res["role_ref"] == ROLE
    (call,) = f.calls
    assert call["external_id"] == ch["external_id"] and call["control_external_id"] not in ("", ch["external_id"])
    ov = p.customer_connect_overview("u_f", "org_a")
    assert [(c["provider"], c["account_id"], c["status"]) for c in ov["cloud"]] == [("aws", ACCT, "connected")]


def _challenge_records(s) -> int:
    from sigil.governor.cloud_connect import CHALLENGE_SIGNAL
    return sum(1 for r in s.iter_records() if isinstance(r.payload, dict) and r.payload.get("signal") == CHALLENGE_SIGNAL)


def test_starting_again_resumes_so_a_role_already_created_keeps_working():
    # the customer created the role with the first trust policy, then reloaded / came back later and pressed Connect
    # again: they get the SAME external id (no new challenge), so the role they made verifies without an edit
    f = _StubCloudFetcher()
    p, s, orgs = _prov(cloud_fetcher=f)
    _seat(orgs, "org_a", "u_f", "operator")
    first = p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    assert first["resumed"] is False and _challenge_records(s) == 1
    assert p.customer_connect_overview("u_f", "org_a")["cloud"] == [
        {"provider": "aws", "account_id": ACCT, "access": "read-only", "status": "pending"}]   # Continue, not lost
    again = p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    assert again["resumed"] is True and _challenge_records(s) == 1
    assert (again["external_id"], again["trust_policy"]) == (first["external_id"], first["trust_policy"])
    p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    assert f.calls[-1]["external_id"] == first["external_id"]
    assert [c["status"] for c in p.customer_connect_overview("u_f", "org_a")["cloud"]] == ["connected"]


def test_cancelling_a_half_finished_connection_retires_its_external_id():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    first = p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    assert p.cloud_disconnect("u_f", "org_a", "aws", ACCT) == {"provider": "aws", "account_id": ACCT,
                                                               "disconnected": False, "cancelled": True}
    assert p.customer_connect_overview("u_f", "org_a")["cloud"] == []
    with pytest.raises(ProvisionDenied, match="no outstanding"):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)       # the old id can no longer connect anything
    fresh = p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    assert fresh["resumed"] is False and fresh["external_id"] != first["external_id"]


def test_cloud_verify_demands_a_fresh_step_up_before_any_fetch_or_ceiling(monkeypatch):
    from sigil.ui.provision import ProvisionStepUpRequired
    f = _StubCloudFetcher()
    p, s, orgs = _prov(cloud_fetcher=f, cloud_max=1)
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    t0 = time.time()
    with pytest.raises(ProvisionStepUpRequired):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE, mfa_at=0.0, now=t0)
    assert f.calls == []
    # stepped up: the verify runs at once — the refused attempt spent none of the (one-per-window) ceiling
    assert p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE, mfa_at=t0, now=t0 + 1)["access"] == "read-only"


def test_the_confused_deputy_role_is_refused_and_records_nothing():
    # the role trusts VIGIL's principal but NOT only under our external id (the control assume succeeded): any VIGIL
    # tenant could have named it — refused, with the fix named, and nothing recorded
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher(control_denied=False))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    with pytest.raises(ProvisionDenied, match="sts:ExternalId"):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "aws", ACCT) is None


def test_connect_an_account_you_do_not_own_is_refused_and_records_nothing():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher(account_seen="999999999999"))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    with pytest.raises(ProvisionDenied, match="not proven"):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "aws", ACCT) is None


def test_a_fetcher_failure_reaches_the_customer_in_the_fetchers_own_words_only():
    from sigil.ui.cloud_fetch import CloudFetchError
    err = CloudFetchError("VIGIL could not assume the role with the external id shown",
                          detail="AssumeRole HTTP 403 AccessDenied: arn:aws:iam::111122223333:user/internal")
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher(error=err))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    with pytest.raises(ProvisionDenied) as e:
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    assert str(e.value) == "VIGIL could not assume the role with the external id shown"
    assert "111122223333" not in str(e.value)          # the AWS detail goes to the operator audit only


def test_the_cloud_leg_fails_closed_until_the_owner_provisions_it():
    for kw in ({"cloud_fetcher": None}, {"cloud_fetcher": _StubCloudFetcher(), "principal": ""},
               {"cloud_fetcher": _StubCloudFetcher(), "limiters": False}):
        p, s, orgs = _prov(**kw)
        _seat(orgs, "org_a", "u_f", "operator")
        with pytest.raises(ProvisionError, match="not available"):
            p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
        with pytest.raises(ProvisionError, match="not available"):
            p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)


def test_the_cloud_actions_refuse_while_the_cloud_flag_is_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_CLOUD_CONNECT")
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    for call in (lambda: p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT),
                 lambda: p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE),
                 lambda: p.cloud_disconnect("u_f", "org_a", "aws", ACCT)):
        with pytest.raises(ProvisionDenied, match="not enabled"):
            call()


def test_cloud_verify_is_rate_limited_per_org():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher(account_seen="999999999999"), cloud_max=1)
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    with pytest.raises(ProvisionRateLimited):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)


def test_unverifiable_providers_are_refused_before_any_record():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    before = s.next_seq
    with pytest.raises(ProvisionDenied, match="provider must be one of"):   # every KNOWN provider is verifiable now
        p.cloud_connect_challenge("u_f", "org_a", "digitalocean", "acct-1")
    assert s.next_seq == before                          # no challenge, no audit row: nothing written at all


# ---- SELF-RED-PEN: cross-tenant + connect -> offense ----------------------------------------------------------
def test_cross_tenant_org_b_cannot_read_or_disconnect_org_a_grant():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_a", "operator")
    _seat(orgs, "org_b", "u_b", "operator")
    _connect_cloud(p, "u_a", "org_a")
    assert p.customer_connect_overview("u_b", "org_b")["cloud"] == []
    out = p.cloud_disconnect("u_b", "org_b", "aws", ACCT)
    assert out["disconnected"] is False and out["cancelled"] is False
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "aws", ACCT) is not None
    assert CloudConnectRegistry(s, owner_key=None).challenge("org_a", "aws", ACCT) is not None   # A's id untouched
    resumed = p.cloud_connect_challenge("u_b", "org_b", "aws", ACCT)    # B naming A's account gets ITS OWN id
    assert resumed["resumed"] is False
    assert resumed["external_id"] != CloudConnectRegistry(s, owner_key=None).challenge("org_a", "aws", ACCT).external_id
    with pytest.raises(ProvisionDenied):                 # and org B cannot even READ org A as org A
        p.customer_connect_overview("u_b", "org_a")


def test_connecting_a_cloud_account_authorizes_no_offense():
    from vigil_core.posture import customer_prod_execution_enabled
    from sigil.ui.target_authorization import list_targets
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    assert customer_prod_execution_enabled() is False
    _connect_cloud(p, "u_f", "org_a")
    assert list_targets()["targets"] == []                       # no engagement authority minted
    assert customer_prod_execution_enabled() is False            # the live-offense owner gate is unchanged
    from sigil.ui.launch_gate import LaunchGate
    r = LaunchGate(s).reserve_launch(requester="u_f", org_id="org_a", host="apme.cm", units=10,
                                     now=float(next(_iss)))
    assert r["ok"] is False                                      # a cloud grant never unlocks a host launch


def test_disconnect_latches_and_is_idempotent():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    _connect_cloud(p, "u_f", "org_a")
    assert p.cloud_disconnect("u_f", "org_a", "aws", ACCT)["disconnected"] is True
    assert p.customer_connect_overview("u_f", "org_a")["cloud"] == []
    assert p.cloud_disconnect("u_f", "org_a", "aws", ACCT)["disconnected"] is False


# ---- the GCP leg (the second wired provider, NAME-bound) --------------------------------------------------------
def test_the_gcp_challenge_hands_back_the_name_bound_placement():
    from sigil.governor import cloud_connect as cc
    p, s, orgs = _prov(gcp_fetcher=_StubGcpFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "gcp", GCP_PROJECT)
    assert ch["provider"] == "gcp" and ch["account_id"] == GCP_PROJECT
    assert ch["connector_sa"] == GCP_CONNECTOR_SA
    assert ch["token_creator_role"] == "roles/iam.serviceAccountTokenCreator"
    assert ch["sa_id"] == cc._gcp_expected_sa_id(ch["external_id"])
    assert ch["sa_email"] == cc._gcp_expected_sa_email(GCP_PROJECT, ch["external_id"])
    assert any(f"create {ch['sa_id']}" in cmd for cmd in ch["gcloud"])
    assert "trust_policy" not in ch and "principal_arn" not in ch and "description" not in ch   # AWS-only keys absent


def test_gcp_challenge_then_verify_records_a_read_only_grant():
    f = _StubGcpFetcher()
    p, s, orgs = _prov(gcp_fetcher=f)
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "gcp", GCP_PROJECT)
    res = p.cloud_connect_verify("u_f", "org_a", "gcp", GCP_PROJECT, ch["sa_email"])   # the SA shown on the screen
    assert res["access"] == "read-only" and res["role_ref"] == ch["sa_email"] and res["provider"] == "gcp"
    (call,) = f.calls
    assert call["external_id"] == ch["external_id"] and call["role"] == ch["sa_email"]
    ov = p.customer_connect_overview("u_f", "org_a")
    assert [(c["provider"], c["account_id"], c["status"]) for c in ov["cloud"]] == [("gcp", GCP_PROJECT, "connected")]


def test_a_gcp_grant_vigil_cannot_use_reaches_the_customer_in_the_fetchers_words():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    from sigil.ui.cloud_fetch import CloudFetchError
    err = CloudFetchError("VIGIL could not impersonate the service account shown — create exactly that service "
                          "account and grant VIGIL's connector the roles/iam.serviceAccountTokenCreator role on it")
    p, s, orgs = _prov(gcp_fetcher=_StubGcpFetcher(error=err))
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "gcp", GCP_PROJECT)
    with pytest.raises(ProvisionDenied, match="serviceAccountTokenCreator"):
        p.cloud_connect_verify("u_f", "org_a", "gcp", GCP_PROJECT, ch["sa_email"])
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "gcp", GCP_PROJECT) is None


def test_connect_a_gcp_project_you_do_not_control_is_refused():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(gcp_fetcher=_StubGcpFetcher(project_seen="evil-project"))
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "gcp", GCP_PROJECT)
    with pytest.raises(ProvisionDenied, match="not proven"):
        p.cloud_connect_verify("u_f", "org_a", "gcp", GCP_PROJECT, ch["sa_email"])
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "gcp", GCP_PROJECT) is None


def test_the_gcp_leg_fails_closed_until_the_owner_provisions_it():
    # an AWS-only deployment: a GCP challenge / verify refuses with "not available" (no dead-end flow), never a record
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())        # no GCP fetcher / connector SA
    _seat(orgs, "org_a", "u_f", "operator")
    before = s.next_seq
    dummy_sa = f"vgl-aaaaaaaaaaaaaaaaaaaa@{GCP_PROJECT}.iam.gserviceaccount.com"
    with pytest.raises(ProvisionError, match="not available"):
        p.cloud_connect_challenge("u_f", "org_a", "gcp", GCP_PROJECT)
    with pytest.raises(ProvisionError, match="not available"):
        p.cloud_connect_verify("u_f", "org_a", "gcp", GCP_PROJECT, dummy_sa)
    assert s.next_seq == before


def test_gcp_and_aws_can_both_be_connected_in_one_org():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher(), gcp_fetcher=_StubGcpFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    gch = p.cloud_connect_challenge("u_f", "org_a", "gcp", GCP_PROJECT)
    p.cloud_connect_verify("u_f", "org_a", "gcp", GCP_PROJECT, gch["sa_email"])
    ov = {c["provider"]: c["status"] for c in p.customer_connect_overview("u_f", "org_a")["cloud"]}
    assert ov == {"aws": "connected", "gcp": "connected"}
    assert p.customer_connect_overview("u_f", "org_a")["available"]["cloud_connect"] is True
