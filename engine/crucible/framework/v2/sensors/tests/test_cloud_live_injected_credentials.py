"""Wave B.1 — the CloudLiveSensor CUSTOMER-credential seam (the identity-substitution guard).

The collector's defining customer-posture invariant: when a scoped read-only session is injected (a
``vigil_core.cloud_session.MintedSession``, duck-typed here so the engine imports no governor object — the
FATAL-2 boundary), the collector reaches the customer's cloud as THAT identity and NEVER consults VIGIL's
ambient boto3 credential chain; a run that REQUIRES an injected session fails CLOSED rather than fall back to
VIGIL's own identity; and a session that lands in a DIFFERENT account than the grant claimed is refused at
collection time (defence in depth over the sovereign mint's own drift check).

boto3 is faked in-process (``monkeypatch.setitem(sys.modules, "boto3", ...)``), as the sibling fail-closed
tests do — no SDK, no network."""
from __future__ import annotations

import sys
from types import SimpleNamespace

from framework.v2.sensors.cloud_live import CloudLiveSensor

ACCT = "123456789012"
OTHER = "999999999999"


class _Creds:
    """Duck-typed scoped read-only credentials — the exact shape a vigil_core MintedSession exposes. Fields are
    overridable so a test can forge an EMPTY/PARTIAL AWS session or a non-AWS (gcp/azure) session."""

    def __init__(self, *, account_id: str = ACCT, region: str = "us-east-1", provider: str = "aws",
                 access_key_id: str = "ASIATEMPKEY", secret_access_key: str = "temp-secret-value",
                 session_token: str = "temp-session-token") -> None:
        self.provider = provider
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.region = region
        self.account_id = account_id


def _fake_boto3(*, sts_account: str = ACCT, forbid_ambient: bool = True):
    """A boto3 whose Session records its constructor kwargs and serves a working STS identity. Its
    get_credentials() RAISES when ``forbid_ambient`` — so a test proves the ambient chain was never consulted
    on an injected run. s3/iam/s3control clients expose no methods, so the collectors degrade to empty (this
    suite tests credential handling, not collection — the moto E2E covers collection)."""
    rec: dict = {"kwargs": None}

    def make_session(**kwargs):
        rec["kwargs"] = kwargs

        def get_credentials():
            if forbid_ambient:
                raise AssertionError("ambient get_credentials() must not be consulted on an injected run")
            return SimpleNamespace(access_key="ambient-identity")  # a non-None ambient identity

        def client(name, **kw):
            if name == "sts":
                return SimpleNamespace(get_caller_identity=lambda: {"Account": sts_account})
            return SimpleNamespace()  # s3/iam/s3control: no methods -> collectors catch + degrade

        return SimpleNamespace(get_credentials=get_credentials, client=client)

    return SimpleNamespace(Session=make_session), rec


def test_injected_session_is_used_and_ambient_chain_is_never_consulted(monkeypatch):
    fake, rec = _fake_boto3()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = CloudLiveSensor(credentials=_Creds()).run({}, SimpleNamespace())
    assert r.ok is True
    # the session was built from the INJECTED credentials (if the ambient chain had been consulted, the fake's
    # get_credentials() would have raised AssertionError and failed this test):
    assert rec["kwargs"]["aws_access_key_id"] == "ASIATEMPKEY"
    assert rec["kwargs"]["aws_secret_access_key"] == "temp-secret-value"
    assert rec["kwargs"]["aws_session_token"] == "temp-session-token"


def test_customer_run_fails_closed_rather_than_use_ambient_identity(monkeypatch):
    # require_injected_credentials + NO injected session + a perfectly good ambient identity available -> REFUSE.
    fake, _ = _fake_boto3(forbid_ambient=False)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = CloudLiveSensor(require_injected_credentials=True).run({}, SimpleNamespace())
    assert r.ok is False and "no identity substitution" in r.note.lower()


def test_scoped_run_refuses_account_drift_at_collection_time(monkeypatch):
    # the credentials assume, but the session lands in a DIFFERENT account than the grant claimed -> refuse.
    fake, _ = _fake_boto3(sts_account=OTHER)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = CloudLiveSensor(credentials=_Creds(account_id=ACCT)).run({}, SimpleNamespace())
    assert r.ok is False and "could not confirm" in r.note.lower()


def test_empty_or_partial_injected_credentials_fail_closed_never_ambient(monkeypatch):
    # red-pen HIGH: boto3.Session with empty aws_* args silently falls back to VIGIL's ambient chain. The seam
    # must REJECT an empty/partial credential BEFORE building the session — the require_injected branch cannot
    # catch a non-None-but-empty object. Assert refusal AND that no boto3.Session was ever constructed.
    for bad in (_Creds(secret_access_key=""), _Creds(session_token=""), _Creds(access_key_id="")):
        fake, rec = _fake_boto3()
        monkeypatch.setitem(sys.modules, "boto3", fake)
        r = CloudLiveSensor(credentials=bad, require_injected_credentials=True).run({}, SimpleNamespace())
        assert r.ok is False and "no identity substitution" in r.note.lower()
        assert rec["kwargs"] is None     # refused before any boto3.Session (no ambient fall-through possible)


def test_non_aws_injected_session_fails_closed(monkeypatch):
    # a GCP/Azure MintedSession (bearer only; aws_* empty) handed to the AWS collector must be refused, never
    # treated as AWS creds (which would fall back to the ambient chain).
    fake, rec = _fake_boto3()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    gcp = _Creds(provider="gcp", access_key_id="", secret_access_key="", session_token="")
    r = CloudLiveSensor(credentials=gcp).run({}, SimpleNamespace())
    assert r.ok is False and "non-aws" in r.note.lower()
    assert rec["kwargs"] is None


def test_injected_run_refuses_an_unresolved_landed_account(monkeypatch):
    # the empty-account drift edge: STS returns Account "" on an injected run -> tenancy UNCONFIRMED -> fail
    # closed (the old `if claimed and account` guard silently SKIPPED this).
    fake, _ = _fake_boto3(sts_account="")
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = CloudLiveSensor(credentials=_Creds(account_id=ACCT)).run({}, SimpleNamespace())
    assert r.ok is False and "could not confirm" in r.note.lower()


def test_injected_credentials_never_leak_into_the_result(monkeypatch):
    fake, _ = _fake_boto3(sts_account=ACCT)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    creds = _Creds()
    r = CloudLiveSensor(credentials=creds).run({}, SimpleNamespace())
    blob = f"{r.summary}\n{getattr(r, 'note', '')}\n{r.output}"
    assert creds.secret_access_key not in blob
    assert creds.session_token not in blob
    assert creds.access_key_id not in blob


def test_scoped_run_succeeds_when_the_account_matches(monkeypatch):
    fake, _ = _fake_boto3(sts_account=ACCT)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = CloudLiveSensor(credentials=_Creds(account_id=ACCT)).run({}, SimpleNamespace())
    assert r.ok is True
    assert (r.output or {}).get("account") == ACCT


def test_ambient_path_is_unchanged_when_no_session_is_injected(monkeypatch):
    # regression: no injection + require_injected False -> the ambient chain is used exactly as before.
    fake, _ = _fake_boto3(forbid_ambient=False)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = CloudLiveSensor().run({}, SimpleNamespace())
    assert r.ok is True


def test_injected_session_region_pins_egress_without_an_explicit_region(monkeypatch):
    # the minted session's region drives egress-host pinning when no explicit region/endpoint is given.
    monkeypatch.delenv("CRUCIBLE_AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    s = CloudLiveSensor(credentials=_Creds(region="eu-west-1"))
    assert "sts.eu-west-1.amazonaws.com" in s.egress_hosts
