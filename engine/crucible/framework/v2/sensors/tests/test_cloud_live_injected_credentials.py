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
    """Duck-typed scoped read-only credentials — the exact shape a vigil_core MintedSession exposes."""

    def __init__(self, *, account_id: str = ACCT, region: str = "us-east-1") -> None:
        self.access_key_id = "ASIATEMPKEY"
        self.secret_access_key = "temp-secret-value"
        self.session_token = "temp-session-token"
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
    assert r.ok is False and "different aws account" in r.note.lower()


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
