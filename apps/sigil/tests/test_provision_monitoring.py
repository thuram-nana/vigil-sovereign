"""AEGIS-SaaS AE-1 — the sovereign MINT PATH for DEFENSIVE monitoring authority.

Invariants pinned here:
  * flag (default OFF) -> admit_customer(manage_monitoring) -> step-up -> registry grant -> owner-signed publish;
  * org_admin may authorize; viewer / analyst / operator / non-member may not (manage_monitoring is disjoint from
    run_engagement / offense_authority — observe != offense-test);
  * cross-tenant: org A cannot authorize / revoke / list org B's hosts; the edge ignores a body org_id;
  * no ownership proof -> refused; window is SERVER-capped (client may only shorten);
  * step-up enforced (when ON) and checked only AFTER admit;
  * the published artifact verifies against the owner TrustRoot and a tampered one does not; 0600 / 0700;
  * revoke unpublishes (idempotent); a BLOCK grant turns on nothing by itself.
"""
from __future__ import annotations

import itertools
import json
import os
import stat
import tempfile

import pytest

_iss = itertools.count(1000)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_MONITORING_PUBLISH_DIR", os.path.join(tempfile.mkdtemp(), "pub"))
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)


def _prov():
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
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                  base_lock_s=1.0),
                    email_sender=NullEmailSender(), now_fn=lambda: float(next(_iss)))
    return p, s, orgs


def _seat(orgs, org, user, role):
    if orgs.org(org) is None:
        orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


def _prove(store, org, host):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=float(next(_iss)),
                          ttl_seconds=1e9)


def _owner_root():
    from sigil.governor.identity import owner_keypair
    from vigil_core import AuthorizerKey, TrustRoot
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner_keypair().public_key_b64)])


def _pubdir():
    from sigil import config
    return config.monitoring_publish_dir()


def _rig():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    _seat(orgs, "org_b", "bob", "org_admin")
    _prove(s, "org_a", "apme.cm")
    _prove(s, "org_b", "beta.cm")
    _subscribe(s, "org_a", "aegis_respond_5h")
    _subscribe(s, "org_b", "aegis_respond_5h")
    return p, s, orgs


def _subscribe(store, org, plan_id, *, period_end=1e12):
    from sigil.governor.subscription import SubscriptionRegistry
    SubscriptionRegistry(store).subscribe(org, plan_id, 0, period_start=0.0, period_end=period_end,
                                          issued_at=float(next(_iss)))


# --- positive path + artifact ------------------------------------------------------------------------
def test_org_admin_authorizes_and_published_artifact_verifies_and_tamper_fails():
    from vigil_core.monitoring_authority import (MonitoringMode, SignedMonitoringAuthority,
                                                 verify_monitoring_authority)
    p, s, _ = _rig()
    r = p.monitor_authorize("alice", "org_a", "apme.cm")
    assert r["mode"] == "observe" and r["host"] == "apme.cm" and r["org_id"] == "org_a"
    d = _pubdir()
    files = [f for f in os.listdir(d)]
    assert files == [r["published"]] and "apme" not in r["published"]          # hashed name, no host string
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    fp = d / r["published"]
    assert stat.S_IMODE(os.stat(fp).st_mode) == 0o600
    raw = fp.read_text()
    assert "private" not in raw.lower()
    signed = SignedMonitoringAuthority.model_validate_json(raw)
    ok, why = verify_monitoring_authority(signed, _owner_root())
    assert ok, why
    tampered = signed.model_copy(update={"document": signed.document.model_copy(update={"host": "evil.cm"})})
    assert verify_monitoring_authority(tampered, _owner_root())[0] is False
    flipped = signed.model_copy(update={"document": signed.document.model_copy(update={"mode": MonitoringMode.BLOCK})})
    assert verify_monitoring_authority(flipped, _owner_root())[0] is False
    lst = p.monitor_list("alice", "org_a")
    assert [g["host"] for g in lst["grants"]] == ["apme.cm"] and lst["grants"][0]["active"] is True


def test_window_is_server_decided_client_may_only_shorten(monkeypatch):
    from sigil import config
    from sigil.ui.provision import ProvisionError
    monkeypatch.setattr(config, "MONITORING_WINDOW_SECONDS", 100)
    p, s, _ = _rig()
    r = p.monitor_authorize("alice", "org_a", "apme.cm", window_s=10_000, now=5000.0)
    assert r["not_after"] - r["not_before"] == 100.0                          # cannot ask for longer
    r = p.monitor_authorize("alice", "org_a", "apme.cm", window_s=7, now=6000.0)
    assert r["not_after"] - r["not_before"] == 7.0
    for bad in (0, -1, "x", float("nan"), True):
        with pytest.raises(ProvisionError, match="positive number"):
            p.monitor_authorize("alice", "org_a", "apme.cm", window_s=bad, now=7000.0)


# --- authority ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["viewer", "analyst", "operator"])
def test_non_admin_roles_denied(role):
    from sigil.ui.provision import ProvisionDenied
    p, s, orgs = _rig()
    _seat(orgs, "org_a", "carol", role)
    with pytest.raises(ProvisionDenied):
        p.monitor_authorize("carol", "org_a", "apme.cm")
    with pytest.raises(ProvisionDenied):
        p.monitor_revoke("carol", "org_a", "apme.cm")
    assert not os.path.exists(_pubdir())


def test_non_member_denied():
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    for fn in (lambda: p.monitor_authorize("mallory", "org_a", "apme.cm"),
               lambda: p.monitor_revoke("mallory", "org_a", "apme.cm"),
               lambda: p.monitor_list("mallory", "org_a")):
        with pytest.raises(ProvisionDenied):
            fn()


def test_cross_tenant_cannot_authorize_revoke_or_list():
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    p.monitor_authorize("bob", "org_b", "beta.cm")
    with pytest.raises(ProvisionDenied):
        p.monitor_authorize("alice", "org_b", "beta.cm")                      # not a member of org_b
    with pytest.raises(ProvisionDenied):
        p.monitor_revoke("alice", "org_b", "beta.cm")
    with pytest.raises(ProvisionDenied):
        p.monitor_list("alice", "org_b")
    with pytest.raises(ProvisionDenied):                                       # org_a has no proof of org_b's host
        p.monitor_authorize("alice", "org_a", "beta.cm")
    r = p.monitor_revoke("alice", "org_a", "beta.cm")                          # own-org revoke never touches org_b
    assert r["revoked"] is False
    assert p.monitor_list("alice", "org_a")["grants"] == []
    assert MonitoringAuthorityRegistry(s, owner_key=None).grant_for("org_b", "beta.cm") is not None
    assert len(os.listdir(_pubdir())) == 1


def test_no_ownership_proof_refused():
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    with pytest.raises(ProvisionDenied, match="ownership"):
        p.monitor_authorize("alice", "org_a", "unproven.cm")
    assert not os.path.exists(_pubdir())


def test_bad_mode_refused():
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    with pytest.raises(ProvisionDenied):
        p.monitor_authorize("alice", "org_a", "apme.cm", mode="enforce")


def test_flag_off_refuses(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    for fn in (lambda: p.monitor_authorize("alice", "org_a", "apme.cm"),
               lambda: p.monitor_revoke("alice", "org_a", "apme.cm"),
               lambda: p.monitor_list("alice", "org_a")):
        with pytest.raises(ProvisionDenied):
            fn()
    assert not os.path.exists(_pubdir())


def test_stepup_required_when_on_and_only_after_admit(monkeypatch):
    from sigil.ui.provision import ProvisionDenied, ProvisionStepUpRequired
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    p, s, _ = _rig()
    with pytest.raises(ProvisionDenied):                                       # non-member: admit first, no prompt
        p.monitor_authorize("mallory", "org_a", "apme.cm", mfa_at=0.0, now=10_000.0)
    with pytest.raises(ProvisionStepUpRequired):
        p.monitor_authorize("alice", "org_a", "apme.cm", mfa_at=0.0, now=10_000.0)
    with pytest.raises(ProvisionStepUpRequired):                               # stale factor
        p.monitor_authorize("alice", "org_a", "apme.cm", mfa_at=1.0, now=10_000.0)
    r = p.monitor_authorize("alice", "org_a", "apme.cm", mfa_at=9_990.0, now=10_000.0)
    assert r["host"] == "apme.cm"


# --- revoke / block -----------------------------------------------------------------------------------
def test_revoke_unpublishes_and_is_idempotent():
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    p, s, _ = _rig()
    r = p.monitor_authorize("alice", "org_a", "apme.cm")
    assert (_pubdir() / r["published"]).exists()
    out = p.monitor_revoke("alice", "org_a", "apme.cm")
    assert out == {"org_id": "org_a", "host": "apme.cm", "revoked": True, "unpublished": True}
    assert not (_pubdir() / r["published"]).exists()
    assert MonitoringAuthorityRegistry(s, owner_key=None).grant_for("org_a", "apme.cm") is None
    again = p.monitor_revoke("alice", "org_a", "apme.cm")
    assert again["revoked"] is False and again["unpublished"] is False



# --- red-pen fold: every revoke path unpublishes; a failed publish leaves no active grant ------------
def test_ownership_proof_revoke_unpublishes_artifact():
    from sigil.governor.asset_ownership import AssetOwnershipRegistry
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    p, s, _ = _rig()
    r = p.monitor_authorize("alice", "org_a", "apme.cm")
    rb = p.monitor_authorize("bob", "org_b", "beta.cm")
    AssetOwnershipRegistry(s).revoke_proof("org_a", "apme.cm")
    assert not (_pubdir() / r["published"]).exists()
    assert (_pubdir() / rb["published"]).exists()                      # other tenant untouched
    assert ("org_a", "apme.cm") not in MonitoringAuthorityRegistry(s, owner_key=None)._fold()


def test_org_offboarding_unpublishes_all_org_artifacts():
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    p, s, orgs = _rig()
    _prove(s, "org_a", "apme2.cm")
    r1 = p.monitor_authorize("alice", "org_a", "apme.cm")
    r2 = p.monitor_authorize("alice", "org_a", "apme2.cm", mode="block")
    rb = p.monitor_authorize("bob", "org_b", "beta.cm")
    orgs.revoke_org("org_a")
    assert not (_pubdir() / r1["published"]).exists() and not (_pubdir() / r2["published"]).exists()
    assert (_pubdir() / rb["published"]).exists()
    assert MonitoringAuthorityRegistry(s, owner_key=None).grants("org_a") == []


def test_publish_failure_revokes_the_grant(monkeypatch):
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    from sigil.ui import provision as pv
    from sigil.ui.provision import ProvisionError
    p, s, _ = _rig()

    def _boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(pv, "_publish_monitoring", _boom)
    with pytest.raises(ProvisionError):
        p.monitor_authorize("alice", "org_a", "apme.cm")
    reg = MonitoringAuthorityRegistry(s, owner_key=None)
    assert reg.grant_for("org_a", "apme.cm") is None
    assert ("org_a", "apme.cm") not in reg._fold()
    assert [g for g in p.monitor_list("alice", "org_a")["grants"] if g["active"]] == []


def test_block_grant_enables_nothing_by_itself():
    from sigil import config
    p, s, _ = _rig()
    n0 = sum(1 for _ in s.iter_records(since_seq=-1))
    r = p.monitor_authorize("alice", "org_a", "apme.cm", mode="block")
    assert r["mode"] == "block"
    signals = [rec.payload.get("signal") for rec in list(s.iter_records(since_seq=-1))[n0:]]
    assert set(signals) == {"governor.monitoring_authority", "provision.audit"}   # no entitlement/enforcement
    assert os.listdir(_pubdir()) == [r["published"]]                            # only the signed artifact
    assert "enforce" not in json.dumps(r).lower()
    assert config.customer_stepup_required() is False


# --- transport: server dispatch + edge ----------------------------------------------------------------
class _P:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def f(*a, **k):
            self.calls.append((name, a, k))
            return {"ok": True}
        return f


def test_server_dispatch_absent_when_flag_off(monkeypatch):
    from sigil.ui.server import Handler
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    for a in ("monitor_authorize", "monitor_revoke", "monitor_list"):
        p = _P()
        assert Handler._provision_dispatch(None, p, a, "alice", {"org_id": "org_a", "host": "apme.cm"}) is None
        assert p.calls == []
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    p = _P()
    Handler._provision_dispatch(None, p, "monitor_authorize", "alice",
                                {"org_id": "org_a", "host": "apme.cm", "mode": "block", "window_s": 5})
    name, args, kw = p.calls[0]
    assert name == "monitor_authorize" and args == ("alice", "org_a", "apme.cm")
    assert kw["mode"] == "block" and kw["window_s"] == 5


def _edge(session):
    from sigil.ui.custui import CustomerHandler
    h = object.__new__(CustomerHandler)
    sent = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal,
                                                                body=body) or (200, {"ok": True}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


def test_edge_routes_use_session_org_and_ignore_body_org():
    h, sent = _edge({"username": "alice", "org_id": "org_a", "mfa_at": 42.0})
    h._dispatch("monitoring/authorize", {"host": "apme.cm", "org_id": "org_b", "requester": "bob"})
    assert sent["action"] == "monitor_authorize" and sent["principal"] == "alice"
    assert sent["body"]["org_id"] == "org_a" and sent["body"]["mfa_at"] == 42.0
    h._dispatch("monitoring/revoke", {"host": "apme.cm", "org_id": "org_b"})
    assert sent["action"] == "monitor_revoke" and sent["body"]["org_id"] == "org_a"
    h, sent = _edge(None)
    h._dispatch("monitoring/authorize", {"host": "apme.cm"})
    assert sent["code"] == 401 and "action" not in sent


def test_edge_routes_refuse_as_unknown_when_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    for action in ("monitoring/authorize", "monitoring/revoke"):
        h, sent = _edge({"username": "alice", "org_id": "org_a"})
        h._dispatch(action, {"host": "apme.cm"})
        h2, unknown = _edge({"username": "alice", "org_id": "org_a"})
        h2._dispatch("no/such/route", {})
        assert sent == unknown == {"code": 404, "out": {"error": "unknown action"}}


def test_edge_get_list_route_flag_gated(monkeypatch):
    h, sent = _edge({"username": "alice", "org_id": "org_a"})
    h.path = "/api/customer/monitoring?org_id=org_b"
    h.do_GET()
    assert sent["action"] == "monitor_list" and sent["body"]["org_id"] == "org_a"
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    h, sent = _edge({"username": "alice", "org_id": "org_a"})
    h.path = "/api/customer/monitoring"
    h.do_GET()
    h2, unknown = _edge({"username": "alice", "org_id": "org_a"})
    h2.path = "/api/customer/nope"
    h2.do_GET()
    assert sent == unknown == {"code": 404, "out": {"error": "not found"}}
