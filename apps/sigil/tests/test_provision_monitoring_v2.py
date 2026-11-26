"""AEGIS AS-2f — the SOVEREIGN v2 MINT FLOW through the Provisioner (grant/revoke/renew).

Invariants pinned here (deterministic, NO-LLM):
  * the whole v2 surface is default-OFF behind `VIGIL_AEGIS_SOVEREIGN_V2` (second gate on top of monitoring);
  * flag(v2) -> admit_customer(manage_monitoring) -> STEP-UP (Respond + capability changes) -> plan gate ->
    INTENT ROW FIRST -> owner-signed grant -> EpochStatement -> READ-BACK -> audited activity line;
  * cross-tenant (TT-B) authorize / revoke / renew is DENIED (ProvisionDenied => the HTTP layer maps to 403);
  * step-up is REQUIRED for an enforcing capability (respond) and for ANY capability change, even when the
    GLOBAL step-up toggle is OFF; a missing / stale step-up DENIES (ProvisionStepUpRequired);
  * `monitor_renew` re-mints the SAME capabilities with a strictly-higher epoch; no active grant => denied;
  * a step-up + activity line is recorded for a granted authority.
"""
from __future__ import annotations

import itertools
import os
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
    monkeypatch.setenv("VIGIL_AEGIS_SOVEREIGN_V2", "1")
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)      # GLOBAL step-up OFF by default


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
    s = SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))
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


def _subscribe(store, org, plan_id="aegis_respond_5h", *, period_end=1e12):
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    MonitoringSubscriptionRegistry(store).subscribe(org, plan_id, 0, period_start=0.0, period_end=period_end,
                                                    issued_at=float(next(_iss)))


def _rig():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    _seat(orgs, "org_b", "bob", "org_admin")
    _prove(s, "org_a", "apme.cm")
    _prove(s, "org_b", "beta.cm")
    _subscribe(s, "org_a")
    _subscribe(s, "org_b")
    return p, s, orgs


def _owner_root():
    from sigil.governor.identity import owner_keypair
    from vigil_core import AuthorizerKey, TrustRoot
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner_keypair().public_key_b64)])


# --- flag gating --------------------------------------------------------------------------------------
def test_v2_flag_off_refuses(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    monkeypatch.delenv("VIGIL_AEGIS_SOVEREIGN_V2")
    for fn in (lambda: p.monitor_authorize_v2("alice", "org_a", "apme.cm"),
               lambda: p.monitor_revoke_v2("alice", "org_a", "apme.cm"),
               lambda: p.monitor_renew("alice", "org_a", "apme.cm")):
        with pytest.raises(ProvisionDenied):
            fn()


# --- positive observe path (no step-up needed) + read-back + activity line -----------------------------
def test_observe_grant_publishes_verifies_and_records_activity():
    from vigil_core.authority_v2 import verify_monitoring_authority_v2
    from vigil_core.monitoring_authority import SignedMonitoringAuthority  # unchanged v1 publish, not used here
    from sigil.governor.monitoring_authority_v2 import SIGNAL_V2, SIGNAL_V2_INTENT, SignedMonitoringAuthorityV2
    p, s, _ = _rig()
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)           # observe, no step-up required
    assert r["capabilities"] == ["observe"] and r["epoch"] == 1 and r["org_id"] == "org_a"
    # the published artifact verifies against the owner root (read-back already enforced this inside the mint)
    from sigil import config
    pubdir = config.monitoring_v2_publish_dir()
    raw = (pubdir / r["published"]).read_text()
    signed = SignedMonitoringAuthorityV2.model_validate_json(raw)
    assert verify_monitoring_authority_v2(signed, _owner_root())[0] is True
    assert signed.document.origin is None                                        # AS-2g seam: no tenant origin
    # the activity line + the intent row are both on the spine
    seen = {"granted": False, "intent": False}
    for rec in s.iter_records():
        pl = getattr(rec, "payload", None)
        if not isinstance(pl, dict):
            continue
        if pl.get("signal") == SIGNAL_V2_INTENT:
            seen["intent"] = True
        if pl.get("action") == "monitor_authorize_v2" and str(pl.get("outcome", "")).startswith("granted"):
            seen["granted"] = True
    assert seen["intent"] and seen["granted"]
    _ = SignedMonitoringAuthority  # imported to assert the v1 contract still loads unchanged


# --- step-up for Respond and capability changes (the core AS-2f enforcement) --------------------------
def test_respond_requires_stepup_even_when_global_toggle_off():
    from sigil.ui.provision import ProvisionStepUpRequired
    from vigil_core.authority_v2 import MonitoringCapability
    p, s, _ = _rig()
    # respond is an ENFORCING capability => a fresh step-up is REQUIRED, even though the global toggle is off
    with pytest.raises(ProvisionStepUpRequired):
        p.monitor_authorize_v2("alice", "org_a", "apme.cm",
                               capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.RESPOND],
                               now=5000.0, mfa_at=0.0)
    # with a FRESH step-up stamp it succeeds and records the activity line
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm",
                               capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.RESPOND],
                               now=5000.0, mfa_at=5000.0)
    assert r["capabilities"] == ["observe", "respond"] and r["epoch"] == 1


def test_capability_change_requires_stepup():
    from sigil.ui.provision import ProvisionStepUpRequired
    from vigil_core.authority_v2 import MonitoringCapability
    p, s, _ = _rig()
    p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)               # observe baseline (no step-up)
    # observe -> observe+block is a CAPABILITY CHANGE => step-up required
    with pytest.raises(ProvisionStepUpRequired):
        p.monitor_authorize_v2("alice", "org_a", "apme.cm",
                               capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK],
                               now=5001.0, mfa_at=0.0)
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm",
                               capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK],
                               now=5001.0, mfa_at=5001.0)
    assert r["capabilities"] == ["block", "observe"] and r["epoch"] == 2         # epoch advanced (high-water)


def test_re_authorizing_the_same_observe_set_needs_no_stepup():
    p, s, _ = _rig()
    p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5001.0, mfa_at=0.0)   # unchanged => no step-up
    assert r["epoch"] == 2


def test_respond_without_respond_plan_is_refused():
    from sigil.ui.provision import ProvisionDenied
    from vigil_core.authority_v2 import MonitoringCapability
    p, s, orgs = _prov()
    _seat(orgs, "org_c", "carol", "org_admin")
    _prove(s, "org_c", "cme.cm")
    _subscribe(s, "org_c", "aegis_observe_1h")                                    # observe-only plan (no respond)
    with pytest.raises(ProvisionDenied, match="respond"):
        p.monitor_authorize_v2("carol", "org_c", "cme.cm",
                               capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.RESPOND],
                               now=5000.0, mfa_at=5000.0)


# --- cross-tenant (TT-B POST => 403) ------------------------------------------------------------------
def test_cross_tenant_authorize_revoke_renew_denied():
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    p.monitor_authorize_v2("bob", "org_b", "beta.cm", now=5000.0)                 # org_b's own grant
    for fn in (lambda: p.monitor_authorize_v2("alice", "org_b", "beta.cm", now=5001.0),   # alice not in org_b
               lambda: p.monitor_revoke_v2("alice", "org_b", "beta.cm"),
               lambda: p.monitor_renew("alice", "org_b", "beta.cm", now=5001.0),
               lambda: p.monitor_authorize_v2("mallory", "org_a", "apme.cm", now=5001.0)):   # non-member
        with pytest.raises(ProvisionDenied):
            fn()
    # org_b's grant is untouched by the cross-tenant attempts
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry
    assert MonitoringAuthorityV2Registry(s).grant_for("org_b", "beta.cm") is not None


@pytest.mark.parametrize("role", ["viewer", "analyst", "operator"])
def test_non_admin_roles_denied(role):
    from sigil.ui.provision import ProvisionDenied
    p, s, orgs = _rig()
    _seat(orgs, "org_a", "carol", role)
    with pytest.raises(ProvisionDenied):
        p.monitor_authorize_v2("carol", "org_a", "apme.cm", now=5000.0)


# --- revoke + renew -----------------------------------------------------------------------------------
def test_revoke_unpublishes_and_renew_requires_an_active_grant():
    from sigil.ui.provision import ProvisionDenied
    from sigil import config
    p, s, _ = _rig()
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)
    pubfile = config.monitoring_v2_publish_dir() / r["published"]
    assert pubfile.exists()
    rr = p.monitor_revoke_v2("alice", "org_a", "apme.cm", now=5001.0)
    assert rr["revoked"] is True and not pubfile.exists()                         # unpublished
    # renew after a revoke => no active grant => denied
    with pytest.raises(ProvisionDenied, match="no active"):
        p.monitor_renew("alice", "org_a", "apme.cm", now=5002.0)


def test_revoke_v2_unpublishes_the_grants_actual_instance_id():
    """Confirmed LOW: a grant authorized under a NON-default instance_id, then revoked WITHOUT re-supplying it,
    must unpublish the grant's ACTUAL content-addressed path (looked up from the spine fold) — not the
    instance_id='default' path. Mutation-sensitive: against the pre-fix default, the wrong path is unlinked
    (``unpublished`` False) and the real published grant file survives (the data plane keeps honoring it)."""
    from sigil import config
    p, s, _ = _rig()
    g = p.monitor_authorize_v2("alice", "org_a", "apme.cm", instance_id="worker-7", now=5000.0)
    pubfile = config.monitoring_v2_publish_dir() / g["published"]
    assert pubfile.exists() and g["instance_id"] == "worker-7"
    rr = p.monitor_revoke_v2("alice", "org_a", "apme.cm", now=5001.0)             # NO instance_id supplied (defaults)
    assert rr["revoked"] is True and rr["unpublished"] is True                    # the REAL file was removed
    assert not pubfile.exists()


def test_renew_re_mints_same_capabilities_with_higher_epoch():
    p, s, _ = _rig()
    g = p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)
    assert g["epoch"] == 1
    r = p.monitor_renew("alice", "org_a", "apme.cm", now=5005.0)                  # observe => no step-up
    assert r["capabilities"] == ["observe"] and r["epoch"] == 2                   # strictly higher epoch
    # the lease window moved forward
    assert r["lease_not_before"] == 5005.0 and r["lease_not_after"] > 5005.0


def test_renew_of_enforcing_grant_requires_stepup():
    from sigil.ui.provision import ProvisionStepUpRequired
    from vigil_core.authority_v2 import MonitoringCapability
    p, s, _ = _rig()
    p.monitor_authorize_v2("alice", "org_a", "apme.cm",
                           capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.RESPOND],
                           now=5000.0, mfa_at=5000.0)
    with pytest.raises(ProvisionStepUpRequired):
        p.monitor_renew("alice", "org_a", "apme.cm", now=5005.0, mfa_at=0.0)
    r = p.monitor_renew("alice", "org_a", "apme.cm", now=5005.0, mfa_at=5005.0)
    assert r["epoch"] == 2 and r["capabilities"] == ["observe", "respond"]


# --- read-back failure during publish MUST revert (the phantom-grant fix) -----------------------------
def _fail_read_back(monkeypatch):
    """Monkeypatch the registry so ``read_back`` raises ValueError — read_back's ONLY failure mode (unreadable
    file, verify failure, or round-trip mismatch all raise ValueError). This simulates an IO/verify fault that
    strikes AFTER publish() has already overwritten the content-addressed (epoch-less) grant file."""
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry

    def boom(self, *a, **k):
        raise ValueError("read-back failed: simulated disk/verify fault")
    monkeypatch.setattr(MonitoringAuthorityV2Registry, "read_back", boom)


def test_renew_read_back_failure_reverts_the_phantom_grant_and_is_not_a_bare_denied(monkeypatch):
    """Confirmed MEDIUM: a read-back ValueError DURING renew must reach the revert (``except Exception``), not the
    ``except ValueError`` -> ProvisionDenied clause that left the revoke+unpublish DEAD. Because
    ``authority_publish_path`` is epoch-less, renew's publish() already overwrote the prior valid grant file, so a
    missed revert leaves a PHANTOM active grant on the spine + a destroyed valid file. Mutation-sensitive: against
    the pre-fix code this raises ProvisionDenied and grant_for stays active + the file stays published."""
    from sigil import config
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry
    from sigil.ui.provision import ProvisionDenied, ProvisionError
    p, s, _ = _rig()
    g = p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)           # active grant, epoch 1, published
    pubfile = config.monitoring_v2_publish_dir() / g["published"]
    assert pubfile.exists()
    _fail_read_back(monkeypatch)
    with pytest.raises(ProvisionError) as e:
        p.monitor_renew("alice", "org_a", "apme.cm", now=5005.0)
    assert not isinstance(e.value, ProvisionDenied)                               # the revert clause, not ValueError->Denied
    assert "could not renew" in str(e.value)
    assert MonitoringAuthorityV2Registry(s).grant_for("org_a", "apme.cm") is None  # the phantom grant was revoked
    assert not pubfile.exists()                                                   # the republished file was unpublished


def test_renew_grant_valueerror_is_still_a_denied_and_publishes_nothing(monkeypatch):
    """The split keeps grant()'s OWN ValueError (a bad window / anti-replay refusal — nothing published yet) a
    ProvisionDenied, NOT the critical publish_failed revert path. Mirrors ``monitor_authorize_v2``."""
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry
    from sigil.ui.provision import ProvisionDenied
    p, s, _ = _rig()
    p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)

    def bad_grant(self, *a, **k):
        raise ValueError("not_after must be strictly after not_before")
    monkeypatch.setattr(MonitoringAuthorityV2Registry, "grant", bad_grant)
    with pytest.raises(ProvisionDenied, match="not_after"):
        p.monitor_renew("alice", "org_a", "apme.cm", now=5005.0)


def test_authorize_read_back_failure_reverts_and_is_not_a_bare_denied(monkeypatch):
    """The equivalent revert test for ``monitor_authorize_v2`` (its revert was previously untested): a read-back
    ValueError reaches the revert clause (revoke + unpublish), surfaces a ProvisionError (not ProvisionDenied), and
    leaves NO active grant and NO published grant file behind. Mutation-sensitive against removing the revert."""
    from sigil import config
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry
    from sigil.ui.provision import ProvisionDenied, ProvisionError
    p, s, _ = _rig()
    _fail_read_back(monkeypatch)
    with pytest.raises(ProvisionError) as e:
        p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)
    assert not isinstance(e.value, ProvisionDenied)
    assert "could not publish/verify" in str(e.value)
    assert MonitoringAuthorityV2Registry(s).grant_for("org_a", "apme.cm") is None  # the revert revoked it
    pubdir = config.monitoring_v2_publish_dir()
    leftover = [f.name for f in pubdir.glob("*.json")
                if not f.name.endswith(".epoch.json")] if pubdir.exists() else []
    assert leftover == []                                                         # the grant bytes were unpublished


# --- window is server-decided (client may only shorten) -----------------------------------------------
def test_window_server_decided_client_may_only_shorten(monkeypatch):
    from sigil import config
    from sigil.ui.provision import ProvisionError
    monkeypatch.setattr(config, "MONITORING_WINDOW_SECONDS", 100)
    p, s, _ = _rig()
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm", window_s=10_000, now=5000.0)
    assert r["not_after"] - r["not_before"] == 100.0
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm", window_s=7, now=6000.0)
    assert r["not_after"] - r["not_before"] == 7.0
    with pytest.raises(ProvisionError, match="positive number"):
        p.monitor_authorize_v2("alice", "org_a", "apme.cm", window_s=-1, now=7000.0)
