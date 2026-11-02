"""K2 — the keyless offense-side credit-launch-lease precondition (framework.v2.launch_lease).

The security heart of the customer-launch seam on the OFFENSE side: a customer engagement (cust_ slug) runs
ONLY if a current owner-signed CreditLaunchLease on the seam verifies owner-pinned, binds to this
engagement/host/tenant/window, and passes the strict single-use floor. Operator/greenfield runs consult no
lease. The positive END-TO-END (a real customer engage actually proceeding with per-tenant CRUCIBLE_TENANT
isolation) is sandbox-gated; these tests pin the code-verifiable conjunct: owner-pinned verify, every bind
clause fail-closed, single-use, re-lease-advances, and the engage hook's cust_-gate (operator untouched).
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone

import pytest

import framework.v2.launch_lease as LL
from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.live.credit_lease_broker import write_credit_lease

SLUG = "cust_abc123"
HOST = "apme.cm"
ORG = "org_a"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, slug=SLUG, org=ORG, host=HOST, nonce="n1", issued=1000.0):
    t = datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=10,
                            not_before=t - timedelta(hours=1), not_after=t + timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _rig(monkeypatch, owner, signed, *, base=None):
    base = base or tempfile.mkdtemp()
    write_credit_lease(base, signed.document.engagement_slug, signed, _owner_root(owner))
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    return base


def test_valid_lease_verifies_and_binds(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    ok, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)
    assert ok, reason


def test_single_use_second_consume_refuses(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0)[0]       # consume
    ok2, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0)   # replay
    assert not ok2 and "single-use" in reason


def test_each_bind_clause_fails_closed(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    assert not LL.verify_customer_launch_lease(SLUG, "evil.cm", ORG, base_dir=base, now=1000.0, consume=False)[0]
    assert not LL.verify_customer_launch_lease(SLUG, HOST, "org_evil", base_dir=base, now=1000.0, consume=False)[0]
    assert not LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=9e12, consume=False)[0]  # expired
    assert not LL.verify_customer_launch_lease(SLUG, HOST, None, base_dir=base, now=1000.0, consume=False)[0]  # unsharded
    assert not LL.verify_customer_launch_lease("cust_absent", HOST, ORG, base_dir=base, now=1000.0, consume=False)[0]


def test_forged_lease_does_not_verify_under_owner_key(monkeypatch):
    owner = generate_keypair()
    attacker = generate_keypair()
    base = tempfile.mkdtemp()
    # the attacker signs a lease AND co-lists only their own key in the seam bundle — but we PIN the owner root,
    # so a bundle the owner did not sign is refused (never the seam-carried root).
    forged = sign_credit_launch_lease(_lease(owner).document, {"owner": attacker.private_key_b64})
    write_credit_lease(base, SLUG, forged, _owner_root(attacker))
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    ok, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)
    assert not ok and "does not verify" in reason


def test_no_owner_root_fails_closed(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: None)
    assert not LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)[0]


def test_release_with_newer_issued_at_passes_old_replay_refused(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce="n1", issued=1000.0))
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0)[0]        # consume v1
    write_credit_lease(base, SLUG, _lease(owner, nonce="n2", issued=2000.0), _owner_root(owner))  # genuine re-lease
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=2000.0)[0]        # newer passes
    write_credit_lease(base, SLUG, _lease(owner, nonce="n1", issued=1000.0), _owner_root(owner))  # replay the old
    assert not LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0)[0]    # floor refuses it


# ---- the engage.py hook: cust_-gated; operator/greenfield untouched -----------------------------------
def test_engage_hook_is_a_noop_for_an_operator_slug():
    from framework.v2.engage import _engage_launch_lease_precondition
    # a non-cust_ slug consults NO lease and never raises (operator/greenfield path byte-identical)
    _engage_launch_lease_precondition("pentest-main", "https://apme.cm")


def test_engage_hook_refuses_a_customer_slug_without_a_lease(monkeypatch, tmp_path):
    from framework.v2.engage import EngagementRefused, _engage_launch_lease_precondition
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path))                 # empty seam -> no lease
    monkeypatch.setattr("framework.v2.common.tenant.tenant_id", lambda: ORG)
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: None)
    with pytest.raises(EngagementRefused):
        _engage_launch_lease_precondition("cust_abc123", "https://apme.cm")


def test_engage_hook_resume_revalidates_without_reconsuming(monkeypatch, tmp_path):
    """K2 resume/consume: ``--resume`` ALWAYS re-runs preflight, so the lease hook re-runs on resume. It must
    RE-VALIDATE + RE-BIND the lease but NOT re-burn the single-use floor the first arm consumed — else the
    same issued_at yields the same floor seq and EVERY resumed customer engagement dies as a 'replay',
    stranding its paid reservation. A FRESH re-arm (resume=False) still refuses (single-use intact); a
    RESUME (resume=True) passes."""
    import time as _time

    from framework.v2.engage import EngagementRefused, _engage_launch_lease_precondition
    owner = generate_keypair()
    now = _time.time()                                                 # lease window must cover the hook's time.time()
    base = str(tmp_path)
    write_credit_lease(base, SLUG, _lease(owner, issued=now), _owner_root(owner))
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    monkeypatch.setattr("framework.v2.common.tenant.tenant_id", lambda: ORG)
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    seed = f"https://{HOST}"
    _engage_launch_lease_precondition(SLUG, seed)                      # fresh arm -> consumes the single-use floor
    with pytest.raises(EngagementRefused):                             # a FRESH re-arm is a replay -> refused
        _engage_launch_lease_precondition(SLUG, seed)
    _engage_launch_lease_precondition(SLUG, seed, resume=True)         # a RESUME must NOT refuse (no re-consume)
    # and resume stays bound: a resume whose tenant/host no longer matches the lease is still fail-closed
    with pytest.raises(EngagementRefused):
        _engage_launch_lease_precondition(SLUG, "https://evil.example", resume=True)


# ---- K4-0: structural customer gate (issued_by, not the cust_ string) ---------------------------------
def test_customer_engagement_requires_lease_is_structural(monkeypatch):
    import types
    # cust_ fast-path: True with no owner root / authority machinery at all (matches the K2 arm fail-closed)
    assert LL.customer_engagement_requires_lease("cust_x") is True
    # a NON-cust_ slug whose VERIFIED authority is customer-issued -> True (closes hole b: no skip-by-rename)
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda *a, **k: object())
    monkeypatch.setattr("framework.v2.authority.store.load_verified_authority",
                        lambda slug, root, *a, **k: types.SimpleNamespace(issued_by="customer:org_a"))
    assert LL.customer_engagement_requires_lease("weird-noncust-slug") is True
    # an operator authority (issued_by "owner") -> False (operator path byte-identical: no lease)
    monkeypatch.setattr("framework.v2.authority.store.load_verified_authority",
                        lambda slug, root, *a, **k: types.SimpleNamespace(issued_by="owner"))
    assert LL.customer_engagement_requires_lease("pentest-main") is False
    # no verifiable authority (greenfield) -> False; and no owner root -> False (both fail-closed to no-lease)
    monkeypatch.setattr("framework.v2.authority.store.load_verified_authority",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no authority")))
    assert LL.customer_engagement_requires_lease("greenfield") is False
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda *a, **k: None)
    assert LL.customer_engagement_requires_lease("greenfield") is False


def test_engage_hook_gates_a_customer_authority_under_a_noncust_slug(monkeypatch, tmp_path):
    """K4-0 hole (b): a customer engagement that (hypothetically) ran under a NON-cust_ slug is no longer
    silently un-gated — the structural issued_by marker makes it require a lease, so an empty seam refuses it."""
    import types

    from framework.v2.engage import EngagementRefused, _engage_launch_lease_precondition
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path))                 # empty seam -> no lease
    monkeypatch.setattr("framework.v2.common.tenant.tenant_id", lambda: ORG)
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda *a, **k: object())
    monkeypatch.setattr("framework.v2.authority.store.load_verified_authority",
                        lambda slug, root, *a, **k: types.SimpleNamespace(issued_by="customer:org_a"))
    with pytest.raises(EngagementRefused):
        _engage_launch_lease_precondition("weird-noncust-slug", "https://apme.cm")


# ---- K4-1 / K5: a settled/canceled lease is no longer runnable at the arm -----------------------------
def test_settled_lease_is_not_runnable(monkeypatch):
    from vigil_integration.live.credit_lease_broker import record_lease_settlement
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce="n1"))
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)[0]
    record_lease_settlement(base, SLUG, "n1")                           # settle/cancel marks this (slug,nonce)
    ok, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)
    assert not ok and "settled" in reason.lower()                      # enqueue pre-check refuses it
    assert not LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)[0]  # arm too
