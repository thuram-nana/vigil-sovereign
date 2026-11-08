"""pause/resume PR-2 — the keyless offense-side arm/precheck REFUSES a PAUSED credit-launch lease.

A PAUSE is a REVERSIBLE operator halt on a lease ``(slug, nonce)`` (the PR-1 substrate
``credit_lease_pause``: fail-CLOSED reader, default-OFF when no marker). PR-2 wires it into the ONE shared
owner-pinned verify+bind chokepoint (``launch_lease._verify_and_bind_lease``), so a paused lease is refused on
BOTH consume paths — the enqueue/trigger pre-check (consume=False) and the engine arm (consume=True) — WITHOUT
burning the single-use ``issued_at`` floor, so a later resume (``clear_lease_pause``) re-arms the SAME lease.

These pin the code-verifiable conjunct: DEFAULT-OFF regression (no marker ⇒ byte-identical to today), refusal
on both consume paths, NO floor-burn (resume re-arms the same lease), fail-CLOSED on a corrupt marker, and the
window check still precedes the pause re-check. The helpers mint a signed lease + owner trust root exactly as
the sibling ``test_launch_lease.py`` does.
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone

import pytest

import framework.v2.launch_lease as LL
from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
# crucible-core runs framework/v2 WITHOUT the integration package (the two-env boundary); this test seeds a
# lease + a pause marker via the integration seam, so skip it cleanly there — it belongs to the integration
# leg's coverage. The sovereign/integration leg HAS vigil_integration, so importorskip returns the modules and
# the test runs fully (mirrors the sibling test_launch_lease.py).
_clb = pytest.importorskip("vigil_integration.live.credit_lease_broker")
_clp = pytest.importorskip("vigil_integration.live.credit_lease_pause")
write_credit_lease = _clb.write_credit_lease
record_lease_pause = _clp.record_lease_pause
clear_lease_pause = _clp.clear_lease_pause
pause_path = _clp.pause_path

SLUG = "cust_abc123"
HOST = "apme.cm"
ORG = "org_a"
NONCE = "n1"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, slug=SLUG, org=ORG, host=HOST, nonce=NONCE, issued=1000.0):
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


def test_unpaused_lease_verifies_and_arms_default_off(monkeypatch):
    """DEFAULT-OFF regression: with NO pause marker recorded, the substrate adds no behaviour — the lease
    verifies on the pre-check (consume=False) and arms on the consume path (consume=True), exactly as today."""
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)[0]
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)[0]


def test_paused_lease_refuses_on_both_consume_paths(monkeypatch):
    """A recorded pause REFUSES the verify on BOTH the enqueue pre-check (consume=False) and the engine arm
    (consume=True) — the pause re-check lives in the shared verify+bind, so one guard covers every caller."""
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce=NONCE))
    record_lease_pause(base, SLUG, NONCE)                                      # operator pause
    ok_pre, reason_pre = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)
    assert not ok_pre and "paused" in reason_pre.lower()                       # precheck refuses
    ok_arm, reason_arm = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)
    assert not ok_arm and "paused" in reason_arm.lower()                       # arm refuses too


def test_pause_refusal_does_not_burn_floor_resume_re_arms(monkeypatch):
    """The pause refusal must NOT advance the single-use issued_at floor: the arm is refused WHILE paused, then
    a resume (clear_lease_pause) re-arms the SAME lease (same issued_at ⇒ same floor seq). If the pause path had
    burned the floor, this re-arm would be refused as a 'single-use' replay — so a green arm here proves no
    re-burn (this is the load-bearing test for mutation #2)."""
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce=NONCE, issued=1000.0))
    record_lease_pause(base, SLUG, NONCE)
    assert not LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)[0]  # paused -> refused
    clear_lease_pause(base, SLUG, NONCE)                                       # operator resume
    ok, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)
    assert ok, reason                                                          # SAME lease re-arms — floor was never burned


def test_corrupt_pause_marker_fails_closed(monkeypatch):
    """FAIL-CLOSED: a pause marker that EXISTS but cannot be read as 'not paused' (corrupt/foreign) is treated
    as PAUSED by is_lease_paused, so the verify refuses rather than falling through to consume — the deliberate
    inversion of the settlement re-check's fail-OPEN."""
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce=NONCE))
    pp = pause_path(base, SLUG)
    assert pp is not None
    pp.parent.mkdir(parents=True, exist_ok=True)
    pp.write_text("{ this is not valid json", encoding="utf-8")               # existing-but-corrupt marker
    for consume in (False, True):                                             # BOTH the pre-check and the arm
        ok, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=consume)
        assert not ok and "paused" in reason.lower()


def test_paused_but_window_lapsed_still_fails_window_check(monkeypatch):
    """A pause does not mask the other conjuncts: a paused lease whose validity window has LAPSED still fails on
    the window check (``nb <= t < na``), which PRECEDES the pause re-check in the shared verify+bind — so the
    refusal is the window one, proving the earlier bind clauses still fire under a pause."""
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce=NONCE, issued=1000.0))
    record_lease_pause(base, SLUG, NONCE)
    ok, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=9e12, consume=False)  # far past not_after
    assert not ok and "window" in reason.lower()
