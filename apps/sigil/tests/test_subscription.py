"""Behavioral tests for the SaaS plan/subscription state-of-record (`governor/subscription.py`).

Load-bearing invariants (a false-green would let a lapsed/forged plan read as active, or let a replayed grant
resurrect a canceled plan):
  * subscribe is owner-signed + FRESH (strictly > per-org high-water); a forged/stale/replayed active is inert;
  * past_due/cancel are the SAFE direction — honored on sight even unsigned, lowering only the status and
    retaining the plan; a fresh owner-signed subscribe recovers to active;
  * a lapsed period reads as not-active even before dunning (fail-closed);
  * plan_id/period/allotment validated fail-closed at binding; tenants isolated (keyed org_id == tenant_id).
The prune-survival + replay-across-prune properties live in test_snapshot_fold_subscription.py.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.subscription import (STATUS_ACTIVE, STATUS_CANCELED, STATUS_PAST_DUE, SUBSCRIPTION_SIGNAL,
                                         SubscriptionRegistry)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()

_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return SubscriptionRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def test_subscribe_then_read():
    s = _store()
    r = _reg(s)
    r.subscribe("acme", "pro", 6000, period_start=1000.0, period_end=2000.0, issued_at=_issue())
    sub = r.subscription("acme")
    assert sub.status == STATUS_ACTIVE and sub.plan_id == "pro" and sub.allotment == 6000
    assert r.active_subscription("acme") is not None
    assert "acme" in {x.org_id for x in r.subscriptions()}
    assert r.subscription("ghost") is None


def test_period_elapsed_reads_not_active():
    s = _store()
    r = _reg(s)
    r.subscribe("acme", "pro", 6000, period_start=1000.0, period_end=2000.0, issued_at=_issue())
    assert r.active_subscription("acme", now=1500.0) is not None    # inside the period
    assert r.active_subscription("acme", now=2000.0) is None         # period elapsed -> fail-closed
    assert r.active_subscription("acme", now=5000.0) is None


def test_past_due_retains_plan_and_blocks_active():
    s = _store()
    r = _reg(s)
    r.subscribe("acme", "pro", 6000, period_start=1000.0, period_end=2000.0, issued_at=_issue())
    r.mark_past_due("acme")
    sub = r.subscription("acme")
    assert sub.status == STATUS_PAST_DUE and sub.plan_id == "pro" and sub.allotment == 6000  # plan retained
    assert r.active_subscription("acme") is None                     # but not active


def test_cancel_then_renewal_recovers():
    s = _store()
    r = _reg(s)
    r.subscribe("acme", "starter", 1000, period_start=1.0, period_end=100.0, issued_at=_issue())
    r.cancel("acme")
    assert r.subscription("acme").status == STATUS_CANCELED
    # a fresh owner-signed subscribe (new period) recovers to active
    r.subscribe("acme", "pro", 6000, period_start=100.0, period_end=200.0, issued_at=_issue())
    sub = r.subscription("acme")
    assert sub.status == STATUS_ACTIVE and sub.plan_id == "pro"


def test_replayed_stale_active_does_not_resurrect():
    s = _store()
    r = _reg(s)
    seq = r.subscribe("acme", "pro", 6000, period_start=1.0, period_end=2.0, issued_at=5.0)
    captured = s.get(seq).payload
    r.cancel("acme")
    assert r.subscription("acme").status == STATUS_CANCELED
    # ATTACK: replay the captured active (issued_at 5.0 <= per-org high-water) -> ignored
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert r.subscription("acme").status == STATUS_CANCELED, "a replayed stale active must not resurrect a canceled plan"


def test_forged_active_ignored():
    s = _store()
    r = _reg(s)
    r.subscribe("acme", "starter", 1000, period_start=1.0, period_end=2.0, issued_at=_issue())
    r.cancel("acme")
    core = {"signal": SUBSCRIPTION_SIGNAL, "org_id": "acme", "plan_id": "pro", "period_start": 1.0,
            "period_end": 2.0, "allotment": 6000, "status": "active", "issued_at": 99999.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    assert r.subscription("acme").status == STATUS_CANCELED, "an attacker-signed active must be ignored"


def test_safe_direction_honored_unsigned():
    s = _store()
    r = _reg(s)
    r.subscribe("acme", "pro", 6000, period_start=1.0, period_end=2.0, issued_at=_issue())
    nokey = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    nokey.owner_key = None                                           # truly unsigned
    nokey.cancel("acme")                                            # safe direction still takes effect
    assert r.subscription("acme").status == STATUS_CANCELED


def test_binding_validation():
    s = _store()
    r = _reg(s)
    for bad in ("", "BadUpper", "a/b", "x" * 65):
        with pytest.raises(ValueError):
            r.subscribe("acme", bad, 10, period_start=1.0, period_end=2.0, issued_at=_issue())
    with pytest.raises(ValueError):                                 # period_end <= period_start
        r.subscribe("acme", "pro", 10, period_start=5.0, period_end=5.0, issued_at=_issue())
    with pytest.raises(ValueError):                                 # negative allotment
        r.subscribe("acme", "pro", -1, period_start=1.0, period_end=2.0, issued_at=_issue())
    nokeyless = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    nokeyless.owner_key = None
    with pytest.raises(ValueError):                                 # subscribe needs the owner key
        nokeyless.subscribe("acme", "pro", 10, period_start=1.0, period_end=2.0, issued_at=_issue())


def test_bare_down_state_for_never_subscribed_org_reads_absent():
    # A cancel/past_due appended for an org that NEVER had an honored `active` must NOT fabricate a phantom
    # canceled Subscription (empty plan, allotment 0) — `subscription()` promises None for a never-subscribed
    # tenant, and the billing roster must not list it. (A plan canceled AFTER subscribing is still retained.)
    s = _store()
    r = _reg(s)
    r.cancel("ghost")                                   # bare safe-direction record, no prior subscribe
    assert r.subscription("ghost") is None
    assert "ghost" not in {x.org_id for x in r.subscriptions()}
    r.mark_past_due("spectre")
    assert r.subscription("spectre") is None
    # contrast: a genuine subscribe-then-cancel retains the plan row and is still readable (dunning view)
    r.subscribe("real", "pro", 6000, period_start=1.0, period_end=2.0, issued_at=_issue())
    r.cancel("real")
    sub = r.subscription("real")
    assert sub is not None and sub.status == STATUS_CANCELED and sub.plan_id == "pro"
    assert {x.org_id for x in r.subscriptions()} == {"real"}


def test_tenants_isolated():
    s = _store()
    r = _reg(s)
    r.subscribe("orga", "pro", 6000, period_start=1.0, period_end=2.0, issued_at=_issue())
    r.subscribe("orgb", "starter", 1000, period_start=1.0, period_end=2.0, issued_at=_issue())
    r.cancel("orgb")
    assert r.subscription("orga").status == STATUS_ACTIVE
    assert r.subscription("orgb").status == STATUS_CANCELED
    assert r.active_subscription("orgb") is None


def test_webhook_past_due_is_freshness_gated_vs_the_active_high_water():
    # H4: a WEBHOOK-sourced down-state carries the provider event's `created` as issued_at and is applied only if
    # FRESHER than the last honored activation — so a stale/replayed failed charge cannot re-suspend a recovered
    # tenant — while the OWNER-MANUAL latch (issued_at 0.0) stays honored on sight.
    r = _reg(_store())
    r.subscribe("acme", "pro", 6000, period_start=100.0, period_end=1100.0, issued_at=100.0)   # active, high-water 100
    r.mark_past_due("acme", issued_at=50.0)                 # STALE webhook failure (< 100) -> ignored
    assert r.subscription("acme").status == STATUS_ACTIVE, "a stale webhook past_due must not lower a fresher active"
    r.mark_past_due("acme", issued_at=200.0)                # genuine current failure (> 100) -> applied
    assert r.subscription("acme").status == STATUS_PAST_DUE
    r.subscribe("acme", "pro", 6000, period_start=300.0, period_end=1300.0, issued_at=300.0)   # recovered, high-water 300
    assert r.subscription("acme").status == STATUS_ACTIVE
    r.mark_past_due("acme", issued_at=200.0)                # STALE replay (< 300) after recovery -> ignored
    assert r.subscription("acme").status == STATUS_ACTIVE, "a stale replay must not re-suspend a recovered tenant"


def test_owner_manual_latch_still_honored_on_sight_over_a_fresher_active():
    # The owner-manual 0.0 latch must stay UN-gated (fail-SAFE): even against a very fresh active, an owner
    # mark_past_due / cancel (issued_at 0.0) still lowers access on sight.
    r = _reg(_store())
    r.subscribe("acme", "pro", 6000, period_start=1000.0, period_end=2000.0, issued_at=1000.0)
    r.mark_past_due("acme")                                 # default 0.0 -> honored on sight
    assert r.subscription("acme").status == STATUS_PAST_DUE
    r.subscribe("acme", "pro", 6000, period_start=3000.0, period_end=4000.0, issued_at=3000.0)  # recover
    assert r.subscription("acme").status == STATUS_ACTIVE
    r.cancel("acme")                                        # owner cancel (0.0) -> honored on sight vs a fresh active
    assert r.subscription("acme").status == STATUS_CANCELED
