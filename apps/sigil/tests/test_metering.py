"""Behavioral tests for the SaaS credit burn-down meter + period-scoped plan-credit ledger (`governor/metering.py`).

Load-bearing invariants (a false-green would let an expired tranche read as spendable, let a forged/replayed plan
grant mint credits, or let the refill bridge double-grant or refill a non-paying tenant):
  * a plan tranche is spendable ONLY while period_end > now (NON-ROLLOVER): its unspent remainder — AND its
    debits — vanish at expiry, so an expired tranche contributes exactly 0 (never negative);
  * grant/debit are BOTH owner-signed + verified (no honored-unsigned direction) and idempotent per
    (signal, org_id, entry_id); a forged/replayed record is inert; a forged negative credit clamps to 0;
  * the CreditMeter is persistent-wallet + live-plan composition; persistent (trial/topup) never expires;
  * the refill bridge grants ONE tranche per active period (idempotent, no redundant append), refills NO
    non-active tenant, and a new period grants a fresh tranche (the prior one simply expires — non-rollover);
  * period_end/credits validated fail-closed at binding; tenants isolated (keyed org_id == tenant_id).
The prune-survival + replay-across-prune properties live in test_snapshot_fold_metering.py.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.metering import (PLAN_GRANT_SIGNAL, CreditMeter, PlanCreditLedger,
                                      refill_active_subscription)
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
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


def _plan(store):
    return PlanCreditLedger(store, owner_key=OWNER, trusted_pubkey=OP)


def _wallet(store):
    return WalletRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def _subs(store):
    return SubscriptionRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def test_grant_debit_and_tranche_remainder():
    s = _store()
    p = _plan(s)
    p.grant("acme", 6000, period_end=2000.0, issued_at=_issue())
    p.debit("acme", 100, period_end=2000.0, issued_at=_issue())
    [t] = p.tranches("acme")
    assert t.period_end == 2000.0 and t.granted == 6000 and t.debited == 100 and t.remaining == 5900


def test_tranche_expires_non_rollover():
    s = _store()
    p = _plan(s)
    p.grant("acme", 6000, period_end=2000.0, issued_at=_issue())
    p.debit("acme", 100, period_end=2000.0, issued_at=_issue())
    assert p.available("acme", now=1500.0) == 5900         # inside the period
    assert p.available("acme", now=2000.0) == 0            # period elapsed -> unspent remainder VANISHES
    assert p.available("acme", now=9999.0) == 0            # stays gone (non-rollover)


def test_two_periods_only_live_one_counts():
    s = _store()
    p = _plan(s)
    p.grant("acme", 1000, period_end=100.0, issued_at=_issue())   # old period
    p.grant("acme", 6000, period_end=200.0, issued_at=_issue())   # current period
    assert p.available("acme", now=150.0) == 6000          # old tranche expired, only the current counts
    assert p.available("acme", now=50.0) == 7000           # both live


def test_debit_charged_to_its_own_period_only():
    s = _store()
    p = _plan(s)
    p.grant("acme", 1000, period_end=100.0, issued_at=_issue())
    p.grant("acme", 6000, period_end=200.0, issued_at=_issue())
    p.debit("acme", 900, period_end=100.0, issued_at=_issue())    # drains ONLY the old tranche
    assert p.available("acme", now=50.0) == 100 + 6000     # old: 1000-900=100; new: 6000
    assert p.available("acme", now=150.0) == 6000          # old expired (its debit vanishes with it), new intact


def test_forged_and_replayed_grants_inert():
    s = _store()
    p = _plan(s)
    # attacker-signed grant -> never verifies -> inert
    core = {"signal": PLAN_GRANT_SIGNAL, "org_id": "acme", "entry_id": "x1", "credits": 9999,
            "period_end": 2000.0, "issued_at": 1.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    assert p.available("acme", now=1.0) == 0
    # a real grant, then a replay of the SAME entry_id -> counted once (idempotent)
    seq = p.grant("acme", 500, period_end=2000.0, entry_id="e1", issued_at=_issue())
    captured = s.get(seq).payload
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert p.available("acme", now=1.0) == 500


def test_forged_negative_credit_clamps():
    s = _store()
    p = _plan(s)
    p.grant("acme", 500, period_end=2000.0, issued_at=_issue())
    core = {"signal": PLAN_GRANT_SIGNAL, "org_id": "acme", "entry_id": "neg", "credits": -1000,
            "period_end": 2000.0, "issued_at": 2.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, OWNER)})
    assert p.available("acme", now=1.0) == 500             # negative grant clamped to 0, cannot cancel balance


def test_meter_composes_persistent_and_current_period_plan():
    s = _store()
    w, p, subs = _wallet(s), _plan(s), _subs(s)
    meter = CreditMeter(w, p, subs)
    w.grant("acme", 200, "topup", issued_at=_issue())
    w.grant("acme", 20, "trial", issued_at=_issue())
    subs.subscribe("acme", "pro", 6000, period_start=1.0, period_end=2000.0, issued_at=_issue())
    p.grant("acme", 6000, period_end=2000.0, issued_at=_issue())     # the current period's tranche
    assert meter.available("acme", now=1500.0) == 6220     # 220 persistent + 6000 current-period plan
    assert meter.available("acme", now=2500.0) == 220      # period elapsed -> plan 0; persistent persists
    pos = meter.position("acme", now=1500.0)
    assert pos.persistent == 220 and pos.plan_live == 6000 and pos.available == 6220
    assert meter.available("ghost", now=1.0) == 0          # unknown tenant fail-closed


def test_meter_counts_only_the_current_subscription_period_not_overlapping_tranches():
    # The invariant that closes the Slice-4 red-pen MED: two plan tranches whose windows OVERLAP must NEVER sum
    # to a double allotment. The meter counts ONLY the tranche for the ACTIVE subscription's current period, so a
    # prior / stray tranche is ignored even while it is still unexpired in the raw ledger.
    s = _store()
    w, p, subs = _wallet(s), _plan(s), _subs(s)
    meter = CreditMeter(w, p, subs)
    p.grant("acme", 6000, period_end=1100.0, issued_at=_issue())    # an earlier (overlapping) tranche
    subs.subscribe("acme", "pro", 6000, period_start=600.0, period_end=1600.0, issued_at=_issue())
    p.grant("acme", 6000, period_end=1600.0, issued_at=_issue())    # the current period's tranche
    assert p.available("acme", now=700.0) == 12000                  # raw ledger: BOTH tranches live (diagnostic)
    assert meter.available("acme", now=700.0) == 6000, "meter must count ONLY the current subscription period"


def test_plan_credits_require_an_active_in_period_subscription():
    # Plan credits come from a subscription: no active, in-period subscription -> no plan credits (fail-closed,
    # the dunning/cancel behaviour). Persistent top-ups are unaffected.
    s = _store()
    w, p, subs = _wallet(s), _plan(s), _subs(s)
    meter = CreditMeter(w, p, subs)
    w.grant("acme", 50, "topup", issued_at=_issue())
    subs.subscribe("acme", "pro", 6000, period_start=1.0, period_end=2000.0, issued_at=_issue())
    p.grant("acme", 6000, period_end=2000.0, issued_at=_issue())
    assert meter.available("acme", now=1000.0) == 6050
    subs.mark_past_due("acme")                                      # dunning -> plan credits gone, top-up stays
    assert meter.available("acme", now=1000.0) == 50
    subs.cancel("acme")
    assert meter.available("acme", now=1000.0) == 50


def test_refill_bridge_grants_one_tranche_and_is_idempotent():
    s = _store()
    subs, p = _subs(s), _plan(s)
    subs.subscribe("acme", "pro", 6000, period_start=1000.0, period_end=2000.0, issued_at=_issue())
    seq = refill_active_subscription(subs, p, "acme", issued_at=_issue())
    assert seq is not None and p.available("acme", now=1500.0) == 6000
    base = s.append(kind="event", source="t", actor="u", payload={"i": "marker"})  # count records before re-run
    assert refill_active_subscription(subs, p, "acme", issued_at=_issue()) is None   # idempotent: no new grant
    # no plan record was appended after the marker (append-level idempotency, not just fold-level)
    assert all(r.payload.get("signal") != PLAN_GRANT_SIGNAL for r in s.iter_records(since_seq=base))
    assert p.available("acme", now=1500.0) == 6000


def test_refill_bridge_refuses_non_active_and_rolls_to_new_period():
    s = _store()
    subs, p = _subs(s), _plan(s)
    # no subscription -> nothing to refill
    assert refill_active_subscription(subs, p, "acme", issued_at=_issue()) is None
    # ACTIVE then past_due with NO prior refill for this period: refusal must be the ACTIVE-check itself, not the
    # append-level idempotency guard (which would only fire if a tranche already existed for this period_end).
    subs.subscribe("acme", "starter", 1000, period_start=1.0, period_end=100.0, issued_at=_issue())
    subs.mark_past_due("acme")
    assert refill_active_subscription(subs, p, "acme", issued_at=_issue()) is None
    assert p.tranches("acme") == [], "a past_due tenant must not get a plan tranche (isolates the active-check)"
    # cancel is likewise non-active -> no refill
    subs.cancel("acme")
    assert refill_active_subscription(subs, p, "acme", issued_at=_issue()) is None
    assert p.tranches("acme") == []
    # recover + renew to a NEW active period -> a fresh tranche (non-rollover: nothing carried from before)
    subs.subscribe("acme", "pro", 6000, period_start=100.0, period_end=200.0, issued_at=_issue())
    seq = refill_active_subscription(subs, p, "acme", issued_at=_issue())
    assert seq is not None
    assert p.available("acme", now=150.0) == 6000          # only the new period's tranche is live
    assert {t.period_end for t in p.tranches("acme")} == {200.0}


def test_binding_validation():
    s = _store()
    p = _plan(s)
    for bad in (0.0, -1.0, float("inf"), float("nan")):
        with pytest.raises(ValueError):
            p.grant("acme", 10, period_end=bad, issued_at=_issue())
    for badc in (0, -5):
        with pytest.raises(ValueError):
            p.grant("acme", badc, period_end=2000.0, issued_at=_issue())
    nokey = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    nokey.owner_key = None
    with pytest.raises(ValueError):                        # grant needs the owner key
        nokey.grant("acme", 10, period_end=2000.0, issued_at=_issue())
    with pytest.raises(ValueError):                        # debit needs the owner key
        nokey.debit("acme", 10, period_end=2000.0, issued_at=_issue())


def test_tenants_isolated():
    s = _store()
    p = _plan(s)
    p.grant("orga", 6000, period_end=2000.0, issued_at=_issue())
    p.grant("orgb", 1000, period_end=2000.0, issued_at=_issue())
    p.debit("orgb", 400, period_end=2000.0, issued_at=_issue())
    assert p.available("orga", now=1.0) == 6000
    assert p.available("orgb", now=1.0) == 600
