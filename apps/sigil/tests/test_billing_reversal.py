"""W5 — the owner-signed reversal ledger: disputes, refunds, the arrears they leave, and the billing hold.

Each test is named for the property it proves. The ledger moves credits in a real ``WalletRegistry`` on a real spine
and reads the hold back from the fold — so a weakened guard (the target formula, the cap, the spendable floor, the
order tolerance, the idempotency, the crash recovery) turns a named test red.
"""
from __future__ import annotations

import tempfile

import pytest

from sigil.governor.billing_reversal import (BillingReversalLedger, REASON_DISPUTE, REASON_REFUND, REVERSAL_SIGNAL,
                                             ReversalRefused, apply_billing_reversal, rev_entry_id)
from sigil.governor.wallet import CREDIT_DEBIT_SIGNAL, CREDIT_GRANT_SIGNAL, WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
_K = {"owner_key": OWNER, "trusted_pubkey": OWNER.public_key_b64}


def _rig(*, granted=1000, spent=300):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    w = WalletRegistry(s, **_K)
    L = BillingReversalLedger(s, wallet=w, **_K)
    if granted:
        w.grant("acme", granted, "topup", entry_id="cs_1", issued_at=1.0)
    if spent:
        w.debit("acme", spent, entry_id="spend1", issued_at=2.0)
    return s, w, L


# ---- the full dispute lifecycle --------------------------------------------------------------------------------
def test_a_dispute_opening_removes_the_spendable_credits_and_books_the_spent_part_as_owed():
    _s, w, L = _rig()
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    assert w.available("acme") == 0 and L.owed("acme") == 300 and L.on_hold("acme")
    assert r.removed == 1000 and r.owed == 300 and r.moved == 1000


def test_a_dispute_created_then_won_gives_everything_back_and_clears_the_arrears():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=5.0, disputed=0)      # won: funds reinstated
    assert w.available("acme") == 700 and L.owed("acme") == 0 and not L.on_hold("acme")


def test_a_dispute_created_then_lost_keeps_the_credits_removed():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=5.0, disputed=1000)   # lost: still held
    assert w.available("acme") == 0 and L.owed("acme") == 300 and r.seq is None


def test_funds_withdrawn_then_reinstated_for_a_partial_dispute_restores_exactly_what_it_removed():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=600)
    assert w.available("acme") == 100 and L.owed("acme") == 0
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=5.0, disputed=0)
    assert w.available("acme") == 700 and L.owed("acme") == 0


def test_a_warning_closed_or_prevented_dispute_gives_the_credits_back_like_a_win():
    # the provider maps warning_closed / prevented to disputed=0 (RETURNS_FUNDS); the ledger gives them back
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=5.0, disputed=0)
    assert L.owed("acme") == 0 and w.available("acme") == 700


# ---- idempotency and order tolerance ---------------------------------------------------------------------------
def test_a_duplicate_dispute_event_moves_nothing_the_second_time():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=4.0, disputed=1000)
    assert r.seq is None and r.moved == 0 and L.owed("acme") == 300 and w.available("acme") == 0


def test_an_out_of_order_reinstated_before_created_removes_only_when_the_dispute_actually_holds_funds():
    _s, w, L = _rig()
    r1 = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=0)   # reinstated arrives first
    assert r1.seq is None and L.owed("acme") == 0 and w.available("acme") == 700
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=4.0, disputed=1000)      # created arrives late
    assert L.owed("acme") == 300 and w.available("acme") == 0


# ---- refunds ---------------------------------------------------------------------------------------------------
def test_a_partial_refund_removes_only_the_refunded_credits():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=3.0, processor_refunded=400)
    assert w.available("acme") == 300 and L.owed("acme") == 0


def test_a_full_refund_removes_the_spendable_and_owes_the_spent_part():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=3.0, processor_refunded=1000)
    assert w.available("acme") == 0 and L.owed("acme") == 300


def test_a_refund_growing_from_partial_to_full_removes_only_the_extra():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=3.0, processor_refunded=400)
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=4.0, processor_refunded=1000)
    assert r.moved == 600 and w.available("acme") == 0 and L.owed("acme") == 300


def test_a_refund_of_a_charge_that_also_has_a_dispute_never_removes_more_than_the_purchase_granted():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=4.0, processor_refunded=500, disputed=1000)
    assert r.moved == 0 and L.owed("acme") == 300           # capped at the 1000 granted — no double-remove
    # the refund fact is kept: if the dispute is later won, only the refunded 500 stays removed
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=5.0, disputed=0)
    assert w.available("acme") == 200 and L.owed("acme") == 0


# ---- balances never negative -----------------------------------------------------------------------------------
def test_a_reversal_larger_than_the_balance_books_arrears_and_the_wallet_never_goes_negative():
    _s, w, L = _rig(granted=1000, spent=900)
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    assert w.available("acme") == 0 and w.balance("acme").available == 0 and L.owed("acme") == 900


# ---- repay -----------------------------------------------------------------------------------------------------
def test_the_next_top_up_repays_the_arrears_and_lifts_the_hold_exactly_once():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    assert L.owed("acme") == 300
    w.grant("acme", 500, "topup", entry_id="cs_2", issued_at=6.0)
    res = L.repay("acme", "cs_2", now=7.0)
    assert res.repaid == 300 and L.owed("acme") == 0 and not L.on_hold("acme") and w.available("acme") == 200
    again = L.repay("acme", "cs_2", now=8.0)              # a re-drive repays nothing more
    assert again.repaid == 0 and L.owed("acme") == 0 and w.available("acme") == 200


def test_a_top_up_smaller_than_the_arrears_repays_what_it_can_and_the_hold_stays():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)     # owes 300
    w.grant("acme", 100, "topup", entry_id="cs_2", issued_at=6.0)
    res = L.repay("acme", "cs_2", now=7.0)
    assert res.repaid == 100 and L.owed("acme") == 200 and L.on_hold("acme") and w.available("acme") == 0


def test_repay_is_a_no_op_when_nothing_is_owed():
    _s, w, L = _rig()
    res = L.repay("acme", "cs_2", now=7.0)
    assert res.seq is None and res.repaid == 0 and L.owed("acme") == 0


# ---- crash recovery (a wallet record a crashed step left without its step record) ------------------------------
def test_a_crashed_remove_debit_is_adopted_before_the_next_reconcile_so_nothing_is_debited_twice():
    s, w, L = _rig()
    w.debit("acme", 700, entry_id=rev_entry_id("cs_1", 1), issued_at=3.0)     # a crash: the debit, not its step
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=4.0, disputed=1000)
    assert w.available("acme") == 0 and L.owed("acme") == 300                 # 700 taken once, 300 owed
    assert L.purchase("acme", "cs_1").removed == 1000 and L.purchase("acme", "cs_1").k == 2 and r.seq is not None


def test_a_crashed_repay_debit_is_adopted_and_counts_once():
    s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)   # owes 300
    w.grant("acme", 500, "topup", entry_id="cs_2", issued_at=6.0)
    from sigil.governor.billing_reversal import repay_entry_id
    w.debit("acme", 300, entry_id=repay_entry_id(L.repays("acme") + 1), issued_at=6.5)     # crash: the repay debit
    res = L.repay("acme", "cs_2", now=7.0)
    assert L.owed("acme") == 0 and w.available("acme") == 200                 # the adopted 300 cleared it, no second debit


# ---- the owner refund path -------------------------------------------------------------------------------------
def test_an_owner_refund_removes_unused_credits_through_the_same_path():
    _s, w, L = _rig()
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=3.0, owner_refund=400, unused_only=True)
    assert w.available("acme") == 300 and L.owed("acme") == 0 and r.moved == 400


def test_an_owner_refund_is_refused_when_it_would_exceed_the_unused_balance():
    _s, w, L = _rig()           # available 700
    with pytest.raises(ReversalRefused):
        L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=3.0, owner_refund=800, unused_only=True)
    assert w.available("acme") == 700 and L.owed("acme") == 0        # nothing moved


def test_an_owner_refund_then_a_processor_refund_of_the_same_money_removes_nothing_more():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=3.0, owner_refund=400, unused_only=True)
    r = L.reconcile("acme", "cs_1", cap=1000, reason=REASON_REFUND, now=4.0, processor_refunded=400)
    assert r.moved == 0 and w.available("acme") == 300              # max(processor, owner) — not their sum


# ---- fail-closed fold ------------------------------------------------------------------------------------------
def test_a_replayed_reversal_record_is_counted_once_in_the_fold():
    # the fold's own (org, entry_id) idempotency: a captured remove record re-appended verbatim folds once
    s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)   # owes 300
    remove = next(r.payload for r in s.iter_records(since_seq=-1)
                  if isinstance(r.payload, dict) and r.payload.get("signal") == REVERSAL_SIGNAL
                  and r.payload.get("step") == "remove")
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(remove))   # replay the signed record
    assert L.owed("acme") == 300 and w.available("acme") == 0           # not 600 / not negative


def test_an_unsigned_or_forged_reversal_record_is_inert_in_the_fold():
    s, w, L = _rig()
    # a hand-built unsigned remove for 500 — never verifies, so it moves no arrears and consumes nothing
    s.append(kind="event", source="governor", actor="WARDEN", payload={
        "signal": REVERSAL_SIGNAL, "v": 1, "org_id": "acme", "entry_id": rev_entry_id("cs_1", 1), "step": "remove",
        "cause": "dispute", "ref": "cs_1", "k": 1, "credits": 500, "wallet": 0, "owed": 500, "cap": 1000,
        "removed": 500, "owner_refunded": 0, "processor_refunded": 0, "disputed": 500, "issued_at": 3.0})
    assert L.owed("acme") == 0 and not L.on_hold("acme")


def test_a_reconcile_of_a_purchase_whose_cap_changed_is_refused():
    _s, w, L = _rig()
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    with pytest.raises(ReversalRefused):
        L.reconcile("acme", "cs_1", cap=900, reason=REASON_DISPUTE, now=4.0, disputed=1000)


def test_a_malformed_step_record_is_consumed_but_counts_nothing_even_when_signed():
    # a SIGNED remove whose credits != wallet + owed breaks the step invariant: the fold consumes its key (so a later
    # well-formed copy is still inert) but counts nothing. _append would itself refuse it, so forge it on the spine.
    s, w, L = _rig()
    from sigil.governor.authn import signed_payload
    core = {"signal": REVERSAL_SIGNAL, "v": 1, "org_id": "acme", "entry_id": rev_entry_id("cs_1", 1), "step": "remove",
            "cause": "dispute", "ref": "cs_1", "k": 1, "credits": 500, "wallet": 100, "owed": 100, "cap": 1000,
            "removed": 400, "owner_refunded": 0, "processor_refunded": 0, "disputed": 500, "issued_at": 3.0}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, OWNER), "by": "owner"})
    assert L.owed("acme") == 0 and L.has_entry("acme", rev_entry_id("cs_1", 1))


def test_the_hold_alarm_file_names_an_owing_org_and_drops_it_when_repaid(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    from sigil.governor import billing_hold
    assert billing_hold.sync_hold("acme", 300) and billing_hold.read_holds() == [
        {"org_id": "acme", "owed": 300, "since": billing_hold.read_holds()[0]["since"]}]
    assert billing_hold.sync_hold("acme", 0) and billing_hold.read_holds() == []    # repaid -> dropped


def test_two_orgs_reverse_independently():
    s, w, L = _rig()
    w.grant("globex", 2000, "topup", entry_id="cs_g", issued_at=1.0)
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)
    L.reconcile("globex", "cs_g", cap=2000, reason=REASON_REFUND, now=3.0, processor_refunded=2000)
    assert L.owed("acme") == 300 and L.owed("globex") == 0 and w.available("globex") == 0
    assert sorted(L.holds()) == [("acme", 300)]
