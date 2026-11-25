"""Terms §8 — a refunded PLAN period loses its plan credits in the refunded proportion (the consumer's withdrawal).

Two paths reach the SAME owner-signed ledger step (``BillingReversalLedger.reconcile_plan``): the Stripe drain's refund
of a plan charge (charge -> invoice -> the subscription's metadata -> that org's plan period) and the owner's
``sigil billing-reversal plan-withdraw`` verb (``test_cli_billing_reversal.py``). The rules each named test proves:
the removal is ``allotment x refunded / price``, bounded by what REMAINS of that period's plan tranche (never negative,
never booked as owed), idempotent per invoice (the facts are TOTALS, the owner's and the processor's converge), crash
safe, and a refund never mints credit. A refund VIGIL cannot trace to one credited plan period still quarantines.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import tempfile

import pytest

from sigil.governor.billing import (EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, BillingSigner, Entitlement,
                                    ReversalUnaccounted, StripeBillingProvider)
from sigil.governor.billing_reversal import (REVERSAL_SIGNAL, BillingReversalLedger, ReversalFold, ReversalRefused,
                                             ReversalRetry, apply_billing_reversal, plan_ref, rev_entry_id)
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
_K = {"owner_key": OWNER, "trusted_pubkey": OWNER.public_key_b64}
_WHSEC = "whsec_plan_reversal"
PE = 5_000_000.0                        # the plan period's end (its tranche key)
INV = "in_plan1"
ALLOT, PRICE = 20_000, 9_900            # a 20,000-credit plan period paid $99.00


def _rig(*, allot=ALLOT, used=0, wallet_credits=500):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    w, plan, inv = WalletRegistry(s, **_K), PlanCreditLedger(s, **_K), InvoiceRegistry(s, **_K)
    L = BillingReversalLedger(s, wallet=w, plan=plan, **_K)
    if wallet_credits:
        w.grant("acme", wallet_credits, "topup", entry_id="cs_test_t1", issued_at=1.0)
    plan.grant("acme", allot, period_end=PE, entry_id=f"refill:acme:{PE!r}", issued_at=1.0)
    inv.record("acme", invoice_id=INV, kind="subscription", price_id="vigil_pro_monthly", amount_minor=PRICE,
               currency="USD", credits=allot, period_start=1.0, period_end=PE, issued_at=1.0)
    if used:
        plan.debit("acme", used, period_end=PE, entry_id="reserve-plan:s1:n1", issued_at=2.0)
    return s, w, plan, L


def _left(plan):
    return plan.remaining_for_period("acme", PE)


# ---- the ledger step ------------------------------------------------------------------------------------------------
def test_a_full_refund_of_an_unused_plan_period_removes_all_its_plan_credits_and_nothing_else():
    _s, w, plan, L = _rig()
    r = L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=ALLOT)
    assert _left(plan) == 0 and r.moved == ALLOT and r.removed == ALLOT and r.seq is not None
    assert w.available("acme") == 500 and L.owed("acme") == 0 and not L.on_hold("acme")   # wallet untouched


def test_the_removal_is_bounded_by_what_remains_and_never_goes_negative_or_owed():
    _s, w, plan, L = _rig(used=5_000)                       # 15,000 left; a refund of the whole price
    r = L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=ALLOT)
    assert _left(plan) == 0 and r.moved == 15_000 and r.removed == 15_000
    assert L.owed("acme") == 0 and w.available("acme") == 500
    assert [t.debited for t in plan.tranches("acme")] == [20_000]   # exactly the allotment, never more


def test_a_partial_refund_removes_the_same_proportion_of_the_allotment():
    _s, _w, plan, L = _rig()
    L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, processor_refunded=ALLOT * 2_475 // PRICE)
    assert _left(plan) == ALLOT - 5_000                     # $24.75 of $99.00 = a quarter


def test_running_it_again_with_the_same_total_moves_nothing():
    _s, _w, plan, L = _rig(used=5_000)
    L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=ALLOT)
    again = L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=4.0, owner_refunded=ALLOT)
    assert again.seq is None and again.moved == 0 and _left(plan) == 0


def test_the_owner_and_the_processor_facts_converge_on_one_removal():
    _s, _w, plan, L = _rig()
    L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=10_000)
    r = L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=4.0, processor_refunded=10_000)
    assert r.moved == 0 and _left(plan) == 10_000           # the same refund, seen twice, removes once


def test_credits_that_come_back_to_the_period_are_removed_by_the_next_run():
    s, _w, plan, L = _rig(used=5_000)
    L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=ALLOT)
    plan.grant("acme", 300, period_end=PE, entry_id="settle-plan:s1:n1", issued_at=4.0)   # a launch refunded
    r = L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=5.0, owner_refunded=ALLOT)
    assert r.moved == 300 and _left(plan) == 0


def test_a_refund_that_went_down_is_refused_and_never_mints_credit():
    _s, w, plan, L = _rig()
    L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, processor_refunded=ALLOT)
    with pytest.raises(ReversalRefused, match="never given back"):
        L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=4.0, processor_refunded=0)
    assert _left(plan) == 0 and w.available("acme") == 500


def test_the_owner_total_never_goes_down():
    _s, _w, plan, L = _rig()
    L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=ALLOT)
    r = L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=4.0, owner_refunded=1)
    assert r.seq is None and L.purchase("acme", plan_ref(INV)).owner_refunded == ALLOT


@pytest.mark.parametrize("kw", [dict(cap=0), dict(cap=ALLOT, period_end=0.0), dict(cap=ALLOT, period_end=float("inf")),
                                dict(cap=ALLOT, processor_refunded=-1), dict(cap=ALLOT, owner_refunded=True)])
def test_malformed_plan_steps_are_refused_before_anything_moves(kw):
    _s, _w, plan, L = _rig()
    args = dict(period_end=PE, now=3.0)
    args.update(kw)
    with pytest.raises(ReversalRefused):
        L.reconcile_plan("acme", INV, **args)
    assert _left(plan) == ALLOT


@pytest.mark.parametrize("iid", ["cs_test_t1", "in_", "in_a:b", "plan-in_x", "in_" + "a" * 89, "", None])
def test_a_plan_step_names_its_period_by_a_stripe_invoice_id(iid):
    _s, _w, _plan, L = _rig()
    with pytest.raises(ReversalRefused):
        L.reconcile_plan("acme", iid, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=ALLOT)


def test_the_wallet_reconcile_refuses_a_plan_purchase():
    _s, w, _plan, L = _rig()
    with pytest.raises(ReversalRefused, match="reconcile_plan"):
        L.reconcile("acme", plan_ref(INV), cap=ALLOT, reason="refund", now=3.0, owner_refund=100)
    assert w.available("acme") == 500


def test_a_cap_that_changed_is_refused():
    _s, _w, plan, L = _rig()
    L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=3.0, owner_refunded=1_000)
    with pytest.raises(ReversalRefused, match="reconcile by hand"):
        L.reconcile_plan("acme", INV, cap=ALLOT + 1, period_end=PE, now=4.0, owner_refunded=2_000)


def test_a_crash_between_the_plan_debit_and_its_step_is_adopted_never_debited_twice():
    s, _w, plan, L = _rig()
    eid = rev_entry_id(plan_ref(INV), 1)
    plan.debit("acme", 4_000, period_end=PE, entry_id=eid, issued_at=3.0)   # the step record never landed
    r = L.reconcile_plan("acme", INV, cap=ALLOT, period_end=PE, now=4.0, owner_refunded=4_000)
    assert _left(plan) == ALLOT - 4_000 and r.moved == 0
    st = L.purchase("acme", plan_ref(INV))
    assert st.removed == 4_000 and st.owner_refunded == 4_000       # step 1 adopted (recovered), step 2 the facts
    assert [t.debited for t in plan.tranches("acme")] == [4_000]


def _signed_step(store, **over):
    """An owner-signed reversal record with ``over`` applied (the fold-invariant tests)."""
    from sigil.governor.authn import signed_payload
    from sigil.governor.billing_reversal import _CORE
    ref = over.pop("ref", plan_ref(INV))
    core = {"signal": REVERSAL_SIGNAL, "v": 1, "org_id": "acme", "entry_id": rev_entry_id(ref, 1),
            "step": "plan_remove", "cause": "refund", "ref": ref, "k": 1, "credits": 100, "wallet": 100,
            "owed": 0, "cap": ALLOT, "removed": 100, "owner_refunded": 100, "processor_refunded": 0, "disputed": 0,
            "issued_at": 3.0}
    core.update(over)
    assert set(core) == set(_CORE)
    return signed_payload(core, OWNER)


@pytest.mark.parametrize("over,counts", [
    ({}, True),                                                         # a well-formed plan step
    ({"ref": "cs_test_t1"}, False),                                     # a plan step on a top-up purchase
    ({"step": "remove"}, False),                                        # a wallet removal on a plan purchase
    ({"step": "restore", "owed": 0}, False),                            # a give-back on a plan purchase
    ({"owed": 50, "credits": 150}, False),                              # a plan step that books arrears
    ({"wallet": 99}, False),                                            # credits != the plan debit
    ({"disputed": 1}, False),                                           # a plan step carrying a dispute
])
def test_the_fold_counts_only_a_well_formed_plan_step(over, counts):
    st = ReversalFold()
    apply_billing_reversal(_signed_step(None, **over), OWNER.public_key_b64, st)
    ref = over.get("ref", plan_ref(INV))
    assert ((("acme", ref) in st.refs) is counts) and st.owed("acme") == 0


# ---- the Stripe drain: a refunded plan charge ------------------------------------------------------------------------
def _charge(*, refunded=PRICE, invoice=None, pi="pi_plan1"):
    c = {"object": "charge", "id": "ch_plan1", "livemode": False, "amount": PRICE, "amount_refunded": refunded,
         "currency": "usd", "created": 1000, "payment_intent": pi}
    if invoice is not None:
        c["invoice"] = invoice                                  # API versions before 2025-03-31
    return c


def _invoice(*, status="paid", reason="subscription_create", sub="sub_plan1", amount=PRICE, ccy="usd"):
    return {"object": "invoice", "id": INV, "livemode": False, "status": status, "billing_reason": reason,
            "amount_paid": amount, "currency": ccy,
            "parent": {"type": "subscription_details", "subscription_details": {"subscription": sub}}}


def _sub(*, org="acme", sid="sub_plan1"):
    return {"object": "subscription", "id": sid, "livemode": False, "status": "active",
            "metadata": {"org_id": org, "price_id": "vigil_pro_monthly", "tx_ref": f"vigil:{org}:n1"}}


def _payment(*, invoice=INV, pi="pi_plan1", status="paid", ptype="payment_intent"):
    return {"object": "invoice_payment", "id": "inpay_1", "livemode": False, "invoice": invoice, "status": status,
            "payment": {"type": ptype, "payment_intent": pi}}


class _Drain:
    def __init__(self, *, charge=None, invoice=None, sub=None, payments=None, disputes=(), sessions=(),
                 used=0, allot=ALLOT, record=True):
        s, w, plan, L = _rig(allot=allot, used=used)
        self.store, self.wallet, self.plan, self.L = s, w, plan, L
        if not record:                                           # an invoice VIGIL never credited
            self.invoices = InvoiceRegistry(SpineStore(tempfile.mktemp(suffix=".jsonl")), **_K)
        else:
            self.invoices = InvoiceRegistry(s, **_K)
        self.objects = {o["id"]: o for o in (charge or _charge(), invoice or _invoice(), sub or _sub())}
        self.lists = {"disputes_for_charge": list(disputes), "checkout_sessions_for_payment_intent": list(sessions),
                      "invoice_payments_for_payment_intent": [_payment()] if payments is None else list(payments)}
        self.fetched: list = []
        provider = StripeBillingProvider(_WHSEC, fetcher=self._fetch, expected_mode="test",
                                         enable_reference_adapter=True, reversals=True)
        self.signer = BillingSigner(provider, wallet=w, subscriptions=SubscriptionRegistry(s, **_K), plan=plan,
                                    catalog={"vigil_pro_monthly": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE,
                                                                              plan_id="pro", allotment=allot,
                                                                              period_s=30 * 86400.0),
                                             "price_topup": Entitlement(kind=EVENT_TOPUP, credits=500)},
                                    expected={"vigil_pro_monthly": (PRICE, "USD")}, invoices=self.invoices,
                                    reversals=L)

    def _fetch(self, kind, oid):
        self.fetched.append((kind, oid))
        if kind in self.lists:
            return {"object": "list", "has_more": False, "data": copy.deepcopy(self.lists[kind])}
        # an object our key cannot see comes back as something else (the provider maps it to nothing)
        return copy.deepcopy(self.objects.get(oid, {"object": "unknown", "id": oid, "livemode": False}))

    def send(self, etype="charge.refunded", oid="ch_plan1", t=2000):
        ev = {"id": "evt_r1", "object": "event", "type": etype, "created": t, "livemode": False,
              "data": {"object": {"id": oid}}}
        raw = json.dumps(ev).encode()
        mac = hmac.new(_WHSEC.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
        return self.signer.ingest(raw, f"t={t},v1={mac}", now=float(t))


def test_a_full_refund_of_a_plan_charge_removes_that_periods_plan_credits():
    d = _Drain()
    assert d.send() is not None
    assert _left(d.plan) == 0 and d.wallet.available("acme") == 500 and d.L.owed("acme") == 0
    assert ("invoice_payments_for_payment_intent", "pi_plan1") in d.fetched


def test_a_plan_charge_on_an_older_api_version_maps_through_charge_invoice():
    d = _Drain(charge=_charge(invoice=INV), payments=[])
    assert d.send() is not None and _left(d.plan) == 0
    assert all(k != "invoice_payments_for_payment_intent" for k, _ in d.fetched)


def test_a_partial_refund_of_a_used_plan_removes_its_proportion_bounded_by_what_remains():
    d = _Drain(charge=_charge(refunded=PRICE // 2), used=15_000)      # half refunded; 5,000 left
    d.send()
    assert _left(d.plan) == 0 and d.L.purchase("acme", plan_ref(INV)).removed == 5_000
    assert d.L.owed("acme") == 0                                      # what was used is never owed


def test_a_redelivered_plan_refund_moves_nothing_more():
    d = _Drain(charge=_charge(refunded=PRICE // 2))
    d.send()
    assert d.send(t=2100) is None and _left(d.plan) == ALLOT - ALLOT // 2


def test_a_plan_refund_that_went_down_is_refused_and_mints_nothing():
    d = _Drain()
    d.send()
    d.objects["ch_plan1"]["amount_refunded"] = 0                      # the refund failed after the credits left
    with pytest.raises(ReversalRefused):
        d.send(t=2100)
    assert _left(d.plan) == 0 and d.wallet.available("acme") == 500


@pytest.mark.parametrize("payments", [
    [],                                                               # no invoice paid by it
    [_payment(), dict(_payment(), id="inpay_2")],                     # more than one
    [_payment(status="open")],                                        # not a paid payment
    [_payment(pi="pi_other")],                                        # another PaymentIntent's
    [_payment(ptype="payment_record")],
    [_payment(invoice="cs_test_x")],                                  # not an invoice id
])
def test_a_charge_vigil_cannot_trace_to_one_paid_invoice_quarantines(payments):
    d = _Drain(payments=payments)
    with pytest.raises(ReversalUnaccounted, match="does not belong to one paid invoice"):
        d.send()
    assert _left(d.plan) == ALLOT and not any(k == "invoice" for k, _ in d.fetched)   # refused before any invoice read


@pytest.mark.parametrize("inv", [_invoice(status="open"), _invoice(reason="manual"),
                                 _invoice(reason="subscription_update"), _invoice(ccy="eur"),
                                 _invoice(sub="sub_missing")])
def test_an_invoice_that_is_not_a_credited_plan_period_quarantines(inv):
    d = _Drain(invoice=inv)
    with pytest.raises(ReversalUnaccounted):
        d.send()
    assert _left(d.plan) == ALLOT


@pytest.mark.parametrize("charge,inv", [
    (dict(_charge(refunded=PRICE // 2), amount=PRICE // 2), _invoice()),   # this charge paid half the invoice
    (_charge(), _invoice(amount=PRICE * 2)),                               # the invoice was paid by more than it
])
def test_a_charge_that_paid_only_part_of_its_invoice_quarantines(charge, inv):
    # the proportion is sized against the charge and the refund total is read per charge: a full refund of half
    # the payment must never remove the whole period's allotment
    d = _Drain(charge=charge, invoice=inv)
    with pytest.raises(ReversalUnaccounted, match="did not pay the whole of invoice"):
        d.send()
    assert _left(d.plan) == ALLOT and d.L.purchase("acme", plan_ref(INV)).removed == 0


def test_a_plan_charge_that_is_not_the_price_its_invoice_line_records_quarantines():
    # the charge paid the whole invoice, but not the price VIGIL's billing-history line records (the price the
    # owner's plan-withdraw verb sizes the same refund against): the two paths would size it differently
    d = _Drain(charge=dict(_charge(refunded=9_000), amount=9_000), invoice=_invoice(amount=9_000))
    with pytest.raises(ReversalUnaccounted, match=r"is not the price \(9900\)"):
        d.send()
    assert _left(d.plan) == ALLOT


def test_a_subscription_without_one_tenant_quarantines():
    sub = _sub()
    sub["metadata"]["org_id"] = "other"                               # tx_ref and org_id disagree
    d = _Drain(sub=sub)
    with pytest.raises(ReversalUnaccounted, match="tenant"):
        d.send()
    assert _left(d.plan) == ALLOT


def test_a_disputed_plan_charge_quarantines():
    disp = {"object": "dispute", "id": "du_p1", "livemode": False, "charge": "ch_plan1", "status": "needs_response",
            "amount": PRICE, "currency": "usd"}
    d = _Drain(disputes=[disp])
    d.objects["du_p1"] = disp
    with pytest.raises(ReversalUnaccounted, match="dispute"):
        d.send("charge.dispute.created", "du_p1")
    with pytest.raises(ReversalUnaccounted, match="dispute"):
        d.send()
    assert _left(d.plan) == ALLOT


def test_a_plan_period_vigil_has_not_credited_is_retried():
    d = _Drain(record=False)
    with pytest.raises(ReversalRetry):
        d.send()
    assert _left(d.plan) == ALLOT


def test_a_monitoring_plan_refund_has_no_credits_to_remove_and_quarantines():
    d = _Drain()
    s2 = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    d.signer.invoices = InvoiceRegistry(s2, **_K)
    d.signer.invoices.record("acme", invoice_id=INV, kind="subscription", price_id="vigil_aegis_observe_1h_monthly",
                             amount_minor=PRICE, currency="USD", credits=0, period_start=1.0, period_end=PE,
                             issued_at=1.0)
    with pytest.raises(ReversalUnaccounted, match="no credits"):
        d.send()
    assert _left(d.plan) == ALLOT


def test_a_top_up_refund_still_takes_the_top_up_path():
    sess = {"object": "checkout.session", "id": "cs_test_t1", "livemode": False, "mode": "payment",
            "payment_intent": "pi_plan1", "client_reference_id": "vigil:acme:n1",
            "metadata": {"org_id": "acme", "price_id": "price_topup"}}
    d = _Drain(charge=_charge(refunded=PRICE), sessions=[sess])
    d.signer.invoices.record("acme", invoice_id="cs_test_t1", kind="topup", price_id="price_topup",
                             amount_minor=PRICE, currency="USD", credits=500, issued_at=1.0)
    d.send()
    assert d.wallet.available("acme") == 0 and _left(d.plan) == ALLOT
    assert all(k != "invoice_payments_for_payment_intent" for k, _ in d.fetched)


def test_a_plan_period_whose_tranche_is_not_on_the_spine_yet_is_retried():
    d = _Drain()
    s2 = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    d.signer.plan = PlanCreditLedger(s2, **_K)                        # the invoice line is there, the tranche is not
    with pytest.raises(ReversalRetry, match="not delivered"):
        d.send()
    assert _left(d.plan) == ALLOT


def test_a_plan_refund_in_another_currency_than_its_invoice_line_quarantines():
    d = _Drain()
    s2 = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    d.signer.invoices = InvoiceRegistry(s2, **_K)
    d.signer.invoices.record("acme", invoice_id=INV, kind="subscription", price_id="vigil_pro_monthly",
                             amount_minor=PRICE, currency="EUR", credits=ALLOT, period_start=1.0, period_end=PE,
                             issued_at=1.0)
    with pytest.raises(ReversalUnaccounted, match="EUR"):
        d.send()
    assert _left(d.plan) == ALLOT


# ---- the drain's sweep: plan credits that come back to a refunded plan period -------------------------------------------
def test_the_sweep_removes_plan_credits_a_settled_launch_gives_back_to_a_fully_refunded_period():
    d = _Drain(used=19_000)                          # a launch still running holds 19,000 of the period's 20,000
    d.send()                                         # the WHOLE price refunded: the 1,000 left are removed
    assert _left(d.plan) == 0 and d.L.plan_shortfalls() == [("acme", INV, ALLOT, 1_000, ALLOT)]
    d.plan.grant("acme", 18_900, period_end=PE, entry_id="settle-plan:s1:n1", issued_at=2_500.0)   # it settles
    assert d.signer.sweep_plan_reversals(3_000.0) == [("acme", INV, 18_900)]
    assert _left(d.plan) == 0 and d.L.purchase("acme", plan_ref(INV)).removed == 19_900
    assert d.signer.sweep_plan_reversals(3_100.0) == []                # nothing more to do: it moves nothing
    assert d.wallet.available("acme") == 500 and d.L.owed("acme") == 0


def test_the_sweep_never_removes_more_than_the_refunded_proportion():
    d = _Drain(charge=_charge(refunded=PRICE // 4), used=19_000)       # 25% refunded: 5,000 credits; 1,000 left
    d.send()
    assert d.L.purchase("acme", plan_ref(INV)).removed == 1_000
    d.plan.grant("acme", 18_900, period_end=PE, entry_id="settle-plan:s1:n1", issued_at=2_500.0)
    assert d.signer.sweep_plan_reversals(3_000.0) == [("acme", INV, 4_000)]
    assert d.L.purchase("acme", plan_ref(INV)).removed == 5_000 and _left(d.plan) == 14_900
    assert d.L.plan_shortfalls() == [] and d.signer.sweep_plan_reversals(3_100.0) == []


def test_the_sweep_leaves_an_ended_period_and_a_period_with_nothing_back():
    d = _Drain(used=19_000)
    d.send()
    assert d.signer.sweep_plan_reversals(3_000.0) == []                # nothing came back yet
    d.plan.grant("acme", 18_900, period_end=PE, entry_id="settle-plan:s1:n1", issued_at=2_500.0)
    assert d.signer.sweep_plan_reversals(PE) == [] and _left(d.plan) == 18_900   # ended: its credits expired
    d.signer.reversals = None                                          # VIGIL_BILLING_REVERSALS off: no sweep
    assert d.signer.sweep_plan_reversals(3_000.0) == [] and _left(d.plan) == 18_900


def test_the_sweep_reports_a_period_it_cannot_price_and_still_sweeps_the_others(capsys):
    d = _Drain(used=19_000)
    d.send()
    # a plan step on the spine for an invoice with no billing-history line (reconciled by hand from another copy)
    d.L.reconcile_plan("acme", "in_ghost1", cap=ALLOT, period_end=PE, now=2_100.0, owner_refunded=ALLOT)
    d.plan.grant("acme", 18_900, period_end=PE, entry_id="settle-plan:s1:n1", issued_at=2_500.0)
    assert d.signer.sweep_plan_reversals(3_000.0) == [("acme", INV, 18_900)]
    assert "invoice in_ghost1 of org 'acme' has no matching billing-history line" in capsys.readouterr().err
