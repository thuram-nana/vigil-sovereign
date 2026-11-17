"""W5 — a SIGNED Stripe dispute/refund event is re-fetched and mints a wallet reversal from the FETCHED objects only.

Driven through ``BillingSigner.ingest`` with a real wallet / invoice ledger, the reversal ledger, and a fake Stripe
API (the ``fetcher``). The webhook body is trusted for the event type and the object id, nothing else: the charge,
its amount/amount_refunded, its one dispute's status/amount, and the Checkout Session (top-up + tenant) all come from
the re-fetched objects and the two filtered list reads.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import tempfile

import pytest

from sigil.governor.billing import (EVENT_TOPUP, BillingSigner, Entitlement, ReversalUnaccounted,
                                    StripeBillingProvider)
from sigil.governor.billing_reversal import BillingReversalLedger
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
_K = {"owner_key": OWNER, "trusted_pubkey": OWNER.public_key_b64}
_WHSEC = "whsec_w5_reversal"
# a 1,000-credit top-up costs $10 (1000 minor units in USD at the catalog) — the charge amount is in those minor units
_CATALOG = {"price_topup_1k": Entitlement(kind=EVENT_TOPUP, credits=1000)}
_EXPECTED = {"price_topup_1k": (1000, "USD")}


def _charge(cid="ch_1", *, amount=1000, refunded=0, pi="pi_1", created=1000, livemode=False):
    return {"object": "charge", "id": cid, "livemode": livemode, "amount": amount, "amount_refunded": refunded,
            "currency": "usd", "created": created, "payment_intent": pi}


def _dispute(did="du_1", *, charge="ch_1", status="needs_response", amount=1000, livemode=False):
    return {"object": "dispute", "id": did, "livemode": livemode, "charge": charge, "status": status,
            "amount": amount, "currency": "usd", "created": 1000}


def _refund(rid="re_1", *, charge="ch_1", livemode=False):
    return {"object": "refund", "id": rid, "livemode": livemode, "charge": charge, "amount": 400, "currency": "usd"}


def _session(sid="cs_test_s1", *, org="acme", pi="pi_1", price="price_topup_1k", livemode=False):
    return {"object": "checkout.session", "id": sid, "livemode": livemode, "mode": "payment",
            "status": "complete", "payment_status": "paid", "payment_intent": pi,
            "client_reference_id": f"vigil:{org}:n1", "amount_total": 1000, "currency": "usd", "created": 900,
            "metadata": {"org_id": org, "price_id": price}}


class _Rig:
    def __init__(self, *, reversals=True, objects=(), disputes=None, sessions=None):
        s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
        s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
        self.store = s
        self.wallet = WalletRegistry(s, **_K)
        self.invoices = InvoiceRegistry(s, **_K)
        self.reversals = BillingReversalLedger(s, wallet=self.wallet, **_K)
        self.objects = {o["id"]: o for o in objects}
        self.disputes = {} if disputes is None else dict(disputes)       # charge id -> [dispute, ...]
        self.sessions = {} if sessions is None else dict(sessions)       # pi -> [session, ...]
        for ds in self.disputes.values():                                # a dispute event fetches the dispute by id
            for d in ds:
                self.objects.setdefault(d["id"], d)
        self.fetched: list = []
        self.provider = StripeBillingProvider(_WHSEC, fetcher=self._fetch, expected_mode="test",
                                              enable_reference_adapter=True, reversals=reversals)
        self.signer = BillingSigner(self.provider, wallet=self.wallet, subscriptions=SubscriptionRegistry(s, **_K),
                                    plan=PlanCreditLedger(s, **_K), catalog=_CATALOG, expected=_EXPECTED,
                                    invoices=self.invoices, reversals=self.reversals if reversals else None)

    def topup(self, org="acme", sid="cs_test_s1", credits=1000):
        self.wallet.grant(org, credits, "topup", entry_id=sid, issued_at=1.0)
        self.invoices.record(org, invoice_id=sid, kind="topup", price_id="price_topup_1k", amount_minor=1000,
                             currency="USD", credits=credits, issued_at=1.0)

    def _fetch(self, kind, oid):
        self.fetched.append((kind, oid))
        if kind == "disputes_for_charge":
            return {"object": "list", "url": "/v1/disputes", "has_more": False,
                    "data": [copy.deepcopy(d) for d in self.disputes.get(oid, [])]}
        if kind == "checkout_sessions_for_payment_intent":
            return {"object": "list", "url": "/v1/checkout/sessions", "has_more": False,
                    "data": [copy.deepcopy(x) for x in self.sessions.get(oid, [])]}
        obj = self.objects[oid]
        if isinstance(obj, Exception):
            raise obj
        return copy.deepcopy(obj)

    def send(self, etype, oid, *, eid="evt_1", t=2000, secret=_WHSEC):
        ev = {"id": eid, "object": "event", "type": etype, "created": t, "livemode": False,
              "data": {"object": {"id": oid}}}
        raw = json.dumps(ev).encode()
        mac = hmac.new(secret.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
        return self.signer.ingest(raw, f"t={t},v1={mac}", now=float(t))


# ---- the dispute lifecycle, end to end through the signer ------------------------------------------------------
def test_a_dispute_created_event_removes_credits_from_the_wallet_and_books_arrears():
    r = _Rig(objects=[_charge()], disputes={"ch_1": [_dispute(status="needs_response")]}, sessions={"pi_1": [_session()]})
    r.topup(); r.wallet.debit("acme", 300, entry_id="spend", issued_at=1.5)   # spent 300 of 1000
    assert r.send("charge.dispute.created", "du_1") is not None
    assert r.wallet.available("acme") == 0 and r.reversals.owed("acme") == 300 and r.reversals.on_hold("acme")


def test_a_dispute_won_close_gives_the_credits_back():
    r = _Rig(objects=[_charge()], disputes={"ch_1": [_dispute(status="needs_response")]}, sessions={"pi_1": [_session()]})
    r.topup(); r.wallet.debit("acme", 300, entry_id="spend", issued_at=1.5)
    r.send("charge.dispute.created", "du_1")
    r.disputes["ch_1"] = [_dispute(status="won")]
    assert r.send("charge.dispute.closed", "du_1", eid="evt_2") is not None
    assert r.reversals.owed("acme") == 0 and r.wallet.available("acme") == 700 and not r.reversals.on_hold("acme")


def test_funds_reinstated_gives_the_credits_back():
    r = _Rig(objects=[_charge()], disputes={"ch_1": [_dispute(status="needs_response")]}, sessions={"pi_1": [_session()]})
    r.topup(); r.wallet.debit("acme", 300, entry_id="spend", issued_at=1.5)
    r.send("charge.dispute.funds_withdrawn", "du_1")
    r.disputes["ch_1"] = [_dispute(status="won")]
    assert r.send("charge.dispute.funds_reinstated", "du_1", eid="evt_2") is not None
    assert r.reversals.owed("acme") == 0 and r.wallet.available("acme") == 700


def test_a_lost_dispute_keeps_the_credits_removed():
    r = _Rig(objects=[_charge()], disputes={"ch_1": [_dispute(status="needs_response")]}, sessions={"pi_1": [_session()]})
    r.topup(); r.wallet.debit("acme", 300, entry_id="spend", issued_at=1.5)
    r.send("charge.dispute.created", "du_1")
    r.disputes["ch_1"] = [_dispute(status="lost")]
    r.send("charge.dispute.closed", "du_1", eid="evt_2")
    assert r.reversals.owed("acme") == 300 and r.wallet.available("acme") == 0


def test_duplicate_and_out_of_order_dispute_events_converge_on_the_fresh_stripe_state():
    r = _Rig(objects=[_charge()], disputes={"ch_1": [_dispute(status="needs_response")]}, sessions={"pi_1": [_session()]})
    r.topup(); r.wallet.debit("acme", 300, entry_id="spend", issued_at=1.5)
    r.send("charge.dispute.created", "du_1")
    r.send("charge.dispute.created", "du_1", eid="evt_dup")        # a duplicate delivery -> no change
    r.send("charge.dispute.updated", "du_1", eid="evt_upd")        # another no-change event
    assert r.reversals.owed("acme") == 300 and r.wallet.available("acme") == 0


# ---- refunds ---------------------------------------------------------------------------------------------------
def test_a_charge_refunded_event_removes_the_refunded_credits():
    r = _Rig(objects=[_charge(refunded=400)], disputes={"ch_1": []}, sessions={"pi_1": [_session()]})
    r.topup()                                    # unspent 1000
    assert r.send("charge.refunded", "ch_1") is not None
    assert r.wallet.available("acme") == 600 and r.reversals.owed("acme") == 0


def test_a_refund_created_event_removes_the_refunded_credits():
    r = _Rig(objects=[_charge(refunded=400), _refund()], disputes={"ch_1": []}, sessions={"pi_1": [_session()]})
    r.topup()
    assert r.send("refund.created", "re_1") is not None
    assert r.wallet.available("acme") == 600


def test_a_partial_refund_of_a_spent_top_up_books_the_rest_as_owed():
    r = _Rig(objects=[_charge(refunded=1000)], disputes={"ch_1": []}, sessions={"pi_1": [_session()]})
    r.topup(); r.wallet.debit("acme", 500, entry_id="spend", issued_at=1.5)   # spent 500
    r.send("charge.refunded", "ch_1")
    assert r.wallet.available("acme") == 0 and r.reversals.owed("acme") == 500


# ---- the top-up repay ------------------------------------------------------------------------------------------
def test_a_new_top_up_repays_the_arrears_then_lifts_the_hold():
    r = _Rig(objects=[_charge()], disputes={"ch_1": [_dispute(status="needs_response")]}, sessions={"pi_1": [_session()]})
    r.topup(); r.wallet.debit("acme", 300, entry_id="spend", issued_at=1.5)
    r.send("charge.dispute.created", "du_1")
    assert r.reversals.on_hold("acme")
    # a second top-up arrives as a paid Checkout Session -> its grant, then arrears repaid
    r.objects["cs_test_s2"] = _session(sid="cs_test_s2")
    raw = {"id": "evt_t2", "object": "event", "type": "checkout.session.completed", "created": 3000,
           "livemode": False, "data": {"object": {"id": "cs_test_s2"}}}
    body = json.dumps(raw).encode()
    mac = hmac.new(_WHSEC.encode(), b"3000." + body, hashlib.sha256).hexdigest()
    assert r.signer.ingest(body, f"t=3000,v1={mac}", now=3000.0) is not None
    assert r.reversals.owed("acme") == 0 and not r.reversals.on_hold("acme") and r.wallet.available("acme") == 700


# ---- fail-closed -----------------------------------------------------------------------------------------------
def test_a_charge_that_is_not_a_credited_top_up_is_refused():
    r = _Rig(objects=[_charge()], disputes={"ch_1": []}, sessions={"pi_1": [_session()]})
    # no top-up recorded for this session -> the reversal cannot be priced
    from sigil.governor.billing_reversal import ReversalRetry
    with pytest.raises((ReversalUnaccounted, ReversalRetry)):
        r.send("charge.refunded", "ch_1")
    assert r.reversals.owed("acme") == 0


def test_a_dispute_with_an_unknown_status_is_refused():
    r = _Rig(objects=[_charge()], disputes={"ch_1": [_dispute(status="martian")]}, sessions={"pi_1": [_session()]})
    r.topup()
    with pytest.raises(ReversalUnaccounted):
        r.send("charge.dispute.created", "du_1")
    assert r.reversals.owed("acme") == 0 and r.wallet.available("acme") == 1000


def test_more_than_one_dispute_for_the_charge_is_refused():
    r = _Rig(objects=[_charge()], sessions={"pi_1": [_session()]},
             disputes={"ch_1": [_dispute(did="du_1"), _dispute(did="du_2")]})
    r.topup()
    with pytest.raises(ReversalUnaccounted):
        r.send("charge.dispute.created", "du_1")
    assert r.reversals.owed("acme") == 0 and r.wallet.available("acme") == 1000


def test_more_than_one_checkout_session_for_the_payment_intent_is_refused():
    r = _Rig(objects=[_charge()], disputes={"ch_1": []},
             sessions={"pi_1": [_session(sid="cs_test_s1"), _session(sid="cs_test_s2")]})
    r.topup()
    with pytest.raises(ReversalUnaccounted):
        r.send("charge.refunded", "ch_1")


def test_with_reversals_off_a_dispute_event_mints_nothing_and_fetches_nothing():
    r = _Rig(reversals=False, objects=[_charge()], disputes={"ch_1": [_dispute()]}, sessions={"pi_1": [_session()]})
    r.topup()
    assert r.send("charge.dispute.created", "du_1") is None
    assert r.fetched == [] and r.reversals.owed("acme") == 0 and r.wallet.available("acme") == 1000
