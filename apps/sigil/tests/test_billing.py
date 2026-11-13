"""Behavioral + security tests for the payment-provider boundary (`governor/billing.py`).

Load-bearing invariants (a false-green would let a forged/tampered/stale webhook mint credits, let an on-the-wire
amount decide money, let a replay double-credit, or mint against a guessed tenant):
  * verify-then-mint: a webhook that does NOT verify (forged/tampered sig, stale/future timestamp, malformed)
    mints NOTHING — the signer never calls a mint on an unverified event;
  * the credited amount / plan comes ONLY from the owner-controlled catalog keyed by the paid price_id, never
    from a field on the wire;
  * idempotent by provider event_id: a duplicate delivery / replay does not double-credit (fold-level dedup);
  * org_id is validated (org_id == tenant_id) — an event with a missing/invalid tenant is ignored;
  * the deterministic kind→mint mapping (topup→wallet, active→subscribe+refill, canceled→cancel,
    payment_failed→past_due) is exactly as specified; no LLM, no agent-asserted field.
Slice 4 adds NO new spine state — it composes the (already prune-durable) wallet/subscription/plan ledgers — so
there is no fold/prune harness here; replay-across-prune is covered by those ledgers' own suites.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import tempfile

import pytest

from sigil.governor.billing import (CAP_HOSTED_CHECKOUT, CAP_MOBILE_MONEY, CAP_REFUND, CAP_UNATTENDED_TOPUP,
                                     CAP_VERIFY_WEBHOOK, EVENT_PAYMENT_FAILED, EVENT_SUBSCRIPTION_ACTIVE,
                                     EVENT_SUBSCRIPTION_CANCELED, EVENT_TOPUP, BillingSigner, CheckoutSession,
                                     Entitlement, FlutterwaveBillingProvider, MockBillingProvider,
                                     StripeBillingProvider, UnsupportedCapability)
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import CreditMeter, PlanCreditLedger
from sigil.governor.subscription import (STATUS_ACTIVE, STATUS_CANCELED, STATUS_PAST_DUE,
                                          SubscriptionRegistry)
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)


def _rig():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    plan = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    meter = CreditMeter(w, plan, subs)
    catalog = {
        "price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200),
        "price_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000, period_s=1000.0),
    }
    mock = MockBillingProvider("sek")
    signer = BillingSigner(mock, wallet=w, subscriptions=subs, plan=plan, catalog=catalog)
    return s, w, subs, plan, meter, mock, signer


def _mk(mock, d):
    body = json.dumps(d).encode()
    return body, mock.sign(body)


def _inv_rig(expected=None):
    """A mock-provider rig WITH an invoice ledger + the owner catalog's expected amounts, so the signer records
    one owner-signed billing-history line per value-granting mint (Slice H). `expected` defaults to a priced
    catalog; pass {} to model an unpriced catalog. Returns (store, invoices, mock, signer)."""
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    plan = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    inv = InvoiceRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    catalog = {
        "price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200),
        "price_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000, period_s=1000.0),
    }
    exp = {"price_topup_200": (4900, "USD"), "price_pro": (9900, "USD")} if expected is None else expected
    mock = MockBillingProvider("sek")
    signer = BillingSigner(mock, wallet=w, subscriptions=subs, plan=plan, catalog=catalog,
                           expected=exp, invoices=inv)
    return s, inv, mock, signer


# ---- Slice H: a value-granting mint ALSO records an owner-signed invoice (catalog-priced, idempotent) -----
def test_topup_emits_an_invoice_with_the_catalog_amount():
    _s, inv, mock, signer = _inv_rig()
    body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200"})
    assert signer.ingest(body, sig, now=100.0) is not None
    invs = inv.invoices("acme")
    assert len(invs) == 1
    i = invs[0]
    # MONEY DOCTRINE: the mock event carries NO amount (amount_minor defaults to 0), yet the line records the
    # owner-CATALOG price (4900 USD) — the amount is catalog-derived, never read off the wire.
    assert (i.kind, i.price_id, i.amount_minor, i.currency, i.credits) == \
        ("topup", "price_topup_200", 4900, "USD", 200)
    signer.ingest(body, sig, now=100.0)                 # replay (same event_id)
    assert len(inv.invoices("acme")) == 1, "a replayed webhook must not duplicate the invoice line"


def test_only_a_paid_topup_counts_as_a_credit_purchase():
    s, inv, mock, signer = _inv_rig()
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    # credits that were GRANTED, not bought: a trial, a plan refill, a settle refund, even a hand-made "topup"
    # wallet grant — none writes an invoice, so none is a purchase
    for i, kind in enumerate(("trial", "subscription_refill", "refund", "topup")):
        w.grant("acme", 500, kind, entry_id=f"grant_{i}", issued_at=float(10 + i))
    assert w.available("acme") == 2_000 and inv.has_purchased_credits("acme") is False
    body, sig = _mk(mock, {"event_id": "sub_1", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                           "created": 50.0, "price_id": "price_pro"})
    assert signer.ingest(body, sig, now=50.0) is not None
    assert inv.has_purchased_credits("acme") is False, "a plan subscription is not a credit purchase"
    body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200"})
    assert signer.ingest(body, sig, now=100.0) is not None
    assert inv.has_purchased_credits("acme") is True
    assert inv.has_purchased_credits("globex") is False


def test_subscription_emits_an_invoice_with_the_period():
    _s, inv, mock, signer = _inv_rig()
    body, sig = _mk(mock, {"event_id": "sub_1", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                           "created": 500.0, "price_id": "price_pro"})
    assert signer.ingest(body, sig, now=500.0) is not None
    invs = inv.invoices("acme")
    assert len(invs) == 1
    i = invs[0]
    assert (i.kind, i.price_id, i.amount_minor, i.credits) == ("subscription", "price_pro", 9900, 6000)
    assert (i.period_start, i.period_end) == (500.0, 1500.0)   # created, created + period_s


def test_dunning_and_cancel_events_record_no_invoice():
    _s, inv, mock, signer = _inv_rig()
    for kind in (EVENT_PAYMENT_FAILED, EVENT_SUBSCRIPTION_CANCELED):
        body, sig = _mk(mock, {"event_id": f"d_{kind}", "kind": kind, "org_id": "acme", "created": 100.0,
                               "price_id": ""})
        signer.ingest(body, sig, now=100.0)
    assert inv.invoices("acme") == [], "a dunning/cancel event is not a charge — it records no billing line"


def test_invoice_amount_is_zero_when_the_catalog_does_not_price_it():
    # when the owner catalog does not price a price_id (no `expected` entry), the line records amount 0 but STILL
    # records the credits/plan — the money amount is never guessed from the wire (fail-closed to 0).
    _s, inv, mock, signer = _inv_rig(expected={})
    body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200"})
    signer.ingest(body, sig, now=100.0)
    i = inv.invoices("acme")[0]
    assert (i.amount_minor, i.currency, i.credits) == (0, "", 200)


def test_pathological_event_id_mints_nothing_on_both_value_paths():
    # red-pen FINDING 1: an event_id too long / with control chars must fail the WHOLE value-granting event
    # CLOSED (mint nothing), SYMMETRIC across top-up and subscription — never the half-mint where a subscription
    # commits (subscribe/refill don't touch event_id) while only its invoice silently drops.
    from sigil.governor.subscription import SubscriptionRegistry
    s, inv, mock, signer = _inv_rig()
    bad = "x" * 200
    body, sig = _mk(mock, {"event_id": bad, "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200"})
    assert signer.ingest(body, sig, now=100.0) is None               # top-up: mint nothing
    body, sig = _mk(mock, {"event_id": bad, "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                           "created": 100.0, "price_id": "price_pro"})
    assert signer.ingest(body, sig, now=100.0) is None               # subscription: mint nothing (was half-mint)
    assert SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP).subscription("acme") is None  # NOT active
    assert inv.invoices("acme") == []


def test_whitespace_only_event_id_mints_nothing_on_both_value_paths():
    # red-pen completeness-critic: a whitespace-only event_id (" ") must fail CLOSED at apply()'s bound (which
    # now .strip()s to match the ledgers) — never pass apply() yet strip to "" inside record()/grant() and
    # half-mint a subscription. Symmetric across top-up and subscription.
    from sigil.governor.subscription import SubscriptionRegistry
    s, inv, mock, signer = _inv_rig()
    body, sig = _mk(mock, {"event_id": "   ", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200"})
    assert signer.ingest(body, sig, now=100.0) is None
    body, sig = _mk(mock, {"event_id": " ", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                           "created": 100.0, "price_id": "price_pro"})
    assert signer.ingest(body, sig, now=100.0) is None
    assert SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP).subscription("acme") is None  # NOT active
    assert inv.invoices("acme") == []


def test_stale_out_of_order_subscription_records_no_invoice():
    # red-pen FINDING 2: an older subscription event delivered AFTER a newer one (distinct event_id, smaller
    # created) is a stale LWW no-op mint -> it must record NO invoice line (the history must never show a period
    # the plan ledger never granted).
    s, inv, mock, signer = _inv_rig()
    b1, s1 = _mk(mock, {"event_id": "evt_new", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                        "created": 200.0, "price_id": "price_pro"})
    assert signer.ingest(b1, s1, now=200.0) is not None
    b2, s2 = _mk(mock, {"event_id": "evt_old", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                        "created": 100.0, "price_id": "price_pro"})      # out of order, distinct id
    signer.ingest(b2, s2, now=200.0)
    assert [i.invoice_id for i in inv.invoices("acme")] == ["evt_new"], "the stale event must record no invoice"


def test_no_invoice_ledger_is_backward_compatible():
    # a signer built WITHOUT an invoice ledger (the pre-H default) still mints money and emits no invoice.
    _s, w, _subs, _plan, _m, mock, signer = _rig()
    body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200"})
    assert signer.ingest(body, sig, now=100.0) is not None and w.available("acme") == 200
    assert signer.invoices is None


# ---- the signer: verify-then-mint, catalog amounts, idempotency, mapping ------------------------------
def test_topup_mints_and_replay_is_idempotent():
    _s, w, _subs, _plan, _m, mock, signer = _rig()
    body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200"})
    assert signer.ingest(body, sig, now=100.0) is not None
    assert w.available("acme") == 200
    signer.ingest(body, sig, now=100.0)                 # replay (same event_id)
    assert w.available("acme") == 200, "a replayed webhook must not double-credit (fold-level dedup)"


def test_forged_signature_mints_nothing():
    _s, w, _subs, _plan, _m, mock, signer = _rig()
    body, _sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                            "price_id": "price_topup_200"})
    assert signer.ingest(body, "deadbeef", now=100.0) is None    # bad sig
    assert signer.ingest(body + b" ", mock.sign(body), now=100.0) is None   # tampered body vs captured sig
    assert w.available("acme") == 0, "an unverified webhook must mint nothing"


def test_amount_comes_from_catalog_not_the_wire():
    _s, w, _subs, _plan, _m, mock, signer = _rig()
    # the wire carries a huge 'credits' field; the signer must ignore it and grant the CATALOG's 200.
    body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_topup_200", "credits": 999999, "data": {"credits": 999999}})
    signer.ingest(body, sig, now=100.0)
    assert w.available("acme") == 200, "credits must come from the catalog, never a field on the wire"


def test_unknown_price_mints_nothing():
    _s, w, _subs, _plan, _m, mock, signer = _rig()
    body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": "acme", "created": 100.0,
                           "price_id": "price_not_in_catalog"})
    assert signer.ingest(body, sig, now=100.0) is None
    assert w.available("acme") == 0


def test_invalid_org_id_is_ignored():
    _s, w, _subs, _plan, _m, mock, signer = _rig()
    for bad in ("", "Bad/Org", "x" * 65):
        body, sig = _mk(mock, {"event_id": "evt_1", "kind": EVENT_TOPUP, "org_id": bad, "created": 100.0,
                               "price_id": "price_topup_200"})
        assert signer.ingest(body, sig, now=100.0) is None, f"event with invalid org_id {bad!r} must be ignored"


def test_subscription_active_subscribes_and_refills():
    _s, _w, subs, _plan, meter, mock, signer = _rig()
    body, sig = _mk(mock, {"event_id": "evt_2", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                           "created": 100.0, "price_id": "price_pro"})
    assert signer.ingest(body, sig, now=100.0) is not None
    assert subs.subscription("acme").plan_id == "pro"
    assert meter.available("acme", now=500.0) == 6000           # inside the period (100 + 1000)
    assert meter.available("acme", now=2000.0) == 0             # period elapsed -> non-rollover
    signer.ingest(body, sig, now=100.0)                         # replay -> inert
    assert meter.available("acme", now=500.0) == 6000


def test_renewal_advances_the_period():
    _s, _w, _subs, _plan, meter, mock, signer = _rig()
    b1, s1 = _mk(mock, {"event_id": "evt_a", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                        "created": 100.0, "price_id": "price_pro"})
    signer.ingest(b1, s1, now=100.0)
    b2, s2 = _mk(mock, {"event_id": "evt_b", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                        "created": 2000.0, "price_id": "price_pro"})        # a later renewal (created advances)
    signer.ingest(b2, s2, now=2000.0)
    assert meter.available("acme", now=2500.0) == 6000          # the new period (2000+1000) is live
    assert meter.available("acme", now=1500.0) == 6000          # (old period also live at 1500, pre-expiry)


def test_overlapping_active_events_do_not_double_the_allotment():
    # The Slice-4 red-pen MED, now closed: two DISTINCT subscription_active events whose derived periods overlap
    # must NOT give the tenant 2x the allotment. The meter counts only the current subscription period's tranche.
    _s, _w, _subs, _plan, meter, mock, signer = _rig()
    b1, s1 = _mk(mock, {"event_id": "evt_a", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                        "created": 100.0, "price_id": "price_pro"})      # period [100,1100]
    signer.ingest(b1, s1, now=100.0)
    b2, s2 = _mk(mock, {"event_id": "evt_b", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme",
                        "created": 600.0, "price_id": "price_pro"})      # period [600,1600] — overlaps [600,1100]
    signer.ingest(b2, s2, now=600.0)
    assert meter.available("acme", now=700.0) == 6000, "overlapping tranches must not sum to a double allotment"


def test_cancel_and_payment_failed_map_to_safe_direction():
    _s, _w, subs, _plan, _m, mock, signer = _rig()
    bA, sA = _mk(mock, {"event_id": "e1", "kind": EVENT_SUBSCRIPTION_ACTIVE, "org_id": "acme", "created": 100.0,
                        "price_id": "price_pro"})
    signer.ingest(bA, sA, now=100.0)
    bF, sF = _mk(mock, {"event_id": "e2", "kind": EVENT_PAYMENT_FAILED, "org_id": "acme", "created": 200.0})
    signer.ingest(bF, sF, now=200.0)
    assert subs.subscription("acme").status == STATUS_PAST_DUE
    bC, sC = _mk(mock, {"event_id": "e3", "kind": EVENT_SUBSCRIPTION_CANCELED, "org_id": "acme", "created": 300.0})
    signer.ingest(bC, sC, now=300.0)
    assert subs.subscription("acme").status == STATUS_CANCELED


def test_mock_provider_rejects_malformed():
    mock = MockBillingProvider("sek")
    assert mock.verify_and_parse(b"not json", mock.sign(b"not json"), now=1.0) is None
    good = json.dumps({"event_id": "e", "kind": EVENT_TOPUP, "org_id": "acme", "created": 1.0}).encode()
    assert mock.verify_and_parse(good, "", now=1.0) is None                     # empty sig
    assert mock.verify_and_parse(json.dumps({"kind": "nope", "event_id": "e", "org_id": "a", "created": 1.0}).encode(),
                                 mock.sign(json.dumps({"kind": "nope", "event_id": "e", "org_id": "a",
                                                       "created": 1.0}).encode()), now=1.0) is None  # unknown kind


# ---- the Stripe provider: HMAC signature scheme + server-side re-fetch ----------------------------------
_SECRET = "whsec_test_123"


def _stripe_sub(org="acme", price="price_pro"):
    return {"object": "subscription", "id": "sub_1", "livemode": False,
            "metadata": {"org_id": org, "price_id": price}}


def _stripe_invoice(billing_reason="subscription_cycle", status="paid", paid_at=1000):
    return {"object": "invoice", "id": "in_1", "livemode": False, "status": status, "billing_reason": billing_reason,
            "subscription": "sub_1", "amount_paid": 5000, "currency": "usd", "created": 990,
            "status_transitions": {"paid_at": paid_at}}


def _stripe(objs=None, **kw):
    """The Stripe adapter with a fake fetcher serving `objs` (by id)."""
    table = {"in_1": _stripe_invoice(), "sub_1": _stripe_sub()} if objs is None else objs

    def fetch(kind, oid):
        return table[oid]
    return StripeBillingProvider(_SECRET, fetcher=fetch, expected_mode="test", enable_reference_adapter=True, **kw)


def _stripe_body(etype="invoice.paid", oid="in_1", eid="evt_s1", created=1000):
    return json.dumps({"id": eid, "type": etype, "created": created, "livemode": False,
                       "data": {"object": {"id": oid}}}).encode()


def _sig(secret, t, body):
    mac = hmac.new(secret.encode(), str(t).encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


def test_stripe_valid_signature_parses():
    p = _stripe()
    body = _stripe_body()
    ev = p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0)
    assert ev is not None and ev.kind == EVENT_SUBSCRIPTION_ACTIVE and ev.org_id == "acme" \
        and ev.price_id == "price_pro" and ev.event_id == "in_1" and ev.amount_minor == 5000 and ev.currency == "USD"


def test_stripe_rejects_bad_tampered_stale_and_malformed_sig():
    p = _stripe(tolerance_s=300.0)
    body = _stripe_body()
    good = _sig(_SECRET, 1000, body)
    assert p.verify_and_parse(body, "t=1000,v1=deadbeef", now=1000.0) is None      # wrong MAC
    assert p.verify_and_parse(body, _sig("whsec_other", 1000, body), now=1000.0) is None  # wrong secret
    assert p.verify_and_parse(body + b"x", good, now=1000.0) is None               # tampered body
    assert p.verify_and_parse(body, good, now=1000.0 + 600) is None                # stale (outside tolerance)
    assert p.verify_and_parse(body, good, now=1000.0 - 600) is None                # future-dated
    assert p.verify_and_parse(body, "v1=abc", now=1000.0) is None                  # missing t
    assert p.verify_and_parse(body, "t=1000", now=1000.0) is None                  # missing v1
    assert p.verify_and_parse(body, "", now=1000.0) is None                        # empty header


def test_stripe_accepts_any_valid_v1_on_rotation():
    p = _stripe()
    body = _stripe_body()
    mac = hmac.new(_SECRET.encode(), b"1000." + body, hashlib.sha256).hexdigest()
    hdr = f"t=1000,v1=deadbeef,v1={mac}"            # one bad + one good v1 (secret rotation) -> accepted
    assert p.verify_and_parse(body, hdr, now=1000.0) is not None


def test_stripe_ignores_unmapped_and_missing_org():
    p = _stripe()
    body = _stripe_body(etype="charge.updated")                 # not a minted type
    assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None
    sub = _stripe_sub()
    sub["metadata"] = {"price_id": "price_pro"}                 # the fetched subscription names no tenant
    p2 = _stripe({"in_1": _stripe_invoice(), "sub_1": sub})
    body2 = _stripe_body()
    assert p2.verify_and_parse(body2, _sig(_SECRET, 1000, body2), now=1000.0) is None


def test_stripe_ignores_mid_cycle_invoice_billing_reason():
    # Only subscription_create / subscription_cycle invoices advance the period; a mid-cycle proration/update
    # invoice (which Stripe genuinely emits) must be ignored, or it would mint a second overlapping allotment.
    body = _stripe_body()
    for reason in ("subscription_update", "manual", "subscription_threshold", "", None):
        p = _stripe({"in_1": _stripe_invoice(billing_reason=reason), "sub_1": _stripe_sub()})
        assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None, \
            f"invoice.paid with billing_reason={reason!r} must be ignored"
    for reason in ("subscription_cycle", "subscription_create"):
        p = _stripe({"in_1": _stripe_invoice(billing_reason=reason), "sub_1": _stripe_sub()})
        assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is not None


def test_stripe_subscription_mode_checkout_is_ignored():
    # a subscription-mode session is minted by its invoice.paid, never as a top-up
    session = {"object": "checkout.session", "id": "cs_test_a1", "livemode": False, "mode": "subscription",
               "status": "complete", "payment_status": "paid", "client_reference_id": "vigil:acme:n1",
               "amount_total": 5000, "currency": "usd", "created": 1000}
    p = _stripe({"cs_test_a1": session})
    body = _stripe_body(etype="checkout.session.completed", oid="cs_test_a1")
    assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None


def test_stripe_timestamp_must_be_plain_ascii_digits():
    """`t` is decimal ASCII digits only. Non-ASCII digits used to pass float() and then crash on encode("ascii");
    exponent, sign, whitespace and nan/inf forms are refused too (all return None, never raise)."""
    p = _stripe()
    body = _stripe_body()
    mac = hmac.new(_SECRET.encode(), b"1000." + body, hashlib.sha256).hexdigest()
    for t in ("１０００", "١٠٠٠", "1e3", "+1000", " 1000", "nan", "inf", "-1000", "1000.0", "",
              "1" * 13, "1" * 5000):
        assert p.verify_and_parse(body, f"t={t},v1={mac}", now=1000.0) is None, t
    assert p.verify_and_parse(body, f"t=1000,v1={mac}", now=1000.0) is not None      # negative control


def test_stripe_tolerance_edge_is_inclusive():
    p = _stripe(tolerance_s=300.0)
    body = _stripe_body()
    good = _sig(_SECRET, 1000, body)
    assert p.verify_and_parse(body, good, now=1300.0) is not None and p.verify_and_parse(body, good, now=700.0)
    assert p.verify_and_parse(body, good, now=1301.0) is None and p.verify_and_parse(body, good, now=699.0) is None


def test_stripe_v1_must_be_lowercase_hex_sha256():
    p = _stripe()
    body = _stripe_body()
    mac = hmac.new(_SECRET.encode(), b"1000." + body, hashlib.sha256).hexdigest()
    for v1 in (mac.upper(), mac[:-1], mac + "0", "ｆ" * 64, " " + mac):
        assert p.verify_and_parse(body, f"t=1000,v1={v1}", now=1000.0) is None, v1
    assert p.verify_and_parse(body, f"t=1000,v1={mac}", now=1000.0) is not None


def test_stripe_paid_invoice_without_a_stable_time_mints_nothing():
    body = _stripe_body()
    for paid_at in (None, 0, -5, "nan", "1000", 1000.5, True, 10 ** 13):
        p = _stripe({"in_1": _stripe_invoice(paid_at=paid_at), "sub_1": _stripe_sub()})
        assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None, paid_at


def test_stripe_secret_fetcher_and_mode_required():
    fetch = lambda kind, oid: {}                                                    # noqa: E731
    with pytest.raises(ValueError):
        StripeBillingProvider("", fetcher=fetch, expected_mode="test", enable_reference_adapter=True)
    with pytest.raises(ValueError):
        StripeBillingProvider(_SECRET, fetcher=None, expected_mode="test",           # type: ignore[arg-type]
                              enable_reference_adapter=True)
    for mode in ("", "prod", "LIVE", None):
        with pytest.raises(ValueError):
            StripeBillingProvider(_SECRET, fetcher=fetch, expected_mode=mode,         # type: ignore[arg-type]
                                  enable_reference_adapter=True)


# ---- Stripe disabled-by-default guard ----------------------------------------------------------------
def test_stripe_disabled_by_default():
    fetch = lambda kind, oid: {}                                                    # noqa: E731
    with pytest.raises(UnsupportedCapability):
        StripeBillingProvider("whsec_x", fetcher=fetch, expected_mode="test")       # no opt-in -> refuses
    assert StripeBillingProvider("whsec_x", fetcher=fetch, expected_mode="test",
                                 enable_reference_adapter=True) is not None         # explicit flag
    import os
    _prev = os.environ.get("VIGIL_BILLING_ENABLE_STRIPE")
    os.environ["VIGIL_BILLING_ENABLE_STRIPE"] = "1"
    try:
        assert StripeBillingProvider("whsec_x", fetcher=fetch, expected_mode="test") is not None   # env opt-in
    finally:
        if _prev is None:
            os.environ.pop("VIGIL_BILLING_ENABLE_STRIPE", None)
        else:
            os.environ["VIGIL_BILLING_ENABLE_STRIPE"] = _prev


# ---- Flutterwave provider (primary) — verif-hash + MANDATORY server-side re-verify -------------------
_FLW_SECRET = "flw-secret-hash-xyz"


def _verifier(table):
    def v(txid):
        return table.get(str(txid))
    return v


def _flw_rig(table):
    s, w, subs, plan, meter, _mock, _signer = _rig()
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier(table))
    signer = BillingSigner(flw, wallet=w, subscriptions=subs, plan=plan, catalog={
        "price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200),
        "flwplan_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000, period_s=1000.0),
    })
    return s, w, subs, plan, meter, flw, signer


def _flw_wh(event, txid):
    return json.dumps({"event": event, "data": {"id": txid}}).encode()


def test_flutterwave_requires_secret_and_verifier():
    with pytest.raises(ValueError):
        FlutterwaveBillingProvider("", _verifier({}))
    with pytest.raises(ValueError):
        FlutterwaveBillingProvider(_FLW_SECRET, None)               # a server-side verifier is mandatory


def test_flutterwave_topup_via_reverify_and_idempotent():
    table = {"9911": {"id": 9911, "status": "successful", "tx_ref": "vigil:acme:n1", "currency": "XAF",
                      "amount": 5000, "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
    _s, w, _subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 9911), _FLW_SECRET, now=100.0) is not None
    assert w.available("acme") == 200                               # credits from catalog, not the wire amount
    signer.ingest(_flw_wh("charge.completed", 9911), _FLW_SECRET, now=100.0)   # duplicate delivery
    assert w.available("acme") == 200, "duplicate webhook (same transaction id) must not double-credit"


def test_flutterwave_idempotency_anchors_on_verified_id_not_the_body_spelling():
    # SECURITY (red-pen follow-up): the idempotency anchor (wallet entry_id) must be the CANONICAL verified id, not
    # the body's id SPELLING. Two deliveries of ONE real tx under two body-id spellings that /verify collapses to
    # the same canonical id must grant ONCE — else a verif-hash holder double-credits a real payment by varying
    # the spelling (e.g. a leading zero) whenever the verify endpoint canonicalizes it.
    canonical = {"id": 9911, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
                 "meta": {"price_id": "price_topup_200"}}

    def verifier(txid):                                 # the endpoint canonicalizes "9911" and "09911" -> tx 9911
        return canonical if str(txid).lstrip("0") == "9911" else None

    s, w, subs, plan, _meter, _mock, _signer = _rig()
    flw = FlutterwaveBillingProvider(_FLW_SECRET, verifier)
    signer = BillingSigner(flw, wallet=w, subscriptions=subs, plan=plan,
                           catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)})
    assert signer.ingest(_flw_wh("charge.completed", "9911"), _FLW_SECRET, now=100.0) is not None
    signer.ingest(_flw_wh("charge.completed", "09911"), _FLW_SECRET, now=100.0)   # SAME tx, different spelling
    assert w.available("acme") == 200, "two spellings of one verified tx must collapse to a single grant"


def test_flutterwave_missing_verified_id_mints_nothing():
    # fail-closed: a verified object carrying no canonical id cannot be anchored idempotently -> mint nothing.
    table = {"9911": {"status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
                      "meta": {"price_id": "price_topup_200"}}}      # no "id" field on the verified object
    _s, w, _subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 9911), _FLW_SECRET, now=100.0) is None
    assert w.available("acme") == 0


def test_flutterwave_forged_hash_mints_nothing():
    table = {"9911": {"id": 9911, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1",
                      "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
    _s, w, _subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 9911), "WRONG-HASH", now=100.0) is None
    assert w.available("acme") == 0


def test_flutterwave_only_the_reverify_grants_not_the_webhook_body():
    # THE core trust property: the webhook body is NOT trusted; only the server-side re-verify can grant. The
    # verifier here reports id 5 as FAILED, yet the webhook body brazenly CLAIMS a successful 999999-credit
    # top-up for acme. The authoritative re-verify must win -> mint nothing.
    # Verifier knows NOTHING about id 404 (returns None); the webhook body brazenly CLAIMS a fully-successful
    # 999999 top-up for acme. The authoritative re-verify (None) must win -> mint nothing. A "trust the body"
    # regression would mint 200 here.
    _s, w, _subs, _plan, _m, _flw, signer = _flw_rig({"5": {"id": 5, "status": "failed", "tx_ref": "vigil:acme:x"}})
    liar = json.dumps({"event": "charge.completed",
                       "data": {"id": 404, "status": "successful", "tx_ref": "vigil:acme:x",
                                "amount": 999999, "meta": {"price_id": "price_topup_200"}}}).encode()
    assert signer.ingest(liar, _FLW_SECRET, now=1.0) is None, "a body claiming success for an unverifiable tx must not grant"
    assert signer.ingest(_flw_wh("charge.completed", 5), _FLW_SECRET, now=1.0) is None      # verifier says failed
    assert w.available("acme") == 0, "a webhook whose transaction does not re-verify as successful grants nothing"


def test_flutterwave_subscription_active_then_lapses_at_period_end():
    # A re-verified successful PLAN charge subscribes + refills the period; non-rollover means the plan credits
    # simply VANISH at period_end (the meter's active-subscription + live-period check), with no webhook needed.
    table = {"9912": {"id": 9912, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n2", "created_at": 100.0,
                      "payment_plan": "flwplan_pro"}}
    _s, _w, _subs, _plan, meter, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 9912), _FLW_SECRET, now=100.0) is not None
    assert meter.available("acme", now=500.0) == 6000               # subscribe + plan refill, inside [100, 1100]
    assert meter.available("acme", now=1500.0) == 0                 # period elapsed -> plan credits lapse


def test_flutterwave_failed_recurring_charge_marks_past_due():
    # H4: a definitively-FAILED RECURRING (payment_plan) charge that RE-VERIFIES drives DUNNING -> past_due. The
    # tenant/status/timestamp are taken from the AUTHORITATIVE verify object (the tx_ref WE set at checkout), never
    # the body — so a verif-hash holder cannot name a victim: only a REAL failed charge on a tenant's own plan duns.
    table = {"9912": {"id": 9912, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n2", "created_at": 100.0,
                      "payment_plan": "flwplan_pro"},
             "9913": {"id": 9913, "status": "failed", "tx_ref": "vigil:acme:n3", "payment_plan": "flwplan_pro",
                      "created_at": 200.0}}
    _s, _w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    signer.ingest(_flw_wh("charge.completed", 9912), _FLW_SECRET, now=100.0)
    assert subs.subscription("acme").status == STATUS_ACTIVE
    assert signer.ingest(_flw_wh("charge.completed", 9913), _FLW_SECRET, now=200.0) is not None
    assert subs.subscription("acme").status == STATUS_PAST_DUE, "a re-verified failed recurring charge must past_due"


def test_flutterwave_cancel_webhook_is_still_ignored():
    # H4 SCOPE BOUND: a bare `subscription.cancelled` webhook carries no transaction to re-verify, so there is no
    # authoritative subscription->org mapping — we must NOT cancel a victim named only in the unauthenticated body.
    table = {"9912": {"id": 9912, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n2", "created_at": 100.0,
                      "payment_plan": "flwplan_pro"}}
    _s, _w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    signer.ingest(_flw_wh("charge.completed", 9912), _FLW_SECRET, now=100.0)
    body = json.dumps({"event": "subscription.cancelled",
                       "data": {"id": "sub_1", "tx_ref": "vigil:acme:n2", "created_at": 300.0}}).encode()
    assert signer.ingest(body, _FLW_SECRET, now=300.0) is None
    assert subs.subscription("acme").status == STATUS_ACTIVE, "a cancel webhook must not cancel a named victim"


def test_flutterwave_failed_topup_does_not_dun():
    # A failed ONE-TIME top-up (no payment_plan) reduces nothing — there is no subscription to past_due -> no-op.
    table = {"9920": {"id": 9920, "status": "failed", "tx_ref": "vigil:acme:n9", "created_at": 200.0,
                      "meta": {"price_id": "price_topup_200"}}}
    _s, _w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 9920), _FLW_SECRET, now=200.0) is None
    assert subs.subscription("acme") is None, "a failed top-up must not create or past_due any subscription"


def test_flutterwave_failed_charge_without_recoverable_org_is_noop():
    # fail-closed: a failed plan charge whose verify object names NO recoverable tenant (no tx_ref / meta) duns
    # NOBODY — we never act on a guess.
    table = {"9921": {"id": 9921, "status": "failed", "payment_plan": "flwplan_pro", "created_at": 200.0}}
    _s, _w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 9921), _FLW_SECRET, now=200.0) is None
    assert subs.subscription("acme") is None


def test_flutterwave_pending_charge_does_not_dun():
    # A NON-DEFINITIVE status (pending) must NOT reduce access — we dun only on a definitively `failed` verify.
    table = {"9912": {"id": 9912, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n2", "created_at": 100.0,
                      "payment_plan": "flwplan_pro"},
             "9922": {"id": 9922, "status": "pending", "tx_ref": "vigil:acme:n2", "payment_plan": "flwplan_pro",
                      "created_at": 200.0}}
    _s, _w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    signer.ingest(_flw_wh("charge.completed", 9912), _FLW_SECRET, now=100.0)
    assert signer.ingest(_flw_wh("charge.completed", 9922), _FLW_SECRET, now=200.0) is None
    assert subs.subscription("acme").status == STATUS_ACTIVE


def test_flutterwave_stale_failed_charge_after_recovery_does_not_resuspend():
    # THE freshness invariant (H4): the failed-charge webhook carries the verify object's `created` as the
    # down-latch freshness key. After a tenant RECOVERS (a later successful renewal), a STALE / replayed /
    # out-of-order failed charge from BEFORE the recovery must NOT re-suspend them (at-least-once + unordered
    # webhook delivery make this real). A GENUINE current failure still duns (it post-dates its activation).
    table = {"9912": {"id": 9912, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n2", "created_at": 100.0,
                      "payment_plan": "flwplan_pro"},
             "9913": {"id": 9913, "status": "failed", "tx_ref": "vigil:acme:n3", "payment_plan": "flwplan_pro",
                      "created_at": 200.0},
             "9914": {"id": 9914, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n4", "created_at": 300.0,
                      "payment_plan": "flwplan_pro"}}
    _s, _w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    signer.ingest(_flw_wh("charge.completed", 9912), _FLW_SECRET, now=100.0)   # active @100
    signer.ingest(_flw_wh("charge.completed", 9913), _FLW_SECRET, now=200.0)   # failed @200 -> past_due
    assert subs.subscription("acme").status == STATUS_PAST_DUE
    signer.ingest(_flw_wh("charge.completed", 9914), _FLW_SECRET, now=300.0)   # renewal @300 -> active (recovered)
    assert subs.subscription("acme").status == STATUS_ACTIVE
    signer.ingest(_flw_wh("charge.completed", 9913), _FLW_SECRET, now=400.0)   # STALE replay of the @200 failure
    assert subs.subscription("acme").status == STATUS_ACTIVE, \
        "a stale failed-charge replay must not re-suspend a recovered tenant"


def test_flutterwave_org_comes_from_verified_not_the_body():
    # SECURITY (red-pen #2): the tenant must come from the AUTHORITATIVE verified object, never the body. The
    # verified tx belongs to 'honest'; the body smuggles a 'victim' tx_ref. The grant must land on 'honest'.
    table = {"42": {"id": 42, "status": "successful", "currency": "USD", "tx_ref": "vigil:honest:n1", "created_at": 10.0,
                    "meta": {"price_id": "price_topup_200"}}}
    _s, w, _subs, _plan, _m, _flw, signer = _flw_rig(table)
    liar = json.dumps({"event": "charge.completed",
                       "data": {"id": 42, "tx_ref": "vigil:victim:x", "meta": {"org_id": "victim"}}}).encode()
    assert signer.ingest(liar, _FLW_SECRET, now=10.0) is not None
    assert w.available("honest") == 200, "org must come from the verified object (honest)"
    assert w.available("victim") == 0, "the body's smuggled tenant must get nothing"
    # and the exact old bug (`_flw_org_id(verified) or _flw_org_id(body)`): verified has NO recoverable org, the
    # body smuggles one -> must mint NOTHING (no body fallback for the tenant of a sovereign mint).
    table2 = {"43": {"id": 43, "status": "successful", "currency": "USD", "tx_ref": "no-org", "created_at": 10.0,
                     "meta": {"price_id": "price_topup_200"}}}      # verified: unrecoverable tenant
    _s2, w2, _s2b, _p2, _m2, _flw2, signer2 = _flw_rig(table2)
    smuggle = json.dumps({"event": "charge.completed",
                          "data": {"id": 43, "tx_ref": "vigil:victim:x"}}).encode()
    assert signer2.ingest(smuggle, _FLW_SECRET, now=10.0) is None
    assert w2.available("victim") == 0, "an unrecoverable verified tenant must never fall back to the body"


def test_flutterwave_body_injected_payment_plan_cannot_force_the_plan_path():
    # SECURITY (red-pen #3): plan-vs-topup is decided by the VERIFIED object only. The verified tx is a plain
    # top-up (no payment_plan); the body injects payment_plan. It must still be minted as a TOPUP, not a plan.
    table = {"50": {"id": 50, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1", "created_at": 10.0,
                    "meta": {"price_id": "price_topup_200"}}}
    _s, w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    body = json.dumps({"event": "charge.completed",
                       "data": {"id": 50, "payment_plan": "flwplan_pro"}}).encode()   # body lies: this is a plan
    assert signer.ingest(body, _FLW_SECRET, now=10.0) is not None
    assert w.available("acme") == 200                               # minted as a top-up, from the verified object
    assert subs.subscription("acme") is None, "a body-injected payment_plan must not create a subscription"


def test_flutterwave_iso_created_at_and_replay_inertness():
    # red-pen #4: created_at is an ISO-8601 STRING; it must parse to a stable epoch (not 0 -> wall-clock), so a
    # duplicate delivery is inert (same derived period, no re-grant / period extension). period_s=1000.
    iso = "2024-01-02T03:04:05.000Z"                                # = 1704164645.0 UTC
    epoch = 1704164645.0
    table = {"77": {"id": 77, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1", "created_at": iso,
                    "payment_plan": "flwplan_pro"}}
    _s, _w, subs, _plan, meter, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 77), _FLW_SECRET, now=epoch) is not None
    sub1 = subs.subscription("acme")
    assert sub1.period_end == epoch + 1000.0                        # period anchored on the PARSED created_at
    assert meter.available("acme", now=epoch + 500.0) == 6000
    # a duplicate delivery (same tx id, same parsed created) -> inert: no new period, still one live tranche
    signer.ingest(_flw_wh("charge.completed", 77), _FLW_SECRET, now=epoch + 900.0)
    assert subs.subscription("acme").period_end == epoch + 1000.0, "a replay must not extend the period"
    assert meter.available("acme", now=epoch + 500.0) == 6000


def test_flutterwave_unparseable_created_at_mints_nothing():
    # red-pen #4 (fail-closed): a verified tx with no parseable timestamp must mint NOTHING — replay-safety needs a
    # stable period anchor, and a wall-clock fallback would let duplicates advance the period.
    table = {"78": {"id": 78, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n1", "created_at": "not-a-date",
                    "payment_plan": "flwplan_pro"},
             "79": {"id": 79, "status": "successful", "currency": "USD", "tx_ref": "vigil:acme:n2",
                    "meta": {"price_id": "price_topup_200"}}}      # created_at absent entirely
    _s, w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 78), _FLW_SECRET, now=100.0) is None
    assert signer.ingest(_flw_wh("charge.completed", 79), _FLW_SECRET, now=100.0) is None
    assert subs.subscription("acme") is None and w.available("acme") == 0


def test_flutterwave_unrecoverable_org_is_ignored():
    table = {"7": {"id": 7, "status": "successful", "currency": "USD", "tx_ref": "no-org-here", "created_at": 1.0,
                   "meta": {"price_id": "price_topup_200"}}}
    _s, w, _subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 7), _FLW_SECRET, now=1.0) is None
    assert w.available("acme") == 0


def test_flutterwave_capabilities_and_noauth_gate():
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}))
    assert CAP_MOBILE_MONEY in flw.capabilities()
    assert CAP_UNATTENDED_TOPUP not in flw.capabilities()           # NOAUTH approval-gated -> off by default
    flw.require(CAP_REFUND)                                         # declared -> no raise
    with pytest.raises(UnsupportedCapability):
        flw.require(CAP_UNATTENDED_TOPUP)
    approved = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), noauth_approved=True)
    assert CAP_UNATTENDED_TOPUP in approved.capabilities()          # on once the merchant account is approved


# ---- CONTRACT TESTS covering BOTH adapters + the mock (provider independence) -------------------------
def _all_providers():
    return [
        ("mock", MockBillingProvider("sek")),
        ("stripe", StripeBillingProvider("whsec_x", fetcher=lambda kind, oid: {}, expected_mode="test",
                                         enable_reference_adapter=True)),
        ("flutterwave", FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}))),
    ]


def test_contract_all_providers_declare_verify_webhook():
    for name, p in _all_providers():
        assert CAP_VERIFY_WEBHOOK in p.capabilities(), f"{name} must declare verify_webhook"


def test_contract_forged_signature_mints_nothing_every_provider():
    # The one invariant every adapter must satisfy: an unauthenticated/forged webhook yields no event.
    body = json.dumps({"event": "charge.completed", "data": {"id": 1},
                       "kind": EVENT_TOPUP, "event_id": "e", "org_id": "acme", "created": 1.0,
                       "id": "evt", "type": "invoice.paid"}).encode()
    for name, p in _all_providers():
        assert p.verify_and_parse(body, "definitely-not-a-valid-signature", now=1.0) is None, \
            f"{name} must reject a forged signature"
        assert p.verify_and_parse(b"not-json", "definitely-not-a-valid-signature", now=1.0) is None


def test_contract_require_raises_on_undeclared_capability():
    for name, p in _all_providers():
        missing = next(c for c in ("totally_made_up_cap",) if not p.supports(c))
        with pytest.raises(UnsupportedCapability):
            p.require(missing)


# ================= Slice F — outbound hosted checkout + inbound amount cross-check =================
_EXPECTED = {"price_topup_200": (20000, "USD"), "flwplan_pro": (5000, "XAF")}


def _ok_creator(captured=None, link="https://checkout.flutterwave.com/pay/abc"):
    def cc(payload):
        if captured is not None:
            captured["payload"] = dict(payload)
        return {"status": "success", "data": {"link": link}}
    return cc


def test_create_checkout_binds_tenant_and_uses_catalog_amount():
    cap = {}
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=_ok_creator(cap))
    sess = flw.create_checkout("acme-corp", "price_topup_200", expected=_EXPECTED,
                               customer_email="a@acme.com", redirect_url="https://app.vigil/return", nonce="N1")
    assert isinstance(sess, CheckoutSession)
    assert sess.tx_ref == "vigil:acme-corp:N1"                    # tenant bound into the one echoed field
    assert sess.amount_minor == 20000 and sess.currency == "USD"  # from the CATALOG, never the caller
    assert sess.hosted_link == "https://checkout.flutterwave.com/pay/abc"
    p = cap["payload"]
    assert p["tx_ref"] == "vigil:acme-corp:N1"
    assert p["amount"] == 200.0                                   # 20000 minor USD -> 200.00 major (catalog, not caller)
    assert p["currency"] == "USD"
    assert p["meta"] == {"org_id": "acme-corp", "price_id": "price_topup_200"}   # redundant tenant+price binding
    assert p["customer"] == {"email": "a@acme.com"} and p["redirect_url"] == "https://app.vigil/return"


def test_create_checkout_zero_decimal_currency_amount_is_whole():
    cap = {}
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=_ok_creator(cap))
    flw.create_checkout("acme", "flwplan_pro", expected=_EXPECTED, nonce="N2")
    assert cap["payload"]["amount"] == 5000 and cap["payload"]["currency"] == "XAF"   # XAF: 0 decimals, minor == major


def test_create_checkout_refuses_unknown_price():
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=_ok_creator())
    with pytest.raises(ValueError):                                # caller cannot price an offering outside the catalog
        flw.create_checkout("acme", "price_not_in_catalog", expected=_EXPECTED)


def test_create_checkout_without_creator_refuses_not_simulates():
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}))   # no checkout_creator injected
    assert flw.supports(CAP_HOSTED_CHECKOUT)                        # capability is declared...
    with pytest.raises(UnsupportedCapability):                      # ...but it refuses rather than simulating a checkout
        flw.create_checkout("acme", "price_topup_200", expected=_EXPECTED)


def test_create_checkout_refuses_non_https_or_failed_link():
    for bad in ({"status": "success", "data": {"link": "http://evil/pay"}},
                {"status": "success", "data": {"link": "javascript:alert(1)"}},
                {"status": "success", "data": {}},
                {"status": "error", "message": "bad", "data": {"link": "https://checkout.flutterwave.com/x"}},
                None):
        flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=lambda p, r=bad: r)
        with pytest.raises(UnsupportedCapability):
            flw.create_checkout("acme", "price_topup_200", expected=_EXPECTED)


def test_create_checkout_refuses_invalid_org():
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=_ok_creator())
    for bad_org in ("has:colon", "has space", ""):                 # an invalid/foreign tenant id is refused fail-closed
        with pytest.raises(ValueError):
            flw.create_checkout(bad_org, "price_topup_200", expected=_EXPECTED)


def _flw_rig_expected(table, expected):
    _s, w, subs, plan, _m, _mock, _signer = _rig()
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier(table))
    signer = BillingSigner(flw, wallet=w, subscriptions=subs, plan=plan,
                           catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)},
                           expected=expected)
    return w, signer


def test_inbound_underpaid_charge_mints_nothing():
    # verified amount 150.00 USD = 15000 minor < 20000 expected -> refuse (anti-underpay defense-in-depth).
    table = {"71": {"id": 71, "status": "successful", "tx_ref": "vigil:acme:n", "currency": "USD",
                    "amount": 150.00, "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
    w, signer = _flw_rig_expected(table, {"price_topup_200": (20000, "USD")})
    assert signer.ingest(_flw_wh("charge.completed", 71), _FLW_SECRET, now=100.0) is None
    assert w.available("acme") == 0


def test_inbound_wrong_currency_mints_nothing():
    table = {"72": {"id": 72, "status": "successful", "tx_ref": "vigil:acme:n", "currency": "EUR",
                    "amount": 200.00, "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
    w, signer = _flw_rig_expected(table, {"price_topup_200": (20000, "USD")})
    assert signer.ingest(_flw_wh("charge.completed", 72), _FLW_SECRET, now=100.0) is None
    assert w.available("acme") == 0


def test_inbound_exact_catalog_amount_mints():
    table = {"73": {"id": 73, "status": "successful", "tx_ref": "vigil:acme:n", "currency": "USD",
                    "amount": 200.00, "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
    w, signer = _flw_rig_expected(table, {"price_topup_200": (20000, "USD")})
    assert signer.ingest(_flw_wh("charge.completed", 73), _FLW_SECRET, now=100.0) is not None
    assert w.available("acme") == 200                              # exact catalog amount -> mints the catalog credits


def test_inbound_cross_check_skipped_when_no_expected_configured():
    # backward-compatible: with NO `expected` map, an underpaid charge still mints on the price_id binding alone
    # (the primary doctrine). The cross-check is a defense-in-depth add, off unless the owner wires expected_amounts.
    table = {"74": {"id": 74, "status": "successful", "tx_ref": "vigil:acme:n", "currency": "USD",
                    "amount": 1.00, "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
    w, signer = _flw_rig_expected(table, None)                     # expected=None -> no cross-check
    assert signer.ingest(_flw_wh("charge.completed", 74), _FLW_SECRET, now=100.0) is not None
    assert w.available("acme") == 200


_NO_CURRENCY = object()


@pytest.mark.parametrize("currency", [_NO_CURRENCY, None, "", "   ", 840])
@pytest.mark.parametrize("expected", [{"price_topup_200": (20000, "USD")}, None])
def test_inbound_verified_charge_without_a_currency_mints_nothing(currency, expected):
    # The signer's underpay / wrong-currency cross-check keys on the event's currency, so a verified "successful"
    # charge with no (usable) currency would skip it and mint the catalog top-up on the price_id alone. The
    # provider refuses it: no currency, no mint, whether or not an expected price is configured.
    tx = {"id": 75, "status": "successful", "tx_ref": "vigil:acme:n", "amount": 200.00, "created_at": 100.0,
          "meta": {"price_id": "price_topup_200"}}
    if currency is not _NO_CURRENCY:
        tx["currency"] = currency
    w, signer = _flw_rig_expected({"75": tx}, expected)
    assert signer.ingest(_flw_wh("charge.completed", 75), _FLW_SECRET, now=100.0) is None
    assert w.available("acme") == 0


# ---- Slice F red-pen fold (LOW hardening): link sanitizer, fail-closed creator, price guard, binding round-trip
def test_create_checkout_refuses_crlf_userinfo_and_foreign_host_links():
    for bad_link in ("https://checkout.flutterwave.com/pay\r\nSet-Cookie: x=y",   # CRLF -> header-split
                     "https://checkout.flutterwave.com/p ay",                      # embedded whitespace
                     "https://user:pass@checkout.flutterwave.com/pay",             # embedded credentials
                     "https://evil.example/pay",                                   # foreign host
                     "https://flutterwave.com.evil.example/pay",                   # suffix-spoofed host
                     "https://evilflutterwave.com/pay"):                           # no dot boundary
        flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}),
                                         checkout_creator=lambda p, L=bad_link: {"status": "success",
                                                                                 "data": {"link": L}})
        with pytest.raises(UnsupportedCapability):
            flw.create_checkout("acme", "price_topup_200", expected=_EXPECTED)


def test_create_checkout_fails_closed_when_creator_raises():
    def boom(payload):
        raise RuntimeError("TLS handshake failed: secret-ish internals")                 # outbound POST failure
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=boom)
    with pytest.raises(UnsupportedCapability) as ei:
        flw.create_checkout("acme", "price_topup_200", expected=_EXPECTED)
    assert "secret-ish internals" not in str(ei.value)                                   # provider internals NOT leaked


def test_create_checkout_refuses_zero_negative_or_empty_catalog_price():
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=_ok_creator())
    for bad in ({"p": (0, "USD")}, {"p": (-100, "USD")}, {"p": (5000, "")}):              # mispriced catalog entry
        with pytest.raises(ValueError):
            flw.create_checkout("acme", "p", expected=bad)


def test_create_checkout_rejects_colon_in_explicit_nonce():
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=_ok_creator())
    with pytest.raises(ValueError):
        flw.create_checkout("acme", "price_topup_200", expected=_EXPECTED, nonce="bad:nonce")   # delimiter poison


def test_create_checkout_default_nonce_and_binding_round_trip():
    cap = {}
    flw = FlutterwaveBillingProvider(_FLW_SECRET, _verifier({}), checkout_creator=_ok_creator(cap))
    sess = flw.create_checkout("acme-corp", "price_topup_200", expected=_EXPECTED)        # NO explicit nonce
    prefix, org, nonce = sess.tx_ref.split(":", 2)
    assert prefix == "vigil" and org == "acme-corp" and nonce and ":" not in nonce        # default nonce well-formed
    assert cap["payload"]["meta"]["org_id"] == "acme-corp"                                 # tx_ref org == meta org
    # ROUND-TRIP: a paid charge carrying THIS tx_ref mints to the SAME org, never another.
    _s, w, subs, plan, _m, _mock, _signer = _rig()
    table = {"500": {"id": 500, "status": "successful", "tx_ref": sess.tx_ref, "currency": "USD",
                     "amount": 200.0, "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
    signer = BillingSigner(FlutterwaveBillingProvider(_FLW_SECRET, _verifier(table)), wallet=w,
                           subscriptions=subs, plan=plan,
                           catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)})
    assert signer.ingest(_flw_wh("charge.completed", 500), _FLW_SECRET, now=100.0) is not None
    assert w.available("acme-corp") == 200 and w.available("victim-org") == 0
