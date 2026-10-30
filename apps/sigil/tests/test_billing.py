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

from sigil.governor.billing import (CAP_MOBILE_MONEY, CAP_REFUND, CAP_UNATTENDED_TOPUP, CAP_VERIFY_WEBHOOK,
                                     EVENT_PAYMENT_FAILED, EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED,
                                     EVENT_TOPUP, BillingSigner, Entitlement, FlutterwaveBillingProvider,
                                     MockBillingProvider, StripeBillingProvider, UnsupportedCapability)
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


# ---- the Stripe provider: HMAC signature scheme -----------------------------------------------------
_SECRET = "whsec_test_123"


def _stripe_body(etype="invoice.paid", org="acme", price="price_pro", eid="evt_s1", created=1000,
                 billing_reason="subscription_cycle"):
    obj = {"metadata": {"org_id": org}, "items": {"data": [{"price": {"id": price}}]}}
    if etype in ("invoice.paid", "invoice.payment_failed"):
        obj["billing_reason"] = billing_reason
    return json.dumps({"id": eid, "type": etype, "created": created, "data": {"object": obj}}).encode()


def _sig(secret, t, body):
    mac = hmac.new(secret.encode(), str(t).encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


def test_stripe_valid_signature_parses():
    p = StripeBillingProvider(_SECRET, enable_reference_adapter=True)
    body = _stripe_body()
    ev = p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0)
    assert ev is not None and ev.kind == EVENT_SUBSCRIPTION_ACTIVE and ev.org_id == "acme" \
        and ev.price_id == "price_pro" and ev.event_id == "evt_s1"


def test_stripe_rejects_bad_tampered_stale_and_malformed_sig():
    p = StripeBillingProvider(_SECRET, tolerance_s=300.0, enable_reference_adapter=True)
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
    p = StripeBillingProvider(_SECRET, enable_reference_adapter=True)
    body = _stripe_body()
    mac = hmac.new(_SECRET.encode(), b"1000." + body, hashlib.sha256).hexdigest()
    hdr = f"t=1000,v1=deadbeef,v1={mac}"            # one bad + one good v1 (secret rotation) -> accepted
    assert p.verify_and_parse(body, hdr, now=1000.0) is not None


def test_stripe_ignores_unmapped_and_missing_org():
    p = StripeBillingProvider(_SECRET, enable_reference_adapter=True)
    body = _stripe_body(etype="charge.updated")                 # not a minted type
    assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None
    body2 = json.dumps({"id": "e", "type": "invoice.paid", "created": 1000,
                        "data": {"object": {"items": {"data": [{"price": {"id": "price_pro"}}]}}}}).encode()
    assert p.verify_and_parse(body2, _sig(_SECRET, 1000, body2), now=1000.0) is None   # no org_id metadata


def test_stripe_ignores_mid_cycle_invoice_billing_reason():
    # Only subscription_create / subscription_cycle invoices advance the period; a mid-cycle proration/update
    # invoice (which Stripe genuinely emits) must be ignored, or it would mint a second overlapping allotment.
    p = StripeBillingProvider(_SECRET, enable_reference_adapter=True)
    for reason in ("subscription_update", "manual", "subscription_threshold", ""):
        body = _stripe_body(billing_reason=reason)
        assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None, \
            f"invoice.paid with billing_reason={reason!r} must be ignored"
    # the cycle/create reasons DO parse
    for reason in ("subscription_cycle", "subscription_create"):
        body = _stripe_body(billing_reason=reason)
        assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is not None


def test_stripe_subscription_mode_checkout_is_ignored():
    # a checkout.session.completed in subscription mode is handled by invoice.paid, not as a top-up
    p = StripeBillingProvider(_SECRET, enable_reference_adapter=True)
    body = json.dumps({"id": "cs1", "type": "checkout.session.completed", "created": 1000,
                       "data": {"object": {"mode": "subscription", "metadata": {"org_id": "acme"}}}}).encode()
    assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None


def test_stripe_secret_required():
    with pytest.raises(ValueError):
        StripeBillingProvider("", enable_reference_adapter=True)


# ---- Stripe disabled-by-default guard ----------------------------------------------------------------
def test_stripe_disabled_by_default():
    with pytest.raises(UnsupportedCapability):
        StripeBillingProvider("whsec_x")                            # no opt-in -> refuses
    assert StripeBillingProvider("whsec_x", enable_reference_adapter=True) is not None   # explicit flag
    import os
    _prev = os.environ.get("VIGIL_BILLING_ENABLE_STRIPE")
    os.environ["VIGIL_BILLING_ENABLE_STRIPE"] = "1"
    try:
        assert StripeBillingProvider("whsec_x") is not None         # env opt-in
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


def test_flutterwave_forged_hash_mints_nothing():
    table = {"9911": {"id": 9911, "status": "successful", "tx_ref": "vigil:acme:n1",
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
    table = {"9912": {"id": 9912, "status": "successful", "tx_ref": "vigil:acme:n2", "created_at": 100.0,
                      "payment_plan": "flwplan_pro"}}
    _s, _w, _subs, _plan, meter, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 9912), _FLW_SECRET, now=100.0) is not None
    assert meter.available("acme", now=500.0) == 6000               # subscribe + plan refill, inside [100, 1100]
    assert meter.available("acme", now=1500.0) == 0                 # period elapsed -> plan credits lapse


def test_flutterwave_does_not_act_on_cancel_or_failed_webhooks():
    # SECURITY (red-pen #1/#3): Flutterwave's verif-hash authenticates only the caller, NOT the body, so a
    # `subscription.cancelled` / failed-charge webhook cannot name a victim tenant soundly. This slice therefore
    # mints NOTHING on those events — a verif-hash holder must not be able to cancel/past_due any named org.
    table = {"9912": {"id": 9912, "status": "successful", "tx_ref": "vigil:acme:n2", "created_at": 100.0,
                      "payment_plan": "flwplan_pro"},
             "9913": {"id": 9913, "status": "failed", "tx_ref": "vigil:acme:n3", "payment_plan": "flwplan_pro",
                      "created_at": 200.0}}
    _s, _w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    signer.ingest(_flw_wh("charge.completed", 9912), _FLW_SECRET, now=100.0)
    assert subs.subscription("acme").status == STATUS_ACTIVE
    # a failed plan charge -> NOT dunning (we do not act on failed charges) -> still active
    assert signer.ingest(_flw_wh("charge.completed", 9913), _FLW_SECRET, now=200.0) is None
    assert subs.subscription("acme").status == STATUS_ACTIVE, "a failed-charge webhook must not past_due in 4b"
    # a cancellation webhook naming acme in the (unauthenticated) body -> ignored -> still active
    body = json.dumps({"event": "subscription.cancelled",
                       "data": {"id": "sub_1", "tx_ref": "vigil:acme:n2", "created_at": 300.0}}).encode()
    assert signer.ingest(body, _FLW_SECRET, now=300.0) is None
    assert subs.subscription("acme").status == STATUS_ACTIVE, "a cancel webhook must not cancel a named victim"


def test_flutterwave_org_comes_from_verified_not_the_body():
    # SECURITY (red-pen #2): the tenant must come from the AUTHORITATIVE verified object, never the body. The
    # verified tx belongs to 'honest'; the body smuggles a 'victim' tx_ref. The grant must land on 'honest'.
    table = {"42": {"id": 42, "status": "successful", "tx_ref": "vigil:honest:n1", "created_at": 10.0,
                    "meta": {"price_id": "price_topup_200"}}}
    _s, w, _subs, _plan, _m, _flw, signer = _flw_rig(table)
    liar = json.dumps({"event": "charge.completed",
                       "data": {"id": 42, "tx_ref": "vigil:victim:x", "meta": {"org_id": "victim"}}}).encode()
    assert signer.ingest(liar, _FLW_SECRET, now=10.0) is not None
    assert w.available("honest") == 200, "org must come from the verified object (honest)"
    assert w.available("victim") == 0, "the body's smuggled tenant must get nothing"
    # and the exact old bug (`_flw_org_id(verified) or _flw_org_id(body)`): verified has NO recoverable org, the
    # body smuggles one -> must mint NOTHING (no body fallback for the tenant of a sovereign mint).
    table2 = {"43": {"id": 43, "status": "successful", "tx_ref": "no-org", "created_at": 10.0,
                     "meta": {"price_id": "price_topup_200"}}}      # verified: unrecoverable tenant
    _s2, w2, _s2b, _p2, _m2, _flw2, signer2 = _flw_rig(table2)
    smuggle = json.dumps({"event": "charge.completed",
                          "data": {"id": 43, "tx_ref": "vigil:victim:x"}}).encode()
    assert signer2.ingest(smuggle, _FLW_SECRET, now=10.0) is None
    assert w2.available("victim") == 0, "an unrecoverable verified tenant must never fall back to the body"


def test_flutterwave_body_injected_payment_plan_cannot_force_the_plan_path():
    # SECURITY (red-pen #3): plan-vs-topup is decided by the VERIFIED object only. The verified tx is a plain
    # top-up (no payment_plan); the body injects payment_plan. It must still be minted as a TOPUP, not a plan.
    table = {"50": {"id": 50, "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 10.0,
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
    table = {"77": {"id": 77, "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": iso,
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
    table = {"78": {"id": 78, "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": "not-a-date",
                    "payment_plan": "flwplan_pro"},
             "79": {"id": 79, "status": "successful", "tx_ref": "vigil:acme:n2",
                    "meta": {"price_id": "price_topup_200"}}}      # created_at absent entirely
    _s, w, subs, _plan, _m, _flw, signer = _flw_rig(table)
    assert signer.ingest(_flw_wh("charge.completed", 78), _FLW_SECRET, now=100.0) is None
    assert signer.ingest(_flw_wh("charge.completed", 79), _FLW_SECRET, now=100.0) is None
    assert subs.subscription("acme") is None and w.available("acme") == 0


def test_flutterwave_unrecoverable_org_is_ignored():
    table = {"7": {"id": 7, "status": "successful", "tx_ref": "no-org-here", "created_at": 1.0,
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
        ("stripe", StripeBillingProvider("whsec_x", enable_reference_adapter=True)),
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
