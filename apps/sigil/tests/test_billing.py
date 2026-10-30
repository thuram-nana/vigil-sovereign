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

from sigil.governor.billing import (EVENT_PAYMENT_FAILED, EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED,
                                     EVENT_TOPUP, BillingSigner, Entitlement, MockBillingProvider,
                                     StripeBillingProvider)
from sigil.governor.metering import CreditMeter, PlanCreditLedger
from sigil.governor.subscription import STATUS_CANCELED, STATUS_PAST_DUE, SubscriptionRegistry
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
    meter = CreditMeter(w, plan)
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


def _stripe_body(etype="invoice.paid", org="acme", price="price_pro", eid="evt_s1", created=1000):
    return json.dumps({"id": eid, "type": etype, "created": created,
                       "data": {"object": {"metadata": {"org_id": org},
                                            "items": {"data": [{"price": {"id": price}}]}}}}).encode()


def _sig(secret, t, body):
    mac = hmac.new(secret.encode(), str(t).encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


def test_stripe_valid_signature_parses():
    p = StripeBillingProvider(_SECRET)
    body = _stripe_body()
    ev = p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0)
    assert ev is not None and ev.kind == EVENT_SUBSCRIPTION_ACTIVE and ev.org_id == "acme" \
        and ev.price_id == "price_pro" and ev.event_id == "evt_s1"


def test_stripe_rejects_bad_tampered_stale_and_malformed_sig():
    p = StripeBillingProvider(_SECRET, tolerance_s=300.0)
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
    p = StripeBillingProvider(_SECRET)
    body = _stripe_body()
    mac = hmac.new(_SECRET.encode(), b"1000." + body, hashlib.sha256).hexdigest()
    hdr = f"t=1000,v1=deadbeef,v1={mac}"            # one bad + one good v1 (secret rotation) -> accepted
    assert p.verify_and_parse(body, hdr, now=1000.0) is not None


def test_stripe_ignores_unmapped_and_missing_org():
    p = StripeBillingProvider(_SECRET)
    body = _stripe_body(etype="charge.updated")                 # not a minted type
    assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None
    body2 = json.dumps({"id": "e", "type": "invoice.paid", "created": 1000,
                        "data": {"object": {"items": {"data": [{"price": {"id": "price_pro"}}]}}}}).encode()
    assert p.verify_and_parse(body2, _sig(_SECRET, 1000, body2), now=1000.0) is None   # no org_id metadata


def test_stripe_subscription_mode_checkout_is_ignored():
    # a checkout.session.completed in subscription mode is handled by invoice.paid, not as a top-up
    p = StripeBillingProvider(_SECRET)
    body = json.dumps({"id": "cs1", "type": "checkout.session.completed", "created": 1000,
                       "data": {"object": {"mode": "subscription", "metadata": {"org_id": "acme"}}}}).encode()
    assert p.verify_and_parse(body, _sig(_SECRET, 1000, body), now=1000.0) is None


def test_stripe_secret_required():
    with pytest.raises(ValueError):
        StripeBillingProvider("")
