"""Stripe parity ST-2: the shared billing seams, with Flutterwave behaviour pinned byte-for-byte.

* `BillingProvider.create_checkout` exists on the base class and refuses with `UnsupportedCapability` (a provider
  that has no hosted checkout fails explicitly, never with an AttributeError from a duck-typed call).
* `_https_link_on` is the one checkout-link check; Flutterwave keeps its exact `*.flutterwave.com` rule.
* `checkout_tx_ref` is the one `vigil:<org>:<nonce>` builder.
* `BillingSigner(require_verified_amount=True)` refuses a priced event without a verified currency (the underpay
  check then bounds the amount, so 0 is refused too); the default (False) is unchanged.
* The Stripe adapter declares only the capabilities it implements (webhook verification + the object re-fetch).
* GOLDEN: a fixed Flutterwave top-up and plan charge produce exactly the recorded spine payloads, so a later
  slice that touches shared code cannot change what Flutterwave mints.
"""
from __future__ import annotations

import base64
import hashlib
import json
import tempfile

import pytest

from sigil.governor.billing import (CAP_HOSTED_CHECKOUT, CAP_RECONCILE, CAP_REFUND, CAP_VERIFY_TRANSACTION,
                                    CAP_VERIFY_WEBHOOK, EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, BillingEvent,
                                    BillingProvider, BillingSigner, Entitlement, FlutterwaveBillingProvider, MockBillingProvider,
                                    StripeBillingProvider, UnaccountedPayment, UnsupportedCapability,
                                    _flw_checkout_link, _https_link_on, checkout_tx_ref)
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import KeyPair
from sigil.spine.store import SpineStore


def _fixed_test_owner() -> KeyPair:
    """A FIXED owner keypair derived at runtime from a public test seed (no key material is committed), so the golden
    payloads (and their Ed25519 signatures, which are deterministic) are reproducible."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"vigil-test-billing-seams").digest())
    return KeyPair(
        public_key_b64=base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
        private_key_b64=base64.b64encode(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())


OWNER = _fixed_test_owner()
_FLW_SECRET = "flw-secret-hash-seams"
_CATALOG = {
    "price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200),
    "flwplan_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000, period_s=1000.0),
}
_EXPECTED = {"price_topup_200": (20000, "USD"), "flwplan_pro": (5000, "XAF")}


def _registries():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    plan = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    return s, w, subs, plan


# ---- base-class checkout + honest capabilities -----------------------------------------------------------------

class _BareProvider(BillingProvider):
    """The smallest possible adapter: only the abstract method; everything else is the base class."""

    def verify_and_parse(self, raw_body, sig_header, *, now):
        return None


def test_a_provider_without_hosted_checkout_refuses_explicitly():
    for p in (_BareProvider(), _stripe_ref()):
        assert not p.supports(CAP_HOSTED_CHECKOUT)
        with pytest.raises(UnsupportedCapability):
            p.require(CAP_HOSTED_CHECKOUT)
        with pytest.raises(UnsupportedCapability):                     # not AttributeError
            p.create_checkout("acme", "price_topup_200", expected=_EXPECTED)


def _stripe_ref():
    return StripeBillingProvider("whsec_x", fetcher=lambda kind, oid: {}, expected_mode="test",
                                 enable_reference_adapter=True)


def test_stripe_declares_only_what_it_implements():
    caps = _stripe_ref().capabilities()
    assert caps == frozenset({CAP_VERIFY_WEBHOOK, CAP_VERIFY_TRANSACTION})
    for missing in (CAP_HOSTED_CHECKOUT, CAP_REFUND, CAP_RECONCILE):
        assert missing not in caps


# ---- the shared checkout-link check -----------------------------------------------------------------------------

def test_flutterwave_link_rule_is_unchanged():
    ok = {"status": "success", "data": {"link": "https://checkout.flutterwave.com/v3/hosted/pay/abc"}}
    assert _flw_checkout_link(ok) == ok["data"]["link"]
    assert _flw_checkout_link({"status": "success", "data": {"link": "https://flutterwave.com/pay"}})
    for bad in ("https://evilflutterwave.com/pay", "https://flutterwave.com.evil.io/pay", "http://checkout.flutterwave.com/x",
                "https://user@checkout.flutterwave.com/x", "https://checkout.flutterwave.com/x\r\nLocation: y",
                "javascript:alert(1)", ""):
        assert _flw_checkout_link({"status": "success", "data": {"link": bad}}) is None, bad
    assert _flw_checkout_link({"status": "error", "data": ok["data"]}) is None


def test_exact_host_pin_admits_only_that_host():
    assert _https_link_on("https://checkout.stripe.com/c/pay/cs_x", exact_hosts=frozenset({"checkout.stripe.com"}))
    for bad in ("https://evil.checkout.stripe.com/c", "https://checkout.stripe.com.evil.io/c",
                "https://stripe.com/c", "https://checkout.stripe.co/c"):
        assert _https_link_on(bad, exact_hosts=frozenset({"checkout.stripe.com"})) is None, bad


def test_checkout_tx_ref_format():
    assert checkout_tx_ref("acme", "n1") == "vigil:acme:n1"


# ---- opt-in verified-amount guard on the signer -----------------------------------------------------------------

def _apply(signer, kind, *, currency, amount, price="price_topup_200", eid="ev1"):
    return signer.apply(BillingEvent(event_id=eid, kind=kind, org_id="acme", created=100.0, price_id=price,
                                     amount_minor=amount, currency=currency), now=100.0)


def test_default_signer_still_mints_an_event_without_a_currency():
    _s, w, subs, plan = _registries()
    signer = BillingSigner(MockBillingProvider("sek"), wallet=w, subscriptions=subs, plan=plan, catalog=_CATALOG,
                           expected=_EXPECTED)
    assert _apply(signer, EVENT_TOPUP, currency="", amount=0) is not None and w.available("acme") == 200


def test_require_verified_amount_refuses_a_priced_event_without_one():
    _s, w, subs, plan = _registries()
    signer = BillingSigner(MockBillingProvider("sek"), wallet=w, subscriptions=subs, plan=plan, catalog=_CATALOG,
                           expected=_EXPECTED, require_verified_amount=True)
    assert _apply(signer, EVENT_TOPUP, currency="", amount=20000) is None
    assert _apply(signer, EVENT_TOPUP, currency="USD", amount=0, eid="ev2") is None
    assert w.available("acme") == 0
    assert _apply(signer, EVENT_TOPUP, currency="USD", amount=20000, eid="ev3") is not None   # verified -> mints
    assert w.available("acme") == 200


def test_require_verified_amount_alarms_on_a_plan_when_the_alarm_is_on():
    _s, w, subs, plan = _registries()
    signer = BillingSigner(MockBillingProvider("sek"), wallet=w, subscriptions=subs, plan=plan, catalog=_CATALOG,
                           expected=_EXPECTED, require_verified_amount=True, alarm_unaccounted_plans=True)
    with pytest.raises(UnaccountedPayment):
        _apply(signer, EVENT_SUBSCRIPTION_ACTIVE, currency="", amount=5000, price="flwplan_pro")


# ---- GOLDEN: what Flutterwave mints is pinned --------------------------------------------------------------------

_GOLDEN_TABLE = {
    "9911": {"id": 9911, "status": "successful", "tx_ref": "vigil:acme:n1", "currency": "USD", "amount": 200.00,
             "created_at": 100.0, "meta": {"price_id": "price_topup_200"}},
    "9922": {"id": 9922, "status": "successful", "tx_ref": "vigil:acme:n2", "currency": "XAF", "amount": 5000,
             "created_at": 200.0, "payment_plan": "flwplan_pro"},
}


def _golden_payloads():
    s, w, subs, plan = _registries()
    flw = FlutterwaveBillingProvider(_FLW_SECRET, lambda txid: _GOLDEN_TABLE.get(str(txid)))
    signer = BillingSigner(flw, wallet=w, subscriptions=subs, plan=plan, catalog=_CATALOG, expected=_EXPECTED)
    for txid in ("9911", "9922"):
        body = json.dumps({"event": "charge.completed", "data": {"id": int(txid)}}).encode()
        assert signer.ingest(body, _FLW_SECRET, now=300.0) is not None
    return [json.dumps({"kind": r.kind, "payload": r.payload}, sort_keys=True, separators=(",", ":"))
            for r in (s.decrypted_or_raw(x) for x in s.iter_records())]


def test_golden_flutterwave_mint_is_unchanged():
    got = _golden_payloads()
    assert got == _golden_payloads()                                   # deterministic
    assert got == GOLDEN, "a shared-code change altered what a Flutterwave payment mints:\n" + "\n".join(got)


GOLDEN: list = [   # recorded from the pre-Stripe-parity code (main 43b0d7fa); regenerate only for a deliberate change
    '{"kind":"event","payload":{"by":"owner","credits":200,"decision":"auto","entry_id":"9911","issued_at":100.0,"kind":"topup","org_id":"acme","pubkey":"nAt68w0nKZD61NiHQMii+RnsXYROOLpH6NrSPgBjSt4=","reason":"credit grant 200 (topup) -> acme","requested_by":"owner","sig":"CIgblzp+c6Ptnv4sTsX6C9WE4E3xiFEtYKlI+oDvRdCji7Eo99WuCimnHOIOAUKVV9wMZutECGNBpUqUePM+Dw==","signal":"governor.credit_grant","source_ref":"9911","tier":"A0"}}',
    '{"kind":"event","payload":{"allotment":6000,"by":"owner","decision":"auto","issued_at":200.0,"org_id":"acme","period_end":1200.0,"period_start":200.0,"plan_id":"pro","pubkey":"nAt68w0nKZD61NiHQMii+RnsXYROOLpH6NrSPgBjSt4=","reason":"subscription acme -> plan pro (active, allotment 6000)","requested_by":"owner","sig":"4DR4TUK91Wvo4W71EhBF05hBgoLM81zcTnpWm2qzQTxy4tGq3Zwd7f6HOiu4qWWxlyh1RLK2N7vSTVB+aUSgCg==","signal":"governor.subscription","status":"active","tier":"A0"}}',
    '{"kind":"event","payload":{"by":"owner","credits":6000,"decision":"auto","entry_id":"refill:acme:1200.0","issued_at":200.0,"org_id":"acme","period_end":1200.0,"pubkey":"nAt68w0nKZD61NiHQMii+RnsXYROOLpH6NrSPgBjSt4=","reason":"plan credit grant 6000 -> acme (period_end 1200.0)","requested_by":"owner","sig":"lSRe/T6EUkcoJxeW8nDbdmziqPp76P1rBlL6Qvz+Su4PyhyZpijr/wbegLjd+SklXJPLjrpnZeg4r5r+N7rWBA==","signal":"governor.plan_grant","tier":"A0"}}',
]
