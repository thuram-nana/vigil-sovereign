"""Stripe parity ST-6: the outbound Stripe Checkout Session primitive.

Same contract as the Flutterwave `create_checkout`: the amount and currency come from the owner catalog, the
tenant is bound into every field the inbound mapper reads (and they agree), and the returned session must echo
what we asked for with an https link on exactly checkout.stripe.com. A round trip proves the binding: what this
creates is exactly what ST-5 mints from.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import tempfile

import pytest

from sigil.governor.billing import (CAP_HOSTED_CHECKOUT, CAP_RECURRING_PLAN, EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP,
                                    BillingSigner, Entitlement, StripeBillingProvider, UnsupportedCapability)
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

_EXPECTED = {"price_topup_200": (20000, "USD"), "price_pro": (5000, "USD")}
_PERIODS = {"price_pro": 30 * 86400.0}
_RETURN = "https://app.example.test/#/billing/return"
_WHSEC = "whsec_" + "checkout-st6"


class _Stripe:
    """A fake Stripe API: records each create and answers with a session built from the posted params."""

    def __init__(self, **override):
        self.calls: list = []
        self.sessions: dict = {}
        self.override = override

    def create(self, params, *, idempotency_key):
        self.calls.append((copy.deepcopy(params), idempotency_key))
        sid = f"cs_test_{len(self.calls)}x"
        li = params["line_items"][0]["price_data"]
        sess = {"object": "checkout.session", "id": sid, "livemode": False, "mode": params["mode"],
                "client_reference_id": params["client_reference_id"], "metadata": dict(params["metadata"]),
                "amount_total": li["unit_amount"], "currency": li["currency"],
                "url": f"https://checkout.stripe.com/c/pay/{sid}", "status": "open", "payment_status": "unpaid",
                "created": 1000}
        if "expires_at" in params:                     # Stripe echoes the session bound it was asked for
            sess["expires_at"] = params["expires_at"]
        sess.update(self.override)
        self.sessions[sid] = sess
        return copy.deepcopy(sess)


def _provider(api=None, **kw):
    return StripeBillingProvider(_WHSEC, fetcher=lambda kind, oid: {}, expected_mode="test",
                                 enable_reference_adapter=True,
                                 checkout_creator=(api.create if api is not None else None),
                                 plan_periods=_PERIODS, **kw)


def _checkout(p, price="price_topup_200", **kw):
    kw.setdefault("redirect_url", _RETURN)
    kw.setdefault("nonce", "n1")
    return p.create_checkout("acme", price, expected=_EXPECTED, **kw)


# ---- capability + refusals -------------------------------------------------------------------------------------
def test_no_creator_means_no_checkout():
    p = _provider()
    assert not p.supports(CAP_HOSTED_CHECKOUT)
    with pytest.raises(UnsupportedCapability):
        _checkout(p)
    assert {CAP_HOSTED_CHECKOUT, CAP_RECURRING_PLAN} <= _provider(_Stripe()).capabilities()


@pytest.mark.parametrize("kw,err", [
    ({"redirect_url": None}, ValueError), ({"redirect_url": "http://app.example.test/#/r"}, ValueError),
    ({"redirect_url": "https://u@app.example.test/"}, ValueError), ({"redirect_url": "https://a b/"}, ValueError),
    ({"redirect_url": "/relative"}, ValueError), ({"nonce": "a:b"}, ValueError), ({"nonce": "a b"}, ValueError),
])
def test_checkout_refuses_a_bad_return_url_or_nonce_before_calling_stripe(kw, err):
    api = _Stripe()
    with pytest.raises(err):
        _checkout(_provider(api), **kw)
    assert api.calls == []


def test_checkout_refuses_an_unknown_price_or_invalid_org():
    api = _Stripe()
    p = _provider(api)
    with pytest.raises(ValueError):
        p.create_checkout("acme", "price_free_lunch", expected=_EXPECTED, redirect_url=_RETURN)
    with pytest.raises(ValueError):
        p.create_checkout("../evil", "price_topup_200", expected=_EXPECTED, redirect_url=_RETURN)
    with pytest.raises(ValueError):
        p.create_checkout("acme", "price_zero", expected={"price_zero": (0, "USD")}, redirect_url=_RETURN)
    assert api.calls == []


@pytest.mark.parametrize("periods,plan", [({}, "price_pro"), ({"price_pro": 30.5 * 86400}, "price_pro"),
                                          ({"price_pro": 366 * 86400.0}, "price_pro"),
                                          ({"price_pro": 0.0}, "price_pro"), ({"price_pro": float("nan")}, "price_pro"),
                                          (_PERIODS, "price_other")])
def test_a_plan_checkout_needs_a_whole_day_catalog_period_and_its_own_price(periods, plan):
    api = _Stripe()
    p = StripeBillingProvider(_WHSEC, fetcher=lambda k, o: {}, expected_mode="test", enable_reference_adapter=True,
                              checkout_creator=api.create, plan_periods=periods)
    with pytest.raises(ValueError):
        p.create_checkout("acme", "price_pro", expected=_EXPECTED, redirect_url=_RETURN, payment_plan=plan)
    assert api.calls == []


# ---- the posted form --------------------------------------------------------------------------------------------
def test_a_topup_checkout_posts_catalog_priced_tenant_bound_params():
    api = _Stripe()
    sess = _checkout(_provider(api), customer_email="a@example.test")
    (params, ikey), = api.calls
    meta = {"org_id": "acme", "price_id": "price_topup_200", "tx_ref": "vigil:acme:n1"}
    assert params == {
        "mode": "payment",
        "line_items": [{"price_data": {"currency": "usd", "unit_amount": 20000,
                                       "product_data": {"name": "price_topup_200"}}, "quantity": 1}],
        "client_reference_id": "vigil:acme:n1",
        "metadata": meta,
        "payment_intent_data": {"metadata": meta},
        "success_url": _RETURN + "?status=successful&session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": _RETURN + "?status=cancelled",
        "adaptive_pricing": {"enabled": False},                         # never localised away from the catalog currency
        "customer_email": "a@example.test",
    }
    assert ikey == "vigil-co-n1"
    assert (sess.tx_ref, sess.org_id, sess.price_id, sess.amount_minor, sess.currency) == \
        ("vigil:acme:n1", "acme", "price_topup_200", 20000, "USD")
    assert sess.hosted_link == "https://checkout.stripe.com/c/pay/cs_test_1x"


def test_the_amount_follows_the_catalog_never_the_caller():
    api = _Stripe()
    _provider(api).create_checkout("acme", "price_topup_200", expected={"price_topup_200": (31337, "USD")},
                                   redirect_url=_RETURN, nonce="n1")
    pd = api.calls[0][0]["line_items"][0]["price_data"]
    assert (pd["unit_amount"], pd["currency"]) == (31337, "usd")


@pytest.mark.parametrize("ccy", ["ISK", "MGA", "HUF", "KWD", "EUR", "XAF"])
def test_a_currency_not_confirmed_for_stripe_is_refused_before_calling_stripe(ccy):
    api = _Stripe()
    with pytest.raises(ValueError, match="not enabled for"):
        _provider(api).create_checkout("acme", "p", expected={"p": (5000, ccy)}, redirect_url=_RETURN, nonce="n1")
    assert api.calls == []


def test_a_plan_checkout_is_a_subscription_recurring_in_days_with_subscription_metadata():
    api = _Stripe()
    _checkout(_provider(api), price="price_pro", payment_plan="price_pro")
    params = api.calls[0][0]
    assert params["mode"] == "subscription"
    assert params["line_items"][0]["price_data"]["recurring"] == {"interval": "day", "interval_count": 30}
    assert params["subscription_data"] == {"metadata": {"org_id": "acme", "price_id": "price_pro",
                                                        "tx_ref": "vigil:acme:n1"}}
    assert "payment_intent_data" not in params


def test_the_status_is_appended_where_the_customer_app_reads_it():
    for url, ok in (("https://app.example.test/#/billing/return",
                     "https://app.example.test/#/billing/return?status=successful"),
                    ("https://app.example.test/#/billing/return?x=1",
                     "https://app.example.test/#/billing/return?x=1&status=successful"),
                    ("https://app.example.test/return", "https://app.example.test/return?status=successful"),
                    ("https://app.example.test/return?x=1", "https://app.example.test/return?x=1&status=successful")):
        api = _Stripe()
        _checkout(_provider(api), redirect_url=url)
        assert api.calls[0][0]["success_url"].startswith(ok), url


# ---- the response must be the session we asked for ----------------------------------------------------------------
@pytest.mark.parametrize("override", [
    {"url": "https://checkout.stripe.com.evil.example/c/pay/x"}, {"url": "https://stripe.com/c/pay/x"},
    {"url": "https://evil.checkout.stripe.com/c/pay/x"}, {"url": "http://checkout.stripe.com/c/pay/x"},
    {"url": "https://u@checkout.stripe.com/c/pay/x"}, {"url": "https://checkout.stripe.com/c\r\nLocation: x"},
    {"url": None}, {"client_reference_id": "vigil:beta:n1"}, {"amount_total": 1}, {"amount_total": True},
    {"currency": "eur"}, {"currency": None}, {"mode": "subscription"}, {"livemode": True},
    {"object": "payment_intent"}, {"id": "pi_123"}, {"id": "cs_test_ok/../x"},
])
def test_a_response_that_is_not_our_session_is_refused(override):
    with pytest.raises(UnsupportedCapability):
        _checkout(_provider(_Stripe(**override)))


def test_a_creator_failure_never_leaks_its_message():
    def boom(params, *, idempotency_key):
        raise RuntimeError("Bearer " + "sk_" + "live_" + "do-not-print")
    p = StripeBillingProvider(_WHSEC, fetcher=lambda k, o: {}, expected_mode="test", enable_reference_adapter=True,
                              checkout_creator=boom)
    with pytest.raises(UnsupportedCapability) as ei:
        _checkout(p)
    assert "do-not-print" not in str(ei.value) and "RuntimeError" in str(ei.value)


# ---- round trip: what checkout binds is what the inbound mapper mints from ------------------------------------------
def test_checkout_then_the_paid_session_event_mints_for_the_bound_org():
    owner = generate_keypair()
    k = {"owner_key": owner, "trusted_pubkey": owner.public_key_b64}
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    api = _Stripe()
    objects: dict = {}

    def fetch(kind, oid):
        return copy.deepcopy(objects[oid])

    p = StripeBillingProvider(_WHSEC, fetcher=fetch, expected_mode="test", enable_reference_adapter=True,
                              checkout_creator=api.create, plan_periods=_PERIODS)
    wallet, subs = WalletRegistry(s, **k), SubscriptionRegistry(s, **k)
    signer = BillingSigner(p, wallet=wallet, subscriptions=subs, plan=PlanCreditLedger(s, **k),
                           invoices=InvoiceRegistry(s, **k), expected=_EXPECTED, require_verified_amount=True,
                           catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200),
                                    "price_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro",
                                                             allotment=6000, period_s=_PERIODS["price_pro"])})

    def send(etype, oid, eid):
        raw = json.dumps({"id": eid, "type": etype, "created": 1000, "livemode": False,
                          "data": {"object": {"id": oid}}}).encode()
        mac = hmac.new(_WHSEC.encode(), b"1000." + raw, hashlib.sha256).hexdigest()
        return signer.ingest(raw, f"t=1000,v1={mac}", now=1000.0)

    # top-up: the customer pays the session we created
    _checkout(p)
    sess = dict(api.sessions["cs_test_1x"], status="complete", payment_status="paid")
    objects[sess["id"]] = sess
    send("checkout.session.completed", sess["id"], "evt_1")
    assert wallet.available("acme") == 200

    # plan: Stripe creates the subscription carrying our subscription_data metadata, then bills its first invoice
    _checkout(p, price="price_pro", payment_plan="price_pro", nonce="n2")
    sub_meta = api.calls[1][0]["subscription_data"]["metadata"]
    objects["sub_1"] = {"object": "subscription", "id": "sub_1", "livemode": False, "metadata": sub_meta}
    objects["in_1"] = {"object": "invoice", "id": "in_1", "livemode": False, "status": "paid",
                       "billing_reason": "subscription_create", "subscription": "sub_1", "amount_paid": 5000,
                       "currency": "usd", "created": 1000, "status_transitions": {"paid_at": 1000}}
    send("invoice.paid", "in_1", "evt_2")
    sub = subs.subscription("acme")
    assert sub is not None and sub.plan_id == "pro" and sub.period_end - sub.period_start == _PERIODS["price_pro"]


# ---- the bounded plan session (the provisioner's pending plan-checkout record outlives it) ---------------------------
def test_a_bounded_session_sets_expires_at_and_an_unbounded_one_sends_none(monkeypatch):
    from sigil.governor import billing
    monkeypatch.setattr(billing.time, "time", lambda: 1_000_000.5)
    api = _Stripe()
    p = _provider(api)
    _checkout(p, price="price_pro", payment_plan="price_pro", session_minutes=30)
    _checkout(p, price="price_pro", payment_plan="price_pro", session_minutes=1440, nonce="n2")
    _checkout(p, nonce="n3")
    (bounded, _k), (ceiling, _k2), (topup, _k3) = api.calls
    # 30 min plus a little slack for our clock reading before Stripe creates the session; never past 24 h
    assert bounded["expires_at"] == 1_000_000 + 30 * 60 + 60
    assert ceiling["expires_at"] == 1_000_000 + 1440 * 60
    assert "expires_at" not in topup                                      # no bound asked: the payload is unchanged


@pytest.mark.parametrize("bad", [0, 29, 1441, True, "30", 30.0, -30])
def test_a_session_outside_stripes_range_is_refused_before_calling_stripe(bad):
    api = _Stripe()
    with pytest.raises(ValueError, match="session_minutes"):
        _checkout(_provider(api), price="price_pro", payment_plan="price_pro", session_minutes=bad)
    assert api.calls == []


@pytest.mark.parametrize("echo", [None, 0, True, "x", "same+1"])
def test_a_session_that_does_not_confirm_the_bound_is_refused(monkeypatch, echo):
    from sigil.governor import billing
    monkeypatch.setattr(billing.time, "time", lambda: 1_000_000.0)
    want = 1_000_000 + 30 * 60 + 60
    api = _Stripe(expires_at=(want + 1 if echo == "same+1" else echo))
    if echo is None:
        api = _Stripe()
        api.create = (lambda real: (lambda params, *, idempotency_key: {
            k: v for k, v in real(params, idempotency_key=idempotency_key).items() if k != "expires_at"}))(api.create)
    with pytest.raises(UnsupportedCapability, match="bounded payment session"):
        _checkout(_provider(api), price="price_pro", payment_plan="price_pro", session_minutes=30)
    ok = _Stripe()
    assert _checkout(_provider(ok), price="price_pro", payment_plan="price_pro", session_minutes=30).hosted_link


@pytest.mark.parametrize("resp", [None, ["checkout.session"], "cs_test_1x"])
def test_a_bounded_session_create_that_returns_no_session_is_refused(resp):
    api = _Stripe()
    api.create = lambda params, *, idempotency_key: resp
    with pytest.raises(UnsupportedCapability):
        _checkout(_provider(api), price="price_pro", payment_plan="price_pro", session_minutes=30)
