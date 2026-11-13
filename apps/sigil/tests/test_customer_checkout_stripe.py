"""Stripe parity ST-9: the customer checkout picks its processor from VIGIL_BILLING_PROVIDER.

Unset or `flutterwave` is the Flutterwave provider exactly as before; `stripe` builds the Stripe provider only when
every precondition of the Stripe lane holds; any other value is "not configured" and never falls back to the other
processor (which would take a payment the configured drain does not credit). The customer-facing checkout edge
(admit, offers, the second-plan guard, monitoring never sold) is unchanged when Stripe serves it.
"""
from __future__ import annotations

import copy

import pytest

from sigil.governor import catalog
from test_customer_checkout import _iso, _on, _provisioner  # noqa: F401

_PLAN = "vigil_pro_monthly"
_RETURN = "https://app.example.test/#/billing/return"


def _key(mode="test"):
    return "_".join(["sk", mode, "dummy" + "0" * 6 + "notreal"])


@pytest.fixture(autouse=True)
def _stripe_env(monkeypatch):
    for k in ("VIGIL_BILLING_PROVIDER", "VIGIL_BILLING_ENABLE_STRIPE", "VIGIL_STRIPE_WEBHOOK_SECRET",
              "VIGIL_STRIPE_SECRET_KEY", "VIGIL_STRIPE_API_VERSION"):
        monkeypatch.delenv(k, raising=False)


def _stripe_on(monkeypatch):
    monkeypatch.setenv("VIGIL_BILLING_PROVIDER", "stripe")
    monkeypatch.setenv("VIGIL_BILLING_ENABLE_STRIPE", "1")
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SECRET", "whsec_" + "st9")
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", "2000-01-01")
    monkeypatch.setenv("VIGIL_CUSTOMER_BILLING_RETURN_URL", _RETURN)


class _FakeStripe:
    def __init__(self):
        self.calls: list = []

    def create(self, params, *, idempotency_key):
        self.calls.append(copy.deepcopy(params))
        li = params["line_items"][0]["price_data"]
        sid = f"cs_test_{len(self.calls)}z"
        return {"object": "checkout.session", "id": sid, "livemode": False, "mode": params["mode"],
                "client_reference_id": params["client_reference_id"], "amount_total": li["unit_amount"],
                "currency": li["currency"], "url": f"https://checkout.stripe.com/c/pay/{sid}"}


def _with_fake_stripe(monkeypatch):
    from sigil.governor import stripe_egress as se
    fake = _FakeStripe()
    monkeypatch.setattr(se, "make_checkout_creator", lambda **k: fake.create)
    monkeypatch.setattr(se, "make_object_fetcher", lambda **k: (lambda kind, oid: {}))
    return fake


# ---- the selector ----------------------------------------------------------------------------------------------------
def test_stripe_serves_a_catalog_priced_tenant_bound_checkout(monkeypatch):
    _on(monkeypatch)
    _stripe_on(monkeypatch)
    fake = _with_fake_stripe(monkeypatch)
    p, admin, _t, org, _o, wallet = _provisioner()
    before = wallet.available(org)
    r = p.billing_checkout(admin, org, "vigil_topup_1k")
    amount, ccy = catalog.expected_amounts()["vigil_topup_1k"]
    assert r["checkout_url"].startswith("https://checkout.stripe.com/c/pay/cs_test_1z")
    assert r["tx_ref"].startswith(f"vigil:{org}:") and (r["amount_minor"], r["currency"]) == (amount, ccy)
    (params,) = fake.calls
    assert params["mode"] == "payment" and params["client_reference_id"] == r["tx_ref"]
    assert params["line_items"][0]["price_data"]["unit_amount"] == amount
    assert params["customer_email"] == "admin@acme.com" and params["metadata"]["org_id"] == org
    assert wallet.available(org) == before                      # checkout never credits


def test_a_stripe_plan_checkout_is_a_subscription_and_the_second_plan_guard_holds(monkeypatch):
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")
    _stripe_on(monkeypatch)
    fake = _with_fake_stripe(monkeypatch)
    ensure_owner_keypair()
    p, admin, _t, org, _o, _w = _provisioner()
    p.billing_checkout(admin, org, _PLAN, now=1000.0)
    period = catalog.entitlements()[_PLAN].period_s
    assert fake.calls[0]["mode"] == "subscription"
    assert fake.calls[0]["line_items"][0]["price_data"]["recurring"] == {"interval": "day",
                                                                         "interval_count": int(period // 86400)}
    SubscriptionRegistry(p.store).subscribe(org, "research", 2000, period_start=100.0, period_end=10_000.0,
                                            issued_at=100.0)
    with pytest.raises(ProvisionDenied, match="already has a plan"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    assert len(fake.calls) == 1


def test_monitoring_is_never_sold_through_stripe(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    _stripe_on(monkeypatch)
    fake = _with_fake_stripe(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, sorted(catalog.monitoring_price_ids())[0])
    assert fake.calls == []


@pytest.mark.parametrize("value", ["strpe", "stripe-test", "paypal", "flutterwave,stripe"])
def test_an_unknown_provider_is_not_configured_and_never_falls_back(monkeypatch, value):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "flw-" + "x")
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", "flw-" + "key")           # Flutterwave fully provisioned
    monkeypatch.setenv("VIGIL_BILLING_PROVIDER", value)
    p, admin, _t, org, _o, _w = _provisioner()
    assert p._checkout_provider() is None
    with pytest.raises(ProvisionDenied, match="not configured"):
        p.billing_checkout(admin, org, "vigil_topup_1k")


@pytest.mark.parametrize("missing", ["VIGIL_BILLING_ENABLE_STRIPE", "VIGIL_STRIPE_WEBHOOK_SECRET",
                                     "VIGIL_STRIPE_SECRET_KEY", "VIGIL_STRIPE_API_VERSION"])
def test_stripe_needs_every_precondition(monkeypatch, missing):
    _on(monkeypatch)
    _stripe_on(monkeypatch)
    _with_fake_stripe(monkeypatch)
    monkeypatch.delenv(missing)
    p, *_rest = _provisioner()
    assert p._checkout_provider() is None


def test_stripe_with_an_unrecognisable_key_or_only_flutterwave_secrets_is_refused(monkeypatch):
    _on(monkeypatch)
    _stripe_on(monkeypatch)
    _with_fake_stripe(monkeypatch)
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "dummy-not-a-stripe-key")
    p, *_rest = _provisioner()
    assert p._checkout_provider() is None
    for k in ("VIGIL_BILLING_ENABLE_STRIPE", "VIGIL_STRIPE_WEBHOOK_SECRET", "VIGIL_STRIPE_SECRET_KEY",
              "VIGIL_STRIPE_API_VERSION"):
        monkeypatch.delenv(k)
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "flw-" + "x")
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", "flw-" + "key")
    assert p._checkout_provider() is None                         # stripe chosen: Flutterwave secrets never serve


@pytest.mark.parametrize("value", [None, "", "flutterwave", " Flutterwave "])
def test_unset_or_flutterwave_is_the_flutterwave_provider(monkeypatch, value):
    from sigil.governor.billing import FlutterwaveBillingProvider
    _stripe_on(monkeypatch)                                       # Stripe fully set: still not used
    if value is None:
        monkeypatch.delenv("VIGIL_BILLING_PROVIDER")
    else:
        monkeypatch.setenv("VIGIL_BILLING_PROVIDER", value)
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "flw-" + "x")
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", "flw-" + "key")
    p, *_rest = _provisioner()
    assert isinstance(p._checkout_provider(), FlutterwaveBillingProvider)
