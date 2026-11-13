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
        sess = {"object": "checkout.session", "id": sid, "livemode": False, "mode": params["mode"],
                "client_reference_id": params["client_reference_id"], "amount_total": li["unit_amount"],
                "currency": li["currency"], "url": f"https://checkout.stripe.com/c/pay/{sid}"}
        if "expires_at" in params:                     # Stripe echoes the session bound it was asked for
            sess["expires_at"] = params["expires_at"]
        return sess


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


# ---- audit E1 on the Stripe lane: the shared checkout seam's pending plan-checkout guard ---------------------------
def _stripe_guarded(monkeypatch, tmp_path, now=5000.0):
    """A Stripe-served provisioner whose pending plan-checkout ledger reads the spools where production looks
    (``billing_spool_dirs``), with the Stripe proxy spool pointed at ``tmp_path``; Stripe's clock is ``now``."""
    from sigil.governor import billing
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui.pending_checkout import PendingPlanCheckouts, billing_spool_dirs
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")
    _stripe_on(monkeypatch)
    for k in ("VIGIL_BILLING_WEBHOOK_SPOOL", "VIGIL_BILLING_SPOOL", "VIGIL_STRIPE_BILLING_SPOOL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SPOOL", str(tmp_path / "stripe-spool"))
    monkeypatch.setattr(billing.time, "time", lambda: now)
    fake = _with_fake_stripe(monkeypatch)
    ensure_owner_keypair()
    p, admin, _t, org, other, _w = _provisioner()
    old = p.pending_checkouts
    p.pending_checkouts = PendingPlanCheckouts(old.dir, owner_key=old.owner_key, trusted_pubkey=old.trusted_pubkey,
                                               billing_spools=billing_spool_dirs())
    return p, admin, org, other, fake, tmp_path / "stripe-spool"


def _stripe_envelope(root, obj: dict, stage: str, n: int):
    """What the proxy's /webhooks/stripe spools (``vigil.webhook.stripe.v1``) for an event about ``obj``."""
    import base64
    import json
    body = {"id": f"evt_{n}", "type": "invoice.paid" if obj.get("object") == "invoice"
            else "checkout.session.completed", "livemode": False, "data": {"object": obj}}
    env = {"schema": "vigil.webhook.stripe.v1", "body_b64": base64.b64encode(json.dumps(body).encode()).decode(),
           "stripe_signature": "t=1,v1=00", "received_at": 1.0}
    d = root / stage
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{n:032x}.json").write_text(json.dumps(env))


def _audits(p):
    seen: list = []
    real = p.store.append

    def cap(**kw):
        pl = kw.get("payload")
        if isinstance(pl, dict) and pl.get("signal") == "provision.audit":
            seen.append(pl)
        return real(**kw)
    p.store.append = cap
    return seen


def test_a_stripe_plan_link_dies_before_its_pending_record_and_a_topup_is_unbounded(monkeypatch, tmp_path):
    from sigil.ui.pending_checkout import DEFAULT_TTL_S, PLAN_LINK_SESSION_MIN
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, _root = _stripe_guarded(monkeypatch, tmp_path)
    p.billing_checkout(admin, org, "vigil_topup_1k", now=5000.0)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    topup, plan = fake.calls
    assert "expires_at" not in topup                                       # the top-up payload is unchanged
    assert plan["mode"] == "subscription"
    assert 5000 + PLAN_LINK_SESSION_MIN * 60 <= plan["expires_at"] < 5000 + DEFAULT_TTL_S
    with pytest.raises(ProvisionDenied, match="already in progress"):     # the second Stripe plan is refused
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S - 1)
    assert len(fake.calls) == 2


def test_a_stripe_session_without_the_bound_is_refused_and_frees_the_claim(monkeypatch, tmp_path):
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, _root = _stripe_guarded(monkeypatch, tmp_path)
    real = fake.create                     # (the patched creator factory reads fake.create at each checkout)
    fake.create = lambda params, *, idempotency_key: {
        k: v for k, v in real(params, idempotency_key=idempotency_key).items() if k != "expires_at"}
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    fake.create = real
    assert p.billing_checkout(admin, org, _PLAN, now=5001.0)["checkout_url"]   # no stale claim was left behind


@pytest.mark.parametrize("shape", ["session_ref", "session_meta", "session_blank_ref", "invoice_parent",
                                   "invoice_legacy"])
@pytest.mark.parametrize("stage", ["incoming", "working", "retry", "rejected"])
def test_an_undrained_stripe_webhook_holds_an_expired_window(monkeypatch, tmp_path, shape, stage):
    """The Stripe twin of the Flutterwave case: the paid plan's webhook waits undrained in the STRIPE spool (any
    stage), so the expired record must not lapse — and the refusal names that webhook, not an unreadable one."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    obj = {"session_ref": {"object": "checkout.session", "id": "cs_test_1z", "client_reference_id": first},
           "session_meta": {"object": "checkout.session", "id": "cs_test_1z", "metadata": {"tx_ref": first}},
           # an empty reference is no reference: the session is attributed by its metadata alone
           "session_blank_ref": {"object": "checkout.session", "id": "cs_test_1z", "client_reference_id": "",
                                 "metadata": {"tx_ref": first}},
           "invoice_parent": {"object": "invoice", "id": "in_1",
                              "parent": {"subscription_details": {"metadata": {"tx_ref": first}}}},
           "invoice_legacy": {"object": "invoice", "id": "in_1",
                              "subscription_details": {"metadata": {"tx_ref": first}}}}[shape]
    _stripe_envelope(root, obj, stage, 1)
    seen = _audits(p)
    later = 5000.0 + DEFAULT_TTL_S + 1
    assert p.customer_billing_offers(admin, org, now=later)["plan_checkout_pending"] is True
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=later)
    assert seen[-1]["outcome"] == "refused_pending_unconfirmed"
    assert first in seen[-1]["reason"] and f"{stage}/" in seen[-1]["reason"]
    assert len(fake.calls) == 1


def test_a_stripe_webhook_for_another_checkout_does_not_hold_the_window(monkeypatch, tmp_path):
    """Attribution is exact on the Stripe lane too: another org's quarantined invoice does not block this org."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    _stripe_envelope(root, {"object": "invoice", "id": "in_9",
                            "parent": {"subscription_details": {"metadata": {"tx_ref": "vigil:org_other:n9"}}}},
                     "rejected", 1)
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)   # the abandoned checkout lapsed
    assert len(fake.calls) == 2


@pytest.mark.parametrize("obj", [
    {"object": "invoice", "id": "in_1"},                                                   # names no checkout
    {"object": "checkout.session", "id": "cs_test_1z", "client_reference_id": "vigil:org_chk1:a",
     "metadata": {"tx_ref": "vigil:org_chk1:b"}},                                           # two that disagree
])
def test_a_stripe_webhook_that_cannot_be_attributed_refuses(monkeypatch, tmp_path, obj):
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    _stripe_envelope(root, obj, "rejected", 1)
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert "cannot be attributed" in seen[-1]["reason"] and len(fake.calls) == 1
