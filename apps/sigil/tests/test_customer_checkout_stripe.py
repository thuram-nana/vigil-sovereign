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
        if "payment_method_types" in params:           # ... and the payment methods it was limited to
            sess["payment_method_types"] = list(params["payment_method_types"])
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


def _stripe_envelope(root, obj: dict, stage: str, n: int, etype: "str | None" = None):
    """What the proxy's /webhooks/stripe spools (``vigil.webhook.stripe.v1``) for an event about ``obj`` (of type
    ``etype``; by default ``invoice.paid`` for an invoice, else ``checkout.session.completed``)."""
    import base64
    import json
    body = {"id": f"evt_{n}", "type": etype or ("invoice.paid" if obj.get("object") == "invoice"
                                                else "checkout.session.completed"),
            "livemode": False, "data": {"object": obj}}
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


# ---- a COMPLETED Stripe subscription checkout drains as a no-op: it holds the window until a plan from it drains --
_COMPLETED = ("checkout.session.completed", "checkout.session.async_payment_succeeded")


def _completed_session(ref: str, *, mode: str = "subscription", paid: str = "unpaid") -> dict:
    return {"object": "checkout.session", "id": "cs_test_1z", "mode": mode, "status": "complete",
            "payment_status": paid, "client_reference_id": ref, "metadata": {"tx_ref": ref}, "subscription": "sub_1"}


def _plan_invoice(ref: str) -> dict:
    return {"object": "invoice", "id": "in_1", "parent": {"subscription_details": {"metadata": {"tx_ref": ref}}}}


@pytest.mark.parametrize("paid", ["unpaid", "paid"])
@pytest.mark.parametrize("etype", _COMPLETED)
def test_a_completed_stripe_subscription_checkout_holds_the_window_until_its_plan_drains(monkeypatch, tmp_path,
                                                                                        etype, paid):
    """The drain archives a subscription-mode completed session to processed/ as a no-op (that subscription's
    invoice.paid mints the plan). The checkout DID complete, so past its window the plan must not be offered or
    sold again while no plan from it has drained."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _stripe_envelope(root, _completed_session(first, paid=paid), "processed", 1, etype=etype)
    seen = _audits(p)
    later = 5000.0 + DEFAULT_TTL_S + 1
    assert p.customer_billing_offers(admin, org, now=later)["plan_checkout_pending"] is True
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=later)
    assert seen[-1]["outcome"] == "refused_pending_unconfirmed"
    assert first in seen[-1]["reason"] and "processed/" in seen[-1]["reason"]
    assert len(fake.calls) == 1 and fake.calls[0]["payment_method_types"] == ["card"]


def test_a_completed_stripe_subscription_checkout_holds_without_its_pending_record(monkeypatch, tmp_path):
    """The spine backstop reads the same: with the pending record file gone, the lapsed spine row's completed
    checkout still refuses the second plan."""
    from pathlib import Path

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _stripe_envelope(root, _completed_session(first), "processed", 1)
    for rec in Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64):
        rec.unlink()
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert seen[-1]["outcome"] == "refused_pending_unconfirmed" and first in seen[-1]["reason"]
    assert len(fake.calls) == 1


@pytest.mark.parametrize("settle", ["invoice.paid", "checkout.session.async_payment_failed"])
def test_the_hold_lifts_once_its_plan_invoice_drains_or_its_async_payment_fails(monkeypatch, tmp_path, settle):
    """Once that subscription's invoice.paid has drained (a drained live plan then refuses on its own), or its
    delayed payment failed, the completed session no longer holds the window."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _stripe_envelope(root, _completed_session(first), "processed", 1)
    _stripe_envelope(root, _plan_invoice(first) if settle == "invoice.paid" else _completed_session(first),
                     "processed", 2, etype=settle)
    later = 5000.0 + DEFAULT_TTL_S + 1
    assert p.customer_billing_offers(admin, org, now=later)["plan_checkout_pending"] is False
    p.billing_checkout(admin, org, _PLAN, now=later)
    assert len(fake.calls) == 2


@pytest.mark.parametrize("case", ["other_checkout", "payment_mode", "names_no_checkout", "not_an_envelope",
                                  "billing_schema"])
def test_only_a_completed_subscription_session_for_this_checkout_holds(monkeypatch, tmp_path, case):
    """Attribution is exact, and processed/ holds only what is ours: another checkout's completed session, a
    one-off (payment-mode) session, an event naming no checkout, or a file that is not an envelope does not hold
    the window (processed/ is the drain's permanent ledger; anything it archived was already handled)."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    if case == "other_checkout":
        _stripe_envelope(root, _completed_session("vigil:org_other:n9"), "processed", 1)
    elif case == "payment_mode":
        _stripe_envelope(root, _completed_session(first, mode="payment", paid="paid"), "processed", 1)
    elif case == "names_no_checkout":
        _stripe_envelope(root, {"object": "checkout.session", "id": "cs_test_9z", "mode": "subscription"},
                         "processed", 1)
    elif case == "not_an_envelope":
        (root / "processed").mkdir(parents=True, exist_ok=True)
        (root / "processed" / ("0" * 32 + ".json")).write_text("not json")
    else:  # the Flutterwave envelope schema: only the Stripe envelope schema carries Stripe's drained events
        import base64
        import json
        body = {"type": "checkout.session.completed", "data": {"object": _completed_session(first)}}
        (root / "processed").mkdir(parents=True, exist_ok=True)
        (root / "processed" / ("2" * 32 + ".json")).write_text(json.dumps(
            {"schema": "vigil.webhook.billing.v1", "body_b64": base64.b64encode(json.dumps(body).encode()).decode()}))
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert len(fake.calls) == 2


def test_each_earlier_checkout_is_held_on_its_own(monkeypatch, tmp_path):
    """Two earlier plan checkouts on the spine: the first completed and its plan drained (then lapsed), the second
    completed with no plan drained. With the pending record gone, the second still refuses on its own."""
    from pathlib import Path

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _stripe_envelope(root, _completed_session(first), "processed", 1)
    _stripe_envelope(root, _plan_invoice(first), "processed", 2)
    t1 = 5000.0 + DEFAULT_TTL_S + 1
    second = p.billing_checkout(admin, org, _PLAN, now=t1)["tx_ref"]
    _stripe_envelope(root, _completed_session(second), "processed", 3)
    for rec in Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64):
        rec.unlink()
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=t1 + DEFAULT_TTL_S + 1)
    assert seen[-1]["outcome"] == "refused_pending_unconfirmed" and second in seen[-1]["reason"]
    assert len(fake.calls) == 2


def test_another_checkouts_settling_event_does_not_lift_the_hold(monkeypatch, tmp_path):
    """Lifting is exact too: another checkout's drained invoice or failed payment leaves THIS hold in place."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _stripe_envelope(root, _completed_session(first), "processed", 1)
    _stripe_envelope(root, _plan_invoice("vigil:org_other:n9"), "processed", 2)
    _stripe_envelope(root, _completed_session("vigil:org_other:n9"), "processed", 3,
                     etype="checkout.session.async_payment_failed")
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert len(fake.calls) == 1


@pytest.mark.parametrize("fault", ["file", "stage"])
def test_a_processed_file_that_cannot_be_read_refuses(monkeypatch, tmp_path, fault):
    """Fail-closed: a file in the Stripe spool's processed/ that cannot be read, or a processed/ that cannot be
    listed, could hide the completed session."""
    import os

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, _other, fake, root = _stripe_guarded(monkeypatch, tmp_path)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    if fault == "file":
        (root / "processed").mkdir(parents=True, exist_ok=True)
        os.symlink(tmp_path / "elsewhere.json", root / "processed" / ("1" * 32 + ".json"))   # never followed
    else:
        root.mkdir(parents=True, exist_ok=True)
        (root / "processed").write_text("")                     # not a directory: it cannot be listed
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert "processed/" in seen[-1]["reason"] and "unreadable" in seen[-1]["reason"]
    assert len(fake.calls) == 1


def test_only_the_stripe_spools_processed_is_read(tmp_path):
    """The ledger reads processed/ only in the spools it is given as Stripe's (production: the Stripe spool
    locations), so the Flutterwave spool's drained ledger is never read."""
    import os

    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    flw, stripe = tmp_path / "flw", tmp_path / "stripe"
    for root in (flw, stripe):
        (root / "processed").mkdir(parents=True)
    os.symlink(tmp_path / "x.json", flw / "processed" / ("1" * 32 + ".json"))   # unreadable, but not read
    kp = generate_keypair()
    led = PendingPlanCheckouts(tmp_path / "pending", owner_key=kp, trusted_pubkey=kp.public_key_b64,
                               billing_spools=[flw, stripe], stripe_spools=[stripe])
    assert led.undrained(["vigil:org_chk1:n1"]) == ""
    os.symlink(tmp_path / "x.json", stripe / "processed" / ("1" * 32 + ".json"))
    assert "unreadable" in led.undrained(["vigil:org_chk1:n1"])
    every = PendingPlanCheckouts(tmp_path / "pending", owner_key=kp, trusted_pubkey=kp.public_key_b64,
                                 billing_spools=[flw])      # not told which are Stripe's: it reads them all
    assert "unreadable" in every.undrained(["vigil:org_chk1:n1"])


# ---- processed/ is a never-pruned ledger: its reads are bounded, and a bound that is hit holds ----------------------
def _ledger_envelope(proc, obj: dict, etype: str) -> str:
    """Write one Stripe event to ``proc`` (a processed/) the way the drain names it: by the sha256 of its bytes."""
    import base64
    import hashlib
    import json
    body = {"id": "evt_x", "type": etype, "livemode": False, "data": {"object": obj}}
    raw = json.dumps({"schema": "vigil.webhook.stripe.v1", "body_b64": base64.b64encode(json.dumps(body).encode())
                      .decode(), "stripe_signature": "t=1,v1=00", "received_at": 1.0}).encode()
    name = hashlib.sha256(raw).hexdigest() + ".json"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / name).write_bytes(raw)
    return name


def _counted_processed_reads(monkeypatch, stages=None):
    """Start from an empty remembered ledger and count every processed/ file opened (and, into ``stages``, every
    file opened in an undrained stage)."""
    import sigil.ui.pending_checkout as PC
    monkeypatch.setattr(PC, "_PROCESSED_SEEN", {})
    opened: list = []
    real = PC._read_capped

    def counting(path):
        if path.parent.name == "processed":
            opened.append(path.name)
        elif stages is not None:
            stages.append(path.name)
        return real(path)
    monkeypatch.setattr(PC, "_read_capped", counting)
    return opened


def _ledger(tmp_path, *roots):
    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    kp = generate_keypair()
    return PendingPlanCheckouts(tmp_path / "pending", owner_key=kp, trusted_pubkey=kp.public_key_b64,
                                billing_spools=list(roots), stripe_spools=list(roots))


def test_each_processed_file_is_opened_once_across_offers_reads(monkeypatch, tmp_path):
    """The offers read (``pending``) of an org whose record has expired re-checks processed/ every time. Each
    content-addressed file there is opened ONCE (then remembered by its name), and the spool locations that resolve
    to the same directory are read once (the undrained stages too): a later read opens only what is new."""
    import os

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    root = tmp_path / "stripe-spool"
    os.symlink(root, tmp_path / "alias", target_is_directory=True)
    proc = root / "processed"
    for i in range(40):                                              # the ledger: other checkouts' settled plans
        _ledger_envelope(proc, _plan_invoice(f"vigil:org_old{i}:n{i}"), "invoice.paid")
    _stripe_envelope(root, _plan_invoice("vigil:org_other:n9"), "retry", 7)   # another org's webhook, parked
    led = _ledger(tmp_path, root, tmp_path / "alias", root)
    ref = led.claim("org_chk1", _PLAN, "vigil:org_chk1:n1", now=1000.0)["record"]["tx_ref"]
    _ledger_envelope(proc, _completed_session(ref), "checkout.session.completed")
    staged: list = []
    opened = _counted_processed_reads(monkeypatch, staged)
    later = 1000.0 + DEFAULT_TTL_S + 1
    assert led.pending("org_chk1", now=later) is True                # the completed checkout holds
    assert len(opened) == 41 and len(set(opened)) == 41              # every file once, not once per alias
    assert len(staged) == 2                                          # the parked one: once per stage pass
    for _ in range(3):
        assert led.pending("org_chk1", now=later) is True
    assert len(opened) == 41                                         # nothing re-opened
    settled = _ledger_envelope(proc, _plan_invoice(ref), "invoice.paid")
    assert led.pending("org_chk1", now=later) is False               # its plan drained: the hold lifts
    assert opened[41:] == [settled]                                  # ... and only the new file was opened


def test_a_read_budget_that_is_hit_holds_until_the_ledger_is_read(monkeypatch, tmp_path):
    """At most ``_PROCESSED_READ_BUDGET`` unseen files are opened per check; a check that leaves any unread holds
    (reads as pending, refuses the claim) and the next check reads on from there."""
    import sigil.ui.pending_checkout as PC
    from sigil.ui.pending_checkout import DEFAULT_TTL_S, PendingCheckoutRefused
    root = tmp_path / "stripe-spool"
    for i in range(25):
        _ledger_envelope(root / "processed", _plan_invoice(f"vigil:org_old{i}:n{i}"), "invoice.paid")
    led = _ledger(tmp_path, root)
    led.claim("org_chk1", _PLAN, "vigil:org_chk1:n1", now=1000.0)
    opened = _counted_processed_reads(monkeypatch)
    monkeypatch.setattr(PC, "_PROCESSED_READ_BUDGET", 10)
    later = 1000.0 + DEFAULT_TTL_S + 1
    assert led.pending("org_chk1", now=later) is True and len(opened) == 10
    with pytest.raises(PendingCheckoutRefused, match="has not been confirmed") as exc:
        led.claim("org_chk1", _PLAN, "vigil:org_chk1:n2", now=later)
    assert "has 5 envelope(s) not read yet" in exc.value.detail and len(opened) == 20
    assert led.undrained(["vigil:org_chk1:n1"]) == "" and len(opened) == 25
    assert led.pending("org_chk1", now=later) is False and len(opened) == 25
    assert led.claim("org_chk1", _PLAN, "vigil:org_chk1:n2", now=later)["record"]["tx_ref"] == "vigil:org_chk1:n2"


def test_a_ledger_over_the_entry_cap_holds_without_being_read(monkeypatch, tmp_path):
    """A processed/ of more than ``_PROCESSED_MAX_ENTRIES`` files holds without opening any; a second location
    resolving to the same directory does not count its files twice."""
    import os

    import sigil.ui.pending_checkout as PC
    root = tmp_path / "stripe-spool"
    for i in range(6):
        _ledger_envelope(root / "processed", _plan_invoice(f"vigil:org_old{i}:n{i}"), "invoice.paid")
    os.symlink(root, tmp_path / "alias", target_is_directory=True)
    led = _ledger(tmp_path, root, tmp_path / "alias")
    opened = _counted_processed_reads(monkeypatch)
    monkeypatch.setattr(PC, "_PROCESSED_MAX_ENTRIES", 6)
    assert led.undrained(["vigil:org_chk1:n1"]) == "" and len(opened) == 6
    _ledger_envelope(root / "processed", _plan_invoice("vigil:org_old6:n6"), "invoice.paid")
    assert "holds more than 6 envelopes" in led.undrained(["vigil:org_chk1:n1"])
    assert len(opened) == 6


def test_the_remembered_ledger_is_capped_and_drops_files_that_are_gone(monkeypatch, tmp_path):
    """The names remembered never exceed ``_PROCESSED_MAX_ENTRIES``: once full, names no longer listed make room."""
    import sigil.ui.pending_checkout as PC
    root = tmp_path / "stripe-spool"
    names = [_ledger_envelope(root / "processed", _plan_invoice(f"vigil:org_old{i}:n{i}"), "invoice.paid")
             for i in range(4)]
    led = _ledger(tmp_path, root)
    opened = _counted_processed_reads(monkeypatch)
    monkeypatch.setattr(PC, "_PROCESSED_MAX_ENTRIES", 4)
    assert led.undrained(["vigil:org_chk1:n1"]) == "" and sorted(PC._PROCESSED_SEEN) == sorted(names)
    for gone in names[:2]:
        (root / "processed" / gone).unlink()
    new = [_ledger_envelope(root / "processed", _plan_invoice(f"vigil:org_new{i}:n{i}"), "invoice.paid")
           for i in range(2)]
    assert led.undrained(["vigil:org_chk1:n1"]) == ""
    assert sorted(PC._PROCESSED_SEEN) == sorted(names[2:] + new) and sorted(opened[4:]) == sorted(new)
    assert led.undrained(["vigil:org_chk1:n1"]) == "" and len(opened) == 6
    listed = [(root / "processed", sorted(names[2:] + new + ["e" * 64 + ".json"]))]
    PC._remember_processed("e" * 64 + ".json", ("", ""), listed)      # full, and every name still listed
    assert len(PC._PROCESSED_SEEN) == 4 and "e" * 64 + ".json" not in PC._PROCESSED_SEEN


def test_a_file_not_named_by_its_content_is_read_every_time(monkeypatch, tmp_path):
    """Only a content-addressed name fixes what the file holds; any other file is opened on every check, so a
    rewrite of it is seen."""
    import sigil.ui.pending_checkout as PC
    root = tmp_path / "stripe-spool"
    ref = "vigil:org_chk1:n1"
    _stripe_envelope(root, _plan_invoice("vigil:org_other:n9"), "processed", 1)
    led = _ledger(tmp_path, root)
    opened = _counted_processed_reads(monkeypatch)
    assert led.undrained([ref]) == "" and len(opened) == 1 and PC._PROCESSED_SEEN == {}
    _stripe_envelope(root, _completed_session(ref), "processed", 1)               # same name, new content
    assert ref in led.undrained([ref]) and len(opened) == 2


def test_processed_is_read_only_after_two_stable_stage_passes(monkeypatch, tmp_path):
    """undrained() reads processed/ only AFTER two consecutive stage passes saw the same files. A completed session
    that the drain moves from working/ to processed/ just as the first stage pass starts is missed by that pass,
    and must be found in processed/ (reading processed/ before the stage scan would miss it in both places)."""
    import os
    root = tmp_path / "stripe-spool"
    ref = "vigil:org_chk1:n1"
    (root / "processed").mkdir(parents=True)
    _stripe_envelope(root, _completed_session(ref), "working", 1)
    led = _ledger(tmp_path, root)
    real, passes = led._spool_pass, []

    def drain_moves_it_first(wanted):
        if not passes:
            src = root / "working" / f"{1:032x}.json"
            os.replace(src, root / "processed" / src.name)       # the drain archives it (a subscription no-op)
        passes.append(1)
        return real(wanted)
    monkeypatch.setattr(led, "_spool_pass", drain_moves_it_first)
    why = led.undrained([ref])
    assert len(passes) == 2 and not (root / "working" / f"{1:032x}.json").exists()
    assert "processed/" in why and ref in why, why


def test_one_stable_stage_pass_is_not_enough_to_read_processed(monkeypatch, tmp_path):
    """A webhook in transit between stages during the first pass (out of retry/, not yet back in incoming/) is
    invisible to it although that pass saw no file vanish. Only a second pass that agrees clears the stages, so it
    is found there and processed/ is never consulted."""
    import os
    root = tmp_path / "stripe-spool"
    ref = "vigil:org_chk1:n1"
    (root / "processed").mkdir(parents=True)
    (root / "incoming").mkdir()
    _stripe_envelope(root, _completed_session(ref), "retry", 1)
    led = _ledger(tmp_path, root)
    real, passes = led._spool_pass, []
    name, held = f"{1:032x}.json", tmp_path / "in-transit.json"

    def in_transit_during_the_first_pass(wanted):
        passes.append(1)
        if len(passes) > 1:
            return real(wanted)
        os.replace(root / "retry" / name, held)
        out = real(wanted)
        os.replace(held, root / "incoming" / name)               # the drain re-admits it to incoming/
        return out
    monkeypatch.setattr(led, "_spool_pass", in_transit_during_the_first_pass)
    why = led.undrained([ref])
    assert len(passes) == 2 and "incoming/" in why and ref in why, why
