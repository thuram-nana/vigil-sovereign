"""Stripe parity ST-5: a signed Stripe event is re-fetched and minted from the FETCHED objects only.

Driven through `BillingSigner.ingest` with real wallet / subscription / plan / invoice / monitoring ledgers and a
fake Stripe API (the `fetcher`). The webhook body is trusted for the event type and the object id, nothing else:
tenant, price, amount, currency, status and time come from the fetched Checkout Session / Invoice / Subscription.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import tempfile

import pytest

from sigil.governor import catalog as cat
from sigil.governor.billing import (EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, BillingSigner, Entitlement,
                                    StripeBillingProvider, StripeEventRefused, UnaccountedPayment)
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
from sigil.governor.stripe_egress import StripeEgressError
from sigil.governor.subscription import STATUS_ACTIVE, STATUS_PAST_DUE, SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
_K = {"owner_key": OWNER, "trusted_pubkey": OWNER.public_key_b64}
_WHSEC = "whsec_" + "stripe-st5-test"
_AEGIS = "vigil_aegis_respond_1h_monthly"
_CATALOG = {
    "price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200),
    "price_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000, period_s=1000.0),
    _AEGIS: cat.mintable_entitlements()[_AEGIS],
}
_EXPECTED = {"price_topup_200": (20000, "USD"), "price_pro": (5000, "USD"), _AEGIS: cat.mintable_expected()[_AEGIS]}


def _session(sid="cs_test_a1", *, org="acme", price="price_topup_200", amount=20000, currency="usd",
             mode="payment", status="complete", payment_status="paid", created=1000, livemode=False, **extra):
    s = {"object": "checkout.session", "id": sid, "livemode": livemode, "mode": mode, "status": status,
         "payment_status": payment_status, "client_reference_id": f"vigil:{org}:n1", "amount_total": amount,
         "currency": currency, "created": created, "metadata": {"org_id": org, "price_id": price}}
    s.update(extra)
    return s


def _sub(sid="sub_1", *, org="acme", price="price_pro", livemode=False):
    return {"object": "subscription", "id": sid, "livemode": livemode,
            "metadata": {"org_id": org, "price_id": price, "tx_ref": f"vigil:{org}:n2"}}


def _invoice(iid="in_1", *, sub="sub_1", status="paid", reason="subscription_create", paid_at=1000, created=990,
             amount=5000, currency="usd", livemode=False):
    return {"object": "invoice", "id": iid, "livemode": livemode, "status": status, "billing_reason": reason,
            "subscription": sub, "amount_paid": amount, "currency": currency, "created": created,
            "status_transitions": {"paid_at": paid_at}}


class _Rig:
    def __init__(self, *, alarm=False, monitoring=True, objects=()):
        s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
        self.wallet, self.subs = WalletRegistry(s, **_K), SubscriptionRegistry(s, **_K)
        self.plan, self.invoices = PlanCreditLedger(s, **_K), InvoiceRegistry(s, **_K)
        self.msubs = MonitoringSubscriptionRegistry(s, **_K) if monitoring else None
        self.objects = {o["id"]: o for o in objects}
        self.fetched: list = []
        self.provider = StripeBillingProvider(_WHSEC, fetcher=self._fetch, expected_mode="test",
                                              enable_reference_adapter=True, alarm_unaccounted_plans=alarm)
        self.signer = BillingSigner(self.provider, wallet=self.wallet, subscriptions=self.subs, plan=self.plan,
                                    catalog=_CATALOG, expected=_EXPECTED, invoices=self.invoices,
                                    monitoring_subscriptions=self.msubs, alarm_unaccounted_plans=alarm,
                                    require_verified_amount=True)

    def _fetch(self, kind, oid):
        self.fetched.append((kind, oid))
        obj = self.objects[oid]
        if isinstance(obj, Exception):
            raise obj
        return copy.deepcopy(obj)

    def put(self, *objs):
        for o in objs:
            self.objects[o["id"]] = o

    def send(self, etype, oid, *, eid="evt_1", t=1000, body_extra=None, secret=_WHSEC, livemode=False):
        ev = {"id": eid, "object": "event", "type": etype, "created": t, "livemode": livemode,
              "data": {"object": {"id": oid, **(body_extra or {})}}}
        raw = json.dumps(ev).encode()
        mac = hmac.new(secret.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
        return self.signer.ingest(raw, f"t={t},v1={mac}", now=float(t))

    def lines(self, org="acme"):
        return [(i.invoice_id, i.kind) for i in self.invoices.invoices(org)]


# ---- top-ups -------------------------------------------------------------------------------------------------
def test_a_paid_topup_session_mints_once_with_one_invoice_line():
    r = _Rig(objects=[_session()])
    assert r.send("checkout.session.completed", "cs_test_a1") is not None
    assert r.wallet.available("acme") == 200 and r.lines() == [("cs_test_a1", "topup")]
    r.send("checkout.session.completed", "cs_test_a1")                          # replay -> folded once
    assert r.wallet.available("acme") == 200 and r.lines() == [("cs_test_a1", "topup")]


def test_completed_and_async_succeeded_for_one_session_mint_once():
    r = _Rig(objects=[_session()])
    r.send("checkout.session.completed", "cs_test_a1", eid="evt_1")
    r.send("checkout.session.async_payment_succeeded", "cs_test_a1", eid="evt_2")
    assert r.wallet.available("acme") == 200 and r.lines() == [("cs_test_a1", "topup")]


@pytest.mark.parametrize("change", [{"payment_status": "unpaid"}, {"status": "open"}, {"status": "expired"},
                                    {"mode": "subscription"}, {"mode": "setup"}])
def test_an_unpaid_or_non_payment_session_mints_nothing(change):
    r = _Rig(objects=[_session(**change)])
    assert r.send("checkout.session.completed", "cs_test_a1") is None
    assert r.wallet.available("acme") == 0


def test_async_payment_failed_mints_nothing_and_fetches_nothing():
    r = _Rig(objects=[_session()])
    assert r.send("checkout.session.async_payment_failed", "cs_test_a1") is None
    assert r.fetched == [] and r.wallet.available("acme") == 0


@pytest.mark.parametrize("amount,currency", [(19999, "usd"), (20000, "eur"), (0, "usd"), (-1, "usd"),
                                             (True, "usd"), (20000.0, "usd")])
def test_underpaid_or_wrong_currency_mints_nothing(amount, currency):
    r = _Rig(objects=[_session(amount=amount, currency=currency)])
    assert r.send("checkout.session.completed", "cs_test_a1") is None
    assert r.wallet.available("acme") == 0


@pytest.mark.parametrize("currency", [None, "", "us", "usdx", "u$d", "уsd"])
def test_no_currency_mints_nothing_and_raises_under_the_alarm(currency):
    r = _Rig(objects=[_session(currency=currency)])
    assert r.send("checkout.session.completed", "cs_test_a1") is None
    alarmed = _Rig(alarm=True, objects=[_session(currency=currency)])
    with pytest.raises(UnaccountedPayment):
        alarmed.send("checkout.session.completed", "cs_test_a1")
    assert alarmed.wallet.available("acme") == 0


def test_the_tenant_comes_from_the_fetched_session_never_the_body():
    r = _Rig(objects=[_session(org="beta")])
    r.send("checkout.session.completed", "cs_test_a1",
           body_extra={"client_reference_id": "vigil:acme:n1", "metadata": {"org_id": "acme"},
                       "amount_total": 999999, "currency": "usd"})
    assert r.wallet.available("acme") == 0 and r.wallet.available("beta") == 200


def test_conflicting_tenants_on_one_session_mint_nothing():
    conflicting = _session(metadata={"org_id": "beta", "price_id": "price_topup_200"})   # ref says acme
    r = _Rig(objects=[conflicting])
    assert r.send("checkout.session.completed", "cs_test_a1") is None
    assert r.wallet.available("acme") == 0 and r.wallet.available("beta") == 0
    with pytest.raises(UnaccountedPayment):
        _Rig(alarm=True, objects=[conflicting]).send("checkout.session.completed", "cs_test_a1")


def test_a_paid_session_without_a_tenant_or_time_raises_only_under_the_alarm():
    for broken in (_session(client_reference_id=None, metadata={"price_id": "price_topup_200"}),
                   _session(created=None), _session(created=1.5)):
        assert _Rig(objects=[broken]).send("checkout.session.completed", "cs_test_a1") is None
        with pytest.raises(UnaccountedPayment):
            _Rig(alarm=True, objects=[broken]).send("checkout.session.completed", "cs_test_a1")


def test_the_price_comes_only_from_metadata_price_id():
    s = _session(metadata={"org_id": "acme"}, line_items={"data": [{"price": {"id": "price_topup_200"}}]})
    r = _Rig(objects=[s])
    assert r.send("checkout.session.completed", "cs_test_a1") is None and r.wallet.available("acme") == 0


# ---- subscriptions -------------------------------------------------------------------------------------------
def test_a_create_invoice_subscribes_refills_and_records_the_catalog_priced_line():
    r = _Rig(objects=[_invoice(), _sub()])
    assert r.send("invoice.paid", "in_1") is not None
    s = r.subs.subscription("acme")
    assert s is not None and s.status == STATUS_ACTIVE and s.plan_id == "pro"
    assert (s.period_start, s.period_end) == (1000.0, 2000.0)
    assert any(t.granted == 6000 for t in r.plan.tranches("acme"))
    inv = r.invoices.invoices("acme")
    assert [(i.invoice_id, i.kind, i.amount_minor, i.currency) for i in inv] == [("in_1", "subscription", 5000, "USD")]
    assert r.fetched == [("invoice", "in_1"), ("subscription", "sub_1")]


def test_a_cycle_invoice_advances_the_period_and_a_replay_is_inert():
    r = _Rig(objects=[_invoice(), _sub(), _invoice("in_2", reason="subscription_cycle", paid_at=2000)])
    r.send("invoice.paid", "in_1")
    r.send("invoice.paid", "in_2", eid="evt_2", t=2000)
    s = r.subs.subscription("acme")
    assert (s.period_start, s.period_end) == (2000.0, 3000.0)
    before = len(r.invoices.invoices("acme"))
    assert r.send("invoice.paid", "in_2", eid="evt_2", t=2000) is None
    assert len(r.invoices.invoices("acme")) == before == 2


@pytest.mark.parametrize("reason", ["subscription_update", "manual", "subscription_threshold", None])
def test_a_mid_cycle_invoice_never_grants_a_period(reason):
    r = _Rig(objects=[_invoice(reason=reason), _sub()])
    assert r.send("invoice.paid", "in_1") is None and r.subs.subscription("acme") is None


@pytest.mark.parametrize("status", ["open", "draft", "void", "uncollectible"])
def test_an_unpaid_invoice_never_grants_a_period(status):
    r = _Rig(objects=[_invoice(status=status), _sub()])
    assert r.send("invoice.paid", "in_1") is None and r.subs.subscription("acme") is None


def test_the_subscription_id_is_read_from_either_api_shape_and_must_agree():
    newer = _invoice(sub=None)
    newer["parent"] = {"subscription_details": {"subscription": "sub_1"}}
    r = _Rig(objects=[newer, _sub()])
    assert r.send("invoice.paid", "in_1") is not None
    disagree = _invoice()
    disagree["parent"] = {"subscription_details": {"subscription": "sub_2"}}
    r2 = _Rig(objects=[disagree, _sub(), _sub("sub_2", org="beta")])
    assert r2.send("invoice.paid", "in_1") is None
    assert r2.subs.subscription("acme") is None and r2.subs.subscription("beta") is None
    with pytest.raises(UnaccountedPayment):
        _Rig(alarm=True, objects=[disagree, _sub()]).send("invoice.paid", "in_1")


def test_a_plan_price_only_in_the_subscription_items_mints_nothing():
    sub = _sub()
    sub["metadata"] = {"org_id": "acme"}
    sub["items"] = {"data": [{"price": {"id": "price_pro"}}]}
    r = _Rig(objects=[_invoice(), sub])
    assert r.send("invoice.paid", "in_1") is None and r.subs.subscription("acme") is None


def test_an_underpaid_renewal_mints_nothing_and_alarms():
    r = _Rig(objects=[_invoice(amount=4999), _sub()])
    assert r.send("invoice.paid", "in_1") is None
    with pytest.raises(UnaccountedPayment):
        _Rig(alarm=True, objects=[_invoice(amount=4999), _sub()]).send("invoice.paid", "in_1")


# ---- dunning ---------------------------------------------------------------------------------------------------
def test_payment_failed_latches_past_due_only_while_the_invoice_is_unpaid_and_fresh():
    r = _Rig(objects=[_invoice(), _sub(),
                      _invoice("in_old", status="open", reason="subscription_cycle", created=900),
                      _invoice("in_2", status="open", reason="subscription_cycle", created=1500),
                      _invoice("in_3", status="paid", reason="subscription_cycle", created=1600, paid_at=1700)])
    r.send("invoice.paid", "in_1")
    r.send("invoice.payment_failed", "in_3", eid="evt_f3")          # paid since -> nothing to reduce
    assert r.subs.subscription("acme").status == STATUS_ACTIVE
    r.send("invoice.payment_failed", "in_old", eid="evt_f0")        # older than the activation -> inert
    assert r.subs.subscription("acme").status == STATUS_ACTIVE
    r.send("invoice.payment_failed", "in_2", eid="evt_f2")          # a fresh failure -> past_due
    assert r.subs.subscription("acme").status == STATUS_PAST_DUE


def test_a_one_off_invoice_failure_reduces_nothing():
    r = _Rig(objects=[_invoice(), _sub(), _invoice("in_2", sub=None, status="open", reason="manual", created=1500)])
    r.send("invoice.paid", "in_1")
    assert r.send("invoice.payment_failed", "in_2", eid="evt_f") is None
    assert r.subs.subscription("acme").status == STATUS_ACTIVE


def test_subscription_deleted_is_not_acted_on():
    r = _Rig(objects=[_invoice(), _sub()])
    r.send("invoice.paid", "in_1")
    assert r.send("customer.subscription.deleted", "sub_1", eid="evt_d") is None
    assert r.subs.subscription("acme").status == STATUS_ACTIVE and ("subscription", "sub_1") not in r.fetched[2:]


# ---- AEGIS monitoring routing ----------------------------------------------------------------------------------
def test_an_aegis_price_mints_the_monitoring_line_only():
    amount, ccy = _EXPECTED[_AEGIS]
    r = _Rig(objects=[_invoice(amount=amount, currency=ccy.lower()), _sub(price=_AEGIS)])
    assert r.send("invoice.paid", "in_1") is not None
    assert r.msubs.subscription("acme") is not None and r.subs.subscription("acme") is None


def test_an_aegis_price_without_a_monitoring_line_mints_nothing_and_alarms():
    amount, ccy = _EXPECTED[_AEGIS]
    objs = [_invoice(amount=amount, currency=ccy.lower()), _sub(price=_AEGIS)]
    r = _Rig(monitoring=False, objects=objs)
    assert r.send("invoice.paid", "in_1") is None and r.subs.subscription("acme") is None
    with pytest.raises(UnaccountedPayment):
        _Rig(alarm=True, monitoring=False, objects=objs).send("invoice.paid", "in_1")


# ---- negative controls ------------------------------------------------------------------------------------------
def test_an_invoice_event_naming_a_session_id_fetches_nothing():
    r = _Rig(objects=[_session()])
    assert r.send("invoice.paid", "cs_test_a1") is None and r.fetched == []
    assert r.send("checkout.session.completed", "in_1") is None and r.fetched == []


@pytest.mark.parametrize("oid", ["../v1/charges", "in_1/x", "cs_test_", "cs_test_a1/../x", "cs_test_a1\n",
                                 "in_1\n", "evt_1", "pi_1", "", None, 7])
def test_a_malformed_object_id_fetches_nothing(oid):
    r = _Rig()
    for etype in ("invoice.paid", "checkout.session.completed"):
        assert r.send(etype, oid) is None
    assert r.fetched == []


def test_a_live_event_on_a_test_endpoint_is_refused_loudly():
    r = _Rig(objects=[_session()])
    with pytest.raises(StripeEventRefused):
        r.send("checkout.session.completed", "cs_test_a1", livemode=True)
    assert r.fetched == [] and r.wallet.available("acme") == 0


def test_an_event_without_a_mode_is_refused_loudly():
    r = _Rig(objects=[_session()])
    ev = json.dumps({"id": "evt_1", "type": "checkout.session.completed", "created": 1000,
                     "data": {"object": {"id": "cs_test_a1"}}}).encode()
    mac = hmac.new(_WHSEC.encode(), b"1000." + ev, hashlib.sha256).hexdigest()
    with pytest.raises(StripeEventRefused):
        r.signer.ingest(ev, f"t=1000,v1={mac}", now=1000.0)


def test_a_fetched_object_from_the_other_mode_is_refused_loudly():
    r = _Rig(objects=[_session(livemode=True)])
    with pytest.raises(StripeEventRefused):
        r.send("checkout.session.completed", "cs_test_a1")
    assert r.wallet.available("acme") == 0


def test_a_connected_account_event_is_refused_loudly():
    r = _Rig(objects=[_session()])
    ev = json.dumps({"id": "evt_1", "type": "checkout.session.completed", "created": 1000, "livemode": False,
                     "account": "acct_1", "data": {"object": {"id": "cs_test_a1"}}}).encode()
    mac = hmac.new(_WHSEC.encode(), b"1000." + ev, hashlib.sha256).hexdigest()
    with pytest.raises(StripeEventRefused):
        r.signer.ingest(ev, f"t=1000,v1={mac}", now=1000.0)
    assert r.fetched == []


@pytest.mark.parametrize("bad", [{"object": "payment_intent"}, {"id": "cs_test_other"}, {"object": None}])
def test_a_fetched_object_that_is_not_the_one_asked_for_mints_nothing(bad):
    s = _session()
    s.update(bad)
    r = _Rig()
    r.objects["cs_test_a1"] = s
    assert r.send("checkout.session.completed", "cs_test_a1") is None and r.wallet.available("acme") == 0


def test_a_fetch_failure_propagates_and_is_never_a_no_op():
    transient = StripeEgressError("Stripe GET returned HTTP 503")
    transient.transient = True
    r = _Rig(objects=[])
    r.objects["cs_test_a1"] = transient
    with pytest.raises(StripeEgressError) as ei:
        r.send("checkout.session.completed", "cs_test_a1")
    assert ei.value.transient is True
    r.objects["cs_test_a1"] = StripeEgressError("Stripe GET returned HTTP 404")
    with pytest.raises(StripeEgressError):
        r.send("checkout.session.completed", "cs_test_a1")


def test_a_body_signed_with_another_secret_or_shaped_for_flutterwave_mints_nothing():
    r = _Rig(objects=[_session()])
    assert r.send("checkout.session.completed", "cs_test_a1", secret="flw-secret-hash") is None
    raw = json.dumps({"event": "charge.completed", "livemode": False, "data": {"id": 9911}}).encode()
    mac = hmac.new(_WHSEC.encode(), b"1000." + raw, hashlib.sha256).hexdigest()
    assert r.signer.ingest(raw, f"t=1000,v1={mac}", now=1000.0) is None
    assert r.fetched == [] and r.wallet.available("acme") == 0


# ---- strict (drain-lane) mode: what the proxy already authenticated never fails silently ------------------------------
def _strict_rig(objects):
    r = _Rig(objects=objects)
    r.provider._strict = True
    return r


def test_strict_mode_quarantines_a_body_the_drain_secret_does_not_verify():
    r = _Rig(objects=[_session()])
    assert r.send("checkout.session.completed", "cs_test_a1", secret="whsec_" + "rolled") is None   # lenient: no-op
    s = _strict_rig([_session()])
    with pytest.raises(StripeEventRefused, match="does not verify"):
        s.send("checkout.session.completed", "cs_test_a1", secret="whsec_" + "rolled")
    assert s.fetched == [] and s.wallet.available("acme") == 0


def test_strict_mode_quarantines_a_signed_body_that_is_not_a_json_object():
    for raw in (b"not json", b"[1, 2]", b"\xff\xfe"):
        s = _strict_rig([])
        mac = hmac.new(_WHSEC.encode(), b"1000." + raw, hashlib.sha256).hexdigest()
        with pytest.raises(StripeEventRefused, match="not a JSON object"):
            s.signer.ingest(raw, f"t=1000,v1={mac}", now=1000.0)


def test_strict_mode_changes_nothing_for_a_good_delivery():
    s = _strict_rig([_session()])
    assert s.send("checkout.session.completed", "cs_test_a1") is not None and s.wallet.available("acme") == 200
