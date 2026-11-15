"""A verified paid TOP-UP the drain cannot credit at the catalog price quarantines and alarms (opt-in).

With ``alarm_unaccounted_topups`` (the Flutterwave lane: ``VIGIL_BILLING_TOPUP_ALARM``; the Stripe lane: always) the
signer raises ``UnaccountedPayment`` — writing nothing at all — for a top-up whose price is not in the catalog (with
a verified paid amount), that carries no verified currency (``require_verified_amount``), or that paid less than /
another currency than the catalog price. Off (the default) it is exactly today's silent no-op. An exact or higher
payment mints once; plan events behave exactly as before.
"""
from __future__ import annotations

import tempfile

import pytest

from sigil import config
from sigil.governor.billing import (EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, BillingEvent, BillingProvider,
                                     BillingSigner, Entitlement, UnaccountedPayment)
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.report_unlock import ReportUnlockRegistry
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
CATALOG = {"price_topup_1k": Entitlement(kind=EVENT_TOPUP, credits=1000),
           "price_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000, period_s=1000.0)}
EXPECTED = {"price_topup_1k": (1000, "USD"), "price_pro": (9900, "USD")}


class _Fixed(BillingProvider):
    def __init__(self, event):
        self.event = event

    def verify_and_parse(self, raw_body, sig_header, *, now):
        return self.event


def _rig(event, *, topups=False, plans=False, require=False):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    k = dict(owner_key=OWNER, trusted_pubkey=OP)
    w, inv, ru = WalletRegistry(s, **k), InvoiceRegistry(s, **k), ReportUnlockRegistry(s, **k)
    signer = BillingSigner(_Fixed(event), wallet=w, subscriptions=SubscriptionRegistry(s, **k),
                           plan=PlanCreditLedger(s, **k), catalog=CATALOG, expected=EXPECTED, invoices=inv,
                           report_unlocks=ru, alarm_unaccounted_plans=plans, require_verified_amount=require,
                           alarm_unaccounted_topups=topups)
    return s, w, inv, ru, signer


def _top(amount=1000, ccy="USD", price="price_topup_1k", eid="flw_1"):
    return BillingEvent(event_id=eid, kind=EVENT_TOPUP, org_id="acme", created=100.0, price_id=price,
                        amount_minor=amount, currency=ccy, data={"tx_ref": "vigil:acme:n1"})


def _length(store):
    return sum(1 for _ in store.iter_records())


@pytest.mark.parametrize("event,require", [
    (_top(amount=900), False),                         # underpaid
    (_top(ccy="EUR"), False),                          # another currency
    (_top(ccy=""), True),                              # no verified currency under require_verified_amount
    (_top(price="price_gone"), False),                 # a price not in the catalog, verified paid amount
], ids=["underpaid", "currency", "no_currency", "unknown_price"])
def test_an_uncreditable_paid_top_up_alarms_and_writes_nothing(event, require):
    s, w, inv, ru, signer = _rig(event, require=require)
    assert signer.ingest(b"{}", "s", now=100.0) is None                # flag OFF: today's silent no-op
    s, w, inv, ru, signer = _rig(event, topups=True, require=require)
    before = _length(s)
    with pytest.raises(UnaccountedPayment) as e:
        signer.ingest(b"{}", "s", now=100.0)
    assert "top-up flw_1" in str(e.value) and "UN-MINTED" in str(e.value) and "refund it or reconcile" in str(e.value)
    assert _length(s) == before                                       # no partial write of any kind
    assert w.available("acme") == 0 and inv.invoices("acme") == [] and not ru.is_unlocked("acme")


def test_the_message_names_the_paid_and_the_catalog_amounts():
    _s, _w, _i, _r, signer = _rig(_top(amount=900), topups=True)
    with pytest.raises(UnaccountedPayment, match=r"paid 900 USD, the catalog expects 1000 USD for 'price_topup_1k'"):
        signer.ingest(b"{}", "s", now=100.0)


@pytest.mark.parametrize("event", [_top(price="price_gone", amount=0, ccy=""), _top(price="price_gone", ccy="")],
                         ids=["no_amount_no_currency", "no_currency"])
def test_an_unknown_price_without_a_verified_paid_amount_stays_a_no_op(event):
    s, _w, _i, _r, signer = _rig(event, topups=True)
    assert signer.ingest(b"{}", "s", now=100.0) is None and _length(s) == 0


@pytest.mark.parametrize("amount", [1000, 1500], ids=["exact", "overpaid"])
def test_an_exact_or_higher_payment_mints_once(amount):
    s, w, inv, _r, signer = _rig(_top(amount=amount), topups=True)
    assert signer.ingest(b"{}", "s", now=100.0) is not None
    signer.ingest(b"{}", "s", now=100.0)                              # a replay folds once
    assert w.available("acme") == 1000 and len(inv.invoices("acme")) == 1


@pytest.mark.parametrize("plans", [False, True], ids=["plan_alarm_off", "plan_alarm_on"])
def test_plan_events_behave_exactly_as_before(plans):
    under = BillingEvent(event_id="in_1", kind=EVENT_SUBSCRIPTION_ACTIVE, org_id="acme", created=100.0,
                         price_id="price_pro", amount_minor=100, currency="USD")
    for topups in (False, True):
        _s, _w, _i, _r, signer = _rig(under, topups=topups, plans=plans)
        if plans:
            with pytest.raises(UnaccountedPayment, match="plan charge"):
                signer.ingest(b"{}", "s", now=100.0)
        else:
            assert signer.ingest(b"{}", "s", now=100.0) is None


def test_the_signer_default_is_off():
    """A signer built WITHOUT the kwarg (every caller before this change) keeps the silent no-op."""
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    k = dict(owner_key=OWNER, trusted_pubkey=OP)
    signer = BillingSigner(_Fixed(_top(amount=900)), wallet=WalletRegistry(s, **k),
                           subscriptions=SubscriptionRegistry(s, **k), plan=PlanCreditLedger(s, **k),
                           catalog=CATALOG, expected=EXPECTED)
    assert signer.ingest(b"{}", "s", now=100.0) is None and _length(s) == 0


@pytest.mark.parametrize("raw,on", [("", False), ("0", False), ("no", False), ("1", True), ("true", True),
                                    ("YES", True), (" on ", True), ("enabled", True)])
def test_the_env_reader(monkeypatch, raw, on):
    monkeypatch.setenv("VIGIL_BILLING_TOPUP_ALARM", raw)
    assert config.billing_topup_alarm_enabled() is on


def test_the_lanes_wire_the_alarm():
    import inspect

    from sigil import cli
    assert "alarm_unaccounted_topups=alarm_topups" in inspect.getsource(cli._billing_signer)
    assert "alarm_topups=billing_topup_alarm_enabled()" in inspect.getsource(cli.cmd_billing_drain)
    assert "alarm_topups=alarm" in inspect.getsource(cli._stripe_billing_watcher)


@pytest.mark.parametrize("ccy", ["USD", ""], ids=["with_currency", "no_currency"])
def test_a_plan_event_never_raises_the_top_up_alarm(ccy):
    """Every top-up alarm site is scoped to top-ups: an unknown-price, an underpaid and a currency-less plan event
    with only the top-up alarm armed stay today's no-op."""
    for price, amount in (("price_gone", 9900), ("price_pro", 100), ("price_pro", 9900)):
        ev = BillingEvent(event_id="in_9", kind=EVENT_SUBSCRIPTION_ACTIVE, org_id="acme", created=100.0,
                          price_id=price, amount_minor=amount, currency=ccy)
        if price == "price_pro" and amount == 9900 and ccy:
            continue                                                  # a correct plan payment mints (not a no-op)
        _s, _w, _i, _r, signer = _rig(ev, topups=True, require=True)
        assert signer.ingest(b"{}", "s", now=100.0) is None, (price, amount, ccy)
