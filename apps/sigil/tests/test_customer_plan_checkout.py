"""Front B CHK-1b — SUBSCRIPTION plans through customer checkout, end to end (the recurring flow).

A plan checkout subscribes the payer to the processor's recurring plan: the catalog's subscription ``price_id`` IS
the Flutterwave ``payment_plan`` id, so the first charge AND every renewal re-verify with ``payment_plan ==
price_id`` and map back (via the tx_ref / meta we set) to the SAME catalog entitlement -> owner-signed subscribe +
allotment. Pinned:
  * plans are offered only with BOTH flags (base checkout + VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED), never the AEGIS
    monitoring plans (the drain does not wire that line — one would be charged for nothing);
  * the checkout posts ``payment_plan`` = the catalog price id, at the CATALOG amount;
  * END TO END: checkout -> verified first charge -> SUBSCRIBED with the catalog allotment; a renewal (new tx, same
    tx_ref) keeps it active;
  * the ALARM (plan flag ON): a verified successful plan charge with no recoverable tenant, or an unknown plan
    price, RAISES UnaccountedPayment (the spool quarantines -> the drain unit stays FAILED) instead of a silent
    no-op; with the flag OFF both stay byte-identical (None).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from test_customer_checkout import _LINK, _on, _provisioner, _real_provider

from sigil.governor import catalog
from sigil.governor.billing import (BillingSigner, FlutterwaveBillingProvider, UnaccountedPayment, _to_major)
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

_PLAN = "vigil_pro_monthly"


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    for k in ("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED",
              "VIGIL_CUSTOMER_MONITORING_ENABLED", "VIGIL_CUSTOMER_BILLING_RETURN_URL",
              "VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_FLW_SECRET_KEY", "VIGIL_BILLING_PLAN_ALARM"):
        monkeypatch.delenv(k, raising=False)


def _plans_on(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")


def _checkout_plan(monkeypatch, price=_PLAN):
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    return p.billing_checkout(admin, org, price), posted, org


def test_plans_need_the_extra_flag(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)                                          # base checkout ON, plan flag OFF
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, _PLAN)
    assert posted == []


def test_a_plan_checkout_posts_the_payment_plan_at_the_catalog_amount(monkeypatch):
    _plans_on(monkeypatch)
    r, posted, org = _checkout_plan(monkeypatch)
    amount_minor, currency = catalog.expected_amounts()[_PLAN]
    assert r["checkout_url"] == _LINK and posted[0]["payment_plan"] == _PLAN
    assert posted[0]["amount"] == _to_major(amount_minor, currency) and posted[0]["currency"] == currency
    assert posted[0]["tx_ref"].startswith(f"vigil:{org}:") and posted[0]["meta"]["org_id"] == org


def test_topups_never_carry_a_payment_plan(monkeypatch):
    _plans_on(monkeypatch)
    _r, posted, _org = _checkout_plan(monkeypatch, price="vigil_topup_1k")
    assert "payment_plan" not in posted[0]


def test_monitoring_plans_are_never_sold_here(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    mon = sorted(catalog.monitoring_price_ids())
    assert mon and set(mon) <= set(catalog.expected_amounts())        # offered + priced in the catalog ...
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, mon[0])
    assert posted == []                                               # ... yet never charged through this edge


def test_payment_plan_is_validated():
    prov = _real_provider([])
    with pytest.raises(ValueError, match="payment_plan"):
        prov.create_checkout("org_x", _PLAN, expected=catalog.expected_amounts(), payment_plan="bad\nplan")


# --- END TO END: checkout -> verified recurring charges -> owner-signed subscription -------------------------------

def _inbound(table, *, alarm=False):
    owner = generate_keypair()
    s = SpineStore(str(Path(__import__("tempfile").mkdtemp()) / "spine.jsonl"))   # never mktemp (CodeQL)
    subs = SubscriptionRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    prov = FlutterwaveBillingProvider("hash", lambda txid: table.get(str(txid)), alarm_unaccounted_plans=alarm)
    signer = BillingSigner(prov, wallet=WalletRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64),
                           subscriptions=subs,
                           plan=PlanCreditLedger(s, owner_key=owner, trusted_pubkey=owner.public_key_b64),
                           catalog=catalog.entitlements(), expected=catalog.expected_amounts(),
                           alarm_unaccounted_plans=alarm)
    return prov, signer, subs


def _charge(txid, tx_ref, created, *, plan=_PLAN, status="successful", org_meta=True):
    amount_minor, currency = catalog.expected_amounts().get(plan, (9900, "USD"))
    obj = {"id": txid, "status": status, "payment_plan": plan, "amount": _to_major(amount_minor, currency),
           "currency": currency, "created_at": created}
    if tx_ref:
        obj["tx_ref"] = tx_ref
    return obj


def _deliver(prov, signer, txid, now):
    ev = prov._reverify_and_map({"event": "charge.completed", "data": {"id": txid}})
    return None if ev is None else signer.apply(ev, now=now)


def test_end_to_end_a_purchased_plan_is_subscribed_and_renewals_keep_it_active(monkeypatch):
    _plans_on(monkeypatch)
    r, _posted, org = _checkout_plan(monkeypatch)
    ent = catalog.entitlements()[_PLAN]
    table = {"7001": _charge(7001, r["tx_ref"], 1000.0)}
    prov, signer, subs = _inbound(table)
    assert _deliver(prov, signer, 7001, 1000.0) is not None              # the first charge MINTS
    sub = subs.subscription(org)
    assert sub is not None and sub.plan_id == ent.plan_id and sub.allotment == ent.allotment
    assert subs.active_subscription(org, now=1000.0 + 10) is not None
    renewal_at = 1000.0 + ent.period_s - 60
    table["7002"] = _charge(7002, r["tx_ref"], renewal_at)                # the processor's renewal, same tx_ref
    assert _deliver(prov, signer, 7002, renewal_at) is not None
    assert subs.active_subscription(org, now=1000.0 + ent.period_s + 3600) is not None   # carried past period 1


def test_an_unattributable_paid_renewal_alarms_when_plans_are_on(monkeypatch):
    table = {"7101": _charge(7101, None, 2000.0)}                          # no tx_ref, no meta: the sandbox risk
    prov, signer, _subs = _inbound(table, alarm=True)
    with pytest.raises(UnaccountedPayment, match="no recoverable tenant"):
        _deliver(prov, signer, 7101, 2000.0)
    prov_off, signer_off, _ = _inbound(table, alarm=False)
    assert _deliver(prov_off, signer_off, 7101, 2000.0) is None         # flag OFF: byte-identical silent no-op


def test_an_unknown_plan_price_alarms_when_plans_are_on(monkeypatch):
    table = {"7201": _charge(7201, "vigil:org_x:n1", 3000.0, plan="flw_plan_not_in_catalog")}
    prov, signer, _subs = _inbound(table, alarm=True)
    with pytest.raises(UnaccountedPayment, match="not in the owner catalog"):
        _deliver(prov, signer, 7201, 3000.0)
    prov_off, signer_off, _ = _inbound(table, alarm=False)
    assert _deliver(prov_off, signer_off, 7201, 3000.0) is None


def test_a_failed_or_topup_charge_never_alarms(monkeypatch):
    table = {"7301": _charge(7301, None, 4000.0, status="failed"),
             "7302": {"id": 7302, "status": "successful", "amount": 10.0, "currency": "USD", "created_at": 4000.0}}
    prov, signer, _subs = _inbound(table, alarm=True)
    assert _deliver(prov, signer, 7301, 4000.0) is None                  # a failed plan debit with no tenant
    assert _deliver(prov, signer, 7302, 4000.0) is None                  # an unattributable TOP-UP: unchanged


def test_an_attributable_unknown_price_topup_stays_the_deliberate_safe_noop(monkeypatch):
    """The alarm is PLAN-scoped: the existing, deliberate "a top-up with an unknown price is a safe no-op" decision
    (test_billing_spool.test_unknown_price_is_a_safe_noop) is unchanged even with the alarm armed."""
    table = {"7303": {"id": 7303, "status": "successful", "tx_ref": "vigil:org_x:n9", "amount": 10.0,
                      "currency": "USD", "created_at": 4000.0, "meta": {"price_id": "topup_not_in_catalog"}}}
    prov, signer, _subs = _inbound(table, alarm=True)
    assert _deliver(prov, signer, 7303, 4000.0) is None


def test_the_drain_arms_the_alarm_exactly_when_plan_checkout_is_on():
    import inspect

    from sigil import cli
    src = inspect.getsource(cli.cmd_billing_drain)                       # the Flutterwave lane: the plan flag decides
    assert "alarm = billing_plan_alarm_enabled()" in src
    assert "alarm_unaccounted_plans=alarm" in src and "alarm=alarm" in src   # the provider AND the signer
    src = inspect.getsource(cli._stripe_billing_watcher)                 # the Stripe lane: always loud
    assert "alarm = True" in src and "alarm_unaccounted_plans=alarm" in src and "alarm=alarm" in src
    assert "alarm_unaccounted_plans=alarm" in inspect.getsource(cli._billing_signer)   # the shared signer builder


# --- CHK-1b red-pen folds -----------------------------------------------------------------------------------------

def test_a_second_plan_is_refused_while_one_is_active(monkeypatch):
    """HIGH: two processor subscriptions would double-bill (no processor cancel/upgrade path; newest charge wins)."""
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    from sigil.governor.identity import ensure_owner_keypair
    ensure_owner_keypair()                                    # the deployment owner identity the product reads with
    p, admin, _t, org, _o, _w = _provisioner()
    SubscriptionRegistry(p.store).subscribe(org, "research", 2000, period_start=100.0, period_end=10_000.0,
                                            issued_at=100.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    with pytest.raises(ProvisionDenied, match="already has a plan"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    assert posted == []
    p.billing_checkout(admin, org, "vigil_topup_1k", now=5000.0)          # top-ups stay available
    p.billing_checkout(admin, org, _PLAN, now=10_001.0)                  # once the plan has lapsed, allowed
    assert [x.get("payment_plan") for x in posted] == [None, _PLAN]


def test_a_plan_price_charge_without_payment_plan_alarms():
    """MED: a successful charge for a catalog PLAN price arriving without payment_plan maps to a top-up."""
    table = {"7401": {"id": 7401, "status": "successful", "tx_ref": "vigil:org_x:n1", "amount": 99.0,
                      "currency": "USD", "created_at": 5000.0, "meta": {"price_id": _PLAN}}}
    prov, signer, _subs = _inbound(table, alarm=True)
    with pytest.raises(UnaccountedPayment, match="carries no payment_plan"):
        _deliver(prov, signer, 7401, 5000.0)
    prov_off, signer_off, _ = _inbound(table, alarm=False)
    assert _deliver(prov_off, signer_off, 7401, 5000.0) is None


@pytest.mark.parametrize("amount,currency", [(79.0, "USD"), (99.0, "NGN")])
def test_an_underpaid_or_wrong_currency_plan_renewal_alarms(amount, currency):
    """MED: a renewal billed below the catalog price / in the wrong currency would mint nothing every period."""
    table = {"7501": {"id": 7501, "status": "successful", "tx_ref": "vigil:org_x:n1", "payment_plan": _PLAN,
                      "amount": amount, "currency": currency, "created_at": 6000.0}}
    prov, signer, _subs = _inbound(table, alarm=True)
    with pytest.raises(UnaccountedPayment, match="catalog expects"):
        _deliver(prov, signer, 7501, 6000.0)
    prov_off, signer_off, _ = _inbound(table, alarm=False)
    assert _deliver(prov_off, signer_off, 7501, 6000.0) is None


def test_a_paid_plan_charge_without_a_currency_alarms_and_never_mints():
    """No currency means no mint: the signer's wrong-currency cross-check cannot run without one."""
    charge = _charge(7701, "vigil:org_x:n1", 7000.0)
    del charge["currency"]
    table = {"7701": charge}
    prov, _signer, _subs = _inbound(table, alarm=True)
    with pytest.raises(UnaccountedPayment, match="has no currency"):
        prov._reverify_and_map({"event": "charge.completed", "data": {"id": 7701}})
    prov_off, signer_off, subs_off = _inbound(table, alarm=False)
    assert _deliver(prov_off, signer_off, 7701, 7000.0) is None
    assert subs_off.subscription("org_x") is None


@pytest.mark.parametrize("price_id", ["vigil_topup_1k", _PLAN])
def test_an_armed_alarm_makes_any_paid_charge_without_a_currency_loud(price_id):
    """A currency-less verify object is malformed for a top-up too, and for a PLAN price that arrived without
    payment_plan the provider's early return would otherwise also skip apply()'s 'carries no payment_plan'
    alarm. Armed: loud (quarantine). Not armed: mint nothing, as for any other refused top-up."""
    assert price_id in catalog.entitlements()
    table = {"7801": {"id": 7801, "status": "successful", "tx_ref": "vigil:org_x:n1", "amount": 10.0,
                      "created_at": 7100.0, "meta": {"price_id": price_id}}}
    prov, signer, _subs = _inbound(table, alarm=True)
    with pytest.raises(UnaccountedPayment, match="has no currency"):
        _deliver(prov, signer, 7801, 7100.0)
    prov_off, signer_off, subs_off = _inbound(table, alarm=False)
    assert _deliver(prov_off, signer_off, 7801, 7100.0) is None
    assert subs_off.subscription("org_x") is None


def test_an_unparseable_timestamp_on_a_paid_plan_charge_alarms():
    table = {"7601": _charge(7601, "vigil:org_x:n1", "not-a-date")}
    prov, _signer, _subs = _inbound(table, alarm=True)
    with pytest.raises(UnaccountedPayment, match="no parseable timestamp"):
        prov._reverify_and_map({"event": "charge.completed", "data": {"id": 7601}})


def test_the_alarm_outlives_turning_plan_sales_off(monkeypatch):
    """LOW: the drain alarm is not the SELLING flag — plans sold earlier keep renewing after sales stop."""
    from sigil import config
    monkeypatch.delenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_BILLING_PLAN_ALARM", raising=False)
    assert config.billing_plan_alarm_enabled() is False
    monkeypatch.setenv("VIGIL_BILLING_PLAN_ALARM", "1")
    assert config.billing_plan_alarm_enabled() is True                  # sales OFF, alarm still ON
    monkeypatch.delenv("VIGIL_BILLING_PLAN_ALARM")
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")
    assert config.billing_plan_alarm_enabled() is True
