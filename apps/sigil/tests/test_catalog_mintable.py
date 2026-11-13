"""S1 — the catalog separates what is OFFERED (on sale) from what is MINTABLE (what the billing drain mints).

Load-bearing invariants:
  * a SKU that was ever sold always mints or raises an alarm, whatever the sale flags say: the drain's signer is
    built from the flag-independent mintable_entitlements() / mintable_expected(), never the flag-filtered
    entitlements() / expected_amounts();
  * a `retired` entry leaves the sale surface (plans(), entitlements(), expected_amounts(), hosted checkout) yet a
    drain-built signer still mints it exactly once;
  * a paid monitoring period that reaches a signer with no monitoring line raises UnaccountedPayment under the plan
    alarm (alarm off keeps the historical no-op);
  * no entry is retired in this slice and the offered surface is byte-identical to before.
"""
from __future__ import annotations

import dataclasses
import json
import tempfile

import pytest

from sigil.governor import catalog as cat
from sigil.governor.billing import (EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, BillingSigner, MockBillingProvider,
                                     UnaccountedPayment)
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64

_MON = "VIGIL_CUSTOMER_MONITORING_ENABLED"


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _drain_signer(s, *, alarm):
    """The billing drain's construction (cli.cmd_billing_drain): FULL catalog, NO monitoring line wired."""
    mock = MockBillingProvider("sek")
    k = {"owner_key": OWNER, "trusted_pubkey": OP}
    w = WalletRegistry(s, **k)
    signer = BillingSigner(mock, wallet=w, subscriptions=SubscriptionRegistry(s, **k), plan=PlanCreditLedger(s, **k),
                           catalog=cat.mintable_entitlements(), expected=cat.mintable_expected(),
                           alarm_unaccounted_plans=alarm)
    return signer, mock, w


def _event(mock, eid, kind, price, created=100.0, org="org_a"):
    body = json.dumps({"event_id": eid, "kind": kind, "org_id": org, "created": created,
                       "price_id": price}).encode()
    return body, mock.sign(body)


def _monitoring_price():
    return next(e.price_id for e in cat._CATALOG if e.monitor_hosts)


def _retire(monkeypatch, price_id):
    new = tuple(dataclasses.replace(e, retired=True) if e.price_id == price_id else e for e in cat._CATALOG)
    cat._validate(new)
    monkeypatch.setattr(cat, "_CATALOG", new)


# --- offers unchanged ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("monitoring", [False, True])
def test_offered_surface_unchanged(monkeypatch, monitoring):
    if monitoring:
        monkeypatch.setenv(_MON, "1")
    else:
        monkeypatch.delenv(_MON, raising=False)
    assert not any(e.retired for e in cat._CATALOG), "S1 retires nothing"
    pre = [e for e in cat._CATALOG if monitoring or not e.monitor_hosts]
    assert cat.plans() == [e.public() for e in pre]
    assert cat.entitlements() == {e.price_id: e.entitlement() for e in pre}
    assert cat.expected_amounts() == {e.price_id: (e.amount_minor, e.currency) for e in pre}
    assert all("retired" not in p for p in cat.plans())          # the public projection is unchanged


@pytest.mark.parametrize("monitoring", [False, True])
def test_mintable_is_the_full_catalog_whatever_the_flags(monkeypatch, monitoring):
    if monitoring:
        monkeypatch.setenv(_MON, "1")
    else:
        monkeypatch.delenv(_MON, raising=False)
    assert cat.mintable_entitlements() == {e.price_id: e.entitlement() for e in cat._CATALOG}
    assert cat.mintable_expected() == {e.price_id: (e.amount_minor, e.currency) for e in cat._CATALOG}
    assert _monitoring_price() in cat.mintable_entitlements()


# --- retired: off sale, still minted --------------------------------------------------------------------------

def test_retired_entry_is_not_offered_but_still_mints_exactly_once(monkeypatch):
    monkeypatch.setenv(_MON, "1")
    pid = next(e.price_id for e in cat._CATALOG if e.kind == EVENT_TOPUP)
    credits = next(e.credits for e in cat._CATALOG if e.price_id == pid)
    _retire(monkeypatch, pid)
    assert pid not in {p["price_id"] for p in cat.plans()}
    assert pid not in cat.entitlements() and pid not in cat.expected_amounts()
    from sigil.ui.provision import Provisioner
    offered, _ = Provisioner._checkout_offered()
    assert pid not in offered                                    # hosted checkout cannot sell it
    assert pid in cat.mintable_entitlements() and pid in cat.mintable_expected()

    s = _store()
    signer, mock, w = _drain_signer(s, alarm=True)
    body, sig = _event(mock, "evt_retired_1", EVENT_TOPUP, pid)
    assert signer.ingest(body, sig, now=100.0) is not None
    signer.ingest(body, sig, now=101.0)                          # a replay folds once
    assert w.available("org_a") == credits


def test_retired_must_be_a_bool():
    bad = (dataclasses.replace(cat._CATALOG[0], retired="yes"),)
    with pytest.raises(ValueError):
        cat._validate(bad)


# --- the monitoring alarm survives the full catalog -----------------------------------------------------------

def test_monitoring_charge_without_a_line_raises_under_the_alarm(monkeypatch):
    monkeypatch.delenv(_MON, raising=False)
    s = _store()
    signer, mock, _ = _drain_signer(s, alarm=True)
    before = s.count()
    body, sig = _event(mock, "evt_mon_1", EVENT_SUBSCRIPTION_ACTIVE, _monitoring_price())
    with pytest.raises(UnaccountedPayment):
        signer.ingest(body, sig, now=100.0)
    assert s.count() == before                     # nothing minted


def test_monitoring_charge_without_a_line_is_a_noop_with_the_alarm_off(monkeypatch):
    monkeypatch.delenv(_MON, raising=False)
    s = _store()
    signer, mock, _ = _drain_signer(s, alarm=False)
    before = s.count()
    body, sig = _event(mock, "evt_mon_2", EVENT_SUBSCRIPTION_ACTIVE, _monitoring_price())
    assert signer.ingest(body, sig, now=100.0) is None
    assert s.count() == before


def test_topup_event_naming_a_monitoring_price_raises_under_the_alarm(monkeypatch):
    """Known change, in the safe direction: with the full catalog a top-up event that names a (subscription)
    monitoring price is now recognised as a paid-but-un-minted charge and quarantined."""
    monkeypatch.delenv(_MON, raising=False)
    s = _store()
    signer, mock, _ = _drain_signer(s, alarm=True)
    body, sig = _event(mock, "evt_mon_3", EVENT_TOPUP, _monitoring_price())
    with pytest.raises(UnaccountedPayment):
        signer.ingest(body, sig, now=100.0)


# --- the drain is wired to the mintable view -------------------------------------------------------------------

def test_billing_drain_builds_its_signer_from_the_mintable_catalog(monkeypatch, tmp_path):
    """Pins the one construction site: with monitoring OFF the drain's signer still knows the monitoring prices
    (mintable view), so a renewal of a plan whose sale flag was turned off alarms instead of vanishing."""
    from types import SimpleNamespace

    from sigil import cli, config
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "s1-test-secret")
    monkeypatch.delenv(_MON, raising=False)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: (lambda txid: None))
    from sigil.governor.identity import ensure_owner_keypair
    ensure_owner_keypair()
    seen = {}

    real_init = BillingSigner.__init__

    def _spy_init(self, *a, **kw):
        # Wrap __init__ rather than swapping the class: a module first imported while the class is swapped
        # (billing_spool's isinstance check) would keep the fake for the rest of the session.
        seen.update(catalog=dict(kw["catalog"]), expected=dict(kw["expected"]))
        real_init(self, *a, **kw)

    monkeypatch.setattr(BillingSigner, "__init__", _spy_init)
    spool = tmp_path / "spool"
    (spool / "incoming").mkdir(parents=True)
    cli.cmd_billing_drain(SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1))
    assert seen["catalog"] == cat.mintable_entitlements()
    assert seen["expected"] == cat.mintable_expected()
    assert _monitoring_price() in seen["catalog"]
