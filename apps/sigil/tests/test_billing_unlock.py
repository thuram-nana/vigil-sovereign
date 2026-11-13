"""S4 — the report unlock is minted by the BillingSigner on an org's first verified credit purchase.

Load-bearing invariants (each a mutation target):
  * eligibility is decided once, at mint time, from the verified event: a top-up or an HONOURED credit-plan
    period, priced by the catalog above 0, whose verified currency is present and equal to the catalog's and
    whose verified amount is at least the catalog's;
  * never from monitoring, an underpaid / wrong-currency / currency-less charge, an unknown price, a stale plan
    event, or a catalog price of 0 — a currency-less charge still mints its credits, only the unlock is refused;
  * exactly once: a replayed webhook gives one unlock, one wallet credit, one invoice;
  * the plan path decides on the honoured period, so a crash between the refill and the invoice heals on the
    re-drive with the invoice AND the unlock (the old `if seq is not None` gate lost both);
  * the tenant comes only from the verified event; org A's purchase never unlocks org B;
  * with report_unlocks=None the appended records are identical to before;
  * the owner commands write owner-signed unlock / relock records.
"""
from __future__ import annotations

import tempfile

import pytest

from sigil.governor import catalog as cat
from sigil.governor.billing import (EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, BillingEvent, BillingSigner,
                                     MockBillingProvider)
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.report_unlock import REPORT_UNLOCK_SIGNAL, ReportUnlockRegistry
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
K = {"owner_key": OWNER, "trusted_pubkey": OP}


def _rig(*, unlocks=True, expected=None):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    ru = ReportUnlockRegistry(s, **K) if unlocks else None
    inv = InvoiceRegistry(s, **K)
    signer = BillingSigner(MockBillingProvider("sek"), wallet=WalletRegistry(s, **K),
                           subscriptions=SubscriptionRegistry(s, **K), plan=PlanCreditLedger(s, **K),
                           catalog=cat.mintable_entitlements(),
                           expected=cat.mintable_expected() if expected is None else expected,
                           invoices=inv, report_unlocks=ru)
    return signer, s, ru, inv


def _price(kind, *, monitoring=False):
    return next(e for e in cat._CATALOG if e.kind == kind and bool(e.monitor_hosts) == monitoring)


def _ev(entry, eid, *, org="org_a", created=100.0, amount=None, currency=None, kind=None):
    return BillingEvent(event_id=eid, kind=kind or entry.kind, org_id=org, created=created,
                        price_id=entry.price_id,
                        amount_minor=entry.amount_minor if amount is None else amount,
                        currency=entry.currency if currency is None else currency)


def _unlock_records(s):
    return [r.payload for r in s.iter_records() if r.payload.get("signal") == REPORT_UNLOCK_SIGNAL]


TOPUP = _price(EVENT_TOPUP)
PLAN = _price(EVENT_SUBSCRIPTION_ACTIVE)
MON = _price(EVENT_SUBSCRIPTION_ACTIVE, monitoring=True)


# --- positive ---------------------------------------------------------------------------------------------------

def test_a_verified_topup_unlocks():
    signer, s, ru, inv = _rig()
    assert signer.apply(_ev(TOPUP, "evt_t1"), now=100.0) is not None
    u = ru.unlock_of("org_a")
    assert ru.is_unlocked("org_a") and (u.source_kind, u.source_ref) == ("topup", "evt_t1")


def test_an_honoured_plan_period_unlocks():
    signer, s, ru, inv = _rig()
    signer.apply(_ev(PLAN, "evt_p1"), now=100.0)
    u = ru.unlock_of("org_a")
    assert ru.is_unlocked("org_a") and u.source_kind == "subscription"
    assert [i.invoice_id for i in inv.invoices("org_a")] == ["evt_p1"]


def test_replay_three_times_is_exactly_once():
    signer, s, ru, inv = _rig()
    for _ in range(3):
        signer.apply(_ev(TOPUP, "evt_t1"), now=100.0)
    assert signer.wallet.available("org_a") == TOPUP.credits
    assert len(inv.invoices("org_a")) == 1 and ru.is_unlocked("org_a")


# --- crash injection --------------------------------------------------------------------------------------------

def _crash_once(monkeypatch, obj, name):
    real = getattr(obj, name)
    st = {"armed": True}

    def wrap(*a, **kw):
        out = real(*a, **kw)
        if st["armed"]:
            st["armed"] = False
            raise RuntimeError("crash")
        return out

    monkeypatch.setattr(obj, name, wrap)


@pytest.mark.parametrize("entry", [TOPUP, PLAN], ids=["topup", "plan"])
@pytest.mark.parametrize("where", ["unlock", "grant_or_refill"])
def test_a_crash_heals_on_redrive(monkeypatch, entry, where):
    signer, s, ru, inv = _rig()
    if where == "unlock":
        _crash_once(monkeypatch, ru, "unlock")
    elif entry is TOPUP:
        _crash_once(monkeypatch, signer.wallet, "grant")
    else:
        _crash_once(monkeypatch, signer.plan, "grant")
    with pytest.raises(RuntimeError):
        signer.apply(_ev(entry, "evt_x"), now=100.0)
    signer.apply(_ev(entry, "evt_x"), now=100.0)               # the at-least-once re-drive
    assert ru.is_unlocked("org_a")
    assert [i.invoice_id for i in inv.invoices("org_a")] == ["evt_x"]


def test_plan_crash_between_refill_and_invoice_heals_on_redrive(monkeypatch):
    """The old `if seq is not None` gate lost the invoice (and would lose the unlock) for good here: the re-drive's
    refill returns None because the period's tranche already exists."""
    signer, s, ru, inv = _rig()
    _crash_once(monkeypatch, inv, "record")
    with pytest.raises(RuntimeError):
        signer.apply(_ev(PLAN, "evt_p1"), now=100.0)
    signer.apply(_ev(PLAN, "evt_p1"), now=100.0)
    assert [i.invoice_id for i in inv.invoices("org_a")] == ["evt_p1"] and ru.is_unlocked("org_a")


# --- negatives --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", [
    {"amount": 1},                       # underpaid
    {"currency": "EUR"},                 # wrong currency
    {"currency": "", "amount": 0},       # the verified object carried no currency
])
def test_an_ineligible_topup_does_not_unlock(change):
    signer, s, ru, inv = _rig()
    signer.apply(_ev(TOPUP, "evt_bad", **change), now=100.0)
    assert not ru.is_unlocked("org_a") and _unlock_records(s) == []


def test_a_currencyless_topup_still_mints_its_credits_but_never_unlocks():
    signer, s, ru, inv = _rig()
    signer.apply(_ev(TOPUP, "evt_nc", currency="", amount=0), now=100.0)
    assert signer.wallet.available("org_a") == TOPUP.credits
    assert not ru.is_unlocked("org_a")


def test_lowercase_matching_currency_unlocks():
    signer, s, ru, inv = _rig()
    signer.apply(_ev(TOPUP, "evt_lc", currency=TOPUP.currency.lower()), now=100.0)
    assert ru.is_unlocked("org_a")


def test_an_overpaid_topup_unlocks():
    signer, s, ru, inv = _rig()
    signer.apply(_ev(TOPUP, "evt_op", amount=TOPUP.amount_minor + 1), now=100.0)
    assert ru.is_unlocked("org_a")


def test_monitoring_never_unlocks():
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    signer, s, ru, inv = _rig()
    signer.monitoring_subscriptions = MonitoringSubscriptionRegistry(s, **K)
    signer.apply(_ev(MON, "evt_m1"), now=100.0)
    assert not ru.is_unlocked("org_a") and _unlock_records(s) == []


def test_unknown_price_and_zero_price_never_unlock():
    signer, s, ru, inv = _rig(expected={TOPUP.price_id: (0, TOPUP.currency)})
    signer.apply(_ev(TOPUP, "evt_zero", amount=0), now=100.0)           # catalog price 0
    unknown = BillingEvent(event_id="evt_u", kind=EVENT_TOPUP, org_id="org_a", created=101.0, price_id="nope",
                           amount_minor=99999, currency="USD")
    signer.apply(unknown, now=101.0)
    assert _unlock_records(s) == []


def test_a_stale_plan_event_writes_neither_unlock_nor_invoice():
    signer, s, ru, inv = _rig()
    signer.apply(_ev(PLAN, "evt_new", created=200.0), now=200.0)
    ru2_before = len(_unlock_records(s))
    signer.apply(_ev(PLAN, "evt_old", created=100.0), now=201.0)        # out of order: not the honoured period
    assert [i.invoice_id for i in inv.invoices("org_a")] == ["evt_new"]
    assert len(_unlock_records(s)) == ru2_before
    assert ru.unlock_of("org_a").source_ref == "evt_new"


def test_tenant_isolation():
    signer, s, ru, inv = _rig()
    signer.apply(_ev(TOPUP, "evt_a", org="org_a"), now=100.0)
    assert ru.is_unlocked("org_a") and not ru.is_unlocked("org_b")


def test_without_the_ledger_the_records_are_unchanged():
    a_signer, a_s, _, _ = _rig(unlocks=False)
    b_signer, b_s, _, _ = _rig()
    for sg in (a_signer, b_signer):
        sg.apply(_ev(TOPUP, "evt_t1"), now=100.0)
        sg.apply(_ev(PLAN, "evt_p1", created=150.0), now=150.0)
    a_sigs = [r.payload["signal"] for r in a_s.iter_records()]
    b_sigs = [r.payload["signal"] for r in b_s.iter_records() if r.payload["signal"] != REPORT_UNLOCK_SIGNAL]
    assert a_sigs == b_sigs and REPORT_UNLOCK_SIGNAL not in a_sigs


def test_an_owner_relock_beats_a_later_purchase():
    signer, s, ru, inv = _rig()
    signer.apply(_ev(TOPUP, "evt_t1", created=100.0), now=100.0)
    ru.owner_set("org_a", "relock", reason="chargeback", issued_at=150.0)
    signer.apply(_ev(TOPUP, "evt_t2", created=200.0), now=200.0)
    assert not ru.is_unlocked("org_a")


# --- drain wiring and owner commands ----------------------------------------------------------------------------

def test_the_drain_wires_the_unlock_ledger_unconditionally(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from sigil import cli, config
    from sigil.governor.identity import ensure_owner_keypair
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "s4-test-secret")
    monkeypatch.delenv("VIGIL_TRIAL_PREVIEW_ENABLED", raising=False)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: (lambda txid: None))
    ensure_owner_keypair()
    seen = {}
    real_init = BillingSigner.__init__

    def spy(self, *a, **kw):
        seen["ru"] = kw.get("report_unlocks")
        real_init(self, *a, **kw)

    monkeypatch.setattr(BillingSigner, "__init__", spy)
    (tmp_path / "spool" / "incoming").mkdir(parents=True)
    cli.cmd_billing_drain(SimpleNamespace(billing_cmd="drain", spool=str(tmp_path / "spool"), interval=0.1))
    assert isinstance(seen["ru"], ReportUnlockRegistry)


def test_owner_unlock_and_relock_commands(monkeypatch, tmp_path, capsys):
    from sigil import cli, config
    from sigil.governor.identity import ensure_owner_keypair
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    ensure_owner_keypair()

    def run(argv):
        try:
            cli.main(argv)
        except SystemExit as e:
            return e.code or 0
        return 0

    assert run(["org", "unlock-reports", "org_ent", "--reason", "enterprise"]) == 0
    assert "now unlocked" in capsys.readouterr().out
    assert run(["org", "relock-reports", "org_ent", "--reason", "chargeback"]) == 0
    assert "now locked" in capsys.readouterr().out
    assert run(["org", "unlock-reports", "org_ent", "--reason", ""]) == 2


@pytest.mark.parametrize("change, ok", [
    ({}, True),
    ({"amount": TOPUP.amount_minor - 1}, False),
    ({"currency": "EUR"}, False),
    ({"currency": ""}, False),
    ({"amount": TOPUP.amount_minor + 50}, True),
])
def test_eligibility_on_its_own(change, ok):
    """The unlock's own check, independent of the earlier underpay guard (which today refuses the same events
    before any mint): it must hold even if that guard changes."""
    signer, s, ru, inv = _rig()
    assert signer._unlock_eligible(_ev(TOPUP, "e", **change)) is ok


# --- review folds -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("unlocks", [True, False])
def test_a_second_distinct_event_for_the_same_period_writes_no_second_invoice(unlocks):
    signer, s, ru, inv = _rig(unlocks=unlocks)
    signer.apply(_ev(PLAN, "evt_p1", created=100.0), now=100.0)
    signer.apply(_ev(PLAN, "evt_p2", created=100.0), now=101.0)    # same second, distinct id: no new tranche
    assert [i.invoice_id for i in inv.invoices("org_a")] == ["evt_p1"]
    assert len(signer.plan.tranches("org_a")) == 1


@pytest.mark.parametrize("down", ["payment_failed", "cancel"])
def test_an_undelivered_period_is_never_invoiced_or_unlocked(monkeypatch, down):
    """A crash before the tranche is granted, then the subscription goes down, then the re-drive: the plan ledger
    never delivered the period, so neither the invoice nor the unlock may be written."""
    from sigil.governor.billing import EVENT_PAYMENT_FAILED
    signer, s, ru, inv = _rig()
    real = signer.plan.grant
    monkeypatch.setattr(signer.plan, "grant", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        signer.apply(_ev(PLAN, "evt_p1", created=100.0), now=100.0)
    monkeypatch.setattr(signer.plan, "grant", real)
    if down == "cancel":
        signer.subscriptions.cancel("org_a")
    else:
        signer.apply(BillingEvent(event_id="evt_f", kind=EVENT_PAYMENT_FAILED, org_id="org_a", created=150.0,
                                  price_id=PLAN.price_id), now=150.0)
    signer.apply(_ev(PLAN, "evt_p1", created=100.0), now=160.0)
    assert signer.plan.tranches("org_a") == [] and inv.invoices("org_a") == []
    assert not ru.is_unlocked("org_a")


def test_a_long_event_id_never_half_mints():
    signer, s, ru, inv = _rig()
    eid = "e" * 128
    assert signer.apply(_ev(TOPUP, eid), now=100.0) is not None
    signer.apply(_ev(TOPUP, eid), now=101.0)
    assert ru.is_unlocked("org_a") and ru.unlock_of("org_a").source_ref == eid
    assert [i.invoice_id for i in inv.invoices("org_a")] == [eid]
    assert signer.wallet.available("org_a") == TOPUP.credits


def test_a_delivered_period_is_invoiced_on_redrive_even_after_the_plan_went_down(monkeypatch):
    """Grant landed, crash before the invoice, the subscription then goes past_due: the period WAS delivered,
    so the re-drive writes its invoice and unlock."""
    from sigil.governor.billing import EVENT_PAYMENT_FAILED
    signer, s, ru, inv = _rig()
    _crash_once(monkeypatch, inv, "record")
    with pytest.raises(RuntimeError):
        signer.apply(_ev(PLAN, "evt_p1", created=100.0), now=100.0)
    signer.apply(BillingEvent(event_id="evt_f", kind=EVENT_PAYMENT_FAILED, org_id="org_a", created=150.0,
                              price_id=PLAN.price_id), now=150.0)
    signer.apply(_ev(PLAN, "evt_p1", created=100.0), now=160.0)
    assert [i.invoice_id for i in inv.invoices("org_a")] == ["evt_p1"] and ru.is_unlocked("org_a")


def test_the_unlock_entry_id_is_bounded():
    from sigil.governor.report_unlock import REPORT_UNLOCK_SIGNAL
    signer, s, ru, inv = _rig()
    signer.apply(_ev(TOPUP, "e" * 128), now=100.0)
    [rec] = [r.payload for r in s.iter_records() if r.payload.get("signal") == REPORT_UNLOCK_SIGNAL]
    assert len(rec["entry_id"]) <= 128 and rec["source_ref"] == "e" * 128
