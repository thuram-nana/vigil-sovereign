"""W5 — ``sigil billing-reversal`` (the owner refund of unused credits + the hold status), default-OFF.

The verb refuses while ``VIGIL_BILLING_REVERSALS`` is off. With it on: ``refund`` removes UNUSED credits of a credited
top-up through the same reversal path (reason ``refund``), refused when it would exceed the spendable balance;
``status`` lists the orgs on a hold.
"""
from __future__ import annotations

import re
import tempfile
from types import SimpleNamespace

import pytest

from sigil import cli
from sigil.governor.billing_reversal import BillingReversalLedger
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("SIGIL_HOME", d)
    monkeypatch.delenv("VIGIL_BILLING_REVERSALS", raising=False)
    # SpineStore()'s default path is bound at import (HANDOFF §0.7) — give this test its own private spine so the
    # CLI (which constructs SpineStore()) and the test's helpers read the same, isolated store.
    path = tempfile.mktemp(suffix=".jsonl")
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: SpineStore(path) if not a else SpineStore(*a, **k))


def _seed(credits=1000, spent=0):
    owner = ensure_owner_keypair()
    s = cli.SpineStore()
    w = WalletRegistry(s, owner_key=owner)
    inv = InvoiceRegistry(s, owner_key=owner)
    w.grant("acme", credits, "topup", entry_id="cs_1", issued_at=1.0)
    inv.record("acme", invoice_id="cs_1", kind="topup", price_id="p", amount_minor=credits, currency="USD",
               credits=credits, issued_at=1.0)
    if spent:
        w.debit("acme", spent, entry_id="d1", issued_at=1.5)
    return owner, s, w


def _ns(**kw):
    base = dict(reversal_cmd="refund", org="acme", topup="cs_1", credits=None, reason="customer request", sync=False)
    base.update(kw)
    return SimpleNamespace(**base)


def test_the_verb_is_refused_while_the_flag_is_off(capsys):
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(credits=100))
    assert e.value.code == 2 and "disabled" in capsys.readouterr().err


def test_an_owner_refund_removes_unused_credits(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000)
    cli.cmd_billing_reversal(_ns(credits=400))
    assert w.available("acme") == 600 and "400 credits removed" in capsys.readouterr().out
    assert not BillingReversalLedger(s, wallet=w).on_hold("acme")


def test_an_owner_refund_over_the_spendable_balance_is_refused(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000, spent=700)         # spendable 300
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(credits=400))
    assert e.value.code == 2 and "unused credits only" in capsys.readouterr().err
    assert w.available("acme") == 300                    # nothing moved


def test_a_refund_of_an_unknown_top_up_is_refused(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    _seed(credits=1000)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(topup="cs_nope", credits=100))
    assert e.value.code == 2 and "not a credited top-up" in capsys.readouterr().err


def test_status_lists_the_orgs_on_a_hold(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000, spent=900)
    BillingReversalLedger(s, wallet=w).reconcile("acme", "cs_1", cap=1000, reason="dispute", now=2.0, disputed=1000)
    cli.cmd_billing_reversal(SimpleNamespace(reversal_cmd="status", org=None, topup=None, credits=None,
                                             reason="", sync=True))
    out = capsys.readouterr().out
    assert "acme" in out and "ON HOLD" in out and "900 credits" in out


# ---- plan-withdraw: a consumer's withdrawal from a plan (Terms §8) ---------------------------------------------------
_PE, _INV, _ALLOT, _PRICE = 5_000_000.0, "in_plan1", 12_000, 9_900


class _FakeStripe:
    """The Stripe the verb reads (invoice -> subscription) and, when the plan still renews, updates."""

    def __init__(self, *, status="active", ending=False, org="acme", livemode=False, echo=True, fail=False,
                 answer_only=False, readback_fail=False):
        self.sub = {"object": "subscription", "id": "sub_p1", "livemode": livemode, "status": status,
                    "cancel_at_period_end": ending, "metadata": {"org_id": org, "price_id": "vigil_pro_monthly"}}
        self.inv = {"object": "invoice", "id": _INV, "livemode": livemode,
                    "parent": {"subscription_details": {"subscription": "sub_p1"}}}
        self.echo, self.fail, self.updates = echo, fail, []
        # answer_only: the update's answer says the plan ends, but the subscription Stripe holds is unchanged
        # readback_fail: the subscription cannot be read again once an update was sent
        self.answer_only, self.readback_fail = answer_only, readback_fail

    def fetch(self, kind, oid):
        if kind == "invoice":
            return dict(self.inv)
        if self.readback_fail and self.updates:
            raise RuntimeError("network")
        return dict(self.sub)

    def update(self, sid, params, *, idempotency_key):
        self.updates.append((sid, dict(params), idempotency_key))
        if self.fail:
            raise RuntimeError("network")
        if self.answer_only:
            return dict(self.sub, cancel_at_period_end=bool(params.get("cancel_at_period_end")))
        if self.echo:
            self.sub["cancel_at_period_end"] = bool(params.get("cancel_at_period_end"))
        return dict(self.sub)


class _ReplayingStripe(_FakeStripe):
    """Stripe's idempotent requests as documented: a repeated Idempotency-Key gets the response saved for it, and
    the update is NOT made again."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.saved: dict = {}

    def update(self, sid, params, *, idempotency_key):
        if idempotency_key in self.saved:
            self.updates.append((sid, dict(params), idempotency_key))
            return dict(self.saved[idempotency_key])
        resp = super().update(sid, params, idempotency_key=idempotency_key)
        self.saved[idempotency_key] = dict(resp)
        return resp


def _seed_plan(monkeypatch, *, used=0, stripe=None, key=True):
    from sigil.governor import stripe_egress as se
    from sigil.governor.metering import PlanCreditLedger
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner = ensure_owner_keypair()
    s = cli.SpineStore()
    plan = PlanCreditLedger(s, owner_key=owner)
    plan.grant("acme", _ALLOT, period_end=_PE, entry_id=f"refill:acme:{_PE!r}", issued_at=1.0)
    InvoiceRegistry(s, owner_key=owner).record("acme", invoice_id=_INV, kind="subscription",
                                               price_id="vigil_pro_monthly", amount_minor=_PRICE, currency="USD",
                                               credits=_ALLOT, period_start=1.0, period_end=_PE, issued_at=1.0)
    if used:
        plan.debit("acme", used, period_end=_PE, entry_id="reserve-plan:s:n", issued_at=2.0)
    fake = stripe or _FakeStripe()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", (lambda: fake.fetch) if key else (lambda: None))
    monkeypatch.setattr(cli, "_stripe_subscription_updater", (lambda: fake.update) if key else (lambda: None))
    monkeypatch.setattr(se, "stripe_key_mode", lambda: "test" if key else None)
    return plan, fake


def _pw(**kw):
    return _ns(**{"reversal_cmd": "plan-withdraw", "topup": _INV, **kw})


def _left(plan):
    return plan.remaining_for_period("acme", _PE)


def test_plan_withdraw_stops_the_renewal_then_removes_the_unused_plan_credits(monkeypatch, capsys):
    plan, fake = _seed_plan(monkeypatch, used=3_000)                 # 9,000 left of 12,000
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE * 9_000 // _ALLOT)))   # refunded the unused 3/4 at Stripe
    out = capsys.readouterr().out
    assert [(sid, params) for sid, params, _key in fake.updates] == [("sub_p1", {"cancel_at_period_end": True})]
    assert re.fullmatch(rf"vigil-pw-{_INV}-[0-9a-f]{{16}}", fake.updates[0][2])     # this run's own key
    assert _left(plan) == 0 and "9000 plan credits removed" in out and "will not renew" in out


def test_a_rerun_after_the_customer_resumed_the_plan_stops_the_renewal_again(monkeypatch, capsys):
    # the customer resumed the plan after a first withdrawal run (the console's "keep my plan" sends
    # cancel_at_period_end=False under its own key); the runbook's re-run must really stop the renewal again and
    # never take an earlier run's saved Stripe answer for this run's update
    from sigil.governor.metering import PlanCreditLedger
    fake = _ReplayingStripe()
    plan, _ = _seed_plan(monkeypatch, used=3_000, stripe=fake)      # 9,000 left: a full refund removes them
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    capsys.readouterr()
    fake.sub["cancel_at_period_end"] = False                         # resumed by the customer
    PlanCreditLedger(cli.SpineStore(), owner_key=ensure_owner_keypair()).grant(
        "acme", 300, period_end=_PE, entry_id="settle-plan:s1:n1", issued_at=4.0)     # a refunded launch
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    out = capsys.readouterr().out
    assert "will not renew" in out and fake.sub["cancel_at_period_end"] is True     # Stripe's state agrees
    assert len(fake.updates) == 2 and fake.updates[0][2] != fake.updates[1][2]     # each run its own key
    assert _left(plan) == 0 and "300 plan credits removed" in out


def test_plan_withdraw_warns_when_the_refunded_plan_credits_were_spent_before_it_ran(monkeypatch, capsys):
    # the runbook's order: `unused` (12,000 unused) -> the whole price refunded at Stripe -> the customer launches a
    # scan that reserves 11,000 plan credits -> plan-withdraw finds only 1,000 to remove: it says so, loudly
    plan, fake = _seed_plan(monkeypatch)
    plan.debit("acme", 11_000, period_end=_PE, entry_id="reserve-plan:s9:n9", issued_at=3.0)
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    out, err = capsys.readouterr()
    assert "1000 plan credits removed" in out and _left(plan) == 0
    assert "WARNING: the refund covers 12000 plan credits of invoice in_plan1, but only 1000" in err
    assert "the other 11000 were spent, or are held by a scan still running" in err


@pytest.mark.parametrize("used,refunded", [(3_000, _PRICE * 9_000 // _ALLOT), (0, _PRICE), (0, _PRICE // 2)])
def test_plan_withdraw_does_not_warn_when_every_refunded_credit_left(monkeypatch, capsys, used, refunded):
    plan, fake = _seed_plan(monkeypatch, used=used)
    cli.cmd_billing_reversal(_pw(credits=str(refunded)))
    cli.cmd_billing_reversal(_pw(credits=str(refunded)))             # the re-run: nothing more, still no warning
    assert "WARNING" not in capsys.readouterr().err


@pytest.mark.parametrize("ended", [False, True])
def test_plan_withdraw_of_an_ended_period_says_its_credits_had_expired_and_names_the_renewals(monkeypatch, capsys,
                                                                                            ended):
    # the plan renewed after the period the invoice paid (in_plan2, to _PE + 30 days): a withdrawal named by the
    # first invoice removes the first period's credits only — expired ones once it ended — and must say so
    import time
    plan, fake = _seed_plan(monkeypatch)
    owner = ensure_owner_keypair()
    pe2 = _PE + 30 * 86400
    plan.grant("acme", _ALLOT, period_end=pe2, entry_id=f"refill:acme:{pe2!r}", issued_at=_PE)
    InvoiceRegistry(cli.SpineStore(), owner_key=owner).record(
        "acme", invoice_id="in_plan2", kind="subscription", price_id="vigil_pro_monthly", amount_minor=_PRICE,
        currency="USD", credits=_ALLOT, period_start=_PE, period_end=pe2, issued_at=_PE)
    monkeypatch.setattr(time, "time", lambda: _PE + 5.0 if ended else _PE - 5.0)
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    out = capsys.readouterr().out
    assert "12000 plan credits removed" in out and _left(plan) == 0
    assert plan.remaining_for_period("acme", pe2) == _ALLOT                # the renewal's credits: untouched
    assert ("this plan period ended on 1970-02-27 20:53 UTC: its plan credits had already expired, so no spendable "
            "credit was removed" in out) is ended
    assert ("the plan has renewed since: the plan period(s) of in_plan2 (to 1970-03-29, 12000 credits) are "
            "untouched" in out) is ended


def test_plan_withdraw_run_again_removes_nothing_more_and_sends_nothing(monkeypatch, capsys):
    plan, fake = _seed_plan(monkeypatch)
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    assert _left(plan) == 0 and len(fake.updates) == 1              # the second run finds the plan already ending
    assert "nothing removed" in capsys.readouterr().out


@pytest.mark.parametrize("status,ending", [("canceled", False), ("active", True), ("incomplete_expired", False)])
def test_plan_withdraw_of_a_plan_already_stopped_at_stripe_sends_no_update(monkeypatch, status, ending):
    plan, fake = _seed_plan(monkeypatch, stripe=_FakeStripe(status=status, ending=ending))
    cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    assert fake.updates == [] and _left(plan) == 0


@pytest.mark.parametrize("why,kw", [
    ("cannot read Stripe from this shell (set VIGIL_STRIPE_SECRET_KEY", dict(key=False)),
    ("could not stop the renewal of sub_p1", dict(stripe=_FakeStripe(fail=True))),
    ("did not confirm that sub_p1 stops renewing", dict(stripe=_FakeStripe(echo=False))),
    ("read back, does not show that it stops renewing", dict(stripe=_FakeStripe(answer_only=True))),
    ("could not be read back (RuntimeError) to confirm that sub_p1", dict(stripe=_FakeStripe(readback_fail=True))),
])
def test_plan_withdraw_refuses_with_the_stripe_step_when_vigil_cannot_stop_the_renewal(monkeypatch, capsys, why, kw):
    plan, _fake = _seed_plan(monkeypatch, **kw)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    err = capsys.readouterr().err
    assert e.value.code == 2 and why in err and "nothing was removed" in err
    assert "in the Stripe Dashboard open" in err and "choose Cancel subscription" in err    # the exact manual step
    assert _left(plan) == _ALLOT                                     # nothing moved


@pytest.mark.parametrize("stripe", [_FakeStripe(org="other"), _FakeStripe(livemode=True)])
def test_plan_withdraw_refuses_a_subscription_of_another_org_or_mode(monkeypatch, capsys, stripe):
    plan, fake = _seed_plan(monkeypatch, stripe=stripe)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    assert e.value.code == 2 and "does not belong" in capsys.readouterr().err
    assert fake.updates == [] and _left(plan) == _ALLOT


@pytest.mark.parametrize("kw,msg", [
    (dict(topup="in_nope", credits=str(_PRICE)), "not a credited plan invoice"),
    (dict(topup="cs_1", credits=str(_PRICE)), "plan invoice id"),
    (dict(credits=str(_PRICE + 1)), "more than"),
    (dict(credits="0"), "cents refunded"),
    (dict(credits=str(_PRICE), reason=" "), "--reason"),
])
def test_plan_withdraw_refuses_what_is_not_a_refund_of_a_credited_plan_invoice(monkeypatch, capsys, kw, msg):
    plan, fake = _seed_plan(monkeypatch)
    args = dict(reversal_cmd="plan-withdraw", topup=_INV)
    args.update(kw)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(**args))
    assert e.value.code == 2 and msg in capsys.readouterr().err
    assert fake.updates == [] and _left(plan) == _ALLOT


@pytest.mark.parametrize("reason", ["withdrawal\x07", "w\x00", "w\u202e"])
def test_plan_withdraw_checks_the_reason_before_it_stops_the_renewal(monkeypatch, capsys, reason):
    # a reason the owner-signed step would refuse is refused BEFORE anything is sent to Stripe
    plan, fake = _seed_plan(monkeypatch)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_pw(credits=str(_PRICE), reason=reason))
    err = capsys.readouterr().err
    assert e.value.code == 2 and "--reason" in err and "printable" in err
    assert fake.updates == [] and fake.sub["cancel_at_period_end"] is False and _left(plan) == _ALLOT


@pytest.mark.parametrize("exc,code", [("refused", 2), ("retry", 3)])
def test_a_refusal_after_the_renewal_stop_says_the_renewal_is_stopped(monkeypatch, capsys, exc, code):
    from sigil.governor.billing_reversal import ReversalRefused, ReversalRetry
    plan, fake = _seed_plan(monkeypatch)

    def boom(*a, **k):
        raise ReversalRefused("hand") if exc == "refused" else ReversalRetry("lock busy")
    monkeypatch.setattr(BillingReversalLedger, "reconcile_plan", boom)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    err = capsys.readouterr().err
    assert e.value.code == code and fake.sub["cancel_at_period_end"] is True
    assert "the renewal IS stopped (subscription sub_p1 now ends at the end of its period" in err
    assert "no plan credit was removed" in err and _left(plan) == _ALLOT


def test_plan_withdraw_refuses_a_monitoring_plan_with_no_credits(monkeypatch, capsys):
    plan, fake = _seed_plan(monkeypatch)
    owner = ensure_owner_keypair()
    InvoiceRegistry(cli.SpineStore(), owner_key=owner).record(
        "acme", invoice_id="in_mon1", kind="subscription", price_id="vigil_aegis_observe_1h_monthly",
        amount_minor=_PRICE, currency="USD", credits=0, period_start=1.0, period_end=_PE, issued_at=1.0)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_pw(topup="in_mon1", credits=str(_PRICE)))
    assert e.value.code == 2 and "monitoring plan" in capsys.readouterr().err and fake.updates == []


def test_plan_withdraw_is_refused_while_the_flag_is_off(monkeypatch, capsys):
    plan, fake = _seed_plan(monkeypatch)
    monkeypatch.delenv("VIGIL_BILLING_REVERSALS")
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_pw(credits=str(_PRICE)))
    assert e.value.code == 2 and "disabled" in capsys.readouterr().err
    assert fake.updates == [] and _left(plan) == _ALLOT


# ---- unused: a purchase's unused credits by the withdrawal rule (read-only) -------------------------------------------
@pytest.mark.parametrize("spent,unused", [
    (0, 1000),        # nothing spent: the whole pack is unused (the 450 trial credits are not counted as bought)
    (400, 1000),      # 400 spent: taken from the trial first, the pack is still whole
    (600, 850),       # 600 spent: the trial is gone and 150 of the pack — 850 unused
    (1450, 0),        # everything spent: the right of withdrawal for the pack has ended
])
def test_unused_takes_trial_credits_as_spent_first_and_never_as_purchased(monkeypatch, capsys, spent, unused):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000, spent=spent)
    w.grant("acme", 450, "trial", entry_id="trial:acme", issued_at=0.5)
    cli.cmd_billing_reversal(_ns(reversal_cmd="unused", credits=None))
    out = capsys.readouterr().out
    assert f"{unused} of its 1000 credits unused" in out
    assert f"purchased balance remaining: {min(1000, 1450 - spent)} " in out      # the trial never counts as bought
    if unused:
        assert f"refund at Stripe: {unused} of 1000 USD" in out and f"refund acme cs_1 {unused}" in out
    else:
        assert "right of withdrawal has ended" in out
    assert w.available("acme") == 1450 - spent                      # read-only: nothing moved


@pytest.mark.parametrize("spent,unused", [
    (1500, 300),      # 500 of the 2,000 bought were left; the refund took 200 of them -> 300 in the pool
    (0, 800),         # nothing spent: cs_2 keeps only the 800 its refund did not remove
])
def test_unused_counts_each_purchase_against_the_purchased_pool_less_what_refunds_removed(monkeypatch, capsys,
                                                                                         spent, unused):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000, spent=0)
    inv = InvoiceRegistry(s, owner_key=owner)
    w.grant("acme", 1000, "topup", entry_id="cs_2", issued_at=1.1)
    inv.record("acme", invoice_id="cs_2", kind="topup", price_id="p", amount_minor=1000, currency="USD",
               credits=1000, issued_at=1.1)
    if spent:
        w.debit("acme", spent, entry_id="d2", issued_at=1.6)
    BillingReversalLedger(s, wallet=w).reconcile("acme", "cs_2", cap=1000, reason="refund", now=2.0,
                                                 owner_refund=200, unused_only=True)
    cli.cmd_billing_reversal(_ns(reversal_cmd="unused", topup="cs_2", credits=None))
    assert f"{unused} of its 1000 credits unused" in capsys.readouterr().out


@pytest.mark.parametrize("ended", [False, True])
def test_unused_of_a_plan_period_is_what_remains_of_its_plan_credits(monkeypatch, capsys, ended):
    import time
    plan, _fake = _seed_plan(monkeypatch, used=3_000)
    monkeypatch.setattr(time, "time", lambda: _PE + 1.0 if ended else _PE - 1.0)
    cli.cmd_billing_reversal(_ns(reversal_cmd="unused", topup=_INV, credits=None))
    out = capsys.readouterr().out
    assert "9000 of its 12000 credits unused" in out and "refund at Stripe: 7425 of 9900 USD" in out
    assert f"plan-withdraw acme {_INV}" in out and _left(plan) == 9_000
    # an ended period's leftover plan credits expired UNUSED: the note says they are still counted as unused
    assert ("has ended: the plan credits it had left expired unused and are counted as unused here" in out) is ended
    assert ("14 days run from its first purchase" in out) is ended


def test_the_unused_refund_is_the_price_in_proportion_rounded_up_to_the_cent(monkeypatch, capsys):
    plan, _fake = _seed_plan(monkeypatch, used=3_001)               # 8,999 left: 9,900 x 8,999 / 12,000 = 7,424.175
    cli.cmd_billing_reversal(_ns(reversal_cmd="unused", topup=_INV, credits=None))
    assert "refund at Stripe: 7425 of 9900 USD" in capsys.readouterr().out


@pytest.mark.parametrize("price,unused,credits,refund", [
    (5_000, 5, 6_000, 5), (5_000, 4_997, 6_000, 4_165), (1_000, 850, 1_000, 850), (9_900, 1, 20_000, 1),
    (5_000, 6_000, 6_000, 5_000), (0, 5, 6_000, 0), (5_000, 0, 6_000, 0), (5_000, -5, 6_000, 0), (5_000, 5, 0, 0),
    # a pack not wholly unused whose rounded-up price would be its whole price: one cent less (the whole price
    # removes every credit of the pack, and the spent ones would be owed)
    (5_000, 5_999, 6_000, 4_999), (3, 5, 7, 2), (3, 6, 7, 2), (3, 7, 7, 3), (1_000, 999, 1_000, 999),
])
def test_withdrawal_refund_minor_rounds_up_and_never_refunds_a_purchase_with_no_price(price, unused, credits, refund):
    assert cli.withdrawal_refund_minor(price, unused, credits) == refund


@pytest.mark.parametrize("unused,refund", [(11_999, 9_900), (12_000, 9_900), (9_000, 7_425), (1, 1)])
def test_a_plan_withdrawal_refund_is_rounded_up_plainly(unused, refund):
    # a plan refund removes only the plan credits that remain and is never owed, so its rounding is never capped
    assert cli.withdrawal_refund_minor(_PRICE, unused, _ALLOT, plan=True) == refund


def test_unused_of_a_bonus_pack_one_credit_short_says_why_the_refund_is_one_cent_less(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner = ensure_owner_keypair()
    s = cli.SpineStore()
    w = WalletRegistry(s, owner_key=owner)
    w.grant("acme", 6_000, "topup", entry_id="cs_6k", issued_at=1.0)
    InvoiceRegistry(s, owner_key=owner).record("acme", invoice_id="cs_6k", kind="topup", price_id="vigil_topup_6k",
                                               amount_minor=5_000, currency="USD", credits=6_000, issued_at=1.0)
    w.debit("acme", 1, entry_id="spend", issued_at=1.5)
    cli.cmd_billing_reversal(_ns(reversal_cmd="unused", topup="cs_6k", credits=None))
    out = capsys.readouterr().out
    assert "5999 of its 6000 credits unused" in out and "refund at Stripe: 4999 of 5000 USD" in out
    assert "would be the whole price" in out and "refund acme cs_6k 5999" in out


def test_unused_refuses_what_is_not_a_purchase_with_credits(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    _seed(credits=1000)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(reversal_cmd="unused", topup="cs_nope", credits=None))
    assert e.value.code == 2 and "not a purchase" in capsys.readouterr().err


def test_the_reversal_flag_ships_commented_in_the_drain_and_cockpit_env_examples():
    # default OFF: both units document it, neither turns it on
    from pathlib import Path
    repo = Path(__file__).resolve().parents[3]
    for rel in ("apps/sigil/deploy/cockpit.env.example", "infra/systemd/vigil-billing-drain-stripe.env.example"):
        lines = [ln.strip() for ln in (repo / rel).read_text(encoding="utf-8").splitlines()]
        assert "# VIGIL_BILLING_REVERSALS=1" in lines, rel
        assert not any(ln.startswith("VIGIL_BILLING_REVERSALS") for ln in lines), rel


def test_go_live_and_the_withdrawal_runbook_subscribe_the_webhook_to_every_reversal_event_the_drain_acts_on():
    # GO-LIVE §9b step 1 is where the owner subscribes the endpoint: it names every event the drain maps to a
    # reversal (the withdrawal runbook points there and lists the same), so a withdrawal's refund reaches the drain
    from pathlib import Path

    from sigil.governor.billing import _STRIPE_REVERSAL_TYPES
    runbooks = Path(__file__).resolve().parents[3] / "docs" / "runbooks"
    doc = (runbooks / "GO-LIVE-quickstart.md").read_text("utf-8")
    s9b = doc[doc.index("## 9b."): doc.index("## 10.")]
    step1 = " ".join(s9b[s9b.index("1. **Stripe dashboard.**"): s9b.index("2. **Proxy route.**")].split())
    withdrawal = " ".join((runbooks / "consumer-withdrawal.md").read_text("utf-8").split())
    assert "`VIGIL_BILLING_REVERSALS=1`" in step1 and "(consumer-withdrawal.md)" in step1
    assert "(GO-LIVE-quickstart.md)" in withdrawal
    for etype in sorted(_STRIPE_REVERSAL_TYPES):
        assert f"`{etype}`" in step1, etype
        assert f"`{etype}`" in withdrawal, etype


def test_the_drain_signer_and_its_reversal_ledger_share_one_plan_ledger(monkeypatch):
    # a refunded plan period is checked (tranche delivered) and debited through the SAME plan ledger
    from sigil.governor.billing import StripeBillingProvider
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    ensure_owner_keypair()
    provider = StripeBillingProvider("whsec_x", fetcher=lambda k, o: {}, expected_mode="test",
                                     enable_reference_adapter=True, reversals=True)
    signer = cli._billing_signer(provider, cli.SpineStore(), alarm=True)
    assert signer.reversals is not None and signer.reversals.plan is signer.plan
    assert signer.reversals.wallet is signer.wallet
    monkeypatch.delenv("VIGIL_BILLING_REVERSALS")
    assert cli._billing_signer(provider, cli.SpineStore(), alarm=True).reversals is None


def test_the_withdrawal_verbs_take_an_automatic_top_ups_payment_intent_id(monkeypatch, capsys):
    # a pack bought by automatic top-up is named in the billing history by its PaymentIntent id (pi_...)
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner = ensure_owner_keypair()
    s = cli.SpineStore()
    w = WalletRegistry(s, owner_key=owner)
    w.grant("acme", 1000, "topup", entry_id="pi_auto1", issued_at=1.0)
    InvoiceRegistry(s, owner_key=owner).record("acme", invoice_id="pi_auto1", kind="topup", price_id="vigil_topup_1k",
                                               amount_minor=1000, currency="USD", credits=1000, issued_at=1.0)
    w.debit("acme", 250, entry_id="spend", issued_at=1.5)
    cli.cmd_billing_reversal(_ns(reversal_cmd="unused", topup="pi_auto1", credits=None))
    out = capsys.readouterr().out
    assert "750 of its 1000 credits unused" in out and "refund acme pi_auto1 750" in out
    cli.cmd_billing_reversal(_ns(topup="pi_auto1", credits="750", reason="withdrawal"))
    assert w.available("acme") == 0
