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


def test_unused_of_a_plan_period_is_what_remains_of_its_plan_credits(monkeypatch, capsys):
    plan, _fake = _seed_plan(monkeypatch, used=3_000)
    cli.cmd_billing_reversal(_ns(reversal_cmd="unused", topup=_INV, credits=None))
    out = capsys.readouterr().out
    assert "9000 of its 12000 credits unused" in out and "refund at Stripe: 7425 of 9900 USD" in out
    assert f"plan-withdraw acme {_INV}" in out and _left(plan) == 9_000


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
