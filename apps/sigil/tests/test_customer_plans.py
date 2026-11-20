"""PR-G (Area 6) — the Plans screen read (``ui/plans``) and the self-serve plan change (``governor/plan_change``).

Load-bearing invariants (each mutation-verified — the named test reds when its guard is broken):
  * MONEY PATH UNCHANGED, PRORATION ZERO BY DESIGN: a scheduled downgrade/upgrade is written to the processor only
    (``proration_behavior=none``, same interval, the OWNER CATALOG price); the current period keeps its full allotment
    and the REAL drain + signer mint the new plan at its full catalog price on the renewal invoice
    (test_a_downgrade_takes_effect_at_renewal_through_the_existing_drain, test_an_upgrade_...).
  * SAFETY RAILS: credit plans on sale only, the same billing period, an active plan outside the renewal cutoff, the
    subscription found from the org's OWN signed history and verified (tenant / mode / status / item / price) — every
    refusal sends nothing (test_decide_refusals, test_current_plan_refusals, test_parse_subscription_refusals,
    test_a_change_inside_the_renewal_cutoff_sends_nothing).
  * UNCONFIRMED IS NOT SUCCESS: a lost or mismatched answer to the update is reported as unconfirmed, audited, and
    writes no display record (test_an_unconfirmed_update_is_never_reported_as_done).
  * GATING: every flag, the owner's latch, manage_billing, step-up, rate limit, a provisioned Stripe lane
    (test_the_change_is_gated_like_checkout, test_flags_off_the_plans_surface_is_absent).
  * DISPLAY RECORD: owner-signed, this period only; a tampered/foreign/other-period record is never shown
    (test_the_display_record_is_signed_and_period_bound).
  * HOP BUDGET: the edge outwaits the plan change's worst case (test_the_plan_change_hop_outwaits_its_egress).
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import itertools
import json
import tempfile
from pathlib import Path

import pytest

from sigil.governor import catalog as cat
from sigil.governor import plan_change as pc
from sigil.governor import stripe_egress as se
from sigil.governor.billing import BillingSigner, StripeBillingProvider
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.pending_checkout import PendingPlanCheckouts
from sigil.ui.provision import ProvisionDenied, Provisioner
from test_compliance_rollup import _area6_env  # noqa: F401  (autouse: every Area-6 flag starts unset)
from test_compliance_rollup import _member, _prov, _store

ORG = "acme"
TEAM, PRO, RESEARCH = "vigil_team_monthly", "vigil_pro_monthly", "vigil_research_monthly"
DAY = 86400.0
T0 = 1_000_000.0
_WHSEC = "whsec_" + "prg-plan-change"
_EXP = cat.mintable_expected()
_ENT = cat.mintable_entitlements()
PERIOD = _ENT[PRO].period_s


@pytest.fixture(autouse=True)
def _plan_env(monkeypatch):
    for k in ("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "VIGIL_BILLING_PROVIDER",
              "VIGIL_BILLING_ENABLE_STRIPE", "VIGIL_STRIPE_WEBHOOK_SECRET", "VIGIL_STRIPE_SECRET_KEY",
              "VIGIL_STRIPE_API_VERSION", "VIGIL_CUSTOMER_MONITORING_ENABLED", "VIGIL_CUSTOMER_STEPUP_REQUIRED"):
        monkeypatch.delenv(k, raising=False)


def _all_on(monkeypatch):
    for k in ("VIGIL_CUSTOMER_PLANS", "VIGIL_CUSTOMER_PLAN_CHANGE", "VIGIL_CUSTOMER_CHECKOUT_ENABLED",
              "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED"):
        monkeypatch.setenv(k, "1")


# ---- a fake Stripe account (objects by id; the update applies to the subscription like Stripe does) ----------------
class _Stripe:
    def __init__(self, *, livemode=False):
        self.livemode = livemode
        self.objects: dict = {}
        self.updates: list = []
        self.products: list = []
        self.fail_update = None          # an exception to raise from the update (after "sending")
        self.echo_tamper = None          # a function(sub) altering the echoed subscription

    def subscription(self, sid="sub_1", *, org=ORG, price=TEAM, item="si_1", product="prod_0", status="active"):
        amount, ccy = _EXP[price]
        self.objects[sid] = {"object": "subscription", "id": sid, "livemode": self.livemode, "status": status,
                             "cancel_at_period_end": False,
                             "metadata": {"org_id": org, "price_id": price, "tx_ref": f"vigil:{org}:n2"},
                             "items": {"object": "list", "data": [{"id": item, "price": {
                                 "id": "price_inline_1", "product": product, "unit_amount": amount,
                                 "currency": ccy.lower(),
                                 "recurring": {"interval": "day", "interval_count": int(PERIOD // DAY)}}}]}}
        return self.objects[sid]

    def invoice(self, iid, *, sub="sub_1", reason="subscription_create", paid_at=T0, price=None):
        amount, ccy = _EXP[price or self.objects[sub]["metadata"]["price_id"]]
        self.objects[iid] = {"object": "invoice", "id": iid, "livemode": self.livemode, "status": "paid",
                             "billing_reason": reason, "subscription": sub, "amount_paid": amount,
                             "currency": ccy.lower(), "created": int(paid_at) - 5,
                             "status_transitions": {"paid_at": int(paid_at)}}
        return self.objects[iid]

    def fetch(self, kind, oid):
        obj = self.objects[oid]
        if isinstance(obj, Exception):
            raise obj
        assert obj["object"] == kind
        return copy.deepcopy(obj)

    def create_product(self, params, *, idempotency_key):
        self.products.append((copy.deepcopy(params), idempotency_key))
        return {"object": "product", "id": f"prod_{len(self.products)}", "livemode": self.livemode,
                "name": params["name"]}

    def update(self, sub_id, params, *, idempotency_key):
        self.updates.append((sub_id, copy.deepcopy(params), idempotency_key))
        if self.fail_update is not None:
            raise self.fail_update
        sub = self.objects[sub_id]
        if "items" in params:
            pd = params["items"][0]["price_data"]
            sub["items"]["data"][0]["price"] = {"id": f"price_inline_{len(self.updates) + 1}",
                                                "product": pd["product"], "unit_amount": pd["unit_amount"],
                                                "currency": pd["currency"], "recurring": dict(pd["recurring"])}
        if "metadata" in params:
            sub["metadata"].update(params["metadata"])
        if "cancel_at_period_end" in params:
            sub["cancel_at_period_end"] = params["cancel_at_period_end"]
        out = copy.deepcopy(sub)
        return self.echo_tamper(out) if self.echo_tamper else out

    def changer(self):
        return pc.StripePlanChanger(fetch=self.fetch, update_subscription=self.update,
                                    create_product=self.create_product, livemode=self.livemode)


# ---- a workspace on a credit plan, minted by the REAL drain + signer ---------------------------------------------------
class _Rig:
    def __init__(self, monkeypatch=None, *, price=TEAM, role="org_admin"):
        self.owner = ensure_owner_keypair()
        self.store = _store()
        self.clock = itertools.count(1)
        self.p = _prov(self.store, self.owner, now=T0)
        self.p.checkout_limiter = LoginRateLimiter(tempfile.mkdtemp(), max_fails=Provisioner._CHECKOUT_MAX,
                                                   window_s=Provisioner._CHECKOUT_WINDOW_S,
                                                   base_lock_s=Provisioner._CHECKOUT_WINDOW_S)
        self.p.pending_checkouts = PendingPlanCheckouts(tempfile.mkdtemp(), owner_key=self.owner,
                                                        trusted_pubkey=self.owner.public_key_b64,
                                                        billing_spools=[tempfile.mkdtemp()])
        self.p._plan_change_ledger_obj = pc.PlanChangeLedger(tempfile.mkdtemp(), owner_key=self.owner,
                                                             trusted_pubkey=self.owner.public_key_b64)
        self.stripe = _Stripe()
        self.p._plan_changer = self.stripe.changer
        _member(self.p.orgs, ORG, "alice", role, iter(range(1, 100)))
        provider = StripeBillingProvider(_WHSEC, fetcher=self.stripe.fetch, expected_mode="test",
                                         enable_reference_adapter=True, alarm_unaccounted_plans=True)
        self.subs, self.plan = SubscriptionRegistry(self.store), PlanCreditLedger(self.store)
        self.invoices = InvoiceRegistry(self.store)
        self.signer = BillingSigner(provider, wallet=WalletRegistry(self.store), subscriptions=self.subs,
                                    plan=self.plan, catalog=_ENT, expected=_EXP, invoices=self.invoices,
                                    alarm_unaccounted_plans=True, require_verified_amount=True)
        if price:
            self.stripe.subscription(price=price)
            self.stripe.invoice("in_1", paid_at=T0)
            assert self.send("invoice.paid", "in_1", t=T0) is not None

    def send(self, etype, oid, *, t):
        ev = {"id": f"evt_{oid}", "object": "event", "type": etype, "created": int(t), "livemode": False,
              "data": {"object": {"id": oid}}}
        raw = json.dumps(ev).encode()
        mac = hmac.new(_WHSEC.encode(), f"{int(t)}.".encode() + raw, hashlib.sha256).hexdigest()
        return self.signer.ingest(raw, f"t={int(t)},v1={mac}", now=float(t))

    def change(self, *, price_id="", cancel=False, at=T0 + 10 * DAY):
        return self.p.billing_plan_change("alice", ORG, price_id=price_id, cancel=cancel, now=at)

    def plans(self, at=T0 + 10 * DAY):
        return self.p.customer_billing_plans("alice", ORG, now=at)

    def audit(self, action="billing_plan_change"):
        return [r.payload for r in self.store.iter_records()
                if isinstance(r.payload, dict) and r.payload.get("signal") == "provision.audit"
                and r.payload.get("action") == action]


# ---- end to end: the change rides the EXISTING drain -------------------------------------------------------------------
def test_a_downgrade_takes_effect_at_renewal_through_the_existing_drain(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    s = r.subs.subscription(ORG)
    assert (s.plan_id, s.allotment) == ("team", _ENT[TEAM].allotment)
    out = r.change(price_id=PRO)
    assert out == {"org_id": ORG, "kind": "change", "effective_at": T0 + PERIOD, "price_id": PRO,
                   "name": "Pro (monthly)", "cancel_at_period_end": False}
    ((sub_id, params, key),) = r.stripe.updates
    ((prod, pkey),) = r.stripe.products
    assert sub_id == "sub_1" and key.startswith("vigil-pc-") and pkey.startswith("vigil-pp-")
    assert prod == {"name": "Pro (monthly)", "metadata": {"price_id": PRO}}
    assert params == {"items": [{"id": "si_1", "price_data": {
        "currency": "usd", "product": "prod_1", "unit_amount": _EXP[PRO][0],
        "recurring": {"interval": "day", "interval_count": int(PERIOD // DAY)}}}],
        "proration_behavior": "none", "cancel_at_period_end": False, "metadata": {"price_id": PRO}}
    # nothing changed in VIGIL's money records: the current period is still Team, with its full allotment
    s = r.subs.subscription(ORG)
    assert (s.plan_id, s.period_end) == ("team", T0 + PERIOD)
    assert [t.granted for t in r.plan.tranches(ORG)] == [_ENT[TEAM].allotment]
    view = r.plans()
    assert view["scheduled_change"] == {"kind": "change", "effective_at": T0 + PERIOD, "price_id": PRO,
                                        "name": "Pro (monthly)"}
    assert next(t for t in view["tiers"] if t["price_id"] == PRO)["scheduled"] is True
    # the processor renews at the NEW catalog price; the REAL signer mints Pro, full allotment, full price — nothing
    # prorated, so the underpay cross-check holds
    r.stripe.invoice("in_2", reason="subscription_cycle", paid_at=T0 + PERIOD)
    assert r.stripe.objects["in_2"]["amount_paid"] == _EXP[PRO][0]
    assert r.send("invoice.paid", "in_2", t=T0 + PERIOD) is not None
    s = r.subs.subscription(ORG)
    assert (s.plan_id, s.allotment, s.period_start) == ("pro", _ENT[PRO].allotment, T0 + PERIOD)
    lines = [(i.invoice_id, i.price_id, i.amount_minor) for i in r.invoices.invoices(ORG)]
    assert lines == [("in_2", PRO, _EXP[PRO][0]), ("in_1", TEAM, _EXP[TEAM][0])]
    after = r.plans(at=T0 + PERIOD + DAY)
    assert after["scheduled_change"] is None and after["current"]["price_id"] == PRO
    audit = r.audit()
    assert [a["outcome"] for a in audit] == ["scheduled_change"] and audit[0]["target"] == PRO


def test_an_upgrade_is_billed_at_the_next_renewal_at_the_full_new_price(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig(price=RESEARCH)
    assert r.change(price_id=TEAM)["kind"] == "change"
    assert r.plans()["tiers"] and r.stripe.objects["sub_1"]["metadata"]["price_id"] == TEAM
    r.stripe.invoice("in_2", reason="subscription_cycle", paid_at=T0 + PERIOD)
    assert r.send("invoice.paid", "in_2", t=T0 + PERIOD) is not None
    assert r.subs.subscription(ORG).plan_id == "team"


def test_cancel_ends_the_plan_when_the_paid_period_ends(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    out = r.change(cancel=True)
    assert out["kind"] == "cancel" and out["cancel_at_period_end"] is True and out["price_id"] == ""
    assert r.stripe.updates[0][1] == {"cancel_at_period_end": True} and r.stripe.products == []
    view = r.plans()
    assert view["scheduled_change"] == {"kind": "cancel", "effective_at": T0 + PERIOD}
    assert view["actions"]["cancel"] is False                     # already ending: not offered again
    with pytest.raises(ProvisionDenied, match="already set to end"):
        r.change(cancel=True)
    # no renewal comes: once the period is over the workspace may choose a plan again through checkout
    later = r.plans(at=T0 + PERIOD + 1)
    assert later["current"]["active"] is False and later["actions"]["checkout"] is True


def test_keep_my_current_plan_undoes_a_change_or_a_cancellation(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    r.change(price_id=PRO)
    out = r.change(price_id=TEAM)                                  # back to the plan in force
    assert out["kind"] == "keep" and r.stripe.objects["sub_1"]["metadata"]["price_id"] == TEAM
    assert r.stripe.objects["sub_1"]["items"]["data"][0]["price"]["unit_amount"] == _EXP[TEAM][0]
    assert r.plans()["scheduled_change"] is None
    r.change(cancel=True)
    out = r.change(price_id=TEAM)                                  # un-cancel: no new price needed
    assert out["kind"] == "keep" and r.stripe.updates[-1][1] == {"cancel_at_period_end": False}
    assert r.stripe.objects["sub_1"]["cancel_at_period_end"] is False
    with pytest.raises(ProvisionDenied, match="already on that plan"):
        r.change(price_id=TEAM)
    r.change(price_id=PRO)
    with pytest.raises(ProvisionDenied, match="already scheduled"):
        r.change(price_id=PRO)


# ---- the rails: each refusal sends nothing --------------------------------------------------------------------------
def test_a_change_inside_the_renewal_cutoff_sends_nothing(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    with pytest.raises(ProvisionDenied, match="renews within a day"):
        r.change(price_id=PRO, at=T0 + PERIOD - pc.CHANGE_CUTOFF_S + 1)
    with pytest.raises(ProvisionDenied, match="period has ended"):
        r.change(price_id=PRO, at=T0 + PERIOD)
    assert r.stripe.updates == [] and r.stripe.products == []
    assert [a["outcome"] for a in r.audit()] == ["refused_renewal_imminent", "refused_period_ended"]
    assert r.plans(at=T0 + PERIOD - 100)["actions"]["change_unavailable_reason"].startswith("this plan renews")


@pytest.mark.parametrize("target,why", [
    ("vigil_topup_1k", "not a plan this workspace can switch to"),
    ("vigil_aegis_observe_1h_monthly", "not a plan this workspace can switch to"),
    ("no_such_price", "not a plan this workspace can switch to"),
    ("", "not a plan this workspace can switch to"),
])
def test_decide_refusals(monkeypatch, target, why):
    _all_on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")   # AEGIS plans on sale — still never a target
    r = _Rig()
    with pytest.raises(ProvisionDenied, match=why):
        r.change(price_id=target)
    assert r.stripe.updates == []


def test_a_plan_with_another_billing_period_is_refused(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    yearly = cat.CatalogEntry("vigil_pro_yearly", "subscription_active", "Pro (yearly)", 99000, "USD",
                              plan_id="pro_y", allotment=72_000, period_s=360 * DAY)
    real = pc.credit_plan_entries
    monkeypatch.setattr(pc, "credit_plan_entries",
                        lambda *, offered_only: real(offered_only=offered_only) + (yearly,))
    with pytest.raises(ProvisionDenied, match="different billing period"):
        r.change(price_id="vigil_pro_yearly")
    assert r.stripe.updates == []


@pytest.mark.parametrize("mutate,code", [
    (lambda s: s["metadata"].update(org_id="globex", tx_ref="vigil:globex:n2"), "tenant"),
    (lambda s: s.update(livemode=True), "mode"),
    (lambda s: s.update(status="past_due"), "status"),
    (lambda s: s["items"]["data"].append(copy.deepcopy(s["items"]["data"][0])), "items"),
    (lambda s: s["items"]["data"][0].update(id="bogus"), "price"),
    (lambda s: s["items"]["data"][0]["price"].update(unit_amount=1), "price"),          # not the catalog price
    (lambda s: s["metadata"].update(price_id="vigil_topup_1k"), "price"),               # not a credit plan
    (lambda s: s["items"]["data"][0]["price"]["recurring"].update(interval_count=31), "price"),
])
def test_parse_subscription_refusals(monkeypatch, mutate, code):
    _all_on(monkeypatch)
    r = _Rig()
    mutate(r.stripe.objects["sub_1"])
    with pytest.raises(ProvisionDenied, match="does not match"):
        r.change(price_id=PRO)
    assert r.stripe.updates == []
    assert r.audit()[-1]["outcome"].startswith("refused_subscription")


def test_current_plan_refusals(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig(price=None)                                            # no plan at all
    with pytest.raises(ProvisionDenied, match="no plan to change"):
        r.change(price_id=PRO)
    r.subs.subscribe(ORG, "team", 20_000, period_start=T0, period_end=T0 + PERIOD, issued_at=T0)
    with pytest.raises(ProvisionDenied, match="not bought through self-serve checkout"):
        r.change(price_id=PRO)                                      # a plan with no billing history (owner-granted)
    r.invoices.record(ORG, invoice_id="flw_evt_1", kind="subscription", price_id=TEAM, amount_minor=_EXP[TEAM][0],
                      currency="USD", credits=20_000, period_start=T0, period_end=T0 + PERIOD, issued_at=T0)
    with pytest.raises(ProvisionDenied, match="does not support self-serve changes"):
        r.change(price_id=PRO)                                      # bought through another processor
    r.subs.mark_past_due(ORG, issued_at=T0 + 1)
    with pytest.raises(ProvisionDenied, match="settle this plan's payment first"):
        r.change(price_id=PRO)
    assert r.stripe.updates == []


def test_a_processor_read_fault_refuses_and_changes_nothing(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    r.stripe.objects["sub_1"] = se.StripeEgressError("Stripe GET returned HTTP 500")
    with pytest.raises(ProvisionDenied, match="could not be reached; nothing was changed"):
        r.change(price_id=PRO)
    assert r.stripe.updates == []


@pytest.mark.parametrize("fault", ["lost", "echo"])
def test_an_unconfirmed_update_is_never_reported_as_done(monkeypatch, fault):
    _all_on(monkeypatch)
    r = _Rig()
    if fault == "lost":
        r.stripe.fail_update = TimeoutError("read timed out")
    else:
        r.stripe.echo_tamper = lambda s: {**s, "metadata": {**s["metadata"], "price_id": TEAM}}
    with pytest.raises(ProvisionDenied, match="did not confirm the change"):
        r.change(price_id=PRO)
    assert r.plans()["scheduled_change"] is None                    # no display record for an unconfirmed change
    rows = r.audit()
    assert rows[-1]["outcome"] == "unconfirmed" and "sha256:" in rows[-1]["reason"]


# ---- the gate (mirrors checkout) ----------------------------------------------------------------------------------------
def test_the_change_is_gated_like_checkout(monkeypatch):
    from sigil.ui.provision import ProvisionStepUpRequired
    r = _Rig()
    for missing in ("VIGIL_CUSTOMER_PLANS", "VIGIL_CUSTOMER_PLAN_CHANGE", "VIGIL_CUSTOMER_CHECKOUT_ENABLED",
                    "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED"):
        _all_on(monkeypatch)
        monkeypatch.delenv(missing)
        with pytest.raises(ProvisionDenied, match="not enabled"):
            r.change(price_id=PRO)
    _all_on(monkeypatch)
    with pytest.raises(ProvisionDenied, match="may not manage billing"):
        r.p.billing_plan_change("mallory", ORG, price_id=PRO, now=T0 + 10 * DAY)
    with pytest.raises(ProvisionDenied, match="may not manage billing"):
        r.p.billing_plan_change("alice", "globex", price_id=PRO, now=T0 + 10 * DAY)
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    with pytest.raises(ProvisionStepUpRequired):
        r.change(price_id=PRO)
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED")
    r.p._plan_changer = lambda: None                                # Stripe not provisioned
    with pytest.raises(ProvisionDenied, match="not provisioned the payment processor"):
        r.change(price_id=PRO)
    assert r.stripe.updates == []


def test_an_operator_who_cannot_spend_money_sees_plans_but_no_actions(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig(role="operator")
    with pytest.raises(ProvisionDenied, match="may not manage billing"):
        r.change(price_id=PRO)
    view = r.plans()
    assert view["can_manage"] is False and view["actions"]["change"] is False
    assert {t["action"] for t in view["tiers"]} <= {"current", "none"}


def test_the_rate_limit_applies(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    r.p.checkout_limiter = LoginRateLimiter(tempfile.mkdtemp(), max_fails=1, window_s=600.0, base_lock_s=600.0)
    r.change(price_id=PRO)
    with pytest.raises(ProvisionDenied, match="too many billing changes"):
        r.change(price_id=TEAM)


def test_the_owner_latch_pauses_plan_changes(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig()
    r.p._latch_refusal = lambda name: "new purchases are paused" if name == "checkout" else None
    with pytest.raises(ProvisionDenied, match="paused"):
        r.change(price_id=PRO)


def test_the_stripe_lane_preconditions_decide_whether_a_changer_exists(monkeypatch):
    p = _prov(_store(), ensure_owner_keypair())
    assert p._plan_changer() is None                                # nothing provisioned
    monkeypatch.setenv("VIGIL_BILLING_PROVIDER", "flutterwave")
    assert p._plan_changer() is None                                # another processor: never
    monkeypatch.setenv("VIGIL_BILLING_PROVIDER", "stripe")
    monkeypatch.setenv("VIGIL_BILLING_ENABLE_STRIPE", "1")
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SECRET", "whsec_" + "x")
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "_".join(["sk", "test", "dummy" + "0" * 6]))
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", "2000-01-01")
    ch = p._plan_changer()
    assert isinstance(ch, pc.StripePlanChanger) and ch._livemode is False


# ---- the Plans read --------------------------------------------------------------------------------------------------
def test_flags_off_the_plans_surface_is_absent(monkeypatch):
    from sigil.ui.server import Handler
    r = _Rig()
    h = Handler.__new__(Handler)
    with pytest.raises(ProvisionDenied, match="not enabled"):
        r.plans()
    assert h._provision_dispatch(r.p, "billing_plans", "alice", {"org_id": ORG}) is None
    assert h._provision_dispatch(r.p, "billing_plan_change", "alice", {"org_id": ORG, "price_id": PRO}) is None
    monkeypatch.setenv("VIGIL_CUSTOMER_PLANS", "1")                 # Plans on, change off: the change stays absent
    assert h._provision_dispatch(r.p, "billing_plan_change", "alice", {"org_id": ORG, "price_id": PRO}) is None
    assert h._provision_dispatch(r.p, "billing_plans", "alice", {"org_id": ORG})["org_id"] == ORG
    assert r.stripe.updates == []


def test_the_plans_read_compares_the_owner_catalog(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PLANS", "1")
    r = _Rig(price=None)
    view = r.plans()
    offered = cat.credit_plan_entries(offered_only=True)
    assert [t["price_id"] for t in view["tiers"]] == [e.price_id for e in offered]
    for t, e in zip(view["tiers"], offered):
        assert (t["amount_minor"], t["currency"], t["credits_per_period"], t["name"]) == (
            e.amount_minor, e.currency, e.allotment, e.display_name)
        assert t["period_days"] == 30.0 and t["action"] == "none" and t["current"] is False
    assert view["current"] is None and view["actions"]["checkout"] is False     # checkout flags off: no buy offer
    assert view["trial"]["credits"] == 100 and view["pay_as_you_go"]["packs"]
    assert all(set(p) == {"price_id", "name", "credits", "amount_minor", "currency"}
               for p in view["pay_as_you_go"]["packs"])
    blob = json.dumps(view).lower()
    for word in ("estimate", "margin", "markup", "claude", "strix", "nyx", "model"):
        assert word not in blob, word


def test_the_upgrade_offer_is_exactly_what_checkout_would_accept(monkeypatch):
    for k in ("VIGIL_CUSTOMER_PLANS", "VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED"):
        monkeypatch.setenv(k, "1")
    r = _Rig(price=None)
    view = r.plans()
    assert view["actions"]["checkout"] is True and {t["action"] for t in view["tiers"]} == {"checkout"}
    r.p.pending_checkouts.claim(ORG, PRO, f"vigil:{ORG}:pend", now=T0)       # a plan checkout in progress
    assert r.plans(at=T0 + 1)["actions"]["checkout"] is False
    plan = _Rig()                                                    # a live plan: no second checkout offered
    assert plan.plans()["actions"]["checkout"] is False


def test_the_plans_read_marks_the_current_plan_and_the_direction_of_a_switch(monkeypatch):
    _all_on(monkeypatch)
    r = _Rig(price=PRO)
    view = r.plans()
    by = {t["price_id"]: t for t in view["tiers"]}
    assert by[PRO]["current"] and by[PRO]["action"] == "current"
    assert by[TEAM]["action"] == "upgrade" and by[RESEARCH]["action"] == "downgrade"
    assert view["current"]["price_id"] == PRO and view["current"]["active"] is True
    assert view["actions"] == {"checkout": False, "change": True, "cancel": True, "change_unavailable_reason": "",
                               "plan_checkout_pending": False}


# ---- the display record ---------------------------------------------------------------------------------------------
def test_the_display_record_is_signed_and_period_bound(tmp_path):
    from sigil.reuse import generate_keypair
    owner, other = generate_keypair(), generate_keypair()
    led = pc.PlanChangeLedger(tmp_path, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    led.record(ORG, kind="change", from_price_id=TEAM, to_price_id=PRO, period_end=500.0, subscription_ref="r",
               issued_at=1.0)
    assert led.scheduled(ORG, period_end=500.0) == {"kind": "change", "from_price_id": TEAM, "to_price_id": PRO,
                                                    "effective_at": 500.0}
    assert led.scheduled(ORG, period_end=501.0) is None             # another period: never shown
    assert led.scheduled("globex", period_end=500.0) is None
    path = next(tmp_path.glob("*.json"))
    rec = json.loads(path.read_text())
    path.write_text(json.dumps({**rec, "to_price_id": RESEARCH}))   # tampered
    assert led.scheduled(ORG, period_end=500.0) is None
    stranger = pc.PlanChangeLedger(tmp_path, owner_key=other, trusted_pubkey=other.public_key_b64)
    stranger.record(ORG, kind="change", from_price_id=TEAM, to_price_id=PRO, period_end=500.0, subscription_ref="r",
                    issued_at=2.0)
    assert led.scheduled(ORG, period_end=500.0) is None             # signed by another key: never shown
    led.record(ORG, kind="keep", from_price_id=TEAM, to_price_id=TEAM, period_end=500.0, subscription_ref="r",
               issued_at=3.0)
    assert led.scheduled(ORG, period_end=500.0) is None             # a keep schedules nothing
    with pytest.raises(pc.PlanChangeRefused):
        with pc.PlanChangeLedger(tmp_path, owner_key=None, trusted_pubkey=None).exclusive(ORG):
            pass


# ---- the egress builders ----------------------------------------------------------------------------------------------
def test_the_stripe_egress_builders(monkeypatch):
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "_".join(["sk", "test", "dummy" + "0" * 6]))
    sent: list = []

    def transport(method, url, **kw):
        sent.append((method, url, kw))
        if url.endswith("/v1/products"):
            return {"object": "product", "id": "prod_9"}
        return {"object": "subscription", "id": url.rsplit("/", 1)[1]}
    bounded = se.with_timeout(pc.EGRESS_TIMEOUT_S, transport=transport)
    assert se.make_product_creator(transport=bounded)({"name": "Pro"}, idempotency_key="vigil-pp-1")["id"] == "prod_9"
    upd = se.make_subscription_updater(transport=bounded)
    assert upd("sub_1", {"cancel_at_period_end": True}, idempotency_key="vigil-pc-1")["id"] == "sub_1"
    assert [(m, u) for m, u, _k in sent] == [("POST", "https://api.stripe.com/v1/products"),
                                             ("POST", "https://api.stripe.com/v1/subscriptions/sub_1")]
    assert all(k["timeout"] == pc.EGRESS_TIMEOUT_S and k["idempotency_key"].startswith("vigil-p") for _m, _u, k in sent)
    for bad in ("sub_1/../x", "cus_1", "", None):
        with pytest.raises(se.StripeEgressError):
            upd(bad, {}, idempotency_key="k")
    for bad_key in ("", "a b", None, "x" * 256):
        with pytest.raises(se.StripeEgressError):
            upd("sub_1", {}, idempotency_key=bad_key)
    with pytest.raises(se.StripeEgressError, match="unexpected object"):
        se.make_subscription_updater(transport=lambda *a, **k: {"object": "subscription", "id": "sub_2"})(
            "sub_1", {}, idempotency_key="k")


def test_the_plan_change_hop_outwaits_its_egress():
    from sigil.ui import custui
    budget = custui._SLOW_HOP_TIMEOUTS_S["billing_plan_change"]
    assert budget > 4 * 2 * pc.EGRESS_TIMEOUT_S                     # 2 reads + 2 writes, connect + read each
    assert budget <= 60.0                                           # the drain deadline / TimeoutStopSec unchanged
    assert pc.EGRESS_TIMEOUT_S < se._DEFAULT_TIMEOUT_S


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
