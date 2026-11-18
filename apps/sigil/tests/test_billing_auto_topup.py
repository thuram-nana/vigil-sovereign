"""A1 — auto top-up: a saved card charged OFF-SESSION once per balance crossing, never above the monthly limit, and
credited ONLY by the verified webhook drain.

Everything runs offline against the repo's fake Stripe: the REAL ``StripeBillingProvider`` (auto-top-up mode) with a
fake PaymentIntent poster and a fake object fetcher, the REAL ``BillingSigner`` minting into a real wallet, and the
owner-signed ``AutoTopUpRegistry``. No network, no real card, no Stripe secret.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import tempfile
from pathlib import Path

import pytest

from sigil.governor import catalog as cat
from sigil.governor import stripe_egress as se
from sigil.governor.auto_topup import (GENESIS_ANCHOR, MAX_SETTING_CREDITS, STATUS_CAP_BLOCKED, STATUS_CHARGED,
                                       STATUS_DECLINED, AutoTopUpCharger, AutoTopUpRegistry, AutoTopUpSettings,
                                       crossing_nonce, decide)
from sigil.governor.billing import (CAP_UNATTENDED_TOPUP, BillingSigner, StripeBillingProvider, StripeEventRefused,
                                    UnsupportedCapability)
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
_K = {"owner_key": OWNER, "trusted_pubkey": OWNER.public_key_b64}
_WHSEC = "whsec_" + "a1-auto-topup-test"
_PACK = "vigil_topup_1k"                                    # a catalog top-up pack
_PACK_CREDITS = cat.mintable_entitlements()[_PACK].credits
_PACK_AMOUNT, _PACK_CCY = cat.mintable_expected()[_PACK]
_NOW = 1_700_000_000.0                                      # 2023-11-14 UTC
_ORG = "acme"


def _store() -> SpineStore:
    return SpineStore(str(Path(tempfile.mkdtemp()) / "spine.jsonl"))


class _FakeStripe:
    """The repo-local fake Stripe: an object store the fetcher reads, and a PaymentIntent poster honouring the
    Idempotency-Key exactly like Stripe (the same key returns the one PaymentIntent)."""

    def __init__(self, *, created: int = int(_NOW)):
        self.objects: dict = {}
        self.pi_calls: list = []
        self.by_key: dict = {}
        self.created = created
        self.fail: "Exception | None" = None        # raised by the next create (before anything is created)
        self.lose_response = False                  # create the PI, then fail transiently (the response is lost)
        self.status = "succeeded"
        self.fetched: list = []

    def fetch(self, kind, oid):
        self.fetched.append((kind, oid))
        return copy.deepcopy(self.objects[oid])

    def create_pi(self, params, *, idempotency_key):
        self.pi_calls.append((copy.deepcopy(params), idempotency_key))
        if self.fail is not None:
            exc, self.fail = self.fail, None
            raise exc
        pid = self.by_key.get(idempotency_key)
        if pid is None:
            pid = f"pi_{len(self.by_key) + 1}A1"
            self.by_key[idempotency_key] = pid
            self.objects[pid] = {
                "object": "payment_intent", "id": pid, "livemode": False, "status": self.status,
                "amount": params["amount"], "amount_received": params["amount"], "currency": params["currency"],
                "customer": params["customer"], "payment_method": params["payment_method"],
                "created": self.created, "metadata": dict(params["metadata"])}
        if self.lose_response:
            self.lose_response = False
            raise se._transient("Stripe POST transport failure (TimeoutError)")
        return copy.deepcopy(self.objects[pid])


class _Rig:
    """One org's wallet + auto-top-up ledger + the Stripe drain's signer, over one spine."""

    def __init__(self, *, auto_topup: bool = True, hook=None):
        self.store = _store()
        self.wallet = WalletRegistry(self.store, **_K)
        self.reg = AutoTopUpRegistry(self.store, **_K)
        self.invoices = InvoiceRegistry(self.store, **_K)
        self.stripe = _FakeStripe()
        self.provider = StripeBillingProvider(
            _WHSEC, fetcher=self.stripe.fetch, expected_mode="test", enable_reference_adapter=True,
            alarm_unaccounted_plans=True, strict=True, auto_topup=auto_topup,
            payment_intent_creator=self.stripe.create_pi if auto_topup else None)
        self.signer = BillingSigner(
            self.provider, wallet=self.wallet, subscriptions=SubscriptionRegistry(self.store, **_K),
            plan=PlanCreditLedger(self.store, **_K), catalog=cat.mintable_entitlements(),
            expected=cat.mintable_expected(), invoices=self.invoices, alarm_unaccounted_plans=True,
            require_verified_amount=True, alarm_unaccounted_topups=True, on_saved_payment_method=hook)
        self.notes: list = []
        self.charger = AutoTopUpCharger(self.reg, self.wallet, self.provider,
                                        notify=lambda org, c: self.notes.append((org, c.status, c.crossing_key)))

    def opt_in(self, *, trigger=100, cap=2 * _PACK_CREDITS, enabled=True, at=1.0, method=True):
        self.reg.set_settings(_ORG, enabled=enabled, trigger_credits=trigger, pack_price_id=_PACK,
                              monthly_cap_credits=cap, issued_at=at)
        if method:
            self.reg.capture_payment_method(_ORG, "cus_A1test", "pm_A1test", issued_at=at)

    def fund(self, credits=500, *, entry="trial-preview:acme", kind="trial"):
        self.wallet.grant(_ORG, credits, kind, entry_id=entry, issued_at=1.0)

    def spend(self, credits, entry):
        self.wallet.debit(_ORG, credits, entry_id=entry, issued_at=2.0)

    def send(self, etype, oid, *, eid="evt_1", t=int(_NOW)):
        ev = {"id": eid, "object": "event", "type": etype, "created": t, "livemode": False,
              "data": {"object": {"id": oid}}}
        raw = json.dumps(ev).encode()
        mac = hmac.new(_WHSEC.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
        return self.signer.ingest(raw, f"t={t},v1={mac}", now=float(t))


def _below_trigger_rig(**kw) -> _Rig:
    r = _Rig(**kw)
    r.fund(500)
    r.opt_in()
    r.spend(450, "d1")                                     # available 50 < trigger 100: a crossing
    return r


# ---- settings + saved method: owner-signed, per org -----------------------------------------------------------------
def test_settings_are_owner_signed_and_per_org():
    s = _store()
    reg = AutoTopUpRegistry(s, **_K)
    reg.set_settings(_ORG, enabled=True, trigger_credits=100, pack_price_id=_PACK, monthly_cap_credits=3000,
                     issued_at=1.0)
    got = reg.settings(_ORG)
    assert got == AutoTopUpSettings(_ORG, True, 100, _PACK, 3000, 1.0)
    assert reg.settings("beta") is None                                 # another org has none
    forger = generate_keypair()                                         # a record signed by anyone else is inert
    AutoTopUpRegistry(s, owner_key=forger, trusted_pubkey=forger.public_key_b64).set_settings(
        "beta", enabled=True, trigger_credits=1, pack_price_id=_PACK, monthly_cap_credits=9999, issued_at=2.0)
    assert reg.settings("beta") is None and reg.enabled_orgs() == [_ORG]
    with pytest.raises(ValueError, match="owner signing key"):
        AutoTopUpRegistry(s, owner_key=None, trusted_pubkey=OWNER.public_key_b64).set_settings(
            _ORG, enabled=False, trigger_credits=0, pack_price_id=_PACK, monthly_cap_credits=0, issued_at=3.0)


def test_a_replayed_older_settings_record_cannot_lift_the_limit():
    s = _store()
    reg = AutoTopUpRegistry(s, **_K)
    reg.set_settings(_ORG, enabled=True, trigger_credits=100, pack_price_id=_PACK, monthly_cap_credits=9000,
                     issued_at=1.0)
    old = next(r.payload for r in s.iter_records() if r.payload.get("signal") == "governor.auto_topup_settings")
    reg.set_settings(_ORG, enabled=True, trigger_credits=100, pack_price_id=_PACK, monthly_cap_credits=1000,
                     issued_at=2.0)
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(old))   # replay the captured old one
    assert reg.settings(_ORG).monthly_cap_credits == 1000
    reg.set_settings(_ORG, enabled=True, trigger_credits=100, pack_price_id=_PACK, monthly_cap_credits=5000,
                     issued_at=1.5)                                      # stale issued_at: inert
    assert reg.settings(_ORG).monthly_cap_credits == 1000


@pytest.mark.parametrize("kw", [{"pack_price_id": "vigil_pro_monthly"}, {"pack_price_id": "nope"},
                                {"trigger_credits": -1}, {"trigger_credits": True}, {"trigger_credits": 1.5},
                                {"monthly_cap_credits": "100"}, {"monthly_cap_credits": MAX_SETTING_CREDITS + 1},
                                {"enabled": 1}])
def test_settings_refuse_a_non_topup_pack_and_bad_values(kw):
    args = {"enabled": True, "trigger_credits": 100, "pack_price_id": _PACK, "monthly_cap_credits": 2000}
    args.update(kw)
    with pytest.raises(ValueError):
        AutoTopUpRegistry(_store(), **_K).set_settings(_ORG, issued_at=1.0, **args)


def test_the_saved_method_holds_only_stripe_ids_per_org():
    reg = AutoTopUpRegistry(_store(), **_K)
    reg.capture_payment_method(_ORG, "cus_X1", "pm_X1", issued_at=1.0)
    m = reg.payment_method(_ORG)
    assert (m.customer_id, m.payment_method_id) == ("cus_X1", "pm_X1") and reg.payment_method("beta") is None
    for cus, pm in (("cus_X1", "4242424242424242"), ("4242424242424242", "pm_X1"), ("cus_X1", "pm_1 2"),
                    ("cus_X1", "card_X1")):
        with pytest.raises(ValueError):
            reg.capture_payment_method(_ORG, cus, pm, issued_at=2.0)


# ---- the pure policy ------------------------------------------------------------------------------------------------
def _s(**kw):
    base = {"org_id": _ORG, "enabled": True, "trigger_credits": 100, "pack_price_id": _PACK,
            "monthly_cap_credits": 2000, "issued_at": 1.0}
    base.update(kw)
    return AutoTopUpSettings(**base)


@pytest.mark.parametrize("settings, kw, reason", [
    (None, {}, "disabled"),
    (_s(enabled=False), {}, "disabled"),
    (_s(), {"available": 100}, "above_trigger"),                 # at the trigger is not below it
    (_s(), {"has_method": False}, "no_method"),
    (_s(), {"already_charged": True}, "already_charged"),
    (_s(), {"month_charged": 1001}, "cap_exceeded"),             # 1001 + 1000 > 2000
    (_s(), {"month_charged": 1000}, "charge"),                   # 1000 + 1000 == 2000: allowed, never above
    (_s(), {}, "charge"),
])
def test_decide_charges_only_on_a_genuine_crossing_under_the_limit(settings, kw, reason):
    args = {"available": 99, "has_method": True, "already_charged": False, "month_charged": 0,
            "pack_credits": 1000, "pack_amount_minor": 1000, "pack_currency": "USD"}
    args.update(kw)
    assert decide(settings, **args).reason == reason


# ---- the off-session charge ----------------------------------------------------------------------------------------
def test_a_crossing_triggers_exactly_one_off_session_charge_and_mints_nothing():
    r = _below_trigger_rig()
    before = r.wallet.available(_ORG)
    res = r.charger.run(_ORG, now=_NOW)
    assert res.reason == "charged" and res.payment_intent_id == "pi_1A1"
    ((params, key),) = r.stripe.pi_calls
    assert params["off_session"] is True and params["confirm"] is True
    assert (params["customer"], params["payment_method"]) == ("cus_A1test", "pm_A1test")
    assert (params["amount"], params["currency"]) == (_PACK_AMOUNT, _PACK_CCY.lower())   # the owner catalog's
    assert params["metadata"]["vigil_auto_topup"] == "1" and params["metadata"]["org_id"] == _ORG
    assert params["metadata"]["price_id"] == _PACK
    nonce = crossing_nonce(_ORG, "trial-preview:acme")            # a ':' anchor still charges (hashed nonce)
    assert key == f"vigil-at-{nonce}" and params["metadata"]["tx_ref"] == f"vigil:{_ORG}:{nonce}"
    (c,) = r.reg.charges(_ORG)
    assert (c.status, c.credits, c.payment_intent_id) == (STATUS_CHARGED, _PACK_CREDITS, "pi_1A1")
    assert r.wallet.available(_ORG) == before                    # the charge call never credits


def test_credit_appears_only_after_the_verified_webhook():
    r = _below_trigger_rig()
    r.charger.run(_ORG, now=_NOW)
    assert r.wallet.available(_ORG) == 50
    # a forged delivery (wrong signing secret) credits nothing
    ev = json.dumps({"id": "evt_x", "object": "event", "type": "payment_intent.succeeded", "created": int(_NOW),
                     "livemode": False, "data": {"object": {"id": "pi_1A1"}}}).encode()
    bad = hmac.new(b"whsec_wrong", f"{int(_NOW)}.".encode() + ev, hashlib.sha256).hexdigest()
    with pytest.raises(StripeEventRefused):                      # the strict drain quarantines it
        r.signer.ingest(ev, f"t={int(_NOW)},v1={bad}", now=_NOW)
    assert r.wallet.available(_ORG) == 50
    assert r.send("payment_intent.succeeded", "pi_1A1") is not None
    assert r.wallet.available(_ORG) == 50 + _PACK_CREDITS
    assert ("payment_intent", "pi_1A1") in r.stripe.fetched      # minted from the RE-FETCHED object
    r.send("payment_intent.succeeded", "pi_1A1", eid="evt_2")    # a redelivery folds once
    assert r.wallet.available(_ORG) == 50 + _PACK_CREDITS
    assert [(i.invoice_id, i.kind) for i in r.invoices.invoices(_ORG)] == [("pi_1A1", "topup")]


def test_rerunning_the_same_crossing_charges_and_notifies_nothing_more():
    r = _below_trigger_rig()
    first = r.charger.run(_ORG, now=_NOW)
    second = r.charger.run(_ORG, now=_NOW + 60)                  # re-drive before the webhook lands
    assert (first.reason, second.reason) == ("charged", "already_charged")
    assert len(r.stripe.pi_calls) == 1 and len(r.reg.charges(_ORG)) == 1
    assert r.notes == [(_ORG, STATUS_CHARGED, "trial-preview:acme")]
    r.send("payment_intent.succeeded", "pi_1A1")
    assert r.charger.run(_ORG, now=_NOW + 120).reason == "above_trigger"
    assert len(r.stripe.pi_calls) == 1 and len(r.notes) == 1


def test_the_next_crossing_after_a_top_up_re_arms_with_a_new_key():
    r = _below_trigger_rig()
    r.charger.run(_ORG, now=_NOW)
    r.send("payment_intent.succeeded", "pi_1A1")
    assert r.reg.last_credit_anchor(_ORG) == "pi_1A1"            # the auto top-up's own grant re-arms it
    r.spend(_PACK_CREDITS, "d2")                                 # back below the trigger: a NEW crossing
    assert r.charger.run(_ORG, now=_NOW + 60).reason == "charged"
    keys = [k for _p, k in r.stripe.pi_calls]
    assert len(keys) == 2 and keys[0] != keys[1]


def test_the_monthly_limit_blocks_a_charge_and_notifies_once():
    r = _Rig()
    r.fund(500)
    r.opt_in(cap=_PACK_CREDITS)                                  # room for exactly one pack this month
    r.spend(450, "d1")
    assert r.charger.run(_ORG, now=_NOW).reason == "charged"
    r.send("payment_intent.succeeded", "pi_1A1")
    r.spend(_PACK_CREDITS, "d2")                                 # a second crossing in the same month
    blocked = r.charger.run(_ORG, now=_NOW + 60)
    assert blocked.reason == "cap_exceeded" and len(r.stripe.pi_calls) == 1   # nothing sent to Stripe
    assert r.notes[-1] == (_ORG, STATUS_CAP_BLOCKED, "pi_1A1")
    assert r.charger.run(_ORG, now=_NOW + 120).reason == "already_charged"
    assert len(r.notes) == 2 and r.reg.month_charged_credits(_ORG, _NOW) == _PACK_CREDITS
    assert r.reg.month_charged_credits(_ORG, _NOW + 40 * 86400) == 0          # a new month starts at zero


def test_the_limit_counts_a_charge_whose_response_was_lost():
    r = _Rig()
    r.fund(500)
    r.opt_in(cap=_PACK_CREDITS)
    r.spend(450, "d1")
    r.stripe.lose_response = True                                # Stripe charged, the response never arrived
    assert r.charger.run(_ORG, now=_NOW).reason == "transient" and r.reg.charges(_ORG) == []
    r.send("payment_intent.succeeded", "pi_1A1")                 # ... and its webhook minted it anyway
    assert r.reg.month_charged_credits(_ORG, _NOW) == _PACK_CREDITS
    r.spend(_PACK_CREDITS, "d2")
    assert r.charger.run(_ORG, now=_NOW + 60).reason == "cap_exceeded"
    assert len(r.stripe.pi_calls) == 1


def test_a_transient_failure_records_nothing_and_retries_under_the_same_key():
    r = _below_trigger_rig()
    r.stripe.fail = se._transient("Stripe POST returned HTTP 503")
    assert r.charger.run(_ORG, now=_NOW).reason == "transient"
    assert r.reg.charges(_ORG) == [] and r.notes == []
    assert r.charger.run(_ORG, now=_NOW + 60).reason == "charged"
    (k1, k2) = [k for _p, k in r.stripe.pi_calls]
    assert k1 == k2 and len(r.stripe.by_key) == 1                # one PaymentIntent for the crossing


def test_a_declined_card_consumes_the_crossing_and_notifies_once():
    r = _below_trigger_rig()
    r.stripe.fail = se.StripeEgressError("Stripe POST returned HTTP 402")    # definitive (card_error)
    res = r.charger.run(_ORG, now=_NOW)
    assert res.reason == "declined" and r.notes == [(_ORG, STATUS_DECLINED, "trial-preview:acme")]
    assert r.charger.run(_ORG, now=_NOW + 60).reason == "already_charged"
    assert len(r.stripe.pi_calls) == 1 and len(r.notes) == 1
    assert r.reg.month_charged_credits(_ORG, _NOW) == 0          # a decline spent nothing


def test_a_requires_action_payment_intent_is_not_a_charge():
    r = _below_trigger_rig()
    r.stripe.status = "requires_action"
    assert r.charger.run(_ORG, now=_NOW).reason == "declined"
    assert r.reg.month_charged_credits(_ORG, _NOW) == 0


def test_no_saved_card_or_no_opt_in_charges_nothing():
    r = _Rig()
    r.fund(500)
    r.opt_in(method=False)
    r.spend(450, "d1")
    assert r.charger.run(_ORG, now=_NOW).reason == "no_method"
    r2 = _Rig()
    r2.fund(500)
    r2.opt_in(enabled=False)
    r2.spend(450, "d1")
    assert r2.charger.run(_ORG, now=_NOW).reason == "disabled"
    assert r.stripe.pi_calls == [] and r2.stripe.pi_calls == [] and r.notes == r2.notes == []


def test_a_crossing_with_no_grant_anchors_at_genesis():
    r = _Rig()
    r.opt_in()
    assert r.reg.last_credit_anchor(_ORG) == GENESIS_ANCHOR
    assert r.charger.run(_ORG, now=_NOW).reason == "charged"
    assert r.reg.charges(_ORG)[0].crossing_key == GENESIS_ANCHOR


# ---- the off-session primitive ---------------------------------------------------------------------------------------
def _provider(creator=None, *, auto=True):
    return StripeBillingProvider(_WHSEC, fetcher=lambda k, o: {}, expected_mode="test",
                                 enable_reference_adapter=True, auto_topup=auto, payment_intent_creator=creator)


def test_the_off_session_amount_comes_from_the_catalog_never_the_caller():
    calls: list = []
    p = _provider(lambda params, idempotency_key: calls.append(params) or {
        "object": "payment_intent", "id": "pi_9", "status": "succeeded"})
    exp = cat.mintable_expected()
    out = p.create_off_session_topup(_ORG, _PACK, customer_id="cus_1", payment_method_id="pm_1", expected=exp,
                                     nonce="n1")
    assert out.accepted and (out.amount_minor, out.currency) == (_PACK_AMOUNT, _PACK_CCY)
    assert calls[0]["amount"] == _PACK_AMOUNT
    for kw in ({"price_id": "unknown"}, {"customer_id": "cus 1"}, {"payment_method_id": "card_1"},
               {"org_id": "bad org"}, {"nonce": "a:b"}):
        args = {"org_id": _ORG, "price_id": _PACK, "customer_id": "cus_1", "payment_method_id": "pm_1",
                "nonce": "n2"}
        args.update(kw)
        with pytest.raises(ValueError):
            p.create_off_session_topup(args.pop("org_id"), args.pop("price_id"), expected=exp, **args)
    with pytest.raises(ValueError, match="not enabled for EUR"):
        p.create_off_session_topup(_ORG, _PACK, customer_id="cus_1", payment_method_id="pm_1",
                                   expected={_PACK: (1000, "EUR")}, nonce="n3")


def test_off_session_charging_is_a_declared_capability_only_with_a_creator():
    assert CAP_UNATTENDED_TOPUP in _provider(lambda *a, **k: {}).capabilities()
    for p in (_provider(None), _provider(lambda *a, **k: {}, auto=False)):
        assert CAP_UNATTENDED_TOPUP not in p.capabilities()
        with pytest.raises(UnsupportedCapability):
            p.create_off_session_topup(_ORG, _PACK, customer_id="cus_1", payment_method_id="pm_1",
                                       expected=cat.mintable_expected(), nonce="n1")


def test_an_unexpected_create_response_is_not_accepted():
    for resp in ({}, {"object": "charge", "id": "ch_1"}, {"object": "payment_intent", "id": "x_1",
                                                           "status": "succeeded"}):
        out = _provider(lambda params, idempotency_key, _r=resp: _r).create_off_session_topup(
            _ORG, _PACK, customer_id="cus_1", payment_method_id="pm_1", expected=cat.mintable_expected(),
            nonce="n1")
        assert out.accepted is False


# ---- the webhook mint path: only OUR off-session PaymentIntent mints ------------------------------------------------
def test_a_checkout_payment_intent_is_never_minted_on_the_auto_topup_path():
    r = _Rig()
    r.stripe.objects["pi_CO1"] = {"object": "payment_intent", "id": "pi_CO1", "livemode": False,
                                  "status": "succeeded", "amount_received": _PACK_AMOUNT, "currency": "usd",
                                  "created": int(_NOW), "metadata": {"org_id": _ORG, "price_id": _PACK,
                                                                     "tx_ref": f"vigil:{_ORG}:n1"}}
    assert r.send("payment_intent.succeeded", "pi_CO1") is None   # no auto-top-up marker -> no second credit
    assert r.wallet.available(_ORG) == 0


@pytest.mark.parametrize("change", [{"status": "processing"}, {"status": "requires_payment_method"},
                                    {"livemode": True}])
def test_an_unfinished_or_other_mode_payment_intent_mints_nothing(change):
    r = _below_trigger_rig()
    r.charger.run(_ORG, now=_NOW)
    r.stripe.objects["pi_1A1"].update(change)
    try:
        assert r.send("payment_intent.succeeded", "pi_1A1") is None
    except Exception:                                            # the other-mode object is refused loudly
        assert change.get("livemode") is True
    assert r.wallet.available(_ORG) == 50


# ---- flag OFF: byte-identical -----------------------------------------------------------------------------------------
def test_flag_off_the_stripe_adapter_ignores_payment_intent_events_without_fetching():
    r = _Rig(auto_topup=False)
    r.stripe.objects["pi_1A1"] = {"object": "payment_intent", "id": "pi_1A1"}
    assert r.send("payment_intent.succeeded", "pi_1A1") is None
    assert r.stripe.fetched == [] and r.wallet.available(_ORG) == 0


def _checkout_params(monkeypatch, **kw):
    from sigil.governor import billing as b
    monkeypatch.setattr(b.secrets, "token_urlsafe", lambda n=18: "FIXEDNONCE")
    sent: list = []

    def creator(params, *, idempotency_key):
        sent.append(copy.deepcopy(params))
        return {"object": "checkout.session", "id": "cs_test_1", "livemode": False, "mode": params["mode"],
                "client_reference_id": params["client_reference_id"], "currency": "usd",
                "amount_total": params["line_items"][0]["price_data"]["unit_amount"],
                "url": "https://checkout.stripe.com/c/pay/cs_test_1"}
    p = StripeBillingProvider(_WHSEC, fetcher=lambda k, o: {}, expected_mode="test", enable_reference_adapter=True,
                              checkout_creator=creator)
    p.create_checkout(_ORG, _PACK, expected=cat.expected_amounts(), redirect_url="https://app.example.test/#/b",
                      **kw)
    return sent[0]


#: The checkout payload the Stripe adapter posted for a top-up BEFORE A1 (pinned): A1 must leave it byte-identical.
_GOLDEN_TOPUP_CHECKOUT = {
    "mode": "payment",
    "line_items": [{"price_data": {"currency": "usd", "unit_amount": _PACK_AMOUNT,
                                   "product_data": {"name": _PACK}}, "quantity": 1}],
    "client_reference_id": f"vigil:{_ORG}:FIXEDNONCE",
    "metadata": {"org_id": _ORG, "price_id": _PACK, "tx_ref": f"vigil:{_ORG}:FIXEDNONCE"},
    "payment_intent_data": {"metadata": {"org_id": _ORG, "price_id": _PACK, "tx_ref": f"vigil:{_ORG}:FIXEDNONCE"}},
    "success_url": "https://app.example.test/#/b?status=successful&session_id={CHECKOUT_SESSION_ID}",
    "cancel_url": "https://app.example.test/#/b?status=cancelled",
    "adaptive_pricing": {"enabled": False},
}


def test_flag_off_the_checkout_payload_is_byte_identical(monkeypatch):
    got = _checkout_params(monkeypatch)
    assert json.dumps(got, sort_keys=True) == json.dumps(_GOLDEN_TOPUP_CHECKOUT, sort_keys=True)
    assert _checkout_params(monkeypatch, save_future_payments=False) == got


def test_an_opted_in_topup_checkout_asks_stripe_to_save_the_card(monkeypatch):
    got = _checkout_params(monkeypatch, save_future_payments=True)
    assert got["customer_creation"] == "always"
    assert got["payment_intent_data"]["setup_future_usage"] == "off_session"
    assert got["metadata"]["vigil_save_method"] == "1" == got["payment_intent_data"]["metadata"]["vigil_save_method"]
    rest = {k: v for k, v in got.items() if k != "customer_creation"}
    rest["metadata"] = {k: v for k, v in got["metadata"].items() if k != "vigil_save_method"}
    rest["payment_intent_data"] = {"metadata": rest["metadata"]}
    assert json.dumps(rest, sort_keys=True) == json.dumps(_GOLDEN_TOPUP_CHECKOUT, sort_keys=True)


def _spine_payloads(store):
    out = []
    for rec in store.iter_records():
        p = dict(rec.payload)
        out.append(json.dumps(p, sort_keys=True))
    return out


def test_flag_off_the_signer_mint_is_byte_identical():
    """The same signed checkout webhook minted by a signer WITHOUT the A1 hook and one WITH it (a session that did
    not ask to save a card) leaves the identical owner-signed records."""
    def mint(hook):
        r = _Rig(auto_topup=False, hook=hook)
        r.stripe.objects["cs_test_g1"] = {
            "object": "checkout.session", "id": "cs_test_g1", "livemode": False, "mode": "payment",
            "status": "complete", "payment_status": "paid", "client_reference_id": f"vigil:{_ORG}:n1",
            "amount_total": _PACK_AMOUNT, "currency": "usd", "created": int(_NOW),
            "metadata": {"org_id": _ORG, "price_id": _PACK}, "customer": "cus_G1", "payment_intent": "pi_G1"}
        assert r.send("checkout.session.completed", "cs_test_g1") is not None
        return _spine_payloads(r.store)
    called: list = []
    assert mint(None) == mint(lambda *a: called.append(a))
    assert called == []


def test_flag_off_the_sweep_refuses(monkeypatch, capsys):
    import argparse

    from sigil import cli
    monkeypatch.delenv("VIGIL_BILLING_AUTO_TOPUP", raising=False)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_auto_topup_run(argparse.Namespace(now=_NOW))
    assert ei.value.code == 2 and "disabled" in capsys.readouterr().err


# ---- the saved card is captured from an opted-in checkout's webhook ------------------------------------------------
def _capture_rig():
    from sigil import cli
    holder: dict = {}

    def fetcher(kind, oid):
        return holder["rig"].stripe.fetch(kind, oid)
    # the capture hook signs with the persisted identity in production; here the rig's owner key, via the registry
    rig = _Rig(auto_topup=True)
    holder["rig"] = rig
    hook = cli._auto_topup_capture_hook(rig.store, fetcher)
    rig.signer.on_saved_payment_method = hook
    return rig


def _paid_session(**meta):
    return {"object": "checkout.session", "id": "cs_test_s1", "livemode": False, "mode": "payment",
            "status": "complete", "payment_status": "paid", "client_reference_id": f"vigil:{_ORG}:n1",
            "amount_total": _PACK_AMOUNT, "currency": "usd", "created": int(_NOW),
            "metadata": {"org_id": _ORG, "price_id": _PACK, **meta}, "customer": "cus_S1",
            "payment_intent": "pi_S1"}


def test_the_saved_card_is_captured_from_an_opted_in_checkout_webhook(monkeypatch):
    from sigil.governor import auto_topup as at
    monkeypatch.setattr(at, "owner_keypair", lambda: OWNER)
    monkeypatch.setattr(at, "owner_pubkey", lambda: OWNER.public_key_b64)
    r = _capture_rig()
    r.stripe.objects["cs_test_s1"] = _paid_session(vigil_save_method="1")
    r.stripe.objects["pi_S1"] = {"object": "payment_intent", "id": "pi_S1", "livemode": False,
                                 "payment_method": "pm_S1", "customer": "cus_S1"}
    assert r.send("checkout.session.completed", "cs_test_s1") is not None
    m = r.reg.payment_method(_ORG)
    assert (m.customer_id, m.payment_method_id) == ("cus_S1", "pm_S1")
    assert r.wallet.available(_ORG) == _PACK_CREDITS


def test_a_checkout_that_did_not_ask_to_save_captures_nothing(monkeypatch):
    from sigil.governor import auto_topup as at
    monkeypatch.setattr(at, "owner_keypair", lambda: OWNER)
    monkeypatch.setattr(at, "owner_pubkey", lambda: OWNER.public_key_b64)
    r = _capture_rig()
    r.stripe.objects["cs_test_s1"] = _paid_session()
    r.send("checkout.session.completed", "cs_test_s1")
    assert r.reg.payment_method(_ORG) is None and ("payment_intent", "pi_S1") not in r.stripe.fetched


def _sweep_env(monkeypatch, store, stripe):
    """The sweep's process env over a test spine: the flag, an explicit SIGIL_HOME, the Stripe lane preconditions
    (a dummy test-mode key — never a real secret) and the repo's fake Stripe in place of the egress."""
    from sigil import cli
    from sigil.governor import auto_topup as at
    from sigil.governor import wallet as w
    monkeypatch.setenv("VIGIL_BILLING_AUTO_TOPUP", "1")
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_BILLING_ENABLE_STRIPE", "1")
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SECRET", _WHSEC)
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "_".join(["sk", "test", "dummy0000notreal"]))
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", "2000-01-01")
    for mod in (at, w):                                      # the persisted owner identity, as the sweep loads it
        monkeypatch.setattr(mod, "owner_keypair", lambda: OWNER)
        monkeypatch.setattr(mod, "owner_pubkey", lambda: OWNER.public_key_b64)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    monkeypatch.setattr(se, "make_object_fetcher", lambda **k: stripe.fetch)
    monkeypatch.setattr(se, "make_payment_intent_creator", lambda **k: stripe.create_pi)


def _sweep(capsys, now):
    import argparse

    from sigil import cli
    cli.cmd_auto_topup_run(argparse.Namespace(now=now))
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_the_sweep_charges_each_opted_in_org_once_per_crossing(monkeypatch, capsys):
    r = _below_trigger_rig()
    r.wallet.grant("beta", 5000, "trial", entry_id="trial-preview:beta", issued_at=1.0)   # opted in, above trigger
    r.reg.set_settings("beta", enabled=True, trigger_credits=100, pack_price_id=_PACK, monthly_cap_credits=5000,
                       issued_at=1.0)
    r.reg.capture_payment_method("beta", "cus_B1", "pm_B1", issued_at=1.0)
    _sweep_env(monkeypatch, r.store, r.stripe)
    out = _sweep(capsys, _NOW)
    assert out == {"orgs": 2, "above_trigger": ["beta"], "charged": [_ORG]}
    assert _sweep(capsys, _NOW + 60) == {"orgs": 2, "above_trigger": ["beta"], "already_charged": [_ORG]}
    assert len(r.stripe.pi_calls) == 1 and r.wallet.available(_ORG) == 50      # credit waits for the webhook


def test_the_checkout_latch_stops_every_new_automatic_charge(monkeypatch, capsys):
    from sigil.governor.customer_latch import turn_off
    r = _below_trigger_rig()
    _sweep_env(monkeypatch, r.store, r.stripe)
    turn_off(r.store, "checkout")
    assert _sweep(capsys, _NOW)["paused"] is True
    assert r.stripe.pi_calls == [] and r.reg.charges(_ORG) == []


@pytest.mark.parametrize("unset", ["VIGIL_STRIPE_WEBHOOK_SECRET", "VIGIL_BILLING_ENABLE_STRIPE",
                                   "VIGIL_STRIPE_API_VERSION", "VIGIL_STRIPE_SECRET_KEY", "SIGIL_HOME"])
def test_the_sweep_refuses_without_every_stripe_lane_precondition(monkeypatch, capsys, unset):
    import argparse

    from sigil import cli
    r = _below_trigger_rig()
    _sweep_env(monkeypatch, r.store, r.stripe)
    monkeypatch.delenv(unset)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_auto_topup_run(argparse.Namespace(now=_NOW))
    assert ei.value.code == 2 and r.stripe.pi_calls == []


def test_a_capture_fault_never_undoes_the_credit():
    def boom(*a):
        raise RuntimeError("capture failed")
    r = _Rig(hook=boom)
    r.stripe.objects["cs_test_s1"] = _paid_session(vigil_save_method="1")
    assert r.send("checkout.session.completed", "cs_test_s1") is not None
    assert r.wallet.available(_ORG) == _PACK_CREDITS
