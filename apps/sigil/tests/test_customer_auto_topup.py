"""A1 — the customer's auto top-up: the settings read + change are flag-gated, admit-first, owner-signed and
credits-only, over the provisioner AND the REAL edge → cockpit hop; an opted-in org's top-up checkout asks Stripe to
save the card (and no other checkout changes); every charge reaches the notification centre exactly once.

Offline: the repo's fake Stripe poster, no network, no real card, no Stripe secret.
"""
from __future__ import annotations

import json

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_checkout import _iso, _on, _provisioner  # noqa: F401  (_iso is autouse)
from test_customer_checkout_stripe import _stripe_env, _stripe_on, _with_fake_stripe  # noqa: F401

from sigil.governor.auto_topup import MAX_SETTING_CREDITS, AutoTopUpRegistry
from sigil.reuse import generate_keypair
from sigil.ui.provision import ProvisionDenied, ProvisionStepUpRequired

_PACK = "vigil_topup_1k"
_ROUTE = "/api/customer/billing/auto-topup"


@pytest.fixture(autouse=True)
def _flag_unset(monkeypatch):
    for k in ("VIGIL_BILLING_AUTO_TOPUP", "VIGIL_CUSTOMER_STEPUP_REQUIRED"):
        monkeypatch.delenv(k, raising=False)


def _flag(monkeypatch):
    monkeypatch.setenv("VIGIL_BILLING_AUTO_TOPUP", "1")


def _set(p, who, org, **kw):
    args = {"enabled": True, "trigger_credits": 100, "pack_price_id": _PACK, "monthly_cap_credits": 2000}
    args.update(kw)
    return p.billing_auto_topup_set(who, org, **args)


def _reg(p, *, signing=False):
    return AutoTopUpRegistry(p.store, owner_key=p.wallet.owner_key if signing else None,
                             trusted_pubkey=p.wallet.trusted_pubkey)


# ---- the provisioner -------------------------------------------------------------------------------------------------
def test_the_settings_read_and_change_are_absent_while_the_flag_is_off():
    p, admin, _t, org, _o, _w = _provisioner()
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.customer_billing_auto_topup(admin, org)
    with pytest.raises(ProvisionDenied, match="not enabled"):
        _set(p, admin, org)
    assert _reg(p).settings(org) is None


def test_only_a_billing_admin_of_the_org_may_arm_auto_top_up(monkeypatch):
    _flag(monkeypatch)
    p, admin, tester, org, _o, _w = _provisioner()
    for who in (tester, "cust_stranger0000000000001"):          # an operator runs tests but spends no money
        with pytest.raises(ProvisionDenied, match="may not manage billing"):
            _set(p, who, org)
    assert _reg(p).settings(org) is None
    assert _set(p, admin, org) == {"enabled": True, "trigger_credits": 100, "pack_price_id": _PACK,
                                   "monthly_cap_credits": 2000}


def test_the_settings_are_owner_signed_under_the_wallet_identity(monkeypatch):
    _flag(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    _set(p, admin, org, trigger_credits=250, monthly_cap_credits=3000)
    s = _reg(p).settings(org)
    assert (s.enabled, s.trigger_credits, s.pack_price_id, s.monthly_cap_credits) == (True, 250, _PACK, 3000)
    stranger = generate_keypair()
    assert AutoTopUpRegistry(p.store, owner_key=None, trusted_pubkey=stranger.public_key_b64).settings(org) is None
    assert _reg(p).settings(other) is None                      # per org: the other tenant is untouched


@pytest.mark.parametrize("kw, why", [
    ({"enabled": "yes"}, "true or false"), ({"enabled": None}, "true or false"),
    ({"trigger_credits": 1.5}, "non-negative integer"), ({"trigger_credits": "100"}, "non-negative integer"),
    ({"trigger_credits": -1}, "non-negative integer"), ({"trigger_credits": True}, "non-negative integer"),
    ({"monthly_cap_credits": MAX_SETTING_CREDITS + 1}, "at most"),
    ({"pack_price_id": "vigil_pro_monthly"}, "offered top-up"), ({"pack_price_id": "nope"}, "offered top-up"),
    ({"pack_price_id": None}, "offered top-up"),
    ({"monthly_cap_credits": 999}, "at least one pack"),        # enabling with room for no pack at all
])
def test_bad_settings_are_refused(monkeypatch, kw, why):
    _flag(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    with pytest.raises(ProvisionDenied, match=why):
        _set(p, admin, org, **kw)
    assert _reg(p).settings(org) is None


def test_turning_auto_top_up_off_needs_no_room_for_a_pack(monkeypatch):
    _flag(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    _set(p, admin, org)
    _set(p, admin, org, enabled=False, monthly_cap_credits=0)
    assert _reg(p).settings(org).enabled is False and _reg(p).enabled_orgs() == []


def test_a_fresh_step_up_is_required_when_enforced(monkeypatch):
    _flag(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    p, admin, _t, org, _o, _w = _provisioner()
    with pytest.raises(ProvisionStepUpRequired):
        _set(p, admin, org)
    assert _reg(p).settings(org) is None


def test_the_read_is_credits_only_and_carries_no_card_or_processor_detail(monkeypatch):
    _flag(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    assert p.customer_billing_auto_topup(admin, org)["settings"] is None
    _set(p, admin, org)
    reg = _reg(p, signing=True)
    reg.capture_payment_method(org, "cus_R1", "pm_R1", issued_at=10.0)
    reg.record_charge(org, crossing_key="pi_prev1", status="charged", pack_price_id=_PACK, credits=1000,
                      amount_minor=1000, currency="USD", payment_intent_id="pi_R1", issued_at=11.0)
    d = p.customer_billing_auto_topup(admin, org, now=11.0)
    assert d["settings"] == {"enabled": True, "trigger_credits": 100, "pack_price_id": _PACK,
                             "monthly_cap_credits": 2000}
    assert d["card_saved"] is True and d["month_credits"] == 1000
    assert d["receipts"] == [{"status": "charged", "credits": 1000, "at": 11.0}]
    assert {pk["price_id"] for pk in d["packs"]} >= {_PACK} and all(set(pk) == {"price_id", "name", "credits"}
                                                                      for pk in d["packs"])
    blob = json.dumps(d).lower()
    for banned in ("amount", "currency", "usd", "$", "cus_", "pm_", "pi_", "estimat"):
        assert banned not in blob, banned


def test_the_read_needs_billing_visibility(monkeypatch):
    _flag(monkeypatch)
    p, _admin, _t, org, _o, _w = _provisioner()
    with pytest.raises(ProvisionDenied, match="may not read"):
        p.customer_billing_auto_topup("cust_stranger0000000000001", org)


# ---- the checkout saves a card only for an opted-in org ------------------------------------------------------------
def _topup_params(p, admin, org, fake):
    p.billing_checkout(admin, org, _PACK)
    params = fake.calls[-1]
    for k in ("client_reference_id",):
        params.pop(k)
    for where in (params["metadata"], params["payment_intent_data"]["metadata"]):
        where.pop("tx_ref")
    return params


def test_an_opted_in_org_checkout_saves_the_card_and_no_other_checkout_changes(monkeypatch):
    _on(monkeypatch)
    _stripe_on(monkeypatch)
    fake = _with_fake_stripe(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    flag_off = _topup_params(p, admin, org, fake)                # the pre-A1 payload
    assert "customer_creation" not in flag_off and "setup_future_usage" not in flag_off["payment_intent_data"]
    _flag(monkeypatch)
    assert _topup_params(p, admin, org, fake) == flag_off        # on, but this org never opted in
    _set(p, admin, org, enabled=False, monthly_cap_credits=0)
    assert _topup_params(p, admin, org, fake) == flag_off        # opted OUT
    _set(p, admin, org)
    saved = _topup_params(p, admin, org, fake)                   # opted in: Stripe saves the card for off-session
    assert saved["customer_creation"] == "always"
    assert saved["payment_intent_data"]["setup_future_usage"] == "off_session"
    assert saved["metadata"]["vigil_save_method"] == "1"
    monkeypatch.delenv("VIGIL_BILLING_AUTO_TOPUP")
    assert _topup_params(p, admin, org, fake) == flag_off        # flag off again: the settings record is inert


# ---- the notification centre: one receipt per charge ----------------------------------------------------------------
def test_every_charge_reaches_the_notification_centre_once_in_credits(monkeypatch):
    p, admin, _t, org, _o, _w = _provisioner()
    reg = _reg(p, signing=True)
    reg.record_charge(org, crossing_key="trial-preview:x", status="charged", pack_price_id=_PACK, credits=1000,
                      amount_minor=1000, currency="USD", payment_intent_id="pi_N1", issued_at=5.0)
    reg.record_charge(org, crossing_key="pi_N1", status="cap_blocked", pack_price_id=_PACK, credits=1000,
                      amount_minor=1000, currency="USD", payment_intent_id="", issued_at=6.0)
    off = {n["id"] for n in p.customer_notifications(admin, org)["notifications"]}
    assert not any(i.startswith("auto_topup:") for i in off)     # flag OFF: the source contributes nothing
    _flag(monkeypatch)
    items = {n["id"]: n for n in p.customer_notifications(admin, org)["notifications"]}
    mine = {i: n for i, n in items.items() if i.startswith("auto_topup:")}
    assert set(mine) == {"auto_topup:trial-preview:x", "auto_topup:pi_N1"}
    assert "1,000 credits" in mine["auto_topup:trial-preview:x"]["body"]
    assert mine["auto_topup:pi_N1"]["title"] == "Monthly top-up limit reached"
    for n in mine.values():
        assert "$" not in n["body"] and "usd" not in n["body"].lower() and n["kind"] == "billing"
    again = [i for i in (n["id"] for n in p.customer_notifications(admin, org)["notifications"])
             if i.startswith("auto_topup:")]
    assert sorted(again) == sorted(mine)                        # stable ids: each receipt once, never duplicated
    stranger = p.customer_notifications("cust_stranger0000000000001", org)["notifications"]
    assert not any(n["id"].startswith("auto_topup:") for n in stranger)   # a non-member sees no tenant's receipts


# ---- over the REAL edge → cockpit hop -------------------------------------------------------------------------------
def _signup(op, ep, email):
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    return _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]


def test_auto_top_up_settings_over_the_edge(tmp_path, monkeypatch):
    _flag(monkeypatch)
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        conf = _signup(op, ep, "a1@acme.io")
        c, d = _get(op, ep, _ROUTE)
        assert c == 200 and d["settings"] is None and d["card_saved"] is False, (c, d)
        body = {"enabled": True, "trigger_credits": 300, "pack_price_id": _PACK, "monthly_cap_credits": 4000,
                "org_id": "org_someone_else"}                    # a body org is ignored: the session org is armed
        c, r = _post(op, ep, "/api/customer/billing/auto-topup", body)
        assert c == 200 and r["trigger_credits"] == 300, (c, r)
        c, d = _get(op, ep, _ROUTE)
        assert d["settings"]["monthly_cap_credits"] == 4000 and d["settings"]["enabled"] is True
        s = AutoTopUpRegistry(sov.store(), owner_key=None).settings(conf["org_id"])
        assert s is not None and s.trigger_credits == 300
        assert AutoTopUpRegistry(sov.store(), owner_key=None).settings("org_someone_else") is None
        c, r = _post(op, ep, "/api/customer/billing/auto-topup", {**body, "trigger_credits": "lots"})
        assert c in (400, 403) and AutoTopUpRegistry(sov.store(), owner_key=None).settings(
            conf["org_id"]).trigger_credits == 300
        assert _get(_opener(), ep, _ROUTE)[0] == 401                 # no session -> nothing
        assert _post(_opener(), ep, "/api/customer/billing/auto-topup", body)[0] == 401
    finally:
        sov.shutdown(); edge.shutdown()


def test_auto_top_up_routes_are_404_while_the_flag_is_off(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "a1off@acme.io")
        assert _get(op, ep, _ROUTE)[0] == 404
        body = {"enabled": True, "trigger_credits": 300, "pack_price_id": _PACK, "monthly_cap_credits": 4000}
        assert _post(op, ep, "/api/customer/billing/auto-topup", body)[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()
