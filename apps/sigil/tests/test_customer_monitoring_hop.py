"""C4 — the server behind the Monitoring screen, over the REAL edge -> cockpit hop, and the server side of AEGIS plans
on Billing.

* With VIGIL_CUSTOMER_MONITORING_ENABLED off, GET api/customer/monitoring, GET .../monitoring/events and POST
  monitoring/authorize|revoke answer exactly as an unknown route (404), and nothing is published.
* The founder turns monitoring on for a host the workspace proved, sees it in the list — with the verified hosts and
  the AEGIS plan, which the server tells only someone who may manage monitoring — sees the event the REAL drain
  recorded, and turns it off. An org_admin may do the same. A viewer, analyst or operator reads the list and the
  events, is told can_manage=false, never gets the hosts or the plan, and every change is refused. One workspace never
  sees or changes another's: a body org_id is ignored, the other workspace's host cannot be turned on, and its
  "revoke" is a no-op on the caller's own workspace.
* With step-up enforced, turning monitoring on answers 401 {step_up_required: true} and grants nothing.
* The manager-only fields: the hosts with a CURRENT proof only (never a pending or expired one, never a challenge
  token, never another workspace's), and the plan exactly as the catalog defines it (host slots + respond + period
  end; no price), or none — a credit plan is never mistaken for an AEGIS plan.
* Billing: an AEGIS plan never hides or blocks a credit plan (the offers read and checkout), checkout still sells no
  AEGIS plan (the billing drain does not mint that line), and the app's buy list shows exactly the plans checkout
  accepts.

Mutation-verify targets (each neuter reds a NAMED test here):
  * can_manage forced true / the hosts or the plan sent to a read-only role
                                     -> test_viewer_analyst_and_operator_read_but_cannot_change_monitoring
                                     -> test_only_a_manager_is_told_the_verified_hosts_and_the_plan
  * the hosts not filtered to a current proof  -> test_only_a_manager_is_told_the_verified_hosts_and_the_plan
  * the plan not the catalog's / a lapsed plan reported -> test_the_plan_is_the_catalogs_own_or_none
  * the edge page flag or the route flag ignored -> test_with_the_flag_off_every_monitoring_route_is_an_unknown_route
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import time

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _get_raw, _opener, _post, _stack

_PW = "customer-pw-123"
_seq = itertools.count(1)


def _iss() -> float:
    """A fresh, strictly increasing owner-record time (each owner-signed record must be above its high-water)."""
    return time.time() + next(_seq) * 1e-3


@pytest.fixture(autouse=True)
def _mon_env(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    monkeypatch.setenv("VIGIL_MONITORING_PUBLISH_DIR", str(tmp_path / "published"))
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    for k in ("VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "VIGIL_TRIAL_PREVIEW_ENABLED",
              "VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_BILLING_RETURN_URL",
              "VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_FLW_SECRET_KEY", "VIGIL_BILLING_PLAN_ALARM"):
        monkeypatch.delenv(k, raising=False)


def _signup(op, ep, email: str, org: str) -> dict:
    tok = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    c, r = _post(op, ep, "/api/customer/signup/confirm", {"token": tok, "password": _PW, "org_name": org})
    assert c == 200, (c, r)
    return r


def _prove(store, org: str, host: str) -> None:
    """The workspace proves control of `host` (the owner-side record the asset flow writes)."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=_iss())
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=time.time(),
                          ttl_seconds=90 * 86400.0)


def _aegis_plan(store, org: str, plan_id: str = "aegis_respond_5h") -> None:
    """The workspace holds an AEGIS plan (the owner-signed monitoring line a paid period mints)."""
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    t = time.time()
    MonitoringSubscriptionRegistry(store).subscribe(org, plan_id, 0, period_start=t - 60.0,
                                                    period_end=t + 30 * 86400.0, issued_at=_iss())


def _teammate(sov, ep, org: str, email: str, role: str):
    """A teammate of `org` holding `role` (granted by the owner, the way an Operator is), signed in to `org`."""
    from sigil.governor.orgs import OrgRegistry
    m = _signup(_opener(), ep, email, "Own " + role)
    reg = OrgRegistry(sov.store())
    reg.grant_membership(org, m["username"], role, issued_at=_iss())
    reg.revoke_org(m["org_id"])                       # so the next sign-in binds `org`, the teammate's only workspace
    op = _opener()
    c, r = _post(op, ep, "/api/customer/login", {"email": email, "password": _PW})
    assert c == 200 and r["active_org"] == org, (c, r)
    return op


def _drain_event(store, spool, org: str, host: str, report_id: str) -> None:
    """One gateway report for (org, host), sealed with that pair's report secret and drained by the REAL drain."""
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    from sigil.inbound import monitoring_spool as ms
    secret = b"r" * 32
    w = ms.MonitoringSpoolWatcher(store, spool_dir=str(spool), authority=MonitoringAuthorityRegistry(store, owner_key=None),
                                  secret_for=lambda o, h: secret if (o, h) == (org, host) else None)
    rep = {"schema": ms.REPORT_SCHEMA, "org_id": org, "host": host, "ts": time.time() - 5.0, "decision": "confirmed",
           "attack_class": "sqli", "action": "block", "confidence": 0.97, "provenance_tier": "grounded",
           "certificate_sha256": "c" * 64, "report_id": report_id}
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(secret, ms.REPORT_DOMAIN + body.encode(), hashlib.sha256).hexdigest()
    (w.incoming / f"{report_id}.json").write_text(json.dumps({"schema": ms.REPORT_SCHEMA, "body": body, "mac": mac}))
    assert w.drain()["recorded"] == 1


def _grants(op, ep) -> list:
    c, d = _get(op, ep, "/api/customer/monitoring")
    assert c == 200, (c, d)
    return [(g["host"], g["mode"], g["active"]) for g in d["grants"]]


# --- over the real hop --------------------------------------------------------------------------------------------------
def test_with_the_flag_off_every_monitoring_route_is_an_unknown_route(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown_get = _get(op, ep, "/api/customer/no-such-read")
        unknown_post = _post(op, ep, "/api/customer/no/such", {"host": "acme.example"})
        assert unknown_get[0] == 404 and unknown_post[0] == 404
        for path in ("/api/customer/monitoring", "/api/customer/monitoring/events"):
            assert _get(op, ep, path) == unknown_get, path
        for action in ("monitoring/authorize", "monitoring/revoke"):
            assert _post(op, ep, "/api/customer/" + action, {"host": "acme.example", "mode": "observe"}) == unknown_post
        assert not (tmp_path / "published").exists()                    # nothing was ever published
        page = _get_raw(ep, "/")[2].decode()
        assert 'data-monitoring="0"' in page and "__VIGIL_MONITORING__" not in page
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_founder_turns_monitoring_on_sees_its_events_and_turns_it_off(tmp_path, monkeypatch):
    from sigil.governor.orgs import OrgRegistry
    monkeypatch.setenv("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "1")
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")              # the founder role needs the preview on
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        f = _signup(op, ep, "founder@acme.com", "Acme")
        store, org, host = sov.store(), f["org_id"], "shop.acme.example"
        assert OrgRegistry(store).membership_role(f["username"], org) == "founder"
        _prove(store, org, host)
        _aegis_plan(store, org)
        c, d = _get(op, ep, "/api/customer/monitoring")
        assert c == 200 and d["org_id"] == org and d["can_manage"] is True and d["grants"] == []
        assert [x["host"] for x in d["hosts"]] == [host] and d["hosts"][0]["expires_at"] > time.time()
        assert d["plan"]["host_slots"] == 5 and d["plan"]["respond"] is True
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "block"})
        assert c == 200 and (r["org_id"], r["host"], r["mode"]) == (org, host, "block"), (c, r)
        assert _grants(op, ep) == [(host, "block", True)]
        _drain_event(store, tmp_path / "spool", org, host, "rep-founder")
        c, ev = _get(op, ep, "/api/customer/monitoring/events")
        assert c == 200 and [(e["host"], e["decision"], e["attack_class"], e["action"]) for e in ev["events"]] == \
            [(host, "confirmed", "sqli", "block")]
        c, r = _post(op, ep, "/api/customer/monitoring/revoke", {"host": host})
        assert c == 200 and r["revoked"] is True and r["unpublished"] is True, (c, r)
        assert _grants(op, ep) == []
    finally:
        sov.shutdown(); edge.shutdown()


def test_an_org_admin_may_manage_monitoring(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")                    # the code default: an org_admin sign-up
        _prove(sov.store(), a["org_id"], "app.acme.example")
        _aegis_plan(sov.store(), a["org_id"], "aegis_observe_1h")
        c, d = _get(op, ep, "/api/customer/monitoring")
        assert d["can_manage"] is True and d["plan"] == {"host_slots": 1, "respond": False,
                                                         "period_end": d["plan"]["period_end"]}
        assert _post(op, ep, "/api/customer/monitoring/authorize", {"host": "app.acme.example"})[0] == 200
        assert _grants(op, ep) == [("app.acme.example", "observe", True)]
        # an Observe plan never turns blocking on, whatever the page asks
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": "app.acme.example", "mode": "block"})
        assert c == 403 and "respond" in r["error"], (c, r)
        assert _grants(op, ep) == [("app.acme.example", "observe", True)]
    finally:
        sov.shutdown(); edge.shutdown()


@pytest.mark.parametrize("role", ["viewer", "analyst", "operator"])
def test_viewer_analyst_and_operator_read_but_cannot_change_monitoring(tmp_path, monkeypatch, role):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop = _opener()
        a = _signup(aop, ep, "admin@acme.com", "Acme")
        org, host = a["org_id"], "shop.acme.example"
        _prove(sov.store(), org, host)
        _aegis_plan(sov.store(), org)
        assert _post(aop, ep, "/api/customer/monitoring/authorize", {"host": host})[0] == 200
        _drain_event(sov.store(), tmp_path / "spool", org, host, "rep-" + role)
        mop = _teammate(sov, ep, org, f"{role}@acme.com", role)
        c, d = _get(mop, ep, "/api/customer/monitoring")
        assert c == 200 and d == {"org_id": org, "can_manage": False,
                                  "grants": [{"host": host, "mode": "observe", "not_before": d["grants"][0]["not_before"],
                                              "not_after": d["grants"][0]["not_after"], "active": True}]}
        c, ev = _get(mop, ep, "/api/customer/monitoring/events")
        assert c == 200 and [e["report_id"] for e in ev["events"]] == ["rep-" + role]
        for action, body in (("authorize", {"host": host, "mode": "block"}), ("revoke", {"host": host})):
            c, r = _post(mop, ep, "/api/customer/monitoring/" + action, body)
            assert c == 403, (action, c, r)
        assert _grants(aop, ep) == [(host, "observe", True)]             # nothing changed
    finally:
        sov.shutdown(); edge.shutdown()


def test_one_workspace_never_sees_or_changes_another(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, bop = _opener(), _opener()
        a, b = _signup(aop, ep, "a@acme.com", "Acme"), _signup(bop, ep, "b@beta.com", "Beta")
        store = sov.store()
        for org, host in ((a["org_id"], "shop.acme.example"), (b["org_id"], "www.beta.example")):
            _prove(store, org, host)
            _aegis_plan(store, org)
        assert _post(aop, ep, "/api/customer/monitoring/authorize", {"host": "shop.acme.example"})[0] == 200
        _drain_event(store, tmp_path / "spool", a["org_id"], "shop.acme.example", "rep-a")
        c, d = _get(bop, ep, "/api/customer/monitoring?org_id=" + a["org_id"])
        assert c == 200 and d["org_id"] == b["org_id"] and d["grants"] == []
        assert [x["host"] for x in d["hosts"]] == ["www.beta.example"]
        c, ev = _get(bop, ep, "/api/customer/monitoring/events")
        assert c == 200 and ev["events"] == [] and "rep-a" not in json.dumps(ev)
        # a body org_id is ignored: B cannot turn on A's host (B holds no proof of it) nor turn A's monitoring off
        c, r = _post(bop, ep, "/api/customer/monitoring/authorize",
                     {"host": "shop.acme.example", "mode": "observe", "org_id": a["org_id"]})
        assert c == 403 and "ownership" in r["error"], (c, r)
        c, r = _post(bop, ep, "/api/customer/monitoring/revoke", {"host": "shop.acme.example", "org_id": a["org_id"]})
        assert c == 200 and r["org_id"] == b["org_id"] and r["revoked"] is False, (c, r)
        assert _grants(aop, ep) == [("shop.acme.example", "observe", True)]
        assert [e["report_id"] for e in _get(aop, ep, "/api/customer/monitoring/events")[1]["events"]] == ["rep-a"]
    finally:
        sov.shutdown(); edge.shutdown()


def test_turning_monitoring_on_asks_for_a_fresh_second_factor(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        _prove(sov.store(), a["org_id"], "shop.acme.example")
        _aegis_plan(sov.store(), a["org_id"])
        c, r = _post(op, ep, "/api/customer/monitoring/authorize", {"host": "shop.acme.example", "mode": "observe"})
        assert c == 401 and r.get("step_up_required") is True, (c, r)    # the shape the screen answers honestly
        assert _grants(op, ep) == []
        assert _post(op, ep, "/api/customer/monitoring/revoke", {"host": "shop.acme.example"})[0] == 200  # never asks
    finally:
        sov.shutdown(); edge.shutdown()


# --- the list's manager-only fields (the provisioner) ------------------------------------------------------------------
def test_only_a_manager_is_told_the_verified_hosts_and_the_plan():
    from test_provision_monitoring import _prov, _prove as _prove_small, _seat, _subscribe

    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    _seat(orgs, "org_a", "fred", "founder")
    for role in ("viewer", "analyst", "operator"):
        _seat(orgs, "org_a", role + "_u", role)
    _prove_small(s, "org_a", "apme.cm")                                 # a current proof
    own = AssetOwnershipRegistry(s)
    own.issue_challenge("org_a", "pending.cm", issued_at=_iss())        # challenged, never verified
    ch = own.issue_challenge("org_a", "lapsed.cm", issued_at=_iss())
    own.verify_and_record("org_a", "lapsed.cm", method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0,
                          ttl_seconds=5.0)                                # verified once, expired long ago
    _subscribe(s, "org_a", "aegis_respond_5h")
    _seat(orgs, "org_b", "bob", "org_admin")
    _prove_small(s, "org_b", "beta.cm")                                  # another workspace's proof
    for manager in ("alice", "fred"):
        d = p.monitor_list(manager, "org_a", now=1e6)
        assert d["can_manage"] is True and d["grants"] == []
        assert [sorted(x) for x in d["hosts"]] == [["expires_at", "host"]] and d["hosts"][0]["host"] == "apme.cm"
        assert d["plan"] == {"host_slots": 5, "respond": True, "period_end": 1e12}
        blob = json.dumps(d)
        assert "pending.cm" not in blob and "lapsed.cm" not in blob and "beta.cm" not in blob
        assert "marker" not in blob and "vigil-site-verification" not in blob and "amount" not in blob
    p.monitor_authorize("alice", "org_a", "apme.cm", now=1e6)
    for role in ("viewer", "analyst", "operator"):
        d = p.monitor_list(role + "_u", "org_a", now=1e6 + 1)
        assert set(d) == {"org_id", "grants", "can_manage"} and d["can_manage"] is False, role
        assert [g["host"] for g in d["grants"]] == ["apme.cm"], role


def test_the_plan_is_the_catalogs_own_or_none():
    from test_provision_monitoring import _prov, _seat, _subscribe

    from sigil.governor.subscription import SubscriptionRegistry
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    assert p.monitor_list("alice", "org_a", now=1e6)["plan"] is None                       # no AEGIS plan
    SubscriptionRegistry(s).subscribe("org_a", "pro", 6000, period_start=0.0, period_end=1e12, issued_at=_iss())
    assert p.monitor_list("alice", "org_a", now=1e6)["plan"] is None                       # a CREDIT plan is not one
    _subscribe(s, "org_a", "aegis_observe_1h", period_end=2e6)
    assert p.monitor_list("alice", "org_a", now=1e6)["plan"] == {"host_slots": 1, "respond": False, "period_end": 2e6}
    assert p.monitor_list("alice", "org_a", now=3e6)["plan"] is None                       # its period has ended


def test_a_plan_the_catalog_no_longer_defines_is_reported_as_none(monkeypatch):
    """Fail closed: a monitoring subscription whose plan the catalog does not (or no longer) define buys nothing, so
    the screen is told there is no plan (and the server's own turn-on gate refuses it the same way)."""
    from test_provision_monitoring import _prov, _seat, _subscribe

    from sigil.governor import catalog
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    _subscribe(s, "org_a", "aegis_respond_5h")
    monkeypatch.setattr(catalog, "monitoring_plan", lambda plan_id: None)
    assert p.monitor_list("alice", "org_a", now=1e6)["plan"] is None


# --- Billing: one plan kind never blocks the other ------------------------------------------------------------------------
def _plans_provisioner(monkeypatch):
    from test_customer_checkout import _provisioner, _real_provider

    from sigil.governor.identity import ensure_owner_keypair
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")
    ensure_owner_keypair()
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    return p, admin, org, posted


def test_an_aegis_plan_never_hides_or_blocks_a_credit_plan(monkeypatch):
    from sigil.governor import catalog
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    p, admin, org, posted = _plans_provisioner(monkeypatch)
    MonitoringSubscriptionRegistry(p.store).subscribe(org, "aegis_respond_5h", 0, period_start=0.0, period_end=1e12,
                                                      issued_at=50.0)
    d = p.customer_billing_offers(admin, org, now=5000.0)
    assert d["has_active_plan"] is False and d["plan_checkout_pending"] is False
    plans = [o["price_id"] for o in d["offers"] if o["kind"] == "subscription_active"]
    assert "vigil_pro_monthly" in plans
    assert not {o["price_id"] for o in d["offers"]} & catalog.monitoring_price_ids()     # AEGIS: not sold here yet
    r = p.billing_checkout(admin, org, "vigil_pro_monthly", now=5000.0)
    assert r["price_id"] == "vigil_pro_monthly" and posted[-1]["payment_plan"] == "vigil_pro_monthly"


def test_the_app_and_checkout_agree_on_which_plans_can_be_bought(monkeypatch):
    """The server's real offers payload, run through the app's own buy list (node): every plan the app shows,
    checkout accepts; every plan it hides, checkout refuses for the second-plan rule — for a workspace holding an
    AEGIS plan (credit plans stay on offer) and one holding a credit plan (only top-ups)."""
    from test_customer_monitoring_screen import _buy

    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.ui.provision import ProvisionDenied
    pa, admin_a, org_a, posted_a = _plans_provisioner(monkeypatch)
    MonitoringSubscriptionRegistry(pa.store).subscribe(org_a, "aegis_observe_1h", 0, period_start=0.0,
                                                       period_end=1e12, issued_at=50.0)
    pc, admin_c, org_c, posted_c = _plans_provisioner(monkeypatch)
    SubscriptionRegistry(pc.store).subscribe(org_c, "research", 2000, period_start=0.0, period_end=1e12,
                                             issued_at=50.0)
    offers_a = pa.customer_billing_offers(admin_a, org_a, now=5000.0)
    offers_c = pc.customer_billing_offers(admin_c, org_c, now=5000.0)
    shown = _buy({"aegis": offers_a, "credit": offers_c})
    name = {o["name"]: o for o in offers_a["offers"]}
    assert shown["aegis"] == [o["name"] for o in offers_a["offers"]]     # every offer, credit plans included
    assert shown["credit"] == [o["name"] for o in offers_c["offers"] if o["kind"] == "topup_purchased"]
    plan = next(name[n]["price_id"] for n in shown["aegis"] if name[n]["kind"] == "subscription_active")
    assert pa.billing_checkout(admin_a, org_a, plan, now=5000.0)["price_id"] == plan
    for o in offers_c["offers"]:
        if o["name"] in shown["credit"]:
            assert pc.billing_checkout(admin_c, org_c, o["price_id"], now=5000.0)["price_id"] == o["price_id"]
        else:
            with pytest.raises(ProvisionDenied, match="already has a plan"):
                pc.billing_checkout(admin_c, org_c, o["price_id"], now=5000.0)
