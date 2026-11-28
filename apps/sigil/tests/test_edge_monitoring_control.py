"""AS-27b — the DEFENSE-CONTROL view read over the REAL edge -> cockpit hop.

The control read (GET api/customer/monitoring/control) returns, for each host the SESSION org's manager can
act on, the AS-27b core evaluator's READ-ONLY grade — whether AEGIS is enforcing live blocking (Respond)
right now and whether an authorized STAND-DOWN (the safe-direction return to observe) would have any effect —
computed from the SAME already-gated monitoring state ``monitor_list`` / ``monitor_preview`` read. It is
READ-ONLY: nothing is minted, armed or stood down; a real stand-down stays behind the owner-signed gate. This
pins the contract end to end:

* A manager with an armed Observe host sees it NOT enforcing (nothing to stand down); RELEASING it to enforce
  (block) flips its control row to ``enforcing`` with a stand-down available — the safe-direction mirror of
  the AS-4b preview (which flips the same host to ``already_enforcing``).
* ``can_manage`` (manage_monitoring) gates the host rows; a read-only role (viewer / analyst / operator) is
  told ``can_manage: False`` and gets NO controls — the hosts and the plan never cross to it.
* ``can_manage_defense`` (manage_defense) is DISTINCT from ``can_manage``: a billing-only org_admin may manage
  monitoring yet NOT operate the live defense (defense-authz != billing-authz), so it sees the rows but
  ``can_manage_defense: False``; a founder (with the founder kill-switch on) sees ``can_manage_defense: True``.
* The org is the SESSION's, never a body field (a body org_id cannot aim the view at another workspace), and
  one workspace never sees another's hosts (no cross-tenant leak) — the x_ct isolation.
* With VIGIL_CUSTOMER_MONITORING_ENABLED off, the control read is an unknown route (404), byte-identical to
  every other monitoring route.
"""
from __future__ import annotations

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_hop import (  # noqa: F401  (_mon_env autouse)
    _aegis_plan,
    _iss,
    _mon_env,
    _prove,
    _signup,
    _teammate,
)


def _control(op, ep) -> dict:
    c, d = _get(op, ep, "/api/customer/monitoring/control")
    assert c == 200, (c, d)
    return d


def _crow(d: dict, host: str) -> dict:
    for r in d["controls"]:
        if r["host"] == host:
            return r
    raise AssertionError(f"no control row for {host} in {[r['host'] for r in d['controls']]}")


def test_a_release_to_enforce_flips_the_control_row_to_enforcing_with_a_standdown(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org = a["org_id"]
        store = sov.store()
        _prove(store, org, "armed.acme.example")
        _prove(store, org, "proven.acme.example")                   # proven but never armed
        _aegis_plan(store, org)                                      # aegis_respond_5h: Respond entitled
        assert _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": "armed.acme.example", "mode": "observe"})[0] == 200
        d = _control(op, ep)
        assert d["org_id"] == org and d["can_manage"] is True
        # a billing-only admin manages monitoring but does NOT operate the live defense (founder kill-switch off)
        assert d["can_manage_defense"] is False
        armed = _crow(d, "armed.acme.example")                       # armed in Observe => not enforcing, nothing to stand down
        assert armed["enforcing"] is False and armed["standdown_available"] is False
        assert armed["standdown_blockers"] == ["not_enforcing"]
        proven = _crow(d, "proven.acme.example")                     # proven but unarmed => not enforcing
        assert proven["enforcing"] is False and proven["standdown_available"] is False
        # RELEASE the armed host to enforce (block) — the control row flips to enforcing, a stand-down now applies
        assert _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": "armed.acme.example", "mode": "block"})[0] == 200
        after = _crow(_control(op, ep), "armed.acme.example")
        assert after["enforcing"] is True and after["mode"] == "block"
        assert after["standdown_available"] is True and after["standdown_blockers"] == []
    finally:
        sov.shutdown(); edge.shutdown()


def test_an_observe_only_plan_host_is_never_enforcing(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org = a["org_id"]
        _prove(sov.store(), org, "app.acme.example")
        _aegis_plan(sov.store(), org, "aegis_observe_1h")           # Observe-only: Respond NOT entitled
        assert _post(op, ep, "/api/customer/monitoring/authorize", {"host": "app.acme.example"})[0] == 200
        row = _crow(_control(op, ep), "app.acme.example")
        assert row["respond_entitled"] is False
        assert row["enforcing"] is False and row["standdown_available"] is False
        assert row["standdown_blockers"] == ["not_enforcing"]
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_founder_may_operate_the_live_defense_but_an_admin_may_not(tmp_path, monkeypatch):
    # can_manage_defense (manage_defense) is DISTINCT from can_manage (manage_monitoring). The founder kill-switch
    # must be ON for a founder membership to keep its testing-domain role; with it on, a founder operates the live
    # defense and a billing admin does not — defense-authz != billing-authz.
    monkeypatch.setenv("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop = _opener()
        a = _signup(aop, ep, "admin@acme.com", "Acme")              # trial-preview off => org_admin (billing only)
        org = a["org_id"]
        _prove(sov.store(), org, "shop.acme.example")
        _aegis_plan(sov.store(), org)
        assert _post(aop, ep, "/api/customer/monitoring/authorize", {"host": "shop.acme.example"})[0] == 200
        # the billing admin sees the rows but may NOT operate the live defense
        d_admin = _control(aop, ep)
        assert d_admin["can_manage"] is True and d_admin["can_manage_defense"] is False
        assert [r["host"] for r in d_admin["controls"]] == ["shop.acme.example"]
        # a founder teammate (kill-switch on) sees the rows AND may operate the live defense
        fop = _teammate(sov, ep, org, "founder@acme.com", "founder")
        d_founder = _control(fop, ep)
        assert d_founder["can_manage"] is True and d_founder["can_manage_defense"] is True
        assert [r["host"] for r in d_founder["controls"]] == ["shop.acme.example"]
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_read_only_role_is_told_it_cannot_manage_and_gets_no_rows(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop = _opener()
        a = _signup(aop, ep, "admin@acme.com", "Acme")
        org, host = a["org_id"], "shop.acme.example"
        _prove(sov.store(), org, host)
        _aegis_plan(sov.store(), org)
        assert _post(aop, ep, "/api/customer/monitoring/authorize", {"host": host})[0] == 200
        for role in ("viewer", "analyst", "operator"):
            mop = _teammate(sov, ep, org, f"{role}@acme.com", role)
            d = _control(mop, ep)
            # the hosts and the plan are manager-only — a read-only role gets can_manage=false and NO rows, and a
            # read-only role never operates the defense either (can_manage_defense false)
            assert d == {"org_id": org, "can_manage": False, "can_manage_defense": False, "controls": []}, role
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_control_view_is_scoped_to_the_session_org_and_leaks_no_other_tenant(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, bop = _opener(), _opener()
        a = _signup(aop, ep, "a@acme.com", "Acme")
        b = _signup(bop, ep, "b@beta.com", "Beta")
        store = sov.store()
        for org, host in ((a["org_id"], "shop.acme.example"), (b["org_id"], "www.beta.example")):
            _prove(store, org, host)
            _aegis_plan(store, org)
            op = aop if org == a["org_id"] else bop
            assert _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": "observe"})[0] == 200
        # B's control only ever shows B's own host — a body org_id aimed at A is ignored (org comes from B's session).
        import json
        c, d = _get(bop, ep, "/api/customer/monitoring/control?org_id=" + a["org_id"])
        assert c == 200 and d["org_id"] == b["org_id"]
        assert [r["host"] for r in d["controls"]] == ["www.beta.example"]
        assert "shop.acme.example" not in json.dumps(d)             # A's host never crosses into B's control view
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_flag_off_the_control_read_is_an_unknown_route(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _get(op, ep, "/api/customer/no-such-read")
        assert unknown[0] == 404
        assert _get(op, ep, "/api/customer/monitoring/control") == unknown     # byte-identical to any unknown route
    finally:
        sov.shutdown(); edge.shutdown()
