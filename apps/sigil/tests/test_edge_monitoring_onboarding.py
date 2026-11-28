"""AS-6d — the tenant ONBOARDING-JOURNEY read over the REAL edge -> cockpit hop.

The onboarding read (GET api/customer/monitoring/onboarding) returns, for the SESSION org's manager, the
AS-6d core evaluator's READ-ONLY grade of where the workspace is on the walk from a connected (proven) host
to a monitored (observe) one — composed from the SAME already-gated monitoring state ``monitor_list`` /
``monitor_preview`` / ``monitor_control`` read (the hosts whose ownership proof is current, the active
grants, and whether the plan entitles Respond). It is READ-ONLY: nothing is minted, armed or released;
turning monitoring on stays behind the existing gated ``monitoring/authorize`` write. This pins the contract
end to end:

* An empty workspace is on step ``prove_host``; proving a host advances the current step to ``plan``; adding
  an AEGIS plan advances it to ``turn_on_observe``; turning monitoring on completes the journey (no current
  step, the explore-next views become available).
* The org is the SESSION's, never a body field (a body org_id cannot aim the read at another workspace), and
  one workspace never sees another's progress (no cross-tenant leak).
* A read-only role (viewer / analyst / operator) is told ``can_manage: False`` and gets NO journey — the
  hosts and the plan never cross to it.
* The read needs BOTH flags: with VIGIL_CUSTOMER_AEGIS_ONBOARDING off (monitoring on), and with
  VIGIL_CUSTOMER_MONITORING_ENABLED off, the read is an unknown route (404), byte-identical to any unknown
  route — the strict second gate.
"""
from __future__ import annotations

import pytest
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


@pytest.fixture(autouse=True)
def _onboarding_env(monkeypatch):
    # AS-6d's strict second gate ON by default in this module (the monitoring gate is on via _mon_env); a
    # single flag-off test deletes it to prove the route 404s.
    monkeypatch.setenv("VIGIL_CUSTOMER_AEGIS_ONBOARDING", "1")


def _onboarding(op, ep) -> dict:
    c, d = _get(op, ep, "/api/customer/monitoring/onboarding")
    assert c == 200, (c, d)
    return d


def _statuses(d: dict) -> dict:
    return {s["key"]: s["status"] for s in d["journey"]["steps"]}


def test_the_journey_walks_from_connected_host_to_monitored(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org = a["org_id"]
        store = sov.store()

        # an empty workspace: the first step (prove a host) is current, the rest to-do, nothing monitored
        d = _onboarding(op, ep)
        assert d["org_id"] == org and d["can_manage"] is True
        assert d["journey"]["complete"] is False and d["journey"]["next_step"] == "prove_host"
        assert _statuses(d) == {"prove_host": "current", "plan": "todo", "turn_on_observe": "todo"}
        assert d["journey"]["explore_available"] is False

        # prove a host -> the current step advances to the plan
        _prove(store, org, "app.acme.example")
        d = _onboarding(op, ep)
        assert d["journey"]["next_step"] == "plan" and d["journey"]["proven_host_count"] == 1
        assert _statuses(d) == {"prove_host": "done", "plan": "current", "turn_on_observe": "todo"}

        # add an AEGIS plan -> the current step advances to turning monitoring on
        _aegis_plan(store, org)
        d = _onboarding(op, ep)
        assert d["journey"]["has_plan"] is True and d["journey"]["next_step"] == "turn_on_observe"
        assert _statuses(d) == {"prove_host": "done", "plan": "done", "turn_on_observe": "current"}

        # turn monitoring on (the EXISTING gated write) -> the journey completes, explore-next opens
        assert _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": "app.acme.example", "mode": "observe"})[0] == 200
        d = _onboarding(op, ep)
        assert d["journey"]["complete"] is True and d["journey"]["next_step"] is None
        assert d["journey"]["active_host_count"] == 1 and d["journey"]["explore_available"] is True
        assert _statuses(d) == {"prove_host": "done", "plan": "done", "turn_on_observe": "done"}
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_read_is_scoped_to_the_session_org_and_leaks_no_other_tenant(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, bop = _opener(), _opener()
        a = _signup(aop, ep, "a@acme.com", "Acme")
        b = _signup(bop, ep, "b@beta.com", "Beta")
        store = sov.store()
        # A is fully monitored; B has proven nothing and holds no plan
        _prove(store, a["org_id"], "shop.acme.example")
        _aegis_plan(store, a["org_id"])
        assert _post(aop, ep, "/api/customer/monitoring/authorize",
                     {"host": "shop.acme.example", "mode": "observe"})[0] == 200
        # B's read only ever reflects B's own (empty) progress — a body org_id aimed at A is ignored (org from session)
        c, d = _get(bop, ep, "/api/customer/monitoring/onboarding?org_id=" + a["org_id"])
        assert c == 200 and d["org_id"] == b["org_id"]
        assert d["journey"]["complete"] is False and d["journey"]["next_step"] == "prove_host"
        assert d["journey"]["proven_host_count"] == 0 and d["journey"]["active_host_count"] == 0
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_read_only_role_is_told_it_cannot_manage_and_gets_no_journey(tmp_path, monkeypatch):
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
            d = _onboarding(mop, ep)
            # the hosts and the plan are manager-only — a read-only role is told can_manage=false, no journey
            assert d == {"org_id": org, "can_manage": False, "journey": None}, role
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_onboarding_flag_off_the_read_is_an_unknown_route(tmp_path, monkeypatch):
    # the monitoring master flag stays ON (via _mon_env) — only the strict AS-6d gate is off
    monkeypatch.delenv("VIGIL_CUSTOMER_AEGIS_ONBOARDING")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _get(op, ep, "/api/customer/no-such-read")
        assert unknown[0] == 404
        assert _get(op, ep, "/api/customer/monitoring/onboarding") == unknown   # byte-identical to any unknown route
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_monitoring_flag_off_the_read_is_an_unknown_route(tmp_path, monkeypatch):
    # the onboarding gate is on, but the monitoring master flag is off — the double gate still 404s
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _get(op, ep, "/api/customer/no-such-read")
        assert unknown[0] == 404
        assert _get(op, ep, "/api/customer/monitoring/onboarding") == unknown   # byte-identical to any unknown route
    finally:
        sov.shutdown(); edge.shutdown()
