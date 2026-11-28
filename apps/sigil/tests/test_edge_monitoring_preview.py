"""AS-4b — the PROTECTION PREVIEW read over the REAL edge -> cockpit hop.

The preview read (GET api/customer/monitoring/preview) returns, for each host the SESSION org's manager can
act on, the AS-4b core evaluator's READ-ONLY grade — what AEGIS does now (observe) and what releasing it to
enforce would add — computed from the SAME already-gated monitoring state ``monitor_list`` reads (the active
grants, the hosts whose ownership proof is current, and whether the plan entitles Respond). It is READ-ONLY:
nothing is minted, armed or released; the actual Release stays behind AS-29's gate. This pins the contract
end to end:

* A Respond-plan manager with an armed Observe host (proof current) gets a releasable preview for it, with
  what enforce would ADD; a proven-but-unarmed host is previewed too, with the "not armed" blocker; releasing
  a host to enforce (AS-29) flips its preview to ``enforcing`` with the ``already_enforcing`` blocker.
* An Observe-only plan previews its armed host with the ``respond_not_in_plan`` blocker — enforce is never
  offered, exactly as AS-29's release gate refuses it.
* The org is the SESSION's, never a body field (a body org_id cannot aim the preview at another workspace),
  and one workspace never sees another's hosts in its preview (no cross-tenant leak).
* A read-only role (viewer / analyst / operator) is told ``can_manage: False`` and gets NO previews — the
  hosts and the plan never cross to it.
* With VIGIL_CUSTOMER_MONITORING_ENABLED off, the preview read is an unknown route (404), byte-identical to
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


def _preview(op, ep) -> dict:
    c, d = _get(op, ep, "/api/customer/monitoring/preview")
    assert c == 200, (c, d)
    return d


def _row(d: dict, host: str) -> dict:
    for r in d["previews"]:
        if r["host"] == host:
            return r
    raise AssertionError(f"no preview row for {host} in {[r['host'] for r in d['previews']]}")


def test_a_respond_manager_sees_each_host_graded_and_a_release_flips_its_preview(tmp_path, monkeypatch):
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
        d = _preview(op, ep)
        assert d["org_id"] == org and d["can_manage"] is True
        armed = _row(d, "armed.acme.example")
        assert armed["headline"] == "observing" and armed["enforce_permitted"] is True and armed["enforce_blockers"] == []
        # the grade is DERIVED from the baseline provider registry, not hard-coded
        assert armed["observe_outcomes"] == ["detected_without_enforcement"]   # armed => detection is LIVE now
        assert armed["observe_adds_outcomes"] == []                 # armed => nothing is only "would be detected"
        assert armed["enforce_adds_outcomes"] == ["prevented_before_execution", "response_withheld_after_execution"]
        assert "websocket" in armed["not_observed"]                 # the honest coverage limitation is surfaced
        proven = _row(d, "proven.acme.example")                     # proven but unarmed => inactive, not-armed blocker
        assert proven["headline"] == "inactive" and proven["enforce_permitted"] is False
        assert proven["enforce_blockers"] == ["not_armed"]
        # RED-PEN AS-4b: a proven-but-unmonitored host claims NO live detection — "now" is empty; the detection
        # arming WOULD make live is carried as a preview-only "would be detected once monitoring is armed".
        assert proven["observe_outcomes"] == []                     # no live-detection over-claim on an unmonitored host
        assert proven["observe_adds_outcomes"] == ["detected_without_enforcement"]
        # RELEASE the armed host to enforce (AS-29) — the preview flips to enforcing / already-enforcing (read-only view)
        assert _post(op, ep, "/api/customer/monitoring/authorize",
                     {"host": "armed.acme.example", "mode": "block"})[0] == 200
        after = _row(_preview(op, ep), "armed.acme.example")
        assert after["headline"] == "enforcing" and after["enforce_permitted"] is False
        assert after["enforce_blockers"] == ["already_enforcing"]
        assert after["observe_outcomes"] == ["detected_without_enforcement"]   # enforcing still detects live
        assert after["observe_adds_outcomes"] == []
    finally:
        sov.shutdown(); edge.shutdown()


def test_an_observe_only_plan_previews_the_respond_blocker(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        a = _signup(op, ep, "admin@acme.com", "Acme")
        org = a["org_id"]
        _prove(sov.store(), org, "app.acme.example")
        _aegis_plan(sov.store(), org, "aegis_observe_1h")           # Observe-only: Respond NOT entitled
        assert _post(op, ep, "/api/customer/monitoring/authorize", {"host": "app.acme.example"})[0] == 200
        row = _row(_preview(op, ep), "app.acme.example")
        assert row["headline"] == "observing" and row["respond_entitled"] is False
        assert row["enforce_permitted"] is False and row["enforce_blockers"] == ["respond_not_in_plan"]
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_preview_is_scoped_to_the_session_org_and_leaks_no_other_tenant(tmp_path, monkeypatch):
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
        # B's preview only ever shows B's own host — a body org_id aimed at A is ignored (org comes from B's session).
        import json
        c, d = _get(bop, ep, "/api/customer/monitoring/preview?org_id=" + a["org_id"])
        assert c == 200 and d["org_id"] == b["org_id"]
        assert [r["host"] for r in d["previews"]] == ["www.beta.example"]
        assert "shop.acme.example" not in json.dumps(d)             # A's host never crosses into B's preview
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
            d = _preview(mop, ep)
            # the hosts and the plan are manager-only — a read-only role is told can_manage=false and gets NO rows
            assert d == {"org_id": org, "can_manage": False, "previews": []}, role
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_flag_off_the_preview_read_is_an_unknown_route(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _get(op, ep, "/api/customer/no-such-read")
        assert unknown[0] == 404
        assert _get(op, ep, "/api/customer/monitoring/preview") == unknown     # byte-identical to any unknown route
    finally:
        sov.shutdown(); edge.shutdown()
