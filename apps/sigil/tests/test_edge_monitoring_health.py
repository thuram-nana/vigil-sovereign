"""AS-3d — HOST HEALTH + ACKNOWLEDGE's read contract, over the REAL edge -> cockpit hop.

AS-3d's Host health section and per-viewer acknowledge are built ENTIRELY over the two reads the Monitoring screen
already makes — GET api/customer/monitoring (the armed grants + the verified hosts) and GET
api/customer/monitoring/events (the gateway-reported attacks). It adds NO route and NO write. So the defensive contract
AS-3d's HONESTY depends on is that those reads are STRICTLY SESSION-ORG-SCOPED: a cross-tenant leak would put another
workspace's attacks into this one's health view, or let this workspace acknowledge an attack report_id it was never
shown. AS-2k/AS-21a/AS-29 exercised the monitoring/authorize WRITE; this pins the monitor_events READ end to end for the
first time on this chain:

* Each workspace's drained monitoring events are scoped to its SESSION org: org A sees only A's events (with the
  fields the health + acknowledge view needs — ts, host, decision, report_id), and NEVER B's event or report_id, and
  B never sees A's.
* A workspace that has armed nothing sees an EMPTY events list and empty grants — never another tenant's events (no
  global scan leaks into the health view).
* The armed grants the health badge stands on are likewise session-scoped: A's monitoring list carries only A's host.
* With VIGIL_CUSTOMER_MONITORING_ENABLED off, both reads are unknown routes (404), so the Host health section has no
  data route at all — byte-identical to every other monitoring route (AS-2f/AS-2g/AS-2k/AS-21a/AS-29).
"""
from __future__ import annotations

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_hop import (  # noqa: F401  (_mon_env autouse)
    _aegis_plan,
    _drain_event,
    _iss,
    _mon_env,
    _prove,
    _signup,
)


def _arm(op, ep, store, spool, org: str, host: str, rid: str, mode: str = "observe") -> None:
    """Prove the host, give the workspace an AEGIS plan, arm monitoring, and drain ONE gateway report for it."""
    _prove(store, org, host)
    _aegis_plan(store, org)
    assert _post(op, ep, "/api/customer/monitoring/authorize", {"host": host, "mode": mode})[0] == 200
    _drain_event(store, spool, org, host, rid)


def _events(op, ep) -> list:
    c, d = _get(op, ep, "/api/customer/monitoring/events")
    assert c == 200, (c, d)
    return d["events"]


def test_each_workspaces_health_events_are_scoped_to_its_session_org(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, bop = _opener(), _opener()
        a = _signup(aop, ep, "a@acme.com", "Acme")
        b = _signup(bop, ep, "b@beta.com", "Beta")
        store = sov.store()
        _arm(aop, ep, store, tmp_path / "spool", a["org_id"], "shop.acme.example", "rep-a")
        _arm(bop, ep, store, tmp_path / "spool", b["org_id"], "www.beta.example", "rep-b")
        # A sees ONLY A's event, carrying exactly the fields the health + acknowledge view reads.
        ea = _events(aop, ep)
        assert [e["host"] for e in ea] == ["shop.acme.example"]
        one = ea[0]
        assert one["decision"] == "confirmed" and one["report_id"] == "rep-a" and one["ts"]
        assert "www.beta.example" not in str(ea) and "rep-b" not in str(ea)     # never B's attack / report_id
        # B sees ONLY B's event — the two workspaces' health streams never cross.
        eb = _events(bop, ep)
        assert [e["host"] for e in eb] == ["www.beta.example"]
        assert "shop.acme.example" not in str(eb) and "rep-a" not in str(eb)
        # the armed grant the health badge stands on is session-scoped too: A's list carries only A's host.
        ca, da = _get(aop, ep, "/api/customer/monitoring")
        assert ca == 200 and [g["host"] for g in da["grants"]] == ["shop.acme.example"]
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_workspace_with_nothing_armed_sees_an_empty_health_view_never_another_tenants(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        aop, cop = _opener(), _opener()
        a = _signup(aop, ep, "a@acme.com", "Acme")
        _signup(cop, ep, "c@gamma.com", "Gamma")                 # Gamma arms nothing
        store = sov.store()
        _arm(aop, ep, store, tmp_path / "spool", a["org_id"], "shop.acme.example", "rep-a")
        # Gamma's health view is EMPTY — the read is session-scoped, so A's drained event never leaks in (no global scan).
        cc, dc = _get(cop, ep, "/api/customer/monitoring/events")
        assert cc == 200 and dc["events"] == []
        assert "shop.acme.example" not in str(dc) and "rep-a" not in str(dc)
        cg, dg = _get(cop, ep, "/api/customer/monitoring")
        assert cg == 200 and dg["grants"] == []
    finally:
        sov.shutdown(); edge.shutdown()


def test_with_the_flag_off_the_health_reads_are_unknown_routes(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep, "off@acme.com", "Off")
        unknown = _get(op, ep, "/api/customer/no-such-read")
        assert unknown[0] == 404
        for path in ("/api/customer/monitoring", "/api/customer/monitoring/events"):
            assert _get(op, ep, path) == unknown, path       # the health section has no data route when the flag is off
    finally:
        sov.shutdown(); edge.shutdown()
