"""
Tests for the CONSUME direction — mcp.client + mcp.sensor.

An external MCP tool (mocked, no real subprocess/network) becomes a GATED CRUCIBLE sensor whose output
enters the ONE world-model as a provenance-labelled OBSERVATION — a LEAD, never a fact. The gate chain
(scope / kill-switch) applies exactly as to a first-party sensor, and untrusted remote payloads can
neither plant an off-scope asset nor crash the pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolRegistry
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind
from framework.v2.mcp.client import MCPClient
from framework.v2.mcp.sensor import MCPSensor, _safe_services
from framework.v2.sensors.pipeline import run_sensor
from framework.v2.worldmodel.graph import WorldModel


_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `10.0.0.5` | Declared host | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    td = tmp_path / "alpha"
    td.mkdir(parents=True, exist_ok=True)
    (td / "charter.md").write_text(_CHARTER.format(slug="alpha"), encoding="utf-8")


# ---- a fake external MCP server (transport) --------------------------------


class _FakeServer:
    """A JSON-RPC transport standing in for an external MCP server. Records every request; returns a
    canned ``result`` (or ``error``, or a deliberately-``raw`` malformed object). No I/O whatsoever."""

    def __init__(self, *, result=None, error=None, raw=None):
        self._result = result
        self._error = error
        self._raw = raw
        self.calls: list[dict] = []

    def __call__(self, request: dict) -> dict:
        self.calls.append(request)
        if self._raw is not None:
            return self._raw
        rid = request.get("id")
        if self._error is not None:
            return {"jsonrpc": "2.0", "id": rid, "error": self._error}
        return {"jsonrpc": "2.0", "id": rid, "result": self._result or {}}


def _tool_result(services, *, is_error=False) -> dict:
    return {"content": [{"type": "text", "text": "scan done"}],
            "isError": is_error, "structuredContent": {"services": services}}


def _sensor(server: _FakeServer, **kw) -> MCPSensor:
    return MCPSensor("mcp_portscan", MCPClient(server), "portscan", **kw)


def _run(sensor: MCPSensor, world: WorldModel, args: dict, *, seq: int = 1, dry_run: bool = False):
    reg = ToolRegistry()
    reg.register(sensor)
    ingest = IntelIngest(world, engagement_slug="alpha")
    ctx = ToolContext(slug="alpha", dry_run=dry_run)
    return run_sensor(reg, sensor.name, args, ctx, ingest=ingest, seq=seq)


# ---- client ----------------------------------------------------------------


def test_client_call_tool_normalizes_a_result() -> None:
    fake = _FakeServer(result=_tool_result([{"port": 443, "protocol": "tcp"}]))
    out = MCPClient(fake).call_tool("portscan", {"host": "10.0.0.5"})
    assert out["ok"] is True and out["is_error"] is False
    assert out["structured"]["services"] == [{"port": 443, "protocol": "tcp"}]
    # the request was a well-formed JSON-RPC tools/call with a deterministic integer id
    assert fake.calls[0]["method"] == "tools/call" and fake.calls[0]["id"] == 1


def test_client_treats_a_jsonrpc_error_as_a_structured_error() -> None:
    fake = _FakeServer(error={"code": -32000, "message": "boom"})
    out = MCPClient(fake).call_tool("portscan", {})
    assert out["ok"] is False and out["is_error"] is True and out["error"]["message"] == "boom"


def test_client_handles_a_non_dict_transport_response() -> None:
    out = MCPClient(_FakeServer(raw=[1, 2, 3])).call_tool("portscan", {})
    assert out["ok"] is False and out["error"] is not None            # no crash


def test_client_ids_are_deterministic_and_monotonic() -> None:
    fake = _FakeServer(result=_tool_result([]))
    c = MCPClient(fake)
    c.call_tool("a", {})
    c.call_tool("b", {})
    assert [r["id"] for r in fake.calls] == [1, 2]                     # counter, no rng/wallclock


# ---- the sensor: a consumed tool is a GATED LEAD producer ------------------


def test_consumed_mcp_tool_becomes_a_gated_sensor_producing_leads() -> None:
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([
        {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx"}]))
    res = _run(_sensor(fake), world, {"host": "10.0.0.5"})
    assert res.ok and res.applied > 0
    assert world.has_node("host:10.0.0.5")
    assert world.has_node("service:10.0.0.5:443/tcp")
    # the observation is tagged with the MCP_TOOL provenance kind
    assert all(o.source_kind is IntelSourceKind.MCP_TOOL for o in res.observations)
    assert fake.calls and fake.calls[0]["method"] == "tools/call"


def test_consumed_output_is_a_lead_not_a_fact() -> None:
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([{"port": 443, "protocol": "tcp"}]))
    _run(_sensor(fake), world, {"host": "10.0.0.5"})
    svc = world.get_node("service:10.0.0.5:443/tcp")
    assert svc is not None
    # GROUNDING_INTEL — a lead, never oracle-proof (mirrors every other sensor)
    assert svc.provenance.startswith("intel:")


def test_out_of_scope_host_is_refused_and_mints_nothing_without_calling_out() -> None:
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([{"port": 53, "protocol": "udp"}]))
    res = _run(_sensor(fake), world, {"host": "8.8.8.8"})
    assert res.result.refused and res.result.gate == "scope"
    assert res.observations == [] and res.applied == 0
    assert not world.has_node("host:8.8.8.8")
    assert fake.calls == []                                            # the gate ran BEFORE any call-out


def test_kill_switch_refuses_the_consumed_sensor_without_calling_out() -> None:
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("test halt")
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([{"port": 443, "protocol": "tcp"}]))
    res = _run(_sensor(fake), world, {"host": "10.0.0.5"})
    assert res.result.refused and res.result.gate == "kill-switch"
    assert res.observations == [] and fake.calls == []


def test_untrusted_remote_host_claim_is_ignored_scope_tight() -> None:
    # The remote tries to attribute services to an OFF-SCOPE host (both as a per-service field and a
    # bogus port on another host). Normalization mints ONLY under the gate-validated scoped host — no
    # off-scope asset can be planted.
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([
        {"port": 443, "protocol": "tcp", "host": "evil.example.com"},
        {"port": 22, "protocol": "tcp", "subject": "domain:evil.example.com"}]))
    res = _run(_sensor(fake), world, {"host": "10.0.0.5"})
    assert res.ok
    assert world.has_node("service:10.0.0.5:443/tcp") and world.has_node("service:10.0.0.5:22/tcp")
    assert not world.has_node("domain:evil.example.com")
    assert not world.has_node("host:evil.example.com")


def test_remote_tool_error_is_a_failed_result_not_a_guess() -> None:
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([{"port": 443}], is_error=True))
    res = _run(_sensor(fake), world, {"host": "10.0.0.5"})
    assert not res.ok and res.observations == [] and res.applied == 0


def test_malformed_remote_structured_content_yields_no_leads_no_crash() -> None:
    world = WorldModel()
    # services is not a list; and a junk transport shape — the sensor must degrade, never crash
    fake = _FakeServer(result={"isError": False, "structuredContent": {"services": "not-a-list"}})
    res = _run(_sensor(fake), world, {"host": "10.0.0.5"})
    # malformed services -> zero SERVICE leads (the in-scope host itself is still honestly observed)
    assert res.ok and not world.has_node("service:10.0.0.5:443/tcp")
    assert not any(o.relation is not None for o in res.observations)   # no service/edge claims


def test_dry_run_short_circuits_the_external_call_but_still_gates() -> None:
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([{"port": 443, "protocol": "tcp"}]))
    res = _run(_sensor(fake), world, {"host": "10.0.0.5"}, dry_run=True)
    assert res.ok and fake.calls == []                # no call-out under dry-run
    assert not world.has_node("service:10.0.0.5:443/tcp")   # the scan result is short-circuited


def test_consume_is_idempotent_no_belief_inflation() -> None:
    world = WorldModel()
    fake = _FakeServer(result=_tool_result([{"port": 443, "protocol": "tcp", "product": "nginx"}]))
    sensor = _sensor(fake)
    reg = ToolRegistry()
    reg.register(sensor)
    ingest = IntelIngest(world, engagement_slug="alpha")
    ctx = ToolContext(slug="alpha")
    run_sensor(reg, sensor.name, {"host": "10.0.0.5"}, ctx, ingest=ingest, seq=1)
    mean_before = world.get_node("service:10.0.0.5:443/tcp").belief_mean
    r2 = run_sensor(reg, sensor.name, {"host": "10.0.0.5"}, ctx, ingest=ingest, seq=1)
    assert r2.applied == 0
    assert world.get_node("service:10.0.0.5:443/tcp").belief_mean == mean_before


# ---- untrusted-input sanitization -----------------------------------------


def test_safe_services_strips_unknown_fields_and_bounds_strings() -> None:
    dirty = [
        {"port": 443, "protocol": "tcp", "product": "x" * 5000, "host": "evil", "attrs": {"a": 1}},
        {"no_port": True},                       # dropped (no port)
        "not-a-dict",                            # dropped
        {"port": 80, "state": "open", "evil": "\x00drop"},
    ]
    clean = _safe_services(dirty)
    assert len(clean) == 2
    first = clean[0]
    assert set(first) <= {"port", "protocol", "state", "service", "product", "version"}
    assert "host" not in first and "attrs" not in first
    assert len(first["product"]) <= 256                       # overlong value is clipped
    assert _safe_services("not-a-list") == [] and _safe_services(None) == []
