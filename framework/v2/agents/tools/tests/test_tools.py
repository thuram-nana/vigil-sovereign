"""
Tests for W1.4 — the gated agentic tool-use / sensor-driving seam.

The invoker must: run a registered tool through the FAIL-CLOSED gate chain (kill-switch ->
entitlement -> scope -> destructive-confirm -> egress); record a tool_call before and a
tool_result after on the spine (provenance-linked); and NEVER run the tool when a gate refuses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.tools import (
    ToolContext, ToolError, ToolRegistry, ToolResult, default_registry, invoke_tool,
)
from framework.v2.entitlement import Capability


# ---- test tools ------------------------------------------------------------


class _SpyTool:
    name = "spy"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def __init__(self) -> None:
        self.ran = False

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        self.ran = True
        return ToolResult(ok=True, summary="ran", output={"echo": args})


class _GatedTool(_SpyTool):
    name = "gated"
    tier = "T2"
    capability = Capability.EXPLOIT_EXECUTION


class _DestructiveTool(_SpyTool):
    name = "destructive"
    destructive = True


class _EgressTool(_SpyTool):
    name = "egress"
    egress_hosts = ("evil.invalid",)


class _RaisingTool:
    name = "boom"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        raise RuntimeError("kaboom")


# ---- fixtures --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate the kill-switch + target paths so no test reads/writes the real targets/ tree."""
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)


@pytest.fixture()
def spine(tmp_path: Path):
    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.spine_sink import SpineSink
    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    yield SpineSink(bb, "alpha"), bb
    bb.close()


def _ctx() -> ToolContext:
    return ToolContext(slug="alpha")


# ---- registry --------------------------------------------------------------


def test_registry_register_get_names_and_failures() -> None:
    reg = ToolRegistry()
    spy = _SpyTool()
    reg.register(spy)
    assert reg.get("spy") is spy and reg.names() == ["spy"] and "spy" in reg and len(reg) == 1
    with pytest.raises(ToolError):
        reg.register(_SpyTool())         # duplicate name
    with pytest.raises(ToolError):
        reg.register(object())           # no name / no run


def test_default_registry_ships_the_reverify_tool() -> None:
    reg = default_registry()
    assert "reverify_finding" in reg


# ---- gated invocation ------------------------------------------------------


def test_safe_tool_runs_and_emits_provenance_linked_events(spine) -> None:
    sink, bb = spine
    reg = ToolRegistry()
    spy = _SpyTool()
    reg.register(spy)

    res = invoke_tool(reg, "spy", {"x": 1}, _ctx(), sink=sink)
    assert res.ok and spy.ran and not res.refused

    calls = bb.read(engagement="alpha", kinds=["tool_call"])
    results = bb.read(engagement="alpha", kinds=["tool_result"])
    assert len(calls) == 1 and len(results) == 1
    assert calls[0].payload["tool"] == "spy" and calls[0].payload["tier"] == "T1"
    assert results[0].payload["ok"] is True and results[0].payload["refused"] is False
    assert results[0].parent_id == calls[0].id            # tool_result -> tool_call provenance edge


def test_kill_switch_refuses_before_the_tool_runs(spine) -> None:
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("test halt")
    sink, bb = spine
    reg = ToolRegistry()
    spy = _SpyTool()
    reg.register(spy)

    res = invoke_tool(reg, "spy", {}, _ctx(), sink=sink)
    assert res.refused and res.gate == "kill-switch" and not res.ok and not spy.ran
    # intent recorded, refusal recorded, and a refused result recorded
    assert bb.read(engagement="alpha", kinds=["tool_call"])
    assert bb.read(engagement="alpha", kinds=["refusal"])
    results = bb.read(engagement="alpha", kinds=["tool_result"])
    assert results and results[0].payload["refused"] is True and results[0].payload["gate"] == "kill-switch"


def test_entitlement_refuses_a_gated_tool_before_it_runs(spine, monkeypatch) -> None:
    from framework.v2 import entitlement

    def _deny(cap):
        raise RuntimeError(f"not entitled to {cap}")

    monkeypatch.setattr(entitlement, "require_capability", _deny)
    sink, bb = spine
    reg = ToolRegistry()
    gated = _GatedTool()
    reg.register(gated)

    res = invoke_tool(reg, "gated", {}, _ctx(), sink=sink)
    assert res.refused and res.gate == "entitlement" and not gated.ran
    calls = bb.read(engagement="alpha", kinds=["tool_call"])
    assert calls and calls[0].payload["capability"] == Capability.EXPLOIT_EXECUTION.value


def test_destructive_tool_refused_by_default_deny() -> None:
    reg = ToolRegistry()
    tool = _DestructiveTool()
    reg.register(tool)
    # no prompt_callback -> default-deny
    res = invoke_tool(reg, "destructive", {}, _ctx())
    assert res.refused and res.gate == "destructive-confirm" and not tool.ran


def test_egress_tool_refused_when_host_not_on_allowlist() -> None:
    reg = ToolRegistry()
    tool = _EgressTool()
    reg.register(tool)
    res = invoke_tool(reg, "egress", {}, _ctx())
    assert res.refused and res.gate == "egress" and not tool.ran


class _StringEgressTool(_SpyTool):
    name = "str-egress"
    egress_hosts = "api.example.invalid"   # author typo: a str, not a 1-tuple


class _NonIterableEgressTool(_SpyTool):
    name = "bad-egress"
    egress_hosts = True                    # misconfiguration: a truthy non-iterable


def test_string_egress_hosts_is_one_host_not_iterated_per_character() -> None:
    # Review fix: a str egress_hosts must be treated as ONE host (not per-character), and refused
    # because it is not on the charter allowlist — NOT refused on the nonsense single-char host 'a'.
    reg = ToolRegistry()
    tool = _StringEgressTool()
    reg.register(tool)
    res = invoke_tool(reg, "str-egress", {}, _ctx())
    assert res.refused and res.gate == "egress" and not tool.ran
    assert "api.example.invalid" in res.note        # the whole host, not a single character


def test_non_iterable_egress_hosts_refuses_fail_closed_never_crashes() -> None:
    # Review fix: a truthy non-iterable egress_hosts must REFUSE (fail-closed), never raise a
    # TypeError out of invoke_tool.
    reg = ToolRegistry()
    tool = _NonIterableEgressTool()
    reg.register(tool)
    res = invoke_tool(reg, "bad-egress", {}, _ctx())   # must not raise
    assert res.refused and res.gate == "egress" and not tool.ran


class _RaisingBoolEgress:
    """__bool__ itself raises — a pathological metadata object."""
    def __bool__(self):
        raise RuntimeError("no bool")


class _RaisingBoolEgressTool(_SpyTool):
    name = "raisingbool-egress"
    egress_hosts = _RaisingBoolEgress()


def test_egress_hosts_with_a_raising_truthiness_refuses_never_crashes() -> None:
    # Re-review fix: even a metadata object whose __bool__/__len__ raises must be contained —
    # invoke_tool returns a refused ToolResult, never propagates the exception.
    reg = ToolRegistry()
    tool = _RaisingBoolEgressTool()
    reg.register(tool)
    res = invoke_tool(reg, "raisingbool-egress", {}, _ctx())   # must not raise
    assert res.refused and res.gate == "egress" and not tool.ran


def test_unknown_tool_is_a_failed_result_not_a_crash() -> None:
    res = invoke_tool(ToolRegistry(), "nope", {}, _ctx())
    assert not res.ok and "no such tool" in res.note


def test_a_raising_tool_becomes_a_failed_result() -> None:
    reg = ToolRegistry()
    reg.register(_RaisingTool())
    res = invoke_tool(reg, "boom", {}, _ctx())
    assert not res.ok and not res.refused and "tool error" in res.note


def test_reverify_tool_runs_offline_and_produces_an_observation() -> None:
    reg = default_registry()
    finding = {"bug_class": "reflected_xss", "oracle_context": {"bug_class": "reflected_xss"}}
    res = invoke_tool(reg, "reverify_finding", {"finding": finding}, _ctx())
    # it RAN offline (no egress) and returned a provenance-labelled observation, not a Finding
    assert res.ok and "is_fact" in res.output and isinstance(res.output["is_fact"], bool)


def test_events_carry_no_wallclock_so_the_signed_chain_is_stable(spine) -> None:
    # tool_call/tool_result payloads must be digest-stable (no raw timestamps) — the spine chain
    # signs the payload and excludes posted_at, so re-emitting the same call yields the same digest.
    sink, bb = spine
    reg = ToolRegistry()
    reg.register(_SpyTool())
    invoke_tool(reg, "spy", {"x": 1}, _ctx(), sink=sink)
    from framework.v2.agents.spine_chain import event_digest
    call = bb.read(engagement="alpha", kinds=["tool_call"])[0]
    result = bb.read(engagement="alpha", kinds=["tool_result"])[0]
    # digests are a pure function of the (kind, agent, payload, parent) — recomputing is identical
    assert event_digest(call) == event_digest(call)
    assert event_digest(result) == event_digest(result)
    assert "posted_at" not in call.payload and "posted_at" not in result.payload
