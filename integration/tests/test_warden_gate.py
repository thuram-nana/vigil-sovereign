"""WARDEN tool-name gate (P7 Slice 2): the raise-only floor + auto/queue/deny outcome logic,
and the fail-safe hook adapter. Classification is injected (stub), so the core is tested without
the kernel; an optional test exercises the real sigil-kernel classifier when it's present."""

from __future__ import annotations

import asyncio
import shutil
import sys
import types

import pytest

from vigil_integration.warden_gate import (
    WardenDenied,
    WardenGateHooks,
    attach_from_env,
    compose_run_hooks,
    decide_tool,
    kernel_classifier,
)


def _stub(mapping: dict[str, str], default: str = "A3"):
    return lambda name: mapping.get(name, default)


# ---- the decision core (raise-only floor + auto/queue/deny) --------------------------------

def test_exec_command_a3_is_queued():
    d = decide_tool("exec_command", classify=_stub({"exec_command": "A3"}))
    assert d.tier == "A3" and d.outcome == "queue"


def test_read_shaped_name_is_floored_up_and_queued_on_live_posture():
    # http.get classifies A0 (contains the A0 verb 'get'); the A2 floor raises it -> queue.
    d = decide_tool("http.get", classify=_stub({"http.get": "A0"}))
    assert d.tier == "A2" and d.outcome == "queue"


def test_staging_posture_lets_recon_auto_run():
    # On a TWIN/STAGING target the operator lowers the floor to A1: a read tool then auto-runs...
    d = decide_tool("http.get", classify=_stub({"http.get": "A0"}), floor="A1", ceiling="A1")
    assert d.tier == "A1" and d.outcome == "auto"
    # ...but a destructive/exec tool is still A3 -> queue even at the lowered floor.
    d2 = decide_tool("exec_command", classify=_stub({"exec_command": "A3"}), floor="A1", ceiling="A1")
    assert d2.tier == "A3" and d2.outcome == "queue"


def test_floor_only_raises_never_lowers():
    # a tool the kernel already puts at A3 stays A3 even with an A2 floor (max, not set).
    d = decide_tool("delete_bucket", classify=_stub({"delete_bucket": "A3"}), floor="A2")
    assert d.tier == "A3"


def test_empty_and_denylist_and_garbage_fail_closed():
    assert decide_tool("", classify=_stub({})).outcome == "deny"
    assert decide_tool("x", classify=_stub({"x": "A0"}), denylist=["x"]).outcome == "deny"
    # classifier returns an unknown tier string -> treated as A3
    d = decide_tool("weird", classify=_stub({"weird": "ZZ"}))
    assert d.tier == "A3" and d.outcome == "queue"


def test_bad_floor_string_fails_closed_to_a3():
    d = decide_tool("http.get", classify=_stub({"http.get": "A0"}), floor="nonsense")
    assert d.tier == "A3"


# ---- the fail-safe hook adapter -------------------------------------------------------------

class _FakeTool:
    def __init__(self, name):
        self.name = name


def test_hook_raises_on_non_auto_and_records_decisions():
    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3", "http.get": "A0"}))
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))
    with pytest.raises(WardenDenied):  # http.get floored to A2 -> queue -> blocked (fail-safe)
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("http.get")))
    assert [d.tool for d in hooks.decisions] == ["exec_command", "http.get"]
    assert all(not d.auto for d in hooks.decisions)


def test_hook_allows_an_auto_decision():
    # staging posture: a read tool auto-runs -> on_tool_start does NOT raise
    hooks = WardenGateHooks(classify=_stub({"http.get": "A0"}), floor="A1", ceiling="A1")
    asyncio.run(hooks.on_tool_start(None, None, _FakeTool("http.get")))  # no raise
    assert hooks.decisions[-1].auto


def test_hook_unnamed_tool_fails_closed():
    hooks = WardenGateHooks(classify=_stub({}))
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("")))  # empty name -> deny


# ---- optional: the REAL kernel classifier (skips if the binary isn't built) ----------------

@pytest.mark.skipif(shutil.which("sigil-kernel") is None, reason="sigil-kernel binary not on PATH")
def test_real_kernel_classifies_exec_high_and_read_low():
    classify = kernel_classifier()
    assert classify("exec_command") == "A3"          # exec is an A3 token
    assert classify("http.get") in ("A0", "A1")      # read-verb -> low (that's why we floor)
    # and the gate floors the low one up to queue
    assert decide_tool("http.get", classify=classify).outcome == "queue"


def test_unresolved_kernel_fails_closed_without_bare_name_exec(monkeypatch):
    # PATH-plant hardening: with no explicit kernel_bin and none on PATH, the classifier must fail-closed
    # to A3 WITHOUT exec'ing a bare 'sigil-kernel' (which would resolve an attacker-planted PATH binary).
    import vigil_integration.warden_gate as wg
    monkeypatch.setattr(wg.shutil, "which", lambda _n: None)   # nothing on PATH
    monkeypatch.setattr(wg.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not exec a bare name")))
    classify = kernel_classifier()                              # kernel_bin=None, unresolved
    assert classify("exec_command") == "A3"                    # fail-closed, no subprocess


# ---- T3: the Strix runner soft-wire (compose_run_hooks + env-gated attach_from_env) --------------
#
# The openai-agents SDK is not vendored on disk, so a MINIMAL fake ``agents.lifecycle.RunHooks`` is
# injected to exercise the composite; ``live.wiring`` is faked too so these tests never pull the offense
# engine / framework (they run in the framework-free first CI invocation).


def _install_fake_agents(monkeypatch):
    """Inject a minimal ``agents.lifecycle.RunHooks`` base (async no-op lifecycle methods) so
    ``compose_run_hooks`` — which lazily subclasses it — can be exercised without the real SDK."""
    agents = types.ModuleType("agents")
    lifecycle = types.ModuleType("agents.lifecycle")

    class RunHooks:
        async def on_agent_start(self, *a, **k): ...
        async def on_agent_end(self, *a, **k): ...
        async def on_handoff(self, *a, **k): ...
        async def on_tool_start(self, *a, **k): ...
        async def on_tool_end(self, *a, **k): ...
        async def on_llm_start(self, *a, **k): ...
        async def on_llm_end(self, *a, **k): ...

    lifecycle.RunHooks = RunHooks
    agents.lifecycle = lifecycle
    monkeypatch.setitem(sys.modules, "agents", agents)
    monkeypatch.setitem(sys.modules, "agents.lifecycle", lifecycle)


def _install_fake_wiring(monkeypatch, mapping):
    """Inject a fake ``vigil_integration.live.wiring`` exposing ``default_classify`` so
    ``attach_from_env`` composes without importing the real (framework-touching) live engine."""
    w = types.ModuleType("vigil_integration.live.wiring")
    w.default_classify = lambda name: mapping.get(name, "A2")
    monkeypatch.setitem(sys.modules, "vigil_integration.live.wiring", w)


def test_compose_fans_out_and_warden_blocks_the_shell(monkeypatch):
    _install_fake_agents(monkeypatch)
    accounting: list = []

    class _Base:
        async def on_llm_end(self, *a, **k):
            accounting.append(("llm_end", a))

    warden = WardenGateHooks(classify=_stub({"exec_command": "A3", "http.get": "A0"}))
    comp = compose_run_hooks(_Base(), warden)

    # on_llm_end fans out to the base accounting (the existing ReportUsageHooks role)
    asyncio.run(comp.on_llm_end("ctx", "agent", "resp"))
    assert accounting == [("llm_end", ("ctx", "agent", "resp"))]

    # on_tool_start: the WARDEN gate BLOCKS the arbitrary shell (A3 → non-auto → raise)
    with pytest.raises(WardenDenied):
        asyncio.run(comp.on_tool_start("ctx", "agent", _FakeTool("exec_command")))
    assert warden.decisions[-1].tool == "exec_command" and not warden.decisions[-1].auto


def test_compose_allows_an_auto_tool(monkeypatch):
    _install_fake_agents(monkeypatch)
    # staging posture: a read tool at A1 auto-runs → the composite does NOT raise
    warden = WardenGateHooks(classify=_stub({"http.get": "A0"}), floor="A1", ceiling="A1")
    comp = compose_run_hooks(warden)
    asyncio.run(comp.on_tool_start("c", "a", _FakeTool("http.get")))   # no raise
    assert warden.decisions[-1].auto


def test_attach_from_env_is_noop_when_not_opted_in(monkeypatch):
    # Absent the opt-in env var, attach_from_env returns the base hooks UNCHANGED (byte-identical Strix).
    monkeypatch.delenv("VIGIL_WARDEN_STRIX_GATE", raising=False)
    base = object()
    assert attach_from_env(base) is base


def test_attach_from_env_opted_in_composes_and_blocks(monkeypatch):
    _install_fake_agents(monkeypatch)
    _install_fake_wiring(monkeypatch, {"exec_command": "A3", "http.get": "A0"})
    monkeypatch.setenv("VIGIL_WARDEN_STRIX_GATE", "1")

    class _Base:
        async def on_llm_end(self, *a, **k): ...

    base = _Base()
    composed = attach_from_env(base)
    assert composed is not base                       # a composite was attached
    with pytest.raises(WardenDenied):                 # and it gates Strix's arbitrary shell
        asyncio.run(composed.on_tool_start("c", "a", _FakeTool("exec_command")))


def test_attach_from_env_fails_safe_to_base_when_wiring_broken(monkeypatch):
    # Opted in but the composition raises (SDK/classifier unavailable) → return the base hooks (a wiring
    # error must NEVER stop a scan). Here the fake agents module is deliberately NOT installed, so the
    # lazy `from agents.lifecycle import RunHooks` inside compose_run_hooks fails.
    monkeypatch.delitem(sys.modules, "agents", raising=False)
    monkeypatch.delitem(sys.modules, "agents.lifecycle", raising=False)
    _install_fake_wiring(monkeypatch, {"exec_command": "A3"})
    monkeypatch.setenv("VIGIL_WARDEN_STRIX_GATE", "1")
    base = object()
    assert attach_from_env(base) is base
