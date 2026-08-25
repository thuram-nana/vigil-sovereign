"""B3/H10 — the engine PLAN-ONLY guarantee + the CLI guards.

``EngineConfig.plan_only`` runs exactly ONE think() (which, with a wired brain, PERSISTS the proposed chain)
then STOPS before ``authorize_edge`` (the conjunctive gate + CRUCIBLE scope) and before the executor — so it
proposes and never drives. This pins that the gate AND the executor are never even consulted under plan_only
(a decision that WOULD otherwise run a tool executes nothing), and that the CLI refuses ``--plan-only``
without ``--brain`` or without a proposal destination (fail-closed, never a silent no-op).

Framework co-loads the offense env, so this SKIPS where ``framework.v2`` is not importable (the sovereign env).
Runs in the offense process (``PYTHONPATH=integration:engine/crucible:gateway``).
"""
from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")

from vigil_integration.agent.state import (  # noqa: E402
    ActionType,
    LLMDecision,
    ToolCall,
)
from vigil_integration.live.think_claude import ReplayThinker  # noqa: E402
from vigil_integration.live.wiring import EngineConfig, build_engine, provision_authority  # noqa: E402

LOOPBACK = "http://127.0.0.1:18081/"


def _use_terminal(command: str) -> LLMDecision:
    # A decision that, WITHOUT plan_only, reaches the gate and (approved) runs — the strongest negative:
    # under plan_only it must reach NEITHER.
    return LLMDecision(action=ActionType.USE_TOOL,
                       tool=ToolCall(tool_name="terminal.run",
                                     tool_args={"command": command, "target": "127.0.0.1"}))


def _complete() -> LLMDecision:
    return LLMDecision(action=ActionType.COMPLETE, summary="done")


@pytest.fixture()
def hermetic_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    # Force the keyless-live REPLAY think path: if a key were resolvable, think() would take the cloud path
    # (and, with none valid, fail-closed to ASK_USER) — leaving the scripted decisions inert and the test
    # vacuous. Unset every key source so the ReplayThinker actually supplies each decision.
    for k in ("ANTHROPIC_API_KEY", "VIGIL_ANTHROPIC_API_KEY", "CLAUDE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def _engine(tmp_path, replay, *, plan_only: bool):
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    cfg = EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), replay=replay,
                       provisioned=prov, runner=lambda *a, **k: SimpleNamespace(
                           exit_code=0, stdout="ok", stderr="", timed_out=False, truncated=False),
                       max_iterations=6, owner_approves_offense=True, plan_only=plan_only)
    return build_engine(cfg)


def test_plan_only_stops_before_the_gate_and_the_executor(hermetic_root, tmp_path):
    engine = _engine(tmp_path, ReplayThinker([_use_terminal("echo X"), _use_terminal("echo Y")]),
                     plan_only=True)

    def _boom_gate(*a, **k):
        raise AssertionError("the gate was consulted under plan_only")

    def _boom_exec(*a, **k):
        raise AssertionError("the executor ran under plan_only")

    engine = dataclasses.replace(engine, seams=dataclasses.replace(
        engine.seams, gate=_boom_gate, run_tool=_boom_exec))
    rep = engine.engage(LOOPBACK)

    assert rep.paused == "plan-only"            # the honest terminal state
    assert rep.iterations == 1                  # exactly ONE think(), then stop
    assert rep.tool_calls == []                 # nothing ran…
    assert rep.fact_count == 0 and not rep.leads   # …and nothing was minted


def test_without_plan_only_the_same_decision_reaches_the_gate(hermetic_root, tmp_path):
    # Non-vacuity control: the SAME decision, plan_only OFF, DOES reach the gate (authorize_edge → seams.gate)
    # — so the main test's `_boom_gate` NOT firing under plan_only is meaningful, not vacuous. (The gate is on
    # the path of every USE_TOOL; plan_only returns before it.)
    engine = _engine(tmp_path, ReplayThinker([_use_terminal("echo OBSIDIAN-TEST-X"), _complete()]),
                     plan_only=False)
    reached = {"gate": False}
    _orig = engine.seams.gate

    def _spy(*a, **k):
        reached["gate"] = True
        return _orig(*a, **k)

    engine = dataclasses.replace(engine, seams=dataclasses.replace(engine.seams, gate=_spy))
    engine.engage(LOOPBACK)
    assert reached["gate"] is True


# --- CLI guards (fail-closed, not a silent no-op) --------------------------------------------------

def _engage_args(**over):
    base = dict(url="http://127.0.0.1:9/", slug="_planonly", base_dir="", scope="127.0.0.1", connect="",
                replay="", brain="", brain_objective="quick", brain_observations="",
                brain_execute_via_body=False, plan_only=False, proposal_out="", model="", backend="",
                access_log="", auth_log="", conn_log="", max_iterations=6, approve_offense=False,
                objective="", resume=False, session="")
    base.update(over)
    return SimpleNamespace(**base)


def test_cli_plan_only_requires_brain(hermetic_root, monkeypatch):
    from vigil_integration import cli
    rc = cli._cmd_engage(_engage_args(plan_only=True, brain=""))
    assert rc == 2   # --plan-only without --brain is refused


def test_cli_plan_only_requires_a_destination(hermetic_root, monkeypatch):
    from vigil_integration import cli
    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    rc = cli._cmd_engage(_engage_args(plan_only=True, brain="hexstrike", proposal_out=""))
    assert rc == 2   # --plan-only + --brain but nowhere to write the proposal is refused
