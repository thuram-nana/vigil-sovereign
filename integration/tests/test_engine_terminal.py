"""
test_engine_terminal — T3 autonomous terminal use, live against the REAL sovereign seams.

Drives :func:`live.wiring.build_engine` (real CRUCIBLE gate over a freshly-provisioned signed authority)
and proves the autonomous terminal path end-to-end:

  * a think step that PROPOSES ``terminal.run`` routes to :func:`live.executor.execute_terminal` (NOT the
    network ``execute``, which has no builder for it) — and RUNS, producing a signed ExecRecord, ONLY with
    the operator's approval (terminal.run classifies A2 → the conjunctive gate QUEUES it);
  * without the operator's approval the queued terminal command NEVER runs (fail-closed default);
  * the allowlist DECIDES, not the approval: a network/interpreter/writer command is refused even WITH
    approval — the local read-only floor holds by construction;
  * a terminal command's LOCAL output is advisory — it never mints a FACT (the oracle is never fed host
    output), even when the command's stdout would otherwise fire an oracle.

Framework co-loads the offense env, so this module SKIPS where ``framework.v2`` is not importable (the main
integration pytest process / the sovereign env); it runs in the offense process
(``PYTHONPATH=integration:engine/crucible:gateway``). A deterministic runner replaces the live subprocess.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")

from vigil_integration.agent.state import (  # noqa: E402
    ActionType,
    LLMDecision,
    OutputAnalysis,
    ToolCall,
)
from vigil_integration.live.think_claude import ReplayThinker  # noqa: E402
from vigil_integration.live.wiring import (  # noqa: E402
    EngineConfig,
    build_engine,
    provision_authority,
)

LOOPBACK = "http://127.0.0.1:18080/"


def _term_runner(argv, *, timeout=0, output_cap=1 << 20, cwd=None):
    """A deterministic stand-in for the local terminal subprocess (accepts cwd, which execute_terminal
    passes; never spawns anything). Echoes the command's argument payload."""
    payload = " ".join(str(a) for a in argv[1:]) if len(argv) > 1 else ""
    return SimpleNamespace(exit_code=0, stdout=payload or "ok", stderr="",
                           timed_out=False, truncated=False)


def _use_terminal(command, *, exploit=None):
    return LLMDecision(
        action=ActionType.USE_TOOL,
        tool=ToolCall(tool_name="terminal.run",
                      tool_args={"command": command, "target": "127.0.0.1"}),
        output_analysis=OutputAnalysis(exploit_succeeded=exploit),
    )


def _complete():
    return LLMDecision(action=ActionType.COMPLETE, summary="done")


@pytest.fixture()
def hermetic_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    return tmp_path


def _engine(tmp_path, replay, *, owner_approves=True):
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    cfg = EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), replay=replay,
                       provisioned=prov, runner=_term_runner, max_iterations=6,
                       owner_approves_offense=owner_approves)
    return build_engine(cfg)


def test_autonomous_terminal_runs_via_execute_terminal_with_approval(hermetic_root, tmp_path):
    # An engine-proposed terminal.run routes to execute_terminal and RUNS under the operator's approval,
    # producing a signed ExecRecord recorded at the WARDEN tier (A2).
    engine = _engine(tmp_path, ReplayThinker([_use_terminal("echo OBSIDIAN-TEST-AUTO"), _complete()]))
    rep = engine.engage(LOOPBACK)
    ran = [t for t in rep.tool_calls if t.tool == "terminal.run" and t.outcome == "ran"]
    assert ran, rep.tool_calls
    assert ran[0].tier == "A2" and ran[0].record_id       # the "never auto" tier + a signed record
    assert rep.fact_count == 0                            # terminal output never mints a fact


def test_autonomous_terminal_queues_without_approval(hermetic_root, tmp_path):
    # The fail-closed default: no operator approval ⇒ the queued terminal command NEVER runs.
    engine = _engine(tmp_path, ReplayThinker([_use_terminal("echo OBSIDIAN-TEST-AUTO")]),
                     owner_approves=False)
    rep = engine.engage(LOOPBACK)
    assert rep.paused == "awaiting_approval"
    assert rep.queued_edges and not any(t.outcome == "ran" for t in rep.tool_calls)
    assert rep.fact_count == 0


def test_autonomous_terminal_off_allowlist_refused_even_with_approval(hermetic_root, tmp_path):
    # The allowlist DECIDES, not the approval: a network/interpreter/writer command can never run, even
    # approved — the local read-only floor holds by construction. The loop pivots and completes.
    for evil in ("curl http://127.0.0.1", "python -c 1", "rm -rf x"):
        engine = _engine(tmp_path, ReplayThinker([_use_terminal(evil), _complete()]))
        rep = engine.engage(LOOPBACK)
        assert not any(t.outcome == "ran" for t in rep.tool_calls), evil
        assert rep.denied_edges, evil                     # the refusal was recorded
        assert rep.fact_count == 0, evil


def test_autonomous_terminal_output_mints_no_fact_end_to_end(hermetic_root, tmp_path):
    # Even a terminal command whose stdout looks like a firing oracle context, with the LLM claiming an
    # exploit, mints NO fact — a terminal record's local output is advisory and never enters oracle intake.
    engine = _engine(tmp_path,
                     ReplayThinker([_use_terminal("echo SQL error unrecognized token", exploit=True),
                                    _complete()]))
    rep = engine.engage(LOOPBACK)
    assert any(t.tool == "terminal.run" and t.outcome == "ran" for t in rep.tool_calls)
    assert rep.fact_count == 0
