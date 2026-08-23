"""H1x-1 — the flag-gated brain EXECUTE-path convergence (``--brain-execute-via-body``, DEFAULT OFF).

This is the pre-checkpoint prefix of H1 body convergence: the PROPOSE half already flows through the ONE
canonical ``HexstrikeAgentBody`` (its ``plan`` drives every ``vigil engage --brain hexstrike`` run via the
``BrainThink`` adapter). This slice wires the EXECUTE half behind a default-OFF flag WITHOUT opening the FACT
seam:

  * flag OFF (default): BYTE-IDENTICAL to today — a gate-authorized tool runs through the live engine's
    governed executor; the body is only PLANNED through, never executed. ``fact_count == 0``.
  * flag ON: a gate-authorized NON-terminal tool executes through ``HexstrikeAgentBody.execute`` instead.
    The gate is UNCHANGED (DENY-PARITY: nuclei stays A2, offense still queues), and the FACT seam stays
    CLOSED — the body is driven with NO RunnerDeps, so it runs no tool and mints ZERO facts.
    ``fact_count == 0`` stays green even ON.

The first live FACT (nmap SERVICE_REACHABILITY — the operator's "H8f") is a SEPARATE, operator-checkpoint-
gated slice: it provisions the body's runner AND updates the FP-0 tripwire tool-by-tool. It is NOT done here.

The FP-0 tripwire (``test_brain_fact_path_tripwire.py``) stays green in BOTH flag states — it drives
``BrainThink`` directly (a PLAN-only surface), which this slice does not touch; the engine-level FP-0
(``fact_count == 0``) is additionally re-proven here for both states.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("framework")  # offense leg only — the sovereign leg lacks engine/crucible on the path

from vigil_integration.brains import hexstrike_body
from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain, ToolDanger, _TOOL_DANGER
from vigil_integration.live.wiring import (
    EngineConfig,
    build_engine,
    default_classify,
    provision_authority,
)

TARGET = "http://127.0.0.1/"  # a web target → the brain proposes nmap/httpx/katana/nuclei/gobuster/…


def _echo_runner(argv, *, timeout=0, output_cap=1 << 20):
    # A deterministic stand-in for the live Kali binaries: the full gate/oracle/spine wiring is exercised
    # without them present. (Only reached on the flag-OFF executor path; the flag-ON body path has no runner.)
    return SimpleNamespace(exit_code=0, stdout="service on 80/tcp", stderr="",
                           timed_out=False, truncated=False)


@pytest.fixture(autouse=True)
def _hermetic(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    from framework.v2.agents import blackboard as _bb
    db = tmp_path / "bb.sqlite"
    monkeypatch.setattr(_bb, "open_blackboard", lambda **_kw: _bb.Blackboard(db_path=db))


def _cfg(tmp_path, brain, *, owner_approves=True, via_body=False):
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    return EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), provisioned=prov,
                        runner=_echo_runner, max_iterations=10, owner_approves_offense=owner_approves,
                        brain=brain, brain_execute_via_body=via_body)


def _spy_body_execute(monkeypatch):
    calls = {"n": 0, "actions": []}
    orig = hexstrike_body.HexstrikeAgentBody.execute

    def _spy(self, action, decision):
        calls["n"] += 1
        calls["actions"].append(getattr(action, "kind", ""))
        return orig(self, action, decision)

    monkeypatch.setattr(hexstrike_body.HexstrikeAgentBody, "execute", _spy)
    return calls


# ---------------------------------------------------------------------------------------------------
# FLAG OFF (default) — byte-identical to today: the executor path, the body is never executed, 0 facts
# ---------------------------------------------------------------------------------------------------
def test_flag_off_uses_the_executor_never_the_body_and_mints_no_fact(tmp_path, monkeypatch):
    calls = _spy_body_execute(monkeypatch)
    brain = BrainThink(HexstrikeBrain(), target=TARGET)
    report = build_engine(_cfg(tmp_path, brain, via_body=False)).engage(TARGET)

    assert report.tool_calls, "the brain drove no tool calls"
    # today's path: gate-authorized tools RAN through the governed executor …
    assert any(getattr(t, "outcome", "") == "ran" for t in report.tool_calls), \
        "flag OFF should run tools through the governed executor (outcome 'ran')"
    # … and the body's own execute was NEVER reached (the body is only PLANNED through).
    assert calls["n"] == 0, "flag OFF must not route execution through HexstrikeAgentBody.execute"
    # FP-0 (engine level): the brain's proposals are LEADs — nothing became a FACT without the oracle.
    assert report.fact_count == 0


def test_flag_defaults_off(tmp_path):
    """The field defaults OFF — a plain --brain engage is unchanged unless the operator opts in."""
    assert EngineConfig(slug="x").brain_execute_via_body is False


# ---------------------------------------------------------------------------------------------------
# FLAG ON — execution routes through body.execute, the FACT seam stays CLOSED (0 facts), deny-parity
# ---------------------------------------------------------------------------------------------------
def test_flag_on_routes_execution_through_the_body_but_mints_no_fact(tmp_path, monkeypatch):
    calls = _spy_body_execute(monkeypatch)
    brain = BrainThink(HexstrikeBrain(), target=TARGET)
    report = build_engine(_cfg(tmp_path, brain, via_body=True)).engage(TARGET)

    assert report.tool_calls, "the brain drove no tool calls"
    # (1) execution genuinely routed through the ONE canonical body's own execute …
    assert calls["n"] >= 1, "flag ON must route gate-authorized execution through HexstrikeAgentBody.execute"
    assert calls["actions"], "the body.execute spy captured no proposed action"
    # (2) … but the FACT seam stayed CLOSED: the body has no runner, so nothing executed and no fact minted.
    assert report.fact_count == 0, "flag ON must still mint ZERO facts (fact seam stays closed pending H8f)"
    # (3) DENY-PARITY at the sink: with no runner the body returns an unexecuted LEAD → recorded as a refusal,
    #     never a 'ran'. (H8f — provisioning the runner — is what will flip a specific tool to a real FACT.)
    assert all(getattr(t, "outcome", "") != "ran" for t in report.tool_calls), \
        "the runner-less body must not report any tool as 'ran'"
    assert report.denied_edges, "a body-routed LEAD (no runner) must surface as a recorded refusal"


def test_flag_on_engine_level_fp0_holds(tmp_path, monkeypatch):
    """The engine-level FP-0 canary, flag ON: a full engage reports fact_count == 0. Paired with the
    flag-OFF proof above, this is the 'fact_count==0 in BOTH flag states' guarantee at the engine level."""
    _spy_body_execute(monkeypatch)
    for approves in (True, False):
        brain = BrainThink(HexstrikeBrain(), target=TARGET)
        report = build_engine(_cfg(tmp_path, brain, owner_approves=approves, via_body=True)).engage(TARGET)
        assert report.fact_count == 0, f"flag ON minted a fact (owner_approves={approves})"


# ---------------------------------------------------------------------------------------------------
# DENY-PARITY — the flag does NOT relax the gate: nuclei stays A2 (danger carried) in BOTH states
# ---------------------------------------------------------------------------------------------------
def test_danger_class_carried_nuclei_stays_a2_regardless_of_flag(tmp_path):
    """The brain's ACTIVE danger class is carried across the seam by BrainThink.danger_floor, which the gate
    consults independently of the execute-routing flag. nuclei is in the executor's curated recon set (base
    A1) yet is ACTIVE to the brain — the floor raises it to A2 so it can never auto-fire. This is
    flag-independent by construction (the flag touches only the post-gate execute sink)."""
    assert _TOOL_DANGER["nuclei"] is ToolDanger.ACTIVE
    assert default_classify("nuclei") == "A1", "base classifier no longer treats nuclei as recon"
    floored = BrainThink(HexstrikeBrain(), target=TARGET).danger_floor(default_classify)
    assert floored("nuclei") == "A2", "the brain's ACTIVE danger for nuclei must be carried to A2"
    # a RECON tool is untouched (nmap stays auto-eligible A1) — the floor only raises.
    assert floored("nmap") == default_classify("nmap")


def test_flag_on_offense_still_queues_never_auto_fires(tmp_path, monkeypatch):
    """DENY-PARITY end-to-end: with no standing approval, an offense tool (>= A2, e.g. nuclei) still QUEUES
    for owner approval and never runs — the flag does not relax the gate. No tool ran; no fact minted."""
    _spy_body_execute(monkeypatch)
    brain = BrainThink(HexstrikeBrain(), target=TARGET)
    report = build_engine(_cfg(tmp_path, brain, owner_approves=False, via_body=True)).engage(TARGET)
    assert all(getattr(t, "outcome", "") != "ran" for t in report.tool_calls), \
        "an offense tool auto-fired under the flag — the gate was relaxed"
    assert report.paused == "awaiting_approval" or report.queued_edges, \
        "an A2 offense tool should queue for owner approval (the gate's human leg)"
    assert report.fact_count == 0


# ---------------------------------------------------------------------------------------------------
# The routing is guarded by the flag (structural byte-identity when OFF) + fail-closed on a bad brain
# ---------------------------------------------------------------------------------------------------
def test_routing_is_flag_guarded_in_wiring():
    """Pin the guard: the body-routing branch is entered only when the flag is set AND a brain is wired, so
    the flag-OFF path is the unchanged executor path by construction."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[1].joinpath(
        "vigil_integration/live/wiring.py").read_text(encoding="utf-8")
    assert "config.brain_execute_via_body and config.brain is not None and not is_terminal" in src, \
        "the body-routing branch must be guarded by the flag + a wired brain + non-terminal"
    assert "return _run_via_body(tool)" in src


def test_body_route_fails_closed_when_the_brain_has_no_body_accessor(tmp_path, monkeypatch):
    """FAIL-CLOSED: if the flag is set but the wired 'brain' exposes no canonical body(), a gate-authorized
    tool is a recorded DENY — never executed, never a crash, never a fact."""
    calls = _spy_body_execute(monkeypatch)

    class _NoBodyBrain:
        # a propose-only ThinkFn that emits one USE_TOOL then COMPLETE, but exposes no body() accessor.
        def __init__(self):
            self._n = 0

        def __call__(self, state):
            from vigil_integration.agent.state import ActionType, LLMDecision, ToolCall
            self._n += 1
            if self._n == 1:
                return LLMDecision(action=ActionType.USE_TOOL,
                                   reasoning="no-body brain proposes one recon step",
                                   tool=ToolCall(tool_name="nmap", tool_args={"target": TARGET},
                                                 reason="recon"))
            return LLMDecision(action=ActionType.COMPLETE, summary="done")

    report = build_engine(_cfg(tmp_path, _NoBodyBrain(), via_body=True)).engage(TARGET)
    assert calls["n"] == 0, "no canonical body() → HexstrikeAgentBody.execute must not be reached"
    assert all(getattr(t, "outcome", "") != "ran" for t in report.tool_calls), \
        "a brain with no body() must not execute anything under the flag (fail-closed)"
    assert report.fact_count == 0
