"""engage --resume (W2b): continue a prior run from its last SIGNED checkpoint instead of starting fresh.

Proven here:
  * resume seeds the loop from the checkpointed iteration and the monotonic seq at head_seq+1 (no seq
    collides an already-persisted turn), and the report reflects TOTAL progress (prior facts/leads);
  * a fresh run (the default) ignores the rebuild seam entirely;
  * resuming a COMPLETED run is a no-op — the OODA loop never re-executes;
  * head_seq + rebuild off a real spine file are chain-contiguous across a fresh binder (the actual
    crash/restart path) and honour the engagement filter.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_core import generate_keypair
from vigil_integration.agent.state import ActionType, AgentState, Finding, LLMDecision, ToolCall
from vigil_integration.live.engine import EngineSeams, VigilEngine
from vigil_integration.live.spine_vigilcore import VigilCoreSpine
from vigil_integration.live.think_claude import ReplayThinker

TARGET = "http://127.0.0.1:18080/"


def _attest_allow(**kw):
    return SimpleNamespace(allowed=True, reason="attested",
                           attestation=SimpleNamespace(record_hash="att-" + "a" * 60))


def _complete():
    return LLMDecision(action=ActionType.COMPLETE, summary="done")


def _use_tool():
    return LLMDecision(action=ActionType.USE_TOOL,
                       tool=ToolCall(tool_name="nmap", tool_args={"target": TARGET}))


def _prior_state(iteration: int = 3) -> AgentState:
    st = AgentState(engagement_slug="loopback", iteration=iteration, objective="own the box")
    st.record_lead(Finding(ref="l-xss", bug_class="xss", title="reflected xss?", severity="medium",
                           source="zap"))
    return st


def _engine(seams: EngineSeams, **kw) -> VigilEngine:
    return VigilEngine(slug="loopback", seams=seams, max_iterations=kw.pop("max_iterations", 6), **kw)


def test_resume_continues_from_the_checkpointed_iteration_and_carries_progress():
    prior = _prior_state(iteration=3)
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: prior, head_seq=lambda: 7)
    rep = _engine(seams).engage(TARGET, resume=True)
    assert rep.resumed is True
    # a COMPLETE-first run from iteration 4 (prior.iteration+1) reports iterations == 5 — NOT 1 (fresh).
    assert rep.iterations == 5
    assert any(ld.ref == "l-xss" for ld in rep.leads)   # the report reflects total progress


def test_fresh_start_ignores_the_rebuild_seam():
    prior = _prior_state(iteration=3)
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: prior, head_seq=lambda: 7)
    rep = _engine(seams).engage(TARGET)                  # resume defaults False
    assert rep.resumed is False
    assert rep.iterations == 1                           # started at iteration 0
    assert not rep.leads                                 # no prior state carried in


def test_resume_of_a_completed_run_is_a_noop():
    prior = _prior_state(iteration=1)
    prior.done = True
    ran = {"tool": False}

    def _run_tool(tool, phase, seq, **kw):
        ran["tool"] = True
        return SimpleNamespace(ran=True, outcome="ran", stdout="x", stderr="", tool=tool.tool_name,
                               tier="A1", target="127.0.0.1", destructive=False,
                               record=SimpleNamespace(record_id="r1"))

    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_use_tool()]),
                        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
                        run_tool=_run_tool, rebuild=lambda: prior, head_seq=lambda: 3)
    rep = _engine(seams).engage(TARGET, resume=True)
    assert rep.resumed is True
    assert rep.done is True
    assert not rep.tool_calls                            # the OODA loop never ran on a completed run
    assert ran["tool"] is False


def test_resume_with_no_prior_state_degrades_to_a_fresh_start():
    # an empty spine → rebuild() returns a fresh AgentState → resume is a clean fresh start, never a crash.
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: AgentState(), head_seq=lambda: 0)
    rep = _engine(seams).engage(TARGET, resume=True)
    assert rep.resumed is False
    assert rep.iterations == 1


def test_resume_survives_a_rebuild_seam_that_raises():
    def _boom():
        raise RuntimeError("spine unreadable")
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=_boom, head_seq=lambda: 0)
    rep = _engine(seams).engage(TARGET, resume=True)     # must not crash
    assert rep.refused is False
    assert rep.iterations == 1                           # degraded to a fresh start


# --- head_seq + rebuild off a REAL spine file (the actual crash/restart path) -----------------------
def test_head_seq_and_rebuild_are_chain_contiguous_across_a_fresh_binder(tmp_path):
    kp = generate_keypair()
    path = str(tmp_path / "eng.spine")
    s1 = VigilCoreSpine(kp, path)
    for i in (1, 2, 3):
        s1.write_state(AgentState(engagement_slug="e", iteration=i), seq=i, engagement="e")
    # a FRESH binder on the SAME file — pure disk read, nothing cached (the restart path)
    s2 = VigilCoreSpine(kp, path)
    assert s2.head_seq(engagement="e") == 3
    assert s2.rebuild(engagement="e").iteration == 3
    # continue the SAME chain at head_seq+1 — contiguous, and a third binder sees it
    s2.write_state(AgentState(engagement_slug="e", iteration=4), seq=4, engagement="e")
    s3 = VigilCoreSpine(kp, path)
    assert s3.head_seq(engagement="e") == 4
    assert s3.rebuild(engagement="e").iteration == 4
    assert s3.head_seq(engagement="other") == 0          # engagement filter: an unrelated slug has no head


def test_head_seq_is_zero_on_an_empty_spine(tmp_path):
    s = VigilCoreSpine(generate_keypair(), str(tmp_path / "empty.spine"))
    assert s.head_seq() == 0
