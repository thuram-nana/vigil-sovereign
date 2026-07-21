"""
test_engine — WS-2 unified engine (live/engine.py).

Proves the sovereign invariants of the OODA loop with INJECTED seams (no live infra):
  * attestation-first: no attestation seam (mandatory) OR a denied attestation ⇒ the whole engagement
    is REFUSED with an empty run (deep-core rule: no attestation → no run);
  * the oracle — not the LLM — mints facts: a think step that CLAIMS exploit_succeeded produces a LEAD,
    never a FACT, unless the injected oracle re-fires and returns a signed evidence ref;
  * the gate authorizes actions: an out-of-scope / gate-denied tool call is refused (and no gate wired
    ⇒ every tool call is denied), while the loop PIVOTS instead of giving up;
  * a phase escalation NEVER auto-runs on the LLM's word — it stays queued until a signed operator
    approval is supplied;
  * totality: a raising think / executor is a pause / deny, never a crash;
  * the Detection Mirror pairs each run with its dual (fact/lead) certs.
"""

from __future__ import annotations

from types import SimpleNamespace

from vigil_integration.agent.state import (
    ActionType,
    LLMDecision,
    OutputAnalysis,
    Phase,
    ToolCall,
)
from vigil_integration.live.engine import EngineSeams, VigilEngine
from vigil_integration.live.think_claude import ReplayThinker

TARGET = "http://127.0.0.1:18080/"


# --- fake seams ------------------------------------------------------------------------------------


def _allow_gate(tool_name, target, destructive):
    return SimpleNamespace(allowed=True, outcome="allow", reason="in scope (loopback)")


def _deny_gate(tool_name, target, destructive):
    return SimpleNamespace(allowed=False, outcome="deny", reason="out of scope (fail-closed)")


def _ran_result(*, stdout="RAW TOOL OUTPUT", tool="nmap", tier="A1"):
    return SimpleNamespace(ran=True, outcome="ran", stdout=stdout, stderr="", tool=tool, tier=tier,
                           target="127.0.0.1:18080", destructive=False,
                           record=SimpleNamespace(record_id="exec-rec-1"))


def _run_tool_ok(tool, phase, seq):
    return _ran_result(tool=tool.tool_name)


def _attest_allow(**kw):
    return SimpleNamespace(allowed=True, reason="attested",
                           attestation=SimpleNamespace(record_hash="att-" + "a" * 60))


def _attest_deny(**kw):
    return SimpleNamespace(allowed=False, reason="unbound operator (fail-closed)", attestation=None)


def _use_tool(*, exploit=None, tool="nmap"):
    return LLMDecision(
        action=ActionType.USE_TOOL,
        tool=ToolCall(tool_name=tool, tool_args={"target": TARGET}),
        output_analysis=OutputAnalysis(exploit_succeeded=exploit,
                                       findings=[{"title": "candidate", "bug_class": "sqli"}]),
    )


def _complete():
    return LLMDecision(action=ActionType.COMPLETE, summary="done")


def _engine(seams: EngineSeams, **kw) -> VigilEngine:
    return VigilEngine(slug="loopback", seams=seams, max_iterations=kw.pop("max_iterations", 6), **kw)


# --- attestation-first -----------------------------------------------------------------------------


def test_no_attestation_seam_refuses_the_whole_engagement():
    eng = _engine(EngineSeams(think=ReplayThinker([_use_tool()]), gate=_allow_gate,
                              run_tool=_run_tool_ok))  # attest=None, require_attestation defaults True
    rep = eng.engage(TARGET)
    assert rep.refused is True
    assert "no attestation" in rep.refusal_reason.lower()
    assert rep.iterations == 0 and not rep.tool_calls and not rep.facts


def test_denied_attestation_refuses_the_whole_engagement():
    eng = _engine(EngineSeams(attest=_attest_deny, think=ReplayThinker([_use_tool()]),
                              gate=_allow_gate, run_tool=_run_tool_ok))
    rep = eng.engage(TARGET)
    assert rep.refused is True
    assert "attestation denied" in rep.refusal_reason.lower()
    assert rep.iterations == 0


def test_attestation_error_refuses_fail_closed():
    def boom(**kw):
        raise RuntimeError("hsm offline")

    eng = _engine(EngineSeams(attest=boom, think=ReplayThinker([_complete()])))
    rep = eng.engage(TARGET)
    assert rep.refused is True and "fail-closed" in rep.refusal_reason.lower()


def test_attestation_allows_and_records_the_ref():
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()])))
    rep = eng.engage(TARGET)
    assert rep.refused is False
    assert rep.attestation_ref.startswith("att-")


# --- the oracle, not the LLM, mints facts ----------------------------------------------------------


def test_llm_exploit_claim_is_a_lead_without_the_oracle():
    # think CLAIMS exploit_succeeded=True but NO oracle is wired ⇒ it can never be a fact.
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_use_tool(exploit=True)]),
                              gate=_allow_gate, run_tool=_run_tool_ok))
    rep = eng.engage(TARGET)
    assert rep.fact_count == 0
    assert any("UNCONFIRMED" in (f.title or "") for f in rep.leads)
    # the proposed finding from output_analysis is also a lead.
    assert any(f.bug_class == "sqli" and f.status == "lead" for f in rep.leads)


def test_oracle_confirmation_mints_a_signed_fact():
    calls = {"n": 0}

    def oracle(raw_output, analysis):
        calls["n"] += 1
        assert raw_output == "RAW TOOL OUTPUT"      # the oracle re-fires over the RAW output
        return "spine:" + "d" * 60                  # a signed evidence ref ⇒ FACT

    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_use_tool(exploit=True)]),
                              gate=_allow_gate, run_tool=_run_tool_ok, oracle=oracle))
    rep = eng.engage(TARGET)
    assert calls["n"] == 1
    assert rep.fact_count == 1
    fact = rep.facts[0]
    assert fact.status == "fact" and fact.evidence_ref.startswith("spine:")


def test_oracle_silence_keeps_the_claim_a_lead():
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_use_tool(exploit=True)]),
                              gate=_allow_gate, run_tool=_run_tool_ok,
                              oracle=lambda raw, an: None))       # oracle does not fire
    rep = eng.engage(TARGET)
    assert rep.fact_count == 0
    assert any("UNCONFIRMED" in (f.title or "") for f in rep.leads)


# --- the gate authorizes actions -------------------------------------------------------------------


def test_gate_denied_tool_call_is_refused_and_the_loop_pivots():
    eng = _engine(EngineSeams(attest=_attest_allow,
                              think=ReplayThinker([_use_tool(exploit=True), _complete()]),
                              gate=_deny_gate, run_tool=_run_tool_ok,
                              oracle=lambda raw, an: "spine:x"))
    rep = eng.engage(TARGET)
    assert rep.denied_edges                        # the denied edge was recorded
    assert rep.fact_count == 0                     # nothing ran ⇒ nothing to confirm
    assert not rep.tool_calls                      # the executor was never reached
    assert rep.done is True                         # the loop pivoted to the next decision and completed


def test_no_gate_wired_denies_every_tool_call():
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_use_tool(), _complete()]),
                              run_tool=_run_tool_ok))     # gate=None
    rep = eng.engage(TARGET)
    assert rep.denied_edges and rep.fact_count == 0


# --- phase escalation needs a signed approval ------------------------------------------------------


def _transition(to=Phase.EXPLOITATION):
    return LLMDecision(action=ActionType.TRANSITION_PHASE, target_phase=to)


def test_phase_escalation_stays_queued_without_a_signed_approval():
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_transition()])))
    rep = eng.engage(TARGET)
    assert rep.paused == "awaiting_approval"
    assert rep.queued_edges
    # the phase never escalated on the LLM's word alone.


def test_phase_escalation_proceeds_only_with_a_signed_approval():
    approved = {"seen": 0}

    def approval(decision, state):
        approved["seen"] += 1
        return decision.action == ActionType.TRANSITION_PHASE      # a valid signed operator approval

    # transition, then (now in EXPLOITATION) complete.
    eng = _engine(EngineSeams(attest=_attest_allow, approval=approval,
                              think=ReplayThinker([_transition(), _complete()])))
    rep = eng.engage(TARGET)
    assert approved["seen"] >= 1
    assert rep.done is True and rep.paused == ""


# --- totality --------------------------------------------------------------------------------------


def test_executor_error_is_a_deny_not_a_crash():
    def boom(tool, phase, seq):
        raise RuntimeError("subprocess exploded")

    eng = _engine(EngineSeams(attest=_attest_allow,
                              think=ReplayThinker([_use_tool(), _complete()]),
                              gate=_allow_gate, run_tool=boom))
    rep = eng.engage(TARGET)              # must not raise
    assert rep.denied_edges and rep.done is True


def test_broken_think_pauses_never_crashes():
    class _Boom:
        def __call__(self, state):
            raise ValueError("model meltdown")

    eng = _engine(EngineSeams(attest=_attest_allow, think=_Boom()))
    rep = eng.engage(TARGET)              # must not raise
    assert rep.paused == "ask_user"


def test_ask_user_pauses_the_run():
    ask = LLMDecision(action=ActionType.ASK_USER, question="which host?")
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([ask])))
    rep = eng.engage(TARGET)
    assert rep.paused == "ask_user" and rep.done is False


# --- projection / checkpoint / detection mirror ----------------------------------------------------


def test_facts_are_projected_and_state_checkpointed():
    projected: list = []
    checkpoints: list = []

    def project(facts):
        projected.extend(facts)

    def checkpoint(state, seq):
        checkpoints.append(seq)
        return SimpleNamespace(record_hash=f"snap-{seq}")

    eng = _engine(EngineSeams(attest=_attest_allow,
                              think=ReplayThinker([_use_tool(exploit=True), _complete()]),
                              gate=_allow_gate, run_tool=_run_tool_ok,
                              oracle=lambda raw, an: "spine:" + "e" * 60,
                              project=project, checkpoint=checkpoint))
    rep = eng.engage(TARGET)
    assert projected and projected[0].status == "fact"
    assert rep.checkpoints and any(c.startswith("snap-") for c in rep.checkpoints)


def test_detection_mirror_counts_dual_certs():
    def detect():
        return [SimpleNamespace(is_fact=True), SimpleNamespace(is_fact=True),
                SimpleNamespace(is_fact=False)]

    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]), detect=detect))
    rep = eng.engage(TARGET)
    assert rep.detection_facts == 2 and rep.detection_leads == 1


def test_a_governor_is_advisory_only_never_gates_truth():
    # even a governor that "denies" everything cannot suppress an oracle-confirmed fact.
    def govern(state):
        return SimpleNamespace(tier="halt", allowed=False)

    eng = _engine(EngineSeams(attest=_attest_allow,
                              think=ReplayThinker([_use_tool(exploit=True), _complete()]),
                              gate=_allow_gate, run_tool=_run_tool_ok,
                              oracle=lambda raw, an: "spine:" + "f" * 60, govern=govern))
    rep = eng.engage(TARGET)
    assert rep.fact_count == 1        # the governor did not gate the fact
