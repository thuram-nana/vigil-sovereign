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


# --- autonomous terminal output is ADVISORY: it never reaches the oracle, never mints a fact ---------


def _use_terminal(*, command="cat /etc/hostname"):
    # An autonomous terminal.run proposal that ALSO claims an exploit + a finding — the loop must ignore
    # BOTH for a terminal command (its host output is not target-produced evidence).
    return LLMDecision(
        action=ActionType.USE_TOOL,
        tool=ToolCall(tool_name="terminal.run", tool_args={"command": command, "target": TARGET}),
        output_analysis=OutputAnalysis(exploit_succeeded=True,
                                       findings=[{"title": "candidate", "bug_class": "sqli"}]),
    )


def _run_tool_terminal(tool, phase, seq):
    # A terminal ExecResult whose LOCAL output looks exactly like a firing oracle context — it must still
    # never be handed to the oracle.
    return SimpleNamespace(ran=True, outcome="ran", stdout="SQL error: unrecognized token near 'x'",
                           stderr="", tool="terminal.run", tier="A2", target="local",
                           destructive=False, record=SimpleNamespace(record_id="term-rec-1"))


def test_terminal_output_is_advisory_and_never_mints_a_fact():
    # Even a terminal command whose stdout WOULD fire the oracle, with the LLM claiming exploit_succeeded,
    # mints NEITHER a fact NOR a lead — the oracle is never called on host output. The signed call IS recorded.
    calls = {"n": 0}

    def oracle(raw_output, analysis):
        calls["n"] += 1
        return "spine:" + "e" * 60                    # WOULD mint a fact if it were ever reached

    eng = _engine(EngineSeams(attest=_attest_allow,
                              think=ReplayThinker([_use_terminal(), _complete()]),
                              gate=_allow_gate, run_tool=_run_tool_terminal, oracle=oracle))
    rep = eng.engage(TARGET)
    assert calls["n"] == 0                            # the oracle NEVER saw terminal host output
    assert rep.fact_count == 0                        # no fact minted
    assert not any((f.bug_class or "") == "sqli" for f in rep.leads)   # not even a lead from the claim
    assert any(t.tool == "terminal.run" and t.outcome == "ran" for t in rep.tool_calls)  # but it IS recorded
    assert rep.done is True


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


# --- A5: mid-run operator instructions (advisory; the ASK_USER dead-end becomes resumable) ----------


def _ask_user():
    return LLMDecision(action=ActionType.ASK_USER, reasoning="need guidance",
                       question="how should I proceed?")


class _ScriptedThink:
    """A think seam that returns a scripted decision sequence AND snapshots what operator instructions
    were in state at each call — so a test can prove the instruction actually reached the reasoning step."""

    def __init__(self, decisions):
        self._it = iter(decisions)
        self.seen: list = []

    def __call__(self, state):
        self.seen.append(list(state.operator_instructions))
        return next(self._it, _complete())


def _op_msgs(*batches):
    """An operator_messages seam yielding one batch per call, then [] forever."""
    it = iter(batches)
    return lambda: list(next(it, []))


def test_ask_user_pauses_when_no_operator_instruction():
    eng = _engine(EngineSeams(attest=_attest_allow, think=_ScriptedThink([_ask_user()]),
                              operator_messages=_op_msgs()))   # no instruction ever
    rep = eng.engage(TARGET)
    assert rep.paused == "ask_user" and not rep.done          # unchanged pre-A5 behaviour

def test_ask_user_resumes_when_an_operator_instruction_is_queued():
    think = _ScriptedThink([_ask_user(), _complete()])
    # first drain (top of it0) is empty; the instruction arrives at the ASK_USER re-drain
    eng = _engine(EngineSeams(attest=_attest_allow, think=think,
                              operator_messages=_op_msgs([], ["check the admin API for BOLA"])))
    rep = eng.engage(TARGET)
    assert rep.paused == "" and rep.done                       # the dead-end resumed, no pause
    assert rep.decisions == ["ask_user->resumed", "complete"]
    assert think.seen[1] == ["check the admin API for BOLA"]   # the instruction reached the next think


def test_operator_instruction_is_advisory_not_a_tool_trigger():
    # an instruction reaches think, but a USE_TOOL it prompts is STILL gated — with a denying gate the
    # tool never runs. The instruction cannot manufacture an un-gated fire path.
    think = _ScriptedThink([_use_tool()])
    eng = _engine(EngineSeams(attest=_attest_allow, think=think, gate=_deny_gate,
                              run_tool=_run_tool_ok, operator_messages=_op_msgs(["focus on auth"])))
    rep = eng.engage(TARGET)
    assert think.seen[0] == ["focus on auth"]                  # advisory context reached the model
    assert rep.denied_edges and not [t for t in rep.tool_calls if t.outcome == "ran"]  # still gated


def test_operator_messages_seam_is_total_a_raise_is_not_a_crash():
    def _boom():
        raise RuntimeError("instruction source unavailable")
    eng = _engine(EngineSeams(attest=_attest_allow, think=_ScriptedThink([_ask_user()]),
                              operator_messages=_boom))
    rep = eng.engage(TARGET)                                    # must not raise
    assert rep.paused == "ask_user"                            # fail-closed: a broken source → no resume


# --- A4c: the fireteam deploy bridge (an APPROVED deploy fans out; folds facts fail-closed) ----------

from vigil_integration.agent.state import Finding                                    # noqa: E402
from vigil_integration.fireteam.models import EscalationRequest                       # noqa: E402
from vigil_integration.fireteam.orchestrator import FireteamOutcome                   # noqa: E402


def _deploy():
    return LLMDecision(action=ActionType.DEPLOY_FIRETEAM, reasoning="fan out",
                       fireteam=[{"member_id": "a", "capped_tier": "A1", "tools": ["nmap"]}])


def _approve_all(decision, state):
    return True                       # the operator's signed approval satisfied the queued deploy edge


def test_approved_deploy_folds_wave_facts_leads_and_escalations():
    fact = Finding(ref="f1", bug_class="sqli", status="fact", evidence_ref="spine:" + "a" * 58)
    lead = Finding(ref="l1", bug_class="xss", status="lead")
    esc = EscalationRequest(wave_id="w", member_id="a", tool_name="sqlmap", reason="destructive → queued")
    outcome = FireteamOutcome(facts=[fact], leads=[lead], escalations=[esc])
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_deploy(), _complete()]),
                              gate=_allow_gate, approval=_approve_all,
                              deploy_fireteam=lambda d, s, seq: outcome))
    rep = eng.engage(TARGET)
    assert "deploy_fireteam" in rep.decisions
    assert rep.fact_count == 1 and rep.facts[0].ref == "f1"          # the oracle-confirmed fact folded in
    assert any(ld.ref == "l1" for ld in rep.leads)                  # the lead folded in
    assert any("escalation" in q for q in rep.queued_edges)          # member escalation surfaced (never run)


def test_wave_fact_without_a_signed_ref_is_downgraded_to_a_lead():
    # honesty guard: a Finding that lands in outcome.facts WITHOUT a signed evidence ref must NOT become a
    # fact in the run — it degrades to a lead (a FACT needs a signed ref, even from a wave).
    mislabeled = Finding(ref="x1", bug_class="rce", status="lead", evidence_ref="")   # no ref
    outcome = FireteamOutcome(facts=[mislabeled])
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_deploy(), _complete()]),
                              gate=_allow_gate, approval=_approve_all,
                              deploy_fireteam=lambda d, s, seq: outcome))
    rep = eng.engage(TARGET)
    assert rep.fact_count == 0 and any(ld.ref == "x1" for ld in rep.leads)   # downgraded, not a fact


def test_approved_deploy_with_no_seam_is_a_recorded_refusal_not_a_crash():
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_deploy(), _complete()]),
                              gate=_allow_gate, approval=_approve_all))       # deploy_fireteam=None
    rep = eng.engage(TARGET)
    assert rep.fact_count == 0 and any("no fireteam seam" in d for d in rep.denied_edges)


def test_refused_plan_spawns_nothing():
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_deploy(), _complete()]),
                              gate=_allow_gate, approval=_approve_all,
                              deploy_fireteam=lambda d, s, seq: FireteamOutcome(refused=True,
                                                                                reason="over-cap")))
    rep = eng.engage(TARGET)
    assert rep.fact_count == 0 and any("refused" in q for q in rep.queued_edges)


def test_deploy_seam_raise_is_fail_closed():
    def _boom(d, s, seq):
        raise RuntimeError("wave backend down")
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_deploy(), _complete()]),
                              gate=_allow_gate, approval=_approve_all, deploy_fireteam=_boom))
    rep = eng.engage(TARGET)                                     # must not raise
    assert any("fireteam wave error" in d for d in rep.denied_edges)


def test_unapproved_deploy_stays_queued_and_never_fans_out():
    called = {"n": 0}
    def _seam(d, s, seq):
        called["n"] += 1
        return FireteamOutcome()
    # no approval seam ⇒ the queued deploy is never approved ⇒ the seam is NEVER invoked (approve-then-run)
    eng = _engine(EngineSeams(attest=_attest_allow, think=ReplayThinker([_deploy()]),
                              gate=_allow_gate, deploy_fireteam=_seam))
    rep = eng.engage(TARGET)
    assert rep.paused == "awaiting_approval" and called["n"] == 0


# --- T3: end-of-run blackboard-chain persist seam --------------------------------------------------


def test_persist_spine_seam_is_called_once_at_end_of_run():
    calls = []
    seams = EngineSeams(attest=_attest_allow, think=lambda s: _complete(),
                        persist_spine=lambda: calls.append(1))
    report = _engine(seams).engage(TARGET)
    assert not report.refused
    assert calls == [1]                         # persisted exactly once, after the loop + detection mirror


def test_persist_spine_error_never_crashes_the_run():
    def _boom():
        raise RuntimeError("blackboard persist backend down")
    seams = EngineSeams(attest=_attest_allow, think=lambda s: _complete(), persist_spine=_boom)
    report = _engine(seams).engage(TARGET)      # must not raise (best-effort, fail-closed)
    assert report.done is True


def test_persist_spine_not_called_on_a_refused_run():
    # A refused engagement (no attestation) returns BEFORE the loop, so there is nothing to persist.
    calls = []
    seams = EngineSeams(attest=_attest_deny, think=lambda s: _complete(),
                        persist_spine=lambda: calls.append(1))
    report = _engine(seams).engage(TARGET)
    assert report.refused and calls == []
