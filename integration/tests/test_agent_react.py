"""F2 — the sovereign ReAct interposition: fail-closed decision parse, action-edge authorization
through the gate, phase→tier escalation, and the oracle interposition (claims→LEADs, oracle→FACTs)."""

from __future__ import annotations

import json

import pytest

from vigil_integration.agent import (
    ActionType,
    AgentState,
    Finding,
    LLMDecision,
    OutputAnalysis,
    Phase,
    ToolCall,
    apply_intake,
    authorize_edge,
    can_transition,
    classify_edge,
    intake_result,
    parse_decision,
    phase_tier,
    tool_tier,
)


# --- phase machine ---------------------------------------------------------------------------

def test_phase_tier_and_destructive_floor():
    assert phase_tier(Phase.INFORMATIONAL) == "A1"
    assert phase_tier(Phase.EXPLOITATION) == "A2"
    assert phase_tier(Phase.POST_EXPLOITATION) == "A3"
    assert tool_tier(Phase.INFORMATIONAL) == "A1"
    assert tool_tier(Phase.INFORMATIONAL, destructive=True) == "A3"   # destructive floors at A3
    assert tool_tier(Phase.POST_EXPLOITATION, destructive=True) == "A3"


def test_phase_transitions_are_monotone_one_step():
    assert can_transition(Phase.INFORMATIONAL, Phase.EXPLOITATION)[0] is True
    assert can_transition(Phase.EXPLOITATION, Phase.POST_EXPLOITATION)[0] is True
    assert can_transition(Phase.EXPLOITATION, Phase.INFORMATIONAL)[0] is False   # no downgrade
    assert can_transition(Phase.INFORMATIONAL, Phase.POST_EXPLOITATION)[0] is False  # no skip
    assert can_transition(Phase.EXPLOITATION, Phase.EXPLOITATION)[0] is False    # no-op


# --- fail-closed decision parse --------------------------------------------------------------

def test_parse_valid_decision():
    d = parse_decision('{"action": "use_tool", "tool": {"tool_name": "nmap", "tool_args": {"target": "x"}}}')
    assert d.action == ActionType.USE_TOOL and d.tool.tool_name == "nmap"


def test_unparseable_pauses_for_a_human():
    d = parse_decision("the model rambled with no json")
    assert d.action == ActionType.ASK_USER and d.question   # never an action-bearing edge


def test_malformed_actions_downgrade_never_up():
    # a broken deploy_fireteam must NEVER become a deploy
    assert parse_decision('{"action": "deploy_fireteam", "fireteam": []}').action == ActionType.ASK_USER
    # a deploy with a fallback tool downgrades to a single gated tool, not a deploy
    d = parse_decision('{"action":"deploy_fireteam","fireteam":[],"tool":{"tool_name":"curl"}}')
    assert d.action == ActionType.USE_TOOL
    # use_tool without a tool, transition without a target, plan without steps, switch without a skill
    assert parse_decision('{"action": "use_tool"}').action == ActionType.ASK_USER
    assert parse_decision('{"action": "transition_phase"}').action == ActionType.ASK_USER
    assert parse_decision('{"action": "plan_tools", "plan": []}').action == ActionType.ASK_USER
    assert parse_decision('{"action": "switch_skill"}').action == ActionType.ASK_USER


# --- action-edge classification --------------------------------------------------------------

def _st(phase=Phase.INFORMATIONAL):
    return AgentState(engagement_slug="acme", phase=phase)


def test_inert_actions_touch_no_target():
    for action in (ActionType.ASK_USER, ActionType.COMPLETE, ActionType.SWITCH_SKILL):
        spec = classify_edge(LLMDecision(action=action, skill="x", question="q"), Phase.INFORMATIONAL)
        assert spec.inert is True and spec.target_touching is False and spec.denied is False


def test_use_tool_needs_the_phase_tier_and_destructive_needs_A3():
    d = LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name="nmap", tool_args={"target": "h"}))
    spec = classify_edge(d, Phase.EXPLOITATION)
    assert spec.target_touching and spec.tier == "A2" and spec.target == "h" and not spec.destructive
    dd = LLMDecision(action=ActionType.USE_TOOL,
                     tool=ToolCall(tool_name="metasploit", blast_class="destructive", tool_args={"target": "h"}))
    spec2 = classify_edge(dd, Phase.INFORMATIONAL)
    assert spec2.destructive and spec2.tier == "A3" and spec2.requires_signed_approval


def test_phase_escalation_requires_signed_approval_and_bad_transition_denied():
    ok = classify_edge(LLMDecision(action=ActionType.TRANSITION_PHASE, target_phase=Phase.EXPLOITATION),
                       Phase.INFORMATIONAL)
    assert ok.requires_signed_approval is True and ok.denied is False and ok.tier == "A2"
    bad = classify_edge(LLMDecision(action=ActionType.TRANSITION_PHASE, target_phase=Phase.POST_EXPLOITATION),
                        Phase.INFORMATIONAL)
    assert bad.denied is True   # skipping phases is refused


# --- action-edge authorization (through the injected gate) -----------------------------------

class _Gate:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def __call__(self, tool_name, target, destructive=False):
        self.calls.append((tool_name, target, destructive))
        allowed = self.outcome == "allow"
        return type("V", (), {"outcome": self.outcome, "allowed": allowed, "reason": "stub"})()


def test_tool_edge_routes_through_the_gate():
    d = LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name="nmap", tool_args={"target": "h"}))
    g = _Gate("allow")
    v = authorize_edge(d, _st(Phase.EXPLOITATION), gate=g)
    assert v.allowed is True and v.outcome == "allow" and g.calls == [("nmap", "h", False)]
    # a gate deny/queue is honoured
    assert authorize_edge(d, _st(Phase.EXPLOITATION), gate=_Gate("deny")).outcome == "deny"
    assert authorize_edge(d, _st(Phase.EXPLOITATION), gate=_Gate("queue")).allowed is False


def test_tool_edge_without_a_gate_fails_closed():
    d = LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name="nmap", tool_args={"target": "h"}))
    v = authorize_edge(d, _st(), gate=None)
    assert v.allowed is False and v.outcome == "deny"


def test_gate_error_fails_closed():
    def boom(*a, **k):
        raise RuntimeError("kernel down")
    d = LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name="nmap", tool_args={"target": "h"}))
    v = authorize_edge(d, _st(), gate=boom)
    assert v.outcome == "deny" and "fail-closed" in v.reason


def test_escalation_and_fireteam_queue_for_signed_approval():
    esc = authorize_edge(LLMDecision(action=ActionType.TRANSITION_PHASE, target_phase=Phase.EXPLOITATION),
                         _st(Phase.INFORMATIONAL), gate=_Gate("allow"))
    assert esc.outcome == "queue" and esc.requires_signed_approval is True and esc.allowed is False
    ft = authorize_edge(LLMDecision(action=ActionType.DEPLOY_FIRETEAM, fireteam=[{"role": "x"}]),
                        _st(), gate=_Gate("allow"))
    assert ft.outcome == "queue" and ft.requires_signed_approval is True


def test_inert_edges_allow_without_the_gate():
    for action in (ActionType.ASK_USER, ActionType.COMPLETE):
        v = authorize_edge(LLMDecision(action=action, question="q"), _st(), gate=None)
        assert v.allowed is True and v.outcome == "allow"


def test_invalid_edge_is_denied():
    v = authorize_edge(LLMDecision(action=ActionType.USE_TOOL), _st(), gate=_Gate("allow"))
    assert v.outcome == "deny"   # use_tool with no tool


# --- the oracle interposition (the anti-hallucination keystone) ------------------------------

def test_llm_claims_are_leads_never_facts():
    analysis = OutputAnalysis(exploit_succeeded=True, verdict="new_info",
                              findings=[{"title": "SQLi", "bug_class": "sqli", "severity": "high"}])
    # NO oracle wired → nothing can be a fact (fail-closed)
    r = intake_result("id=1,2,3 admin=true", analysis, oracle=None, source="sqlmap")
    assert r.facts == []
    assert len(r.leads) == 2   # the proposed finding + the unconfirmed exploit claim
    assert all(f.status == "lead" for f in r.leads)
    assert any("UNCONFIRMED" in f.title for f in r.leads)


def test_oracle_confirmation_mints_a_fact_with_evidence():
    analysis = OutputAnalysis(exploit_succeeded=True, findings=[{"title": "SQLi", "bug_class": "sqli"}])
    def oracle(raw, an):
        return "spine:abc123" if "admin=true" in raw else None
    r = intake_result("id=1 admin=true", analysis, oracle=oracle, source="sqlmap")
    assert len(r.facts) == 1 and r.facts[0].status == "fact" and r.facts[0].evidence_ref == "spine:abc123"
    # the LLM's proposed finding is STILL a lead (only the exploit-oracle result is a fact)
    assert any(f.status == "lead" and f.title == "SQLi" for f in r.leads)


def test_oracle_non_fire_keeps_it_a_lead():
    analysis = OutputAnalysis(exploit_succeeded=True)
    r = intake_result("no results", analysis, oracle=lambda raw, an: None, source="sqlmap")
    assert r.facts == [] and len(r.leads) == 1 and "UNCONFIRMED" in r.leads[0].title


def test_oracle_error_fails_closed():
    def boom(raw, an):
        raise RuntimeError("oracle crashed")
    r = intake_result("x", OutputAnalysis(exploit_succeeded=True), oracle=boom)
    assert r.facts == []   # an oracle error confirms nothing


def test_apply_intake_separates_fact_and_lead_stores():
    st = AgentState(engagement_slug="acme")
    r = intake_result("admin=true", OutputAnalysis(exploit_succeeded=True, findings=[{"title": "x"}]),
                      oracle=lambda raw, an: "spine:z", source="t")
    apply_intake(st, r)
    assert len(st.facts) == 1 and st.facts[0].status == "fact" and st.facts[0].evidence_ref == "spine:z"
    assert len(st.leads) == 1 and st.leads[0].status == "lead"


def test_state_record_fact_requires_evidence():
    st = AgentState(engagement_slug="acme")
    with pytest.raises(ValueError, match="signed evidence"):
        st.record_fact(Finding(ref="x"), evidence_ref="")   # a FACT without evidence is refused


def test_agent_state_roundtrips_json():
    st = AgentState(engagement_slug="acme", phase=Phase.EXPLOITATION, iteration=3)
    st.record_lead(Finding(ref="l1", bug_class="xss"))
    back = AgentState.model_validate(json.loads(st.model_dump_json()))
    assert back.phase == Phase.EXPLOITATION and back.iteration == 3 and back.leads[0].ref == "l1"


def test_whitespace_oracle_ref_mints_no_fact():
    # LOW: a buggy oracle returning a truthy-but-garbage ref must NOT launder a fact
    for junk in ("   ", "\t\n", ""):
        r = intake_result("admin=true", OutputAnalysis(exploit_succeeded=True),
                          oracle=lambda raw, an, j=junk: j)
        assert r.facts == [] and len(r.leads) == 1 and "UNCONFIRMED" in r.leads[0].title


def test_malformed_gate_never_presents_as_allow():
    # LOW: a gate returning outcome="allow" but allowed omitted/False must yield a DENY EdgeVerdict
    class _Malformed:
        def __call__(self, *a, **k):
            return type("V", (), {"outcome": "allow"})()   # no .allowed attribute
    d = LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name="nmap", tool_args={"target": "h"}))
    v = authorize_edge(d, _st(), gate=_Malformed())
    assert v.allowed is False and v.outcome == "deny"


def test_fact_finding_requires_evidence_at_the_type_level():
    # LOW: enforce fact-needs-evidence in the TYPE so deserialization/checkpoint can't build an
    # evidence-less fact even without going through record_fact
    Finding.model_validate({"ref": "x", "status": "fact", "evidence_ref": "spine:z"})  # ok
    with pytest.raises(Exception):
        Finding.model_validate({"ref": "x", "status": "fact", "evidence_ref": ""})
    with pytest.raises(Exception):
        Finding.model_validate({"ref": "x", "status": "fact", "evidence_ref": "   "})
    with pytest.raises(Exception):
        AgentState.model_validate({"engagement_slug": "a",
                                   "facts": [{"ref": "x", "status": "fact", "evidence_ref": ""}]})


def test_import_clean_no_offense_modules():
    import sys
    import vigil_integration.agent  # noqa: F401
    assert not any(m == "framework" or m.startswith("framework.")
                   or m == "strix" or m.startswith("strix.") for m in sys.modules)
