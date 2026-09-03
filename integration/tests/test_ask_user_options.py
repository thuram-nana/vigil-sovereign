"""S2 — an agent ask_user question may carry OPTIONAL suggested answers (`question_options`) so the chat can
render click-to-pick buttons (+ "Other → type your own"). This guards the plumbing think→parse→engine event:
the model's `options` (or `question_options`) map onto the decision, and the engine mirrors them onto the
ask_user decision spine event as `agent_question_options`. Advisory only — a picked option is folded back as
the resume answer; it authorises nothing.

Pure fakes (no framework, no network) — runs in both CI legs.
"""

from __future__ import annotations

from types import SimpleNamespace

from vigil_integration.agent import ActionType, LLMDecision
from vigil_integration.agent.react import parse_decision
from vigil_integration.live.engine import EngineSeams, VigilEngine
from vigil_integration.live.think_claude import ReplayThinker

TARGET = "http://127.0.0.1:19010/"


def test_parse_maps_options_under_either_key():
    d = parse_decision('{"action":"ask_user","question":"Which target?","options":["a","b"]}')
    assert d.action == ActionType.ASK_USER and d.question_options == ["a", "b"]
    d2 = parse_decision('{"action":"ask_user","question":"Q","question_options":["x"]}')
    assert d2.question_options == ["x"]
    # no options → empty list (free-text only), never an error
    d3 = parse_decision('{"action":"ask_user","question":"Q"}')
    assert d3.question_options == []


def _attest_allow(**kw):
    return SimpleNamespace(allowed=True, reason="attested",
                           attestation=SimpleNamespace(record_hash="att-" + "a" * 60))


def test_engine_mirrors_options_onto_the_ask_user_decision_event():
    events = []
    dec = LLMDecision(action=ActionType.ASK_USER, question="Which target should I probe?",
                      question_options=["127.0.0.1:19010", "127.0.0.1:8080"])
    eng = VigilEngine(slug="loopback", max_iterations=2, seams=EngineSeams(
        attest=_attest_allow, think=ReplayThinker([dec]),
        spine_post=lambda k, p, parent_id=None: events.append((k, p)) or len(events)))
    eng.engage(TARGET)
    decisions = [p for (k, p) in events if k == "decision"]
    assert decisions, "no decision event posted"
    d0 = decisions[0]
    assert d0.get("choice") == "ask_user"
    assert d0.get("agent_question") == "Which target should I probe?"
    assert d0.get("agent_question_options") == ["127.0.0.1:19010", "127.0.0.1:8080"]


def test_engine_omits_options_for_non_ask_user():
    events = []
    eng = VigilEngine(slug="loopback", max_iterations=1, seams=EngineSeams(
        attest=_attest_allow, think=ReplayThinker([LLMDecision(action=ActionType.COMPLETE, summary="done")]),
        spine_post=lambda k, p, parent_id=None: events.append((k, p)) or len(events)))
    eng.engage(TARGET)
    decisions = [p for (k, p) in events if k == "decision"]
    assert decisions and decisions[0].get("agent_question_options") == []
