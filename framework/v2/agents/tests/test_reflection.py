"""
Nervous-System N4 — in-loop metacognitive reflection over the reasoning trace.

The reflection reads the spine and posts re-orienting ``reflection`` events (dead threads,
stalls) that re-rank/defer — never gate a surface. Deterministic and deduped.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.reflection import ReflectionAgent, reflect


def _bb(tmp_path):
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    b.engagement_id("e")
    return b


def _hyp(b, handle):
    return b.post(engagement="e", kind="hypothesis", agent_name="h",
                  payload={"handle": handle, "surface": "/x", "bug_class": "boolean_sqli",
                           "given": "g", "if_action": "a", "then_observation": "o",
                           "because_model": "m", "refute_on": "r", "cheap_test": "c"})


def _action(b):
    return b.post(engagement="e", kind="action", agent_name="x",
                  payload={"action_id": "A", "tool": "curl", "args_summary": "?q=1"})


def _finding(b, handle=None):
    return b.post(engagement="e", kind="finding", agent_name="x",
                  payload={"finding_slug": "1", "title": "t", "severity": "High",
                           "bug_class": "boolean_sqli", "surface": "/x", "summary": "s",
                           "derived_from_hypothesis": handle})


def test_reflect_flags_a_dead_thread(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    _hyp(b, "H-1")
    rs = reflect(b, "e")
    assert any(r["trigger"] == "dead-thread" and "H-1" in r["observations"][0] for r in rs)
    assert all("defer" in r["reorientation"] for r in rs if r["trigger"] == "dead-thread")
    # a finding derived from the hypothesis clears the dead thread
    _finding(b, "H-1")
    assert not any(r["trigger"] == "dead-thread" for r in reflect(b, "e"))
    b.close()


def test_reflect_flags_a_stall(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    for _ in range(5):
        _action(b)
    rs = reflect(b, "e")
    stall = [r for r in rs if r["trigger"] == "stall"]
    assert stall and "do not skip any" in stall[0]["reorientation"]     # re-rank, never skip a surface
    # a confirmed finding clears the stall
    _finding(b)
    assert not any(r["trigger"] == "stall" for r in reflect(b, "e"))
    b.close()


def test_reflection_agent_dedups_and_quiesces(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    _hyp(b, "H-1")
    for _ in range(5):
        _action(b)
    agent = ReflectionAgent(b, "e")
    n = agent.step()
    assert n >= 2                                                       # dead-thread + stall
    assert agent.step() == 0 and not agent.should_run()                # deduped; no repeats
    assert len(b.read(engagement="e", kinds=["reflection"])) == n
    b.close()
