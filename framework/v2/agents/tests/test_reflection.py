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


def test_reflection_cursor_picks_up_new_threads_without_reposting(tmp_path: Path) -> None:
    # X3 durable dedup cursor: after quiescing, a NEW dead thread (new hypothesis) is detected
    # and posted exactly once; old reflections are never re-posted (the incremental cursor is
    # complete and monotonic). Equivalent behaviour to the old full-scan dedup, at O(new) cost.
    b = _bb(tmp_path)
    _hyp(b, "H-1")
    for _ in range(5):
        _action(b)
    agent = ReflectionAgent(b, "e")
    assert agent.step() >= 2 and agent.step() == 0                      # posted once, then quiesces
    _hyp(b, "H-2")                                                      # a new dead thread appears
    assert agent.should_run()
    assert agent.step() >= 1                                            # the new thread is posted
    assert agent.step() == 0                                            # and never re-posted
    keys = [(r.payload.get("trigger"), r.payload.get("reorientation"))
            for r in b.read(engagement="e", kinds=["reflection"], limit=10_000)]
    assert len(keys) == len(set(keys))                                 # no duplicate reflections
    b.close()


def test_pending_is_memoized_within_a_tick(tmp_path: Path, monkeypatch) -> None:
    # X3: reflect() is a full-log analysis; should_run() + step() in ONE tick (no new events
    # between them) must not each re-scan the log — the count-keyed memo serves the second call.
    import framework.v2.agents.reflection as refl

    b = _bb(tmp_path)
    _hyp(b, "H-1")
    for _ in range(5):
        _action(b)
    agent = refl.ReflectionAgent(b, "e")
    calls = {"n": 0}
    real = refl.reflect

    def counting_reflect(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(refl, "reflect", counting_reflect)
    assert agent.should_run()                       # computes reflect() once, memoized at head=N
    after_should_run = calls["n"]
    agent.step()                                    # head unchanged until it posts -> memo hit
    assert calls["n"] == after_should_run           # step() did NOT re-run reflect() before posting
    b.close()
