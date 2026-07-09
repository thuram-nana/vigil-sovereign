"""
Nervous-System N0 — the unified event spine's vocabulary + the engage/scanner bridge.

The blackboard is the one append-only, typed, provenance-linked event stream. N0 extends its
vocabulary additively (reward / critic_verdict / reflection / refusal), gives the flagship
engage/scanner world a best-effort SpineSink to emit onto it, and exposes a replay cursor. A
critic verdict is typed so it can NEVER say "confirm" — critics advise; only the oracle
confirms. Every spine write is best-effort: it must never perturb the run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.blackboard import BlackboardError, open_blackboard
from framework.v2.agents.spine_sink import SpineSink
from framework.v2.scanner.progress import ProgressSink

_SLUG = "spine-test"


def _bb(tmp_path: Path):
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    b.engagement_id(_SLUG)
    return b


# ---- the additive vocabulary --------------------------------------------------


def test_new_event_kinds_validate_and_roundtrip(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    b.post(engagement=_SLUG, kind="reward", agent_name="bus",
           payload={"source": "bandit", "arm": "sqli:q", "signal": "oracle_confirmed", "reward": 0.9})
    b.post(engagement=_SLUG, kind="critic_verdict", agent_name="soundness",
           payload={"critic": "soundness", "target_event_id": 1, "verdict": "object", "severity": "major"})
    b.post(engagement=_SLUG, kind="reflection", agent_name="reflector",
           payload={"trigger": "stall", "observations": ["3 refuted hypotheses on /login"],
                    "reorientation": "defer /login, prioritise /api"})
    b.post(engagement=_SLUG, kind="refusal", agent_name="gate",
           payload={"gate": "scope", "action_refused": "GET https://evil.example", "reason": "out of scope", "fatal": True})
    kinds = {r.kind for r in b.read(engagement=_SLUG)}
    assert {"reward", "critic_verdict", "reflection", "refusal"} <= kinds
    rew = next(r for r in b.read(engagement=_SLUG, kinds=["reward"]))
    assert rew.payload["reward"] == 0.9 and rew.payload["signal"] == "oracle_confirmed"
    b.close()


def test_critic_verdict_can_never_say_confirm(tmp_path: Path) -> None:
    # oracle authority at the TYPE level: a critic verdict Literal is endorse|object|abstain.
    b = _bb(tmp_path)
    with pytest.raises(BlackboardError):
        b.post(engagement=_SLUG, kind="critic_verdict", agent_name="rogue",
               payload={"critic": "x", "target_event_id": 1, "verdict": "confirm"})
    b.close()


def test_reward_out_of_range_is_rejected(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    with pytest.raises(BlackboardError):
        b.post(engagement=_SLUG, kind="reward", agent_name="bus",
               payload={"source": "bandit", "reward": 1.5})   # > 1.0
    b.close()


# ---- SpineSink: the ProgressSink bridge + typed helpers -----------------------


def test_spine_sink_satisfies_progress_sink(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    sink = SpineSink(b, _SLUG)
    assert isinstance(sink, ProgressSink)                       # duck-typed conformance
    sink.phase("crawl")
    sink.finding("boolean_sqli", "differential_response", "q", "/search", 0.91)
    sink.done(findings=1, requests_sent=42, elapsed_s=3.2)
    obs = b.read(engagement=_SLUG, kinds=["observation"])
    sources = {o.payload["source"] for o in obs}
    assert {"scanner:phase", "scanner:finding", "scanner:done"} <= sources
    b.close()


def test_spine_sink_typed_helpers_post_correct_kinds(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    sink = SpineSink(b, _SLUG)
    sink.refusal("kill-switch", "audit /admin", reason="tripped", fatal=True)
    sink.reward("bandit", 0.8, arm="sqli:q", signal="oracle_confirmed")
    sink.decision("next", "pivot to /api")
    sink.finding_event({"finding_slug": "x", "title": "t", "severity": "High",
                        "bug_class": "boolean_sqli", "surface": "query:q", "summary": "s"})
    by_kind = {r.kind for r in b.read(engagement=_SLUG)}
    assert {"refusal", "reward", "decision", "finding"} <= by_kind
    ref = next(r for r in b.read(engagement=_SLUG, kinds=["refusal"]))
    assert ref.payload["gate"] == "kill-switch" and ref.payload["fatal"] is True
    b.close()


def test_spine_sink_is_best_effort_and_never_raises(tmp_path: Path) -> None:
    # a write that fails (blackboard closed) is swallowed — the spine can never sink a run.
    b = _bb(tmp_path)
    sink = SpineSink(b, _SLUG)
    b.close()
    sink.phase("crawl")                                         # would raise if not guarded
    assert sink.reward("bandit", 0.5) is None                   # returns None, no exception


# ---- replay cursor ------------------------------------------------------------


def test_replay_returns_events_in_order_from_cursor(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    ids = [b.post(engagement=_SLUG, kind="observation", agent_name="a",
                  payload={"source": "s", "surface": f"p{i}", "summary": "x"}) for i in range(5)]
    full = b.replay(engagement=_SLUG)
    assert [e.id for e in full] == ids                          # strict id order
    tail = b.replay(engagement=_SLUG, since_id=ids[2])
    assert [e.id for e in tail] == ids[3:]                      # only after the cursor
    b.close()
