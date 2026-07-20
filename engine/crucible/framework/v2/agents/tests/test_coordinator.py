"""
Tests for the Agent base class and Coordinator scheduling.

Two trivial in-process agents (a poster and a counter) exercise the
lifecycle, the cursor advance, the quiet-ticks termination, and
the wall-clock-bound run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.base import Agent
from framework.v2.agents.blackboard import Blackboard, open_blackboard
from framework.v2.agents.coordinator import Coordinator


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def bb(tmp_path: Path) -> Blackboard:
    db = tmp_path / "bb.sqlite"
    b = open_blackboard(db_path=db)
    b.engagement_id("alpha")
    yield b
    b.close()


# ---------------------------------------------------------------------------
# trivial agents for testing
# ---------------------------------------------------------------------------


class PostNObservationsAgent(Agent):
    """Posts up to N observations across N ticks, one per tick."""

    name = "test-poster"

    def __init__(self, bb: Blackboard, slug: str, n: int) -> None:
        super().__init__(bb, slug)
        self._remaining = n
        self._posted = 0

    def should_run(self) -> bool:
        return self._remaining > 0

    def step(self) -> int:
        self._posted += 1
        self.bb.post(
            engagement=self.engagement_id, kind="observation",
            agent_name=self.name,
            payload={
                "source": "test", "surface": f"/tick-{self._posted}",
                "summary": f"observation #{self._posted}",
            },
        )
        self._remaining -= 1
        self._advance_cursor()
        return 1


class ReactsToObservationsAgent(Agent):
    """Posts a Decision in response to each new observation it sees."""

    name = "test-reactor"

    def __init__(self, bb: Blackboard, slug: str) -> None:
        super().__init__(bb, slug)
        self.reactions = 0

    def should_run(self) -> bool:
        return self.bb.latest_event_id(engagement=self.engagement_id) > self._cursor

    def step(self) -> int:
        new_events = self._new_events(kinds=("observation",))
        posted = 0
        for ev in new_events:
            self.bb.post(
                engagement=self.engagement_id, kind="decision",
                agent_name=self.name, parent_id=ev.id,
                payload={
                    "question": f"react to event {ev.id}?",
                    "choice": "yes",
                    "rationale": "test",
                },
            )
            posted += 1
            self.reactions += 1
        self._advance_cursor()
        return posted


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_agent_cursor_starts_at_zero(bb: Blackboard) -> None:
    a = PostNObservationsAgent(bb, "alpha", n=1)
    assert a._cursor == 0


def test_coordinator_runs_a_single_agent(bb: Blackboard) -> None:
    poster = PostNObservationsAgent(bb, "alpha", n=3)
    coord = Coordinator(blackboard=bb, engagement_slug="alpha", agents=[poster])
    report = coord.run_until_quiet()
    # 3 events from poster + however many quiet ticks at the end
    assert report.total_events == 3
    assert report.quiet_ticks_hit
    assert bb.count(engagement="alpha", kind="observation") == 3


def test_coordinator_chains_agents_through_blackboard(bb: Blackboard) -> None:
    poster = PostNObservationsAgent(bb, "alpha", n=2)
    reactor = ReactsToObservationsAgent(bb, "alpha")
    coord = Coordinator(
        blackboard=bb, engagement_slug="alpha",
        agents=[poster, reactor],
    )
    report = coord.run_until_quiet()
    assert bb.count(engagement="alpha", kind="observation") == 2
    assert bb.count(engagement="alpha", kind="decision") == 2
    assert reactor.reactions == 2
    assert report.quiet_ticks_hit


def test_coordinator_run_for_seconds_respects_budget(bb: Blackboard) -> None:
    poster = PostNObservationsAgent(bb, "alpha", n=10_000)  # never quiets
    coord = Coordinator(
        blackboard=bb, engagement_slug="alpha", agents=[poster],
        max_ticks=10_000,
    )
    report = coord.run_for_seconds(0.1)
    assert report.halted_by  # set
    assert "wall-clock" in report.halted_by or "max_ticks" in report.halted_by
    assert report.seconds_elapsed >= 0.1 - 0.05  # allow scheduling jitter


def test_coordinator_external_stop(bb: Blackboard) -> None:
    poster = PostNObservationsAgent(bb, "alpha", n=10_000)
    coord = Coordinator(
        blackboard=bb, engagement_slug="alpha", agents=[poster],
    )
    coord.stop("test asks to stop")
    report = coord.run_until_quiet()
    assert report.halted_by == "test asks to stop"
    assert report.ticks == 0  # never ticked because stop was set


def test_coordinator_swallows_agent_exception(bb: Blackboard) -> None:
    """A buggy agent should not take down the whole coordinator."""

    class BuggyAgent(Agent):
        name = "buggy"

        def should_run(self) -> bool:
            return True

        def step(self) -> int:
            raise RuntimeError("simulated bug")

    healthy = PostNObservationsAgent(bb, "alpha", n=1)
    coord = Coordinator(
        blackboard=bb, engagement_slug="alpha",
        agents=[BuggyAgent(bb, "alpha"), healthy],
    )
    report = coord.run_until_quiet()
    # Healthy agent still posted its event
    assert bb.count(engagement="alpha", kind="observation") == 1
    assert report.quiet_ticks_hit


def test_coordinator_critique_pending_count(bb: Blackboard) -> None:
    bb.post(
        engagement="alpha", kind="finding", agent_name="x",
        payload={
            "finding_slug": "001-x", "title": "x", "severity": "Low",
            "bug_class": "x", "surface": "/x", "summary": "x",
            # critique_status defaults to "pending"
        },
    )
    coord = Coordinator(blackboard=bb, engagement_slug="alpha", agents=[])
    assert coord.critique_pending_findings() == 1
