"""
agents.coordinator — boots agents, schedules ticks, arbitrates.

A tick is one round-robin pass through every registered agent's
`should_run()` then `step()`. The coordinator owns the wall-clock,
the tick budget, and termination.

Termination conditions (any one ends the run):
  - `run_until_quiet`: no agent posted anything new in `quiet_ticks`
    consecutive ticks.
  - `run_for_seconds`: wall-clock exhausted.
  - `max_ticks`: hard tick cap.
  - `stop_event`: external signal.
  - Watchdog (when ACP is wired in) raises `WatchdogHalt`.

Per FORGE PROTOCOL § 3.4 the coordinator does not have authority to
suppress critique-agent objections; it only enforces ordering and
budget.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

from ..common import logging as v2log
from ..common.errors import CrucibleError
from .base import Agent
from .blackboard import Blackboard


_log = v2log.get_logger(__name__)


class CoordinatorHalt(CrucibleError):
    """Raised by external machinery (watchdog) to halt the coordinator."""


@dataclass
class TickReport:
    tick: int
    agents_ran: int
    events_posted: int
    elapsed_ms: float


@dataclass
class RunReport:
    ticks: int
    total_events: int
    quiet_ticks_hit: bool = False
    seconds_elapsed: float = 0.0
    halted_by: str = ""
    per_tick: list[TickReport] = field(default_factory=list)


class Coordinator:
    """Owns agent scheduling. One Coordinator per engagement."""

    def __init__(
        self,
        *,
        blackboard: Blackboard,
        engagement_slug: str,
        agents: Iterable[Agent],
        max_ticks: int = 1000,
        quiet_ticks: int = 3,
    ) -> None:
        self.bb = blackboard
        self.slug = engagement_slug
        self.engagement_id = blackboard.engagement_id(engagement_slug)
        self.agents: list[Agent] = list(agents)
        self.max_ticks = max_ticks
        self.quiet_ticks = quiet_ticks
        self._stop = False
        self._stop_reason = ""

    def stop(self, reason: str = "external stop") -> None:
        """External stop. Run loops check this between ticks."""
        self._stop = True
        self._stop_reason = reason
        _log.info("coordinator.stop_requested", reason=reason, slug=self.slug)

    def tick(self, n: int = 0) -> TickReport:
        """One round-robin pass."""
        t0 = time.perf_counter()
        agents_ran = 0
        events_posted = 0
        for agent in self.agents:
            try:
                if agent.should_run():
                    agents_ran += 1
                    events_posted += agent.step()
            except CrucibleError:
                # ethics/runtime errors propagate; coordinator does not swallow
                raise
            except Exception as e:
                # log and continue: one buggy agent should not take down the
                # coordinator. The error is on the engagement log for review.
                _log.error(
                    "coordinator.agent_step_error",
                    agent=agent.name, error=str(e), error_type=type(e).__name__,
                )
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TickReport(
            tick=n, agents_ran=agents_ran,
            events_posted=events_posted, elapsed_ms=elapsed,
        )

    def run_until_quiet(self, *, max_ticks: int | None = None) -> RunReport:
        """Tick until either max_ticks reached or quiet_ticks consecutive
        ticks produced no events."""
        cap = max_ticks if max_ticks is not None else self.max_ticks
        consecutive_quiet = 0
        report = RunReport(ticks=0, total_events=0)
        t0 = time.perf_counter()

        for n in range(1, cap + 1):
            if self._stop:
                report.halted_by = self._stop_reason or "stop"
                break
            tr = self.tick(n)
            report.per_tick.append(tr)
            report.ticks = n
            report.total_events += tr.events_posted
            if tr.events_posted == 0:
                consecutive_quiet += 1
            else:
                consecutive_quiet = 0
            if consecutive_quiet >= self.quiet_ticks:
                report.quiet_ticks_hit = True
                break

        report.seconds_elapsed = time.perf_counter() - t0
        _log.info(
            "coordinator.run_complete",
            slug=self.slug, ticks=report.ticks,
            events=report.total_events, quiet=report.quiet_ticks_hit,
            halted_by=report.halted_by, seconds=int(report.seconds_elapsed),
        )
        return report

    def run_for_seconds(self, seconds: float) -> RunReport:
        """Tick continuously until the wall-clock budget is exhausted."""
        report = RunReport(ticks=0, total_events=0)
        t0 = time.perf_counter()
        n = 0
        while True:
            if self._stop:
                report.halted_by = self._stop_reason or "stop"
                break
            elapsed = time.perf_counter() - t0
            if elapsed >= seconds:
                report.halted_by = "wall-clock exhausted"
                break
            n += 1
            if n > self.max_ticks:
                report.halted_by = "max_ticks reached"
                break
            tr = self.tick(n)
            report.per_tick.append(tr)
            report.ticks = n
            report.total_events += tr.events_posted

        report.seconds_elapsed = time.perf_counter() - t0
        return report

    # ---- arbitration ----

    def critique_pending_findings(self) -> int:
        """Return count of findings whose critique_status is still pending.
        Used by the coordinator to refuse termination while pending."""
        rows = self.bb.read(
            engagement=self.engagement_id, kinds=["finding"],
        )
        pending = 0
        for r in rows:
            if r.payload.get("critique_status", "pending") == "pending":
                pending += 1
        return pending
