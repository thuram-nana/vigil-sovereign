"""
intel.scheduler — a PURE, tick-driven schedule for the vuln-intel feed (K1).

Deliberately NOT a daemon: no thread, no ``sleep``, no wallclock. The orchestrator owns the loop and
calls ``run_once`` on each of its own monotonic ticks; ``due()`` is a pure predicate over the injected
tick. That keeps the feed STOPPABLE (the orchestrator just stops calling — nothing lingers) and
DETERMINISTIC (a schedule is a value advanced by returning a new one, never mutated by a wall clock).
"""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class FeedSchedule:
    """A refresh cadence measured in monotonic ticks (seq units), not seconds.

    ``last_run < 0`` means 'never run' → due immediately. A non-positive ``interval`` disables the
    schedule (never due). Immutable: ``advance`` returns a new schedule rather than mutating.
    """

    interval: int                     # ticks between refreshes; < 1 disables the schedule
    last_run: int = -1

    def due(self, now: int) -> bool:
        if self.interval < 1:
            return False
        return self.last_run < 0 or (int(now) - self.last_run) >= self.interval

    def advance(self, now: int) -> "FeedSchedule":
        return replace(self, last_run=int(now))


@dataclass
class TickResult:
    ran: bool
    schedule: FeedSchedule
    result: object | None = None       # whatever `refresh` returned, when it ran


def run_once(schedule: FeedSchedule, now: int, *, refresh, cancel=None) -> TickResult:
    """One scheduler tick.

    If ``cancel()`` is tripped or the schedule is not ``due(now)``, do nothing (idle-cheap and stoppable).
    Otherwise run ``refresh()`` and advance the schedule to ``now``. Pure orchestration — the caller
    supplies both the tick and the ``refresh`` thunk, so there is no hidden clock or background work.
    """
    cancel = cancel or (lambda: False)
    if cancel() or not schedule.due(now):
        return TickResult(ran=False, schedule=schedule)
    result = refresh()
    return TickResult(ran=True, schedule=schedule.advance(now), result=result)
