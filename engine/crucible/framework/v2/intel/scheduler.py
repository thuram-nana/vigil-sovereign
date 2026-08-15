"""
intel.scheduler — a PURE, tick-driven schedule for the vuln-intel feed (K1).

Deliberately NOT a daemon: no thread, no ``sleep``, no wallclock. The orchestrator owns the loop and
calls ``run_once`` on each of its own monotonic ticks; ``due()`` is a pure predicate over the injected
tick. That keeps the feed STOPPABLE (the orchestrator just stops calling — nothing lingers) and
DETERMINISTIC (a schedule is a value advanced by returning a new one, never mutated by a wall clock).
"""

from __future__ import annotations

import math
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


# ---- resume checkpoint: persist REAL cadence across a daemon restart ------------------------------
#
# ``FeedSchedule`` is measured in the daemon's MONOTONIC ticks, which reset to 0 every process start.
# So on restart ``last_run=-1`` reads as "never run → due immediately" and every restart fires a pull,
# regardless of how recently the last real pull happened. To resume the REAL cadence we persist a small
# WALL-CLOCK checkpoint (seconds since epoch) per feed and, on start, translate it back into the daemon's
# tick space with a pure, clock-injected function. This module stays pure — it never reads a clock; the
# daemon injects ``now_wall``. The checkpoint records STATE only; it never mints or promotes a finding.


@dataclass(frozen=True)
class ScheduleCheckpoint:
    """One feed's persisted wall-clock schedule state (seconds since epoch).

    ``last_run`` is when the last real refresh fired; ``interval_seconds`` is the cadence at persist time;
    ``next_run`` is informational (``last_run + interval_seconds``). A ``last_run < 0`` (or a non-positive
    ``interval_seconds``) means "unknown" and is treated as fire-now on resume — the fail-open default.
    """

    last_run: float
    interval_seconds: float
    next_run: float = -1.0

    def to_json(self) -> dict:
        return {
            "last_run": self.last_run,
            "interval_seconds": self.interval_seconds,
            "next_run": self.next_run,
        }

    @classmethod
    def from_json(cls, doc: object) -> "ScheduleCheckpoint | None":
        """Parse a persisted entry, or ``None`` if it is missing/malformed (caller then falls back to
        fire-now). Total: never raises on a broken/foreign document — a bad checkpoint is a no-op.

        Non-finite floats are treated as MALFORMED and rejected. ``float()`` accepts ``nan``/``inf``, and
        ``json.loads`` accepts the bare JSON tokens ``NaN``/``Infinity`` by default, so a torn or tampered
        checkpoint can carry them. They are poison downstream: ``resume_plan``'s degeneracy guard is a chain
        of ``<= 0`` / ``< 0`` comparisons, and every NaN comparison is False while ``+inf`` passes them all,
        so a non-finite value would slip past the guard and crash the daemon in the tick math. Rejecting them
        here degrades to the fail-open fire-now default instead."""
        if not isinstance(doc, dict):
            return None
        try:
            last = float(doc["last_run"])
            interval = float(doc["interval_seconds"])
        except (KeyError, TypeError, ValueError, ArithmeticError):
            # ArithmeticError covers OverflowError: a JSON int is arbitrary-precision, so a tampered
            # last_run/interval like 10**400 raises OverflowError in float() — reject it, don't crash.
            return None
        if not (math.isfinite(last) and math.isfinite(interval)):
            return None
        try:
            nxt = float(doc.get("next_run", last + interval))
        except (TypeError, ValueError, ArithmeticError):
            nxt = last + interval
        if not math.isfinite(nxt):                           # informational field; recompute if poisoned
            nxt = last + interval
        return cls(last_run=last, interval_seconds=interval, next_run=nxt)


@dataclass(frozen=True)
class ResumePlan:
    """How the daemon should start given a (possibly absent) checkpoint: the initial ``schedule`` and the
    ``start_tick`` its monotonic tick counter should begin at so the FIRST refresh lands on the real cadence.
    """

    schedule: FeedSchedule
    start_tick: int


def resume_plan(
    interval_ticks: int,
    poll_seconds: float,
    checkpoint: "ScheduleCheckpoint | None",
    now_wall: float,
) -> ResumePlan:
    """Pure: pick the daemon's initial ``(schedule, start_tick)`` from the persisted wall-clock checkpoint.

    ``now_wall`` is the injected current wall time (seconds since epoch) — this function reads NO clock, so
    it stays deterministic and testable. Behaviour:

      * No / malformed / degenerate checkpoint, or the interval already elapsed while the daemon was down
        → fire-now: ``FeedSchedule(interval, last_run=-1)`` at ``start_tick=0`` (the pre-existing behaviour).
      * Otherwise resume: start with a NOT-yet-run schedule (``last_run=0``) and offset ``start_tick`` so the
        first ``due`` tick falls exactly when the remaining real time elapses — no spurious immediate pull.

    ``start_tick`` is always in ``[0, interval-1]`` (non-negative), so ``FeedSchedule.due`` — which reads any
    negative ``last_run`` as fire-now — is never accidentally tripped.
    """
    interval = max(1, int(interval_ticks))
    fire_now = ResumePlan(schedule=FeedSchedule(interval=interval, last_run=-1), start_tick=0)
    if checkpoint is None:
        return fire_now
    try:
        poll = float(poll_seconds)
        interval_seconds = float(checkpoint.interval_seconds)
        last = float(checkpoint.last_run)
        now = float(now_wall)
    except (TypeError, ValueError):
        return fire_now
    if poll <= 0 or interval_seconds <= 0 or last < 0:
        return fire_now
    elapsed = now - last
    if elapsed < 0:                          # clock skew / restored back-in-time → treat as no time passed
        elapsed = 0.0
    remaining = interval_seconds - elapsed
    if remaining <= 0:                       # cadence elapsed while we were down → genuinely due, fire now
        return fire_now
    ticks_remaining = max(1, math.ceil(remaining / poll))
    ticks_remaining = min(ticks_remaining, interval)          # clamp: never wait past one current interval
    start_tick = interval - ticks_remaining                  # ∈ [0, interval-1]
    return ResumePlan(schedule=FeedSchedule(interval=interval, last_run=0), start_tick=start_tick)
