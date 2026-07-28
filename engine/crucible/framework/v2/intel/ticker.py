"""
intel.ticker — the thin, stoppable DAEMON that drives the pure ``intel.scheduler`` on real time (K1 wiring).

``scheduler.py`` is a PURE tick predicate (``FeedSchedule.due`` / ``run_once``) with, by design, no thread,
no ``sleep``, no wallclock — so *something* has to tick it. This is that something, and nothing more: a loop
that increments a monotonic tick each ``poll`` seconds and calls ``run_once``, firing the injected
``refresh`` thunk ONLY when the schedule is due. The kill-switch/``cancel`` is checked EVERY tick (top of
loop and inside ``run_once``), so a STOP halts within one ``poll`` even between refreshes.

Determinism where it matters is preserved: the schedule math stays pure (a value advanced by returning a new
one); the only wall-time here is the injectable ``sleep`` that PACES the loop and the tick counter — neither
feeds oracle/graph/learning math. ``sleep`` and ``max_ticks`` are injectable so the loop is fully testable
without real time. Off by default: the caller only supplies a real ``refresh`` under an explicit ``--live``.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from .scheduler import FeedSchedule, TickResult, run_once


def run_feed_daemon(
    *,
    interval_ticks: int,
    poll_seconds: float,
    refresh: Callable[[], object],
    cancel: Optional[Callable[[], bool]] = None,
    on_tick: Optional[Callable[[int, TickResult], None]] = None,
    max_ticks: Optional[int] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Tick ``run_once`` forever (or ``max_ticks`` times) at a ``poll_seconds`` cadence.

    A refresh fires only when the ``FeedSchedule(interval=interval_ticks)`` is due; ``on_tick(tick, result)``
    (if given) observes every tick so the caller can log the ones that ran. Returns a summary
    ``{"ticks", "refreshes"}``. Stops cleanly the moment ``cancel()`` trips — no lingering work.
    """
    cancel = cancel or (lambda: False)
    schedule = FeedSchedule(interval=max(1, int(interval_ticks)))
    tick = 0
    refreshes = 0
    while max_ticks is None or tick < max_ticks:
        if cancel():
            break
        result = run_once(schedule, tick, refresh=refresh, cancel=cancel)
        schedule = result.schedule
        if result.ran:
            refreshes += 1
        if on_tick is not None:
            on_tick(tick, result)
        tick += 1
        if max_ticks is not None and tick >= max_ticks:
            break
        if cancel():                                  # re-check before sleeping so a STOP doesn't wait a poll
            break
        sleep(max(0.0, float(poll_seconds)))
    return {"ticks": tick, "refreshes": refreshes}
