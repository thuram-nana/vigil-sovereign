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

Restart resume (RESUME CHECKPOINT). The daemon's tick counter resets to 0 every process start, so a naive
restart reads ``last_run=-1`` ("never run → due immediately") and fires an immediate pull no matter how
recently the last real pull happened. To resume the REAL cadence, the daemon persists a tiny WALL-CLOCK
checkpoint per feed (``last_run`` / ``next_run`` seconds since epoch) under the live dir and, on start, loads
it and translates it back into tick space via the pure ``scheduler.resume_plan`` (clock injected — the
schedule math never reads a wall clock). TOTAL / fail-open: a missing/broken checkpoint, or ANY persist
failure, degrades to the pre-existing "due immediately" behaviour and never raises. The checkpoint records
STATE only — it never mints or promotes a finding.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable, Optional

from . import scheduler
from .scheduler import TickResult, run_once


def default_schedule_path() -> Path:
    """The live-dir JSON checkpoint the feed daemon persists its schedule to.

    Mirrors the console's live-dir convention: ``$VIGIL_LIVE_DIR`` (what ``vigil up`` exports) or the
    ``.vigil-live`` default, under ``live-ui/`` beside the other feed sidecars. Pure path construction —
    it touches no disk here; every read/write of the file is wrapped fail-open at its call site.
    """
    base = (os.environ.get("VIGIL_LIVE_DIR") or "").strip() or ".vigil-live"
    return Path(base).expanduser() / "live-ui" / "feed-schedule.json"


def _safe_now(now_wall: Callable[[], float]) -> Optional[float]:
    """Read the injected wall clock, or ``None`` if it misbehaves — so a broken clock can never raise
    into the loop (resume then falls back to fire-now; a save is simply skipped)."""
    try:
        return float(now_wall())
    except Exception:                                     # noqa: BLE001 — a clock read must never break the loop
        return None


def load_checkpoint(state_path: Optional[Path], feed_id: str) -> "scheduler.ScheduleCheckpoint | None":
    """Read ``feed_id``'s persisted checkpoint from ``state_path``. TOTAL / fail-open: a disabled path, a
    missing file, a parse error, or an unknown feed all return ``None`` — which ``resume_plan`` treats as the
    current 'due immediately' behaviour. Never raises."""
    if state_path is None:
        return None
    try:
        doc = json.loads(Path(state_path).read_text(encoding="utf-8"))
        feeds = doc.get("feeds") if isinstance(doc, dict) else None
        entry = feeds.get(str(feed_id)) if isinstance(feeds, dict) else None
        return scheduler.ScheduleCheckpoint.from_json(entry)
    except Exception:                                     # noqa: BLE001 — a broken checkpoint is a no-op, never a crash
        return None


def save_checkpoint(
    state_path: Optional[Path],
    feed_id: str,
    *,
    last_run: Optional[float],
    interval_seconds: float,
) -> bool:
    """Persist ``feed_id``'s wall-clock checkpoint (``last_run`` / ``next_run``) under the live dir.

    TOTAL / fail-open: returns ``True`` on a successful write and ``False`` on ANY problem (disabled path,
    no timestamp, unwritable dir, a raise anywhere) — a persist failure is a recorded no-op, NEVER an abort
    of the refresh that just succeeded. Read-modify-writes so multiple feeds share one file, and swaps via a
    temp file + atomic rename so a crash mid-write never leaves a torn checkpoint.
    """
    if state_path is None or last_run is None:
        return False
    try:
        p = Path(state_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                doc = {}
        except (OSError, ValueError):
            doc = {}
        feeds = doc.get("feeds")
        if not isinstance(feeds, dict):
            feeds = {}
        cp = scheduler.ScheduleCheckpoint(
            last_run=float(last_run),
            interval_seconds=float(interval_seconds),
            next_run=float(last_run) + float(interval_seconds),
        )
        feeds[str(feed_id)] = cp.to_json()
        doc["feeds"] = feeds
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, p)                                # atomic swap — no torn file on a crash mid-write
        return True
    except Exception:                                     # noqa: BLE001 — persistence is best-effort; degrade, never raise
        return False


def run_feed_daemon(
    *,
    interval_ticks: int,
    poll_seconds: float,
    refresh: Callable[[], object],
    cancel: Optional[Callable[[], bool]] = None,
    on_tick: Optional[Callable[[int, TickResult], None]] = None,
    max_ticks: Optional[int] = None,
    sleep: Callable[[float], None] = time.sleep,
    state_path: Optional[Path] = None,
    feed_id: str = "default",
    now_wall: Callable[[], float] = time.time,
) -> dict:
    """Tick ``run_once`` forever (or ``max_ticks`` times) at a ``poll_seconds`` cadence.

    A refresh fires only when the ``FeedSchedule`` is due; ``on_tick(tick, result)`` (if given) observes
    every tick so the caller can log the ones that ran. Returns a summary ``{"ticks", "refreshes"}`` where
    ``ticks`` counts iterations THIS run. Stops cleanly the moment ``cancel()`` trips — no lingering work.

    Resume (RESUME CHECKPOINT). When ``state_path`` is given, the daemon loads ``feed_id``'s persisted
    wall-clock checkpoint and resumes the REAL cadence instead of firing immediately: ``scheduler.resume_plan``
    (pure, ``now_wall`` injected) chooses the initial schedule and the starting tick offset. After each
    refresh that actually RAN, it persists a fresh checkpoint. Both the load and every save are fail-open —
    any failure degrades to the current 'due immediately' behaviour and never breaks the loop. When
    ``state_path`` is ``None`` (the default) persistence is off and behaviour is byte-identical to before.
    """
    cancel = cancel or (lambda: False)
    interval = max(1, int(interval_ticks))

    # --- resume: translate the persisted wall-clock checkpoint back into this run's tick space (fail-open) ---
    now_val = _safe_now(now_wall)
    # A missing/broken checkpoint OR a misbehaving clock both degrade to fire-now (the pre-existing behaviour).
    checkpoint = load_checkpoint(state_path, feed_id) if now_val is not None else None
    plan = scheduler.resume_plan(interval, poll_seconds, checkpoint, now_val if now_val is not None else 0.0)
    schedule = plan.schedule
    tick = plan.start_tick
    interval_seconds = float(interval) * max(0.0, float(poll_seconds))

    ticks_run = 0
    refreshes = 0
    while max_ticks is None or ticks_run < max_ticks:
        if cancel():
            break
        result = run_once(schedule, tick, refresh=refresh, cancel=cancel)
        schedule = result.schedule
        if result.ran:
            refreshes += 1
            # RESUME CHECKPOINT: record the real time of this pull so a restart resumes the cadence.
            save_checkpoint(state_path, feed_id, last_run=_safe_now(now_wall), interval_seconds=interval_seconds)
        if on_tick is not None:
            on_tick(tick, result)
        tick += 1
        ticks_run += 1
        if max_ticks is not None and ticks_run >= max_ticks:
            break
        if cancel():                                  # re-check before sleeping so a STOP doesn't wait a poll
            break
        sleep(max(0.0, float(poll_seconds)))
    return {"ticks": ticks_run, "refreshes": refreshes}
