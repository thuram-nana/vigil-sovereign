"""
K1 feed-daemon schedule RESUME CHECKPOINT — the persistence that stops a restart firing an immediate pull.

Proves the three properties the slice must have:
  (a) PERSIST      — a refresh writes a wall-clock checkpoint (last_run / next_run / interval_seconds) under
                     the live dir, keyed per feed.
  (b) RESUME/SKIP  — on restart the daemon resumes the REAL cadence: within the interval it does NOT re-fire
                     the already-done pull (idempotent — no double-execute); once the interval has elapsed it
                     fires. The tick math is pure with an INJECTED clock.
  (c) FAIL-OPEN    — a missing/broken checkpoint, an unwritable path, or an IO raise mid-save all degrade to
                     the pre-existing 'due immediately' behaviour and NEVER raise.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.intel import ticker
from framework.v2.intel.scheduler import (
    FeedSchedule,
    ScheduleCheckpoint,
    resume_plan,
)


# ---- (b) pure resume math: injected clock, no wallclock, deterministic ----------------------------

def test_resume_plan_no_checkpoint_fires_now():
    plan = resume_plan(interval_ticks=5, poll_seconds=10, checkpoint=None, now_wall=1000.0)
    assert plan.start_tick == 0
    assert plan.schedule == FeedSchedule(interval=5, last_run=-1)
    assert plan.schedule.due(0) is True                     # fire-now == the pre-existing behaviour


def test_resume_plan_within_interval_offsets_the_start_tick_and_is_not_due_now():
    # persisted 25s ago on a 50s cadence (5 ticks * 10s/poll) → 25s remaining → 3 ticks remaining.
    cp = ScheduleCheckpoint(last_run=1000.0, interval_seconds=50.0, next_run=1050.0)
    plan = resume_plan(interval_ticks=5, poll_seconds=10, checkpoint=cp, now_wall=1025.0)
    assert plan.schedule == FeedSchedule(interval=5, last_run=0)
    assert plan.start_tick == 2                             # 5 - ceil(25/10) = 5 - 3 = 2
    # NOT due at the resumed start tick — no spurious immediate pull — but due when the cadence elapses.
    assert plan.schedule.due(plan.start_tick) is False
    assert plan.schedule.due(5) is True


def test_resume_plan_overdue_fires_now():
    cp = ScheduleCheckpoint(last_run=1000.0, interval_seconds=50.0, next_run=1050.0)
    plan = resume_plan(interval_ticks=5, poll_seconds=10, checkpoint=cp, now_wall=1100.0)  # 100s > 50s
    assert plan.start_tick == 0 and plan.schedule.due(0) is True


def test_resume_plan_clock_skew_backwards_never_fires_early_and_start_tick_is_bounded():
    # now BEFORE last_run (clock moved back): treat as no time passed → full interval still to wait.
    cp = ScheduleCheckpoint(last_run=1000.0, interval_seconds=50.0, next_run=1050.0)
    plan = resume_plan(interval_ticks=5, poll_seconds=10, checkpoint=cp, now_wall=900.0)
    assert 0 <= plan.start_tick <= 4                        # always in [0, interval-1], never negative
    assert plan.schedule.due(plan.start_tick) is False      # does not fire immediately on a backwards clock


def test_resume_plan_is_pure_and_deterministic():
    cp = ScheduleCheckpoint(last_run=1000.0, interval_seconds=50.0, next_run=1050.0)
    a = resume_plan(interval_ticks=5, poll_seconds=10, checkpoint=cp, now_wall=1025.0)
    b = resume_plan(interval_ticks=5, poll_seconds=10, checkpoint=cp, now_wall=1025.0)
    assert a == b                                           # same inputs → same output; reads no clock/rng


def test_schedule_checkpoint_roundtrips_and_rejects_garbage():
    cp = ScheduleCheckpoint(last_run=1000.0, interval_seconds=50.0, next_run=1050.0)
    assert ScheduleCheckpoint.from_json(cp.to_json()) == cp
    assert ScheduleCheckpoint.from_json(None) is None
    assert ScheduleCheckpoint.from_json({"interval_seconds": 50}) is None     # missing last_run
    assert ScheduleCheckpoint.from_json({"last_run": "nope", "interval_seconds": 50}) is None


# ---- (a) PERSIST: a refresh writes the checkpoint under the live dir, keyed per feed --------------

def _run(state_path, *, now, max_ticks, feed_id="default", interval_ticks=5, poll_seconds=10):
    calls = []
    summary = ticker.run_feed_daemon(
        interval_ticks=interval_ticks, poll_seconds=poll_seconds,
        refresh=lambda: calls.append(1) or "r",
        max_ticks=max_ticks, sleep=lambda _s: None,
        state_path=state_path, feed_id=feed_id, now_wall=lambda: now)
    return summary, calls


def test_persist_writes_the_wall_clock_checkpoint(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    summary, calls = _run(sp, now=1000.0, max_ticks=1)
    assert summary == {"ticks": 1, "refreshes": 1} and len(calls) == 1
    assert sp.exists()
    doc = json.loads(sp.read_text(encoding="utf-8"))
    entry = doc["feeds"]["default"]
    assert entry["last_run"] == 1000.0
    assert entry["interval_seconds"] == 50.0               # 5 ticks * 10s poll
    assert entry["next_run"] == 1050.0                     # last_run + interval_seconds
    assert not list(tmp_path.glob("**/*.tmp"))             # atomic swap left no torn temp behind


def test_persist_keeps_distinct_feeds_separate(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    _run(sp, now=1000.0, max_ticks=1, feed_id="a1:nvd")
    _run(sp, now=2000.0, max_ticks=1, feed_id="a2:osv")
    doc = json.loads(sp.read_text(encoding="utf-8"))
    assert doc["feeds"]["a1:nvd"]["last_run"] == 1000.0    # second feed did not clobber the first
    assert doc["feeds"]["a2:osv"]["last_run"] == 2000.0


# ---- (b) RESUME: a restart continues the cadence and SKIPS the already-done pull ------------------

def test_resume_within_interval_does_not_refire_the_done_pull(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    # run 1 (fresh): fires once and persists last_run=1000 on a 50s cadence.
    s1, _ = _run(sp, now=1000.0, max_ticks=1)
    assert s1["refreshes"] == 1

    # run 2 (restart 25s later, still inside the interval): resumes → does NOT re-fire the done pull.
    s2, calls2 = _run(sp, now=1025.0, max_ticks=3)
    assert s2 == {"ticks": 3, "refreshes": 0} and calls2 == []   # idempotent: no double-execute


def test_resume_fires_again_once_the_cadence_elapses(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    _run(sp, now=1000.0, max_ticks=1)                       # persists last_run=1000
    # restart 25s in, run long enough to REACH the resumed due tick (start_tick 2 → due at tick 5).
    s2, calls2 = _run(sp, now=1025.0, max_ticks=4)
    assert s2["refreshes"] == 1 and len(calls2) == 1        # fires on the real cadence, not immediately


def test_resume_after_full_interval_fires_immediately(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    _run(sp, now=1000.0, max_ticks=1)                       # persists last_run=1000
    s2, calls2 = _run(sp, now=1050.0, max_ticks=1)          # exactly one interval later → overdue
    assert s2["refreshes"] == 1 and len(calls2) == 1


# ---- (c) FAIL-OPEN: broken file / unwritable path / IO raise never break the daemon --------------

def test_fail_open_broken_checkpoint_file_degrades_to_fire_now(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text("{ this is not valid json", encoding="utf-8")
    assert ticker.load_checkpoint(sp, "default") is None    # parse error → no checkpoint, no raise
    s, calls = _run(sp, now=1000.0, max_ticks=1)
    assert s == {"ticks": 1, "refreshes": 1} and len(calls) == 1   # degraded to due-immediately


def test_fail_open_unknown_feed_id_returns_none(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    _run(sp, now=1000.0, max_ticks=1, feed_id="present")
    assert ticker.load_checkpoint(sp, "absent") is None     # a feed not in the file is a no-op, not a raise


def test_fail_open_unwritable_path_is_a_recorded_noop(tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("x", encoding="utf-8")               # parent of the checkpoint is a FILE → mkdir fails
    sp = blocker / "feed-schedule.json"
    assert ticker.save_checkpoint(sp, "default", last_run=1000.0, interval_seconds=50.0) is False
    # the daemon still runs to completion despite the persist being impossible — never aborts the refresh.
    s, calls = _run(sp, now=1000.0, max_ticks=1)
    assert s == {"ticks": 1, "refreshes": 1} and len(calls) == 1


def test_fail_open_io_raise_mid_save_does_not_break_the_loop(tmp_path, monkeypatch):
    sp = tmp_path / "live-ui" / "feed-schedule.json"

    def _boom(*_a, **_k):
        raise OSError("disk gone mid-write")

    monkeypatch.setattr(ticker.os, "replace", _boom)        # the atomic swap explodes
    s, calls = _run(sp, now=1000.0, max_ticks=1)            # daemon must survive and still report the refresh
    assert s == {"ticks": 1, "refreshes": 1} and len(calls) == 1
    assert not sp.exists()                                   # the failed save left no committed file


def test_fail_open_missing_now_clock_degrades_to_fire_now(tmp_path):
    sp = tmp_path / "live-ui" / "feed-schedule.json"
    _run(sp, now=1000.0, max_ticks=1)                       # a valid checkpoint exists

    def _bad_clock():
        raise RuntimeError("no clock")

    # even WITH a checkpoint, a broken clock degrades to fire-now rather than raising or waiting wrongly.
    calls = []
    s = ticker.run_feed_daemon(
        interval_ticks=5, poll_seconds=10, refresh=lambda: calls.append(1),
        max_ticks=1, sleep=lambda _s: None, state_path=sp, now_wall=_bad_clock)
    assert s["refreshes"] == 1 and len(calls) == 1


# ---- persistence OFF (state_path=None) is byte-identical to the pre-checkpoint behaviour ----------

def test_persistence_off_matches_legacy_behaviour_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                             # so a stray relative write would show up here
    calls = []
    s = ticker.run_feed_daemon(
        interval_ticks=3, poll_seconds=0, refresh=lambda: calls.append(1) or "r",
        max_ticks=7, sleep=lambda _s: None)                # no state_path → persistence disabled
    assert s == {"ticks": 7, "refreshes": 3} and len(calls) == 3
    assert not list(tmp_path.rglob("feed-schedule.json"))  # nothing persisted when off
