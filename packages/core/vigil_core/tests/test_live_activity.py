"""vigil_core.live_activity — the customer-safe engagement activity seam (offense emits, sovereign reads).
Invariants: round-trips with friendly labels + a seq cursor; off-allowlist phase/status is DROPPED (a leak is
impossible by construction); fail-closed on missing/corrupt/oversized files and unsafe slugs."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from vigil_core import live_activity as la


def test_emit_then_read_round_trips_with_labels_and_cursor():
    base = tempfile.mkdtemp()
    la.emit(base, "eng1", "preflight", "started", ts=1.0)
    la.emit(base, "eng1", "scan", "completed", ts=2.0)
    la.emit(base, "eng1", "reasoning_pass", "completed", ts=3.0)
    rows = la.read(base, "eng1")
    assert [(r["seq"], r["phase"], r["status"]) for r in rows] == [
        (0, "preflight", "started"), (1, "scan", "completed"), (2, "reasoning_pass", "completed")]
    assert rows[1]["label"] == "Running authorized checks"          # friendly, customer-facing
    # the cursor: only rows AFTER `since` come back (incremental delivery). The real cursor is the LAST seq (2);
    # polling again with it returns nothing new. (A since BEYOND the file means the trail was reset under the
    # cursor and resyncs from the start — covered by test_a_cursor_beyond_the_reset_file_resyncs_from_the_start.)
    assert [r["seq"] for r in la.read(base, "eng1", since=1)] == [2]
    assert la.read(base, "eng1", since=2) == []


def test_off_allowlist_rows_are_never_written_or_shown():
    base = tempfile.mkdtemp()
    la.emit(base, "eng1", "scan", "completed", ts=1.0)
    la.emit(base, "eng1", "exfiltrate-secrets", "completed", ts=2.0)   # not a real phase -> ignored by emit
    la.emit(base, "eng1", "scan", "pwned", ts=3.0)                      # not a real status -> ignored by emit
    rows = la.read(base, "eng1")
    assert [r["phase"] for r in rows] == ["scan"] and [r["status"] for r in rows] == ["completed"]
    # even if a hostile line is injected directly into the file, the reader DROPS anything off the allowlist
    p = Path(base) / "eng1.activity.jsonl"
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": 9.0, "phase": "scan", "status": "completed",
                             "secret": "AKIA-leaked"}) + "\n")
    rows = la.read(base, "eng1")
    # the reader projects ONLY {seq, ts, phase, label, status} — the injected 'secret' key never surfaces
    assert all(set(r.keys()) == {"seq", "ts", "phase", "label", "status"} for r in rows)
    assert not any("secret" in r for r in rows)


def test_reset_starts_a_fresh_trail_so_the_feed_is_the_current_run():
    # the slug is per (org, host) and reused by every launch of the same host; without a reset at run start the
    # feed would show the concatenation of every past run. reset() clears the trail so the feed is the CURRENT run.
    base = tempfile.mkdtemp()
    la.emit(base, "eng1", "scan", "completed", ts=1.0)             # a previous run on this host
    la.emit(base, "eng1", "reasoning_pass", "completed", ts=2.0)
    la.reset(base, "eng1")                                         # a new run attempt begins (preflight)
    la.emit(base, "eng1", "preflight", "started", ts=3.0)
    la.emit(base, "eng1", "scan", "started", ts=4.0)
    rows = la.read(base, "eng1")
    assert [(r["seq"], r["phase"]) for r in rows] == [(0, "preflight"), (1, "scan")]   # only the current run
    la.reset(base, "never-emitted")                               # reset of a missing trail is a no-op, never raises


def test_a_cursor_beyond_the_reset_file_resyncs_from_the_start():
    # a customer polling with since=<old cursor> when the trail was reset under them (a re-assessment of the same
    # host) must resync to the new run's rows, not silently return nothing because the cursor is now out of range.
    base = tempfile.mkdtemp()
    for i, ph in enumerate(("preflight", "scan", "reasoning_pass")):
        la.emit(base, "eng1", ph, "completed", ts=float(i))
    assert [r["seq"] for r in la.read(base, "eng1")] == [0, 1, 2]   # cursor would be 2
    la.reset(base, "eng1")
    la.emit(base, "eng1", "preflight", "started", ts=9.0)
    la.emit(base, "eng1", "scan", "started", ts=10.0)
    # polling with the STALE cursor (2) from before the reset -> the new 2 rows, not [] (seq 2 is now beyond EOF)
    assert [(r["seq"], r["phase"]) for r in la.read(base, "eng1", since=2)] == [(0, "preflight"), (1, "scan")]


def test_fail_closed_on_missing_corrupt_and_unsafe():
    base = tempfile.mkdtemp()
    assert la.read(base, "never-emitted") == []                        # missing file -> []
    # a corrupt / non-dict / oversized line is skipped, not fatal
    p = Path(base) / "eng1.activity.jsonl"
    p.write_text("not json\n" + json.dumps(["a", "b"]) + "\n"
                 + json.dumps({"phase": "scan", "status": "completed", "ts": 1.0}) + "\n"
                 + "x" * 400 + "\n", encoding="utf-8")
    rows = la.read(base, "eng1")
    assert [r["phase"] for r in rows] == ["scan"]
    # an unsafe slug never resolves a path (no traversal), read is [] and emit is a no-op
    assert la.read(base, "../etc/passwd") == []
    la.emit(base, "../etc/passwd", "scan", "completed", ts=1.0)        # must not raise / must not write
    assert not (Path(base).parent / "etc").exists()
