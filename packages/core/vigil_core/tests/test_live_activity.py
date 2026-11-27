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
    # the cursor: only rows AFTER `since` come back (incremental delivery)
    assert [r["seq"] for r in la.read(base, "eng1", since=1)] == [2]
    assert la.read(base, "eng1", since=3) == []


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
