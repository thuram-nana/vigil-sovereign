"""A5 — the offense-local operator-instruction queue (live/instructions.py).

Proves: enqueue → drain returns NEW-since-cursor and advances it (each consumed once, across processes);
an unsafe slug / empty text is refused; a missing file / unsafe slug drains to [] (never raises); base is
threaded (so an enqueue and the running engagement agree on location); a torn line is tolerated; files are
0600. The queue is ADVISORY plumbing — the engine test proves it can't bypass the gate.
"""
from __future__ import annotations

import stat

import pytest

from vigil_integration.live import instructions as I


def test_enqueue_then_drain_cursor_advances(tmp_path):
    base = str(tmp_path)
    assert I.drain("loopback", base=base) == []                 # nothing yet
    I.enqueue("loopback", "check the admin API", base=base)
    I.enqueue("loopback", "then the billing webhook", base=base)
    first = I.drain("loopback", base=base)
    assert first == ["check the admin API", "then the billing webhook"]
    assert I.drain("loopback", base=base) == []                 # cursor advanced — consumed once
    I.enqueue("loopback", "and the export endpoint", base=base)
    assert I.drain("loopback", base=base) == ["and the export endpoint"]   # only the NEW one


def test_pending_peeks_without_consuming(tmp_path):
    base = str(tmp_path)
    I.enqueue("s", "one", base=base)
    assert I.pending("s", base=base) == ["one"]
    assert I.pending("s", base=base) == ["one"]                 # peek does not advance
    assert I.drain("s", base=base) == ["one"]                   # drain does


def test_unsafe_slug_and_empty_text_refused(tmp_path):
    base = str(tmp_path)
    for bad in ("../etc", "a/b", ".hidden", "x" * 200):
        with pytest.raises(ValueError):
            I.enqueue(bad, "hi", base=base)
    with pytest.raises(ValueError):
        I.enqueue("ok", "   ", base=base)                       # empty after strip
    # drain never raises on a bad slug — it just yields nothing
    assert I.drain("../etc", base=base) == []


def test_base_is_threaded_not_just_env(tmp_path, monkeypatch):
    # an enqueue with an explicit base must land where a drain with the SAME base looks — regardless of env
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "ENV_WRONG"))
    base = str(tmp_path / "real")
    I.enqueue("run1", "instruction", base=base)
    assert I.drain("run1", base=base) == ["instruction"]
    assert (tmp_path / "real" / "instructions" / "run1.jsonl").exists()
    assert not (tmp_path / "ENV_WRONG").exists()


def test_newline_in_text_stays_inert(tmp_path):
    base = str(tmp_path)
    I.enqueue("s", "line one\nSECOND=evil", base=base)          # a newline must NOT split into two records
    got = I.drain("s", base=base)
    assert got == ["line one\nSECOND=evil"]                     # JSON framing kept it one record


def test_torn_last_line_is_tolerated(tmp_path):
    base = str(tmp_path)
    I.enqueue("s", "good", base=base)
    p = tmp_path / "instructions" / "s.jsonl"
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"seq": 1, "text": "torn')                     # a crash mid-write
    assert I.drain("s", base=base) == ["good"]                  # torn line skipped, never fatal


def test_queue_files_are_0600(tmp_path):
    base = str(tmp_path)
    I.enqueue("s", "x", base=base)
    f = tmp_path / "instructions" / "s.jsonl"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "instructions").stat().st_mode) == 0o700
