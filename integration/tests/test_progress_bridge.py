"""W6c — the offense child's progress bridge: WARDEN blocks and Strix graph activity reach the console's
live process box via ``$VIGIL_PROOF_RUN_DIR/progress.jsonl`` (the file ``/api/events?run=`` already tails).

The invariants under test:
  * a block is SURFACED (gate + what was refused + why + fatal), so "blocked by WARDEN, because X" is visible;
  * surfacing is BEST-EFFORT — a feed failure never breaks the run, and never turns a block into an allow;
  * an ALLOWED call emits nothing (negative control — the box must not show a phantom block);
  * the Strix summary leaks no agent ids/names/metadata — only a status histogram.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import time

import pytest

from vigil_integration.progress import append_progress, strix_graph_event
from vigil_integration.warden_gate import WardenDenied, WardenGateHooks

ENV = "VIGIL_PROOF_RUN_DIR"


def _stub(table):
    return lambda name: table.get(name, "A3")


class _FakeTool:
    def __init__(self, name):
        self.name = name


def _lines(d):
    p = os.path.join(str(d), "progress.jsonl")
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


# --- append_progress: writes, and fails SILENTLY ---------------------------------------------------
def test_append_progress_writes_one_json_line_per_event(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    assert append_progress({"event": "a", "n": 1}) is True
    assert append_progress({"event": "b"}) is True
    got = _lines(tmp_path)
    assert [g["event"] for g in got] == ["a", "b"], "appends must not truncate a prior line"
    assert got[0]["n"] == 1


def test_append_progress_is_a_silent_noop_without_a_run_dir(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert append_progress({"event": "a"}) is False          # no console run dir → nothing to feed
    monkeypatch.setenv(ENV, str(tmp_path / "does-not-exist"))
    assert append_progress({"event": "a"}) is False          # unwritable path → silent, no raise


class _Blocked(BaseException):
    """Deliberately a BaseException, NOT an Exception: ``append_progress`` catches ``Exception`` and
    returns False, so an Exception-derived timeout would be SWALLOWED by the code under test and the
    assertion `is False` would pass — the test would green-wash the very hang it exists to catch.
    (Verified: with an AssertionError timeout, a mutant dropping O_NONBLOCK passed 19/19.)"""


@contextlib.contextmanager
def _deadline(seconds=3):
    """Turn a HANG into a test FAILURE. Without this, a regression on "telemetry never blocks the gate"
    surfaces only as a CI job that runs to the runner limit with no pytest output — a far weaker signal
    than a red test (red-pen MEDIUM-2)."""
    def _fire(_sig, _frm):
        raise _Blocked("append_progress BLOCKED — telemetry must never delay a WARDEN refusal")
    old = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    started = time.monotonic()
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    # belt-and-braces: even if a future refactor swallows the signal, a slow call still fails here.
    assert time.monotonic() - started < seconds, "append_progress took too long — it blocked"


def test_append_progress_never_blocks_on_a_fifo(tmp_path, monkeypatch):
    """A FIFO planted at progress.jsonl must NOT wedge the writer. The WARDEN gate emits BEFORE it raises,
    so a blocking open here would hang the refusal itself — telemetry altering the gate (red-pen BLOCK-3).
    The call must return promptly and falsely-claim nothing."""
    monkeypatch.setenv(ENV, str(tmp_path))
    os.mkfifo(os.path.join(str(tmp_path), "progress.jsonl"))   # no reader attached
    with _deadline():
        assert append_progress({"event": "warden.block"}) is False  # returns — does not hang


def test_append_progress_refuses_a_fifo_that_HAS_a_reader(tmp_path, monkeypatch):
    """The case the open flags do NOT cover: with a reader attached, O_NONBLOCK opens the FIFO happily —
    only the fstat S_ISREG check stops the write. Without that check this test's bytes would land in the
    pipe instead of a file (red-pen BLOCK-2: a mutant deleting S_ISREG passed the whole suite)."""
    monkeypatch.setenv(ENV, str(tmp_path))
    fifo = os.path.join(str(tmp_path), "progress.jsonl")
    os.mkfifo(fifo)
    rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)      # attach a reader
    try:
        with _deadline():
            assert append_progress({"event": "warden.block"}) is False
        try:
            spilled = os.read(rfd, 4096)
        except BlockingIOError:
            spilled = b""
        assert spilled == b"", "the event was written into a FIFO instead of being refused"
    finally:
        os.close(rfd)


def test_append_progress_refuses_a_hardlink(tmp_path, monkeypatch):
    """A hardlink is a real regular file, so O_NOFOLLOW and S_ISREG both pass it — st_nlink is what
    refuses it, so these appends can't be redirected into a second name for the same inode."""
    monkeypatch.setenv(ENV, str(tmp_path))
    victim = tmp_path / "victim.txt"
    victim.write_text("original\n", encoding="utf-8")
    os.link(str(victim), os.path.join(str(tmp_path), "progress.jsonl"))
    assert append_progress({"event": "warden.block"}) is False
    assert victim.read_text(encoding="utf-8") == "original\n", "the append wrote through a hardlink"


def test_warden_block_fields_are_bounded(tmp_path, monkeypatch):
    """action_refused/reason are rendered by the UI — an SDK tool repr or a long reason must not ride in
    unbounded (red-pen L-2/L-3: dropping either cap left the suite green)."""
    monkeypatch.setenv(ENV, str(tmp_path))
    huge = "T" * 5000
    hooks = WardenGateHooks(classify=_stub({huge: "A3"}), denylist=[huge])
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool(huge)))
    (ev,) = _lines(tmp_path)
    assert len(ev["action_refused"]) <= 120
    assert len(ev["reason"]) <= 400


def test_append_progress_refuses_to_follow_a_symlink(tmp_path, monkeypatch):
    """A symlink at progress.jsonl must not redirect the child's appends to another path."""
    monkeypatch.setenv(ENV, str(tmp_path))
    victim = tmp_path / "victim.txt"
    victim.write_text("original", encoding="utf-8")
    os.symlink(str(victim), os.path.join(str(tmp_path), "progress.jsonl"))
    assert append_progress({"event": "warden.block"}) is False
    assert victim.read_text(encoding="utf-8") == "original", "the append followed a symlink"


def test_append_progress_escapes_every_line_terminator(tmp_path, monkeypatch):
    """One event = one line for EVERY reader. U+2028/U+2029/U+0085 are not newlines to split("\\n") (the
    SSE tailer) but ARE to splitlines() (other readers) — so they must be escaped, not written raw."""
    monkeypatch.setenv(ENV, str(tmp_path))
    nasty = "a\u2028b\u2029c\u0085d\ne"   # LS, PS, NEL, and a real newline
    assert append_progress({"event": "warden.block", "reason": nasty}) is True
    raw = (tmp_path / "progress.jsonl").read_text(encoding="utf-8")
    assert len(raw.splitlines()) == 1, "a payload split one event across multiple lines"
    assert json.loads(raw)["reason"] == nasty, "escaping must round-trip the value intact"


def test_append_progress_rejects_non_mappings_and_oversized_payloads(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    assert append_progress("not-a-mapping") is False         # type: ignore[arg-type]
    assert append_progress({"event": "big", "blob": "x" * 40000}) is False   # dropped, not torn
    assert _lines(tmp_path) == []


# --- WARDEN blocks are surfaced -------------------------------------------------------------------
def test_warden_hard_deny_is_surfaced_as_a_fatal_block(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"rm_rf": "A3"}), denylist=["rm_rf"])
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("rm_rf")))
    (ev,) = _lines(tmp_path)
    assert ev["event"] == "warden.block" and ev["gate"] == "warden"
    assert ev["action_refused"] == "rm_rf"
    assert ev["fatal"] is True                      # a hard class deny never runs
    assert ev["reason"], "a block with no reason tells the operator nothing"


def test_warden_queue_block_is_surfaced_as_non_fatal(tmp_path, monkeypatch):
    """A QUEUE block (no approval authority) is approvable — it must NOT read as a fatal deny."""
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3"}))   # no approver → fail-safe block
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))
    (ev,) = _lines(tmp_path)
    assert ev["action_refused"] == "exec_command" and ev["outcome"] == "queue"
    assert ev["fatal"] is False
    assert "authority" in ev["reason"]


def test_warden_block_from_a_RAISING_approver_is_surfaced(tmp_path, monkeypatch):
    """The 4th block site: the approval broker itself errored → fail-closed block. This is the case an
    operator is least able to diagnose unaided, so it must not be a SILENT block. (Red-pen MEDIUM-1: a
    mutant deleting this emit previously escaped the whole suite.)"""
    monkeypatch.setenv(ENV, str(tmp_path))

    def _boom_approver(*_a):
        raise RuntimeError("broker down")

    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3"}), approver=_boom_approver)
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))
    (ev,) = _lines(tmp_path)
    assert ev["event"] == "warden.block" and ev["action_refused"] == "exec_command"
    assert "RuntimeError" in ev["reason"] and "fail-closed" in ev["reason"]


def test_warden_denied_by_approver_is_surfaced(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3"}), approver=lambda *_a: False)
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))
    (ev,) = _lines(tmp_path)
    assert ev["event"] == "warden.block" and ev["action_refused"] == "exec_command"


# --- NEGATIVE CONTROLS: no phantom blocks, and the feed never weakens the gate ---------------------
def test_an_allowed_call_emits_no_block(tmp_path, monkeypatch):
    """The box must never show a block for a call that RAN — the phantom-block negative control."""
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"http.get": "A0"}), floor="A1", ceiling="A1")
    asyncio.run(hooks.on_tool_start(None, None, _FakeTool("http.get")))   # auto → no raise
    assert _lines(tmp_path) == []


def test_an_approved_call_emits_no_block(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3"}), approver=lambda *_a: True)
    asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))   # owner-approved → ran
    assert _lines(tmp_path) == []


def test_a_broken_feed_still_blocks(tmp_path, monkeypatch):
    """FAIL-SAFE: if surfacing the block raises, the BLOCK still happens. Telemetry must never be able to
    turn a refusal into an allow."""
    monkeypatch.setenv(ENV, str(tmp_path))
    import vigil_integration.warden_gate as wg

    def _boom(*_a, **_k):
        raise OSError("feed exploded")

    monkeypatch.setattr(wg, "append_progress", _boom)
    hooks = WardenGateHooks(classify=_stub({"rm_rf": "A3"}), denylist=["rm_rf"])
    with pytest.raises(WardenDenied):        # still refused
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("rm_rf")))


def test_no_run_dir_means_no_feed_but_still_blocks(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    hooks = WardenGateHooks(classify=_stub({"rm_rf": "A3"}), denylist=["rm_rf"])
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("rm_rf")))


# --- Strix graph summary: a histogram, never identities -------------------------------------------
def test_strix_graph_event_is_a_histogram_only():
    snap = {"statuses": {"a1": "running", "a2": "running", "a3": "done"},
            "names": {"a1": "sqli-hunter"}, "metadata": {"a1": {"secret": "s3cret"}}}
    ev = strix_graph_event(snap)
    assert ev == {"event": "strix.graph", "agents": 3, "statuses": {"running": 2, "done": 1}}
    blob = json.dumps(ev)
    assert "sqli-hunter" not in blob and "s3cret" not in blob and "a1" not in blob


def test_strix_graph_event_handles_empty_and_junk():
    assert strix_graph_event(None) is None
    assert strix_graph_event({}) is None
    assert strix_graph_event({"statuses": "not-a-map"}) is None      # type: ignore[arg-type]
    assert strix_graph_event({"statuses": {}}) == {"event": "strix.graph", "agents": 0, "statuses": {}}
