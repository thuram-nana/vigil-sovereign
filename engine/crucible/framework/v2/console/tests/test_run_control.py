"""W4 run control — Cancel a running run; Retry (restart) / Resume (continue) a finished one.

Cancel signals the run's recorded pid and lets the run's own supervisor thread record the terminal status
(only an ORPHANED run is closed by cancel itself); retry relaunches the run's OWN recorded argv as a new
linked run — RESUMED (argv + --resume) only where the CLI supports it, RESTARTED elsewhere — re-pointing
any baked output path at the new run's dir and refusing a second concurrent run of the same slug.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from framework.v2.console import actions


@pytest.fixture()
def console_root(tmp_path, monkeypatch):
    root = tmp_path / "console"
    (root / "runs").mkdir(parents=True)
    monkeypatch.setattr(actions, "console_dir", lambda: root)
    return root


def _write(root, run_id: str, meta: dict):
    d = root / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")


def _meta(root, run_id: str) -> dict:
    return json.loads((root / "runs" / run_id / "meta.json").read_text(encoding="utf-8"))


def _safe_read(run_id):
    """Meta read tolerant of a not-yet-written file (the supervisor thread writes it async). {} if absent."""
    m = actions._read_run_meta(run_id)
    return m if isinstance(m, dict) else {}


def _wait_until(run_id, pred, tries=120):
    """Poll the run's meta until pred(meta) holds (or tries exhaust). Returns the last meta seen."""
    m = {}
    for _ in range(tries):
        m = _safe_read(run_id)
        if pred(m):
            return m
        time.sleep(0.05)
    return m


# --- cancel -------------------------------------------------------------------------------------
def test_cancel_of_a_live_run_is_recorded_cancelled_by_its_supervisor(console_root):
    # a REAL run via _spawn_background (its supervisor thread reaps the child). cancel signals it; the
    # supervisor's negative-rc path records 'cancelled' — and cancel does not race/overwrite it (BLOCK-2).
    rd = actions.run_dir("c1")
    rd.mkdir(parents=True, exist_ok=True)
    actions._spawn_background("c1", rd, [sys.executable, "-c", "import time; time.sleep(20)"],
                              {"slug": "s", "run_kind": "engage"}, capture_report=False)
    m = _wait_until("c1", lambda x: x.get("pid") and x.get("status") == "running")  # supervisor recorded pid
    assert m.get("pid")
    res = actions.cancel_run("c1")
    assert res["ok"] is True and res["status"] == "cancelled"
    assert _safe_read("c1")["status"] == "cancelled"       # sole terminal writer, not 'error'


def test_cancel_of_an_orphaned_run_marks_it_cancelled(console_root, monkeypatch):
    # no supervisor thread (a prior console) and the pid is gone → cancel closes it itself.
    monkeypatch.setattr(actions.time, "sleep", lambda *_a: None)     # don't wait the grace in the test
    _write(console_root, "o1", {"status": "running", "pid": 999_999_999})
    res = actions.cancel_run("o1")
    assert res["ok"] is True and res["status"] == "cancelled"
    assert _meta(console_root, "o1")["status"] == "cancelled"


def test_cancel_of_a_prior_boot_run_does_not_signal_a_recycled_pid(console_root, monkeypatch):
    monkeypatch.setattr(actions.time, "sleep", lambda *_a: None)
    monkeypatch.setattr(actions, "_boot_id", lambda: "boot-now")
    signalled = []
    monkeypatch.setattr(actions, "_signal_pid", lambda pid: signalled.append(pid) or True)
    _write(console_root, "b1", {"status": "running", "pid": 4242, "boot_id": "an-older-boot"})
    res = actions.cancel_run("b1")
    assert res["ok"] is True and res["status"] == "cancelled"
    assert signalled == []                                  # a cross-reboot (recycled) pid is never killed


def test_cancel_is_a_noop_on_a_finished_run(console_root):
    _write(console_root, "d1", {"status": "done"})
    res = actions.cancel_run("d1")
    assert res["ok"] is True and res["status"] == "done" and res.get("note")


def test_cancel_no_such_run(console_root):
    assert actions.cancel_run("nope")["ok"] is False


# --- retry / resume -----------------------------------------------------------------------------
def test_retry_restarts_a_nonresumable_run(console_root, monkeypatch):
    captured = {}
    monkeypatch.setattr(actions, "_spawn_background",
                        lambda rid, rd, cmd, meta, **kw: captured.update(rid=rid, cmd=cmd, meta=meta))
    _write(console_root, "r3", {"status": "error", "run_kind": "strix",
                                "cmd": ["strix", "--target", "/x"], "slug": "s"})
    res = actions.retry_run("r3")
    assert res["ok"] is True and res["resumed"] is False
    assert "--resume" not in captured["cmd"]
    assert captured["meta"]["parent_run_id"] == "r3"


def test_retry_resumes_a_resumable_vigil_engage(console_root, monkeypatch):
    captured = {}
    monkeypatch.setattr(actions, "_spawn_background",
                        lambda rid, rd, cmd, meta, **kw: captured.update(cmd=cmd))
    _write(console_root, "r4", {"status": "interrupted", "resumable": True, "run_kind": "engage",
                                "cmd": ["vigil", "engage", "http://127.0.0.1/", "--slug", "s"], "slug": "s"})
    res = actions.retry_run("r4")
    assert res["ok"] is True and res["resumed"] is True
    assert "--resume" in captured["cmd"]


def test_retry_does_not_append_resume_to_a_framework_engage(console_root, monkeypatch):
    captured = {}
    monkeypatch.setattr(actions, "_spawn_background",
                        lambda rid, rd, cmd, meta, **kw: captured.update(cmd=cmd))
    _write(console_root, "r5", {"status": "interrupted", "resumable": True, "run_kind": "url",
                                "cmd": [sys.executable, "-m", "framework.v2", "engage",
                                        "http://127.0.0.1/", "--slug", "s"], "slug": "s"})
    res = actions.retry_run("r5")
    assert res["resumed"] is False
    assert "--resume" not in captured["cmd"]


def test_retry_rewrites_baked_run_dir_paths_for_a_scan(console_root, monkeypatch):
    # BLOCK-1: a loopback scan bakes ABSOLUTE --progress-log/--reverifiable-out paths under the PARENT run
    # dir. Retry must re-point them at the NEW run's dir, or it clobbers the parent's artifacts and the new
    # run has none.
    captured = {}
    monkeypatch.setattr(actions, "_spawn_background",
                        lambda rid, rd, cmd, meta, **kw: captured.update(cmd=cmd))
    parent_rd = str(actions.run_dir("p1"))
    cmd = [sys.executable, "-m", "framework.v2", "scan", "http://127.0.0.1/", "--format", "json",
           "--progress-log", parent_rd + "/progress.jsonl",
           "--reverifiable-out", parent_rd + "/reverifiable.json"]
    _write(console_root, "p1", {"status": "done", "run_kind": "scan", "slug": "loopback", "cmd": cmd})
    res = actions.retry_run("p1")
    assert res["ok"] is True
    new_rd = str(actions.run_dir(res["run_id"]))
    assert parent_rd not in " ".join(captured["cmd"])          # nothing still points at the parent's dir
    assert (new_rd + "/reverifiable.json") in captured["cmd"]
    assert (new_rd + "/progress.jsonl") in captured["cmd"]


def test_retry_refuses_a_second_run_of_a_busy_slug(console_root):
    # a resume/retry must not start a SECOND concurrent run of a slug (two `engage --resume` would collide
    # the spine seq).
    _write(console_root, "live", {"status": "running", "slug": "s", "cmd": ["x"]})
    _write(console_root, "old", {"status": "error", "slug": "s", "resumable": True,
                                 "cmd": ["vigil", "engage", "x", "--slug", "s"]})
    res = actions.retry_run("old")
    assert res["ok"] is False and "already in progress" in res["error"]


def test_retry_refuses_a_still_running_run(console_root):
    _write(console_root, "r6", {"status": "running", "pid": 123, "cmd": ["x"], "slug": "z"})
    assert actions.retry_run("r6")["ok"] is False


def test_retry_needs_a_recorded_command(console_root):
    _write(console_root, "r7", {"status": "error"})
    assert actions.retry_run("r7")["ok"] is False


def test_cmd_supports_resume_only_for_the_integration_vigil_engage():
    assert actions._cmd_supports_resume(["vigil", "engage", "x", "--slug", "s"])
    assert not actions._cmd_supports_resume([sys.executable, "-m", "framework.v2", "engage", "x"])
    assert not actions._cmd_supports_resume(["strix", "--target", "/x"])
