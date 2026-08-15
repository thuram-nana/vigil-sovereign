"""W4 run control — Cancel a running run; Retry (restart) / Resume (continue) a finished one.

Cancel terminates the run's recorded pid; retry relaunches the run's OWN recorded argv as a new linked
run — RESUMED (argv + --resume) only where the CLI actually supports it (the integration `vigil engage`,
W2b), RESTARTED everywhere else (so a `--resume` is never appended to a CLI that would reject it).
"""
from __future__ import annotations

import json
import subprocess
import sys

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


# --- cancel ---------------------------------------------------------------------------------------
def test_cancel_terminates_a_running_pid(console_root):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])  # a real, live child
    try:
        _write(console_root, "r1", {"status": "running", "pid": proc.pid})
        res = actions.cancel_run("r1")
        assert res["ok"] is True and res["status"] == "cancelled"
        assert res["terminated"] is True                       # the pid is gone
        assert _meta(console_root, "r1")["status"] == "cancelled"
    finally:
        try:
            proc.kill()
        except Exception:
            pass


def test_cancel_is_a_noop_on_a_finished_run(console_root):
    _write(console_root, "r2", {"status": "done"})
    res = actions.cancel_run("r2")
    assert res["ok"] is True and res["status"] == "done" and res.get("note")


def test_cancel_no_such_run(console_root):
    assert actions.cancel_run("nope")["ok"] is False


# --- retry / resume -------------------------------------------------------------------------------
def test_retry_restarts_a_nonresumable_run(console_root, monkeypatch):
    captured = {}
    monkeypatch.setattr(actions, "_spawn_background",
                        lambda rid, rd, cmd, meta, **kw: captured.update(rid=rid, cmd=cmd, meta=meta))
    _write(console_root, "r3", {"status": "error", "run_kind": "strix",
                                "cmd": ["strix", "--target", "/x"], "slug": "s"})
    res = actions.retry_run("r3")
    assert res["ok"] is True and res["resumed"] is False
    assert "--resume" not in captured["cmd"]                    # a restart, not a resume
    assert captured["meta"]["parent_run_id"] == "r3"           # linked to the original


def test_retry_resumes_a_resumable_vigil_engage(console_root, monkeypatch):
    captured = {}
    monkeypatch.setattr(actions, "_spawn_background",
                        lambda rid, rd, cmd, meta, **kw: captured.update(cmd=cmd, meta=meta))
    _write(console_root, "r4", {"status": "interrupted", "resumable": True, "run_kind": "engage",
                                "cmd": ["vigil", "engage", "http://127.0.0.1/", "--slug", "s"], "slug": "s"})
    res = actions.retry_run("r4")
    assert res["ok"] is True and res["resumed"] is True
    assert "--resume" in captured["cmd"]                        # continues the slug's spine


def test_retry_does_not_append_resume_to_a_framework_engage(console_root, monkeypatch):
    # the offense `framework.v2 engage` scanner has no --resume — retry must RESTART it, never append a flag
    # it would reject as an unrecognised argument.
    captured = {}
    monkeypatch.setattr(actions, "_spawn_background",
                        lambda rid, rd, cmd, meta, **kw: captured.update(cmd=cmd))
    _write(console_root, "r5", {"status": "interrupted", "resumable": True, "run_kind": "url",
                                "cmd": [sys.executable, "-m", "framework.v2", "engage",
                                        "http://127.0.0.1/", "--slug", "s"], "slug": "s"})
    res = actions.retry_run("r5")
    assert res["resumed"] is False
    assert "--resume" not in captured["cmd"]


def test_retry_refuses_a_still_running_run(console_root):
    _write(console_root, "r6", {"status": "running", "pid": 123, "cmd": ["x"]})
    assert actions.retry_run("r6")["ok"] is False


def test_retry_needs_a_recorded_command(console_root):
    _write(console_root, "r7", {"status": "error"})
    assert actions.retry_run("r7")["ok"] is False


def test_cmd_supports_resume_only_for_the_integration_vigil_engage():
    assert actions._cmd_supports_resume(["vigil", "engage", "x", "--slug", "s"])
    assert not actions._cmd_supports_resume([sys.executable, "-m", "framework.v2", "engage", "x"])
    assert not actions._cmd_supports_resume(["strix", "--target", "/x"])
