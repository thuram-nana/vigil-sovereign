"""The run registry (W1): a live pid on every launched run, orphan reconciliation on console startup, and
the registry fields on the runs listing.

The operator symptom this fixes: "a live engagement I did not start" that a refresh could not clear — a run
left 'running' by a console/host that has since gone. On startup the console now reconciles any such run to
'interrupted' + resumable (the process is provably gone), and never touches one whose pid is still alive.
"""
from __future__ import annotations

import json
import os

import pytest

from framework.v2.console import actions, api


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
    return d


def _meta(root, run_id: str) -> dict:
    return json.loads((root / "runs" / run_id / "meta.json").read_text(encoding="utf-8"))


def test_reconcile_marks_a_dead_running_run_interrupted(console_root):
    _write(console_root, "r-dead", {"status": "running", "pid": 999_999_999,
                                    "boot_id": actions._boot_id(), "run_kind": "engage"})
    n = actions.reconcile_orphaned_runs()
    assert n == 1
    m = _meta(console_root, "r-dead")
    assert m["status"] == "interrupted"
    assert m["resumable"] is True
    assert m.get("interrupted_reason")


def test_reconcile_leaves_a_live_running_run_alone(console_root):
    # our own pid is unquestionably alive; same boot id → not a reboot → left running.
    _write(console_root, "r-live", {"status": "running", "pid": os.getpid(),
                                    "boot_id": actions._boot_id()})
    n = actions.reconcile_orphaned_runs()
    assert n == 0
    assert _meta(console_root, "r-live")["status"] == "running"


def test_reconcile_treats_a_reboot_as_all_pids_dead(console_root):
    if not actions._boot_id():
        pytest.skip("no host boot_id available on this platform")
    # a LIVE pid but a stale boot id → the number was recycled across a reboot → interrupted.
    _write(console_root, "r-reboot", {"status": "running", "pid": os.getpid(),
                                      "boot_id": "0000-old-boot-id-that-differs"})
    n = actions.reconcile_orphaned_runs()
    assert n == 1
    assert _meta(console_root, "r-reboot")["status"] == "interrupted"


def test_reconcile_marks_a_pidless_running_run_interrupted(console_root):
    # a pre-registry run recorded no pid: it is from an older console version and cannot still be running.
    _write(console_root, "r-legacy", {"status": "running"})
    n = actions.reconcile_orphaned_runs()
    assert n == 1
    assert _meta(console_root, "r-legacy")["status"] == "interrupted"


def test_reconcile_leaves_finished_runs_untouched(console_root):
    _write(console_root, "r-done", {"status": "done", "pid": 999_999_999})
    _write(console_root, "r-err", {"status": "error"})
    assert actions.reconcile_orphaned_runs() == 0
    assert _meta(console_root, "r-done")["status"] == "done"
    assert _meta(console_root, "r-err")["status"] == "error"


def test_reconcile_skips_broken_meta_and_never_raises(console_root):
    d = console_root / "runs" / "r-broken"
    d.mkdir(parents=True)
    (d / "meta.json").write_text("{not valid json", encoding="utf-8")
    assert actions.reconcile_orphaned_runs() == 0   # must not raise


def test_list_runs_surfaces_registry_fields(console_root):
    _write(console_root, "r1", {"status": "interrupted", "resumable": True, "run_kind": "engage",
                                "interrupted_reason": "the process was gone when the console restarted",
                                "rc": None, "started": 1.0, "slug": "job1"})
    rows = api.list_runs()["runs"]
    row = [r for r in rows if r["run_id"] == "r1"][0]
    assert row["resumable"] is True
    assert row["run_kind"] == "engage"
    assert "process was gone" in row["interrupted_reason"]


def test_list_runs_surfaces_a_failed_runs_rc_and_stderr(console_root):
    _write(console_root, "r2", {"status": "error", "rc": 2, "stderr": "boom on line 5",
                                "error": "", "started": 2.0})
    rows = api.list_runs()["runs"]
    row = [r for r in rows if r["run_id"] == "r2"][0]
    assert row["rc"] == 2
    assert "boom on line 5" in row["stderr_tail"]


def test_launch_scan_does_not_advance_started_across_the_pid_write(console_root, monkeypatch):
    """LOW-3: `started` is stamped once. The in-thread pid write rewrites the whole meta.json, so a fresh
    time.time() there would silently move the launch time forward — assert it does not."""
    class _FakeProc:
        pid = 4321
        returncode = 0

        def communicate(self, timeout=None):
            return ('{"findings": []}', "")   # non-empty stdout → a 'done' scan with a report

    monkeypatch.setattr(actions.subprocess, "Popen", lambda *a, **k: _FakeProc())
    # run the launch thread INLINE so the pid + terminal writes complete before we read the meta.
    monkeypatch.setattr(actions.threading, "Thread",
                        lambda target=None, **k: type("_T", (), {"start": lambda self: target()})())
    # a monotonic clock that advances on every call: a re-stamp would be a strictly later value.
    ticks = iter([1000.0, 2000.0, 3000.0, 4000.0, 5000.0, 6000.0])
    monkeypatch.setattr(actions.time, "time", lambda: next(ticks))

    res = actions.launch_scan("http://127.0.0.1:18080/")
    meta = _meta(console_root, res["run_id"])
    assert meta["status"] == "done"
    assert meta["pid"] == 4321
    # started is the ONE tick taken when _base was built; finished is strictly later — proving the pid
    # write in between did NOT re-stamp started.
    assert meta["started"] < meta["finished"]
    assert meta["started"] == 2000.0
