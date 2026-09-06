"""Behavioural proof for per-run kill: cancelling ONE run kills its process and leaves a same-prompt
SIBLING run untouched — the "kill one of two same-prompt engagements" requirement.

Drives the REAL ``framework.v2.console.actions.cancel_run`` against two real child processes standing in for
two runs of the same prompt (same objective, distinct run ids + pids, as the console mints them). Framework
is only importable in the offense CI leg, so this is importorskip-guarded and listed there.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time

import pytest

actions = pytest.importorskip("framework.v2.console.actions")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover — exists but not ours
        return True


@pytest.fixture()
def isolated_console(tmp_path, monkeypatch):
    base = tmp_path / ".console"
    (base / "runs").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(actions, "console_dir", lambda: base)
    return base


def test_cancel_kills_one_run_and_spares_the_same_prompt_sibling(isolated_console):
    boot = actions._boot_id()
    procs = {}
    try:
        for rid in ("dupe-A", "dupe-B"):
            p = subprocess.Popen(["sleep", "300"], start_new_session=True)
            procs[rid] = p
            actions.run_dir(rid).mkdir(parents=True, exist_ok=True)
            actions._write_meta(rid, status="running", pid=p.pid, boot_id=boot,
                                objective="confirm SQLi on the same target", slug="dupe-slug")
        assert _alive(procs["dupe-A"].pid) and _alive(procs["dupe-B"].pid)

        res = actions.cancel_run("dupe-A")
        assert res.get("ok") is True, res
        # this test parents A, so reap the SIGKILL'd child so the liveness check sees it truly gone
        try:
            procs["dupe-A"].wait(timeout=5)
        except Exception:
            pass

        assert not _alive(procs["dupe-A"].pid), "run A survived its own cancel"
        assert _alive(procs["dupe-B"].pid), "the same-prompt sibling B was killed too — cancel leaked"
        assert (actions._read_run_meta("dupe-A") or {}).get("status") in ("cancelled", "error")
        assert (actions._read_run_meta("dupe-B") or {}).get("status") == "running"

        # idempotent: cancelling an already-ended run is a clean no-op, and STILL never touches the sibling
        res2 = actions.cancel_run("dupe-A")
        assert res2.get("ok") is True, res2
        assert _alive(procs["dupe-B"].pid), "sibling B killed by the idempotent second cancel"
    finally:
        for p in procs.values():
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                pass


def test_cancel_unknown_run_is_a_clean_error(isolated_console):
    res = actions.cancel_run("does-not-exist")
    assert res.get("ok") is False and "no such run" in (res.get("error") or "")
