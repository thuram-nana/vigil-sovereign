"""W6-5 — the .vigil-live/ui/logs/*.log child-capture files are now SIZE-BOUNDED and ROTATED.

Before W6-5 a backend's merged stdout/stderr was appended to an unbounded file handed straight to the
child's fd. It is now piped and pumped through a ``RotatingLineWriter`` (the same bounds every plane's
logging uses), so a chatty or long-running backend can no longer fill the disk. uiproxy is pure-stdlib
(imports no offense framework), so this runs in the P5 integration leg.
"""
from __future__ import annotations

import glob
import os
import stat
import sys
import threading
import time

from vigil_integration import uiproxy

_POSIX = os.name == "posix"


class _FakeProc:
    """A stand-in for a spawned child whose stdout yields a fixed set of lines then closes (EOF)."""

    def __init__(self, lines):
        self.stdout = iter(lines)
        self.killed = False

    def kill(self):
        self.killed = True


def test_pump_rotates_and_retains_deterministically(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LOG_MAX_BYTES", "256")
    monkeypatch.setenv("VIGIL_LOG_BACKUP_COUNT", "3")
    log_path = tmp_path / "ui" / "logs" / "offense-console.log"
    lines = [f"line-{i:05d}-{'x' * 40}\n" for i in range(300)]
    done = threading.Event()

    def _on_line(line):
        if line == "":            # the pump emits an empty sentinel at EOF
            done.set()

    proc = _FakeProc(lines)
    uiproxy._pump_child_output(proc, log_path, on_line=_on_line)
    assert done.wait(timeout=10), "pump thread did not finish draining"

    files = sorted(glob.glob(str(log_path) + "*"))
    assert len(files) >= 2, "the child log never rotated"
    assert len(files) <= 1 + 3, "retention window not enforced"
    for f in files:
        assert os.path.getsize(f) <= 4096, f"{f} exceeded the size bound"
    if _POSIX:
        assert stat.S_IMODE(os.stat(log_path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(log_path.parent).st_mode) == 0o700


def test_spawn_end_to_end_bounds_a_chatty_child(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LOG_MAX_BYTES", "1024")
    monkeypatch.setenv("VIGIL_LOG_BACKUP_COUNT", "3")
    log_path = tmp_path / "ui" / "logs" / "backend.log"
    argv = [sys.executable, "-c",
            "import sys\n"
            "for i in range(3000):\n"
            "    print('L%06d ' % i + 'x' * 80)\n"
            "sys.stdout.flush()\n"]
    proc = uiproxy._spawn(argv, log_path)
    proc.wait(timeout=60)
    deadline = time.time() + 15
    while time.time() < deadline:
        if len(glob.glob(str(log_path) + "*")) >= 2:
            break
        time.sleep(0.1)
    files = sorted(glob.glob(str(log_path) + "*"))
    assert len(files) >= 2, "a chatty child's log never rotated"
    assert len(files) <= 1 + 3, "retention window not enforced"
    total = sum(os.path.getsize(f) for f in files)
    # bounded to ~(backup_count + 1) * max_bytes, with generous slack for the last unrotated write.
    assert total <= (1 + 3) * 1024 + 8192, f"child logs unbounded: {total} bytes across {files}"
