"""E3bc — the hardened cross-process lock behind the money seam's locks (``vigil_integration.live.seam_lock``).

Pins: a planted symlink, a FIFO or a directory at the lock path raises at once (never follows the link, never
blocks the open, never hangs a holder of the settle lock); a lock held by ANOTHER PROCESS raises ``LockBusy``
after the bounded wait; shared locks coexist and exclude an exclusive one; no ``fcntl`` fails closed; an absent
``create=False`` lock is created and, under root, handed to the directory's owner; and the seam readers' ``*.json``
globs never pick up a ``*.json.lock`` file. The marker writers (settlement, pause, paused-past-expiry) take the
lock and fail closed when it cannot be taken.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from vigil_integration.live import credit_lease_broker as B
from vigil_integration.live import credit_lease_pause as P
from vigil_integration.live import seam_lock as L

pytestmark = pytest.mark.skipif(L.fcntl is None, reason="POSIX flock")


def _tmp() -> Path:
    return Path(tempfile.mkdtemp())


@pytest.mark.parametrize("kind", ["symlink", "fifo", "dir"])
def test_an_unusable_lock_path_raises_without_blocking(kind):
    d = _tmp()
    p = d / "x.lock"
    if kind == "symlink":
        (d / "target").write_text("", encoding="utf-8")
        p.symlink_to(d / "target")
    elif kind == "fifo":
        os.mkfifo(p)
    else:
        p.mkdir()
    t0 = time.monotonic()
    for create in (True, False):
        for shared in (False, True):
            with pytest.raises(OSError):
                with L.locked_file(p, wait_s=5.0, create=create, shared=shared):
                    pass
    assert time.monotonic() - t0 < 2.0                       # raised at once: no wait, no blocked open
    if kind == "symlink":
        assert (d / "target").read_text(encoding="utf-8") == ""   # the link target was never touched


_HOLD = r"""
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_SH if sys.argv[2] == "sh" else fcntl.LOCK_EX)
open(sys.argv[3], "w").close()
time.sleep(float(sys.argv[4]))
"""


def _holder(path: Path, mode: str, hold_s: float):
    ready = path.parent / f"ready-{mode}-{time.monotonic_ns()}"
    p = subprocess.Popen([sys.executable, "-c", _HOLD, str(path), mode, str(ready), str(hold_s)])
    deadline = time.monotonic() + 30
    while not ready.exists():
        assert time.monotonic() < deadline and p.poll() is None, "lock holder did not start"
        time.sleep(0.01)
    return p


def test_a_lock_held_by_another_process_raises_lock_busy_after_the_bounded_wait():
    p = _tmp() / "x.lock"
    h = _holder(p, "ex", 30)
    try:
        t0 = time.monotonic()
        with pytest.raises(L.LockBusy):
            with L.locked_file(p, wait_s=0.3):
                pass
        waited = time.monotonic() - t0
        assert 0.25 <= waited < 3.0, waited
        assert isinstance(L.LockBusy("x"), OSError)          # every caller's OSError path covers it
    finally:
        h.kill()
        h.wait()
    with L.locked_file(p, wait_s=1.0):                        # released when its holder dies
        pass


def test_shared_locks_coexist_and_exclude_an_exclusive_one():
    p = _tmp() / "x.lock"
    h = _holder(p, "sh", 30)
    try:
        with L.locked_file(p, shared=True, wait_s=0.5, create=False):   # another shared holder: fine
            pass
        with pytest.raises(L.LockBusy):
            with L.locked_file(p, wait_s=0.2):                           # an exclusive one waits, then LockBusy
                pass
    finally:
        h.kill()
        h.wait()


def test_no_fcntl_fails_closed(monkeypatch):
    monkeypatch.setattr(L, "fcntl", None)
    with pytest.raises(OSError, match="unavailable"):
        with L.locked_file(_tmp() / "x.lock"):
            pass


def test_an_absent_reader_lock_is_created_and_a_root_opener_hands_it_to_the_directory_owner(monkeypatch):
    d = _tmp()
    p = d / ".spool.lock"
    seen = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: seen.append((uid, gid)))
    with L.locked_file(p, shared=True, create=False, chown_like=d, wait_s=1.0):
        pass
    st = d.stat()
    assert p.is_file() and (p.stat().st_mode & 0o777) == 0o600
    assert seen == [(st.st_uid, st.st_gid)]
    with L.locked_file(p, shared=True, create=False, chown_like=d, wait_s=1.0):   # present: opened, not re-chowned
        pass
    assert seen == [(st.st_uid, st.st_gid)]


def test_the_seam_json_globs_ignore_lock_files():
    base = tempfile.mkdtemp()
    B.record_lease_settlement(base, "cust_abc", "n1")
    P.record_lease_pause(base, "cust_abc", "n1")
    P.record_paused_past_expiry(base, "cust_abc", "n1")
    assert (B.settlements_root(base) / "cust_abc.json.lock").is_file()
    assert (P.pauses_root(base) / "cust_abc.json.lock").is_file()
    (B.leases_root(base)).mkdir(parents=True, exist_ok=True)
    (B.leases_root(base) / "cust_abc.json.lock").write_text("", encoding="utf-8")
    assert B.list_credit_leases(base) == []
    assert P.paused_launches(base) == [("cust_abc", ["n1"])]
    assert P.unreadable_pause_markers(base) == []
    assert P.pause_store_unreadable(base) is None


@pytest.mark.parametrize("writer", ["settle", "pause", "clear", "past_expiry"])
def test_a_marker_writer_whose_lock_cannot_be_taken_writes_nothing(writer):
    base = tempfile.mkdtemp()
    if writer == "settle":
        path, call = B.settlements_root(base) / "cust_abc.json", lambda: B.record_lease_settlement(base, "cust_abc", "n1")
    elif writer == "past_expiry":
        path = P._past_expiry_path(base, "cust_abc")
        call = lambda: P.record_paused_past_expiry(base, "cust_abc", "n1")   # noqa: E731
    else:
        path = P.pauses_root(base) / "cust_abc.json"
        call = (lambda: P.record_lease_pause(base, "cust_abc", "n1")) if writer == "pause" else (  # noqa: E731
            lambda: P.clear_lease_pause(base, "cust_abc", "n1"))
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / (path.name + ".lock")).mkdir()                 # an unusable lock file
    with pytest.raises(OSError):
        call()
    assert not path.exists()


def test_a_marker_writer_waits_for_another_processs_read_modify_write(monkeypatch):
    base = tempfile.mkdtemp()
    path = P.pauses_root(base) / "cust_abc.json"
    path.parent.mkdir(parents=True)
    monkeypatch.setattr(B, "_MARKER_LOCK_WAIT_S", 0.3)
    h = _holder(path.parent / "cust_abc.json.lock", "ex", 30)
    try:
        with pytest.raises(L.LockBusy):
            P.record_lease_pause(base, "cust_abc", "n1")
        assert not path.exists()
    finally:
        h.kill()
        h.wait()
    P.record_lease_pause(base, "cust_abc", "n1")
    assert P.is_lease_paused(base, "cust_abc", "n1")
