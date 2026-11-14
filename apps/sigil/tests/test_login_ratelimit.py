"""Slice E1 — the fail-closed login/signup/recovery rate-limiter.

Load-bearing invariants (a false-green would let an attacker brute-force customer/operator credentials):
  * a key locks after `max_fails` failures inside the window, and the lock has a positive remaining;
  * lockouts escalate EXPONENTIALLY on repeated abuse of the same key;
  * a legitimate success CLEARS the counter;
  * the gate is FAIL-CLOSED: an existing-but-unreadable/corrupt marker DENIES (never opens the gate),
    while a genuinely absent key is allowed (no failures yet);
  * `check()` refuses when EITHER the per-account or the per-IP key is locked;
  * failures outside the sliding window do not accumulate, and a lapsed lock re-opens;
  * CONCURRENCY (audit E1): concurrent `record_failure`s — across PROCESSES — never lose an update, and a LOCKED
    key never reads as unlocked while another process records against it (no unlink-then-write window);
  * `admit` (the checkout limiter's guard-and-count) admits exactly `max_fails` per window across processes and
    refuses on every fault (no lock, a corrupt marker, a full directory, a write that does not land).
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sigil.ui import login_ratelimit
from sigil.ui.login_ratelimit import LoginRateLimiter


def _lim():
    # small, fast params: lock after 3 fails in a 100s window; 10s base lock, doubling, capped at 40s.
    return LoginRateLimiter(tempfile.mkdtemp(), max_fails=3, window_s=100.0,
                            base_lock_s=10.0, max_lock_s=40.0)


def test_locks_after_max_fails_and_success_clears():
    lim = _lim()
    assert lim.locked("acct:a@x.com", now=0.0) is None            # pristine → allowed
    assert lim.record_failure("acct:a@x.com", now=1.0) is None     # 1
    assert lim.record_failure("acct:a@x.com", now=2.0) is None     # 2
    locked_for = lim.record_failure("acct:a@x.com", now=3.0)       # 3 → lock
    assert locked_for == 10.0
    rem = lim.locked("acct:a@x.com", now=4.0)
    assert rem is not None and 8.0 < rem <= 10.0                    # ~9s remaining
    # a success clears everything → allowed again immediately
    lim.record_success("acct:a@x.com")
    assert lim.locked("acct:a@x.com", now=5.0) is None


def test_exponential_backoff_on_repeat_abuse():
    lim = _lim()
    # first lockout at t=3 for 10s (until 13)
    for i in range(3):
        lim.record_failure("ip:1.2.3.4", now=1.0 + i)
    assert lim.locked("ip:1.2.3.4", now=4.0) == 9.0               # 13 - 4
    # after the first lock lapses (t>=13), 3 more fails → SECOND lockout doubles to 20s (escalation persists)
    for i in range(3):
        lim.record_failure("ip:1.2.3.4", now=20.0 + i)
    second = lim.locked("ip:1.2.3.4", now=23.0)
    assert second is not None and 18.0 < second <= 20.0            # doubled: ~19s of a 20s lock
    # a THIRD round doubles again toward 40s and hits the cap
    for i in range(3):
        lim.record_failure("ip:1.2.3.4", now=100.0 + i)
    third = lim.locked("ip:1.2.3.4", now=103.0)
    assert third is not None and 38.0 < third <= 40.0             # doubled again, capped at max_lock_s


def test_absent_key_is_allowed():
    lim = _lim()
    assert lim.locked("never-seen", now=0.0) is None


def test_fail_closed_on_corrupt_marker():
    d = tempfile.mkdtemp()
    lim = LoginRateLimiter(d, max_fails=3, window_s=100.0, base_lock_s=10.0, max_lock_s=40.0)
    # plant a hostile/corrupt marker where key 'acct:z' would live
    marker = Path(d) / hashlib.sha256(b"acct:z").hexdigest()
    marker.write_text("}{ this is not json", encoding="utf-8")
    rem = lim.locked("acct:z", now=0.0)
    assert rem == 10.0, "an existing-but-corrupt marker must FAIL CLOSED (deny), not open the gate"


def test_empty_key_denies():
    lim = _lim()
    assert lim.locked("", now=0.0) == 10.0          # a missing key is a caller bug → deny, never allow


def test_check_refuses_if_either_key_locked():
    lim = _lim()
    for i in range(3):
        lim.record_failure("acct:b@x.com", now=1.0 + i)           # lock the account key only
    # ip key is pristine, but check() across both must still refuse (account is locked)
    worst = lim.check("acct:b@x.com", "ip:9.9.9.9", now=4.0)
    assert worst is not None and worst > 0.0
    # both pristine → allowed
    assert lim.check("acct:fresh", "ip:fresh", now=4.0) is None


def test_window_prunes_old_failures():
    lim = _lim()
    lim.record_failure("acct:c", now=1.0)
    lim.record_failure("acct:c", now=2.0)
    # third failure comes AFTER the first two age out of the 100s window → no lock (only 1 in-window)
    assert lim.record_failure("acct:c", now=200.0) is None
    assert lim.locked("acct:c", now=201.0) is None


def test_lapsed_lock_reopens():
    lim = _lim()
    for i in range(3):
        lim.record_failure("acct:d", now=1.0 + i)                 # lock until ~13
    assert lim.locked("acct:d", now=5.0) is not None
    assert lim.locked("acct:d", now=20.0) is None                 # lock lapsed → allowed again


# --- concurrency: record_failure across processes (audit E1) --------------------------------------------------
# Each worker loads THIS checkout's login_ratelimit.py by path (`-I`: nothing else on sys.path), so the test runs
# real processes against one marker directory.
_LOAD = (
    "import importlib.util, sys\n"
    "spec = importlib.util.spec_from_file_location('lrl', sys.argv[1])\n"
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n")


def _procs(code: str, *args: str, n: int):
    return [subprocess.Popen([sys.executable, "-I", "-c", _LOAD + code, login_ratelimit.__file__, *args],
                             stdout=subprocess.PIPE, text=True) for _ in range(n)]


def test_concurrent_failures_from_separate_processes_are_never_lost(tmp_path):
    """8 PROCESSES x 25 failures on ONE key: all 200 are recorded. (main: the unserialized read-modify-write lost
    almost all of them — a parallel brute force got far more than `max_fails` guesses.)"""
    d = str(tmp_path / "l")
    code = ("lim = m.LoginRateLimiter(sys.argv[2], max_fails=10_000, window_s=1e9, base_lock_s=1e9)\n"
            "for _ in range(25):\n    lim.record_failure('acct:victim', now=1000.0)\n")
    procs = _procs(code, d, n=8)
    assert all(p.wait(timeout=120) == 0 for p in procs)
    rec = json.loads(LoginRateLimiter(d)._marker("acct:victim").read_text(encoding="utf-8"))
    assert len(rec["fails"]) == 200


def test_a_locked_key_never_reads_unlocked_while_other_processes_record(tmp_path):
    """3 processes keep recording failures against a LOCKED key while a 4th polls `locked()`: it is locked on every
    read. (main: record_failure unlinked the marker before rewriting it, so a reader saw "no failures yet", and a
    concurrent writer reading the gap reset the lock.)"""
    d = str(tmp_path / "l")
    lim = LoginRateLimiter(d, max_fails=3, window_s=1e9, base_lock_s=1e9, max_lock_s=1e9)
    for _ in range(3):
        lim.record_failure("acct:locked", now=2000.0)
    assert lim.locked("acct:locked", now=2000.0) is not None
    writer = ("lim = m.LoginRateLimiter(sys.argv[2], max_fails=3, window_s=1e9, base_lock_s=1e9, max_lock_s=1e9)\n"
              "for _ in range(300):\n    lim.record_failure('acct:locked', now=2000.0)\n")
    reader = ("import os\n"
              "lim = m.LoginRateLimiter(sys.argv[2], max_fails=3, window_s=1e9, base_lock_s=1e9, max_lock_s=1e9)\n"
              "n = opened = 0\n"
              "while not os.path.exists(sys.argv[3]):\n"
              "    n += 1\n"
              "    opened += lim.locked('acct:locked', now=2000.0) is None\n"
              "print(n, opened)\n")
    done = tmp_path / "done"
    rd = _procs(reader, d, str(done), n=1)[0]
    writers = _procs(writer, d, n=3)
    assert all(p.wait(timeout=120) == 0 for p in writers)
    done.write_text("x", encoding="utf-8")
    n, opened = map(int, rd.communicate(timeout=60)[0].split())
    assert rd.returncode == 0 and n > 0
    assert opened == 0, f"a LOCKED key read as unlocked on {opened} of {n} checks"
    assert lim.locked("acct:locked", now=2000.0) is not None


def test_record_failure_still_counts_when_the_flock_cannot_be_taken(tmp_path, monkeypatch):
    class _NoLock:
        LOCK_EX = 2

        @staticmethod
        def flock(fd, op):
            raise OSError("no lock")
    lim = LoginRateLimiter(tmp_path / "l", max_fails=2, window_s=100.0, base_lock_s=10.0)
    monkeypatch.setattr(login_ratelimit, "fcntl", _NoLock)
    lim.record_failure("acct:x", now=1.0)
    assert lim.record_failure("acct:x", now=2.0) == 10.0          # best-effort: counted (and locked) as before


# --- admit: the checkout limiter's guard-and-count (audit E1a) ------------------------------------------------

def _alim(d, **kw):
    return LoginRateLimiter(d, **{"max_fails": 3, "window_s": 100.0, "base_lock_s": 100.0, **kw})


def test_admit_counts_every_attempt_and_refuses_past_the_ceiling(tmp_path):
    lim = _alim(tmp_path / "l")
    assert [lim.admit("a", "b", now=10.0) for _ in range(3)] == [None, None, None]
    assert lim.admit("a", "b", now=11.0) == pytest.approx(99.0)        # locked until 10 + 100
    assert lim.admit("a", now=12.0) is not None and lim.admit("b", now=12.0) is not None
    assert lim.admit("c", now=12.0) is None                            # an unrelated key is unaffected
    assert lim.admit("a", "b", now=111.0) is None                      # the lockout lapses


@pytest.mark.parametrize("locked", ["org", "user"])
def test_admit_records_nothing_when_any_key_is_locked(tmp_path, locked):
    lim = _alim(tmp_path / "l")
    for _ in range(3):
        assert lim.admit(locked, now=1.0) is None                      # that key is now locked
    other = "user" if locked == "org" else "org"
    assert lim.admit("org", "user", now=2.0) is not None
    assert not lim._marker(other).exists()                             # the refused attempt counted nowhere


def test_admit_fails_closed_when_the_attempt_cannot_be_recorded(tmp_path, monkeypatch):
    lim = _alim(tmp_path / "l")
    monkeypatch.setattr(LoginRateLimiter, "_write_atomic", lambda self, m, r: False)
    assert lim.admit("a", now=1.0) == lim.base_lock_s


def test_admit_fails_closed_without_a_key_or_a_lock(tmp_path, monkeypatch):
    lim = _alim(tmp_path / "l")
    assert lim.admit(now=1.0) == lim.base_lock_s and lim.admit("", now=1.0) == lim.base_lock_s

    class _NoLock:
        LOCK_EX = 2

        @staticmethod
        def flock(fd, op):
            raise OSError("no lock")
    monkeypatch.setattr(login_ratelimit, "fcntl", _NoLock)
    assert lim.admit("a", now=1.0) == lim.base_lock_s
    assert not lim._marker("a").exists()


@pytest.mark.parametrize("content", ["{not json", "[]"])
def test_admit_refuses_on_a_corrupt_marker_and_does_not_reset_it(tmp_path, content):
    lim = _alim(tmp_path / "l")
    assert lim.admit("a", "b", now=1.0) is None
    lim._marker("b").write_text(content, encoding="utf-8")
    assert lim.admit("a", "b", now=2.0) == lim.base_lock_s
    assert lim._marker("b").read_text(encoding="utf-8") == content      # never trusted, never silently reset
    assert json.loads(lim._marker("a").read_text(encoding="utf-8"))["fails"] == [1.0]   # nothing recorded


@pytest.mark.parametrize("content", ["", "{torn", "[]"])
def test_a_corrupt_marker_older_than_any_lock_it_could_hold_is_counted_afresh(tmp_path, content):
    """A marker torn by a crash (or otherwise corrupt) refuses — but not for ever: once the FILE is older than one
    window + the longest lock, nothing it held can still be live, so the key is admitted and counted afresh (before,
    only another key's sweep could ever reap it: a quiet single-org deployment stayed locked out)."""
    import os
    lim = _alim(tmp_path / "l")
    assert lim.admit("a", now=1.0) is None
    lim._marker("a").write_text(content, encoding="utf-8")
    t = 10_000.0
    os.utime(lim._marker("a"), (t - lim.window_s - lim.max_lock_s + 5, t - lim.window_s - lim.max_lock_s + 5))
    assert lim.admit("a", now=t) == lim.base_lock_s                    # still within reach of a live lock: refuse
    os.utime(lim._marker("a"), (t - lim.window_s - lim.max_lock_s - 5, t - lim.window_s - lim.max_lock_s - 5))
    assert lim.admit("a", now=t) is None
    assert json.loads(lim._marker("a").read_text(encoding="utf-8"))["fails"] == [t]   # counted from zero


def test_admit_refuses_when_the_directory_bound_is_full(tmp_path):
    lim = _alim(tmp_path / "l", max_keys=1)
    assert lim.admit("a", now=1.0) is None
    assert lim.admit("b", now=2.0) == lim.base_lock_s                  # cannot record a new key → refuse


def test_the_sweep_never_reaps_the_lock_file(tmp_path):
    lim = _alim(tmp_path / "l")
    assert lim.admit("a", now=1.0) is None
    lim.record_failure("z", now=10_000.0)                               # a sweep long after "a" went cold
    assert (tmp_path / "l" / ".limiter.lock").exists()


def test_admit_is_exact_across_concurrent_processes(tmp_path):
    """8 PROCESSES x 6 attempts on one marker dir: exactly max_fails (10) are admitted — the flock serializes the
    read-check-write across processes (no lost update lets two processes admit on the same count). Every process
    waits at a start barrier and the read-to-write step is widened (test instrumentation), so the attempts really
    overlap: without the flock, processes read the same count and admit past the ceiling on every run."""
    import time
    bar = tmp_path / "barrier"
    code = ("import os, time\n"
            "lim = m.LoginRateLimiter(sys.argv[2], max_fails=10, window_s=1e6, base_lock_s=1e6)\n"
            "real = lim._next_record\n"
            "def slow(rec, t):\n"
            "    time.sleep(0.01)\n"
            "    return real(rec, t)\n"
            "lim._next_record = slow\n"
            "open(sys.argv[3] + '.ready.' + str(os.getpid()), 'w').close()\n"
            "while not os.path.exists(sys.argv[3] + '.go'):\n"
            "    time.sleep(0.002)\n"
            "sys.stdout.write(''.join('1' if lim.admit('org', 'user', now=1000.0) is None else '0' "
            "for _ in range(6)))\n")
    procs = _procs(code, str(tmp_path / "l"), str(bar), n=8)
    deadline = time.monotonic() + 60
    while len(list(tmp_path.glob("barrier.ready.*"))) < 8:
        assert time.monotonic() < deadline and all(p.poll() is None for p in procs), "a worker never got ready"
        time.sleep(0.01)
    (tmp_path / "barrier.go").touch()
    out = "".join(p.communicate(timeout=120)[0] for p in procs)
    assert all(p.returncode == 0 for p in procs)
    assert len(out) == 48 and out.count("1") == 10, out
