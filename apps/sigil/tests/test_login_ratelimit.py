"""Slice E1 — the fail-closed login/signup/recovery rate-limiter.

Load-bearing invariants (a false-green would let an attacker brute-force customer/operator credentials):
  * a key locks after `max_fails` failures inside the window, and the lock has a positive remaining;
  * lockouts escalate EXPONENTIALLY on repeated abuse of the same key;
  * a legitimate success CLEARS the counter;
  * the gate is FAIL-CLOSED: an existing-but-unreadable/corrupt marker DENIES (never opens the gate),
    while a genuinely absent key is allowed (no failures yet);
  * `check()` refuses when EITHER the per-account or the per-IP key is locked;
  * failures outside the sliding window do not accumulate, and a lapsed lock re-opens.
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

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
