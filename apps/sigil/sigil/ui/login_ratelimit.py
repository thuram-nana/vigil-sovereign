"""Program Slice E1 — a fail-closed login/signup/recovery rate-limiter.

Brute-force and credential-stuffing defence for the CUSTOMER auth surface (and reusable by the operator
login): a per-key sliding window of recent FAILURES plus an exponential lockout once the window fills.
The caller consults it under TWO keys per attempt — one per account (the submitted email/username) and one
per client IP (from a TRUSTED forwarded hop, never a raw client header — a spoofable key would let an
attacker dodge the per-IP leg, so per-account is the reliable leg and per-IP is best-effort on a trusted
hop). A single lock on EITHER key refuses the attempt.

Discipline mirrors `sessions.SessionLedger` / `login_challenges.ChallengeLedger`: one 0600 marker file per
key, named `sha256(key)` (a fixed `[0-9a-f]{64}` string, so a key can neither escape the directory nor
poison another entry), written atomically (temp + `os.replace`, `O_EXCL | O_NOFOLLOW`), with a per-mint
sweep + hard cap bounding the directory.

FAIL-CLOSED is the whole point of a brute-force gate: if an EXISTING marker cannot be read/parsed (I/O
error, corruption, a hostile file), `locked()` DENIES (returns a lockout) rather than fails open — an
attacker must never be able to bypass the limiter by corrupting its state. A genuinely ABSENT marker is the
normal "no failures yet" case and is allowed (that is not an error).

Stdlib only — no framework/strix/vigil_core/sigil. Offense-free and plane-pure by construction.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional

# Defaults (operator-tunable by the caller via config). A key is locked once it accumulates `max_fails`
# failures within `window_s`; the lock lasts `base_lock_s`, DOUBLING on each subsequent lockout of the same
# key up to `max_lock_s` (exponential backoff), so a persistent attacker is slowed geometrically while a
# fat-fingering legitimate user recovers after a short cool-down.
_DEFAULT_MAX_FAILS = 5
_DEFAULT_WINDOW_S = 15 * 60.0            # 15 minutes
_DEFAULT_BASE_LOCK_S = 60.0             # first lockout: 1 minute
_DEFAULT_MAX_LOCK_S = 60 * 60.0          # cap a single lockout at 1 hour
_DEFAULT_MAX_KEYS = 65536               # directory bound (anti-exhaustion)


class LoginRateLimiter:
    """A durable, fail-closed sliding-window + exponential-lockout limiter keyed by an opaque string
    (`acct:<email>` / `ip:<addr>` — the namespacing is the caller's). One 0600 marker per key named
    `sha256(key)`. `locked()` is the gate; `record_failure()` / `record_success()` update state."""

    def __init__(self, path: "str | os.PathLike", *, max_fails: int = _DEFAULT_MAX_FAILS,
                 window_s: float = _DEFAULT_WINDOW_S, base_lock_s: float = _DEFAULT_BASE_LOCK_S,
                 max_lock_s: float = _DEFAULT_MAX_LOCK_S, max_keys: int = _DEFAULT_MAX_KEYS,
                 escalation_memory_s: "Optional[float]" = None) -> None:
        self.dir = Path(path)
        self.max_fails = int(max_fails)
        self.window_s = float(window_s)
        self.base_lock_s = float(base_lock_s)
        self.max_lock_s = float(max_lock_s)
        self.max_keys = int(max_keys)
        # How long a key's escalation history (lock_count) survives after its last activity, so an attacker
        # cannot reset the exponential backoff by simply WAITING OUT each lock. Bounded (fully-cold keys are
        # still reaped by `_sweep`), and never shorter than one window + one max lock.
        self.escalation_memory_s = (float(escalation_memory_s) if escalation_memory_s is not None
                                    else self.window_s + self.max_lock_s)

    def _marker(self, key: str) -> Path:
        digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}: no traversal
        return self.dir / digest

    @staticmethod
    def _unlink(path: "str | os.PathLike") -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _write_atomic(self, marker: Path, rec: dict) -> bool:
        try:
            self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = marker.with_name(f"{marker.name}.{secrets.token_hex(8)}.tmp")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(tmp), flags, 0o600)
            try:
                os.write(fd, json.dumps(rec).encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, marker)
            return True
        except OSError:
            return False

    def _recent_fails(self, rec: dict, now: float) -> "list[float]":
        """The failure timestamps still inside the sliding window (fail-closed parse — a non-numeric entry
        is dropped, never crashes the gate)."""
        out: "list[float]" = []
        for ts in rec.get("fails", []) or []:
            if isinstance(ts, (int, float)) and not isinstance(ts, bool) and (now - float(ts)) <= self.window_s:
                out.append(float(ts))
        return out

    def _sweep(self, now: float) -> int:
        """Remove every marker that is neither locked nor carries a recent failure (and every corrupt one);
        return the count of LIVE markers remaining (the directory bound)."""
        live = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for entry in entries:
            if entry.name.endswith(".tmp"):
                continue
            try:
                rec = json.loads(Path(entry.path).read_text(encoding="utf-8"))
                assert isinstance(rec, dict)
            except (OSError, ValueError, AssertionError):
                self._unlink(entry.path)               # corrupt marker → reap (a fresh attempt re-creates it)
                continue
            lu_raw = rec.get("lock_until")
            lu = float(lu_raw) if isinstance(lu_raw, (int, float)) and not isinstance(lu_raw, bool) else 0.0
            fails = self._recent_fails(rec, now)
            # last meaningful activity = the (possibly future) lock end, or the most recent in-window failure.
            last_activity = max([lu, *fails]) if fails else lu
            if now < lu or fails or (now - last_activity) <= self.escalation_memory_s:
                live += 1                              # locked, recently failed, or still within escalation memory
            else:
                self._unlink(entry.path)               # fully cold (lock lapsed + memory elapsed) → reap
        return live

    def locked(self, key: str, *, now: "Optional[float]" = None) -> "Optional[float]":
        """Seconds remaining on an active lockout for `key`, or None if the key may attempt. FAIL-CLOSED: an
        ABSENT marker is allowed (None — no failures recorded yet), but an existing marker that cannot be
        read/parsed DENIES (returns a `base_lock_s` lockout) so a corrupted/hostile state can never open the
        gate. A lock whose `lock_until` has passed is not a lock (None)."""
        if not isinstance(key, str) or not key:
            return self.base_lock_s                    # a caller with no key is a bug → deny, never allow
        t = time.time() if now is None else float(now)
        marker = self._marker(key)
        try:
            raw = marker.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None                                # no failures yet → allowed (NOT an error)
        except OSError:
            return self.base_lock_s                    # unreadable existing marker → FAIL-CLOSED (deny)
        try:
            rec = json.loads(raw)
            if not isinstance(rec, dict):
                raise ValueError("not an object")
        except ValueError:
            return self.base_lock_s                    # corrupt/hostile marker → FAIL-CLOSED (deny)
        lock_until = rec.get("lock_until")
        if isinstance(lock_until, (int, float)) and not isinstance(lock_until, bool):
            remaining = float(lock_until) - t
            if remaining > 0:
                return remaining
        return None

    def record_failure(self, key: str, *, now: "Optional[float]" = None) -> "Optional[float]":
        """Record one failed attempt for `key`. Prunes failures outside the window, appends this one, and —
        if the window now holds `max_fails` or more — escalates the lockout (lock_count += 1, lock =
        min(base * 2**(lock_count-1), max_lock)) and clears the window. Returns the new lockout seconds if a
        lock was (re)armed, else None. FAIL-CLOSED on a corrupt existing marker: it is reset to a single
        fresh failure rather than trusted. Best-effort under I/O error (the `locked` gate still denies on an
        unreadable marker)."""
        if not isinstance(key, str) or not key:
            return None
        t = time.time() if now is None else float(now)
        if self._sweep(t) >= self.max_keys:
            # directory full of live (locked/recent-fail) keys: we are already under attack and denying;
            # do not grow the dir further — the existing locks hold, so this is safe.
            return None
        marker = self._marker(key)
        rec: dict = {}
        try:
            raw = marker.read_text(encoding="utf-8")
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                rec = loaded
        except (OSError, ValueError):
            rec = {}                                   # absent/corrupt → start fresh (a corrupt marker is
            #                                            never TRUSTED to lower the count)
        fails = self._recent_fails(rec, t)
        fails.append(t)
        lock_count = rec.get("lock_count", 0)
        lock_count = int(lock_count) if isinstance(lock_count, (int, float)) and not isinstance(lock_count, bool) else 0
        prev_lu_raw = rec.get("lock_until")
        prev_lu = float(prev_lu_raw) if isinstance(prev_lu_raw, (int, float)) and not isinstance(prev_lu_raw, bool) else 0.0
        # carry the prior lock_until forward (even once lapsed) so `_sweep` keeps the escalation memory alive;
        # it never falsely locks, because `locked()` only treats lock_until > now as an active lock.
        new: dict = {"fails": fails, "lock_count": lock_count, "lock_until": prev_lu}
        locked_for: "Optional[float]" = None
        if len(fails) >= self.max_fails:
            lock_count += 1
            locked_for = min(self.base_lock_s * (2 ** (lock_count - 1)), self.max_lock_s)
            new = {"fails": [], "lock_count": lock_count, "lock_until": t + locked_for}
        # atomic replace: unlink any existing marker then exclusive-create the new one
        self._unlink(marker)
        self._write_atomic(marker, new)
        return locked_for

    def record_success(self, key: str) -> None:
        """Clear all failure/lock state for `key` (a legitimate success resets the counter)."""
        if not isinstance(key, str) or not key:
            return
        self._unlink(self._marker(key))

    def check(self, *keys: str, now: "Optional[float]" = None) -> "Optional[float]":
        """Convenience: the MAX remaining lockout across several keys (per-account AND per-IP), or None if
        every key may attempt. A single locked key refuses the attempt."""
        t = time.time() if now is None else float(now)
        worst: "Optional[float]" = None
        for k in keys:
            r = self.locked(k, now=t)
            if r is not None and (worst is None or r > worst):
                worst = r
        return worst
