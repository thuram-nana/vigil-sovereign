"""Slice 1c-ii — server-side session ledger for cookie-backed sessions.

A cookie session is a server-owned record (NOT a self-contained token): the browser holds only an opaque
session id in an HttpOnly cookie, and the AUTHORITY for whether that session is still valid lives here on
the server. That is what lets the server enforce **idle expiry**, **absolute expiry**, **rotation** (a fresh
id on every login → no session fixation) and **immediate revocation** (`revoke`/`revoke_all`) — none of
which a bearer-in-a-header can do.

Discipline mirrors `login_challenges.ChallengeLedger`: one marker file per session, named `sha256(sid)` (a
fixed `[0-9a-f]{64}` string, so a session id can neither escape the directory nor poison another entry), the
marker created `O_CREAT | O_EXCL | O_NOFOLLOW` at 0600, and a per-mint sweep + hard cap bound the directory.
The record is a small JSON object; the raw session id is NEVER written to disk (only its hash names the
file), so a read of the ledger directory cannot recover a live credential.

Stdlib only — no framework/strix/vigil_core. Offense-free by construction.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional

# Defaults (operator-tunable by the caller). Idle: a session dies after this long with no request. Absolute:
# a session dies this long after login no matter how active — the hard ceiling a refresh cannot extend.
DEFAULT_IDLE_TTL_SECONDS = 30 * 60          # 30 minutes
DEFAULT_ABSOLUTE_TTL_SECONDS = 12 * 60 * 60  # 12 hours
# Only rewrite `last_seen` when it advances by more than this — bounds disk I/O under SSE/polling while
# keeping idle-expiry granularity coarse (a session idle < this still counts as active, which is correct).
_LAST_SEEN_WRITE_THROTTLE = 30.0
_DEFAULT_MAX_SESSIONS = 8192


class SessionLedger:
    """A durable server-side ledger of live cookie sessions — one 0600 marker file per session, keyed by
    `sha256(session_id)`. The atomic exclusive-create (mint) and atomic unlink (revoke/expire) are the
    serialization points. BOUNDED: each mint sweeps expired markers and refuses at the cap."""

    def __init__(self, path: "str | os.PathLike", *, idle_ttl: float = DEFAULT_IDLE_TTL_SECONDS,
                 absolute_ttl: float = DEFAULT_ABSOLUTE_TTL_SECONDS,
                 max_sessions: int = _DEFAULT_MAX_SESSIONS) -> None:
        self.dir = Path(path)
        self.idle_ttl = float(idle_ttl)
        self.absolute_ttl = float(absolute_ttl)
        self.max_sessions = int(max_sessions)

    def _marker(self, sid: str) -> Path:
        digest = hashlib.sha256(sid.encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}: no traversal
        return self.dir / digest

    @staticmethod
    def _unlink(path: "str | os.PathLike") -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _read(self, marker: Path) -> "Optional[dict]":
        try:
            rec = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return rec if isinstance(rec, dict) else None

    def _expired(self, rec: dict, now: float) -> bool:
        """True if the record is past its absolute deadline OR idle-expired. Fail-CLOSED: a record missing
        or with a non-numeric deadline/last_seen is treated as expired (deny), never as immortal."""
        deadline = rec.get("absolute_deadline")
        last_seen = rec.get("last_seen")
        if not isinstance(deadline, (int, float)) or not isinstance(last_seen, (int, float)):
            return True                                # missing / non-numeric ⇒ treat as expired (deny)
        return now >= float(deadline) or (now - float(last_seen)) > self.idle_ttl

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

    def _sweep(self, now: float) -> int:
        """Remove every expired/corrupt marker; return the count of LIVE markers remaining (the bound)."""
        live = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for entry in entries:
            if entry.name.endswith(".tmp"):
                continue
            rec = self._read(Path(entry.path))
            if rec is None or self._expired(rec, now):
                self._unlink(entry.path)
            else:
                live += 1
        return live

    def create(self, username: str, role: str, *, is_owner: bool = False,
               now: "Optional[float]" = None) -> "Optional[str]":
        """Mint a FRESH session id (rotation is inherent — a new id every call, so a caller can never pin a
        pre-chosen id → no session fixation), persist its record 0600, and return the id. Sweeps + caps
        first. Returns None if the ledger is full or the write failed (the caller then sets no cookie)."""
        t = time.time() if now is None else float(now)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._sweep(t) >= self.max_sessions:
            return None
        sid = secrets.token_urlsafe(32)
        rec = {"username": str(username), "role": str(role), "is_owner": bool(is_owner),
               "created": t, "last_seen": t, "absolute_deadline": t + self.absolute_ttl}
        if not self._write_atomic(self._marker(sid), rec):
            return None
        return sid

    def resolve(self, sid: str, *, now: "Optional[float]" = None) -> "Optional[dict]":
        """Return the session record for a live, unexpired session, or None (fail-closed). Enforces idle AND
        absolute expiry server-side; an expired session is unlinked and refused. On a live session `last_seen`
        is bumped (write-throttled) so activity slides the IDLE window but NEVER the absolute deadline."""
        if not isinstance(sid, str) or not sid:
            return None
        t = time.time() if now is None else float(now)
        marker = self._marker(sid)
        rec = self._read(marker)
        if rec is None:
            return None
        if self._expired(rec, t):
            self._unlink(marker)                       # dead → reap it and refuse
            return None
        if t - float(rec.get("last_seen", 0.0)) > _LAST_SEEN_WRITE_THROTTLE:
            rec["last_seen"] = t                       # slide the idle window; absolute_deadline UNCHANGED
            self._unlink(marker)                       # replace the record atomically (no in-place edit)
            self._write_atomic(marker, rec)
        return rec

    def revoke(self, sid: str) -> bool:
        """Invalidate ONE session immediately (server-side logout). True if a marker was removed."""
        if not isinstance(sid, str) or not sid:
            return False
        marker = self._marker(sid)
        existed = marker.exists()
        self._unlink(marker)
        return existed

    def revoke_all(self) -> int:
        """Invalidate EVERY session immediately (owner 'sign everyone out'). Returns the count removed."""
        n = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for entry in entries:
            if entry.name.endswith(".tmp"):
                continue
            self._unlink(entry.path)
            n += 1
        return n
