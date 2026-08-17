"""Single-use, short-TTL server login challenges for the S3 challenge/response PoP login.

The `/api/login/challenge` endpoint mints a fresh, unpredictable server nonce (`secrets.token_urlsafe`)
and records it here as OUTSTANDING; `/api/login`'s PoP branch then CONSUMES it exactly once. This is the
replay guard: a captured `{username, challenge, signature}` triple re-sent a second time finds its
challenge already spent and is refused.

Mirrors the atomic single-use discipline of the offense nonce ledger
(`integration/vigil_integration/live/nonce_ledger.py`): one marker file per challenge, named by
`sha256(challenge)` (a fixed `[0-9a-f]{64}` string, so a challenge can neither escape the directory — no
separators / '..' — nor, via an embedded newline, poison another entry), and the filesystem's atomic
primitives ARE the serialization point (no lock held). Two differences fit the login use:
  * MINT records issuance (`O_CREAT | O_EXCL`) with the issue timestamp, so an UNKNOWN challenge (one never
    minted by this server) is refused — the offense ledger's "first consumer wins" would admit any string.
  * CONSUME is an atomic `os.unlink` of that marker: of N concurrent consumers of one challenge EXACTLY ONE
    wins (removes it) and the rest get `FileNotFoundError` (replay refused). A challenge older than the TTL
    is refused (and its marker cleaned up).

Stdlib only — no framework/strix/vigil_core (pure filesystem + hashlib). Offense-free by construction.
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

# Default challenge lifetime. Short by design: the client signs and returns the challenge in one round-trip,
# so a couple of minutes is ample and bounds the window in which a leaked (but unused) challenge is live.
_DEFAULT_TTL_SECONDS = 120.0


class ChallengeLedger:
    """A durable, atomic single-use ledger of OUTSTANDING login challenges — one marker file per challenge,
    where the atomic exclusive-create (mint) and atomic unlink (consume) are the serialization points that
    make single-use hold even under concurrent consumers. `path` is the marker directory."""

    def __init__(self, path: "str | os.PathLike", *, ttl_seconds: float = _DEFAULT_TTL_SECONDS) -> None:
        self.dir = Path(path)
        self.ttl = float(ttl_seconds)

    def _marker(self, challenge: str) -> Path:
        digest = hashlib.sha256(challenge.encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}: no traversal
        return self.dir / digest

    def issue(self, challenge: str, *, now: "float | None" = None) -> None:
        """Record a freshly-minted challenge as OUTSTANDING (single-use). `O_CREAT | O_EXCL` create: a
        duplicate challenge (astronomically unlikely for a 32-byte token) refuses rather than silently
        reissue. Raises on a blank challenge or a real I/O error (the caller then serves no challenge)."""
        c = str(challenge or "").strip()
        if not c:
            raise ValueError("refusing to issue an empty login challenge")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        t = time.time() if now is None else float(now)
        marker = self._marker(c)
        fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # FileExistsError on a dup
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(repr(t))                                            # the issue time, for the TTL check
            fh.flush()
            os.fsync(fh.fileno())
        self._fsync_dir()

    def consume(self, challenge: str, *, now: "float | None" = None) -> bool:
        """ATOMICALLY spend an OUTSTANDING, UNEXPIRED challenge. True iff THIS caller won the single use (the
        marker existed, was fresh, and we removed it); False on unknown / expired / already-consumed. The
        `os.unlink` is the serialization point — of N concurrent consumers exactly one succeeds; the losers
        get `FileNotFoundError` and are refused (replay guard). Never raises (a consume failure is a refusal,
        not a crash)."""
        c = str(challenge or "").strip()
        if not c:
            return False
        marker = self._marker(c)
        try:
            issued_at = float(marker.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return False                          # unknown / unreadable / corrupt marker → refuse
        try:
            os.unlink(str(marker))                # atomic single-use: one winner; FileNotFoundError = spent
        except OSError:
            return False                          # lost the race / already consumed → replay refused
        t = time.time() if now is None else float(now)
        if t - issued_at > self.ttl:              # expired (marker now cleaned) → refuse the stale challenge
            return False
        return True

    def _fsync_dir(self) -> None:
        try:
            dfd = os.open(str(self.dir), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)
