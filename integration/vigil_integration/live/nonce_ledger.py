"""nonce_ledger — the durable, ATOMIC single-use record for destruction-authorization nonces (VIGIL-FUSION LAP-3b).

``destruction_gate.authorize_destruction`` CHECKS ``is_consumed(nonce)`` but deliberately does NOT record
consumption (it is a pure decision — "the pure gate offers the check, not the atomic check-and-consume; a
caller MUST record consumption at/after execution, ATOMICALLY, or a concurrent re-use of the SAME
authorization could double-fire that one action"). This is that caller-side ledger, and it makes the
consume the SERIALIZATION POINT so single-use holds even under concurrent callers of one authorization.

``try_consume(nonce)`` atomically reserves a nonce via ``O_CREAT | O_EXCL`` on a per-nonce marker file — the
atomic exclusive-create IS the uniqueness guarantee: of any number of concurrent callers holding the SAME
owner-signed authorization, EXACTLY ONE wins the create (returns True) and every other loses with
``FileExistsError`` (returns False). No lock is held; correctness comes from the filesystem's atomic
exclusive-create. Markers are named by ``sha256(nonce)`` (a fixed ``[0-9a-f]{64}`` string), so a nonce can
neither escape the directory (no separators / '..') nor — via an embedded newline — poison another nonce's
entry (the historical line-based footgun cannot arise).

Durable: the marker and its directory are fsync'd, so a spent nonce survives a restart / power loss (the
replay-safe direction — a crash after consume but before the PR leaves the nonce spent, never re-fireable).
Fail-closed: an empty/blank nonce reads as ALREADY consumed and can never win a reservation. Import-clean:
stdlib only (no framework/strix/sigil).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class NonceLedger:
    """A durable, ATOMIC single-use ledger of consumed destruction-authorization nonces — one marker file per
    spent nonce, where the atomic ``O_EXCL`` create is the serialization point that makes single-use hold even
    under concurrent callers of the same authorization. ``path`` is the marker directory."""

    def __init__(self, path: str | os.PathLike) -> None:
        self.dir = Path(path)

    def _marker(self, nonce: str) -> Path:
        # sha256 → fixed [0-9a-f]{64} filename: no separators, no '..', no newline ⇒ a nonce can neither
        # escape the directory nor (via an embedded newline) poison another nonce's entry, and distinct
        # nonces never collide.
        digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        return self.dir / digest

    def is_consumed(self, nonce: str) -> bool:
        """True iff ``nonce`` has already been spent (or is blank — blank ⇒ fail-closed consumed). This is an
        advisory, cheap early-reject; the AUTHORITATIVE single-use guarantee is ``try_consume`` (atomic).
        Re-derived from disk each call, so the answer survives a restart / a fresh process."""
        n = str(nonce or "").strip()
        if not n:
            return True                      # a blank nonce is never a valid single-use token → treat as spent
        return self._marker(n).exists()

    def try_consume(self, nonce: str) -> bool:
        """ATOMICALLY reserve ``nonce`` for a single use. Returns True iff THIS caller won the single use (the
        marker did not exist and we created it); False iff it was already consumed by a prior OR concurrent
        caller. The ``O_CREAT | O_EXCL`` create is atomic, so of N concurrent callers of the same
        authorization exactly one gets True. Raises on a blank nonce or a real I/O error — the caller then
        fail-closes to DENY (never authorize a destruction it could not exclusively reserve)."""
        n = str(nonce or "").strip()
        if not n:
            raise ValueError("refusing to consume an empty destruction nonce")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = self._marker(n)
        try:
            fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False                     # already spent — this caller LOST the single-use race
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(n + "\n")               # store the nonce for audit; the filename is its digest
            fh.flush()
            os.fsync(fh.fileno())
        self._fsync_dir()                    # durability: the marker survives a crash ⇒ the nonce stays spent
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
