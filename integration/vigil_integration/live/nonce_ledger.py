"""nonce_ledger — the durable single-use record for destruction-authorization nonces (VIGIL-FUSION LAP-3b).

``destruction_gate.authorize_destruction`` CHECKS ``is_consumed(nonce)`` but deliberately does NOT record
consumption (it is a pure decision — "the pure gate offers the check, not the atomic check-and-consume; a
caller MUST record consumption at/after execution"). This is that caller-side ledger: a 0600 append-only
file that SURVIVES restart, so ``is_consumed`` is re-derived from disk on every call and one owner-signed
authorization can never drive more than one destructive run.

Fail-closed: an empty/blank nonce reads as ALREADY consumed (a blank authorization nonce must never be
honored), and recording a blank nonce raises. Import-clean: stdlib only (no framework/strix/sigil).
"""
from __future__ import annotations

import os
from pathlib import Path


class NonceLedger:
    """A durable, append-only single-use ledger of consumed destruction-authorization nonces."""

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)

    def is_consumed(self, nonce: str) -> bool:
        """True iff ``nonce`` has already been spent (or is blank — blank ⇒ fail-closed consumed). Re-reads
        the ledger from disk each call so the answer survives a restart / a fresh process."""
        n = str(nonce or "").strip()
        if not n:
            return True                      # a blank nonce is never a valid single-use token → treat as spent
        try:
            with open(self.path, encoding="utf-8") as fh:
                return any(line.strip() == n for line in fh)
        except OSError:
            return False                     # no ledger yet ⇒ nothing consumed

    def record(self, nonce: str) -> None:
        """Mark ``nonce`` consumed durably (append + fsync, 0600). Refuses a blank nonce. Idempotent-safe:
        re-recording a nonce is harmless (``is_consumed`` matches any line)."""
        n = str(nonce or "").strip()
        if not n:
            raise ValueError("refusing to record an empty destruction nonce")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(n + "\n")
            fh.flush()
            os.fsync(fh.fileno())
