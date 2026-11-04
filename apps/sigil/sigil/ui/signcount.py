"""Slice E3b-2 — the per-credential WebAuthn sign-count clone-floor ledger (NON-SIGNED).

A WebAuthn authenticator increments a monotonic ``signCount`` on every assertion; the RP stores the last
value seen and refuses an assertion whose count is not strictly greater (``webauthn.verify_assertion`` does
this check given a ``stored_sign_count``), which detects a CLONED authenticator (two devices sharing one
private key diverge on the counter). That floor is deliberately NOT an owner-signed credential record (a
passkey LOGIN must be a pure signature check with NO owner re-sign — E2a doctrine), so it lives here in a
small keyless, atomic edge/provisioner ledger instead of on the spine.

One marker file per credential, named ``sha256(credential_id)`` (a fixed ``[0-9a-f]{64}`` digest, so a
credential_id can neither traverse the directory nor collide), holding the current high-water count. ``bump``
is an ATOMIC write-if-greater (temp file + ``os.replace``), so a concurrent login for the same credential
can never lower the floor. Fail-SAFE for availability: an unreadable floor is treated as 0 (a non-counting
authenticator's value), so a broken ledger never permanently bricks a passkey — the clone guard is a
best-effort tamper signal layered on top of the signature + origin + rp_id binding, not the auth gate itself.

Stdlib only — no framework/strix/vigil_core. Offense-free by construction.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class SignCountLedger:
    """A durable, atomic per-credential monotonic sign-count high-water. ``path`` is the marker directory
    (one per spine/deployment)."""

    def __init__(self, path: "str | os.PathLike") -> None:
        self.dir = Path(path)

    def _marker(self, credential_id: str) -> Path:
        digest = hashlib.sha256(str(credential_id).encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}
        return self.dir / digest

    def floor(self, credential_id: str) -> int:
        """The highest sign-count recorded for ``credential_id`` (0 if none / unreadable). 0 is the correct
        seed: `verify_assertion` treats a (0, 0) pair as a non-counting authenticator, and a real counting
        authenticator's first assertion (count >= 1) then strictly exceeds it."""
        try:
            return int(self._marker(credential_id).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return 0

    def bump(self, credential_id: str, new_count: int) -> None:
        """Record ``new_count`` as the new floor IFF it strictly exceeds the stored one — an ATOMIC
        write-if-greater (temp + ``os.replace``), so a concurrent login cannot lower the floor. A non-counting
        authenticator (``new_count`` 0, stored 0) is a no-op. Best-effort: an I/O fault is swallowed (the
        signature/origin/rp_id binding is the hard gate; the floor is a layered clone signal)."""
        try:
            n = int(new_count)
        except (TypeError, ValueError):
            return
        if n <= self.floor(credential_id):
            return                                            # not strictly greater → nothing to record
        try:
            self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            marker = self._marker(credential_id)
            tmp = marker.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, str(n).encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(str(tmp), str(marker))                 # atomic publish of the new high-water
        except OSError:
            return                                            # best-effort; the signature binding is the gate
