"""pending_totp — the PENDING (unconfirmed) TOTP secret of a customer mid-enrolment.

Confirm-before-activate (VIGIL_CUSTOMER_MFA_ENROLL_STEPUP): when the flag is on, ``enroll_totp`` no longer
ACTIVATES the freshly generated secret — it parks it here until a fresh code proves the customer added it to
their authenticator, and only ``confirm_totp`` then owner-signs the active credential. So a hijacked session
cannot SILENTLY SWAP the victim's second factor: a pending secret grants nothing until it is confirmed, and
confirming needs a live code the attacker does not have.

What is stored is the OWNER-VAULT-SEALED blob (exactly the bytes the active credential would carry), never the
plaintext secret — the provisioner seals at enrol and unseals at confirm, mirroring the active TOTP path. It is
NOT a signed spine record (a pending enrolment carries no authority): one small JSON file per account under
``config.CUSTOMER_MFA_PENDING_TOTP_DIR`` (``$SIGIL_HOME/customer/mfa_totp_pending``), named by a
domain-separated sha256 of the username (no username/email in a path), written atomically (``spine.atomicio``;
temp file 0600) in a 0700 directory. A marker older than ``ttl_s`` reads as ABSENT (a stale pending expires, so
a lingering unconfirmed secret cannot sit forever); a missing, unreadable or malformed marker also reads as
absent — FAIL-CLOSED: the only thing a broken store can do is refuse to confirm, never activate a secret.

FATAL-2: sovereign-side (``assert_no_offense`` at import); the stdlib plus ``spine.atomicio`` only, no offense
plane and no key.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

_MAX_BYTES = 8192        # a sealed b64 blob + a couple of floats is well under this


class PendingTotpEnrolments:
    """A durable, per-account store of ONE pending (sealed) TOTP secret. ``path`` is the marker directory (one
    per spine, so a test's temp spine gets its own isolated store)."""

    def __init__(self, path: "str | os.PathLike", *, ttl_s: float = 900.0) -> None:
        self.dir = Path(path)
        self.ttl_s = float(ttl_s)

    def _marker(self, username: str) -> Path:
        # domain-separated digest -> a fixed [0-9a-f]{64} name: no username in a path, no traversal, no collision
        return self.dir / (hashlib.sha256(b"vigil-mfa-pending-totp\x00" + str(username).encode("utf-8")).hexdigest()
                           + ".json")

    def put(self, username: str, sealed_secret: str, *, now: float) -> None:
        """Store (replacing any prior) the sealed secret pending for ``username``. Raises ``ValueError`` on an
        empty username/secret and ``OSError`` when the directory cannot be written (the caller fails closed)."""
        u = str(username or "")
        if not u:
            raise ValueError("a pending TOTP enrolment needs the account")
        if not isinstance(sealed_secret, str) or not sealed_secret:
            raise ValueError("sealed_secret required (owner-vault seal, not plaintext)")
        d = self.dir
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        from ..spine.atomicio import atomic_write_text
        atomic_write_text(self._marker(u), json.dumps({"sealed_secret": sealed_secret, "at": float(now)},
                                                      sort_keys=True))

    def peek(self, username: str, *, now: float) -> Optional[str]:
        """The sealed secret pending for ``username`` if present AND within ``ttl_s`` of ``now``, else None
        (absent / expired / unreadable / malformed — all FAIL-CLOSED to None, never activate on a bad read)."""
        u = str(username or "")
        if not u:
            return None
        try:
            fd = os.open(str(self._marker(u)), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                raw = os.read(fd, _MAX_BYTES + 1)
            finally:
                os.close(fd)
            if len(raw) > _MAX_BYTES:
                return None
            doc = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        if not isinstance(doc, dict):
            return None
        sealed = doc.get("sealed_secret")
        at = doc.get("at")
        if not isinstance(sealed, str) or not sealed or not isinstance(at, (int, float)):
            return None
        if (float(now) - float(at)) > self.ttl_s:
            return None                                  # a stale pending enrolment expires
        return sealed

    def clear(self, username: str) -> None:
        """Drop any pending secret for ``username`` (idempotent; a missing marker is fine)."""
        u = str(username or "")
        if not u:
            return
        try:
            os.unlink(str(self._marker(u)))
        except OSError:
            pass
