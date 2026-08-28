"""Owner passkey (WebAuthn) credential store — an owner-SIGNED 0600 file (Slice 1c-iii).

The owner's registered passkeys live in a single owner-signed JSON file under `SIGIL_HOME/.vigil-live/`, not
on the append-only spine: a passkey credential is small, owner-only, and needs an in-place `sign_count`
UPDATE on every login, so a file (like the 1b bootstrap token) fits better than a prune-safe spine fold. It
is TAMPER-EVIDENT — the whole credential set is signed with the persisted owner Ed25519 key and verified on
read; a tampered, unsigned, or wrong-key file yields NO credentials (FAIL-CLOSED → the owner falls back to
password recovery, never a forged passkey). Register / revoke / assert emit spine AUDIT events (1c-i)
separately for the trail.

Sovereign-side; imports only the governor owner-key primitives (no framework/strix). Offense-free.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Optional

from ..config import SIGIL_HOME
from ..governor.authn import signed_payload, verify_signed
from ..governor.identity import owner_keypair, owner_pubkey

SIGNAL = "webauthn.creds"
_CORE_FIELDS = ("signal", "credentials")
WEBAUTHN_RELPATH = os.path.join(".vigil-live", "webauthn-credentials.json")


def webauthn_store_path(home: "Optional[Path]" = None) -> Path:
    return (home or SIGIL_HOME) / WEBAUTHN_RELPATH


class WebAuthnStore:
    """The owner's passkey credentials, owner-signed at rest. Each credential is a dict:
    {credential_id, cose_alg, public_key_spki_b64, sign_count, uv}. `credential_id` is the base64url raw id."""

    def __init__(self, *, path: "Optional[Path]" = None, owner_key=None, trusted_pubkey: "Optional[str]" = None):
        self.path = path or webauthn_store_path()
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- reads --------------------------------------------------------------------------------------
    def credentials(self) -> "list[dict]":
        """The verified owner-signed credential list, or [] (fail-closed on a missing / unreadable /
        unsigned / tampered / wrong-key file — the owner then cannot log in by passkey and uses recovery)."""
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(payload, dict) or payload.get("signal") != SIGNAL:
            return []
        if not verify_signed(payload, _CORE_FIELDS, self.trusted_pubkey):
            return []                       # tampered / unsigned / wrong key ⇒ no credentials (fail-closed)
        creds = payload.get("credentials")
        return [c for c in creds if isinstance(c, dict)] if isinstance(creds, list) else []

    def get(self, credential_id: str) -> "Optional[dict]":
        for c in self.credentials():
            if c.get("credential_id") == credential_id:
                return c
        return None

    # -- owner-signed mutations ---------------------------------------------------------------------
    def _write(self, creds: "list[dict]") -> None:
        if self.owner_key is None:
            raise ValueError("owner signing key required to write the passkey store")
        core = {"signal": SIGNAL, "credentials": creds}
        payload = signed_payload(core, self.owner_key)
        data = json.dumps(payload).encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_name(f"{self.path.name}.{secrets.token_hex(8)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp), flags, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def register(self, *, credential_id: str, cose_alg: int, public_key_spki_b64: str,
                 uv: bool = False) -> None:
        """Owner-bind a passkey. Replaces any existing credential with the same id (re-registration). The
        sign_count starts at 0 (a fresh authenticator counter, or a non-counting one)."""
        creds = [c for c in self.credentials() if c.get("credential_id") != credential_id]
        creds.append({"credential_id": str(credential_id), "cose_alg": int(cose_alg),
                      "public_key_spki_b64": str(public_key_spki_b64), "sign_count": 0, "uv": bool(uv)})
        self._write(creds)

    def update_sign_count(self, credential_id: str, new_count: int) -> None:
        """Persist the monotonic signCount after a verified assertion (the clone-detection floor). No-op if
        the credential is gone."""
        creds = self.credentials()
        changed = False
        for c in creds:
            if c.get("credential_id") == credential_id:
                c["sign_count"] = int(new_count)
                changed = True
        if changed:
            self._write(creds)

    def revoke(self, credential_id: str) -> bool:
        creds = self.credentials()
        kept = [c for c in creds if c.get("credential_id") != credential_id]
        if len(kept) == len(creds):
            return False
        self._write(kept)
        return True

    def revoke_all(self) -> int:
        creds = self.credentials()
        if creds:
            self._write([])
        return len(creds)
