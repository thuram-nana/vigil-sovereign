"""CredentialVault (Phase 8, WS-G G-i) — the owner's OWN per-service credentials. Extends
`platform.secrets.SecretStore` preserving its invariant verbatim ("Secrets NEVER enter the append-only
spine, a log, or a network payload"). A `VaultRecord` has NO `password` field — only a `password_ref`
(a keyring key name); the password lives in the OS keyring. The manifest (email/username/ref/version)
lives in a 0700 dir OFF the append-only spine. The password is resolved from the keyring ONLY at
execute time, into a local variable — never assigned to a Proposal payload, never logged, never
journaled. `version` bumps on every edit and BINDS an approval (rotate → version bump → re-approval),
so the spine binds by `service+vault_ref+version` — deliberately NOT a hash of the value (hashing a
low-entropy identity field onto an append-only log is itself a weak-preimage leak)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import SIGIL_HOME

_VAULT = SIGIL_HOME / "vault"
_MANIFEST = _VAULT / "manifest.json"


@dataclass(frozen=True)
class VaultRecord:
    service: str
    email: str = ""
    username: str = ""
    password_ref: str = ""            # keyring key name — NOT the password
    notes: str = ""
    version: int = 1


class CredentialVault:
    def __init__(self, secret_store=None):
        from ..platform.secrets import SecretStore
        self.secrets = secret_store or SecretStore()

    def _load(self) -> dict:
        try:
            return json.loads(_MANIFEST.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        _VAULT.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(_VAULT, 0o700)
        except OSError:
            pass
        fd = os.open(str(_MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # 0600 up-front
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def set_record(self, service: str, *, email: str = "", username: str = "",
                   password: Optional[str] = None, notes: str = "") -> VaultRecord:
        ref = f"vault/{service}/password"
        if password is not None:
            self.secrets.set(ref, password)          # → keyring (or 0600 sigil.env), never the spine
        data = self._load()
        prev = data.get(service, {})
        rec = {"service": service, "email": email or prev.get("email", ""),
               "username": username or prev.get("username", ""), "password_ref": ref,
               "notes": notes or prev.get("notes", ""), "version": int(prev.get("version", 0)) + 1}
        data[service] = rec
        self._save(data)
        return VaultRecord(**rec)

    def get_record(self, service: str) -> Optional[VaultRecord]:
        d = self._load().get(service)
        return VaultRecord(**d) if d else None

    def records(self) -> List[VaultRecord]:
        return [VaultRecord(**d) for d in self._load().values()]

    def resolve_password(self, service: str) -> Optional[str]:
        """Fetch the password from the keyring — call ONLY at execute-time, into a local var."""
        rec = self.get_record(service)
        return self.secrets.get(rec.password_ref) if rec else None
