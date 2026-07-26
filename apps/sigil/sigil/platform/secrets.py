"""SecretStore (Phase 7, WS-D D-ii; hardened in audit G1) — tiered secret handling. Reads/writes API
keys and service passwords via, in order: the OS keyring (macOS Keychain / Windows Credential Manager /
libsecret) when the `keyring` package is present; else a **TPM-sealed store** when the owner vault has
been provisioned (`sigil vault provision`) — an AEAD-sealed JSON blob under SIGIL_HOME, so secrets rest
as ciphertext, closing the audit's plaintext-at-rest gap; else, only when NEITHER is available, the
legacy plaintext `~/.sigil/sigil.env` that `config._load_env_file` loads (unchanged, non-bricking).
Secrets NEVER enter the append-only spine, a log, or a network payload."""
from __future__ import annotations

import json
import os
from typing import Optional

from ..config import SIGIL_HOME

_SERVICE = "sigil"
# The sealed key-value secret store (one AEAD-sealed JSON blob) + its purpose-binding AEAD context.
_SEALED_FILE = SIGIL_HOME / "secrets.sealed"
_SEALED_CONTEXT = b"sigil/secrets.kv"


class SecretStore:
    def __init__(self):
        try:
            import keyring
            self._kr = keyring
        except Exception:  # noqa: BLE001 — no keyring backend → sealed/env fallback
            self._kr = None

    # --- the TPM-sealed key-value tier (used only when the owner vault is provisioned) ------------

    @staticmethod
    def _vault():
        from .vault import owner_vault
        return owner_vault()

    def _sealed_available(self) -> bool:
        try:
            return self._vault().enabled()
        except Exception:  # noqa: BLE001 — vault/config not resolvable → treat as unavailable
            return False

    def _sealed_read_all(self) -> dict:
        from .vault import VaultLocked
        try:
            raw = self._vault().read_text_secret(_SEALED_FILE, context=_SEALED_CONTEXT)
        except VaultLocked:
            return {}  # sealed store present but TPM locked → no secrets surfaced (fail-closed)
        if not raw:
            return {}
        try:
            d = json.loads(raw)
            return d if isinstance(d, dict) else {}
        except Exception:  # noqa: BLE001 — a corrupt sealed store yields no secrets, never a crash
            return {}

    def _sealed_write(self, key: str, value: str) -> None:
        d = self._sealed_read_all()
        d[key] = value
        self._vault().write_text_secret(_SEALED_FILE, json.dumps(d), context=_SEALED_CONTEXT)

    @property
    def backend(self) -> str:
        if self._kr is not None:
            return "keyring"
        return "sealed" if self._sealed_available() else "envfile"

    def get(self, key: str) -> Optional[str]:
        if self._kr is not None:
            try:
                v = self._kr.get_password(_SERVICE, key)
                if v is not None:
                    return v
            except Exception:  # noqa: BLE001
                pass
        if self._sealed_available():
            v = self._sealed_read_all().get(key)
            if v is not None:
                return v
        return os.environ.get(key)                    # sigil.env is loaded into env at config import

    def set(self, key: str, value: str) -> str:
        """Store a secret. Returns the backend used. Prefers the keyring; else the TPM-sealed store when
        the vault is provisioned (never plaintext); else the legacy sigil.env (0600, unchanged)."""
        if self._kr is not None:
            try:
                self._kr.set_password(_SERVICE, key, value)
                os.environ[key] = value               # make it live this process too
                return "keyring"
            except Exception:  # noqa: BLE001
                pass
        if self._sealed_available():
            self._sealed_write(key, value)
            os.environ[key] = value                   # live this process; the at-rest copy is sealed
            return "sealed"
        self._env_upsert(key, value)
        os.environ[key] = value
        return "envfile"

    @staticmethod
    def _env_upsert(key: str, value: str) -> None:
        # The envfile is the injectable KEY=value tier; any caller (set_secret, agents/vault passwords, a
        # direct SecretStore().set) reaches here, so the line-injection guard lives AT this write primitive
        # — a value with a literal "\n"/Unicode line separator must never plant a second line.
        from ..config import assert_env_value_safe
        assert_env_value_safe(value, f"secret value for {key}")
        f = SIGIL_HOME / "sigil.env"
        SIGIL_HOME.mkdir(parents=True, exist_ok=True)
        lines = []
        found = False
        try:
            # Parse on "\n" ONLY (not str.splitlines()) so a stored value containing a Unicode line
            # separator (U+0085/U+2028/U+2029) is never re-split + re-materialized as a real newline on
            # the next upsert (an envfile line-injection). Blank lines are dropped.
            for ln in f.read_text(encoding="utf-8").split("\n"):
                if not ln.strip():
                    continue
                if ln.split("=", 1)[0].strip() == key:
                    lines.append(f"{key}={value}"); found = True
                else:
                    lines.append(ln)
        except OSError:
            pass
        if not found:
            lines.append(f"{key}={value}")
        # create with 0600 up-front (no world-readable window on first write) — N4
        fd = os.open(str(f), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
