"""SecretStore (Phase 7, WS-D D-ii) — keyring-first secret handling. Reads/writes API keys via the
OS keyring (macOS Keychain / Windows Credential Manager / libsecret) when the `keyring` package is
present; otherwise falls back to the plaintext `~/.sigil/sigil.env` that `config._load_env_file`
already loads. Secrets NEVER enter the append-only spine, a log, or a network payload — this is
owner-local plumbing that keeps them off the plaintext file and off the wire (WS-D transport carries
only `{seq,tier,kind}`)."""
from __future__ import annotations

import os
from typing import Optional

from ..config import SIGIL_HOME

_SERVICE = "sigil"


class SecretStore:
    def __init__(self):
        try:
            import keyring
            self._kr = keyring
        except Exception:  # noqa: BLE001 — no keyring backend → env fallback only
            self._kr = None

    @property
    def backend(self) -> str:
        return "keyring" if self._kr is not None else "envfile"

    def get(self, key: str) -> Optional[str]:
        if self._kr is not None:
            try:
                v = self._kr.get_password(_SERVICE, key)
                if v is not None:
                    return v
            except Exception:  # noqa: BLE001
                pass
        return os.environ.get(key)                    # sigil.env is loaded into env at config import

    def set(self, key: str, value: str) -> str:
        """Store a secret. Returns the backend used. Prefers the keyring; falls back to sigil.env
        (0600). Never writes the value anywhere else."""
        if self._kr is not None:
            try:
                self._kr.set_password(_SERVICE, key, value)
                os.environ[key] = value               # make it live this process too
                return "keyring"
            except Exception:  # noqa: BLE001
                pass
        self._env_upsert(key, value)
        os.environ[key] = value
        return "envfile"

    @staticmethod
    def _env_upsert(key: str, value: str) -> None:
        f = SIGIL_HOME / "sigil.env"
        SIGIL_HOME.mkdir(parents=True, exist_ok=True)
        lines = []
        found = False
        try:
            for ln in f.read_text(encoding="utf-8").splitlines():
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
