"""vigil_core.vault — at-rest sealing of secret files under a TPM-sealed KEK (audit G1).

The shared vault used by BOTH envs (sovereign SIGIL for the owner key/secrets, offense worker for the
operator key) — living in vigil_core so neither side re-implements it and the two-env boundary is
unaffected. Opt-in and non-bricking by construction:

  * UNTIL :meth:`Vault.provision` is run once (sealing a fresh KEK to this machine's TPM), the vault is
    DISABLED and every read/write is EXACTLY today's plaintext behaviour (a loud "unsealed" status is
    surfaced) — nothing changes, nothing can break.
  * ONCE provisioned, writes seal + reads unseal transparently; a legacy plaintext file MIGRATES on first
    read NON-DESTRUCTIVELY — the sealed copy is verified to round-trip BEFORE the plaintext is replaced,
    so a migration can never lose the secret.
  * If the TPM later cannot unseal (moved disk / tooling gone), sealed reads fail CLOSED
    (:class:`VaultLocked`) — never a silent plaintext fallback.

The TPM is reached only through :mod:`vigil_core.kek`'s injectable runner seam, so the whole vault is
unit-tested deterministically with a fake TPM; the live path activates once ``tpm2-tools`` + ``tss`` group
are configured (one-time operator setup).
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Optional

from .kek import KekError, TpmRunner, _default_tpm_runner, is_provisioned, load_kek, provision_kek
from .sealing import SealError, is_sealed, seal, unseal


class VaultLocked(Exception):
    """The vault is provisioned (sealed mode) but the KEK could not be unsealed from the TPM — sealed
    material cannot be read. Fail-closed; NEVER degrades to plaintext."""


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes with mode 0600 set BEFORE the secret lands, then atomically replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


class Vault:
    """Seals/opens secret files under a TPM-sealed KEK. ``vault_dir`` holds the sealed-KEK blobs;
    ``runner`` is the injectable tpm2 seam (a fake in tests, the real subprocess in production)."""

    def __init__(self, vault_dir, runner: TpmRunner = _default_tpm_runner) -> None:
        self._dir = Path(vault_dir)
        self._runner = runner
        self._kek_cache: Optional[bytes] = None
        self._lock = threading.RLock()

    # --- provisioning + status --------------------------------------------------------------------

    def enabled(self) -> bool:
        """True iff a sealed KEK has been provisioned here (i.e. sealing is ON)."""
        return is_provisioned(self._dir)

    def provision(self) -> None:
        """One-time: generate + TPM-seal a fresh KEK for this machine. Raises :class:`KekError` if the
        TPM is unavailable (fail-closed — never provisions a fake/plaintext KEK). Existing plaintext key
        files are migrated lazily (on their next read), non-destructively."""
        provision_kek(self._dir, runner=self._runner)
        with self._lock:
            self._kek_cache = None  # force a fresh unseal next use

    def status(self) -> str:
        return ("sealed (TPM-sealed KEK)" if self.enabled()
                else "UNSEALED — trust-root keys/secrets are PLAINTEXT at rest; run `sigil vault provision`")

    # --- read / write / migrate -------------------------------------------------------------------

    def _kek(self) -> bytes:
        with self._lock:
            if self._kek_cache is None:
                try:
                    self._kek_cache = load_kek(self._dir, runner=self._runner)
                except KekError as e:
                    raise VaultLocked(f"cannot unseal the KEK from the TPM: {e}") from e
            return self._kek_cache

    def read_text_secret(self, path, *, context: bytes) -> Optional[str]:
        """Read a UTF-8 secret (e.g. a base64 private key). Transparently unseals a sealed file, or
        returns plaintext (legacy). When the vault is ENABLED and the file is still plaintext, migrate it
        non-destructively first. Returns None if absent/empty. Fail-closed on a sealed file we can't open."""
        p = Path(path)
        try:
            raw = p.read_bytes()
        except OSError:
            return None
        if is_sealed(raw):
            try:
                return unseal(self._kek(), raw, context=context).decode("utf-8")
            except SealError as e:
                raise VaultLocked(f"sealed secret {p.name} failed to open: {e}") from e
        text = raw.decode("utf-8", errors="strict").strip()
        if not text:
            return None
        if self.enabled():
            self._migrate_text(p, text, context)  # opportunistic, non-destructive
        return text

    def write_text_secret(self, path, value: str, *, context: bytes) -> None:
        """Persist a UTF-8 secret — sealed when the vault is enabled, else plaintext (unchanged legacy
        behaviour). Atomic + 0600."""
        p = Path(path)
        if self.enabled():
            blob = seal(self._kek(), value.encode("utf-8"), context=context)
            _atomic_write_bytes(p, blob)
        else:
            _atomic_write_bytes(p, value.encode("utf-8"))

    def _migrate_text(self, path: Path, text: str, context: bytes) -> None:
        """Seal an existing plaintext secret IN PLACE, non-destructively: seal → VERIFY the sealed copy
        round-trips to the exact original → only THEN atomically replace the plaintext. A migration can
        never lose or corrupt the key. Idempotent (a second call sees a sealed file and no-ops)."""
        kek = self._kek()
        blob = seal(kek, text.encode("utf-8"), context=context)
        if unseal(kek, blob, context=context).decode("utf-8") != text:  # paranoia: prove recoverability
            raise VaultLocked(f"refusing to migrate {path.name}: sealed copy did not round-trip")
        _atomic_write_bytes(path, blob)
