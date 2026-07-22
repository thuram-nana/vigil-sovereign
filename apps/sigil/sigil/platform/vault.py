"""sigil.platform.vault — the sovereign-side owner-key vault (audit G1).

The generic sealing :class:`Vault` now lives in :mod:`vigil_core.vault` (shared by BOTH envs — SIGIL for
the owner key/secrets, the offense worker for the operator key). This module re-exports it and adds the
SIGIL-specific process-wide **owner vault** (the trust-root vault at ``SIGIL_HOME/vault``) that all
owner-key I/O (``governor.identity`` + ``spine.checkpoint``) routes through.
"""
from __future__ import annotations

import threading
from typing import Optional

from vigil_core.vault import Vault, VaultLocked

__all__ = ["Vault", "VaultLocked", "owner_vault", "reset_owner_vault_for_test", "OWNER_PRIV_CONTEXT"]

# The stable AEAD context that binds a sealed blob to its purpose, so an owner-key seal can never be
# opened as (or swapped for) another secret.
OWNER_PRIV_CONTEXT = b"sigil/owner.priv"

_owner_vault: Optional[Vault] = None
_owner_vault_lock = threading.Lock()


def owner_vault() -> Vault:
    """The process-wide vault for the sovereign trust root (sealed-KEK blobs under SIGIL_HOME/vault).
    All owner-key I/O (governor.identity + spine.checkpoint) routes through this one instance."""
    global _owner_vault
    with _owner_vault_lock:
        if _owner_vault is None:
            from ..config import SIGIL_HOME
            _owner_vault = Vault(SIGIL_HOME / "vault")
        return _owner_vault


def reset_owner_vault_for_test() -> None:
    """Drop the cached vault (tests that relocate SIGIL_HOME or inject a fake TPM runner)."""
    global _owner_vault
    with _owner_vault_lock:
        _owner_vault = None
