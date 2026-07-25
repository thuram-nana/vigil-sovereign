"""Persisted, optionally-sealed Ed25519 keypairs — the ONE load-or-create implementation (unification S5).

Two offense-side identities need the same behaviour: a stable Ed25519 keypair, generated once and persisted
``0600``, AEAD-sealed at rest when a provisioned vault is supplied, validated on load (weak-key rejection +
priv/pub round-trip), and fail-closed on a sealed-but-unopenable file (never silently minting a NEW divergent
identity). Before S5 that logic lived only in ``attestation/identity.py`` for the operator key; S5 adds a
stable offense-SPINE key with the exact same needs. Rather than copy the crypto (two implementations of one
security-critical routine drift), this is the single shared helper both call, each with its OWN AEAD
``context`` so a blob sealed for one identity can never be opened as the other.

Pure ``vigil_core`` (crypto + a duck-typed vault); importable in both envs. No wallclock, no RNG beyond the
one-time key generation (which is not chain/ordering math)."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from .crypto import KeyPair, generate_keypair, load_public_key, sign, verify_one

_log = logging.getLogger(__name__)

# A transient probe message used only to confirm a loaded private key matches its public key; never persisted.
_PROBE = b"vigil-core/keystore/probe/v1"


def load_or_create_sealed_keypair(*, path: str, context: bytes, vault: object = None) -> KeyPair:
    """Load the persisted keypair at ``path``, or generate + persist one (``0600``) on first use.

    ``context`` is the AEAD purpose-binding for the sealed file — pass a DISTINCT value per identity so a
    blob sealed here can never be opened as another secret. A loaded public key is validated through
    ``load_public_key`` (rejecting non-canonical / low-order weak keys) and the private key by round-tripping
    a signature it must verify; any problem (missing/corrupt/weak/mismatched) falls through to a FRESH key so
    the caller always ends up with a sound identity. Persistence is best-effort (the fresh key is usable in
    memory this run even if the disk write fails). If ``vault`` is supplied AND provisioned the file is sealed
    at rest; a sealed file the TPM cannot unseal propagates ``VaultLocked`` (fail-closed) rather than minting
    a new divergent identity."""
    p = Path(path)
    loaded = _try_load(p, context, vault)
    if loaded is not None:
        return loaded
    kp = generate_keypair()
    _persist(p, kp, context, vault)
    return kp


def _try_load(p: Path, context: bytes, vault: object = None) -> Optional[KeyPair]:
    """Read + validate a persisted keypair, total. Returns None on any missing/corrupt/weak/mismatched
    material. A sealed-but-unopenable file (locked TPM) propagates ``VaultLocked`` — fail-closed, never a
    silent new key."""
    if vault is not None:
        text = vault.read_text_secret(p, context=context)  # VaultLocked propagates (fail-closed)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except Exception:  # noqa: BLE001 — corrupt sealed/plaintext JSON → regenerate
            return None
    else:
        try:
            data = json.loads(p.read_text())
        except Exception:  # noqa: BLE001 — no file / unreadable / non-JSON → regenerate
            return None
    if not isinstance(data, dict):
        return None
    pub = data.get("public_key_b64")
    priv = data.get("private_key_b64")
    if not isinstance(pub, str) or not isinstance(priv, str) or not pub or not priv:
        return None
    try:
        load_public_key(pub)          # rejects non-canonical / low-order weak keys
        probe = sign(priv, _PROBE)    # validates the private key material
    except Exception:  # noqa: BLE001 — weak/invalid persisted key → regenerate rather than trust it
        return None
    if not verify_one(pub, _PROBE, probe):
        return None                   # pub/priv are not a matched pair → regenerate
    return KeyPair(public_key_b64=pub, private_key_b64=priv)


def _persist(p: Path, kp: KeyPair, context: bytes, vault: object = None) -> None:
    """Atomically persist the keypair at ``0600``, best-effort (a disk failure never breaks minting). When a
    provisioned ``vault`` is supplied the keypair is AEAD-sealed at rest under ``context``; else plaintext."""
    payload = json.dumps({"public_key_b64": kp.public_key_b64, "private_key_b64": kp.private_key_b64})
    if vault is not None:
        try:
            vault.write_text_secret(p, payload, context=context)  # sealed iff the vault is provisioned
        except Exception as exc:  # noqa: BLE001 — best-effort; the in-memory keypair still works this run
            _warn_persist_failed(p, exc)
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        # create 0600 from the start so the private key is never briefly world-readable.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    except Exception as exc:  # noqa: BLE001 — best-effort persistence; the in-memory keypair still works this run
        _warn_persist_failed(p, exc)


def _warn_persist_failed(p: Path, exc: Exception) -> None:
    """A persist failure is non-fatal (the key works in memory this run) but must be OBSERVABLE: if it was a
    FIRST-use mint, the next run finds no file and generates a DIFFERENT key — silently orphaning any records
    the in-memory key signed (for the offense spine, exactly the pre-S5 ephemeral-key failure). Warn loudly so
    an operator sees it rather than discovering an un-verifiable spine later."""
    _log.warning("failed to persist keypair at %s: %s — identity is IN-MEMORY ONLY this run; a restart will "
                 "mint a different key and cannot verify records signed now", p, exc)
