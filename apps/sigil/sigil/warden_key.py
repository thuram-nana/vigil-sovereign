"""Rotate + seal the WARDEN kernel key (audit W9-2).

The WARDEN kernel signing key (``warden/warden.key`` — a 32-byte Ed25519 seed the Rust kernel writes
plaintext-0600, ``kernel/src/crypto.rs``) had NO rotation and was left PLAINTEXT even on a TPM host. This
module closes both gaps on the Python (vault-owning) side:

  * SEAL — :func:`seal_warden_key` seals the key at rest under the TPM KEK when a vault is provisioned
    (non-destructive, verify-round-trip-then-replace via :meth:`Vault.seal_file`). Because the Rust kernel
    reads ``warden.key`` as 32 raw bytes, a sealed key must be MATERIALISED to plaintext just before the
    kernel starts (:func:`materialize_warden_key`) — the boot step that hands the kernel its key is the
    live wiring leg; the sealing/unsealing LOGIC and its at-rest ciphertext are tested here.

  * ROTATE — :func:`rotate_warden_key` mints a fresh keypair and records a CROSS-SIGNED SUCCESSION (the
    OUTGOING key signs the incoming public key into an append-only ``warden.succession.jsonl``), so a
    verifier can walk old→new and every action-log entry signed under a prior key still authenticates —
    the same succession design as owner-key rotation (W9-1 #434), applied to the kernel key. The key files
    are swapped verify-then-swap with rollback, and the fresh key is sealed at rest. Re-signing the
    kernel's action log is unnecessary (succession preserves verifiability); teaching the Rust kernel to
    consume a sealed key at boot is the live leg.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vigil_core.canonical import canonical_json
from vigil_core.crypto import sign, verify_one

WARDEN_KEY_CONTEXT = b"sigil/warden.key"
_SUCCESSION = "warden.succession.jsonl"
_SUCCESSION_DOMAIN = "sigil/warden-succession/v1"


class WardenKeyError(Exception):
    """A WARDEN-key seal or rotation could not be completed / proven (fail-closed)."""


def warden_home(home) -> Path:
    """The WARDEN kernel dir — ``$SIGIL_WARDEN_HOME`` or ``<home>/warden`` (mirror of the Rust kernel's
    ``warden_dir()`` and backup._warden_home; the single on-disk location for the kernel keypair)."""
    return Path(os.environ.get("SIGIL_WARDEN_HOME") or (Path(home) / "warden"))


def _key_path(wh: Path) -> Path:
    return wh / "warden.key"


def _pub_path(wh: Path) -> Path:
    return wh / "warden.pub"


def _derive_pub_hex(seed: bytes) -> str:
    """Derive the Ed25519 public key (hex, matching the kernel's ``hex(verifying_key.to_bytes())``) from a
    32-byte private seed — the exact construction ``SigningKey::from_bytes(seed)`` uses (RFC 8032)."""
    if len(seed) != 32:
        raise WardenKeyError(f"WARDEN seed must be 32 bytes, got {len(seed)}")
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


# --- sealing ---------------------------------------------------------------------------------------


def seal_warden_key(home, vault) -> str:
    """Seal ``warden/warden.key`` at rest under the vault KEK when the vault is provisioned. Returns the
    :meth:`Vault.seal_file` status (``"sealed"`` / ``"already-sealed"`` / ``"disabled"`` / ``"absent"``).
    Non-destructive (verify-round-trip-then-replace). No-op (``"disabled"``) when the vault is off."""
    return vault.seal_file(_key_path(warden_home(home)), context=WARDEN_KEY_CONTEXT)


def materialize_warden_key(home, vault) -> Optional[bytes]:
    """Return the plaintext 32-byte WARDEN seed (unsealing it if it rests sealed), for a boot step to write
    where the Rust kernel reads it. ``None`` if absent. Raises ``VaultLocked`` (fail-closed) if the key
    rests sealed and the TPM cannot unseal — never a silent plaintext fallback."""
    seed = vault.read_bytes_secret(_key_path(warden_home(home)), context=WARDEN_KEY_CONTEXT)
    if seed is not None and len(seed) != 32:
        raise WardenKeyError(f"materialised WARDEN key is {len(seed)} bytes, expected 32 (fail-closed)")
    return seed


# --- rotation with cross-signed succession ---------------------------------------------------------


def _succession_bytes(old_pub: str, new_pub: str, seq: int) -> bytes:
    return canonical_json({"d": _SUCCESSION_DOMAIN, "old_pub": old_pub, "new_pub": new_pub, "seq": seq})


def _read_succession(wh: Path) -> list[dict]:
    p = wh / _SUCCESSION
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def rotate_warden_key(home, vault) -> dict:
    """Rotate the WARDEN kernel key: mint a fresh Ed25519 keypair, CROSS-SIGN the succession with the
    OUTGOING key, verify-then-swap the key/pub files (rollback on any failure), and seal the fresh key at
    rest. Fail-closed: refuses if there is no existing key to succeed. Returns the new public key + seq."""
    wh = warden_home(home)
    wh.mkdir(parents=True, exist_ok=True)
    kp, pp = _key_path(wh), _pub_path(wh)

    old_seed = vault.read_bytes_secret(kp, context=WARDEN_KEY_CONTEXT)  # unseals if sealed; plaintext otherwise
    if old_seed is None:
        raise WardenKeyError("no existing WARDEN key to rotate — the kernel must create one first")
    if len(old_seed) != 32:
        raise WardenKeyError(f"existing WARDEN key is {len(old_seed)} bytes, expected 32 (refusing to rotate)")
    old_pub = _derive_pub_hex(old_seed)

    new_seed = os.urandom(32)
    if new_seed == old_seed:
        raise WardenKeyError("fresh WARDEN seed collided with the current one — aborting")
    new_pub = _derive_pub_hex(new_seed)

    # CROSS-SIGN: the outgoing key signs the incoming public key into the append-only succession chain.
    records = _read_succession(wh)
    seq = (records[-1]["seq"] + 1) if records else 1
    sig = sign(base64.b64encode(old_seed).decode("ascii"), _succession_bytes(old_pub, new_pub, seq))
    link = {"v": 1, "kind": "warden.succession", "seq": seq, "old_pub": old_pub, "new_pub": new_pub, "sig": sig}
    # prove the link before we touch anything (fail-closed).
    if not verify_one(base64.b64encode(bytes.fromhex(old_pub)).decode("ascii"),
                      _succession_bytes(old_pub, new_pub, seq), sig):
        raise WardenKeyError("could not self-verify the succession signature (refusing to rotate)")

    # verify-then-swap the key material, with rollback of BOTH files on any failure.
    key_backup = kp.read_bytes() if kp.exists() else None
    pub_backup = pp.read_text(encoding="utf-8") if pp.exists() else None
    try:
        vault.write_bytes_secret(kp, new_seed, context=WARDEN_KEY_CONTEXT)   # sealed iff vault enabled
        _atomic_write_text(pp, new_pub)
        # prove the swapped-in key derives the swapped-in pub (detects a bad write before we commit succession).
        rt = vault.read_bytes_secret(kp, context=WARDEN_KEY_CONTEXT)
        if rt is None or _derive_pub_hex(rt) != new_pub or pp.read_text(encoding="utf-8").strip() != new_pub:
            raise WardenKeyError("swapped-in WARDEN key does not derive its public key — rolling back")
    except Exception as e:  # noqa: BLE001 — roll BOTH files back to the outgoing key (fail-closed)
        if key_backup is not None:
            _atomic_write_bytes(kp, key_backup)
        if pub_backup is not None:
            _atomic_write_text(pp, pub_backup)
        raise WardenKeyError(f"WARDEN key swap failed and was rolled back: {e}") from e

    # only after the key is safely swapped: append the succession link (append-only, ordered).
    with (wh / _SUCCESSION).open("a", encoding="utf-8") as f:
        f.write(json.dumps(link, ensure_ascii=False) + "\n")
    return {"seq": seq, "old_pub": old_pub, "new_pub": new_pub}


def verify_warden_succession(home) -> tuple[bool, str]:
    """Walk the append-only succession chain: every link's signature must verify under its ``old_pub``, each
    link must continue the previous (``old_pub[i] == new_pub[i-1]``), and the final ``new_pub`` must equal
    the current ``warden.pub``. Returns ``(ok, reason)``. A forged link (not signed by the incumbent) or a
    broken continuity fails closed — this is what lets a verifier trust history across rotations."""
    wh = warden_home(home)
    records = _read_succession(wh)
    if not records:
        return True, "no rotations recorded (genesis key)"
    prev_new: Optional[str] = None
    for i, link in enumerate(records):
        old_pub, new_pub, seq, sig = link.get("old_pub"), link.get("new_pub"), link.get("seq"), link.get("sig")
        if not all(isinstance(x, str) for x in (old_pub, new_pub, sig)) or not isinstance(seq, int):
            return False, f"succession link {i} is malformed"
        if prev_new is not None and old_pub != prev_new:
            return False, f"succession break at link {i}: old_pub does not continue the previous new_pub"
        try:
            pub_b64 = base64.b64encode(bytes.fromhex(old_pub)).decode("ascii")
        except ValueError:
            return False, f"succession link {i}: old_pub is not valid hex"
        if not verify_one(pub_b64, _succession_bytes(old_pub, new_pub, seq), sig):
            return False, f"succession link {i}: signature does not verify under the incumbent (old) key"
        prev_new = new_pub
    pub_file = _pub_path(wh)
    if pub_file.exists() and pub_file.read_text(encoding="utf-8").strip() != prev_new:
        return False, "the final succession new_pub does not match the current warden.pub"
    return True, f"succession chain verified across {len(records)} rotation(s)"


# --- atomic file helpers (0600 for the private seed) -----------------------------------------------


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


def _atomic_write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(str(tmp), str(path))
