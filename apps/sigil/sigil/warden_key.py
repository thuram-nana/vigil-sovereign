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


_PENDING = "warden.rotation.pending"   # crash journal: the proven succession link for an in-flight rotation


def _append_link(wh: Path, link: dict) -> None:
    """Durably append one succession link to the append-only chain (fsync'd). The single append site shared by
    the rotation commit and the reconciler, so the two never drift."""
    with (wh / _SUCCESSION).open("a", encoding="utf-8") as f:
        f.write(json.dumps(link, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _link_matches(rec: dict, link: dict) -> bool:
    """Is an on-disk succession record the SAME link as ``link`` (by the signed identity: seq + old/new pub)?
    Used to make the reconciler's append idempotent — never a duplicate link."""
    return (rec.get("seq") == link.get("seq") and rec.get("old_pub") == link.get("old_pub")
            and rec.get("new_pub") == link.get("new_pub"))


def rotate_warden_key(home, vault) -> dict:
    """Rotate the WARDEN kernel key: mint a fresh Ed25519 keypair, CROSS-SIGN the succession with the
    OUTGOING key, and commit through a CRASH JOURNAL so a resumed rotation always completes — never a live
    new key with no succession link (red-pen MEDIUM). Fail-closed: refuses if there is no existing key to
    succeed. Returns the new public key + seq.

    The staged journal (all durable BEFORE any live swap) holds the sealed new key (``warden.key.rot``), the
    new pub (``warden.pub.rot``) and the proven link (``warden.rotation.pending``). Commit then appends the
    link, swaps the key + pub, and drops the journal. A crash at ANY point leaves enough on disk for
    :func:`reconcile_warden_rotation` to finish the exact same rotation (the link is proven + persisted, the
    new key material is staged), so verification is never left broken."""
    wh = warden_home(home)
    wh.mkdir(parents=True, exist_ok=True)
    kp, pp = _key_path(wh), _pub_path(wh)

    # A prior interrupted rotation must be settled before starting a new one (fail-closed).
    if (wh / _PENDING).exists():
        raise WardenKeyError("a prior WARDEN rotation is unfinished (warden.rotation.pending present) — run "
                             "`sigil key reconcile` before rotating again")

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

    key_rot = kp.with_name(kp.name + ".rot")
    pub_rot = pp.with_name(pp.name + ".rot")
    pending = wh / _PENDING
    key_backup = kp.read_bytes() if kp.exists() else None
    pub_backup = pp.read_text(encoding="utf-8") if pp.exists() else None
    try:
        # STAGE (durable) — seal the new key + write the new pub to `.rot` names, then journal the link. The
        # link (pending) is written LAST, so its presence guarantees the staged key material is already there.
        vault.write_bytes_secret(key_rot, new_seed, context=WARDEN_KEY_CONTEXT)   # sealed iff vault enabled
        _atomic_write_text(pub_rot, new_pub)
        rt = vault.read_bytes_secret(key_rot, context=WARDEN_KEY_CONTEXT)          # prove the staged key is good
        if rt is None or _derive_pub_hex(rt) != new_pub:
            raise WardenKeyError("staged WARDEN key does not derive its public key — aborting")
        _atomic_write_text(pending, json.dumps({"link": link, "expected_old_pub": old_pub}, ensure_ascii=False))
    except Exception as e:  # noqa: BLE001 — nothing live was touched; clear the staged artifacts (fail-closed)
        for stray in (key_rot, pub_rot, pending):
            _unlink(stray)
        raise WardenKeyError(f"WARDEN rotation staging failed (nothing swapped): {e}") from e

    try:
        # COMMIT — append the link, swap the key + pub, drop the journal. A crash between any two steps is
        # completed by reconcile_warden_rotation (the pending journal carries the link + staged material).
        _append_link(wh, link)
        os.replace(key_rot, kp)
        os.replace(pub_rot, pp)
        rt = vault.read_bytes_secret(kp, context=WARDEN_KEY_CONTEXT)
        if rt is None or _derive_pub_hex(rt) != new_pub or pp.read_text(encoding="utf-8").strip() != new_pub:
            raise WardenKeyError("post-swap WARDEN key does not derive its public key")
        _unlink(pending)
    except Exception as e:  # noqa: BLE001 — commit is resumable; leave the journal for the reconciler.
        raise WardenKeyError(f"WARDEN rotation commit interrupted — run `sigil key reconcile` to finish "
                             f"(key material + succession link are journaled): {e}") from e
    _ = (key_backup, pub_backup)  # retained only for readability of the pre-commit state; no rollback post-commit
    return {"seq": seq, "old_pub": old_pub, "new_pub": new_pub}


def warden_rotation_incomplete(home) -> bool:
    """True iff a WARDEN rotation journal (``warden.rotation.pending``) is present — a rotation was interrupted
    mid-commit and must be reconciled (else the live key may lack its succession link). Cheap disk check."""
    return (warden_home(home) / _PENDING).exists()


def reconcile_warden_rotation(home, vault) -> dict:
    """Finish an interrupted WARDEN key rotation (red-pen MEDIUM). If a journal is present, drive the on-disk
    state to a consistent, verifiable one by COMPLETING the exact rotation it records: ensure the proven
    succession link is appended (idempotent), swap in the staged key + pub if not yet swapped, verify, then
    drop the journal. Fail-closed + idempotent: no journal → no-op; a state it cannot complete + verify leaves
    the journal in place and raises :class:`WardenKeyError` (never a live new key with no succession link)."""
    wh = warden_home(home)
    kp, pp = _key_path(wh), _pub_path(wh)
    pending = wh / _PENDING
    if not pending.exists():
        return {"status": "clean"}
    try:
        journal = json.loads(pending.read_text(encoding="utf-8"))
        link = journal["link"]
        new_pub = link["new_pub"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise WardenKeyError(f"WARDEN reconcile: the rotation journal is unreadable/malformed (fail-closed): {e}") from e

    key_rot = kp.with_name(kp.name + ".rot")
    pub_rot = pp.with_name(pp.name + ".rot")

    # do we have the new key live, or staged? (identify by the KEY deriving new_pub, not the pub file).
    cur_seed = vault.read_bytes_secret(kp, context=WARDEN_KEY_CONTEXT)
    key_is_new = cur_seed is not None and len(cur_seed) == 32 and _derive_pub_hex(cur_seed) == new_pub

    if not key_is_new and not key_rot.exists():
        raise WardenKeyError("WARDEN reconcile: neither the live key nor a staged `.rot` derives the pending "
                             "new_pub — cannot complete safely (keeping the journal, fail-closed)")

    # 1) ensure the proven succession link is appended exactly once.
    records = _read_succession(wh)
    if not (records and _link_matches(records[-1], link)):
        _append_link(wh, link)

    # 2) ensure the key is swapped in, then consume any leftover staged key.
    if not key_is_new and key_rot.exists():
        os.replace(key_rot, kp)
    _unlink(key_rot)   # idempotent: os.replace above already consumed it, or it was a stale leftover
    # ensure the pub file matches new_pub.
    if pub_rot.exists():
        os.replace(pub_rot, pp)
    else:
        cur_pub = pp.read_text(encoding="utf-8").strip() if pp.exists() else None
        if cur_pub != new_pub:
            _atomic_write_text(pp, new_pub)

    # 3) verify the completed state, then drop the journal (fail-closed if it does not verify).
    rt = vault.read_bytes_secret(kp, context=WARDEN_KEY_CONTEXT)
    if rt is None or _derive_pub_hex(rt) != new_pub or pp.read_text(encoding="utf-8").strip() != new_pub:
        raise WardenKeyError("WARDEN reconcile: post-completion key does not derive new_pub (keeping journal)")
    ok, why = verify_warden_succession(home)
    if not ok:
        raise WardenKeyError(f"WARDEN reconcile: succession still does not verify after completion: {why}")
    _unlink(pending)
    return {"status": "completed", "new_pub": new_pub}


def _unlink(p: Path) -> None:
    try:
        p.unlink()
    except OSError:
        pass


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
