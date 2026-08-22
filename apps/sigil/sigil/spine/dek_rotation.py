"""Rotate the per-spine DATA KEY (DEK) — re-encrypt every sealed content field under a fresh DEK (W9-2).

The spine DEK (``spine/keys/spine.dek``, itself sealed under the TPM KEK) field-seals the sensitive human
CONTENT of spine payloads at rest (see :mod:`sigil.spine.envelope`). Rotating it means RE-ENCRYPTING that
content: open each sealed field under the OLD DEK and re-seal it under a FRESH DEK, so the old DEK can no
longer read anything and every prior payload still reads under the new one.

Unlike a KEK rotation (which re-wraps the DEK *file* and leaves ciphertext — and therefore ``cert_digest``
— untouched), re-encrypting content CHANGES every sealed field's ciphertext, which changes each record's
``cert_digest`` and thus its ``entry_hash`` — so the whole hash-chain is REBUILT and the owner-signed head
must be re-signed. That is why this module handles a plain, UN-ANCHORED single-file spine end-to-end and
FAIL-CLOSED refuses a segmented or already-anchored spine (a signed head / durable floor / segment
manifest): re-keying those composes with the owner-key re-genesis path (W9-1 #434), which re-establishes the
signed head, the monotonic floor, and any transparency checkpoints under the new chain. This keeps W9-2 from
silently orphaning an anchor.

The PURE engine (:func:`reencrypt_payload` / :func:`reencrypt_records`) has no such restriction and is what
the tests exercise: it re-encrypts + rebuilds + proves (chain verifies; every field opens under the new DEK
to the exact original; the old DEK no longer opens a re-keyed field) and is the reusable core the W9-1
re-genesis path calls for an anchored spine.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Optional

from vigil_core.canonical import digest_payload
from vigil_core.chain import build_chain, verify_chain
from vigil_core.models import ChainEntry
from vigil_core.rotation import RotationError, rewrap

from . import envelope
from .atomicio import atomic_write_text


class DekRotationError(RotationError):
    """A spine DEK rotation could not be proven correct and was refused (fail-closed)."""


def reencrypt_payload(old_dek: bytes, new_dek: bytes, stored_payload: Any, *, scope: str, seq: int) -> Any:
    """Re-encrypt every sealed field-envelope in ``stored_payload`` from ``old_dek`` to ``new_dek``, under
    the SAME ``(scope, seq, field)`` AEAD binding. A payload with no sealed field passes through unchanged
    (legacy plaintext / pure-metadata record). Each field is moved via :func:`vigil_core.rotation.rewrap`,
    which proves the new ciphertext opens under the new DEK to the exact original AND no longer opens under
    the old DEK. Raises :class:`DekRotationError` on any failure (fail-closed)."""
    if not isinstance(stored_payload, dict):
        return stored_payload
    if not any(envelope._is_field_envelope(v) for v in stored_payload.values()):
        return stored_payload
    out: dict[str, Any] = {}
    for k, v in stored_payload.items():
        if not envelope._is_field_envelope(v):
            out[k] = v
            continue
        aad = envelope._aad(scope, seq, k)
        try:
            new_ct = rewrap(old_dek, new_dek, base64.b64decode(v["b"]), context=aad)
        except (RotationError, ValueError, TypeError) as e:
            raise DekRotationError(f"re-encrypting field {k!r} at seq {seq} failed: {e}") from e
        out[k] = {"_enc": v.get("_enc", envelope._ENC_VERSION),
                  "alg": v.get("alg", envelope._ALG),
                  "b": base64.b64encode(new_ct).decode("ascii")}
    return out


def reencrypt_records(old_dek: bytes, new_dek: bytes, records: list[dict]) -> list[dict]:
    """Re-encrypt a genesis-rooted, seq-ordered list of spine record dicts under ``new_dek`` and REBUILD
    the hash-chain (``cert_digest`` + ``prev_hash`` + ``entry_hash``) over the new stored form. Returns new
    record dicts (the inputs are not mutated). Proves the result before returning: the rebuilt chain
    verifies. Raises :class:`DekRotationError` on any inconsistency (e.g. a seq gap / non-genesis start,
    which a segmented spine would present — refused here, handled by the re-genesis path)."""
    if not records:
        return []
    out: list[dict] = []
    cert_digests: list[str] = []
    expect_seq = records[0].get("seq", 0)
    if expect_seq != 0:
        raise DekRotationError(f"reencrypt_records expects a genesis-rooted chain (starts at seq 0), got {expect_seq}")
    for r in records:
        seq = r["seq"]
        if seq != expect_seq:
            raise DekRotationError(f"non-contiguous chain at seq {seq} (expected {expect_seq}) — not a single genesis chain")
        expect_seq += 1
        new_payload = reencrypt_payload(old_dek, new_dek, r["payload"], scope=r["scope"], seq=seq)
        content = {
            "scope": r["scope"], "kind": r["kind"], "source": r["source"], "actor": r["actor"],
            "payload": new_payload, "parent_id": r.get("parent_id"), "supersedes_id": r.get("supersedes_id"),
        }
        cert_digests.append(digest_payload(content))
        nr = dict(r)
        nr["payload"] = new_payload
        out.append(nr)
    entries = build_chain(cert_digests)
    for nr, entry in zip(out, entries):
        nr["cert_digest"] = entry.cert_digest
        nr["prev_hash"] = entry.prev_hash
        nr["entry_hash"] = entry.entry_hash
    ok, why = verify_chain([ChainEntry(seq=e.seq, prev_hash=e.prev_hash, cert_digest=e.cert_digest,
                                       entry_hash=e.entry_hash) for e in entries])
    if not ok:
        raise DekRotationError(f"rebuilt chain did not verify after re-encryption: {why}")
    return out


def _prove_reencryption(old_dek: bytes, new_dek: bytes, before: list[dict], after: list[dict]) -> None:
    """Belt-and-suspenders proof over the whole spine: every content field of every record opens under the
    NEW DEK to EXACTLY the plaintext it held under the OLD DEK, and the OLD DEK no longer opens a re-keyed
    field (the negative control). Raises :class:`DekRotationError` on any mismatch."""
    for b, a in zip(before, after):
        seq, scope = b["seq"], b["scope"]
        old_plain = envelope.open_payload(old_dek, b["payload"], scope=scope, seq=seq)
        new_plain = envelope.open_payload(new_dek, a["payload"], scope=scope, seq=seq)
        if old_plain != new_plain:
            raise DekRotationError(f"seq {seq}: re-encrypted payload did not open to the original plaintext")
        # NEGATIVE control: if this record HAD sealed fields, the old DEK must fail on the new ciphertext.
        if any(envelope._is_field_envelope(v) for v in a["payload"].values()):
            try:
                envelope.open_payload(old_dek, a["payload"], scope=scope, seq=seq)
            except envelope.SpinePayloadLocked:
                continue  # expected — the old DEK can no longer read the re-keyed field
            raise DekRotationError(f"seq {seq}: the OLD DEK still opens a re-encrypted field (rotation is a no-op)")


def rotate_spine_dek(spine_path, vault) -> dict:
    """Rotate the spine DEK for a plain, UN-ANCHORED single-file spine: mint a fresh DEK, re-encrypt every
    sealed content field, rebuild the chain, PROVE it (chain + field-open + old-DEK-fails), then atomically
    swap the re-keyed spine and the sealed DEK file — verify-then-swap, with rollback of both on any failure.

    Fail-closed refusals (each composes with the W9-1 re-genesis path, which re-signs the head / re-anchors
    the floor / re-checkpoints transparency under the new chain):
      * a segmented spine (a manifest exists),
      * an anchored spine (a signed ``head.json`` or a durable ``floor.json`` exists),
      * an unprovisioned vault (no DEK to rotate),
      * a locked vault, or any record that cannot be re-encrypted.
    """
    p = Path(spine_path)
    if not vault.enabled():
        raise DekRotationError("cannot rotate the spine DEK — the vault is not provisioned (no DEK)")

    from ..config import FLOOR_PATH, HEAD_PATH, SPINE_DEK_PATH
    from .manifest import SpineLayout, read_manifest
    if read_manifest(SpineLayout.for_path(p)) is not None:
        raise DekRotationError("this spine is SEGMENTED — DEK rotation of a segmented spine composes with the "
                               "W9-1 re-genesis path (rebuilds the chain across segments); refusing here (fail-closed)")
    if Path(HEAD_PATH).exists() or Path(FLOOR_PATH).exists():
        raise DekRotationError("this spine is ANCHORED (a signed head / durable floor exists) — re-encryption "
                               "changes every cert_digest and thus the head_hash; re-key + re-sign via the W9-1 "
                               "re-genesis path (refusing here so an anchor is never silently orphaned)")

    old_dek = envelope.load_or_create_dek(vault, create=False)
    if old_dek is None:
        raise DekRotationError("no spine DEK found to rotate (nothing has been sealed yet)")
    new_dek = os.urandom(32)
    if new_dek == old_dek:
        raise DekRotationError("fresh DEK collided with the current DEK — aborting")

    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise DekRotationError(f"cannot read the spine at {p}: {e}") from e
    before = [json.loads(line) for line in raw.splitlines() if line.strip()]

    after = reencrypt_records(old_dek, new_dek, before)   # re-encrypt + rebuild + verify chain (fail-closed)
    _prove_reencryption(old_dek, new_dek, before, after)  # prove field-open + old-DEK-fails over the whole spine

    # verify-then-swap: stage the re-keyed spine + the fresh sealed DEK, then commit atomically with rollback.
    staged_spine = p.with_name(p.name + ".rot")
    staged_spine.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in after) + "\n", encoding="utf-8")
    dek_path = Path(SPINE_DEK_PATH)
    dek_prev = dek_path.with_name(dek_path.name + ".prev")   # crash anchor: the OLD sealed DEK
    dek_backup: Optional[bytes] = dek_path.read_bytes() if dek_path.exists() else None
    spine_backup = raw
    try:
        # CRASH ANCHOR (red-pen HIGH): snapshot the OLD sealed DEK to `.prev` BEFORE overwriting it, so a
        # power loss between the DEK write and the spine swap is RECOVERABLE — the old DEK still opens the
        # not-yet-swapped (old-ciphertext) spine, and `reconcile_spine_dek` finishes/rolls the swap. `.prev`
        # is dropped only AFTER the spine is confirmed swapped, so the old DEK is never orphaned mid-rotation.
        if dek_backup is not None:
            _atomic_write_bytes(dek_prev, dek_backup)
        # DEK next: once the fresh DEK is in place, a reader opens the re-keyed ciphertext (swapped next).
        vault.write_text_secret(dek_path, base64.b64encode(new_dek).decode("ascii"), context=envelope._DEK_CONTEXT)
        atomic_write_text(p, staged_spine.read_text(encoding="utf-8"), prefix=".spine-rot-")
    except Exception as e:  # noqa: BLE001 — any commit failure rolls BOTH back (fail-closed)
        try:
            atomic_write_text(p, spine_backup, prefix=".spine-rb-")
            if dek_backup is not None:
                _atomic_write_bytes(dek_path, dek_backup)
        finally:
            staged_spine.unlink(missing_ok=True)
            dek_prev.unlink(missing_ok=True)
        raise DekRotationError(f"DEK rotation commit failed and was rolled back: {e}") from e
    # spine is now confirmed swapped under the new DEK — retire the crash anchor (old DEK gone).
    dek_prev.unlink(missing_ok=True)
    staged_spine.unlink(missing_ok=True)
    return {"rotated": len(after), "spine": str(p)}


def dek_rotation_incomplete() -> bool:
    """True iff a spine-DEK crash anchor (``spine.dek.prev``) is present — a DEK rotation wrote the new DEK
    but was interrupted before it confirmed the spine swap (or before it retired the anchor). A cheap disk
    check for the doctor posture / boot reconciler."""
    from ..config import SPINE_DEK_PATH
    return Path(str(SPINE_DEK_PATH) + ".prev").exists()


def reconcile_spine_dek(spine_path, vault) -> dict:
    """Finish an interrupted spine-DEK rotation (red-pen HIGH: no crash anchor → power loss between the DEK
    write and the spine swap destroyed the spine). If ``spine.dek.prev`` is present, decide the on-disk state
    and drive it to a consistent one, then retire the anchor. Fail-closed + idempotent: no anchor → no-op.

      * anchor == current DEK (crash before the new DEK landed) → nothing committed → drop the anchor +
        any staged ``.rot`` (rolled back to the old DEK; the spine was never touched);
      * the spine already opens under the CURRENT (new) DEK (crash after the spine swap) → COMPLETE → drop
        the anchor (and any leftover ``.rot``);
      * the spine still opens under the OLD (anchor) DEK (crash after the new DEK, before the spine swap) →
        re-encrypt every record under the current DEK, PROVE it, atomically swap the spine, then drop the
        anchor. If the staged ``.rot`` verifies it could be reused; here the spine is recomputed from the
        old-DEK plaintext (deterministic proof, no reliance on possibly-torn staged bytes).
    Any step that cannot be proven leaves the anchor in place (the old DEK still opens the old spine) and
    raises :class:`DekRotationError`."""
    from ..config import SPINE_DEK_PATH
    p = Path(spine_path)
    dek_path = Path(SPINE_DEK_PATH)
    dek_prev = dek_path.with_name(dek_path.name + ".prev")
    if not dek_prev.exists():
        return {"status": "clean", "rotated": 0}
    if not vault.enabled():
        raise DekRotationError("cannot reconcile the spine DEK — the vault is not provisioned")

    old_b64 = vault.read_text_secret(dek_prev, context=envelope._DEK_CONTEXT)  # VaultLocked propagates
    cur_b64 = vault.read_text_secret(dek_path, context=envelope._DEK_CONTEXT)
    if not old_b64 or not cur_b64:
        raise DekRotationError("DEK reconcile: the `.prev` anchor or the current DEK is unreadable (fail-closed)")
    old_dek = base64.b64decode(old_b64)
    cur_dek = base64.b64decode(cur_b64)

    if cur_dek == old_dek:
        # the new DEK never landed → nothing was committed. Roll back cleanly.
        p.with_name(p.name + ".rot").unlink(missing_ok=True)
        dek_prev.unlink(missing_ok=True)
        return {"status": "rolled-back", "rotated": 0}

    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise DekRotationError(f"DEK reconcile: cannot read the spine at {p}: {e}") from e
    records = [json.loads(line) for line in raw.splitlines() if line.strip()]

    if _spine_opens_under(cur_dek, records):
        # the spine swap already happened → the rotation is effectively complete; just retire the anchor.
        p.with_name(p.name + ".rot").unlink(missing_ok=True)
        dek_prev.unlink(missing_ok=True)
        return {"status": "completed", "rotated": len(records)}

    if not _spine_opens_under(old_dek, records):
        raise DekRotationError("DEK reconcile: the on-disk spine opens under NEITHER the old nor the current "
                               "DEK — refusing to touch it (keeping the `.prev` anchor, fail-closed)")

    # Crash after the new DEK, before the spine swap: the spine is still old-ciphertext. Complete the swap by
    # re-encrypting from the old DEK to the current (new) DEK, proving it, then swapping atomically.
    after = reencrypt_records(old_dek, cur_dek, records)
    _prove_reencryption(old_dek, cur_dek, records, after)
    atomic_write_text(p, "\n".join(json.dumps(r, ensure_ascii=False) for r in after) + "\n", prefix=".spine-rec-")
    p.with_name(p.name + ".rot").unlink(missing_ok=True)
    dek_prev.unlink(missing_ok=True)
    return {"status": "completed", "rotated": len(after)}


def _spine_opens_under(dek: bytes, records: list[dict]) -> bool:
    """True iff EVERY sealed content field in ``records`` opens under ``dek``. A spine with no sealed field
    trivially 'opens' (there is nothing keyed). Used by the reconciler to tell which DEK the on-disk spine
    is currently encrypted under, without mutating anything."""
    for r in records:
        try:
            envelope.open_payload(dek, r.get("payload"), scope=r.get("scope"), seq=r.get("seq"))
        except envelope.SpinePayloadLocked:
            return False
    return True


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))
