"""W7-3 — the recovery drill covers the SOVEREIGN plane too (create → restore → re-verify the signed chain).

The shipped shell drill is offense-only (the sovereign leg needs a fresh SIGIL_HOME + the sovereign venv). The
sovereign plane holds the owner-signed spine chain, so leaving it undrilled means the plane whose whole point
is a verifiable chain is never proven to survive a restore. This suite drills it in-process (no venv needed):

  * a create → restore round-trip into a FRESH home reports ``verified: True`` and the restored spine's chain +
    per-record binding re-verify, and the records load back — chain verification AFTER restore, the AC's core;
  * a RETAINED (superseded) backup — an OLDER backup kept while a newer one exists — still restores to its
    exact point-in-time state and re-verifies, so a backup that has aged/been retained is proven recoverable,
    not just the just-minted one;
  * NEGATIVE CONTROLS: a corrupted retained backup is DETECTED (``restore_backup`` raises, destination
    untouched — never a silently-broken restore), and dropping a record from the retained spine breaks its
    chain re-verify. Proves the drill's re-verification has teeth.

Sovereign-only — never imports ``framework``/offense (FATAL-2 clean). Runs in the REQUIRED ``sigil-governor``
CI job (the whole ``apps/sigil/tests/`` dir; pure-Python, no Rust kernel / heavy deps).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest

from sigil import backup
from sigil.backup import BackupError, create_backup, restore_backup
from sigil.reuse import canonical_json, sign
from sigil.reuse.chain import sign_head
from sigil.spine.store import SpineStore
from vigil_core.sealing import seal, unseal

# reuse the fully-populated source-home builder + the fake TPM + the restore helper from the functional suite.
from test_backup_recovery_functional import (  # type: ignore
    PW,
    SCOPE,
    _make_full_source,
    _restore,
    make_fake_tpm,
)
from vigil_core.vault import Vault


def _append_record_and_resign(src, owner, text: str) -> None:
    """Evolve the source home: append one spine record and RE-SIGN the head over the new entry set, so a later
    backup captures a genuinely NEWER state than an earlier one (modelling a retained/superseded older backup)."""
    store = SpineStore(str(src / "spine" / "spine.jsonl"))
    store.append(kind="message", source="c", actor="u", payload={"text": text})
    head = sign_head(store.entries(), engagement_slug=SCOPE, signers=[("owner", owner.private_key_b64)])
    (src / "spine" / "head.json").write_text(head.model_dump_json())


# --------------------------------------------------------------------------------------------------
# Round-trip: the sovereign plane is drilled, chain re-verified AFTER restore.
# --------------------------------------------------------------------------------------------------
def test_sovereign_drill_restores_and_reverifies_the_signed_chain(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)

    new, _rv, out = _restore(tmp_path, dest)
    assert out["verified"] is True                          # restore re-verified the staged spine's chain
    recs = [r.payload["text"] for r in SpineStore(str(new / "spine" / "spine.jsonl")).iter_records()]
    assert recs == ["memory one", "memory two"]
    assert json.loads((new / "spine" / "head.json").read_text())["engagement_slug"] == SCOPE


# --------------------------------------------------------------------------------------------------
# A RETAINED (older, superseded) backup still restores + re-verifies to its point-in-time state.
# --------------------------------------------------------------------------------------------------
def test_sovereign_drill_of_a_retained_superseded_backup(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    older = tmp_path / "older.sglbk"
    create_backup(older, PW, home=src, vault=v, owner_key=owner)     # A: 2 records

    _append_record_and_resign(src, owner, "memory three")           # source evolves …
    newer = tmp_path / "newer.sglbk"
    create_backup(newer, PW, home=src, vault=v, owner_key=owner)     # B: 3 records (supersedes A)

    # the RETAINED older backup A still restores to its EXACT 2-record point-in-time state, chain re-verified.
    a_home, _av, a_out = _restore(tmp_path, older, name="restored-older")
    assert a_out["verified"] is True
    assert [r.payload["text"] for r in SpineStore(str(a_home / "spine" / "spine.jsonl")).iter_records()] \
        == ["memory one", "memory two"]

    # and the newer one restores to its 3-record state, so both the retained and the current backup recover.
    b_home, _bv, b_out = _restore(tmp_path, newer, name="restored-newer")
    assert b_out["verified"] is True
    assert [r.payload["text"] for r in SpineStore(str(b_home / "spine" / "spine.jsonl")).iter_records()] \
        == ["memory one", "memory two", "memory three"]


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS — a corrupted retained sovereign backup is detected, never restored silently broken.
# --------------------------------------------------------------------------------------------------
def test_negative_control_corrupted_retained_sovereign_backup_is_detected(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    dest = tmp_path / "retained.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)

    # a same-length byte flip inside the sealed ciphertext → AEAD decrypt fails on restore.
    b = bytearray(dest.read_bytes())
    b[-1] ^= 0xFF
    dest.write_bytes(bytes(b))

    new = tmp_path / "restored-corrupt"
    rv = Vault(new / "vault", make_fake_tpm())
    rv.provision()
    with pytest.raises(BackupError):
        restore_backup(dest, new, PW, vault=rv)
    # fail-closed: nothing of the captured state was swapped into the destination.
    assert not (new / "spine").exists()


def test_negative_control_a_tampered_record_in_a_retained_backup_fails_reverify(tmp_path):
    # Flip a byte INSIDE a spine record (re-sealed + re-signed so the manifest sha/signature still pass) → the
    # keyless hash-chain / per-record binding no longer holds, so the post-restore re-verify must REJECT it
    # rather than swap a chain-inconsistent home into place. Proves the re-verify (not just the AEAD) has teeth.
    src, v, owner, _w = _make_full_source(tmp_path)
    dest = tmp_path / "retained.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)

    salt, sealed = backup._read_header(dest)
    body = json.loads(unseal(backup._derive_key(PW, salt), sealed, context=backup._BODY_CONTEXT))
    spine_rel = next(r for r in body["files"] if r.endswith("spine.jsonl"))
    raw = bytearray(base64.b64decode(body["files"][spine_rel]))
    # corrupt the recorded payload text of the FIRST record ("memory one" → "memory oNe"): the record's stored
    # hash/binding no longer matches its content, breaking the chain the restore re-verifies.
    marker = raw.find(b"memory one")
    assert marker != -1
    raw[marker + 7] ^= 0x20                                   # 'o' -> 'O' inside the payload text, same length
    body["files"][spine_rel] = base64.b64encode(bytes(raw)).decode()
    body["manifest"]["file_sha256"][spine_rel] = hashlib.sha256(bytes(raw)).hexdigest()
    body["manifest_sig"] = sign(owner.private_key_b64, canonical_json(body["manifest"]))
    new_salt = os.urandom(backup._SALT_LEN)
    dest.write_bytes(backup._MAGIC + new_salt
                     + seal(backup._derive_key(PW, new_salt), canonical_json(body), context=backup._BODY_CONTEXT))

    new = tmp_path / "restored-tamperedrec"
    rv = Vault(new / "vault", make_fake_tpm())
    rv.provision()
    with pytest.raises(BackupError):
        restore_backup(dest, new, PW, vault=rv)
    assert not (new / "spine").exists()
