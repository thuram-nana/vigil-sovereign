"""A-S1 — the sovereign backup now also covers the WARDEN permission-kernel dir, and restore hardens perms.

Extends test_backup.py: a source home with a WARDEN dir (actionlog.jsonl + warden.pub + warden.key +
tools.json, plus a transient *.lock) is backed up and restored onto a FRESH SIGIL_HOME. Proves:
  * every non-lock warden file round-trips (the .lock is dropped);
  * the restored `warden/warden.key` (private kernel key) lands 0600, NOT the process umask;
  * the schema-2 manifest records the warden set, and a schema-1 (no-warden) backup still restores;
  * the restored spine still verifies (unchanged G3 property).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration:gateway \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_backup_warden.py -q
"""
from __future__ import annotations

import os
import stat

import pytest

from sigil import backup
from sigil.backup import create_backup, restore_backup
from sigil.spine.store import SpineStore
from vigil_core.vault import Vault

from test_backup import PW, _make_source, make_fake_tpm

WARDEN_FILES = {
    "actionlog.jsonl": b'{"seq":0,"kind":"classify","tier":"A1"}\n',
    "warden.pub": b"WARDEN-PUBLIC-KEY-BYTES",
    "warden.key": b"WARDEN-PRIVATE-KEY-BYTES-0600",   # the kernel's plaintext-0600 private key
    "tools.json": b'{"tools":[{"id":"scrape","tier":"A1"}]}',
}


def _seed_warden(home, monkeypatch):
    """Create a WARDEN dir under <home>/warden (the default when SIGIL_WARDEN_HOME is unset) with the four
    kernel files + a transient lockfile that must NOT be packaged."""
    monkeypatch.delenv("SIGIL_WARDEN_HOME", raising=False)   # use the <home>/warden default deterministically
    wd = home / "warden"
    wd.mkdir(parents=True, exist_ok=True)
    for name, data in WARDEN_FILES.items():
        (wd / name).write_bytes(data)
    (wd / "warden.lock").write_bytes(b"transient")           # a lock — must be skipped by _spine_files
    return wd


def test_warden_dir_is_backed_up_and_restored_with_0600_key(tmp_path, monkeypatch):
    src, v, owner = _make_source(tmp_path)
    _seed_warden(src, monkeypatch)

    dest = tmp_path / "bk.sglbk"
    res = create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    assert res["warden"] == len(WARDEN_FILES)               # 4 warden files packaged; the .lock excluded

    new = tmp_path / "restored"
    rv = Vault(new / "vault", make_fake_tpm())
    out = restore_backup(dest, new, PW, vault=rv)
    assert out["verified"] is True and out["warden"] == len(WARDEN_FILES)

    # every non-lock warden file round-tripped, byte-for-byte; the transient lock did NOT.
    for name, data in WARDEN_FILES.items():
        assert (new / "warden" / name).read_bytes() == data
    assert not (new / "warden" / "warden.lock").exists()

    # the restored kernel PRIVATE key is 0600 (owner-only) — not left at the process umask.
    mode = stat.S_IMODE(os.stat(new / "warden" / "warden.key").st_mode)
    assert mode == 0o600, f"warden.key restored {oct(mode)}, expected 0o600"
    # the public key is not perms-sensitive, so it is written at the normal mode (not force-0600).
    assert (new / "warden" / "warden.pub").exists()

    # the spine itself still verifies after the warden addition (unchanged G3 property).
    ok, _why = SpineStore(str(new / "spine" / "spine.jsonl")).verify()
    assert ok


def test_manifest_records_the_warden_set_schema_2(tmp_path, monkeypatch):
    src, v, owner = _make_source(tmp_path)
    _seed_warden(src, monkeypatch)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)

    # decrypt the body and inspect the SIGNED manifest: the current schema (the warden set was ADDED in
    # schema 2 and persists), and the warden set names every warden rel.
    import json
    from vigil_core.sealing import unseal
    salt, sealed = backup._read_header(dest)
    body = json.loads(unseal(backup._derive_key(PW, salt), sealed, context=backup._BODY_CONTEXT))
    manifest = body["manifest"]
    assert manifest["schema"] == backup._SCHEMA and manifest["schema"] >= 2
    assert set(manifest["warden"]) == {f"warden/{n}" for n in WARDEN_FILES}


def test_schema_1_backup_without_warden_still_restores(tmp_path):
    """Back-compat: a schema-1 body (no 'warden' block) restores unchanged — the field is optional."""
    import base64

    from sigil.reuse import canonical_json, generate_keypair, sha256_hex, sign
    from sigil.reuse.chain import sign_head
    from vigil_core.sealing import seal

    owner = generate_keypair()
    # a minimal valid spine so the post-write SpineStore.verify() passes.
    src = tmp_path / "src"
    store = SpineStore(str(src / "spine" / "spine.jsonl"))
    store.append(kind="message", source="c", actor="u", payload={"text": "one"})
    head = sign_head(store.entries(), engagement_slug="sigil", signers=[("owner", owner.private_key_b64)])

    files = {
        "spine/spine.jsonl": base64.b64encode((src / "spine" / "spine.jsonl").read_bytes()).decode("ascii"),
        "spine/head.json": base64.b64encode(head.model_dump_json().encode()).decode("ascii"),
    }
    hashes = {rel: sha256_hex(base64.b64decode(b64)) for rel, b64 in files.items()}
    manifest = {"schema": 1, "scope": owner.public_key_b64, "file_sha256": hashes,
                "has_owner_priv": False, "has_dek": False}          # NO 'warden' key (schema 1)
    body = {"manifest": manifest, "manifest_sig": sign(owner.private_key_b64, canonical_json(manifest)),
            "manifest_pubkey": owner.public_key_b64, "files": files,
            "owner_priv_b64": None, "spine_dek_b64": None}
    salt = b"\x07" * backup._SALT_LEN
    sealed = seal(backup._derive_key(PW, salt), canonical_json(body), context=backup._BODY_CONTEXT)
    dest = tmp_path / "schema1.sglbk"
    dest.write_bytes(backup._MAGIC + salt + sealed)

    new = tmp_path / "restored"
    out = restore_backup(dest, new, PW, vault=Vault(tmp_path / "rv", make_fake_tpm()))
    assert out["verified"] is True and out["warden"] == 0


def test_partial_warden_manifest_fails_closed(tmp_path):
    """A signed manifest that NAMES a warden file the body omits is refused BEFORE any write (fail-closed on a
    partial warden capture) — the passphrase-holder controls the manifest, so this is a real integrity gate."""
    import base64

    from sigil.reuse import canonical_json, generate_keypair, sha256_hex, sign
    from sigil.reuse.chain import sign_head
    from vigil_core.sealing import seal

    owner = generate_keypair()
    src = tmp_path / "src"
    store = SpineStore(str(src / "spine" / "spine.jsonl"))
    store.append(kind="message", source="c", actor="u", payload={"text": "one"})
    head = sign_head(store.entries(), engagement_slug="sigil", signers=[("owner", owner.private_key_b64)])
    files = {
        "spine/spine.jsonl": base64.b64encode((src / "spine" / "spine.jsonl").read_bytes()).decode("ascii"),
        "spine/head.json": base64.b64encode(head.model_dump_json().encode()).decode("ascii"),
    }
    hashes = {rel: sha256_hex(base64.b64decode(b64)) for rel, b64 in files.items()}
    # the manifest CLAIMS a warden file that is NOT in `files` — a partial/tampered capture.
    manifest = {"schema": 2, "scope": owner.public_key_b64, "file_sha256": hashes,
                "has_owner_priv": False, "has_dek": False, "warden": ["warden/warden.key"]}
    body = {"manifest": manifest, "manifest_sig": sign(owner.private_key_b64, canonical_json(manifest)),
            "manifest_pubkey": owner.public_key_b64, "files": files,
            "owner_priv_b64": None, "spine_dek_b64": None}
    salt = b"\x09" * backup._SALT_LEN
    sealed = seal(backup._derive_key(PW, salt), canonical_json(body), context=backup._BODY_CONTEXT)
    dest = tmp_path / "partial.sglbk"
    dest.write_bytes(backup._MAGIC + salt + sealed)

    new = tmp_path / "restored"
    with pytest.raises(backup.BackupError, match="missing WARDEN file"):
        restore_backup(dest, new, PW, vault=Vault(tmp_path / "rv", make_fake_tpm()))
    assert not (new / "spine").exists()          # fail-closed: nothing written
