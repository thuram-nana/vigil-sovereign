"""G3(a) — portable, passphrase-encrypted off-box backup + verified restore of the trust root + spine.

Proves the disaster-recovery property: a backup restores the spine + owner key + DEK onto a FRESH home
where this machine's TPM is gone, and the restored spine VERIFIES; a wrong passphrase or ANY tamper fails
CLOSED (nothing is written), and the passphrase is the only key (never stored).
"""
from __future__ import annotations

import base64

import pytest

from sigil import backup
from sigil.backup import BackupError, create_backup, restore_backup
from sigil.reuse import generate_keypair
from sigil.reuse.chain import sign_head
from sigil.spine.store import SpineStore
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault

PW = "correct horse battery staple"


def make_fake_tpm():
    from pathlib import Path

    def run(argv, stdin):
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary"); return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub"); Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b""))
            return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):]); return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


def _make_source(tmp_path, *, provision=False, with_dek=False):
    """A source home with a signed 2-record spine, the owner keypair, and (optionally) a sealed DEK."""
    owner = generate_keypair()
    src = tmp_path / "src"
    store = SpineStore(str(src / "spine" / "spine.jsonl"))
    store.append(kind="message", source="c", actor="u", payload={"text": "memory one"})
    store.append(kind="decision", source="c", actor="u", payload={"text": "memory two"})
    head = sign_head(store.entries(), engagement_slug="sigil", signers=[("owner", owner.private_key_b64)])
    (src / "spine" / "head.json").write_text(head.model_dump_json())
    keys = src / "spine" / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "owner.pub").write_text(owner.public_key_b64)
    v = Vault(src / "vault", make_fake_tpm())
    if provision:
        v.provision()
    v.write_text_secret(keys / "owner.priv", owner.private_key_b64, context=backup._OWNER_PRIV_CONTEXT)
    if with_dek:
        v.write_text_secret(keys / "spine.dek", base64.b64encode(b"D" * 32).decode(), context=backup._DEK_CONTEXT)
    return src, v, owner


def test_backup_restore_roundtrip_verifies(tmp_path):
    src, v, owner = _make_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    res = create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    assert res["owner_key"] is True and res["files"] >= 3        # spine + head + owner.pub
    new = tmp_path / "restored"
    rv = Vault(new / "vault", make_fake_tpm())
    out = restore_backup(dest, new, PW, vault=rv)
    assert out["verified"] is True
    # the restored spine reads back the exact records, and the owner key is recovered
    recs = list(SpineStore(str(new / "spine" / "spine.jsonl")).iter_records())
    assert [r.payload["text"] for r in recs] == ["memory one", "memory two"]
    assert rv.read_text_secret(new / "spine" / "keys" / "owner.priv",
                               context=backup._OWNER_PRIV_CONTEXT) == owner.private_key_b64


def test_dek_is_backed_up_and_recovered(tmp_path):
    src, v, owner = _make_source(tmp_path, with_dek=True)
    dest = tmp_path / "bk.sglbk"
    assert create_backup(dest, PW, home=src, vault=v, owner_key=owner)["dek"] is True
    new = tmp_path / "restored"
    rv = Vault(new / "vault", make_fake_tpm())
    restore_backup(dest, new, PW, vault=rv)
    assert rv.read_text_secret(new / "spine" / "keys" / "spine.dek",
                               context=backup._DEK_CONTEXT) == base64.b64encode(b"D" * 32).decode()


def test_owner_priv_never_appears_plaintext_in_the_backup_file(tmp_path):
    src, v, owner = _make_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    blob = dest.read_bytes()
    assert owner.private_key_b64.encode() not in blob            # the whole body is passphrase-encrypted


def test_wrong_passphrase_fails_closed(tmp_path):
    src, v, owner = _make_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    with pytest.raises(BackupError, match="wrong passphrase"):
        restore_backup(dest, tmp_path / "restored", "WRONG passphrase", vault=Vault(tmp_path / "rv", make_fake_tpm()))


def test_tampered_ciphertext_fails_closed(tmp_path):
    src, v, owner = _make_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    raw = bytearray(dest.read_bytes())
    raw[-1] ^= 0xFF                                              # flip a ciphertext byte → AEAD fails
    dest.write_bytes(raw)
    with pytest.raises(BackupError):
        restore_backup(dest, tmp_path / "restored", PW, vault=Vault(tmp_path / "rv", make_fake_tpm()))
    assert not (tmp_path / "restored" / "spine").exists()        # nothing written on a failed restore


def test_empty_passphrase_refused(tmp_path):
    src, v, owner = _make_source(tmp_path)
    with pytest.raises(BackupError, match="empty passphrase"):
        create_backup(tmp_path / "bk.sglbk", "", home=src, vault=v, owner_key=owner)


def test_safe_target_rejects_the_whole_escape_class(tmp_path):
    """The path guard is class-complete and platform-independent — it rejects `..`, absolute, rooted, AND
    Windows drive-relative rels (which re-anchor to another drive on a raw join) even on POSIX, while
    accepting the honest forward-slash relative paths a real backup contains."""
    new_home = tmp_path / "restored"
    resolved = new_home.resolve()
    for evil in ("../x", "..\\x", "a/../../etc", "/etc/passwd", "\\srv\\share", "//srv/share",
                 "D:evil", "D:pwn\\startup.bat", "C:\\windows\\x", "C:/windows/x", "E:", "", "x\x00y"):
        with pytest.raises(BackupError, match="unsafe backup path"):
            backup._safe_target(new_home, resolved, evil)
    for ok in ("spine/head.json", "floor.json", "spine/segments/seg-00000000.jsonl", "spine/keys/owner.pub"):
        target = backup._safe_target(new_home, resolved, ok)
        assert target.resolve().is_relative_to(resolved)         # stays inside the fresh home


def test_list_files_table_fails_closed(tmp_path):
    """A correctly-signed body whose `files`/`file_sha256` is a JSON LIST (not an object) raises
    BackupError, not a bare AttributeError — fail-closed on a malformed-but-signed backup."""
    from sigil.reuse import canonical_json, sign
    from vigil_core.sealing import seal

    owner = generate_keypair()
    manifest = {"schema": 1, "scope": owner.public_key_b64, "file_sha256": ["not", "a", "dict"],
                "has_owner_priv": False, "has_dek": False}
    body = {"manifest": manifest, "manifest_sig": sign(owner.private_key_b64, canonical_json(manifest)),
            "manifest_pubkey": owner.public_key_b64, "files": ["also", "a", "list"],
            "owner_priv_b64": None, "spine_dek_b64": None}
    salt = b"\x01" * backup._SALT_LEN
    sealed = seal(backup._derive_key(PW, salt), canonical_json(body), context=backup._BODY_CONTEXT)
    dest = tmp_path / "malformed.sglbk"
    dest.write_bytes(backup._MAGIC + salt + sealed)
    with pytest.raises(BackupError, match="file table"):
        restore_backup(dest, tmp_path / "restored", PW, vault=Vault(tmp_path / "rv", make_fake_tpm()))


def test_non_string_secret_in_a_signed_body_fails_closed(tmp_path):
    """A correctly-signed body whose owner_priv_b64 (or spine_dek_b64) is a non-string raises BackupError
    BEFORE any write — never a bare AttributeError at the vault's `.encode()`. Needs the full trust root
    (passphrase + owner key) to craft, but the fail-mode contract must still hold."""
    from sigil.reuse import canonical_json, sign
    from vigil_core.sealing import seal

    owner = generate_keypair()
    manifest = {"schema": 1, "scope": owner.public_key_b64, "file_sha256": {},
                "has_owner_priv": True, "has_dek": False}
    body = {"manifest": manifest, "manifest_sig": sign(owner.private_key_b64, canonical_json(manifest)),
            "manifest_pubkey": owner.public_key_b64, "files": {},
            "owner_priv_b64": 1234567890, "spine_dek_b64": None}       # non-str secret
    salt = b"\x02" * backup._SALT_LEN
    sealed = seal(backup._derive_key(PW, salt), canonical_json(body), context=backup._BODY_CONTEXT)
    dest = tmp_path / "badsecret.sglbk"
    dest.write_bytes(backup._MAGIC + salt + sealed)
    new = tmp_path / "restored"
    with pytest.raises(BackupError, match="owner private key is malformed"):
        restore_backup(dest, new, PW, vault=Vault(tmp_path / "rv", make_fake_tpm()))
    assert not (new / "spine" / "keys" / "owner.priv").exists()        # secret never reached the vault


def test_crafted_traversal_path_is_refused(tmp_path):
    """Even a well-formed, correctly-signed backup (the passphrase-holder controls the manifest key) is
    refused if any packaged path escapes the home — the traversal check is unconditional, before any write."""
    from sigil.reuse import canonical_json, sha256_hex, sign
    from vigil_core.sealing import seal

    owner = generate_keypair()
    evil = b"pwned"
    files = {"../escape.txt": base64.b64encode(evil).decode("ascii")}
    manifest = {"schema": 1, "scope": owner.public_key_b64,
                "file_sha256": {"../escape.txt": sha256_hex(evil)}, "has_owner_priv": False, "has_dek": False}
    body = {"manifest": manifest, "manifest_sig": sign(owner.private_key_b64, canonical_json(manifest)),
            "manifest_pubkey": owner.public_key_b64, "files": files, "owner_priv_b64": None, "spine_dek_b64": None}
    salt = b"\x00" * backup._SALT_LEN
    sealed = seal(backup._derive_key(PW, salt), canonical_json(body), context=backup._BODY_CONTEXT)
    dest = tmp_path / "evil.sglbk"
    dest.write_bytes(backup._MAGIC + salt + sealed)

    new = tmp_path / "restored"
    with pytest.raises(BackupError, match="unsafe backup path"):
        restore_backup(dest, new, PW, vault=Vault(tmp_path / "rv", make_fake_tpm()))
    assert not (tmp_path / "escape.txt").exists()                # nothing escaped the home
    assert not (new / "spine").exists()                          # and nothing legitimate was written either


def test_backup_without_a_signed_head_refuses(tmp_path):
    src = tmp_path / "src"
    (src / "spine").mkdir(parents=True)
    (src / "spine" / "spine.jsonl").write_text("")               # a spine dir but no head.json
    with pytest.raises(BackupError, match="no signed spine head"):
        create_backup(tmp_path / "bk.sglbk", PW, home=src, vault=Vault(src / "vault", make_fake_tpm()),
                      owner_key=generate_keypair())
