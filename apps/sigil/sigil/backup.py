"""Signed, passphrase-encrypted OFF-BOX backup of the SIGIL trust root + spine (audit G3(a)).

The TPM-sealed vault (G1) binds the owner key + the spine DEK to THIS machine's TPM, so a dead disk is
unrecoverable from the vault alone — the whole audit ledger + all memory would be lost. This produces a
PORTABLE disaster-recovery backup: the spine (segments + manifest + signed head + floor + the G2 security
manifest + the owner PUBLIC key) plus the OWNER PRIVATE key and the spine DEK are packaged and encrypted
under a key derived from an OWNER PASSPHRASE (scrypt), so the backup restores on NEW hardware where this
machine's TPM is gone.

Integrity is layered, and it is important to be precise about WHICH layer runs WHEN. The whole body is
AEAD-sealed and, inside it, a backup MANIFEST (sha256 of every packaged file) is OWNER-signed — so a wrong
passphrase, or ANY tamper of the sealed bytes, fails to decrypt / fails the manifest signature / fails a
per-file hash check BEFORE a single file is written. AFTER the fresh-home write, `store.verify()` re-checks
the restored spine's hash-chain + per-record payload binding (keyless) and refuses to report success on a
chain-inconsistent ledger — note this last check runs *after* the write, into the throwaway fresh home.
Restore does NOT re-check the owner SIGNATURE on the spine head: that verification is scope/config-bound,
so it belongs to the running instance — run `sigil verify` with `SIGIL_HOME` pointed at the restored home
to confirm the owner-signed head. (Against a passphrase-holder that check would add nothing anyway: the
owner private key is inside the backup, so a holder could re-sign both the manifest and the head — the
passphrase is itself the root of trust here.)

Confidentiality is the scrypt-derived AEAD: without the passphrase the backup is ciphertext (the sensitive
content is doubly protected — the spine payloads are already field-sealed under the DEK, and the whole
backup is sealed under the passphrase). The passphrase is the recovery secret; it is NEVER stored — lose
it and the backup is unrecoverable BY DESIGN (that is the off-box confidentiality guarantee).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from vigil_core.sealing import SealError, seal, unseal

from .reuse import KeyPair, canonical_json, sha256_hex, sign, verify_one

_MAGIC = b"SGLBK1\x00"
_SCHEMA = 1
# scrypt work factors — n=2^16 (64 MiB) is a strong interactive KDF; salt is per-backup, stored in the header.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 16, 8, 1
_SCRYPT_MAXMEM = 132 * _SCRYPT_N * _SCRYPT_R          # headroom over scrypt's 128*n*r working set
_SALT_LEN = 16
# AEAD context binding the sealed backup body to its purpose (domain separation vs the spine/owner seals).
_BODY_CONTEXT = b"sigil/backup/v1"
# The two vault-custodied secrets re-wrapped INTO the passphrase-encrypted backup so recovery is portable.
_OWNER_PRIV_CONTEXT = b"sigil/owner.priv"
_DEK_CONTEXT = b"sigil/spine.dek"


class BackupError(Exception):
    """A backup could not be created or restored (bad passphrase, tamper, corrupt/missing trust root).
    Fail-closed: a restore verifies the owner signature OVER THE MANIFEST + every file hash BEFORE writing
    anything, and re-verifies the restored spine's chain/binding after; it never reports success on an
    unverified restore. (A restore targets a FRESH home, so a caught failure leaves only a throwaway dir to
    discard.)"""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise BackupError("an empty passphrase is refused — the backup would be trivially decryptable")
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                          maxmem=_SCRYPT_MAXMEM, dklen=32)


def _spine_files(home: Path) -> list[Path]:
    """Every trust-root/spine file to package, as absolute paths. Includes the spine dir (segments,
    manifest, signed head, the owner PUBLIC key), the anti-rollback floor, and the G2 security manifest.
    EXCLUDES the machine-bound secrets (they are re-wrapped separately): the sealed owner PRIVATE key, the
    sealed DEK, the TPM-sealed KEK vault dir, and transient lockfiles."""
    out: list[Path] = []
    spine = home / "spine"
    if spine.is_dir():
        for p in sorted(spine.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(home).as_posix()
            if rel.endswith((".lock",)) or rel in ("spine/keys/owner.priv", "spine/keys/spine.dek"):
                continue
            out.append(p)
    for extra in ("floor.json", "security.manifest.json"):
        f = home / extra
        if f.is_file():
            out.append(f)
    return out


def create_backup(dest: str | Path, passphrase: str, *, home: Path, vault: Any, owner_key: KeyPair) -> dict:
    """Write a portable, signed, passphrase-encrypted backup of ``home``'s trust root + spine to ``dest``.

    ``vault`` reads the (possibly TPM-sealed) owner private key + spine DEK as plaintext to re-wrap them
    into the encrypted backup; ``owner_key`` signs the file manifest. Returns a summary."""
    home = Path(home)
    files = _spine_files(home)
    if not any(f.name == "head.json" for f in files):
        raise BackupError(f"no signed spine head under {home} — nothing to back up (run `sigil sign` first)")
    file_blobs: dict[str, str] = {}
    file_hashes: dict[str, str] = {}
    for f in files:
        raw = f.read_bytes()
        rel = f.relative_to(home).as_posix()
        file_blobs[rel] = base64.b64encode(raw).decode("ascii")
        file_hashes[rel] = sha256_hex(raw)

    # the machine-bound secrets, read as plaintext through the vault (unseals if sealed) — re-wrapped
    # portably by living INSIDE the passphrase-encrypted body.
    owner_priv = vault.read_text_secret(home / "spine" / "keys" / "owner.priv", context=_OWNER_PRIV_CONTEXT)
    dek = vault.read_text_secret(home / "spine" / "keys" / "spine.dek", context=_DEK_CONTEXT)

    manifest = {
        "schema": _SCHEMA, "scope": owner_key.public_key_b64, "file_sha256": file_hashes,
        "has_owner_priv": owner_priv is not None, "has_dek": dek is not None,
    }
    manifest_sig = sign(owner_key.private_key_b64, canonical_json(manifest))

    body = {
        "manifest": manifest, "manifest_sig": manifest_sig, "manifest_pubkey": owner_key.public_key_b64,
        "files": file_blobs, "owner_priv_b64": owner_priv, "spine_dek_b64": dek,
    }
    salt = os.urandom(_SALT_LEN)
    sealed = seal(_derive_key(passphrase, salt), canonical_json(body), context=_BODY_CONTEXT)

    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # 0600 before the secrets land
    try:
        os.write(fd, _MAGIC + salt + sealed)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(dest))
    return {"dest": str(dest), "files": len(file_blobs), "owner_key": owner_priv is not None,
            "dek": dek is not None, "bytes": len(sealed)}


def _read_header(src: Path) -> tuple[bytes, bytes]:
    raw = src.read_bytes()
    if not raw.startswith(_MAGIC):
        raise BackupError("not a SIGIL backup file (bad magic)")
    off = len(_MAGIC)
    salt = raw[off:off + _SALT_LEN]
    if len(salt) != _SALT_LEN:
        raise BackupError("truncated backup header")
    return salt, raw[off + _SALT_LEN:]


def _safe_target(new_home: Path, new_home_resolved: Path, rel: str) -> Path:
    """Resolve a packaged relative path to a concrete file INSIDE ``new_home``, or raise BackupError.

    Guards the WHOLE class of path-escape tricks at ONE site — and returns the SAME path the caller must
    WRITE, so a check/write mismatch can never reintroduce an escape:
      * ``PureWindowsPath`` is the STRICTEST interpreter (both ``/`` and ``\\`` are separators, and it
        understands drive letters), so on ANY host — POSIX included — it catches ``..``, absolute, rooted
        (``\\foo``, ``//srv``) AND drive-relative (``D:evil``, which re-anchors to another drive's cwd on a
        raw join) paths;
      * a resolved-containment backstop (the ``.resolve()``d target must stay under ``new_home``) defeats
        any residual trick (symlink games, platform quirks) independent of the syntactic check above.
    """
    win = PureWindowsPath(rel)
    if (not rel or "\x00" in rel or ".." in win.parts or win.is_absolute() or win.drive or win.root
            or PurePosixPath(rel).is_absolute()):
        raise BackupError(f"refusing an unsafe backup path {rel!r}")
    target = new_home / PurePosixPath(rel.replace("\\", "/"))     # rel now proven slash-only + drive-free
    if not target.resolve().is_relative_to(new_home_resolved):
        raise BackupError(f"refusing an unsafe backup path {rel!r}")
    return target


def restore_backup(src: str | Path, new_home: str | Path, passphrase: str, *, vault: Any) -> dict:
    """Decrypt + VERIFY a backup, then write the trust root + spine into ``new_home``. Fail-closed: the
    passphrase must decrypt, the owner signature over the manifest must verify, and every file's sha256
    must match BEFORE anything is written; the restored spine is then re-verified (`store.verify`). The
    owner private key + DEK are re-sealed through ``vault`` (under the NEW machine's TPM if provisioned,
    else plaintext)."""
    src, new_home = Path(src), Path(new_home)
    salt, sealed = _read_header(src)
    try:
        raw = unseal(_derive_key(passphrase, salt), sealed, context=_BODY_CONTEXT)
    except SealError as e:
        raise BackupError("could not decrypt the backup — wrong passphrase or a tampered file") from e
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise BackupError(f"corrupt backup body: {e}") from e
    if not isinstance(body, dict):
        raise BackupError("corrupt backup body: expected a JSON object")

    manifest = body.get("manifest")
    pub = body.get("manifest_pubkey")
    sig = body.get("manifest_sig")
    if not isinstance(manifest, dict) or not isinstance(pub, str) or not isinstance(sig, str):
        raise BackupError("backup is missing its signed manifest")
    try:
        if not verify_one(pub, canonical_json(manifest), sig):
            raise BackupError("backup manifest signature does not verify (tamper)")
    except BackupError:
        raise
    except Exception as e:  # noqa: BLE001 — malformed key/sig → fail-closed
        raise BackupError(f"backup manifest signature is malformed: {e}") from e

    files = body.get("files")
    hashes = manifest.get("file_sha256")
    if not isinstance(files, dict) or not isinstance(hashes, dict):
        raise BackupError("backup is missing its file table")
    if set(files) != set(hashes):
        raise BackupError("backup file set does not match its signed manifest")
    # the two re-wrapped secrets must be strings (or absent) — validated BEFORE any write, so a malformed
    # signed body fails closed with a clean BackupError instead of a bare AttributeError at the vault
    # boundary (`.encode()` on a non-str). Mirrors the manifest/pub/sig/files/hashes type guards above.
    for _label, _val in (("owner private key", body.get("owner_priv_b64")), ("spine DEK", body.get("spine_dek_b64"))):
        if _val is not None and not isinstance(_val, str):
            raise BackupError(f"backup {_label} is malformed (expected a string)")
    # decode + verify EVERY file against the signed manifest BEFORE writing anything (fail-closed). Each rel
    # is resolved to ONE validated target INSIDE new_home, and that SAME target is what we later write — so
    # the check and the write can never diverge (closing the "validate the normalised path, write the raw
    # path" class of escape).
    new_home_resolved = new_home.resolve()
    decoded: list[tuple[Path, bytes]] = []
    for rel, b64 in files.items():
        target = _safe_target(new_home, new_home_resolved, rel)
        try:
            data = base64.b64decode(b64)
        except Exception as e:  # noqa: BLE001
            raise BackupError(f"corrupt file blob {rel!r}: {e}") from e
        if sha256_hex(data) != hashes[rel]:
            raise BackupError(f"file {rel!r} does not match its signed hash (tamper)")
        decoded.append((target, data))

    new_home.mkdir(parents=True, exist_ok=True)
    for target, data in decoded:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    # re-seal the machine-bound secrets through the NEW vault (seals under the new TPM if provisioned).
    if body.get("owner_priv_b64"):
        vault.write_text_secret(new_home / "spine" / "keys" / "owner.priv",
                                body["owner_priv_b64"], context=_OWNER_PRIV_CONTEXT)
    if body.get("spine_dek_b64"):
        vault.write_text_secret(new_home / "spine" / "keys" / "spine.dek",
                                body["spine_dek_b64"], context=_DEK_CONTEXT)

    # re-verify the restored spine's internal integrity (keyless binding + chain) — never claim a restore
    # succeeded on a corrupt ledger.
    from .spine.store import SpineStore
    ok, why = SpineStore(new_home / "spine" / "spine.jsonl").verify()
    if not ok:
        raise BackupError(f"restored spine failed verification ({why}) — the restore is NOT trustworthy")
    return {"home": str(new_home), "files": len(decoded), "owner_key": bool(body.get("owner_priv_b64")),
            "dek": bool(body.get("spine_dek_b64")), "verified": True}
