"""Signed, passphrase-encrypted OFF-BOX backup of the OFFENSE plane's durable state (Claim 6 / Piece A).

The offense plane had NO disaster-recovery path: its durable state under ``--base-dir`` (default ``.vigil-live``)
— every ``{slug}.spine``, the persisted blackboard chain, the operator/spine/governance identity keys, the
usage-attestation ledger, token budgets, attest anchors — plus the CRUCIBLE evidence under
``crucible_root/.console/runs`` and ``.blackboard/store.sqlite`` was unprotected. A dead disk lost the lot.

This is the offense DUAL of the sovereign ``sigil`` backup (``apps/sigil/sigil/backup.py``): it reuses the
SAME reviewed primitives (``vigil_core.sealing.seal/unseal``, a scrypt-derived AEAD key, a signed file
manifest, and the byte-for-byte identical path-escape guard) so the two legs share one hardened design.

Boundary-clean and honest by construction:

  * **Restore authenticity: passphrase-possession by default; governance-key-PINNED on request.** The manifest
    is signed by the stable offense governance keypair (``live.governance_identity``), and that signature lives
    INSIDE the passphrase-sealed body. But restore verifies the signature against the pubkey carried IN the
    body — a self-signed pair ANY passphrase-holder can mint — so WITHOUT an out-of-band pin, restore-time
    authenticity reduces to passphrase-possession (the AEAD passphrase is the real root of trust, exactly as on
    the sovereign leg, whose docstring states the same residual). Passing ``expect_pubkey`` (the orchestrator's
    ``--expect-governance-pubkey``) pins the expected governance pubkey out of band and UPGRADES this to real
    authenticity: a passphrase-holder who does NOT also hold the governance PRIVATE key cannot forge a manifest
    that verifies under the pinned key. Restore does NOT itself consume the ``OFFENSE_GOVERNANCE_ROLE``
    delegation — it pins the KEY; the pinned key's tie back to the owner rests on the recipient having
    validated that owner-signed delegation OUT OF BAND (the same trusted channel that told them which pubkey to
    pin). (The offense side holds no owner private key — the two-env boundary — so the manifest cannot be
    owner-signed as the sovereign leg's is; this is the honest residual of a keyless plane, closed only by the
    out-of-band pin + the out-of-band delegation check.)
  * **Two SEPARATE encrypted files, one per plane — NEVER a merged archive.** A single archive covering both
    planes would require ONE process to hold both plane secrets at once = a FATAL-2 violation. The orchestrator
    (`vigil backup`) writes this offense file in-venv and drives the sovereign leg as a SUBPROCESS; the two
    encrypted files never meet in one interpreter.
  * **Portability mirrors the sovereign re-wrap.** The three offense identity keys (``operator.key``,
    ``offense-spine.key``, ``offense-governance.key``) are read as PLAINTEXT through the source vault and
    re-wrapped INSIDE the passphrase-sealed body, so recovery works on NEW hardware where this box's TPM is
    gone; the TPM-sealed KEK ``vault/`` dir itself (machine-bound, useless off-box) is NOT packaged and is
    re-provisioned on the new host. On restore each key is re-sealed through the NEW vault (or written
    plaintext-0600 until it is provisioned) with its own AEAD purpose context.

Integrity is layered exactly like the sovereign leg. The whole body is AEAD-sealed; inside it a manifest
(sha256 of every packaged file) is governance-signed. A wrong passphrase, or ANY tamper of the sealed bytes,
fails to decrypt / fails the manifest signature / fails a per-file hash check BEFORE a single file is
written. AFTER the write, the restore RE-VERIFIES: EVERY restored ``*.spine`` — enumerated RECURSIVELY over
both ``base_dir`` and ``crucible_root``, the same way ``create`` packages them — re-checks its chain +
signatures under the restored spine pubkey AND must carry ≥1 ATTESTED record — a JSON-object record the binder
actually chain-verified, NOT a raw newline-terminated chunk (a content-free spine — garbage / a JSON scalar /
a torn tail — verifies VACUOUSLY under any key and is refused; counting raw newline chunks would be bypassable
by a single trailing byte), the segment view (`verify_offense_home`) reports no FAILED segment, and every
restored self-contained evidence bundle re-runs the deterministic evidence verify — the restore reports
``verified: True`` ONLY if all pass, else it raises. Critically, ``verified: True`` is NEVER returned for a
check that did not RUN: a restored spine (wherever it landed — a subdir or the crucible tree included) with
no usable offense-spine public key to re-verify it under is a fail-closed refusal, not a silent skip (and
``create`` refuses at the source to produce a spine-bearing backup that omits its spine key, so a
key-present spine is always re-verified and a key-absent one is always refused).

Honest limit on what is re-verified: ``.blackboard/store.sqlite`` is captured as a CONSISTENT point-in-time
snapshot (the stdlib sqlite3 online backup API — so a live writer mid-transaction is captured as a coherent
db, not a torn page mix; a non-SQLite file falls back to a raw byte copy with a logged note). That snapshot
is consistent as of the snapshot INSTANT — NOT against writers that commit afterwards. The run dirs are
still captured as OPAQUE bytes. Neither the store db's internal consistency nor the run dirs are re-checked
on restore — only the signed offense spine and the signed evidence chain are. The passphrase is the recovery
secret; it is NEVER stored — lose it and the backup is unrecoverable BY DESIGN (the off-box confidentiality
guarantee, unchanged from the sovereign leg).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath, PureWindowsPath

from vigil_core import canonical_json, sha256_hex, sign, verify_one
from vigil_core.sealing import SealError, seal, unseal
from vigil_core.vault import Vault

from .attestation.identity import OPERATOR_KEYPAIR_CONTEXT
from .live.governance_identity import (
    DEFAULT_GOVERNANCE_KEY_FILE,
    GOVERNANCE_KEYPAIR_CONTEXT,
    load_or_create_governance_keypair,
)
from .live.spine_identity import DEFAULT_SPINE_KEY_FILE, SPINE_KEYPAIR_CONTEXT

_MAGIC = b"VGLBK1\x00"
_SCHEMA = 1
# scrypt work factors — identical to the sovereign leg (n=2^16 ≈ 64 MiB is a strong interactive KDF).
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 16, 8, 1
_SCRYPT_MAXMEM = 132 * _SCRYPT_N * _SCRYPT_R
_SALT_LEN = 16
# AEAD context binding the sealed offense backup body to its purpose (domain-separated from the sovereign
# body context ``b"sigil/backup/v1"`` and from every spine/key seal).
_BODY_CONTEXT = b"vigil/offense-backup/v1"

_OPERATOR_KEY_FILE = "operator.key"
# The three offense identity keys re-wrapped INTO the passphrase-encrypted body (read plaintext through the
# vault, re-sealed on restore). Each carries its OWN AEAD purpose context so a blob for one identity can never
# be opened as another — the same cross-identity non-interchangeability the keystore enforces at rest.
_REWRAP_KEYS: tuple[tuple[str, bytes], ...] = (
    (_OPERATOR_KEY_FILE, OPERATOR_KEYPAIR_CONTEXT),
    (DEFAULT_SPINE_KEY_FILE, SPINE_KEYPAIR_CONTEXT),
    (DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEYPAIR_CONTEXT),
)
# Crucible-side files travel under this rel prefix so restore routes them to ``crucible_root`` (not base_dir).
_CRUCIBLE_PREFIX = "crucible/"
# The CRUCIBLE blackboard db — captured as a CONSISTENT point-in-time snapshot (not a torn raw byte copy) via
# the stdlib sqlite3 online backup API. Its packaged rel; matched in the create read loop to route it through
# ``_read_sqlite_consistent``.
_STORE_SQLITE_REL = _CRUCIBLE_PREFIX + ".blackboard/store.sqlite"
# A real SQLite database file begins with this fixed 16-byte header; a file that does not is copied raw.
_SQLITE_MAGIC = b"SQLite format 3\x00"

_log = logging.getLogger(__name__)


def _read_sqlite_consistent(src: Path) -> bytes:
    """Return the bytes of ``.blackboard/store.sqlite`` as a CONSISTENT point-in-time snapshot.

    A live CRUCIBLE writer may be mid-transaction when the backup runs; a naive ``read_bytes`` of the db file
    can capture a TORN mix of pages (half of an in-flight write) that fails ``PRAGMA integrity_check`` on
    restore. This uses the stdlib ``sqlite3`` ONLINE BACKUP API (``sqlite3.Connection.backup``) into a temp
    file, which copies a coherent snapshot even while another connection writes (WAL or rollback journal),
    and packages THOSE bytes.

    Falls back to a raw byte copy — with a logged note — ONLY if ``src`` is not a valid SQLite database (bad
    magic / not-a-db / open error): an opaque non-db file is better preserved verbatim than lost. The snapshot
    is consistent as of the snapshot INSTANT; it is not a guarantee about writers that commit afterwards."""
    import sqlite3
    import tempfile

    try:
        with open(src, "rb") as fh:
            magic = fh.read(len(_SQLITE_MAGIC))
    except OSError as e:
        _log.warning("store.sqlite at %s could not be read for a snapshot (%s) — raw byte copy", src, e)
        return src.read_bytes()
    if magic != _SQLITE_MAGIC:
        _log.warning("store.sqlite at %s is not a SQLite database (bad header) — raw byte copy", src)
        return src.read_bytes()

    fd, tmpname = tempfile.mkstemp(prefix="vigil-sqlite-snap-", suffix=".sqlite")
    os.close(fd)
    tmp = Path(tmpname)
    try:
        s = d = None
        try:
            s = sqlite3.connect(str(src), timeout=30.0)   # read-write open handles a WAL db's checkpoint state
            d = sqlite3.connect(str(tmp))
            s.backup(d)                                   # online backup: a coherent snapshot of committed pages
        except sqlite3.Error as e:
            _log.warning("store.sqlite at %s failed a consistent snapshot (%s) — raw byte copy", src, e)
            return src.read_bytes()
        finally:
            if d is not None:
                d.close()
            if s is not None:
                s.close()
        return tmp.read_bytes()                           # connections closed → tmp is a complete, flushed db
    finally:
        for p in (tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm"), Path(str(tmp) + "-journal")):
            try:
                p.unlink()
            except OSError:
                pass


class OffenseBackupError(Exception):
    """An offense backup could not be created or restored (bad passphrase, tamper, corrupt/missing state, or a
    post-restore re-verification failure). Fail-closed: restore verifies the governance signature OVER the
    manifest + every file hash BEFORE writing anything, and re-verifies the restored spine + evidence chain
    AFTER; it never reports success on an unverified restore."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise OffenseBackupError("an empty passphrase is refused — the backup would be trivially decryptable")
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                          maxmem=_SCRYPT_MAXMEM, dklen=32)


def _is_sensitive_rel(rel: str) -> bool:
    """True iff a restored file at ``rel`` must be ``chmod 0600`` — key material or a sealed vault blob that
    would otherwise land at the process umask. Covers any ``*.key`` and anything under a ``vault/`` dir."""
    tail = rel[len(_CRUCIBLE_PREFIX):] if rel.startswith(_CRUCIBLE_PREFIX) else rel
    return tail.endswith(".key") or tail.startswith("vault/") or "/vault/" in tail


def _safe_target(root: Path, root_resolved: Path, rel: str) -> Path:
    """Resolve a packaged relative path to a concrete file INSIDE ``root``, or raise OffenseBackupError.

    COPIED VERBATIM from the sovereign ``backup._safe_target`` — it is the whole path-escape class-fix, and
    returns the SAME path the caller must WRITE so a check/write mismatch can never reintroduce an escape:
      * ``PureWindowsPath`` is the STRICTEST interpreter (both ``/`` and ``\\`` are separators, and it
        understands drive letters), so on ANY host — POSIX included — it catches ``..``, absolute, rooted
        (``\\foo``, ``//srv``) AND drive-relative (``D:evil``) paths;
      * a resolved-containment backstop (the ``.resolve()``d target must stay under ``root``) defeats any
        residual trick (symlink games, platform quirks) independent of the syntactic check above.
    """
    win = PureWindowsPath(rel)
    if (not rel or "\x00" in rel or ".." in win.parts or win.is_absolute() or win.drive or win.root
            or PurePosixPath(rel).is_absolute()):
        raise OffenseBackupError(f"refusing an unsafe backup path {rel!r}")
    target = root / PurePosixPath(rel.replace("\\", "/"))     # rel now proven slash-only + drive-free
    if not target.resolve().is_relative_to(root_resolved):
        raise OffenseBackupError(f"refusing an unsafe backup path {rel!r}")
    return target


def _iter_base_files(base: Path):
    """Yield ``(absolute_path, base-relative posix rel)`` for every packageable file under ``base_dir``.
    Skips: transient ``*.lock``; the TPM-sealed KEK ``vault/`` dir (machine-bound, re-provisioned on restore);
    the socket/pid runtime dirs (``ui/pids/``, ``live-ui/``); symlinks (never followed/packaged); and the
    three identity keys (re-wrapped separately as sealed-body secrets)."""
    skip_names = {name for name, _ctx in _REWRAP_KEYS}
    for p in sorted(base.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(base).as_posix()
        parts = rel.split("/")
        if rel.endswith(".lock") or parts[0] in ("vault", "live-ui") or rel.startswith("ui/pids/"):
            continue
        if rel in skip_names:
            continue
        yield p, rel


def _iter_crucible_files(croot: Path):
    """Yield ``(absolute_path, crucible-prefixed rel)`` for the CRUCIBLE-side durable proof state:
    ``.blackboard/store.sqlite`` and the whole ``.console/runs/**`` subtree (reports, reverifiable findings,
    raw evidence bytes, AND any exported self-contained verifiable bundle — the superset needed so a restored
    FACT re-verifies end-to-end). Skips ``*.lock``, the derived ``dossier.zip``, and non-regular files."""
    bb = croot / ".blackboard" / "store.sqlite"
    if bb.is_file() and not bb.is_symlink():
        yield bb, _CRUCIBLE_PREFIX + ".blackboard/store.sqlite"
    runs = croot / ".console" / "runs"
    if runs.is_dir():
        for p in sorted(runs.rglob("*")):
            if p.is_symlink() or not p.is_file():
                continue
            if p.name == "dossier.zip" or p.name.endswith(".lock"):
                continue
            yield p, _CRUCIBLE_PREFIX + p.relative_to(croot).as_posix()


def create_offense_backup(dest, passphrase: str, *, base_dir, crucible_root=None) -> dict:
    """Write a portable, governance-signed, passphrase-encrypted backup of the offense plane to ``dest``.

    Packages ``base_dir`` (minus locks / the machine-bound vault / socket-pid dirs), re-wraps the three
    offense identity keys through the source vault, and captures the CRUCIBLE proof state under
    ``crucible_root`` (rel-prefixed ``crucible/``). Refuses if no ``{slug}.spine`` exists (nothing to protect).
    Returns a summary. The passphrase is NEVER stored — lose it and the backup is unrecoverable by design."""
    base = Path(base_dir)
    if not any(base.glob("*.spine")):
        raise OffenseBackupError(f"no *.spine under {base} — nothing to back up (run an engagement first)")
    vault = Vault(base / "vault")
    gov = load_or_create_governance_keypair(path=str(base / DEFAULT_GOVERNANCE_KEY_FILE), vault=vault)

    file_blobs: dict[str, str] = {}
    file_hashes: dict[str, str] = {}
    sources = list(_iter_base_files(base))
    if crucible_root:
        sources += list(_iter_crucible_files(Path(crucible_root)))
    for f, rel in sources:
        # ``.blackboard/store.sqlite`` is captured as a CONSISTENT snapshot (online backup API); every other
        # file is an opaque raw byte copy. The snapshot bytes are what gets hashed + packaged, so the pre-write
        # hash check and the restored file agree.
        raw = _read_sqlite_consistent(f) if rel == _STORE_SQLITE_REL else f.read_bytes()
        file_blobs[rel] = base64.b64encode(raw).decode("ascii")
        file_hashes[rel] = sha256_hex(raw)

    # re-wrap the three identity keys: read plaintext through the vault (unseals if sealed), store the JSON
    # keypair text INSIDE the passphrase-sealed body so recovery is portable to new hardware.
    secrets: dict[str, str] = {}
    for name, ctx in _REWRAP_KEYS:
        val = vault.read_text_secret(base / name, context=ctx)
        if val is not None:
            secrets[name] = val
    # A ``*.spine`` exists (guaranteed above). Refuse to produce a backup whose restored spine could NEVER be
    # re-verified: without the offense-spine key captured here, restore has no pubkey to integrity-check the
    # spine under, and would otherwise report an UNVERIFIED restore as ``verified: True``. Fail closed at the
    # source so an honest operator can never mint a spine-bearing backup that silently omits its verifying key.
    if DEFAULT_SPINE_KEY_FILE not in secrets:
        raise OffenseBackupError(
            f"refusing to back up: a *.spine exists under {base} but the offense-spine key "
            f"({DEFAULT_SPINE_KEY_FILE}) is missing/unreadable, so the restored spine could never be "
            f"re-verified — provision or restore the offense-spine key first")

    manifest = {
        "schema": _SCHEMA, "scope": gov.public_key_b64, "file_sha256": file_hashes,
        # names only — the key VALUES live in the AEAD-sealed body (like the sovereign owner_priv/dek).
        "secrets": sorted(secrets.keys()),
    }
    manifest_sig = sign(gov.private_key_b64, canonical_json(manifest))
    body = {
        "manifest": manifest, "manifest_sig": manifest_sig, "manifest_pubkey": gov.public_key_b64,
        "files": file_blobs, "secrets": secrets,
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
    return {"dest": str(dest), "files": len(file_blobs), "secrets": len(secrets),
            "scope": gov.public_key_b64, "bytes": len(sealed)}


def _read_header(src: Path) -> tuple[bytes, bytes]:
    raw = src.read_bytes()
    if not raw.startswith(_MAGIC):
        raise OffenseBackupError("not a VIGIL offense backup file (bad magic)")
    off = len(_MAGIC)
    salt = raw[off:off + _SALT_LEN]
    if len(salt) != _SALT_LEN:
        raise OffenseBackupError("truncated backup header")
    return salt, raw[off + _SALT_LEN:]


def _verify_evidence_bundles(root: Path) -> int:
    """Re-run the deterministic CRUCIBLE evidence verify over every restored SELF-CONTAINED bundle under
    ``root`` (a dir carrying ``evidence-bundle.json`` + ``trust-root.json`` + ``reverifiable.json``). Returns
    the count that re-verified SOUND; raises OffenseBackupError on the FIRST bundle that does NOT — this is the
    "restore preserves the proof" gate (a flipped evidence byte breaks the cert's artifact hash → NOT SOUND).

    It uses the bundle's in-tree trust root (an internal-consistency + reproduction re-check, not an
    out-of-band authenticity pin — that pin is the recipient's job at hand-off). Raw run-dir evidence trees
    with no self-contained bundle are skipped (nothing to re-verify there — never a fake pass)."""
    from framework.v2.evidence.cli import main as _evidence_main   # lazy — offense-only (FATAL-2 stays clean)
    count = 0
    for bj in sorted(root.rglob("evidence-bundle.json")):
        if bj.is_symlink() or not bj.is_file():
            continue
        d = bj.parent
        tr, report, ev = d / "trust-root.json", d / "reverifiable.json", d / "evidence"
        if not (tr.is_file() and report.is_file()):
            continue
        argv = ["verify", "--report", str(report), "--bundle", str(d), "--trust-root", str(tr)]
        if ev.is_dir():
            argv += ["--evidence-root", str(ev)]
        if _evidence_main(argv) != 0:
            raise OffenseBackupError(
                f"restored evidence bundle at {d} did NOT re-verify — the restore did not preserve the "
                f"signed proof chain (fail-closed)")
        count += 1
    return count


def restore_offense_backup(src, new_base, passphrase: str, *, crucible_root=None, expect_pubkey=None) -> dict:
    """Decrypt + VERIFY an offense backup, then write the base_dir state into ``new_base`` and the CRUCIBLE
    proof state into ``crucible_root``. Fail-closed: the passphrase must decrypt, the governance signature
    over the manifest must verify, and every file's sha256 must match BEFORE anything is written. The three
    identity keys are re-sealed through the NEW vault. AFTER the write it RE-VERIFIES — every restored spine's
    chain/signatures, the segment view (no FAILED), and every restored evidence bundle — and returns
    ``{"verified": True, ...}`` ONLY if all pass, else raises OffenseBackupError.

    ``expect_pubkey`` (optional) is the out-of-band AUTHENTICITY pin: the expected offense-GOVERNANCE pubkey
    the recipient obtained through a trusted channel. When supplied, the in-body manifest pubkey MUST equal it
    (and the signature is verified under it), so a passphrase-holder who does not also hold the governance
    private key cannot pass off a self-signed manifest. When omitted, restore-time authenticity reduces to
    passphrase-possession (the AEAD passphrase is the root of trust — see the module docstring)."""
    src, new_base = Path(src), Path(new_base)
    croot = Path(crucible_root) if crucible_root else None
    salt, sealed = _read_header(src)
    try:
        raw = unseal(_derive_key(passphrase, salt), sealed, context=_BODY_CONTEXT)
    except SealError as e:
        raise OffenseBackupError("could not decrypt the backup — wrong passphrase or a tampered file") from e
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise OffenseBackupError(f"corrupt backup body: {e}") from e
    if not isinstance(body, dict):
        raise OffenseBackupError("corrupt backup body: expected a JSON object")

    manifest = body.get("manifest")
    pub = body.get("manifest_pubkey")
    sig = body.get("manifest_sig")
    if not isinstance(manifest, dict) or not isinstance(pub, str) or not isinstance(sig, str):
        raise OffenseBackupError("backup is missing its signed manifest")
    # Out-of-band authenticity pin (optional): reject a manifest NOT signed by the expected governance key
    # BEFORE trusting anything in the body. Without the pin, the in-body pubkey is self-asserted (any
    # passphrase-holder can mint it) — the pin is what turns the governance signature into real authenticity.
    if expect_pubkey is not None and pub != expect_pubkey:
        raise OffenseBackupError(
            "backup manifest is not signed by the pinned --expect-governance-pubkey (authenticity pin "
            "failed) — refusing to restore a manifest of unverified provenance")
    try:
        if not verify_one(pub, canonical_json(manifest), sig):
            raise OffenseBackupError("backup manifest signature does not verify (tamper)")
    except OffenseBackupError:
        raise
    except Exception as e:  # noqa: BLE001 — malformed key/sig → fail-closed
        raise OffenseBackupError(f"backup manifest signature is malformed: {e}") from e

    files = body.get("files")
    hashes = manifest.get("file_sha256")
    if not isinstance(files, dict) or not isinstance(hashes, dict):
        raise OffenseBackupError("backup is missing its file table")
    if set(files) != set(hashes):
        raise OffenseBackupError("backup file set does not match its signed manifest")

    secrets = body.get("secrets", {})
    if not isinstance(secrets, dict):
        raise OffenseBackupError("backup secrets block is malformed (expected an object)")
    for name, val in secrets.items():
        if not isinstance(val, str):
            raise OffenseBackupError(f"backup secret {name!r} is malformed (expected a string)")
    # the manifest's signed secret-name set must match the body's secret keys (a signed body whose secret set
    # was tampered fails closed rather than silently dropping/adding a key).
    if set(secrets) != set(manifest.get("secrets", []) or []):
        raise OffenseBackupError("backup secret set does not match its signed manifest")

    # If a crucible-rooted file exists in the table, restore REQUIRES a crucible_root to route it to.
    if croot is None and any(rel.startswith(_CRUCIBLE_PREFIX) for rel in files):
        raise OffenseBackupError("backup carries CRUCIBLE proof files but no crucible_root was given to "
                                 "restore them into — refusing a partial restore")

    # decode + verify EVERY file against the signed manifest BEFORE writing anything (fail-closed). Each rel is
    # routed to base_dir or crucible_root and resolved to ONE validated target; the SAME target is written.
    new_base_resolved = new_base.resolve()
    croot_resolved = croot.resolve() if croot is not None else None
    decoded: list[tuple[Path, bytes, str]] = []
    for rel, b64 in files.items():
        if rel.startswith(_CRUCIBLE_PREFIX):
            target = _safe_target(croot, croot_resolved, rel[len(_CRUCIBLE_PREFIX):])   # type: ignore[arg-type]
        else:
            target = _safe_target(new_base, new_base_resolved, rel)
        try:
            data = base64.b64decode(b64)
        except Exception as e:  # noqa: BLE001
            raise OffenseBackupError(f"corrupt file blob {rel!r}: {e}") from e
        if sha256_hex(data) != hashes[rel]:
            raise OffenseBackupError(f"file {rel!r} does not match its signed hash (tamper)")
        decoded.append((target, data, rel))

    new_base.mkdir(parents=True, exist_ok=True)
    if croot is not None:
        croot.mkdir(parents=True, exist_ok=True)
    for target, data, rel in decoded:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if _is_sensitive_rel(rel):
            os.chmod(target, 0o600)
    # re-seal the three identity keys through the NEW vault (sealed under the new TPM if provisioned, else
    # plaintext-0600) — each with its own AEAD purpose context.
    dst_vault = Vault(new_base / "vault")
    key_ctx = {name: ctx for name, ctx in _REWRAP_KEYS}
    for name, val in secrets.items():
        ctx = key_ctx.get(name)
        if ctx is None:
            raise OffenseBackupError(f"backup carries an unknown re-wrapped secret {name!r} — refusing")
        dst_vault.write_text_secret(new_base / name, val, context=ctx)

    verified_bundles = _reverify_restored(new_base, croot, secrets)
    return {"new_base": str(new_base), "crucible_root": (str(croot) if croot else None),
            "files": len(decoded), "secrets": len(secrets),
            "bundles_verified": verified_bundles, "verified": True}


def _reverify_restored(new_base: Path, croot, secrets: dict) -> int:
    """Post-write re-verification (the honest teeth). Import-local (FATAL-2 hygiene): re-verify EVERY restored
    ``*.spine`` — enumerated RECURSIVELY over both ``new_base`` and ``crucible_root`` (the SAME way ``create``
    packages them) — under the restored spine pubkey, assert the segment view reports no FAILED segment, and
    re-run the deterministic evidence verify over every restored self-contained bundle. Raises
    OffenseBackupError unless ALL pass. Returns the count of evidence bundles that re-verified."""
    from .live.spine_verify import (
        FAILED,
        VERIFIED,
        _count_attested_records,
        verify_offense_home,
        verify_offense_spine,
    )

    # Enumerate restored spines the SAME way `create` PACKAGES them — RECURSIVELY, over BOTH the base_dir AND
    # the crucible root (create uses rglob and routes crucible-tree files under ``crucible/``). A non-recursive
    # ``new_base``-only glob would MISS a spine that landed in a subdir or under the crucible tree and wave it
    # through un-verified — the rglob/glob asymmetry a red-pen exploited to reforge an unearned `verified: True`.
    spine_files = sorted(new_base.rglob("*.spine"))
    if croot is not None:
        spine_files += sorted(Path(croot).rglob("*.spine"))
    spine_pub = None
    sk = secrets.get(DEFAULT_SPINE_KEY_FILE)
    if sk:
        try:
            spine_pub = json.loads(sk).get("public_key_b64")
        except Exception:  # noqa: BLE001 — a malformed spine key must NOT silently drop the check (fail closed)
            spine_pub = None
    # FAIL CLOSED: any restored spine we cannot integrity-check (no usable spine pubkey) must NEVER be reported
    # as verified. `create` refuses to mint such a backup at the source; this catches a hand-crafted/legacy
    # body too. Reporting success for a re-verify that did not RUN is exactly the unearned `verified: True`
    # the red-pen flagged — the segment view below can't cover it (a keyless spine segment is UNVERIFIABLE,
    # never FAILED), so it is asserted here.
    if spine_files and not spine_pub:
        raise OffenseBackupError(
            f"cannot re-verify {len(spine_files)} restored spine file(s): the backup carries no usable "
            f"offense-spine public key — refusing to report an unverified restore as verified")
    for sp in spine_files:
        v = verify_offense_spine(spine_path=str(sp), spine_pubkey=spine_pub)
        if v.status != VERIFIED:                       # require a POSITIVE verdict, not merely "not FAILED"
            raise OffenseBackupError(
                f"restored spine {sp} did NOT re-verify (status={v.status}: {v.detail}) — the restore is "
                f"NOT trustworthy")
        # A spine that "verifies" with ZERO ATTESTED records attests nothing and passes VACUOUSLY even under a
        # NON-matching key (garbage / JSON-scalar / torn-tail-only body — the binder's empty-chain verify is
        # trivially true). Count the records `verify()` ACTUALLY consumed — the JSON-OBJECT lines the binder's
        # `_read_lines` yields (and, given the VERIFIED verdict above, chain-verified) — NOT raw newline chunks:
        # a raw `_count_records` over-counts a `b"not a valid spine\n"` / `b"[1,2,3]\n"` body as 1 while the
        # binder attested 0, so the raw count is bypassable by a single trailing byte. Refuse the 0-attested case.
        if _count_attested_records(str(sp)) < 1:
            raise OffenseBackupError(
                f"restored spine {sp} re-verified but attests NO records (0 JSON-object records the binder "
                f"chain-verified — a garbage/scalar/torn body verifies vacuously) — refusing to report a "
                f"content-free spine as verified")
    # the segment view: any PRESENT segment that FAILS integrity (e.g. a corrupt usage ledger) is fatal;
    # ABSENT / UNVERIFIABLE segments are honest non-failures (nothing to attest / no owner tie supplied here).
    for seg in verify_offense_home(str(new_base)):
        if seg.status == FAILED:
            raise OffenseBackupError(
                f"restored offense segment {seg.segment} FAILED integrity re-verification ({seg.detail})")
    # every restored self-contained evidence bundle must re-verify SOUND (raises on the first that does not).
    bundles_verified = _verify_evidence_bundles(croot) if croot is not None else 0
    # HONEST FLOOR: a restore that re-verified NOTHING — no `*.spine` re-checked AND no self-contained evidence
    # bundle re-verified — attests nothing, so it must NOT be reported `verified: True`. A real offense backup
    # ALWAYS carries a `{slug}.spine` (`create` refuses a spine-free base at the source), so this only bites a
    # hand-crafted (passphrase-forgeable) body with an empty/spine-free file table — close it fail-closed rather
    # than stamp an empty restore as verified. (spine_files non-empty ⇒ each was VERIFIED with ≥1 attested
    # record above; bundles_verified>0 ⇒ a real evidence re-verify ran — either is a real, non-vacuous attest.)
    if not spine_files and bundles_verified == 0:
        raise OffenseBackupError(
            "restore re-verified NOTHING — no *.spine to re-check and no self-contained evidence bundle to "
            "re-verify — refusing to report an empty/spine-free (hand-crafted) backup as verified")
    return bundles_verified
