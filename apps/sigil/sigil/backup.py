"""Signed, passphrase-encrypted, PORTABLE backup of the SIGIL trust root + spine (audit G3(a)).

Honest naming: this writes a PORTABLE, passphrase-encrypted LOCAL backup file. It is portable (it restores on
NEW hardware where this box's TPM is gone) and encrypted at rest — but a plain ``sigil backup`` writes to the
SAME host's disk, so it is NOT off-HOST replication on its own: a dead host takes the engine AND its local
backups. TRUE off-HOST replication is a SEPARATE, opt-in step — the orchestrator's ``vigil backup --push
<remote>`` copies the ENCRYPTED backup file to a configured remote (see tools/backup/transport.py); transport
moves CIPHERTEXT only, and the remote's own security is the operator's responsibility.

The TPM-sealed vault (G1) binds the owner key + the spine DEK to THIS machine's TPM, so a dead disk is
unrecoverable from the vault alone — the whole audit ledger + all memory would be lost. This produces a
PORTABLE disaster-recovery backup of everything a FUNCTIONAL recovery needs (W7-2): the spine (segments +
manifest + signed head + floor + the G2 security manifest + the owner PUBLIC key), the WARDEN permission-
kernel dir (its signed action ledger + kernel keypair + tool registry), the CONFIG files (the HA witness
roster ``witness.trust.json`` the failover guard depends on, the governor ``budgets.json`` caps, and the
persisted ``sigil.env``), the MEMORY-state subtrees (the ``qdrant/`` vector store + the ``graph/`` mirror),
plus the OWNER PRIVATE key, the spine DEK, and the sealed KV secret store (``secrets.sealed``) are packaged
and encrypted under a key derived from an OWNER PASSPHRASE (scrypt), so the backup restores on NEW hardware
where this machine's TPM is gone. The WARDEN kernel key (`warden/warden.key`) and ``sigil.env`` ride inside
the AEAD-sealed body and are re-created 0600 on restore. Which top-level home entries are captured vs a
DELIBERATE, documented exclusion is the coverage contract in :data:`CAPTURED_TOP_LEVEL` /
:data:`EXCLUDED_TOP_LEVEL` — a structural test proves a populated home leaves nothing unclassified, so a new
state artifact can never be silently dropped from disaster recovery again.

The three portable secrets (owner private key, spine DEK, KV secret store) are re-wrapped from their
PLAINTEXT into the passphrase-sealed body and re-sealed through the NEW vault on restore. These are the
OPERATOR'S OWN recovery material (own keys / own API keys), legitimately co-travelling under the passphrase
root of trust — distinct from captured TARGET-credential evidence, whose W16-8 "keep the DEK OUT of the
place the ciphertext travels" rule governs the OFFENSE leg's shreddable evidence keystore (never touched by
this sovereign trust-root backup).

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
import shutil
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from vigil_core.sealing import SealError, seal, unseal

from .reuse import KeyPair, canonical_json, sha256_hex, sign, verify_one
from .spine.schema_guard import SchemaTooNew, refuse_newer

_MAGIC = b"SGLBK1\x00"
# schema 2 additionally records the WARDEN permission-kernel set ("warden": [rels…]); schema 3 (W7-2)
# additionally covers the config files (witness.trust.json / budgets.json / sigil.env), the memory state
# subtrees (qdrant/ + graph/) and RE-WRAPS the sealed KV secret store (secrets.sealed) portably. Older
# schemas are still read on restore (back-compat) — the file table is authenticated the same way either way.
_SCHEMA = 3
_MAX_BACKUP_SCHEMA = _SCHEMA   # refuse-newer gate (W5-3): a backup schema above this is "upgrade sigil"
# scrypt work factors — n=2^16 (64 MiB) is a strong interactive KDF; salt is per-backup, stored in the header.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 16, 8, 1
_SCRYPT_MAXMEM = 132 * _SCRYPT_N * _SCRYPT_R          # headroom over scrypt's 128*n*r working set
_SALT_LEN = 16
# AEAD context binding the sealed backup body to its purpose (domain separation vs the spine/owner seals).
_BODY_CONTEXT = b"sigil/backup/v1"
# The vault-custodied secrets re-wrapped INTO the passphrase-encrypted backup so recovery is portable.
_OWNER_PRIV_CONTEXT = b"sigil/owner.priv"
_DEK_CONTEXT = b"sigil/spine.dek"
# The sealed key-value secret store (API keys / service passwords). Its AEAD purpose context MUST match
# ``platform.secrets._SEALED_CONTEXT`` — it is read as PLAINTEXT through the source vault and re-sealed
# through the NEW vault on restore, so the operator's own recovery secrets survive a move to new hardware
# where this box's KEK is gone. (This is the OPERATOR'S keys — legitimate recovery material, re-wrapped like
# owner.priv/spine.dek — NOT captured target-credential evidence; W16-8's "don't co-locate the DEK with the
# ciphertext" rule governs the OFFENSE leg's evidence keystore, never touched by this sovereign trust-root
# backup.)  The KV store file itself is NEVER packaged as a raw ``files`` entry — only its plaintext, re-wrapped.
_SECRETS_KV_FILE = "secrets.sealed"
_SECRETS_KV_CONTEXT = b"sigil/secrets.kv"
# Top-level CONFIG files (not key material) packaged verbatim into the sealed body. floor.json /
# security.manifest.json were already covered; W7-2 adds the HA witness roster (the failover guard depends on
# it), the governor budget caps, and the persisted env file. ``sigil.env`` can hold a signing secret (e.g.
# VIGIL_DESTRUCTION_OWNER_KEY) so it is 0600 on restore (see :func:`_is_sensitive_rel`).
_CONFIG_FILES = ("floor.json", "security.manifest.json", "witness.trust.json", "budgets.json", "sigil.env")
# Top-level memory-STATE subtrees packaged verbatim (raw bytes, locks skipped): the Qdrant vector store and
# the Kùzu graph mirror. They are derivable from the spine by a re-index, but a DR restore captures them so a
# recovered install is immediately searchable (bounds RTO) rather than needing a costly re-embed/rebuild.
_STATE_DIRS = ("qdrant", "graph")

# --- backup COVERAGE CONTRACT (W7-2 structural enumeration) ---------------------------------------
# Every top-level entry a real SIGIL_HOME can hold is either CAPTURED by this backup or a DELIBERATE,
# DOCUMENTED exclusion. ``test_backup_coverage`` asserts a populated home has NO unclassified top-level
# entry, so a NEW state artifact cannot be silently omitted from disaster recovery again — the failure is a
# forced decision, not an accident.
CAPTURED_TOP_LEVEL = frozenset({
    "spine",                    # trust root: segments, signed head, owner PUBLIC key, the append-only ledger
    "floor.json",               # anti-rollback floor
    "security.manifest.json",   # G2 security manifest
    "warden",                   # WARDEN permission kernel (signed action ledger + kernel key + tool registry)
    "witness.trust.json",       # HA failover witness roster
    "budgets.json",             # governor per-agent budget caps
    "sigil.env",                # persisted config / legacy secret tier
    "secrets.sealed",           # sealed KV secret store (re-wrapped portably, not a raw file entry)
    "qdrant",                   # vector memory store
    "graph",                    # graph memory mirror
})
# Deliberate exclusions, each with a reason the structural test surfaces. Keeping the REASONS in code is what
# makes this a *documented* exclusion list (acceptance criterion), not a silent skip.
_EXCLUSION_REASONS: dict[str, str] = {
    "vault": "machine-bound TPM-sealed KEK — useless off-box; re-provisioned on the new host (the secrets it "
             "wraps are re-wrapped into the sealed backup body instead)",
    "backups": "the backup OUTPUT directory itself — packaging it would recurse prior backups into new ones",
    "cache": "derived cache — rebuilt on demand, no trust or memory state",
    "models": "re-downloadable ML model files (large) — not trust/memory state",
    "host_id": "per-machine identity — deliberately re-derived on the new host, never carried across",
    "prices.json": "re-fetchable provider price table (a cache)",
    "bastion-assets.json": "BASTION scanner asset feed — a re-fetched cache",
    "bastion-cve-feed.json": "BASTION CVE feed — a re-fetched cache",
    "secret-health.json": "value-free secret-health verdict cache — re-derived",
    "sigil-hud.json": "transient cockpit HUD state",
    "inbox.json": "ENVOY in-flight message queue — operational scratch, not recovery state",
    "actor": "in-flight browser-actor step journals — operational scratch, off the trust root",
    "operator": "in-flight operator plan/journal pre-images — operational scratch, off the trust root",
}
EXCLUDED_TOP_LEVEL = frozenset(_EXCLUSION_REASONS)


def classify_top_level(name: str) -> str:
    """Classify a SIGIL_HOME top-level entry name as ``"captured"``, ``"excluded"`` or ``"unclassified"``.
    A ``*.lock``/``*.tmp`` transient is always ``"excluded"``. The W7-2 structural test uses this to prove a
    populated home has nothing unclassified — so a new state artifact forces a coverage decision."""
    if name.endswith((".lock", ".tmp")):
        return "excluded"
    if name in CAPTURED_TOP_LEVEL:
        return "captured"
    if name in EXCLUDED_TOP_LEVEL:
        return "excluded"
    return "unclassified"


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


def _warden_home(home: Path) -> Path:
    """The WARDEN permission-kernel dir (kernel/src/main.rs ``warden_dir()``): ``$SIGIL_WARDEN_HOME`` or
    ``<home>/warden``. Holds ``actionlog.jsonl`` (the signed action ledger), ``warden.pub``/``warden.key``
    (crypto.rs kernel keypair), and ``tools.json`` (the tool registry)."""
    return Path(os.environ.get("SIGIL_WARDEN_HOME") or (home / "warden"))


def _is_sensitive_rel(rel: str) -> bool:
    """True iff a restored file at ``rel`` must be ``chmod 0600`` — private key material that would otherwise
    land at the process umask (potentially world-readable). Covers the WARDEN kernel key
    (``warden/warden.key`` — a plaintext-0600 Rust-kernel file that rides inside the passphrase-sealed body)
    and ANY packaged ``*.key`` file, PLUS ``sigil.env`` (the persisted config / legacy secret tier, which can
    hold a signing secret such as VIGIL_DESTRUCTION_OWNER_KEY). The whole backup body is AEAD-sealed at rest
    regardless; this closes the post-restore on-disk perms of the sensitive material itself."""
    return rel.endswith(".key") or rel == "sigil.env"


def _spine_files(home: Path) -> list[tuple[Path, str]]:
    """Every trust-root/spine/kernel/config/state file to package, as ``(absolute_path, home-relative posix
    rel)`` pairs. Includes the spine dir (segments, manifest, signed head, the owner PUBLIC key), the config
    files (anti-rollback floor, G2 security manifest, HA witness roster, budget caps, persisted env), the
    WARDEN permission-kernel dir, AND the memory-state subtrees (qdrant/ + graph/). EXCLUDES the machine-bound
    secrets (re-wrapped separately): the sealed owner PRIVATE key, the sealed DEK, the sealed KV store
    (re-wrapped via :data:`_SECRETS_KV_CONTEXT`), the TPM-sealed KEK vault dir, and transient lockfiles.

    The WARDEN files are packaged under a NORMALIZED ``warden/`` rel (relative to the warden dir, not
    ``home``) so a ``SIGIL_WARDEN_HOME`` pointed OUTSIDE ``SIGIL_HOME`` still restores to ``<home>/warden``;
    transient ``*.lock`` is skipped. ``warden.key`` is a plaintext-0600 kernel key — it rides inside the
    AEAD-sealed body like any packaged file (safe: the whole body is passphrase-sealed) and restore re-creates
    it 0600 (see :func:`_is_sensitive_rel`)."""
    out: list[tuple[Path, str]] = []
    spine = home / "spine"
    if spine.is_dir():
        for p in sorted(spine.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(home).as_posix()
            if rel.endswith((".lock",)) or rel in ("spine/keys/owner.priv", "spine/keys/spine.dek"):
                continue
            out.append((p, rel))
    for extra in _CONFIG_FILES:
        f = home / extra
        if f.is_file() and not f.is_symlink():
            out.append((f, f.relative_to(home).as_posix()))
    warden = _warden_home(home)
    if warden.is_dir():
        for p in sorted(warden.rglob("*")):
            if p.is_file() and not p.name.endswith(".lock"):
                out.append((p, "warden/" + p.relative_to(warden).as_posix()))
    # memory-state subtrees (qdrant/ + graph/): raw byte capture of every regular file, locks skipped, symlinks
    # never followed (they would let a crafted home escape the tree; restore's _safe_target is the backstop).
    for state in _STATE_DIRS:
        d = home / state
        if d.is_dir() and not d.is_symlink():
            for p in sorted(d.rglob("*")):
                if p.is_symlink() or not p.is_file() or p.name.endswith(".lock"):
                    continue
                out.append((p, p.relative_to(home).as_posix()))
    return out


def create_backup(dest: str | Path, passphrase: str, *, home: Path, vault: Any, owner_key: KeyPair) -> dict:
    """Write a portable, signed, passphrase-encrypted backup of ``home``'s trust root + spine to ``dest``.

    ``vault`` reads the (possibly TPM-sealed) owner private key + spine DEK + sealed KV secret store as
    plaintext to re-wrap them into the encrypted backup; ``owner_key`` signs the file manifest. Returns a
    summary."""
    home = Path(home)
    files = _spine_files(home)
    if not any(rel == "spine/head.json" for _f, rel in files):
        raise BackupError(f"no signed spine head under {home} — nothing to back up (run `sigil sign` first)")
    # DEFENCE-IN-DEPTH against the W16-8 "don't co-locate the DEK with the ciphertext" rule: the sealed KV
    # store is re-wrapped from its PLAINTEXT (below), never copied as a raw sealed file — assert no file entry
    # is the sealed KV store, so a future _spine_files change can never quietly package the ciphertext too.
    if any(rel == _SECRETS_KV_FILE for _f, rel in files):
        raise BackupError(f"{_SECRETS_KV_FILE} must be re-wrapped from plaintext, never packaged as a raw "
                          f"sealed file — refusing (a coverage bug)")
    file_blobs: dict[str, str] = {}
    file_hashes: dict[str, str] = {}
    warden_rels: list[str] = []
    for f, rel in files:
        raw = f.read_bytes()
        file_blobs[rel] = base64.b64encode(raw).decode("ascii")
        file_hashes[rel] = sha256_hex(raw)
        if rel.startswith("warden/"):
            warden_rels.append(rel)

    # the machine-bound secrets, read as plaintext through the vault (unseals if sealed) — re-wrapped
    # portably by living INSIDE the passphrase-encrypted body.
    owner_priv = vault.read_text_secret(home / "spine" / "keys" / "owner.priv", context=_OWNER_PRIV_CONTEXT)
    dek = vault.read_text_secret(home / "spine" / "keys" / "spine.dek", context=_DEK_CONTEXT)
    # the sealed KV secret store (the operator's own API keys / service passwords): read PLAINTEXT through the
    # source vault so recovery is portable to new hardware where this box's KEK is gone. On restore it is
    # re-SEALED through the NEW vault under the SAME purpose context — the plaintext only ever lives inside the
    # passphrase-encrypted body, exactly like owner.priv/spine.dek.
    secrets_kv = vault.read_text_secret(home / _SECRETS_KV_FILE, context=_SECRETS_KV_CONTEXT)

    manifest = {
        "schema": _SCHEMA, "scope": owner_key.public_key_b64, "file_sha256": file_hashes,
        "has_owner_priv": owner_priv is not None, "has_dek": dek is not None,
        "has_secrets_kv": secrets_kv is not None,
        # the WARDEN permission-kernel set (schema 2) — restore asserts every listed rel is present in the
        # signed file table (fail-closed on a partial warden capture); an empty list means no warden dir existed.
        "warden": sorted(warden_rels),
    }
    manifest_sig = sign(owner_key.private_key_b64, canonical_json(manifest))

    body = {
        "manifest": manifest, "manifest_sig": manifest_sig, "manifest_pubkey": owner_key.public_key_b64,
        "files": file_blobs, "owner_priv_b64": owner_priv, "spine_dek_b64": dek, "secrets_kv_b64": secrets_kv,
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
            "dek": dek is not None, "secrets_kv": secrets_kv is not None, "warden": len(warden_rels),
            "bytes": len(sealed)}


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


def _new_staging_dir(dest: Path) -> Path:
    """A private staging dir under ``dest``'s PARENT (same filesystem → the final ``os.replace`` is an ATOMIC
    rename). The whole restored home is built + re-verified HERE and only swapped onto ``dest`` once everything
    passes, so a mid-restore crash leaves ``dest`` as the complete OLD home (or absent), never a mixed home."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=".restore-staging-", dir=str(dest.parent)))


def _drop_path(p: Path) -> None:
    """Best-effort remove ``p`` whether it is a dir, a file, or a (possibly broken) symlink."""
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p, ignore_errors=True)
    elif p.exists() or p.is_symlink():
        try:
            p.unlink()
        except OSError:
            pass


def _atomic_swap_unit(staged_unit: Path, dest_unit: Path) -> None:
    """Atomically replace ONE captured unit (a FILE or a whole SUBTREE) at ``dest_unit`` with ``staged_unit``,
    leaving every SIBLING under ``dest_unit.parent`` UNTOUCHED. Move-aside → rename-in → drop-old (each rename
    atomic, same filesystem), so a crash leaves ``dest_unit`` as the complete OLD unit, absent, or the complete
    NEW unit — never torn."""
    dest_unit.parent.mkdir(parents=True, exist_ok=True)
    if dest_unit.exists() or dest_unit.is_symlink():
        aside = dest_unit.parent / (".restore-old-" + dest_unit.name)
        _drop_path(aside)                                 # clear any stale aside from a prior crashed restore
        os.replace(str(dest_unit), str(aside))            # atomic: dest_unit → aside
        try:
            os.replace(str(staged_unit), str(dest_unit))  # atomic: staged unit → dest_unit
        except OSError:
            os.replace(str(aside), str(dest_unit))        # best-effort rollback
            raise
        _drop_path(aside)                                 # drop the old unit
    else:
        os.replace(str(staged_unit), str(dest_unit))      # atomic into a fresh slot


def _atomic_swap_captured_units(staged: Path, dest: Path) -> None:
    """Swap each TOP-LEVEL entry of the staged home onto ``dest`` as its own atomic unit, leaving every
    top-level entry ALREADY under ``dest`` that the backup did NOT capture (cache/models/agent journals, other
    SIGIL_HOME state) UNTOUCHED. The staged home holds EXACTLY the captured SUBSET (``spine``, the config
    files, ``warden``, ``qdrant``/``graph``, the re-sealed ``secrets.sealed`` — see ``_spine_files`` /
    :data:`CAPTURED_TOP_LEVEL`), so this replaces exactly those units and nothing else: a ``--force`` restore
    can NEVER delete live, un-captured home content. Units are swapped sequentially — each atomic; the set is
    not jointly atomic (a crash leaves some new, some old, none torn)."""
    dest.mkdir(parents=True, exist_ok=True)
    for staged_unit in sorted(staged.iterdir()):
        _atomic_swap_unit(staged_unit, dest / staged_unit.name)


def restore_backup(src: str | Path, new_home: str | Path, passphrase: str, *, vault: Any,
                   force: bool = False) -> dict:
    """Decrypt + VERIFY a backup, then STAGE the trust root + spine into a private temp dir, re-verify it, and
    only then ATOMICALLY swap it onto ``new_home``. Fail-closed: the passphrase must decrypt, the owner
    signature over the manifest must verify, and every file's sha256 must match BEFORE anything is written; the
    staged spine is then re-verified (`store.verify`). The owner private key + DEK are re-sealed through
    ``vault`` (under the NEW machine's TPM if provisioned, else plaintext).

    STAGED / ATOMIC restore, UNIT-SCOPED (no stale-state overlay, no destruction of un-captured data): the
    restored state is built + verified in a sibling temp dir under ``new_home``'s PARENT, then the CAPTURED
    UNITS (top-level of the backup — ``spine``, ``floor.json``, ``security.manifest.json``, ``warden``) are
    renamed into place, each atomically. The backup is a strict SUBSET of ``SIGIL_HOME``, so restore replaces
    ONLY those units; every un-captured top-level entry already under ``new_home`` (vector/cursor/config caches,
    other home state) is LEFT INTACT — even under ``--force``. The force-gate fires only when a captured unit
    already exists, never merely because the home is non-empty. Honest limits: a mid-restore crash leaves each
    unit complete-old-or-complete-new (never torn) but the set of units is not jointly atomic; and the swap is
    atomic against a CRASH, not against a concurrent WRITER already mutating ``new_home``."""
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

    # REFUSE-NEWER (W5-3, #447): the manifest schema is now AUTHENTICATED (the signature just verified), so
    # trust it and refuse a backup whose schema is newer than this build understands — a newer writer may
    # re-shape the file table / secret-wrapping / a new capture unit, and restoring it as the old shape would
    # silently drop or misread that state. Checked BEFORE any file is decoded or written, so a too-new backup
    # never touches ``new_home``. (A schema-1 backup carries no "schema" key -> default 1, still accepted.)
    try:
        refuse_newer(manifest.get("schema", 1), _MAX_BACKUP_SCHEMA, artifact="backup")
    except SchemaTooNew as e:
        raise BackupError(str(e)) from e

    files = body.get("files")
    hashes = manifest.get("file_sha256")
    if not isinstance(files, dict) or not isinstance(hashes, dict):
        raise BackupError("backup is missing its file table")
    if set(files) != set(hashes):
        raise BackupError("backup file set does not match its signed manifest")
    # schema-2 WARDEN set: every listed warden rel MUST be present in the signed file table (fail-closed on a
    # partial warden capture — a manifest that names a warden file the body omits). Schema-1 backups carry no
    # "warden" block; absent is fine (back-compat). set(files)==set(hashes) already binds these, so this is a
    # defensive assertion that the warden set specifically is whole, plus a type guard on a hostile field.
    warden_listed = manifest.get("warden", [])
    if warden_listed is not None:
        if not isinstance(warden_listed, list) or any(not isinstance(r, str) for r in warden_listed):
            raise BackupError("backup manifest 'warden' set is malformed (expected a list of strings)")
        missing = [r for r in warden_listed if r not in files]
        if missing:
            raise BackupError(f"backup is missing WARDEN file(s) named in its signed manifest: {missing}")
    # the re-wrapped secrets must be strings (or absent) — validated BEFORE any write, so a malformed
    # signed body fails closed with a clean BackupError instead of a bare AttributeError at the vault
    # boundary (`.encode()` on a non-str). Mirrors the manifest/pub/sig/files/hashes type guards above.
    for _label, _val in (("owner private key", body.get("owner_priv_b64")),
                         ("spine DEK", body.get("spine_dek_b64")),
                         ("sealed KV secret store", body.get("secrets_kv_b64"))):
        if _val is not None and not isinstance(_val, str):
            raise BackupError(f"backup {_label} is malformed (expected a string)")
    # STAGED / ATOMIC restore, UNIT-SCOPED: restore replaces ONLY the captured units (top-level of the backup:
    # ``spine``, ``floor.json``, ``security.manifest.json``, ``warden``, the W7-2 config files + qdrant/graph
    # state, and the re-wrapped ``secrets.sealed``), so it refuses (without force) ONLY when one of THOSE
    # already exists at ``new_home`` — never merely because the home is non-empty. This keeps un-captured home
    # content (cache/models/actor journals) both un-blocking AND un-destroyed on a --force restore (the
    # subset-capture-vs-replace-whole fix — "stale files do not survive" must not mean live data).
    captured_units = set(rel.split("/", 1)[0] for rel in files)
    if body.get("secrets_kv_b64") is not None:      # re-wrapped (not a file entry) but lands as a top-level unit
        captured_units.add(_SECRETS_KV_FILE)
    present_units = sorted(u for u in captured_units if (new_home / u).exists())
    if not force and present_units:
        raise BackupError(
            f"refusing to overwrite existing SIGIL state {present_units} under {new_home} (a restore must not "
            f"silently overlay stale state) — pass force=True (--force) to REPLACE those units, or restore into "
            f"a fresh home. Un-captured home content (vector/cursor/config caches) is left intact regardless.")

    staged_dir = _new_staging_dir(new_home)     # the working staging home (always a Path)
    staged: Path | None = staged_dir            # cleanup handle for the finally; None once ownership transfers
    try:
        # decode + verify EVERY file against the signed manifest BEFORE writing anything (fail-closed). Each rel
        # is resolved to ONE validated target INSIDE the STAGED home, and that SAME target is what we write — so
        # the check and the write can never diverge (closing the "validate the normalised path, write the raw
        # path" class of escape).
        staged_resolved = staged_dir.resolve()
        for rel, b64 in files.items():
            target = _safe_target(staged_dir, staged_resolved, rel)
            try:
                data = base64.b64decode(b64)
            except Exception as e:  # noqa: BLE001
                raise BackupError(f"corrupt file blob {rel!r}: {e}") from e
            if sha256_hex(data) != hashes[rel]:
                raise BackupError(f"file {rel!r} does not match its signed hash (tamper)")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            # key material (the WARDEN kernel key + any *.key) must be 0600, not the process umask — a plain
            # write_bytes would otherwise leave it world-readable-by-umask (a real perms fix, not cosmetic).
            if _is_sensitive_rel(rel):
                os.chmod(target, 0o600)
        # re-seal the machine-bound secrets through the NEW vault (seals under the new TPM if provisioned) — into
        # the STAGED home, swapped into place with the rest of the tree.
        if body.get("owner_priv_b64"):
            vault.write_text_secret(staged_dir / "spine" / "keys" / "owner.priv",
                                    body["owner_priv_b64"], context=_OWNER_PRIV_CONTEXT)
        if body.get("spine_dek_b64"):
            vault.write_text_secret(staged_dir / "spine" / "keys" / "spine.dek",
                                    body["spine_dek_b64"], context=_DEK_CONTEXT)
        # re-seal the KV secret store through the NEW vault, under the SAME purpose context — so the operator's
        # own API keys are recoverable on new hardware. Lands as a top-level ``secrets.sealed`` unit in staged.
        if body.get("secrets_kv_b64"):
            vault.write_text_secret(staged_dir / _SECRETS_KV_FILE, body["secrets_kv_b64"],
                                    context=_SECRETS_KV_CONTEXT)

        # re-verify the STAGED spine's internal integrity (keyless binding + chain) — never claim a restore
        # succeeded on a corrupt ledger, and never swap an unverified home into place.
        from .spine.store import SpineStore
        ok, why = SpineStore(staged_dir / "spine" / "spine.jsonl").verify()
        if not ok:
            raise BackupError(f"restored spine failed verification ({why}) — the restore is NOT trustworthy")

        # everything verified: swap ONLY the captured units into new_home (subset capture → leave un-captured
        # home content intact), then drop the drained staging shell (its units were moved out).
        _atomic_swap_captured_units(staged_dir, new_home)
        shutil.rmtree(staged_dir, ignore_errors=True)
        staged = None
    finally:
        if staged is not None:
            shutil.rmtree(staged, ignore_errors=True)

    return {"home": str(new_home), "files": len(files), "owner_key": bool(body.get("owner_priv_b64")),
            "dek": bool(body.get("spine_dek_b64")), "secrets_kv": bool(body.get("secrets_kv_b64")),
            "warden": sum(1 for rel in files if rel.startswith("warden/")), "verified": True}
