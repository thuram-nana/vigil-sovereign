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
import errno
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterator, NoReturn

from vigil_core.sealing import SealError, seal, unseal

from .reuse import KeyPair, canonical_json, sha256_hex, sign, verify_one
from .spine.schema_guard import SchemaTooNew, refuse_newer

_MAGIC = b"SGLBK1\x00"
# schema 2 additionally records the WARDEN permission-kernel set ("warden": [rels…]); schema 3 (W7-2)
# additionally covers the config files (witness.trust.json / budgets.json / sigil.env), the memory state
# subtrees (qdrant/ + graph/) and RE-WRAPS the sealed KV secret store (secrets.sealed) portably. Older
# schemas are still read on restore (back-compat) — the file table is authenticated the same way either way.
_SCHEMA = 3
# schema 4: written ONLY for a home whose spine is HARD-PRUNED, with SIGIL_PRUNED_RESTORE on. The spine, its signed
# head, the floor and the archive are captured as one consistent, verified unit, under the normalized ``spine/archive``
# rel wherever the archive lives, and the signed manifest carries a ``prune_unit`` block a restore cross-checks against
# the staged unit. Every other backup stays schema 3, so an older build still restores it.
_PRUNED_SCHEMA = 4
_MAX_BACKUP_SCHEMA = _PRUNED_SCHEMA   # refuse-newer gate (W5-3): a backup schema above this is "upgrade sigil"
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
# Private key material under spine/keys that is NEVER packaged as a raw file: the owner key and the DEK are re-wrapped
# from plaintext (above); a staged successor owner key (a rotation in progress) is never backed up at all.
_RAW_KEY_RELS = ("spine/keys/owner.priv", "spine/keys/spine.dek", "spine/keys/owner.next.priv")
_STAGED_ROTATION_MARKER = "spine/keys/owner.next.pub"
# A consistent capture of a pruned unit is retried this many times when the spine changed under it (a concurrent
# `sigil sign` writes the head and the floor outside the writer lock), backing off this long times the attempt.
_CAPTURE_ATTEMPTS = 5
_CAPTURE_BACKOFF_S = 0.2
# The roll-forward journal of a restore that swaps a hard-pruned unit in, or that replaces an interrupted restore:
# written (atomically, durably) BEFORE the first swap and removed after the last, so a restore interrupted between its
# swaps is resumed (or, before any swap, aborted) instead of leaving a home whose units come from two different points
# in time.
_JOURNAL_NAME = "restore-journal.json"
_JOURNAL_SCHEMA = 1
# Test-only fault-injection hook at the journaled swap's barriers (mirrors ``spine.store._crash_hook``). Production
# ships it as None; it cannot be armed from the environment.
_crash_hook: Any = None


def _maybe_crash(name: str) -> None:
    if _crash_hook is not None:
        _crash_hook(name)
# Top-level CONFIG files (not key material) packaged verbatim into the sealed body. floor.json /
# security.manifest.json were already covered; W7-2 adds the HA witness roster (the failover guard depends on
# it), the governor budget caps, and the persisted env file. ``sigil.env`` can hold a signing secret (e.g.
# VIGIL_DESTRUCTION_OWNER_KEY) so it is 0600 on restore (see :func:`_is_sensitive_rel`).
_CONFIG_FILES = ("floor.json", "security.manifest.json", "witness.trust.json", "budgets.json", "sigil.env",
                 # #70: the per-unit EnvironmentFiles the shipped sovereign systemd units read from SIGIL_HOME
                 # (apps/sigil/deploy/systemd) — operator config a FUNCTIONAL recovery needs; may hold secrets,
                 # so restored 0600 (see _is_sensitive_rel).
                 "bridge.env", "cockpit.env", "customer.env", "public.env")
# Top-level memory-STATE subtrees packaged verbatim (raw bytes, locks skipped): the Qdrant vector store and
# the Kùzu graph mirror. They are derivable from the spine by a re-index, but a DR restore captures them so a
# recovered install is immediately searchable (bounds RTO) rather than needing a costly re-embed/rebuild.
_STATE_DIRS = ("qdrant", "graph",
               # PRICING M1c: the model gateway's per-launch meters — MONEY data (an unsettled run's charge is
               # computed from its meter), hash-chained, packaged verbatim so a restored install settles it.
               "model_meter",
               # legal/governance S1: the customer-entered General profile (ui/preferences_store.py — legal entity,
               # registered address, contractual + emergency contacts). The customer typed it and NOTHING regenerates
               # it, so a restore must bring it back; it is contact data, so it is restored owner-only
               # (see _PRIVATE_STATE_DIRS).
               "customer_preferences")
# State subtrees whose files hold personal data: restored 0600 in a 0700 directory, as their store writes them.
_PRIVATE_STATE_DIRS = ("customer_preferences",)
# State subtrees a live process writes by temp-file-then-rename (spine.atomicio.atomic_write_text) while a backup may
# be running — the customer profile is saved from the cockpit, the very process that also serves the in-browser backup.
# An atomic write's temp file (spine.consistent_copy.transient) is never state: it exists only while that save is in
# flight, so it is never captured; and a file of such a unit that is gone by the time it is read (renamed over or
# removed since the listing) is simply not in this backup — never a crash that fails the whole backup.
_ATOMIC_STATE_DIRS = ("customer_preferences",)

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
    "model_meter",              # PRICING M1c: per-launch model-gateway meters (money data)
    "customer_preferences",     # legal/governance S1: the customer-entered General profile (0600/0700 on restore)
    "bridge.env",               # #70: shipped unit EnvironmentFiles (operator config; 0600 on restore)
    "cockpit.env",
    "customer.env",
    "public.env",
})
# Deliberate exclusions, each with a reason the structural test surfaces. Keeping the REASONS in code is what
# makes this a *documented* exclusion list (acceptance criterion), not a silent skip.
_EXCLUSION_REASONS: dict[str, str] = {
    "vault": "machine-bound TPM-sealed KEK — useless off-box; re-provisioned on the new host (the secrets it "
             "wraps are re-wrapped into the sealed backup body instead)",
    "backups": "the backup OUTPUT directory itself — packaging it would recurse prior backups into new ones",
    "restore-journal.json": "the roll-forward journal of a restore into this home that was interrupted between its "
                            "swaps (`sigil restore --resume`) — in-progress restore state, never recovery state",
    "alarms": "point-in-time operator alarms about the CURRENT seam (e.g. an eval-capability grant revoke that could "
              "not be confirmed). Not restored: an offense restore leaves the eval publications out (ungranted), "
              "and the next offense close re-checks every published grant from the spine whether or not the alarm "
              "exists, re-raising it if a publication still cannot be confirmed",
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
    "customer": "ephemeral customer-edge operational markers (cookie sessions + single-use email "
                "verify/recover tokens + login/signup/member rate-limit lockouts + the onboarding tour's "
                "finished/skipped marks + the app's copies of launches reserved and not started yet) — the "
                "AUTHORITATIVE customer accounts/orgs/memberships/wallet/reservations are owner-signed on the spine "
                "(captured); these regenerate (re-login / re-request / limits reset / the tour shows once more), "
                "never recovery state (a lost launch copy leaves its reservation on the spine: a later launch of the "
                "same host supersedes it and `ops-sweep reservations` releases it). The settings shell's General "
                "profile is NOT here: the customer typed it and nothing regenerates it, so it is its own top-level "
                "`customer_preferences`, captured",
    "customer_authorization_requests": "legal/governance S12: the UNSIGNED owner-review requests a customer drops from "
                                       "the read-only Authorizations surface (\"please authorize host X\"). An "
                                       "operational owner-review queue, not an authority and not money — it mints "
                                       "nothing and is never owner-signed. EXCLUDED: a restore drops any pending "
                                       "request and the customer re-requests; the AUTHORITATIVE owner-signed "
                                       "EngagementAuthorities live on the authority seam (the offense leg's to "
                                       "capture), and the settings General profile (customer-typed, nothing "
                                       "regenerates it) is the one captured customer_* top-level — this queue is not it",
    "cve": "re-ingestable public CVE catalog cache (CISA-KEV/NVD/OSV/EPSS), rebuilt by `sigil cve ingest` — "
           "public data, no trust or memory state",
    "venv": "the re-installable sovereign Python venv the shipped units run from (rebuilt by bootstrap / "
            "envs/build_envs.sh) — code + third-party packages, no trust or memory state",
    "checkpoint.witnessed.json": "the witnessed-checkpoint OUTPUT `sigil-checkpoint` re-emits every cadence "
                                 "from the (captured) spine; the authoritative copies are the witnesses' — "
                                 "re-derived, never recovery state",
    "vigil-tool-state.tsv": "the offense tool install-state table bootstrap re-derives (`--state-path`) — "
                            "installer bookkeeping, no trust or memory state",
    "fold_cache_audit.json": "the cockpit's last fold-cache rebuild-and-compare report (Front C S0d) — a "
                             "re-derived verdict over the (captured) spine, rewritten every audit interval; "
                             "no trust or memory state",
    "fold_cache_audit.ack.jsonl": "the operator's acknowledgements (who, when, which verdict) of a superseded "
                                  "MISMATCH in that fold-cache audit report (`sigil fold-cache ack`). It only "
                                  "qualifies that report, which is not captured either: a restored install starts "
                                  "with neither the note nor its acknowledgements (each is also logged when made)",
    # #70 — the two SaaS money/delivery dirs the shipped units default under SIGIL_HOME. Both DELIBERATELY
    # excluded from THIS (sovereign) leg; the decision is recorded here so the coverage gate stays honest.
    "credit-lease": "the CROSS-PLANE launch seam = the shared VIGIL_BASE_DIR both planes agree on (leases, "
                    "settlement + pause markers, AND the offense engine's own keys / floor / job queue). It is "
                    "the OFFENSE leg's to capture (`vigil backup --base-dir` = that dir); the sovereign process "
                    "must never package it (FATAL-2: it would carry offense private keys), and two legs "
                    "restoring the same tree from different instants would clobber newer settlement markers",
    "billing-spool": "the money-IN billing-webhook spool at the GO-LIVE runbook path ($SIGIL_HOME/billing-spool, "
                     "the vigil-billing-drain default) — EXCLUDED for the same reason as `spool`: pending signals "
                     "whose non-atomic capture could tear exactly-once; losing them fails SAFE (re-deliverable / "
                     "reconcilable from the processor)",
    "stripe-billing-spool": "the Stripe lane's money-IN webhook spool (the vigil-billing-drain-stripe default) — "
                            "EXCLUDED for the same reason as `billing-spool`: pending signals; losing them fails SAFE "
                            "(Stripe redelivers, and the re-fetch makes a re-ingest idempotent)",
    "spool": "settle / finding / billing spools of PENDING signals. A capture that is not point-in-time "
             "consistent with the spine can tear exactly-once (a settle landing between the spine read and the "
             "spool read => a lost refund; the reverse => a double grant). Losing pending signals fails SAFE: "
             "credits stay HELD (recover via `ops-sweep reservations`) and payments are re-deliverable / "
             "reconcilable from the processor — a consistent money-state capture is a tracked design item",
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
    hold a signing secret such as VIGIL_DESTRUCTION_OWNER_KEY), PLUS every file of a :data:`_PRIVATE_STATE_DIRS`
    subtree (personal data — a customer's contact details), whose directories are restored 0700 as well. The whole
    backup body is AEAD-sealed at rest regardless; this closes the post-restore on-disk perms of the sensitive
    material itself."""
    if rel.endswith(".key") or rel == "sigil.env" or _is_private_state_rel(rel):
        return True
    # #70: the unit EnvironmentFiles (may hold secrets) are owner-only on restore too.
    return "/" not in rel and rel.endswith(".env")


def _is_private_state_rel(rel: str) -> bool:
    """True iff ``rel`` is a file inside a :data:`_PRIVATE_STATE_DIRS` subtree (restored 0600, its directories 0700).
    A ``\\`` counts as the separator it is to :func:`_safe_target`."""
    top, sep, _rest = rel.replace("\\", "/").partition("/")
    return bool(sep) and top in _PRIVATE_STATE_DIRS


def _spine_files(home: Path, *, archive: "Path | None" = None) -> list[tuple[Path, str]]:
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
    it 0600 (see :func:`_is_sensitive_rel`).

    ``archive`` (a hard-pruned unit, see :func:`_capture_pruned_unit`): the effective archive dir. Its files are
    packaged under the normalized ``spine/archive/`` rel wherever it lives (never an absolute path), the default
    ``spine/archive`` dir and the archive dir itself are left out of the spine walk (so the rels never collide), and
    so are the read-index sidecars and atomic-write temp files a concurrent reader or writer leaves."""
    out: list[tuple[Path, str]] = []
    spine = home / "spine"
    skip_dirs = []
    from .spine.consistent_copy import transient
    if archive is not None:
        skip_dirs = [(spine / "archive").resolve(), archive.resolve()]
    if spine.is_dir():
        for p in sorted(spine.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(home).as_posix()
            if rel.endswith((".lock",)) or rel in _RAW_KEY_RELS:
                continue
            if archive is not None and (transient(p.name)
                                        or any(p.resolve().is_relative_to(d) for d in skip_dirs)):
                continue
            out.append((p, rel))
    if archive is not None and archive.resolve().is_dir():
        root = archive.resolve()
        for p in sorted(root.rglob("*")):
            if p.is_symlink() or not p.is_file() or transient(p.name):
                continue
            out.append((p, "spine/archive/" + p.relative_to(root).as_posix()))
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
                if state in _ATOMIC_STATE_DIRS and transient(p.name):    # a save in flight: never state
                    continue
                out.append((p, p.relative_to(home).as_posix()))
    return out


def _read_listed(f: Path, rel: str) -> "bytes | None":
    """The bytes of a file :func:`_spine_files` listed — or ``None`` for a file of an :data:`_ATOMIC_STATE_DIRS` unit
    that is gone by the time it is read (a live save renamed over it or removed it since the listing): it is not in
    this backup. Any other file that cannot be read fails the backup, as before."""
    try:
        return f.read_bytes()
    except FileNotFoundError:
        if rel.partition("/")[0] in _ATOMIC_STATE_DIRS:
            return None
        raise


def _pruned_unit_digest(home: Path, archive: Path) -> str:
    """The content digest of a pruned unit: the spine dir, the floor and the archive (transients excluded)."""
    from .spine.consistent_copy import unit_digest
    return "|".join(unit_digest(p) for p in (home / "spine", home / "floor.json", archive.resolve()))


def _in_pruned_unit(rel: str) -> bool:
    """Whether a captured rel belongs to the pruned unit itself: the spine dir (its archive is captured under the
    normalized ``spine/archive`` rel) or the floor."""
    return rel.startswith("spine/") or rel == "floor.json"


def _verify_captured_unit(raw: "dict[str, bytes]", work_parent: Path) -> dict:
    """Verify the CAPTURED bytes of a pruned unit with the real readers: written to a private scratch home (public
    keys only — the private ones are never captured as files) under ``work_parent`` and verified in a child scoped
    to it (:func:`~sigil.spine.home_unit.verify_unit_isolated`, the archive re-derived in full). Returns its report."""
    from .spine.home_unit import HomeUnit, verify_unit_isolated
    root = Path(tempfile.mkdtemp(prefix=".sigil-backup-verify-", dir=str(work_parent)))
    try:
        unit_home = root / "unit"
        for rel, data in raw.items():
            if _in_pruned_unit(rel):
                p = unit_home / PurePosixPath(rel)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
        return verify_unit_isolated(HomeUnit.for_home(unit_home), work_dir=root / "work", require_archive=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _capture_pruned_unit(home: Path, work_parent: Path) -> "tuple[list[tuple[Path, str]], dict[str, bytes], dict]":
    """Capture a HARD-PRUNED home as one consistent, verified unit: ``(files, bytes by rel, prune_unit)``.

    The home must be this process's own SIGIL_HOME (the archive it uses is this process's effective one). Under a
    SHARED flock on the spine's writer lockfile the unit (spine dir, floor, effective archive dir) is digested, read
    and digested again — nothing else is done under that lock, so appenders wait only for the read: a capture whose
    digests differ raced a writer outside that lock and is retried; one that never settles is refused. The rest of
    the home is read after the lock is released, and the captured unit bytes are then VERIFIED with the real readers
    (chain, signed head, succession tip, snapshot seed, a seeded read, the whole archive re-derived) in a child scoped
    to a scratch copy of them under ``work_parent`` (:func:`_verify_captured_unit`). A unit that does not verify is
    refused — a backup that cannot be restored is no safety net."""
    import time

    from . import config
    from .spine.consistent_copy import shared_writer_lock
    from .spine.home_unit import failure_reason
    from .spine.prune import archive_dir as effective_archive_dir
    if home.resolve() != config.SIGIL_HOME.resolve():
        raise BackupError(f"{home} holds a hard-pruned spine and is not this process's home — its head, floor and "
                          f"archive are read with this process's paths; run the backup with SIGIL_HOME={home}")
    eff = effective_archive_dir()
    relocated = eff.resolve() != (home / "spine" / "archive").resolve()
    for attempt in range(_CAPTURE_ATTEMPTS):
        with shared_writer_lock(home / "spine", "spine.jsonl"):
            before = _pruned_unit_digest(home, eff)
            files = _spine_files(home, archive=eff)
            raw = {rel: f.read_bytes() for f, rel in files if _in_pruned_unit(rel)}
            after = _pruned_unit_digest(home, eff)
        if before == after:
            break
        time.sleep(_CAPTURE_BACKOFF_S * (attempt + 1))
    else:
        raise BackupError("the spine kept changing during the backup (a concurrent sign or prune) — retry when it is "
                          "idle")
    for f, rel in files:
        if rel not in raw:
            data = _read_listed(f, rel)
            if data is not None:
                raw[rel] = data
    files = [(f, rel) for f, rel in files if rel in raw]      # a listed file gone before its read is not captured
    rep = _verify_captured_unit(raw, work_parent)
    if not rep.get("ok") or not rep.get("pruned"):
        why = failure_reason(rep)
        failed = next((c.get("name") for c in rep.get("checks") or [] if not c.get("ok")), "")
        hint = (f" — the backup must see the same SIGIL_SPINE_ARCHIVE_DIR as the services (it read {eff})"
                if "archive" in why else
                " — if a `sigil key rotate` was interrupted before it re-signed the head, finish it with "
                "`sigil key rotate --finish --yes` first" if failed in ("chain", "signed_head") else "")
        raise BackupError(f"the hard-pruned spine does not verify as one unit ({why}){hint}; a backup that "
                          f"cannot be restored is refused")
    sh = rep["shape"]
    stale = relocated and any(p.is_file() for p in (home / "spine" / "archive").rglob("*"))
    prune_unit = {
        "schema": 1, "base_seq": sh["base_seq"], "snapshot_seq": sh["snapshot_seq"],
        "last_seq": sh["last_seq"], "entry_count": sh["entry_count"], "head_sig_hash": sh["head_sig_hash"],
        "floor_head_sig_hash": sh["floor_head_sig_hash"],
        "cumulative_merkle_root": sh["cumulative_merkle_root"],
        "archive": {"rel": "spine/archive", "source": "relocated" if relocated else "default",
                    "source_dir": str(eff), "segments": sh["archive_segments"],
                    "stale_default_skipped": stale},
        "succession_tip": sh["succession_tip"], "verified_at_capture": True,
    }
    return files, raw, prune_unit


def _captures_pruned_unit(home: Path) -> bool:
    """True iff this backup captures ``home`` as a hard-pruned unit (SIGIL_PRUNED_RESTORE on, and the spine pruned —
    its live window starts above seq 0 or its head commits a prune)."""
    from . import config
    if not config.pruned_restore_enabled():
        return False
    from .spine.home_unit import HomeUnit, unit_shape
    return unit_shape(HomeUnit.for_home(home), require_archive=False).pruned


def create_backup(dest: str | Path, passphrase: str, *, home: Path, vault: Any, owner_key: KeyPair) -> dict:
    """Write a portable, signed, passphrase-encrypted backup of ``home``'s trust root + spine to ``dest``.

    ``vault`` reads the (possibly TPM-sealed) owner private key + spine DEK + sealed KV secret store as
    plaintext to re-wrap them into the encrypted backup; ``owner_key`` signs the file manifest. Returns a
    summary. With SIGIL_PRUNED_RESTORE on, a HARD-PRUNED home is captured as one consistent, verified unit
    (:func:`_capture_pruned_unit`, manifest schema 4 with ``prune_unit``); every other home exactly as before."""
    home = Path(home)
    dest = Path(dest)
    if (home / _STAGED_ROTATION_MARKER).exists():
        raise BackupError("an owner-key rotation is staged in this home — finish it with `sigil key rotate --finish "
                          "--yes` before taking a backup")
    raw_by_rel: "dict[str, bytes] | None" = None
    prune_unit: "dict | None" = None
    if _captures_pruned_unit(home):
        dest.parent.mkdir(parents=True, exist_ok=True)        # the captured unit is verified in scratch beside it
        files, raw_by_rel, prune_unit = _capture_pruned_unit(home, dest.parent)
    else:
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
        raw = _read_listed(f, rel) if raw_by_rel is None else raw_by_rel[rel]
        if raw is None:                                 # gone since the listing (see _read_listed): not captured
            continue
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
    if prune_unit is not None:
        manifest["schema"] = _PRUNED_SCHEMA
        manifest["prune_unit"] = prune_unit
    manifest_sig = sign(owner_key.private_key_b64, canonical_json(manifest))

    body = {
        "manifest": manifest, "manifest_sig": manifest_sig, "manifest_pubkey": owner_key.public_key_b64,
        "files": file_blobs, "owner_priv_b64": owner_priv, "spine_dek_b64": dek, "secrets_kv_b64": secrets_kv,
    }
    salt = os.urandom(_SALT_LEN)
    sealed = seal(_derive_key(passphrase, salt), canonical_json(body), context=_BODY_CONTEXT)

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # 0600 before the secrets land
    try:
        os.write(fd, _MAGIC + salt + sealed)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(dest))
    out = {"dest": str(dest), "files": len(file_blobs), "owner_key": owner_priv is not None,
           "dek": dek is not None, "secrets_kv": secrets_kv is not None, "warden": len(warden_rels),
           "bytes": len(sealed)}
    if prune_unit is not None:
        out["prune_unit"] = prune_unit
    return out


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


# Whether this platform lists its mounts in /proc/self/mountinfo (Linux, Android). The mount points under a path, and
# the mount a path is on, are then read from the kernel: a bind mount of the same filesystem included, which neither
# os.path.ismount nor a device number tells apart (it has its parent's device), yet no rename crosses it and rmtree
# descends into it. Elsewhere they are read off the filesystem: a mount point by its device, as os.path.ismount does.
_PROC_MOUNTS = sys.platform.startswith("linux") or sys.platform == "android"
_MOUNTINFO = "/proc/self/mountinfo"


def _read_mountinfo() -> bytes:
    return Path(_MOUNTINFO).read_bytes()


def _mount_points() -> "list[Path]":
    """Every mount point of this process's mount namespace, as the kernel lists it (octal escapes undone). An OSError
    when the list cannot be read whole: a caller that cannot see the mounts refuses."""
    points = []
    for line in _read_mountinfo().splitlines():
        fields = line.split(b" ")
        if len(fields) < 5 or not fields[4].startswith(b"/"):
            raise OSError(f"{_MOUNTINFO} holds a line this build cannot read: {line[:200]!r}")
        points.append(Path(os.fsdecode(re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]),
                                              fields[4]))))
    if not points:
        raise OSError(f"{_MOUNTINFO} lists no mount")
    return points


def _mount_of(p: Path) -> int:
    """The mount ``p`` is on — that of its nearest existing ancestor while it does not exist yet (it is made there).
    A rename never crosses two mounts, even two of one filesystem (a bind mount): where the kernel lists its mounts
    this is its mount ID, read off an O_PATH descriptor of ``p`` (symlinks followed, as a rename into ``p`` follows
    them); elsewhere the filesystem's device."""
    p = Path(p).absolute()
    for a in (p, *p.parents):
        try:
            if not _PROC_MOUNTS:
                return os.stat(a).st_dev
            fd = os.open(a, os.O_PATH)
        except (FileNotFoundError, NotADirectoryError):
            continue
        try:
            info = Path(f"/proc/self/fdinfo/{fd}").read_text()
        finally:
            os.close(fd)
        for line in info.splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "mnt_id":
                return int(value)
        raise OSError(f"the kernel names no mount for {a} (no mnt_id in /proc/self/fdinfo)")
    raise FileNotFoundError(f"no existing ancestor of {p}")


def _mount_at_or_in(p: Path) -> "Path | None":
    """A mount point at the entry ``p``, or anywhere inside it when it is a real dir; else None. A symlink at ``p`` is
    never followed (a restore renames or drops the entry, never what it points to). Where the kernel lists its mounts,
    read from that list (a bind mount of the same filesystem included); elsewhere by device, walking the dir (a dir
    that cannot be listed raises)."""
    p = Path(p)
    if p.is_symlink() or not p.exists():
        return None
    if _PROC_MOUNTS:
        real = p.resolve()
        for mp in _mount_points():
            if mp == real or real in mp.parents:
                return mp
        return None
    if os.path.ismount(p):
        return p
    if not p.is_dir():
        return None

    def refuse(e: OSError) -> None:
        raise e
    for root, dirs, _files in os.walk(p, onerror=refuse):
        for d in dirs:
            if os.path.ismount(os.path.join(root, d)):
                return Path(root) / d
    return None


def _refuse_unrenamable(renames: "list[tuple[Path, Path]]") -> None:
    """Refuse, before anything of the home is touched, a swap the filesystem cannot do — so no restore begins a swap
    whose renames are bound to fail, and none drops what is mounted inside a home. ``renames`` pairs the dir each
    staged unit is renamed from with the entry it replaces. Each staged unit must be on the MOUNT of the dir it is
    renamed into (a home, or an archive dir, that is a mount point — a bind mount of the same filesystem included —
    has its staging beside it on another mount, and no rename crosses two mounts). No entry the swap replaces may be,
    or hold, a mount point, and neither may the old copy an earlier restore left beside it (a restore renames whole
    units aside and drops them, and drops such a leftover before its swap; it never renames or drops a mount point)."""
    try:
        for staging, dst in renames:
            if _mount_of(staging) != _mount_of(dst.parent):
                raise BackupError(f"refusing to restore into {dst.parent}: it is not on the mount of the restore's "
                                  f"staging dir {staging} beside it — a restore renames each unit into place, and no "
                                  f"rename crosses two mounts (a bind mount of one filesystem included), so the home "
                                  f"(and an archive dir) must be a dir on its parent's mount, not a mount point itself "
                                  f"(mount the volume one level up, or name a dir inside it); nothing was written")
            mount = _mount_at_or_in(dst)
            if mount is not None:
                raise BackupError(f"refusing to replace {dst}: {mount} is a mount point — a restore renames whole "
                                  f"units aside and drops them, and never a mount point with one (unmount it, or pass "
                                  f"a dir on that volume, mounted outside the home, as --archive-dir); nothing was "
                                  f"written")
            aside = _aside_of(dst)
            mount = _mount_at_or_in(aside)
            if mount is not None:
                raise BackupError(f"refusing to restore over {aside}, the old copy of {dst.name!r} an earlier restore "
                                  f"left beside it: {mount} is a mount point — a restore drops that leftover before "
                                  f"its swap, and never a mount point with it (unmount it, then remove {aside}); "
                                  f"nothing was written")
    except OSError as e:
        raise BackupError(f"cannot check that the restore's renames stay on one mount ({e}) — nothing was "
                          f"written") from e


def _drop_path(p: Path) -> None:
    """Best-effort remove ``p`` whether it is a dir, a file, or a (possibly broken) symlink — but never a dir that is
    or holds a mount point (what is mounted there is not the restore's to drop; nor one whose mounts cannot be read):
    that is left in place, as is anything that cannot be removed. A caller for which it matters checks."""
    if p.is_dir() and not p.is_symlink():
        try:
            if _mount_at_or_in(p) is not None:
                return
        except OSError:
            return
        shutil.rmtree(p, ignore_errors=True)
    elif p.exists() or p.is_symlink():
        try:
            p.unlink()
        except OSError:
            pass


def _aside_of(dest_unit: Path) -> Path:
    """Where a swap moves the OLD copy of ``dest_unit`` until the new one is in place."""
    return dest_unit.parent / (".restore-old-" + dest_unit.name)


class _AsideInTheWay(FileExistsError):
    """A swap stopped BEFORE its first rename: an entry stands at the aside of its destination. Nothing of the unit
    moved."""


def _swap_in(staged_unit: Path, dest_unit: Path, moved: "list[Path] | None" = None) -> "Path | None":
    """Move the old ``dest_unit`` aside and rename ``staged_unit`` into its place (each rename atomic, same
    filesystem). The old copy is NOT dropped: returns the aside that holds it (None for a fresh slot), so a journaled
    caller can record the new unit as in place before the old one goes. An entry already at the aside is never dropped
    nor renamed over — it may be the only old copy of the unit, moved there by an earlier attempt — and stops the swap
    before its first rename (:class:`_AsideInTheWay`); a caller that has proven it a leftover removes it first.
    ``moved`` collects what this call moved and did not move back (the aside, while the old unit stays there): it is
    empty whenever the call stopped with nothing of the unit moved."""
    moved = [] if moved is None else moved
    dest_unit.parent.mkdir(parents=True, exist_ok=True)
    if dest_unit.exists() or dest_unit.is_symlink():
        aside = _aside_of(dest_unit)
        if aside.exists() or aside.is_symlink():
            raise _AsideInTheWay(errno.EEXIST, "an entry holds the aside", str(aside))
        os.replace(str(dest_unit), str(aside))            # atomic: dest_unit → aside
        moved.append(aside)
        _maybe_crash(f"restore_moved_aside:{dest_unit.name}")
        try:
            os.replace(str(staged_unit), str(dest_unit))  # atomic: staged unit → dest_unit
        except OSError:
            _maybe_crash(f"restore_rolling_back:{dest_unit.name}")
            os.replace(str(aside), str(dest_unit))        # best-effort rollback
            moved.remove(aside)
            raise
        return aside
    os.replace(str(staged_unit), str(dest_unit))          # atomic into a fresh slot
    return None


def _atomic_swap_unit(staged_unit: Path, dest_unit: Path) -> None:
    """Atomically replace ONE captured unit (a FILE or a whole SUBTREE) at ``dest_unit`` with ``staged_unit``,
    leaving every SIBLING under ``dest_unit.parent`` UNTOUCHED. Move-aside → rename-in → drop-old (each rename
    atomic, same filesystem), so a crash leaves ``dest_unit`` as the complete OLD unit, absent, or the complete
    NEW unit — never torn. A leftover at the aside stops it before its first rename (:class:`_AsideInTheWay`)."""
    aside = _swap_in(staged_unit, dest_unit)
    if aside is not None:
        _drop_path(aside)                                 # drop the old unit


def _swap_units(units: "list[tuple[Path, Path]]") -> None:
    """Swap each ``(staged unit, destination)`` pair in order, each atomically (:func:`_atomic_swap_unit`). The list is
    a WHITELIST — exactly the units the backup captured — so nothing else that turns up in the staging dir (a
    reader's lockfile, a stray entry) ever reaches the target, and every top-level entry already under the target
    that the backup did NOT capture (cache/models/agent journals, other SIGIL_HOME state) is left untouched: a
    ``--force`` restore can NEVER delete live, un-captured home content. Units are swapped sequentially, each atomic.
    Only a restore into a home that holds none of the captured units swaps this way (a crash leaves each unit complete
    or absent, nothing old to lose); one that replaces an existing unit is journaled (:func:`_complete_journaled_swap`)."""
    for staged_unit, dest_unit in units:
        _atomic_swap_unit(staged_unit, dest_unit)


def _captured_swap_list(staged: Path, dest: Path, captured_units: "set[str]") -> "list[tuple[Path, Path]]":
    """The whitelist swap for the captured top-level units present in ``staged``, ``spine`` and ``floor.json`` first
    (the spine unit before the floor that records its head), then the rest sorted."""
    order = sorted(captured_units, key=lambda u: ({"spine": 0, "floor.json": 1}.get(u, 2), u))
    return [(staged / u, dest / u) for u in order if (staged / u).exists() or (staged / u).is_symlink()]


def _backup_declares_prune(files: dict, hashes: dict, manifest: dict) -> bool:
    """Whether the authenticated file table holds a HARD-PRUNED spine, read from the signed bytes BEFORE anything is
    written: a ``prune_unit`` block (schema 4), a head that commits a prune, or a segment manifest whose live window
    starts above seq 0 (a backup taken without the unit capture)."""
    if manifest.get("prune_unit") is not None:
        return True

    def blob(rel: str) -> "bytes | None":
        b64 = files.get(rel)
        try:
            data = base64.b64decode(b64) if isinstance(b64, str) else None
        except Exception:  # noqa: BLE001 — a corrupt blob is refused by the per-file check later
            return None
        return data if data is not None and sha256_hex(data) == hashes.get(rel) else None

    try:
        head = json.loads(blob("spine/head.json") or b"{}")
        if isinstance(head, dict) and int(head.get("snapshot_seq", -1)) >= 0:
            return True
    except (ValueError, TypeError):
        pass
    try:
        segs = json.loads(blob("spine/spine.manifest.json") or b"{}").get("segments") or []
        if segs and min(int(seg.get("first_seq", 0)) for seg in segs) > 0:
            return True
    except (ValueError, TypeError, AttributeError):
        pass
    return False


def _overlaps(a: Path, b: Path) -> bool:
    """Whether ``a`` (as given: an entry is compared as itself, never followed) and the real dir ``b`` names are one
    and the same, or one holds the other."""
    b = b.resolve()
    return a == b or a in b.parents or b in a.parents


def _check_archive_target(target: Path, new_home: Path, staged: Path, captured_units: "set[str]") -> None:
    """Refuse an explicit archive dir that would land on (or around) another unit: the restored home itself or a dir
    holding it, any entry of the restored home outside its spine (a captured unit, or live state the backup does not
    capture), the staging dir — and, when restoring into a home that is NOT this process's own, this process's
    SIGIL_HOME or the archive dir its own environment names (on a drill / DR host that is the LIVE archive). Both the
    entry the restore replaces and the dir a symlink at it points to are held to this."""
    from . import config
    from .spine.prune import archive_dir as live_archive_dir
    if Path(target).absolute().name == "..":                   # the swap replaces an entry: it must name one
        raise BackupError(f"refusing the archive dir {target}: it ends in '..', which names no entry a restore can "
                          f"replace — name the archive's dir itself")
    nh = new_home.resolve()
    for t in dict.fromkeys((target.resolve(), _entry_path(target.absolute()))):
        if t == nh or t in nh.parents:
            raise BackupError(f"refusing the archive dir {target}: it is (or contains) the restored home {new_home}")
        if t == (nh / "spine"):
            raise BackupError(f"refusing the archive dir {target}: it is the restored spine dir itself")
        if t.is_relative_to(nh) and not t.is_relative_to(nh / "spine"):
            u = t.relative_to(nh).parts[0]
            what = (f"the restored unit {u!r}" if u in captured_units else
                    f"{u!r}, live state of the restored home that the backup does not capture")
            raise BackupError(f"refusing the archive dir {target}: it overlaps {what} — an archive inside the home "
                              f"goes under its spine dir")
        if _overlaps(t, staged):
            raise BackupError(f"refusing the archive dir {target}: it overlaps the restore's staging dir")
        if nh != config.SIGIL_HOME.resolve():
            if _overlaps(t, config.SIGIL_HOME):
                raise BackupError(f"refusing the archive dir {target}: it overlaps this process's own SIGIL_HOME "
                                  f"({config.SIGIL_HOME}), which this restore does not target")
            if _overlaps(t, live_archive_dir()):
                raise BackupError(f"refusing the archive dir {target}: it overlaps the archive dir this process's "
                                  f"own home uses ({live_archive_dir()}), which this restore does not target")


def _replaceable_archive_dir(target: Path) -> bool:
    """Whether a restore may replace what is at ``target`` with the backup's archive: an archive (its manifest is
    there) or an empty dir — never anything else, whatever ``--force`` says."""
    try:
        return target.is_dir() and ((target / "archive.manifest.json").is_file() or not any(target.iterdir()))
    except OSError:
        return False


def _place_staged_archive(staged: Path, new_home: "Path | None", archive_dir: "Path | None", *, force: bool,
                          verify_only: bool, captured_units: "set[str]") -> dict:
    """Where the restored archive goes, and where the verifier reads it. The backup's archive is staged at
    ``<staging>/spine/archive``. The target is ``archive_dir`` when given, else ``<new_home>/spine/archive`` — NEVER
    the restoring process's ``SIGIL_SPINE_ARCHIVE_DIR``. A target inside the restored spine unit
    (:func:`_in_spine_unit`: decided on the entries the swaps replace, whatever a symlink there points to) travels with
    the spine unit; one outside it is its own unit, staged in a private dir beside the target (same filesystem, so its
    swap is an atomic rename). A backup that carries no archive (taken before the archive was captured) adopts the
    archive already at ``archive_dir`` — only if it verifies against the staged head, and it is never replaced.
    Returns ``{read, target, unit, cleanup, mode}``."""
    staged_arch = staged / "spine" / "archive"
    carried = staged_arch.is_dir()
    out = _place_archive(staged, staged_arch, carried, new_home, archive_dir, force=force, verify_only=verify_only,
                         captured_units=captured_units)
    out["carried"] = carried
    return out


def _in_spine_unit(target: Path, new_home: Path) -> "Path | None":
    """Where ``target`` lies inside the restored home's spine unit (relative to it), or None when it lies outside.
    Decided on the ENTRIES the swaps replace, never on where a symlink points: the spine unit's swap replaces the entry
    ``<home>/spine`` with the staged spine dir, so a path named through that entry (whatever the entry is now: a dir, or
    a symlink) — or an entry whose real parent lies inside the spine dir — is carried by that swap, and lands inside
    the restored spine. A symlink at such a path leaves with the old spine; the dir it points to is never touched."""
    spine_entry = _entry_path(new_home / "spine")
    t = Path(target).absolute()
    if ".." not in t.parts:
        for a in (t, *t.parents):
            if a.name == "spine" and _entry_path(a) == spine_entry:
                return t.relative_to(a)
    e = _entry_path(t)
    return e.relative_to(spine_entry) if e.is_relative_to(spine_entry) else None


def _place_archive(staged: Path, staged_arch: Path, carried: bool, new_home: "Path | None",
                   archive_dir: "Path | None", *, force: bool, verify_only: bool,
                   captured_units: "set[str]") -> dict:
    if new_home is None:                                     # verify-only with no target home: verify in place
        if archive_dir is not None and not carried:
            return {"read": Path(archive_dir), "target": Path(archive_dir), "unit": None, "cleanup": None,
                    "mode": "adopt"}
        return {"read": staged_arch, "target": staged_arch, "unit": None, "cleanup": None, "mode": "staged"}
    spine_new = new_home / "spine"
    target = Path(archive_dir) if archive_dir is not None else spine_new / "archive"
    if archive_dir is not None:
        _check_archive_target(target, new_home, staged, captured_units)
    rel = _in_spine_unit(target, new_home)
    if rel is not None:                                      # inside the spine unit: swapped with it
        in_stage = staged / "spine" / rel
        if carried and in_stage != staged_arch:
            in_stage.parent.mkdir(parents=True, exist_ok=True)
            os.replace(str(staged_arch), str(in_stage))
        return {"read": in_stage, "target": target, "unit": None, "cleanup": None, "mode": "in-spine"}
    if not carried:
        return {"read": target, "target": target, "unit": None, "cleanup": None, "mode": "adopt"}
    if (target.exists() or target.is_symlink()) and not force:
        raise BackupError(f"refusing to overwrite the existing archive at {target} — pass force=True (--force) to "
                          f"replace it with the backup's archive")
    if (target.exists() or target.is_symlink()) and not _replaceable_archive_dir(target):
        raise BackupError(f"refusing to replace {target}: it is not empty and holds no archive (no "
                          f"archive.manifest.json) — --archive-dir names the archive's own dir, or a new or empty one")
    if verify_only:
        return {"read": staged_arch, "target": target, "unit": None, "cleanup": None, "mode": "relocated"}
    target.parent.mkdir(parents=True, exist_ok=True)
    arch_stage = Path(tempfile.mkdtemp(prefix=".restore-staging-archive-", dir=str(target.parent)))
    shutil.move(str(staged_arch), str(arch_stage / "archive"))
    return {"read": arch_stage / "archive", "target": target, "unit": (arch_stage / "archive", target),
            "cleanup": arch_stage, "mode": "relocated"}


def _verify_staged_pruned_unit(staged: Path, placed: dict, manifest: dict, body: dict) -> dict:
    """Verify the staged HARD-PRUNED unit before anything is swapped: its shape (every member present and consistent),
    then the real readers in a child process scoped to the staged home with public keys only, then the signed
    ``prune_unit`` cross-check (schema 4) and the owner-key consistency (the backup's private key must be the key of
    its owner.pub, which must be the validated succession tip — a pruned home whose key is not the tip can never
    re-anchor). Raises BackupError naming the member; returns the verifier's shape."""
    from .governor.identity import _public_of
    from .spine.home_unit import HomeUnit, failure_reason, unit_shape, verify_unit_isolated
    unit = HomeUnit(home=staged, archive_dir=placed["read"])
    shape = unit_shape(unit, require_archive=True)
    if shape.refusals:
        hint = (" (this backup carries no archive: pass the dir that holds it as --archive-dir)"
                if not shape.archive_present and not placed["carried"] else "")
        raise BackupError("the backup's hard-pruned spine is not a complete, matching set: "
                          + "; ".join(shape.refusals) + hint + " — nothing was swapped in")
    if not shape.pruned:
        raise BackupError("the backup declares a hard-pruned spine but its signed head cannot be read as one — "
                          "nothing was swapped in")
    work = Path(tempfile.mkdtemp(prefix=".restore-verify-", dir=str(staged.parent)))
    try:
        rep = verify_unit_isolated(unit, work_dir=work, require_archive=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not rep.get("ok") or not rep.get("pruned"):
        raise BackupError(f"the backup's hard-pruned spine does not verify as one unit ({failure_reason(rep)}) — "
                          f"nothing was swapped in")
    sh = rep["shape"]
    pu = manifest.get("prune_unit")
    if pu is not None:
        if not isinstance(pu, dict):
            raise BackupError("the backup manifest's prune_unit block is malformed")
        fields = ("base_seq", "snapshot_seq", "last_seq", "entry_count", "head_sig_hash", "floor_head_sig_hash",
                  "cumulative_merkle_root", "succession_tip")
        bad = [f for f in fields if pu.get(f) != sh.get(f)]
        arch = pu.get("archive")
        if placed["mode"] != "adopt" and (not isinstance(arch, dict) or arch.get("segments") != sh.get("archive_segments")):
            bad.append("archive.segments")
        if bad:
            raise BackupError(f"mismatched set: the signed prune_unit disagrees with the staged unit on "
                              f"{', '.join(bad)} — nothing was swapped in")
    priv = body.get("owner_priv_b64")
    if priv:
        pub = (unit.owner_pub.read_text(encoding="utf-8").strip() if unit.owner_pub.is_file() else "")
        if _public_of(priv) != pub or pub != sh.get("succession_tip"):
            raise BackupError("the backup's owner private key is not the key of its owner.pub and the validated "
                              "owner-key succession tip — nothing was swapped in")
    return sh


@contextmanager
def _target_writers_quiet(new_home: Path) -> Iterator[None]:
    """Hold the restored home's floor lock and an EXCLUSIVE lock on its spine writer lockfile across the swap. The
    writer lock is only TRIED: a writer (or a backup / drill snapshot) holding it now means the sigil services are
    running against this home — refuse. (The swap is crash-safe, not concurrency-safe: stop the services first.)"""
    from .spine.floor import floor_lock
    fd = None
    lock = new_home / "spine" / "spine.lock"
    if lock.is_file():
        try:
            import fcntl
            fd = os.open(str(lock), os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            os.close(fd) if fd is not None else None
            raise BackupError(f"the spine at {new_home} is being written right now — stop the sigil services "
                              f"before restoring into it") from e
        except (OSError, ImportError):
            if fd is not None:
                os.close(fd)
            fd = None
    try:
        with floor_lock(new_home / "floor.json"):
            yield
    finally:
        if fd is not None:
            os.close(fd)


def _write_journal(path: Path, journal: dict) -> None:
    from .spine.atomicio import atomic_write_text
    atomic_write_text(path, json.dumps(journal, indent=1, sort_keys=True), prefix=".restore-journal-")


def _read_journal(home: Path) -> dict:
    jp = home / _JOURNAL_NAME
    if not jp.exists():
        raise BackupError(f"no interrupted restore at {home} (no {_JOURNAL_NAME})")
    try:
        j = json.loads(jp.read_text(encoding="utf-8"))
        units = j["units"]
        ok = (j.get("schema") == _JOURNAL_SCHEMA and isinstance(units, list)
              and all(isinstance(u, dict) and {"name", "src", "dst", "digest", "started", "done"} <= set(u)
                      and all(isinstance(u[k], str) for k in ("name", "src", "dst", "digest"))
                      and all(isinstance(u[k], bool) for k in ("started", "done"))
                      and isinstance(u.get("aside_foreign", False), bool)
                      and not (u.get("aside_foreign") and (u["started"] or u["done"]))
                      and _identity_shape_ok(u.get("old")) for u in units)
              and all(d is None or isinstance(d, str) for d in (j.get("staging"), j.get("archive_staging")))
              and _replaced_shape_ok(j.get("replaced")) and isinstance(j.get("aborting", False), bool))
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BackupError(f"the restore journal at {jp} cannot be read ({e}) — re-run the restore with --force "
                          f"from the backup") from e
    if not ok:
        raise BackupError(f"the restore journal at {jp} is not one this build wrote — re-run the restore with "
                          f"--force from the backup")
    # every rename the journal names stays inside the restore's own dirs: a unit of the home is one captured
    # top-level entry of THIS home, staged in the restore's staging dir (created beside the home); a relocated archive
    # is staged in its own staging dir, which a restore always creates beside the archive's destination. Every path is
    # compared as the real directory entry it names: a staging dir is a real dir spelled as it resolves, and a staged
    # unit is exactly <its staging dir>/<its name>, never a symlink
    staging = Path(j["staging"]) if j.get("staging") else None
    arch_staging = Path(j["archive_staging"]) if j.get("archive_staging") else None
    replaced_staging = [Path(d) for d in (j.get("replaced") or {}).get("staging", [])]
    if any(d is not None and not _restore_own_dir(d) for d in (staging, arch_staging, *replaced_staging)):
        raise BackupError(f"the restore journal at {jp} names a staging dir that is not a restore's own — refusing")
    if staging is not None and staging.parent not in (home.parent.resolve(), home.resolve().parent):
        raise BackupError(f"the restore journal at {jp} names a staging dir that is not a restore's own (it is not "
                          f"beside {home}) — refusing")
    for u in units:
        name, src, dst = u["name"], Path(u["src"]), Path(u["dst"])
        if name != "archive" and name not in CAPTURED_TOP_LEVEL:
            raise BackupError(f"the restore journal at {jp} names a unit {name!r} that a backup never captures — "
                              f"refusing")
        own = arch_staging if name == "archive" else staging
        if own is None or src != own / name or os.path.islink(src):
            raise BackupError(f"the restore journal at {jp} names a staged unit outside its staging dirs — refusing")
        # a destination is the ENTRY itself (its parent resolved, its last component never followed): a swap
        # replaces that entry, so a symlink at it is replaced, never the dir it points to
        if name == "archive":
            if dst.name in ("", ".", "..") or dst.parent != own.parent:
                raise BackupError(f"the restore journal at {jp} names an archive destination that is not beside its "
                                  f"staging dir — refusing")
            if (dst.exists() or dst.is_symlink()) and not _replaceable_archive_dir(dst):
                raise BackupError(f"the restore journal at {jp} names an archive destination {dst} that holds no "
                                  f"archive — refusing")
        elif dst != _entry_path(home / name):
            raise BackupError(f"the restore journal at {jp} names a destination outside {home} — refusing")
    nested = _nested_unit(units)
    if nested is not None:
        raise BackupError(f"the restore journal at {jp} names {nested} — refusing")
    return j


def _entry_identity(p: Path) -> "list | None":
    """What stands at the entry ``p`` (never followed if it is a symlink): None when nothing does, else the file-system
    object — ``[device, inode, content digest]`` (:func:`unit_digest`). A journal unit records it for its
    destination when it is marked started, ahead of its first rename, so the disk can later prove that destination
    still holds what the restore found there (the same object, of the same content) — never one recreated over a
    freed inode, nor one changed in place."""
    from .spine.consistent_copy import unit_digest
    try:
        st = os.lstat(p)
    except (FileNotFoundError, NotADirectoryError):
        return None
    return [st.st_dev, st.st_ino, unit_digest(p)]


def _identity_shape_ok(v: Any) -> bool:
    return v is None or (isinstance(v, list) and len(v) == 3
                         and all(isinstance(x, int) and not isinstance(x, bool) for x in v[:2])
                         and isinstance(v[2], str))


def _old_unit_in_place(u: dict) -> bool:
    """Whether the disk proves that the destination of a journal unit marked started still holds what the restore
    found there when it marked it (its ``old`` record, :func:`_entry_identity`) — still no entry, for a slot that was
    empty. So no attempt at its swap, this one or an earlier interrupted one, has left the old unit moved. Not proven
    (False) when the unit holds no such record or its destination cannot be read."""
    if "old" not in u:
        return False
    try:
        return _entry_identity(Path(u["dst"])) == u["old"]
    except OSError:
        return False


def _nested_unit(rows: "list[dict]") -> "str | None":
    """Each unit of a swap replaces its own entry: a destination at or inside another unit's destination would be
    swapped in and then carried off with that unit (or moved aside under it). Names such a pair, else None."""
    for a in rows:
        for b in rows:
            if a is not b and Path(a["dst"]).is_relative_to(Path(b["dst"])):
                return f"the unit {a['name']!r} at {a['dst']}, inside the destination of {b['name']!r}"
    return None


def _entry_path(p: Path) -> Path:
    """``p`` with its parent resolved and its last component kept as is (never followed if it is a symlink)."""
    return Path(p).parent.resolve() / Path(p).name


def _restore_own_dir(d: Path) -> bool:
    """Whether ``d`` can name a restore's own staging dir: named as one, absolute, spelled exactly as it resolves (no
    ``..`` and no symlink anywhere along it), and not itself a symlink."""
    d = Path(d)
    return (d.is_absolute() and d.name.startswith(".restore-staging-") and ".." not in d.parts
            and not os.path.islink(d) and d.resolve() == d)


def _replaced_shape_ok(rep: Any) -> bool:
    """The ``replaced`` record of a journal: absent, or ``{restore_id, touched, staging}`` where ``touched`` is the
    list of unit names the replaced restore(s) had begun swapping in (None when that could not be read) and
    ``staging`` the replaced restore's staging dirs."""
    if rep is None:
        return True
    return (isinstance(rep, dict) and (rep.get("restore_id") is None or isinstance(rep.get("restore_id"), str))
            and (rep.get("touched") is None
                 or (isinstance(rep.get("touched"), list) and all(isinstance(n, str) for n in rep["touched"])))
            and isinstance(rep.get("staging", []), list) and all(isinstance(d, str) for d in rep.get("staging", [])))


def _staging_dirs(journal: dict) -> "list[Path]":
    """Every staging dir a journal owns: its own (the home's and a relocated archive's) and those of the interrupted
    restore(s) it replaced."""
    dirs = [journal.get("staging"), journal.get("archive_staging"), *(journal.get("replaced") or {}).get("staging", [])]
    return [Path(d) for d in dirs if d]


def _drop_staging(journal: dict) -> None:
    for d in _staging_dirs(journal):
        if _restore_own_dir(d):
            shutil.rmtree(d, ignore_errors=True)


def _complete_journaled_swap(home: Path, journal: dict) -> None:
    """Swap every not-yet-done unit of ``journal`` into place, in order, write-ahead: a unit is marked ``started``
    (atomic journal rewrite), with what stands at its destination (``old``, :func:`_entry_identity`), before its first
    rename, and ``done`` as soon as the new unit is in place — before its old copy is dropped. Then prove every
    destination is the unit the restore verified, drop the journal and the staging. Idempotent: a unit whose staged
    copy is gone but whose destination already IS the verified unit (a crash after its swap, before it was marked) is
    marked done, and an old copy left aside is dropped; a staged copy that changed since it was verified, or a unit
    that is neither staged nor in place, is refused. An old copy at a unit's aside is never dropped before the new
    unit is marked in place, unless its destination is proven to still hold the old unit (:func:`_clear_the_way`)."""
    from .spine.atomicio import fsync_dir
    from .spine.consistent_copy import unit_digest
    jp = home / _JOURNAL_NAME
    for u in journal["units"]:
        src, dst = Path(u["src"]), Path(u["dst"])
        if not u["done"]:
            if src.exists() or src.is_symlink():
                if unit_digest(src) != u["digest"]:
                    raise BackupError(f"the staged copy of {u['name']!r} changed since the restore verified it — "
                                      f"refusing to swap it in; re-run the restore with --force from the backup")
                if not u["started"]:
                    try:
                        old = _entry_identity(dst)           # what the swap replaces, recorded ahead of its renames
                    except OSError as e:
                        raise BackupError(f"could not swap {u['name']!r} into place: {dst} cannot be read to record "
                                          f"what the swap replaces ({e}) — nothing of it was moved; "
                                          f"{_next_step(home, journal)}") from e
                    u["started"] = True
                    u["old"] = old
                    u.pop("aside_foreign", None)             # an aside from here on may be this swap's own
                    _write_journal(jp, journal)
                    _maybe_crash(f"restore_unit_started:{u['name']}")
                if os.path.lexists(dst) and os.path.lexists(_aside_of(dst)):
                    _clear_the_way(home, journal, u)
                moved: "list[Path]" = []
                try:
                    _swap_in(src, dst, moved)
                except OSError as e:
                    _swap_failed(home, journal, u, e, moved)
                _maybe_crash(f"restore_swapped_in:{u['name']}")
            elif unit_digest(dst) != u["digest"]:
                raise BackupError(f"cannot complete the interrupted restore: the staged copy of {u['name']!r} is gone "
                                  f"and {dst} is not the unit it verified — re-run the restore with --force from the "
                                  f"backup")
            fsync_dir(dst.parent)
            u["started"] = u["done"] = True
            _write_journal(jp, journal)
            _maybe_crash(f"restore_after_unit:{u['name']}")
        _drop_path(_aside_of(dst))                       # the old copy goes only once the new one is marked in place
        fsync_dir(dst.parent)
    changed = [u["name"] for u in journal["units"] if unit_digest(Path(u["dst"])) != u["digest"]]
    if changed:
        raise BackupError(f"restored unit(s) {changed} changed after they were swapped in (is a sigil service running "
                          f"against {home}?) — the restore journal is kept; stop the services and re-run the restore "
                          f"with --force")
    _maybe_crash("restore_before_journal_delete")
    jp.unlink()
    fsync_dir(home)
    _drop_staging(journal)


def _clear_the_way(home: Path, journal: dict, u: dict) -> None:
    """Both the destination of a unit marked started and the aside beside it hold an entry. While the destination still
    holds what the restore found there when it marked the unit (:func:`_old_unit_in_place`), no attempt has left the
    old unit moved, so the entry at the aside is a leftover and not its old copy: it is removed (one that cannot be
    removed stops the swap before its first rename, :class:`_AsideInTheWay`). Otherwise the aside may hold the only old
    copy of the unit, moved there by an earlier attempt, and the destination was recreated after that attempt was
    interrupted: the aside is kept. An empty dir recreated there holds nothing to lose: it is removed, and the new unit
    is renamed into the empty slot. Anything else stops the swap with nothing moved and the unit still marked started."""
    from .spine.atomicio import fsync_dir
    dst = Path(u["dst"])
    aside = _aside_of(dst)
    if _old_unit_in_place(u):
        _drop_path(aside)
        return
    if dst.is_dir() and not dst.is_symlink():
        try:
            os.rmdir(dst)                                # only an EMPTY dir goes: nothing in it is lost
        except OSError:
            pass
        else:
            fsync_dir(dst.parent)
            _maybe_crash(f"restore_cleared_destination:{u['name']}")
            return
    raise BackupError(f"could not swap {u['name']!r} into place: {aside} may hold the old copy of it this restore "
                      f"moved aside, and {dst} is not what the restore found there when it began this swap (it was "
                      f"made after the restore was interrupted) — nothing was moved; move {dst} out of the home (the "
                      f"old copy at {aside} is kept); {_next_step(home, journal)}")


def _swap_failed(home: Path, journal: dict, u: dict, err: OSError, moved: "list[Path]") -> NoReturn:
    """A unit's swap failed with an OSError. Its ``started`` mark goes back durably only on positive evidence that no
    attempt has left anything of the unit moved: this attempt moved nothing it did not move back (``moved``, from
    :func:`_swap_in`, is empty), and the destination still holds what the restore found there when it marked the unit
    started (:func:`_old_unit_in_place` — an earlier, interrupted attempt that moved the old unit aside, or renamed the
    new one in, leaves it false, whatever was made at the destination since). The home then reads as what it is,
    untouched by this unit; a leftover in the way (:class:`_AsideInTheWay`) is marked ``aside_foreign`` with it, so it
    is never read as this restore's old copy. Otherwise every mark stays. Raises a BackupError that says what the home
    now is and how to leave the state the journal keeps it in."""
    dst = Path(u["dst"])
    aside = _aside_of(dst)
    foreign = isinstance(err, _AsideInTheWay)
    untouched = not moved and _old_unit_in_place(u)
    if untouched:
        u["started"] = False
        u.pop("old", None)
        if foreign:
            u["aside_foreign"] = True
        _write_journal(home / _JOURNAL_NAME, journal)
    if untouched:
        where = (f"{dst} was left as it was; {aside}, an old copy this restore did not put there, is in the way of "
                 f"its swap and cannot be removed — remove it" if foreign else f"{dst} was left as it was")
    elif os.path.lexists(aside):
        where = f"its old copy is at {aside}"
    else:
        where = f"{dst} cannot be proven to be what the restore found there when it began this swap"
    raise BackupError(f"could not swap {u['name']!r} into place ({err}): {where}; {_next_step(home, journal)}") from err


def _next_step(home: Path, journal: dict) -> str:
    """What the home is while ``journal`` stands, and how to leave that state."""
    if not _touched_units(journal) and _replaced_touched(journal) == []:
        return (f"the home is still entirely its old self — `sigil restore --abort {home}` discards this restore, or "
                f"`sigil restore --resume {home}` finishes it once the cause is fixed")
    return (f"the home is no longer entirely its old self — fix the cause and finish it with `sigil restore --resume "
            f"{home}`, or replace it with a fresh `sigil restore --force` from the backup")


def _drop_leftover_asides(journal: dict) -> None:
    """Remove the old copy an earlier restore left at the aside of any destination of ``journal``, before it is
    written — or refuse, with nothing of this restore swapped in and its journal not written, naming the leftover
    that cannot be removed (one that is or holds a mount point is refused before this, by
    :func:`_refuse_unrenamable`, and never dropped)."""
    from .spine.atomicio import fsync_dir
    for u in journal["units"]:
        aside = _aside_of(Path(u["dst"]))
        if not (aside.exists() or aside.is_symlink()):
            continue
        _drop_path(aside)
        if aside.exists() or aside.is_symlink():
            raise BackupError(f"cannot remove {aside}, an old copy of {u['name']!r} an earlier restore left beside "
                              f"{u['dst']} — remove it, then run the restore again; nothing of this restore was "
                              f"swapped in and it wrote no journal")
        fsync_dir(aside.parent)


def _new_journal(src: Path, staged: Path, placed: "dict | None", units: "list[tuple[Path, Path]]", shape: dict, *,
                 pruned: bool) -> dict:
    """The journal of a journaled swap: every unit in swap order (a relocated archive first, then the spine, the
    floor and the rest), each with the digest of the staged unit the restore verified and re-sealed."""
    from datetime import datetime, timezone

    from .spine.consistent_copy import unit_digest
    rows = []
    if placed is not None and placed["unit"] is not None:
        a_src, a_dst = placed["unit"]
        rows.append({"name": "archive", "src": str(a_src.resolve()), "dst": str(_entry_path(a_dst)),
                     "digest": unit_digest(a_src), "started": False, "done": False})
    for u_src, u_dst in units:
        rows.append({"name": u_dst.name, "src": str(u_src.resolve()), "dst": str(_entry_path(u_dst)),
                     "digest": unit_digest(u_src), "started": False, "done": False})
    h = hashlib.sha256()
    with open(src, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return {"schema": _JOURNAL_SCHEMA, "restore_id": os.urandom(8).hex(),
            "created": datetime.now(timezone.utc).isoformat(), "backup_sha256": h.hexdigest(),
            "staging": str(staged.resolve()),
            "archive_staging": (str(placed["cleanup"].resolve()) if placed is not None and placed["cleanup"] is not None
                                else None),
            "pruned": pruned, "head_sig_hash": shape.get("head_sig_hash"), "base_seq": shape.get("base_seq"),
            "units": rows}


def restore_resume(home: "str | Path") -> dict:
    """``sigil restore --resume <home>``: complete a restore into ``home`` that was interrupted between its swaps,
    from its journal (no passphrase needed: every unit was verified, and its secrets re-sealed, before the journal
    was written). Each pending unit's staged copy must still be the one the restore verified."""
    home = Path(home)
    _read_journal(home)                                  # nothing to resume: refuse before touching the home
    with _target_writers_quiet(home):
        journal = _read_journal(home)
        if journal.get("aborting"):
            raise BackupError(f"an abort of the interrupted restore into {home} was itself interrupted — finish it "
                              f"with `sigil restore --abort {home}`")
        _complete_journaled_swap(home, journal)
    return {"home": str(home), "units": [u["name"] for u in journal["units"]], "resumed": True}


def _touched_units(journal: dict) -> "list[str]":
    """The units of ``journal`` whose swap has begun, by name: marked started or done in the journal (written ahead
    of the first rename), or — independently of the marks — whose staged copy has left the staging or whose
    destination has an old copy moved aside beside it. Once an abort has marked the journal ``aborting`` (after it
    found nothing touched, before it drops a staged copy), a staged copy that is gone is that abort's doing."""
    staged_evidence = not journal.get("aborting")
    return [u["name"] for u in journal["units"]
            if u["started"] or u["done"] or _swap_began_on_disk(u, staged_evidence=staged_evidence)]


def _swap_began_on_disk(u: dict, *, staged_evidence: bool = True) -> bool:
    """Whether the disk shows that a journal unit's swap began, whatever its marks say: its staged copy has left the
    staging (when ``staged_evidence``), or an old copy is moved aside beside its destination. No old copy is at an
    aside when the journal is written (a restore removes any leftover first), so one there is this restore's own —
    except a leftover that stopped the swap before its first rename, which the journal marks ``aside_foreign``."""
    src, aside = Path(u["src"]), _aside_of(Path(u["dst"]))
    moved_aside = not u.get("aside_foreign") and (aside.exists() or aside.is_symlink())
    return (staged_evidence and not (src.exists() or src.is_symlink())) or moved_aside


def _replaced_touched(journal: dict) -> "list[str] | None":
    """The units the interrupted restore(s) ``journal`` replaced had begun swapping in: [] when it replaced none (or
    one that had touched nothing), None when the replaced journal could not be read (anything may have been)."""
    rep = journal.get("replaced")
    return [] if rep is None else rep.get("touched")


def _replaced_record(home: Path) -> "dict | None":
    """What a restore into ``home`` that replaces the interrupted one standing there records of it, read from that
    journal and the disk BEFORE anything of it is dropped: the units it (or any restore it had itself replaced) had
    begun swapping in — the home is then no longer entirely its old self, whatever the new restore's own units show —
    and its staging dirs, which the new restore drops. None when no restore journal stands in ``home``."""
    if not (home / _JOURNAL_NAME).exists():
        return None
    try:
        prior = _read_journal(home)
    except BackupError:
        return {"restore_id": None, "touched": None, "staging": []}        # unreadable: assume it touched the home
    touched = _touched_units(prior)
    earlier = _replaced_touched(prior)
    return {"restore_id": prior.get("restore_id") if isinstance(prior.get("restore_id"), str) else None,
            "touched": None if earlier is None else touched + [n for n in earlier if n not in touched],
            "staging": [str(d) for d in _staging_dirs(prior)]}


def restore_abort(home: "str | Path") -> dict:
    """``sigil restore --abort <home>``: discard an interrupted restore into ``home`` — only while the home is still
    entirely its old self: none of its units has been touched, and the interrupted restore it replaced (if any) had
    touched none either. Once a swap has begun, only ``--resume`` (the home is then entirely the backup's) or a fresh
    ``--force`` restore from the backup leaves the home consistent; abort then refuses and deletes nothing. Its verdict
    is written to the journal (``aborting``) before anything is dropped and the journal goes last, so an abort that is
    interrupted is finished by running it again; ``--resume`` refuses such a journal."""
    from .spine.atomicio import fsync_dir
    home = Path(home)
    jp = home / _JOURNAL_NAME
    _read_journal(home)                                  # nothing to abort: refuse before touching the home
    with _target_writers_quiet(home):
        journal = _read_journal(home)
        touched = _touched_units(journal)
        if touched:
            raise BackupError(f"cannot abort: the restore into {home} had begun swapping {touched} in — finish it "
                              f"with `sigil restore --resume {home}`, or replace it with a fresh `sigil restore "
                              f"--force` from the backup; nothing was discarded")
        earlier = _replaced_touched(journal)
        if earlier is None or earlier:
            what = (f"the interrupted restore it replaced had begun swapping {earlier} in" if earlier
                    else "it replaced an interrupted restore whose journal could not be read")
            raise BackupError(f"cannot abort: the home {home} is no longer its old self ({what}) — finish this "
                              f"restore with `sigil restore --resume {home}`, or replace it with a fresh `sigil "
                              f"restore --force` from the backup; nothing was discarded")
        # the verdict is durable before anything is dropped: an abort interrupted from here on is finished by
        # running it again (a resume refuses it), however much of the staging it had removed
        if not journal.get("aborting"):
            journal["aborting"] = True
            _write_journal(jp, journal)
            _maybe_crash("restore_abort_marked")
        _drop_staging(journal)
        jp.unlink()
        fsync_dir(home)
    return {"home": str(home), "aborted": True}


def _reseal_secrets(staged: Path, body: dict, vault: Any) -> None:
    """Re-seal the machine-bound secrets through the NEW vault (sealed under the new TPM if provisioned) into the
    staged home, swapped into place with the rest of the tree: the owner private key, the DEK, and the KV secret store
    (under the SAME purpose context, so the operator's own API keys are recoverable on new hardware)."""
    if body.get("owner_priv_b64"):
        vault.write_text_secret(staged / "spine" / "keys" / "owner.priv", body["owner_priv_b64"],
                                context=_OWNER_PRIV_CONTEXT)
    if body.get("spine_dek_b64"):
        vault.write_text_secret(staged / "spine" / "keys" / "spine.dek", body["spine_dek_b64"], context=_DEK_CONTEXT)
    if body.get("secrets_kv_b64"):
        vault.write_text_secret(staged / _SECRETS_KV_FILE, body["secrets_kv_b64"], context=_SECRETS_KV_CONTEXT)


def _owner_key_matches(staged: Path, body: dict) -> "bool | None":
    """Whether the backup's owner private key is the key of its owner.pub (None when the backup carries no key)."""
    priv = body.get("owner_priv_b64")
    if not priv:
        return None
    from .governor.identity import _public_of
    pub_path = staged / "spine" / "keys" / "owner.pub"
    pub = pub_path.read_text(encoding="utf-8").strip() if pub_path.is_file() else ""
    return _public_of(priv) == pub


def _env_file_value(raw: "bytes | None", key: str) -> "str | None":
    """The value ``sigil.env`` bytes give ``key``, parsed the way ``config`` loads the file (``\\n``-separated
    ``KEY=VALUE`` lines, ``#`` comments skipped, the first assignment wins), or None."""
    if raw is None:
        return None
    for line in raw.decode("utf-8", errors="replace").split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip() or None
    return None


def _restore_result(new_home: "Path | None", files: dict, body: dict, *, pruned: bool, swapped: bool,
                    placed: "dict | None", owner_key_matches: "bool | None", env: "bytes | None" = None) -> dict:
    out = {"home": str(new_home) if new_home is not None else None, "files": len(files),
           "owner_key": bool(body.get("owner_priv_b64")), "dek": bool(body.get("spine_dek_b64")),
           "secrets_kv": bool(body.get("secrets_kv_b64")),
           "warden": sum(1 for rel in files if rel.startswith("warden/")), "verified": True, "pruned": pruned,
           "swapped": swapped, "owner_key_matches": owner_key_matches}
    if pruned and placed is not None:
        out["unit_verified"] = True
        out["archive_dir"] = str(placed["target"])
        out["archive_mode"] = placed["mode"]
        # the restored sigil.env is what the restored home's services read their archive dir from: when it names
        # another dir than the one the archive was placed in, they would read (and verify against) the wrong one
        named = _env_file_value(env, "SIGIL_SPINE_ARCHIVE_DIR")
        out["archive_env"] = named
        out["archive_env_mismatch"] = (named is not None and new_home is not None
                                       and Path(named).resolve() != Path(placed["target"]).resolve())
    return out


def restore_backup(src: str | Path, new_home: "str | Path | None", passphrase: str, *, vault: Any,
                   force: bool = False, archive_dir: "str | Path | None" = None, verify_only: bool = False) -> dict:
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
    already exists, never merely because the home is non-empty. A restore into a home that already holds any captured
    unit swaps its units JOURNALED (write-ahead, resumable, see :func:`restore_resume`): a crash during the swap leaves
    a home that fails closed until ``--resume`` makes it entirely the backup's (or, while the home is still entirely
    its old self, ``--abort`` leaves it so); into a fresh home each unit lands complete or not at all. The journaled
    swap holds the target's floor lock and refuses while its spine writer lock is held (stop the services first).
    Exactly the captured units are swapped (a whitelist), never whatever else turns up in the staging dir. A swap the
    filesystem cannot do by renames (a home or archive dir that is a mount point, a bind mount of the same filesystem
    included; a unit, or an old copy an earlier restore left beside one, that is or holds a mount point) is refused
    before anything is written (:func:`_refuse_unrenamable`, read from the kernel's mount list); such a leftover is
    removed before the journal is written, or the restore refuses with nothing swapped in. A unit whose rename still
    fails with nothing of it moved is left unmarked in the journal, so a restore that touched nothing can still be
    discarded with ``--abort``.

    HARD-PRUNED spine (SIGIL_PRUNED_RESTORE on; refused before anything is written while it is off): the spine, its
    signed head, the floor, the owner public key(s) and the archive are verified as ONE unit by the real readers in a
    child process scoped to the staged home, holding back the private keys, the KV store and ``sigil.env`` until it
    verifies (:func:`_verify_staged_pruned_unit`); the archive is placed per :func:`_place_staged_archive`
    (``archive_dir``, never this process's ``SIGIL_SPINE_ARCHIVE_DIR``). Its swap is always JOURNALED, and so is the
    swap of ANY restore that replaces (``--force``) an interrupted one: its journal replaces the interrupted restore's
    before its first swap and carries the units that one had already begun swapping in, so it can then only be
    finished (``--resume``), never aborted onto a home that is no longer entirely its old self. ``verify_only`` runs
    every check into a throwaway staging dir and swaps nothing (``vault`` may then be None); given ``new_home`` it also
    refuses whatever the restore into that home with the same ``force`` would (existing units, an interrupted restore,
    an existing archive dir)."""
    if new_home is None and not verify_only:
        raise BackupError("a restore needs a target home")
    src = Path(src)
    new_home = Path(new_home) if new_home is not None else None
    archive_dir = Path(archive_dir) if archive_dir is not None else None
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
    from . import config
    pruned = _backup_declares_prune(files, hashes, manifest)
    if pruned and not config.pruned_restore_enabled():
        raise BackupError("this backup holds a hard-pruned spine; restoring it as one verified unit needs "
                          "SIGIL_PRUNED_RESTORE=1 — nothing was written")
    captured_units = set(rel.split("/", 1)[0] for rel in files)
    if body.get("secrets_kv_b64") is not None:      # re-wrapped (not a file entry) but lands as a top-level unit
        captured_units.add(_SECRETS_KV_FILE)
    # the target gates run for --verify-only with a home too: it refuses exactly what the restore into that home
    # (with the same --force) would refuse, so a caller that verifies first never starts a restore that is refused
    stale_journal = new_home is not None and (new_home / _JOURNAL_NAME).exists()
    if stale_journal and not force:
        raise BackupError(f"a restore into {new_home} was interrupted — finish it with `sigil restore --resume "
                          f"{new_home}`, or replace it with a fresh restore (--force); `sigil restore --abort "
                          f"{new_home}` discards it only while the home is still entirely its old self")
    present_units = sorted(u for u in captured_units if (new_home / u).exists()) if new_home is not None else []
    if not force and present_units:
        raise BackupError(
            f"refusing to overwrite existing SIGIL state {present_units} under {new_home} (a restore must not "
            f"silently overlay stale state) — pass force=True (--force) to REPLACE those units, or restore into "
            f"a fresh home. Un-captured home content (vector/cursor/config caches) is left intact regardless.")

    staged_dir = (_new_staging_dir(new_home) if new_home is not None     # the working staging home (always a Path)
                  else Path(tempfile.mkdtemp(prefix=".restore-staging-")))
    staged: Path | None = staged_dir            # cleanup handle for the finally; None once ownership transfers
    placed: "dict | None" = None
    held_env: "bytes | None" = None
    sh: dict = {}
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
            if rel == "sigil.env":           # held back: a process scoped to the staged home would load it
                held_env = data
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            # key material (the WARDEN kernel key + any *.key) must be 0600, not the process umask — a plain
            # write_bytes would otherwise leave it world-readable-by-umask (a real perms fix, not cosmetic).
            if _is_sensitive_rel(rel):
                os.chmod(target, 0o600)
            if _is_private_state_rel(rel):
                # personal data: every directory from the file's own up to its top-level unit is owner-only too
                # (0700, as the store keeps it), never the umask's world-listable default
                top = staged_dir / rel.replace("\\", "/").partition("/")[0]
                d = target.parent
                while d != top.parent:
                    os.chmod(d, 0o700)
                    d = d.parent
        from .spine.home_unit import HomeUnit, unit_shape
        pruned = pruned or unit_shape(HomeUnit.for_home(staged_dir), require_archive=False).pruned
        if pruned and not config.pruned_restore_enabled():
            raise BackupError("this backup holds a hard-pruned spine; restoring it as one verified unit needs "
                              "SIGIL_PRUNED_RESTORE=1 — nothing was written")
        if pruned:
            # the HARD-PRUNED unit: placed, then verified as ONE unit before any secret is re-sealed or swapped in
            placed = _place_staged_archive(staged_dir, new_home, archive_dir, force=force, verify_only=verify_only,
                                           captured_units=captured_units)
            sh = _verify_staged_pruned_unit(staged_dir, placed, manifest, body)
        else:
            if not verify_only:
                _reseal_secrets(staged_dir, body, vault)
            # re-verify the STAGED spine's internal integrity (keyless binding + chain) — never claim a restore
            # succeeded on a corrupt ledger, and never swap an unverified home into place.
            from .spine.store import SpineStore
            ok, why = SpineStore(staged_dir / "spine" / "spine.jsonl").verify()
            if not ok:
                raise BackupError(f"restored spine failed verification ({why}) — the restore is NOT trustworthy")
        result = _restore_result(new_home, files, body, pruned=pruned, swapped=not verify_only, placed=placed,
                                 owner_key_matches=_owner_key_matches(staged_dir, body), env=held_env)
        if new_home is not None:
            # every rename the swap would do is one the filesystem can do (--verify-only checks it too): a restore
            # never begins a swap whose renames are bound to fail
            renames = [(staged_dir, new_home / u) for u in sorted(captured_units)]
            if placed is not None and placed["mode"] == "relocated":
                renames.append((placed["cleanup"] or placed["target"].parent, placed["target"]))
            _refuse_unrenamable(renames)
        if verify_only:
            return result
        assert new_home is not None
        if pruned:
            _reseal_secrets(staged_dir, body, vault)      # held back until the unit verified
        if held_env is not None:
            env_path = staged_dir / "sigil.env"
            env_path.write_bytes(held_env)
            os.chmod(env_path, 0o600)
        units = _captured_swap_list(staged_dir, new_home, captured_units)
        new_home.mkdir(parents=True, exist_ok=True)
        replaces_units = any((new_home / u).exists() or (new_home / u).is_symlink() for u in captured_units)
        if pruned or stale_journal or replaces_units:
            # JOURNALED: a hard-pruned unit always; any restore that replaces an existing unit (a crash between moving
            # the old unit aside and renaming the new one in must never leave a home with no guard); and any restore
            # that replaces an interrupted one, whose journal this one's replaces BEFORE the first swap — a crash from
            # here on is resumed into THIS restore, never back into the one it replaced
            journal = _new_journal(src, staged_dir, placed, units, sh, pruned=pruned)
            nested = _nested_unit(journal["units"])
            if nested is not None:
                raise BackupError(f"refusing to swap {nested} — nothing was swapped in")
            with _target_writers_quiet(new_home):
                # what the interrupted restore had already done to the home is read BEFORE its journal is replaced
                # and carried in this one: an abort is then refused while the home holds any of its swapped units
                replaced = _replaced_record(new_home)
                if replaced is not None:
                    if not force:
                        raise BackupError(f"a restore into {new_home} was interrupted — finish it with `sigil restore "
                                          f"--resume {new_home}`, or replace it with a fresh restore (--force)")
                    journal["replaced"] = replaced
                # an old copy an earlier restore left beside a destination goes BEFORE the journal is written (what
                # it says of the restore it replaced is read above), so an old copy aside from here on is this
                # restore's own; one that cannot be removed refuses the restore with nothing swapped in
                _drop_leftover_asides(journal)
                # the journal is durable BEFORE the first swap: from here on a crash is resumed, never left mixed
                _write_journal(new_home / _JOURNAL_NAME, journal)
                staged = None                                # the journal owns the staging dirs now
                placed = None
                _maybe_crash("restore_after_journal")
                if replaced is not None:                     # the replaced restore's staging goes once this stands
                    _drop_staging({"replaced": replaced})
                _complete_journaled_swap(new_home, journal)
        else:
            # everything verified: swap ONLY the captured units into new_home (subset capture → leave un-captured
            # home content intact), then drop the drained staging shell (its units were moved out).
            _swap_units(units)
            shutil.rmtree(staged_dir, ignore_errors=True)
            staged = None
        return result
    finally:
        if staged is not None:
            shutil.rmtree(staged, ignore_errors=True)
        if placed is not None and placed.get("cleanup") is not None:
            shutil.rmtree(placed["cleanup"], ignore_errors=True)
