"""
common.paths — path-portable resolution of CRUCIBLE_ROOT.

The framework can live anywhere on disk. Every subsystem resolves
paths through this module rather than hard-coding. Discovery order:

  1. CRUCIBLE_ROOT env var (validated: must contain CLAUDE.md).
  2. Walk up from this module's location until CLAUDE.md is found
     (the package location is stable regardless of how the CLI was invoked).
  3. Walk up from the running script (sys.argv[0]).
  4. Walk up from CWD.
  5. Fail with CrucibleRootNotFound.

Why the module location is tried before the invoking script: when the CLI is
run through a console-script wrapper (`vigil`/`crucible` in a venv `bin/`),
sys.argv[0] points into that `bin/` dir, and walking up from there can reach a
directory that happens to hold an UNRELATED CLAUDE.md (e.g. one under $HOME).
Rooting there would send the governance key, kill-switch, entitlement trust
root, findings and evidence to the wrong tree — a security-relevant mis-root.
`__file__` is inside the installed package, so its walk resolves to the real
repo root whenever the package lives in the source tree; only when it does not
(a true site-packages install with no CLAUDE.md above it) do we fall through to
the argv[0]/CWD candidates, exactly as before.

Resolution is cached after first success. Tests that need to point at
a different root may call `_reset_cache()`.
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path

from .errors import CrucibleRootNotFound

_SENTINEL = "CLAUDE.md"


def _walk_up_for_sentinel(start: Path) -> Path | None:
    try:
        start = start.resolve()
    except OSError:
        return None
    for cand in [start, *start.parents]:
        if (cand / _SENTINEL).is_file():
            return cand
    return None


@lru_cache(maxsize=1)
def crucible_root() -> Path:
    env = os.environ.get("CRUCIBLE_ROOT")
    if env:
        p = Path(env).expanduser()
        try:
            p = p.resolve()
        except OSError:
            p = Path(env).expanduser()
        if (p / _SENTINEL).is_file():
            return p

    candidates: list[Path | None] = []
    # This module's location FIRST: it lives inside the installed package, so its
    # walk resolves to the real repo root regardless of how the CLI was invoked. A
    # console-script wrapper's argv[0] points into a venv `bin/`, whose walk can hit
    # an unrelated CLAUDE.md (e.g. under $HOME) and mis-root the governance key /
    # kill-switch / entitlement to the wrong tree. argv[0] and CWD remain as
    # fallbacks for a true site-packages install where __file__ has no CLAUDE.md above it.
    candidates.append(Path(__file__).parent)
    if sys.argv and sys.argv[0]:
        candidates.append(Path(sys.argv[0]).parent)
    candidates.append(Path.cwd())

    for c in candidates:
        if c is None:
            continue
        found = _walk_up_for_sentinel(c)
        if found is not None:
            return found

    raise CrucibleRootNotFound(
        "Could not locate CLAUDE.md. Set CRUCIBLE_ROOT to the directory "
        "containing CLAUDE.md, or run from inside that tree."
    )


def _reset_cache() -> None:
    """Clear the cached root. Tests use this; production should not."""
    crucible_root.cache_clear()


# ---------------------------------------------------------------------------
# At-rest protection (Speed program X2). CRUCIBLE writes secrets (entitlement
# trust root, authority + kill-switch), integrity state (the append-only SQLite
# spine / memory / world-model / ledgers) and captured evidence (raw HTTP with
# Authorization/Cookie headers + response bodies) to disk. On a shared host those
# must never be world- or group-readable. These helpers make every framework
# write owner-only, with no encryption dependency (operator decision): a
# restrictive umask latch for the broad stroke, plus explicit 0600-file / 0700-dir
# creation at the sensitive stores for defence-in-depth. All best-effort and
# offline: a filesystem that cannot represent POSIX modes (a mounted/Windows FS)
# is never an error — the write still happens.
# ---------------------------------------------------------------------------

# owner-only: rw------- for files, rwx------ for directories.
SECURE_FILE_MODE = 0o600
SECURE_DIR_MODE = 0o700
# the bits a restrictive umask must mask off (all group + other permissions).
_UMASK_RESTRICT = 0o077


def tighten_umask() -> int:
    """Latch a restrictive umask so every file this process (and its children)
    creates is owner-only (0600) and every directory owner-only (0700). Only ADDS
    restrictions — it unions the requested mask with whatever the environment
    already set, so a stricter ambient umask is never loosened. Returns the
    effective umask. Idempotent. Call once at CLI start; harmless to call again."""
    prev = os.umask(_UMASK_RESTRICT)      # read prev + provisionally restrict
    effective = prev | _UMASK_RESTRICT    # union: keep any stricter ambient bits
    os.umask(effective)
    return effective


def secure_dir(path: Path, *, mode: int = SECURE_DIR_MODE) -> Path:
    """Ensure ``path`` exists as a directory and return it, chmod'ing it owner-only
    (0700) ONLY when this call CREATED it. A pre-existing directory is left exactly
    as the operator set it — we never re-permission a directory we did not make.
    This is load-bearing: a sensitive store's parent can be a SHARED path (the
    framework source root for the ambient log, an operator-chosen evidence output
    dir), and silently chmod'ing that to 0700 would lock other users out of a whole
    tree. New CRUCIBLE state dirs (.memory/.entitlement/.authority/…) are created
    here and so become 0700; their files are independently 0600. Best-effort — a
    filesystem that cannot represent the mode is not an error."""
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if not existed:                    # only tighten a directory WE just created
        try:
            path.chmod(mode)
        except OSError:
            pass
    return path


def secure_write(path: Path, data: str | bytes, *, mode: int = SECURE_FILE_MODE) -> Path:
    """Write ``data`` to ``path`` owner-only (0600 by default) with NO
    world-readable window: the file is created via ``os.open`` with the restrictive
    mode BEFORE any bytes are written (not created-then-chmod'd). The parent dir is
    ensured owner-only. Overwrites (and re-tightens) an existing file. Content is
    byte-for-byte what a plain write would produce — only the permissions differ, so
    determinism/replay and report byte-identity are unaffected."""
    secure_dir(path.parent)
    is_bytes = isinstance(data, (bytes, bytearray))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb" if is_bytes else "w",
                   encoding=None if is_bytes else "utf-8") as f:
        f.write(data)
    try:
        os.chmod(path, mode)   # tighten a pre-existing file that O_CREAT did not chmod
    except OSError:
        pass
    return path


def secure_existing(path: Path, *, mode: int = SECURE_FILE_MODE) -> Path:
    """Best-effort tighten the permissions of an already-written file (e.g. a
    SQLite database created by ``sqlite3.connect``, which we cannot open with an
    explicit mode). No-op if the path does not exist or the FS cannot chmod."""
    try:
        if path.exists():
            path.chmod(mode)
    except OSError:
        pass
    return path


# ---------------------------------------------------------------------------
# v1 paths (read-only from v2's perspective)
# ---------------------------------------------------------------------------


def v1_dir(name: str) -> Path:
    return crucible_root() / "framework" / name


def cognitive_doc(stem: str) -> Path:
    return v1_dir("cognitive") / f"{stem}.md"


def playbook(stem: str) -> Path:
    return v1_dir("playbooks") / f"{stem}.md"


def attack_technique(stem: str) -> Path:
    return v1_dir("knowledge-base") / "attack-techniques" / f"{stem}.md"


def template(stem: str) -> Path:
    return v1_dir("templates") / f"{stem}.md"


def template_dir() -> Path:
    return v1_dir("templates")


def targets_root() -> Path:
    return crucible_root() / "targets"


def target_template_dir() -> Path:
    return targets_root() / "_template"


# ---------------------------------------------------------------------------
# v2 paths (writable)
# ---------------------------------------------------------------------------


def v2_root() -> Path:
    return crucible_root() / "framework" / "v2"


def memory_dir() -> Path:
    return v2_root() / ".memory"


def memory_db() -> Path:
    return memory_dir() / "store.sqlite"


def dryrun_dir() -> Path:
    return v2_root() / ".dryrun"


def fixtures_dir() -> Path:
    """Where intake captures HTTP responses for offline-replay tests."""
    return v2_root() / "intake" / "tests" / "fixtures"


def authorization_ledger() -> Path:
    return v2_root() / ".intake-authorizations.txt"


# ---------------------------------------------------------------------------
# Entitlement layer (Pillar 2). Operator-provisioned, gitignored. The
# directory holds the trust root (authoriser public keys + threshold),
# the threshold-signed entitlement, and the signed revocation list.
#
# Override the directory with CRUCIBLE_ENTITLEMENT_DIR so a deployment
# can keep entitlement material on a read-only mount or HSM-fronted
# path separate from the code tree.
# ---------------------------------------------------------------------------


def entitlement_dir() -> Path:
    override = os.environ.get("CRUCIBLE_ENTITLEMENT_DIR")
    if override:
        return Path(override).expanduser()
    return v2_root() / ".entitlement"


def trust_root_path() -> Path:
    return entitlement_dir() / "trust-root.json"


def entitlement_path() -> Path:
    return entitlement_dir() / "entitlement.json"


def revocation_path() -> Path:
    return entitlement_dir() / "revocation.json"


# ---------------------------------------------------------------------------
# SIL — self-improvement loop artifacts (Pillar 3). Writable, gitignored.
# Gaps and reviewable proposals; never the framework's own canon.
# ---------------------------------------------------------------------------


def improve_dir() -> Path:
    return v2_root() / ".improve"


def proposals_dir() -> Path:
    return improve_dir() / "proposals"


def gaps_dir() -> Path:
    return improve_dir() / "gaps"


# ---------------------------------------------------------------------------
# Engagement authority + kill-switch. Writable, gitignored. The kill-switch
# file is the persistent fail-closed hard stop: if it exists, the
# engagement is halted regardless of process state.
# ---------------------------------------------------------------------------


def authority_dir() -> Path:
    return v2_root() / ".authority"


def authority_path(slug: str) -> Path:
    return authority_dir() / f"{slug}.authority.json"


def killswitch_path(slug: str) -> Path:
    return authority_dir() / f"{slug}.halt"


def aegis_mode_path(slug: str) -> Path:
    """Control file for a LIVE AEGIS observe<->enforce switch. The gateway re-reads it per request
    (mirrors killswitch_path); the console writes 'observe'/'enforce'. Absent -> the startup mode."""
    return authority_dir() / f"{slug}.mode"


# ---------------------------------------------------------------------------
# Governance AUTHORITY trust root (Phase 0.1). DEDICATED store, DECOUPLED from
# the entitlement dir above.
#
# This holds the TrustRoot that verifies a signed EngagementAuthority (the
# owner-signed, threshold-verified remote-engage authority). It is DELIBERATELY
# a SEPARATE path from `trust_root_path()` (`.entitlement/trust-root.json`):
# `entitlement.policy._enforcement_active()` keys capability enforcement on the
# PRESENCE of a file at `trust_root_path()`, so persisting an authority trust
# root there would collaterally flip entitlement enforcement ON with no grant
# minted — denying every gated capability (deep_static_analysis / active_recon /
# exploit_execution) on a fresh deploy the moment an authority is provisioned.
# Storing the authority root HERE keeps capability enforcement keyed ONLY on an
# operator's explicit entitlement provisioning (the `.entitlement/` flow), while
# the authority gate still finds + verifies its own trust root.
#
# Override the directory with VIGIL_AUTHORITY_ROOT_DIR so a deployment can keep
# the authority root on a read-only / HSM-fronted mount separate from the code
# tree (mirrors CRUCIBLE_ENTITLEMENT_DIR for the entitlement store). Gitignored.
# ---------------------------------------------------------------------------


def authority_root_dir() -> Path:
    override = os.environ.get("VIGIL_AUTHORITY_ROOT_DIR")
    if override:
        return Path(override).expanduser()
    return v2_root() / ".authority-root"


def authority_root_path() -> Path:
    return authority_root_dir() / "trust-root.json"


# ---------------------------------------------------------------------------
# Per-target paths
# ---------------------------------------------------------------------------


def target_dir(slug: str) -> Path:
    return targets_root() / slug


def charter_path(slug: str) -> Path:
    return target_dir(slug) / "charter.md"


def charter_draft_path(slug: str) -> Path:
    return target_dir(slug) / "charter.draft.md"


def threat_model_path(slug: str) -> Path:
    return target_dir(slug) / "threat-model.md"


def attack_tree_path(slug: str) -> Path:
    return target_dir(slug) / "attack-tree.md"


def engagement_log(slug: str) -> Path:
    return target_dir(slug) / "notes" / "engagement-log.md"


# ---------------------------------------------------------------------------
# D2 ephemeral / ZDR write-redirect. When an --ephemeral session is active,
# `common.ephemeral` sets a tmpfs base here for the session's lifetime. Only the
# per-engagement WRITE sinks that would otherwise land under the repo's `targets/`
# — the HTTP evidence archive and the engagement audit log — re-root under it, so an
# ephemeral run leaves NOTHING on the real disk. READ paths (charter/scope/threat-
# model) are deliberately NOT redirected: a ZDR run still reads its real charter and
# stays in-scope. Default None => byte-identical (every existing path is unchanged).
# ---------------------------------------------------------------------------

_EPHEMERAL_WRITE_ROOT: Path | None = None


def set_ephemeral_write_root(base: Path | None) -> None:
    """Set (or clear with None) the tmpfs base under which per-engagement write sinks are
    re-rooted for an ephemeral/ZDR session. `common.ephemeral` owns the lifecycle: it sets
    this on session enter and clears it on exit. Idempotent."""
    global _EPHEMERAL_WRITE_ROOT
    _EPHEMERAL_WRITE_ROOT = Path(base) if base is not None else None


def ephemeral_write_root() -> Path | None:
    """The active ephemeral write root, or None when persisting normally."""
    return _EPHEMERAL_WRITE_ROOT


def _write_target_dir(slug: str) -> Path:
    """The per-engagement WRITE base for ``slug``: the ephemeral tmpfs base when a ZDR/ephemeral
    session is active, else exactly ``target_dir(slug)`` — so the DEFAULT path is byte-identical
    (and honours any test/deployment override of ``target_dir``); only ephemeral re-roots."""
    if _EPHEMERAL_WRITE_ROOT is not None:
        return _EPHEMERAL_WRITE_ROOT / slug
    return target_dir(slug)


def evidence_dir(slug: str, action_id: str) -> Path:
    """The per-action HTTP evidence archive dir (request/response/body). Identical to
    ``target_dir(slug)/evidence/<action_id>`` when persisting; re-rooted under the ephemeral
    write base when a ZDR/ephemeral session is active — so captured HTTP (which can hold
    Authorization/Cookie headers + bodies) never touches the real disk in that mode."""
    return _write_target_dir(slug) / "evidence" / action_id


def evidence_archive_dir(slug: str) -> Path:
    """The per-engagement evidence ARCHIVE ROOT — the parent of every per-action
    ``evidence/<action_id>`` dir. This is the on-disk credential sink (raw
    Authorization/Cookie request lines + response bodies) that the W16-8 crypto-shred
    erasure operates over. Re-rooted under the ephemeral write base in a ZDR session
    exactly like ``evidence_dir``."""
    return _write_target_dir(slug) / "evidence"


# ---------------------------------------------------------------------------
# W16-8 — crypto-shredding keystore (right-to-erasure for append-only evidence).
#
# The event spine is append-only by DB trigger, so credential-bearing evidence
# written at-rest cannot be DELETED without breaking the append-only / tamper-
# evidence guarantee. The decision (ADR knowledge/decisions/0008) is to
# CRYPTO-SHRED: evidence is sealed under a per-engagement Data Encryption Key
# (DEK) that lives HERE — OUTSIDE the append-only spine — in a shreddable
# keystore. Erasure destroys the DEK; the ciphertext left behind (on disk, in
# backups, in a spine payload) becomes cryptographically unrecoverable while
# every append-only row and the spine hash-chain stay byte-for-byte unchanged.
#
# This directory therefore MUST be independently deletable and owner-only, and
# is NOT ephemeral-rerooted: a DEK has to survive the capturing session so an
# operator erasure request weeks later can still find and destroy it. Override
# with CRUCIBLE_EVIDENCE_KEYS_DIR to hold DEKs on a separate mount / HSM-fronted
# path away from the ciphertext they protect.
# ---------------------------------------------------------------------------


def evidence_keys_dir() -> Path:
    override = os.environ.get("CRUCIBLE_EVIDENCE_KEYS_DIR")
    if override:
        return Path(override).expanduser()
    return v2_root() / ".evidence-keys"


def crucible_v2_log(slug: str) -> Path:
    return _write_target_dir(slug) / ".crucible-v2.log"


def planner_state(slug: str) -> Path:
    return target_dir(slug) / ".planner-state.json"


def phase_ledger_path(slug: str) -> Path:
    """The append-only engagement PHASE LEDGER (``engage`` scanner-phase checkpoint +
    ``--resume``). One JSON record per line: each phase's started / completed / skipped /
    failed. Re-rooted under the ephemeral write base in a ZDR session exactly like the
    evidence archive, so an ephemeral run's checkpoint is purged on exit (resume is a
    persist-by-default feature). Default path is byte-identical (honours a test override
    of ``target_dir``)."""
    return _write_target_dir(slug) / f"{slug}.phases.jsonl"


def phase_report_path(slug: str) -> Path:
    """The durable ScanReport SNAPSHOT the phase ledger writes when the scan phase
    completes, so a ``--resume`` re-run can SKIP the (traffic-sending) scan and reload the
    authoritative report instead of re-crawling/re-auditing the target. Re-rooted under the
    ephemeral write base like the ledger. Owner-only on disk (it holds finding evidence)."""
    return _write_target_dir(slug) / f"{slug}.report.json"


def endpoints_path(slug: str) -> Path:
    return target_dir(slug) / "notes" / "endpoints.md"


def fingerprint_path(slug: str) -> Path:
    return target_dir(slug) / "recon" / "fingerprint.json"


# ---------------------------------------------------------------------------
# Containment check used by ethics gates
# ---------------------------------------------------------------------------


def is_within(child: Path, parent: Path) -> bool:
    """True iff child resolves inside parent. Used to refuse writes
    outside the engagement directory."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False
