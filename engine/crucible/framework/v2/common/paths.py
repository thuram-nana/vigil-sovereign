"""
common.paths — path-portable resolution of CRUCIBLE_ROOT.

The framework can live anywhere on disk. Every subsystem resolves
paths through this module rather than hard-coding. Discovery order:

  1. CRUCIBLE_ROOT env var (validated: must contain CLAUDE.md).
  2. Walk up from the running script until CLAUDE.md is found.
  3. Walk up from this module's location.
  4. Walk up from CWD.
  5. Fail with CrucibleRootNotFound.

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
    if sys.argv and sys.argv[0]:
        candidates.append(Path(sys.argv[0]).parent)
    candidates.append(Path(__file__).parent)
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


def crucible_v2_log(slug: str) -> Path:
    return _write_target_dir(slug) / ".crucible-v2.log"


def planner_state(slug: str) -> Path:
    return target_dir(slug) / ".planner-state.json"


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
