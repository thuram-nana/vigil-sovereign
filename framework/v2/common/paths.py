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


def crucible_v2_log(slug: str) -> Path:
    return target_dir(slug) / ".crucible-v2.log"


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
