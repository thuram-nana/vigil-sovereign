"""AEGIS seam layout + the DR backup-exclusion predicate (AS-2i).

The ONE canonical home for the AEGIS cross-plane seam subdirectory names and the UNCONDITIONAL rule that makes
BOTH backup legs exclude AEGIS tenant-MONITORING state from disaster recovery, so a restored backup does NOT
resurrect monitoring (acceptance: a restore leaves AEGIS Off and inspects nothing).

WHY THIS LIVES IN ``vigil_core`` (FATAL-2). The sovereign plane (``apps/sigil``) PUBLISHES the owner-signed
monitoring authorities and provisions the per-(org, host) report secrets under ``<seam>/aegis/...``
(``sigil.config.monitoring_publish_dir`` / ``monitoring_secrets_dir``); the keyless offense engine's backup
(``vigil_integration.backup``) CAPTURES the whole seam (``vigil backup --base-dir`` = the seam base) and would
otherwise carry those publications off-host. Both planes must agree on the subdir names and the override env
WITHOUT importing each other, so the constants + predicate live in this shared leaf — stdlib only, no ``sigil.*``,
no ``framework.*`` — exactly like :mod:`vigil_core.seam_base`, which resolves the seam BASE this layout hangs off.
Crucially the offense backup layer MUST NOT import ``sigil.config`` (FATAL-2), so this module re-derives the SAME
publish/secrets locations ``sigil.config`` does, from the base dir + the same override env vars, keeping the two
in lockstep (``sigil.config`` imports these very env-name constants, so they cannot drift).

WHY EXCLUDING IT LOSES NO RECOVERY STATE. The published monitoring authorities are a MIRROR of the sovereign
spine-of-record (``governor.monitoring_authority``, itself captured): restoring an old published artifact would
RESURRECT a grant the spine has since revoked (the artifact verifies on signature + window alone, so the
keyless gateway would honor it until ``not_after``). The report secrets are re-provisionable. So dropping the
whole monitoring subtree from a backup is the SAFE direction — the sovereign re-derives + re-publishes after a
restore, gated on fresh consent (the full restore drill lands with legal-gov S1).

UNCONDITIONAL — NOT OPT-IN (AS-2i red-pen MEDIUM #1). This is a SAFETY exclusion, not a feature: it must bite in
EVERY shipped AEGIS-enabled build, so there is no flag to turn it off. In a default build AEGIS monitoring is
itself OFF so no monitoring dir exists and the exclusion is a no-op either way; it bites exactly where AEGIS
monitoring is enabled (its publications present). Both legs exclude the SAME subtree with no gate — the
sovereign leg by never capturing it (allowlist capture / ``EXCLUDED_TOP_LEVEL`` classification), the offense leg
by this predicate on its capture + restore walk.

FAIL-CLOSED, AND CONFIGURATION-AWARE (AS-2i red-pen MEDIUM #2). The exclusion matches the ENTIRE default
``aegis/`` seam subtree — every known subdir (``monitoring_authority``, ``report_secrets``) AND any future/
unknown entry under it — so a new monitoring artifact is excluded by default, never silently carried into a
backup. AND, because the publish/secrets dirs are CONFIGURABLE (``VIGIL_MONITORING_PUBLISH_DIR`` /
``VIGIL_MONITORING_SECRETS_DIR``), the exclusion also covers whatever location the current config resolves them
to UNDER the captured base — keyed off the ACTUAL configured dirs, not only the literal ``aegis`` segment, so an
operator's non-default dir cannot let the authorities ride off-host.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import FrozenSet, Mapping, Optional, Tuple

#: The AEGIS seam subtree, directly under the cross-plane seam base (:func:`vigil_core.seam_base.resolve_seam_base`):
#: ALL tenant-monitoring state the sovereign publishes for the keyless gateway. Excluded wholesale from DR.
AEGIS_SEAM_SUBDIR = "aegis"
#: Children of ``aegis/`` — named here so the sovereign publish/secrets dirs and the gateway read-path share ONE
#: source of truth for the layout. The exclusion matches the whole ``aegis/`` subtree, not only these.
MONITORING_AUTHORITY_SUBDIR = "monitoring_authority"
REPORT_SECRETS_SUBDIR = "report_secrets"

#: The env overrides for the sovereign monitoring publish/secrets dirs. SINGLE source of truth: ``sigil.config``
#: imports these so the two cannot drift, and the offense backup leg (which must not import ``sigil.config`` —
#: FATAL-2) re-derives the SAME locations from them in :func:`resolve_monitoring_dirs`.
MONITORING_PUBLISH_DIR_ENV = "VIGIL_MONITORING_PUBLISH_DIR"
MONITORING_SECRETS_DIR_ENV = "VIGIL_MONITORING_SECRETS_DIR"


def resolve_monitoring_dirs(
    base: os.PathLike[str] | str, env: Optional[Mapping[str, str]] = None
) -> Tuple[Path, Path]:
    """Resolve ``(publish_dir, secrets_dir)`` the sovereign uses for AEGIS monitoring, WITHOUT importing
    ``sigil.config`` (FATAL-2 — the offense backup layer must stay free of ``sigil.*``).

    Mirrors :func:`sigil.config.monitoring_publish_dir` / :func:`sigil.config.monitoring_secrets_dir` exactly:
    the ``VIGIL_MONITORING_PUBLISH_DIR`` / ``VIGIL_MONITORING_SECRETS_DIR`` override wins; else the default under
    ``base`` — the cross-plane seam base both legs agree on (= the offense backup's ``--base-dir``), which is what
    ``sigil.config._seam_base()`` resolves to. ``env`` defaults to ``os.environ``; pass a mapping to make a caller
    deterministic/testable. Lexical only (no stat/readlink of the backup tree) → safe on a signed path."""
    e = os.environ if env is None else env
    base_abs = os.path.abspath(os.fspath(base))
    pub = (e.get(MONITORING_PUBLISH_DIR_ENV, "") or "").strip()
    sec = (e.get(MONITORING_SECRETS_DIR_ENV, "") or "").strip()
    publish = Path(pub) if pub else Path(base_abs) / AEGIS_SEAM_SUBDIR / MONITORING_AUTHORITY_SUBDIR
    secrets = Path(sec) if sec else Path(base_abs) / AEGIS_SEAM_SUBDIR / REPORT_SECRETS_SUBDIR
    return publish, secrets


def aegis_monitoring_exclusion(
    base: os.PathLike[str] | str, env: Optional[Mapping[str, str]] = None
) -> FrozenSet[str]:
    """The set of base-relative POSIX path PREFIXES a backup of ``base`` must EXCLUDE as AEGIS tenant-monitoring
    state. Pass the result to :func:`is_aegis_monitoring_seam_rel`; compute it ONCE per backup (deterministic
    within one backup).

    Always includes the default ``aegis/`` seam subtree (fail-closed: unknown future entries under it are caught).
    PLUS the base-relative form of the CONFIGURED publish/secrets dirs when an override
    (``VIGIL_MONITORING_PUBLISH_DIR`` / ``VIGIL_MONITORING_SECRETS_DIR``) places them elsewhere UNDER ``base`` —
    so an operator's non-default monitoring dir is excluded too, not silently captured (red-pen MEDIUM #2). An
    override OUTSIDE ``base`` is never captured by this leg, so it needs no skip; an override that IS ``base``
    (degenerate) is ignored rather than excluding the whole backup. Returned as a MINIMAL cover (a prefix already
    covered by a shorter one is dropped — e.g. the DEFAULT publish/secrets dirs collapse back into the plain
    ``aegis/`` subtree). Lexical path math only (no stat/readlink) → deterministic + safe on a signed path."""
    candidates = {AEGIS_SEAM_SUBDIR}
    base_abs = os.path.abspath(os.fspath(base))
    for d in resolve_monitoring_dirs(base, env):
        d_abs = os.path.abspath(os.fspath(d))
        rel = os.path.relpath(d_abs, base_abs)
        parts = rel.split(os.sep)
        if os.path.isabs(rel) or rel == os.curdir or parts[0] == os.pardir:
            continue   # the configured dir is OUTSIDE (or IS) base → nothing captured here to skip
        candidates.add(PurePosixPath(*parts).as_posix())

    def _covered(p: str, others: FrozenSet[str]) -> bool:
        p_segs = p.split("/")
        for o in others:
            if o == p:
                continue
            o_segs = o.split("/")
            if len(o_segs) <= len(p_segs) and p_segs[: len(o_segs)] == o_segs:
                return True
        return False

    frozen = frozenset(candidates)
    return frozenset(p for p in frozen if not _covered(p, frozen))


def is_aegis_monitoring_seam_rel(rel: str, exclusion: Optional[FrozenSet[str]] = None) -> bool:
    """True iff seam-relative path ``rel`` is AEGIS tenant-monitoring state that must be EXCLUDED from a backup.

    ``exclusion`` is the prefix set from :func:`aegis_monitoring_exclusion` (the default ``aegis/`` subtree plus
    any configured publish/secrets override under the base). When omitted it defaults to the single default
    ``aegis/`` subtree — so the whole-subtree fail-closed match still holds with no base/config in hand.

    Matched by PATH SEGMENT prefix, never substring: ``aegis`` matches ``aegis/x`` and ``aegis`` itself but never
    ``aegis-sibling`` or ``jobs/aegis/x``. A ``\\`` is treated as a separator too (backup rels are normalized
    posix, but be robust to a Windows-shaped source rel — the same posture as the backup path-escape guard)."""
    if exclusion is None:
        exclusion = frozenset({AEGIS_SEAM_SUBDIR})
    segs = [s for s in rel.replace("\\", "/").split("/") if s]
    if not segs:
        return False
    for pre in exclusion:
        pre_segs = [s for s in pre.replace("\\", "/").split("/") if s]
        if pre_segs and segs[: len(pre_segs)] == pre_segs:
            return True
    return False
