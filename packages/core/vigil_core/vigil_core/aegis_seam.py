"""AEGIS seam layout + the DR backup-exclusion predicate (AS-2i).

The ONE canonical home for the AEGIS cross-plane seam subdirectory names and the default-OFF flag that makes
BOTH backup legs exclude AEGIS tenant-MONITORING state from disaster recovery, so a restored backup does NOT
resurrect monitoring (acceptance: a restore leaves AEGIS Off and inspects nothing).

WHY THIS LIVES IN ``vigil_core`` (FATAL-2). The sovereign plane (``apps/sigil``) PUBLISHES the owner-signed
monitoring authorities and provisions the per-(org, host) report secrets under ``<seam>/aegis/...``
(``sigil.config.monitoring_publish_dir`` / ``monitoring_secrets_dir``); the keyless offense engine's backup
(``vigil_integration.backup``) CAPTURES the whole seam (``vigil backup --base-dir`` = the seam base) and would
otherwise carry those publications off-host. Both planes must agree on the subdir names and the flag WITHOUT
importing each other, so the constant + predicate live in this shared leaf — stdlib only, no ``sigil.*``, no
``framework.*`` — exactly like :mod:`vigil_core.seam_base`, which resolves the seam BASE this layout hangs off.

WHY EXCLUDING IT LOSES NO RECOVERY STATE. The published monitoring authorities are a MIRROR of the sovereign
spine-of-record (``governor.monitoring_authority``, itself captured): restoring an old published artifact would
RESURRECT a grant the spine has since revoked (the artifact verifies on signature + window alone, so the
keyless gateway would honor it until ``not_after``). The report secrets are re-provisionable. So dropping the
whole ``aegis/`` seam subtree from a backup is the SAFE direction — the sovereign re-derives + re-publishes
after a restore, gated on fresh consent (the full restore drill lands with legal-gov S1).

DEFAULT-OFF, BYTE-IDENTICAL WHEN OFF (mirrors ``framework.v2.aegis.gateway._saas_enforce_flag`` /
``sigil.config.redpen_enabled``): with ``VIGIL_AEGIS_BACKUP_EXCLUDE`` unset the predicate is inert and both legs
capture/restore exactly as before. In a default build AEGIS monitoring is itself OFF so no ``aegis/`` seam dir
exists and the flag changes nothing either way; it bites only where AEGIS monitoring is enabled (its
publications present) AND the flag is set — wired at AEGIS go-live / the S1 restore drill.

FAIL-CLOSED. When enabled the predicate excludes the ENTIRE ``aegis/`` seam subtree — every known subdir
(``monitoring_authority``, ``report_secrets``) AND any future/unknown entry under it — so a new monitoring
artifact is excluded by default, never silently carried into a backup.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

#: The AEGIS seam subtree, directly under the cross-plane seam base (:func:`vigil_core.seam_base.resolve_seam_base`):
#: ALL tenant-monitoring state the sovereign publishes for the keyless gateway. Excluded wholesale from DR.
AEGIS_SEAM_SUBDIR = "aegis"
#: Children of ``aegis/`` — named here so the sovereign publish/secrets dirs and the gateway read-path share ONE
#: source of truth for the layout. The exclusion predicate matches the whole ``aegis/`` subtree, not only these.
MONITORING_AUTHORITY_SUBDIR = "monitoring_authority"
REPORT_SECRETS_SUBDIR = "report_secrets"

#: Strict, fail-closed, DEFAULT-OFF flag turning on the AEGIS DR backup exclusion in BOTH backup legs.
AEGIS_BACKUP_EXCLUDE_ENV = "VIGIL_AEGIS_BACKUP_EXCLUDE"
#: The only tokens that read as affirmative (case-insensitive); matches the project's other strict env gates.
_AFFIRMATIVE = frozenset({"1", "true", "yes", "on", "enabled"})


def aegis_backup_exclude_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """True iff AEGIS tenant-monitoring state must be EXCLUDED from a backup (both legs).

    Strict, fail-closed, DEFAULT OFF: only an explicit affirmative token turns it on; an unset or mistyped value
    keeps it off (so an unset flag is BYTE-IDENTICAL to the pre-AS-2i behaviour). ``env`` defaults to
    ``os.environ``; pass a mapping to make a caller deterministic/testable."""
    e = os.environ if env is None else env
    return (e.get(AEGIS_BACKUP_EXCLUDE_ENV, "") or "").strip().lower() in _AFFIRMATIVE


def is_aegis_monitoring_seam_rel(rel: str) -> bool:
    """True iff seam-relative path ``rel`` is AEGIS tenant-monitoring state — i.e. its FIRST path segment is the
    ``aegis/`` seam subtree.

    FAIL-CLOSED by whole-subtree match: every current subdir (``monitoring_authority``, ``report_secrets``) and
    any future one under ``aegis/`` is caught, so a new monitoring artifact is excluded, not accidentally
    captured. A ``\\`` is treated as a separator too (backup rels are normalized posix, but be robust to a
    Windows-shaped source rel — the same posture as the backup path-escape guard)."""
    first = rel.replace("\\", "/").split("/", 1)[0]
    return first == AEGIS_SEAM_SUBDIR
