"""AS-2i — the canonical AEGIS seam layout + the DEFAULT-OFF DR backup-exclusion predicate shared by BOTH
backup legs (offense ``vigil_integration.backup`` + sovereign ``sigil.backup``). Pure + deterministic: no I/O,
no wallclock, no RNG — safe on a signed path.

    PYTHONPATH=packages/core/vigil_core python -m pytest packages/core/vigil_core/tests/test_aegis_seam.py -q
"""
from __future__ import annotations

from vigil_core.aegis_seam import (
    AEGIS_BACKUP_EXCLUDE_ENV,
    AEGIS_SEAM_SUBDIR,
    MONITORING_AUTHORITY_SUBDIR,
    REPORT_SECRETS_SUBDIR,
    aegis_backup_exclude_enabled,
    is_aegis_monitoring_seam_rel,
)


def test_flag_is_default_off_and_strict() -> None:
    assert aegis_backup_exclude_enabled({}) is False                 # unset → OFF → byte-identical to pre-AS-2i
    assert aegis_backup_exclude_enabled() in (True, False)           # reads os.environ without raising
    for tok in ("1", "true", "TRUE", "yes", "on", "enabled", "  On  "):
        assert aegis_backup_exclude_enabled({AEGIS_BACKUP_EXCLUDE_ENV: tok}) is True, tok
    for tok in ("", "0", "false", "no", "off", "disabled", "nope", "2", "y"):
        assert aegis_backup_exclude_enabled({AEGIS_BACKUP_EXCLUDE_ENV: tok}) is False, tok


def test_predicate_matches_the_whole_aegis_subtree_fail_closed() -> None:
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}/{MONITORING_AUTHORITY_SUBDIR}/deadbeef.json")
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}/{REPORT_SECRETS_SUBDIR}/deadbeef.json")
    # fail-closed: an unknown/future subdir under aegis/ is STILL excluded, not silently captured.
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}/a-future-monitoring-artifact/x")
    assert is_aegis_monitoring_seam_rel(AEGIS_SEAM_SUBDIR)                      # the dir itself
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}\\report_secrets\\x")   # backslash separator too


def test_predicate_does_not_over_match() -> None:
    assert not is_aegis_monitoring_seam_rel("leases/eng-x.json")
    assert not is_aegis_monitoring_seam_rel("aegis-sibling/x")      # a different top-level dir, not aegis/
    assert not is_aegis_monitoring_seam_rel("jobs/aegis/x")         # aegis is NOT the first segment
    assert not is_aegis_monitoring_seam_rel("")
