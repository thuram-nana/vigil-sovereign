"""AS-2i — the canonical AEGIS seam layout + the UNCONDITIONAL, CONFIG-AWARE DR backup-exclusion shared by BOTH
backup legs (offense ``vigil_integration.backup`` + sovereign ``sigil.backup``). Pure + deterministic: lexical
path math only (no stat/readlink, no wallclock, no RNG) — safe on a signed path.

    PYTHONPATH=packages/core/vigil_core python -m pytest packages/core/vigil_core/tests/test_aegis_seam.py -q
"""
from __future__ import annotations

from pathlib import Path

from vigil_core.aegis_seam import (
    AEGIS_SEAM_SUBDIR,
    MONITORING_AUTHORITY_SUBDIR,
    MONITORING_PUBLISH_DIR_ENV,
    MONITORING_SECRETS_DIR_ENV,
    REPORT_SECRETS_SUBDIR,
    aegis_monitoring_exclusion,
    is_aegis_monitoring_seam_rel,
    resolve_monitoring_dirs,
)


def test_predicate_matches_the_whole_aegis_subtree_fail_closed() -> None:
    # No exclusion arg → the default ``aegis/`` subtree, whole-subtree match.
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}/{MONITORING_AUTHORITY_SUBDIR}/deadbeef.json")
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}/{REPORT_SECRETS_SUBDIR}/deadbeef.json")
    # fail-closed: an unknown/future subdir under aegis/ is STILL excluded, not silently captured.
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}/a-future-monitoring-artifact/x")
    assert is_aegis_monitoring_seam_rel(AEGIS_SEAM_SUBDIR)                      # the dir itself
    assert is_aegis_monitoring_seam_rel(f"{AEGIS_SEAM_SUBDIR}\\report_secrets\\x")   # backslash separator too


def test_predicate_does_not_over_match() -> None:
    assert not is_aegis_monitoring_seam_rel("leases/eng-x.json")
    assert not is_aegis_monitoring_seam_rel("aegis-sibling/x")      # a different top-level dir, not aegis/ (segment, not substring)
    assert not is_aegis_monitoring_seam_rel("jobs/aegis/x")         # aegis is NOT the first segment
    assert not is_aegis_monitoring_seam_rel("")


def test_resolve_monitoring_dirs_mirrors_config_default_and_override() -> None:
    base = Path("/srv/seam")
    # default: under base, matching sigil.config.monitoring_publish_dir / monitoring_secrets_dir
    pub, sec = resolve_monitoring_dirs(base, env={})
    assert pub == base / AEGIS_SEAM_SUBDIR / MONITORING_AUTHORITY_SUBDIR
    assert sec == base / AEGIS_SEAM_SUBDIR / REPORT_SECRETS_SUBDIR
    # override wins (verbatim), exactly like config
    env = {MONITORING_PUBLISH_DIR_ENV: "/srv/seam/custom-pub", MONITORING_SECRETS_DIR_ENV: "/elsewhere/sec"}
    pub, sec = resolve_monitoring_dirs(base, env=env)
    assert pub == Path("/srv/seam/custom-pub")
    assert sec == Path("/elsewhere/sec")


def test_exclusion_is_always_the_default_aegis_subtree() -> None:
    # No override → just the default ``aegis/`` subtree (unconditional; no flag involved).
    excl = aegis_monitoring_exclusion("/srv/seam", env={})
    assert excl == frozenset({AEGIS_SEAM_SUBDIR})
    assert is_aegis_monitoring_seam_rel("aegis/monitoring_authority/x.json", excl)
    assert not is_aegis_monitoring_seam_rel("leases/x.json", excl)


def test_exclusion_covers_a_configured_dir_under_base_fail_closed() -> None:
    base = "/srv/seam"
    env = {
        MONITORING_PUBLISH_DIR_ENV: "/srv/seam/custom-pub",     # non-default name, UNDER base
        MONITORING_SECRETS_DIR_ENV: "/srv/seam/nested/sec",     # UNDER base, nested
    }
    excl = aegis_monitoring_exclusion(base, env=env)
    assert AEGIS_SEAM_SUBDIR in excl                            # default subtree STILL excluded (belt + braces)
    assert "custom-pub" in excl
    assert "nested/sec" in excl
    # the configured monitoring dirs are now caught by the predicate — not just the literal 'aegis' segment
    assert is_aegis_monitoring_seam_rel("custom-pub/" + "a" * 64 + ".json", excl)
    assert is_aegis_monitoring_seam_rel("nested/sec/" + "b" * 64 + ".json", excl)
    assert is_aegis_monitoring_seam_rel("aegis/monitoring_authority/x", excl)   # default still excluded too
    # a sibling that merely shares a prefix name is NOT over-matched (segment match, not substring)
    assert not is_aegis_monitoring_seam_rel("custom-pub-sibling/x", excl)
    assert not is_aegis_monitoring_seam_rel("nested/secrets-not-ours/x", excl)
    assert not is_aegis_monitoring_seam_rel("leases/eng-x.json", excl)


def test_exclusion_ignores_a_configured_dir_outside_base() -> None:
    # An override OUTSIDE the captured base is never captured by this leg, so it adds no prefix (and must not
    # accidentally exclude the whole backup). Only the default ``aegis/`` subtree remains.
    excl = aegis_monitoring_exclusion("/srv/seam", env={MONITORING_PUBLISH_DIR_ENV: "/var/monitoring"})
    assert excl == frozenset({AEGIS_SEAM_SUBDIR})
    # a degenerate override that IS the base must be ignored, not turned into a match-everything prefix
    excl_base = aegis_monitoring_exclusion("/srv/seam", env={MONITORING_PUBLISH_DIR_ENV: "/srv/seam"})
    assert excl_base == frozenset({AEGIS_SEAM_SUBDIR})
    assert not is_aegis_monitoring_seam_rel("leases/eng-x.json", excl_base)
