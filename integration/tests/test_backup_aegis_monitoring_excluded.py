"""AS-2i — the OFFENSE backup never resurrects AEGIS tenant-MONITORING state (UNCONDITIONAL + config-aware).

The offense ``vigil backup --base-dir`` captures the cross-plane SEAM, where the sovereign publishes the
owner-signed monitoring authorities (``aegis/monitoring_authority/``) and the per-(org,host) report secrets
(``aegis/report_secrets/``). Those are a MIRROR of the sovereign spine-of-record, not offense recovery state:
carried off-host and restored, the published artifact verifies on signature + window alone, so the keyless
gateway would honor it until ``not_after`` — monitoring a restore must leave Off would come back On.

This is a SAFETY exclusion, not a feature, so it bites in EVERY build with NO flag (red-pen MEDIUM #1): the
whole monitoring subtree is dropped at capture AND skipped on restore (even from an archive made before the
exclusion) with the DEFAULT config and no env set, so a restored backup publishes NOTHING for the gateway to
inspect (acceptance: TT-A stays Off; nothing inspected). AND because the publish/secrets dirs are CONFIGURABLE
(``VIGIL_MONITORING_PUBLISH_DIR`` / ``VIGIL_MONITORING_SECRETS_DIR``), a non-default dir UNDER the base is
excluded too (red-pen MEDIUM #2) — keyed off the ACTUAL configured location, not just a literal ``aegis``
segment. Re-deriving + re-publishing the authorities under fresh consent on restore is the sovereign leg's job
and lands with legal-gov S1 — this proves the EXCLUSION leg only.

    PYTHONPATH="integration:engine/crucible:apps/sigil:gateway:packages/core/vigil_core:." \\
        .venv/bin/python -m pytest integration/tests/test_backup_aegis_monitoring_excluded.py -q
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")   # restore re-verifies the offense spine (like test_backup_roundtrip)

from test_backup_roundtrip import PW, _seed_offense_home

from vigil_core.aegis_seam import MONITORING_PUBLISH_DIR_ENV, MONITORING_SECRETS_DIR_ENV
from vigil_integration import backup as ob

# The sovereign's published monitoring state as the offense base_dir (= the seam) sees it: hashed (org,host)
# filenames under aegis/monitoring_authority + aegis/report_secrets, PLUS an unknown future subdir (fail-closed).
_AEGIS = (
    "aegis/monitoring_authority/" + "a" * 64 + ".json",
    "aegis/report_secrets/" + "b" * 64 + ".json",
    "aegis/some-future-monitoring-artifact/x.json",   # fail-closed: an unknown aegis entry is still excluded
)
# A non-aegis seam file that must ALWAYS round-trip — the control proving the exclusion is scoped to monitoring.
_CONTROL = "leases/eng-x.json"


def _seed(base: Path, rels) -> None:
    for rel in rels:
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text('{"monitoring": "state"}')


def _archive_file_rels(archive: Path, pw: str) -> set[str]:
    """The set of file rels the signed manifest actually PACKAGED — a direct capture-side view of what did (and
    did not) ride into the archive, decrypted the same way restore does."""
    salt, sealed = ob._read_header(archive)
    body = json.loads(ob.unseal(ob._derive_key(pw, salt), sealed, context=ob._BODY_CONTEXT))
    return set(body["manifest"]["file_sha256"].keys())


def test_unconditional_new_backup_leaves_the_aegis_seam_out(tmp_path, monkeypatch):
    # DEFAULT config, NO flag/env set at all — the exclusion must still bite (it is not opt-in).
    monkeypatch.delenv("VIGIL_AEGIS_BACKUP_EXCLUDE", raising=False)   # even the long-gone flag: no effect
    monkeypatch.delenv(MONITORING_PUBLISH_DIR_ENV, raising=False)
    monkeypatch.delenv(MONITORING_SECRETS_DIR_ENV, raising=False)
    base = tmp_path / "base"
    _seed_offense_home(base)
    _seed(base, _AEGIS + (_CONTROL,))

    ob.create_offense_backup(tmp_path / "o.vglbk", PW, base_dir=str(base))
    packaged = _archive_file_rels(tmp_path / "o.vglbk", PW)
    assert not (packaged & set(_AEGIS))        # never even captured → cannot ride off-host
    assert _CONTROL in packaged                # the rest of the seam is still captured

    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "o.vglbk", str(new_base), PW)
    assert not any((new_base / rel).exists() for rel in _AEGIS)       # nothing published → nothing inspected
    assert not (new_base / "aegis").exists()
    assert (new_base / _CONTROL).is_file()                            # the rest of the seam still recovers


def test_configured_non_default_publish_dir_is_excluded(tmp_path, monkeypatch):
    # An operator points the monitoring dirs at NON-default names UNDER the base. The exclusion keys off the
    # ACTUAL configured location (not the literal 'aegis' segment), so these ride nowhere either. (Mutation note:
    # against a predicate that only matched 'aegis', custom-pub/custom-sec WOULD be captured + restored.)
    base = tmp_path / "base"
    pub_rel, sec_rel = "custom-pub", "nested/custom-sec"
    monkeypatch.setenv(MONITORING_PUBLISH_DIR_ENV, str(base / pub_rel))
    monkeypatch.setenv(MONITORING_SECRETS_DIR_ENV, str(base / sec_rel))
    _seed_offense_home(base)
    configured = (f"{pub_rel}/" + "a" * 64 + ".json", f"{sec_rel}/" + "b" * 64 + ".json")
    # seed BOTH the configured dirs AND the default aegis/ dir (default stays excluded belt-and-braces) + control
    _seed(base, configured + _AEGIS + (_CONTROL,))

    ob.create_offense_backup(tmp_path / "o.vglbk", PW, base_dir=str(base))
    packaged = _archive_file_rels(tmp_path / "o.vglbk", PW)
    assert not (packaged & set(configured))    # the CONFIGURED monitoring dirs were excluded at capture
    assert not (packaged & set(_AEGIS))        # the default aegis/ subtree is excluded too
    assert _CONTROL in packaged                # a non-monitoring sibling under the same base still round-trips

    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "o.vglbk", str(new_base), PW)
    assert not any((new_base / rel).exists() for rel in configured + _AEGIS)
    assert (new_base / _CONTROL).is_file()


def test_restore_skips_the_aegis_seam_in_an_older_archive(tmp_path, monkeypatch):
    # An archive made BEFORE the exclusion existed still carries the aegis seam. Simulate it by capturing with
    # the exclusion neutralised; the REAL, unconditional restore skip must still leave monitoring out — verified
    # (tamper check) against the signed manifest, never written. DR-correct: a restore cannot resurrect a
    # since-revoked authority.
    base = tmp_path / "base"
    _seed_offense_home(base)
    _seed(base, _AEGIS + (_CONTROL,))
    monkeypatch.setattr(ob, "aegis_monitoring_exclusion", lambda *a, **k: frozenset())
    ob.create_offense_backup(tmp_path / "old.vglbk", PW, base_dir=str(base))
    assert set(_AEGIS) <= _archive_file_rels(tmp_path / "old.vglbk", PW)   # the old archive DOES carry them
    monkeypatch.undo()                                                     # restore uses the real exclusion

    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "old.vglbk", str(new_base), PW)
    assert not any((new_base / rel).exists() for rel in _AEGIS)            # skipped on restore, never written
    assert (new_base / _CONTROL).is_file()
