"""AS-2i — the OFFENSE backup never resurrects AEGIS tenant-MONITORING state.

The offense ``vigil backup --base-dir`` captures the cross-plane SEAM, where the sovereign publishes the
owner-signed monitoring authorities (``aegis/monitoring_authority/``) and the per-(org,host) report secrets
(``aegis/report_secrets/``). Those are a MIRROR of the sovereign spine-of-record, not offense recovery state:
carried off-host and restored, the published artifact verifies on signature + window alone, so the keyless
gateway would honor it until ``not_after`` — monitoring a restore must leave Off would come back On.

With ``VIGIL_AEGIS_BACKUP_EXCLUDE`` set, the whole ``aegis/`` subtree is dropped at capture AND skipped on
restore (even from an archive made before the exclusion), so a restored backup publishes NOTHING for the
gateway to inspect (acceptance: TT-A stays Off; nothing inspected). With the flag OFF the backup is
byte-identical to the pre-AS-2i behaviour. Re-deriving + re-publishing the authorities under fresh consent on
restore is the sovereign leg's job and lands with legal-gov S1 — this proves the EXCLUSION leg only.

    PYTHONPATH="integration:engine/crucible:apps/sigil:gateway:packages/core/vigil_core:." \\
        .venv/bin/python -m pytest integration/tests/test_backup_aegis_monitoring_excluded.py -q
"""
from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.evidence.cli")   # restore re-verifies the offense spine (like test_backup_roundtrip)

from test_backup_roundtrip import PW, _seed_offense_home

from vigil_core.aegis_seam import AEGIS_BACKUP_EXCLUDE_ENV
from vigil_integration import backup as ob

# The sovereign's published monitoring state as the offense base_dir (= the seam) sees it: hashed (org,host)
# filenames under aegis/monitoring_authority + aegis/report_secrets, PLUS an unknown future subdir (fail-closed).
_AEGIS = (
    "aegis/monitoring_authority/" + "a" * 64 + ".json",
    "aegis/report_secrets/" + "b" * 64 + ".json",
    "aegis/some-future-monitoring-artifact/x.json",   # fail-closed: an unknown aegis entry is still excluded
)
# A non-aegis seam file that must ALWAYS round-trip — the control proving the exclusion is scoped to aegis/.
_CONTROL = "leases/eng-x.json"


def _seed_aegis_seam(base) -> None:
    for rel in _AEGIS + (_CONTROL,):
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text('{"monitoring": "state"}')


def test_flag_on_a_new_backup_leaves_the_aegis_seam_out(tmp_path, monkeypatch):
    monkeypatch.setenv(AEGIS_BACKUP_EXCLUDE_ENV, "1")
    base = tmp_path / "base"
    _seed_offense_home(base)
    _seed_aegis_seam(base)
    ob.create_offense_backup(tmp_path / "o.vglbk", PW, base_dir=str(base))
    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "o.vglbk", str(new_base), PW)
    assert not any((new_base / rel).exists() for rel in _AEGIS)       # nothing published → nothing inspected
    assert not (new_base / "aegis").exists()
    assert (new_base / _CONTROL).is_file()                            # the rest of the seam still recovers


def test_flag_off_is_byte_identical_the_seam_is_captured(tmp_path, monkeypatch):
    monkeypatch.delenv(AEGIS_BACKUP_EXCLUDE_ENV, raising=False)       # DEFAULT OFF
    base = tmp_path / "base"
    _seed_offense_home(base)
    _seed_aegis_seam(base)
    ob.create_offense_backup(tmp_path / "o.vglbk", PW, base_dir=str(base))
    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "o.vglbk", str(new_base), PW)
    assert all((new_base / rel).is_file() for rel in _AEGIS)          # unchanged from before AS-2i
    assert (new_base / _CONTROL).is_file()


def test_restore_skips_the_aegis_seam_in_an_older_archive(tmp_path, monkeypatch):
    # An archive made BEFORE the exclusion (flag off at backup time) still carries the aegis seam; restoring it
    # WITH the flag on must still leave monitoring out — verified (tamper check) against the signed manifest,
    # never written. This is the DR-correct direction: a restore cannot resurrect a since-revoked authority.
    base = tmp_path / "base"
    _seed_offense_home(base)
    _seed_aegis_seam(base)
    monkeypatch.delenv(AEGIS_BACKUP_EXCLUDE_ENV, raising=False)
    ob.create_offense_backup(tmp_path / "old.vglbk", PW, base_dir=str(base))
    monkeypatch.setenv(AEGIS_BACKUP_EXCLUDE_ENV, "1")
    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "old.vglbk", str(new_base), PW)
    assert not any((new_base / rel).exists() for rel in _AEGIS)
    assert (new_base / _CONTROL).is_file()
