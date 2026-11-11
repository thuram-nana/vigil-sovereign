"""#70 — `vigil doctor` flags (ADVISORY) when the cross-plane MONEY SEAM is not inside what the offense backup
captures. The seam (leases + settlement + pause markers) is deliberately excluded from the sovereign `sigil backup`
(cross-plane: it also holds offense keys), so it is covered ONLY if `vigil-backup.service`'s VIGIL_BASE_DIR is the
seam or contains it. DEFAULT-OFF: evaluated only once the settle drain is configured; never an issue / `ok` flip."""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration import doctor as _doc

_REPO = Path(_doc.__file__).resolve().parents[2]


def _cfg(home: Path, settle=None, backup=None) -> None:
    d = home / ".config" / "vigil"
    d.mkdir(parents=True, exist_ok=True)
    if settle is not None:
        (d / "settle-drain.env").write_text(settle)
    if backup is not None:
        (d / "backup.env").write_text(backup)


def test_not_configured_is_silent(tmp_path):
    sec, notes = _doc._money_seam_backup_coverage(tmp_path)
    assert sec == {"configured": False} and notes == []


def test_backup_of_the_seam_itself_is_covered(tmp_path):
    seam = tmp_path / ".sigil" / "credit-lease"
    _cfg(tmp_path, settle=f"VIGIL_SETTLE_BASE_DIR={seam}\n", backup=f"VIGIL_BASE_DIR={seam}\n")
    sec, notes = _doc._money_seam_backup_coverage(tmp_path)
    assert sec["covered"] is True and notes == []


def test_backup_of_a_parent_of_the_seam_is_covered(tmp_path):
    _cfg(tmp_path, settle="# default seam\n", backup=f'VIGIL_BASE_DIR="{tmp_path / ".sigil"}"\n')
    sec, notes = _doc._money_seam_backup_coverage(tmp_path)          # default seam = ~/.sigil/credit-lease
    assert sec["covered"] is True and notes == []


def test_the_shipped_defaults_do_not_cover_the_seam_and_say_so(tmp_path):
    _cfg(tmp_path, settle="VIGIL_SETTLE_SCOPE=*\n", backup="VIGIL_BACKUP_PASSPHRASE=x\nVIGIL_BASE_DIR=.vigil-live\n")
    sec, notes = _doc._money_seam_backup_coverage(tmp_path)
    assert sec["covered"] is False
    assert sec["backup_base_dir"].endswith("vigil/.vigil-live")       # relative ⇒ the unit's WorkingDirectory
    assert len(notes) == 1 and "NOT inside the offense backup" in notes[0]
    assert "VIGIL_BACKUP_PASSPHRASE" not in repr(sec) and "=x" not in notes[0]   # the passphrase never surfaces


def test_no_backup_configured_at_all_is_called_out(tmp_path):
    _cfg(tmp_path, settle="")
    sec, notes = _doc._money_seam_backup_coverage(tmp_path)
    assert sec["covered"] is False and "backed up by NOTHING" in notes[0]


@pytest.mark.parametrize("raw,expected", [
    ("A=1\n# B=2\n\nC='three'\nD=\"four\"\nnot a pair\n", {"A": "1", "C": "three", "D": "four"}),
])
def test_env_file_parser(tmp_path, raw, expected):
    p = tmp_path / "x.env"
    p.write_text(raw)
    assert _doc._parse_env_file(p) == expected
    assert _doc._parse_env_file(tmp_path / "absent.env") is None


def test_doctor_surfaces_it_as_an_advisory_note_never_an_issue(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SIGIL_HOME", str(home / ".sigil"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    (tmp_path / "base").mkdir()
    baseline = _doc.collect(_REPO)
    assert baseline["money_seam_backup"] == {"configured": False}
    _cfg(home, settle="", backup="VIGIL_BASE_DIR=.vigil-live\n")
    report = _doc.collect(_REPO)
    assert any("money seam" in n for n in report["notes"])
    assert not any("money seam" in i for i in report["issues"]) and report["issues"] == baseline["issues"]
