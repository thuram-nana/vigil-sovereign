"""E3a — `vigil doctor` REFUSES (a HARD issue, `ok` False) when the configured money-seam units disagree on the
seam base. A lease the cockpit publishes in one tree is never seen by a drain reading another: every completion
becomes a no-op (credits held), a cancel's started-check + settlement marker land in another tree, and backups
miss the live one. The check reconstructs each unit's process environment from the unit text the way systemd
does (Environment= expands %h, EnvironmentFile values are literal and override it, WorkingDirectory anchors a
relative value, ExecStart's --base-dir ${VAR} wins) and the shared resolver picks. DEFAULT-OFF: a host with no
installed seam unit and none of their env files reports nothing.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the disagreement ``> 1`` check (→ ``> 99``)            -> test_an_env_file_override_on_one_unit_is_a_hard_issue
  * the legacy-alias contradiction check                   -> test_a_retired_settle_base_naming_another_tree_is_hard
  * %h expansion in Environment= (``_spec``)               -> test_the_shipped_units_agree_when_installed
  * env files override Environment=                        -> test_an_env_file_override_on_one_unit_is_a_hard_issue
  * WorkingDirectory anchors a relative value              -> test_a_relative_value_resolves_against_the_working_dir
  * --base-dir ${VAR} on ExecStart wins                    -> test_the_pre_e3a_unit_shapes_disagree
  * realpath compare (a symlinked spelling is the same)    -> test_a_symlinked_spelling_of_the_same_dir_agrees
  * configured = installed or env file present             -> test_nothing_configured_reports_nothing
  * doctor wiring ``_issue`` (→ ``_note``)                  -> test_doctor_collect_flips_ok_on_a_disagreement
"""
from __future__ import annotations

import shutil
from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration.seam_base_units import SEAM_UNITS, seam_base_agreement

_REPO = Path(_doc.__file__).resolve().parents[2]
_SHIPPED = {u: _REPO / d / u for u, d in SEAM_UNITS}


def _agree(home):
    return seam_base_agreement(_REPO, home, parse_env=_doc._parse_env_file)


def _install(home: Path, *units: str, text: "dict | None" = None) -> None:
    d = home / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    for u in units:
        if text and u in text:
            (d / u).write_text(text[u])
        else:
            shutil.copy(_SHIPPED[u], d / u)


def _env(home: Path, rel: str, body: str) -> None:
    p = home / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


_MONEY = ("sigil-cockpit.service", "vigil-settle-drain.service", "vigil-backup.service")


def test_nothing_configured_reports_nothing(tmp_path):
    assert _agree(tmp_path) == ({"units": {}}, [])


def test_the_shipped_units_agree_when_installed(tmp_path):
    _install(tmp_path, *_MONEY, "vigil-backup-push.service", "vigil-backup-drill.service")
    _env(tmp_path, ".config/vigil/backup.env", "VIGIL_BACKUP_PASSPHRASE=x\n")
    sec, issues = _agree(tmp_path)
    assert issues == []
    seam = str(tmp_path / ".sigil" / "credit-lease")
    assert set(sec["units"]) >= set(_MONEY) and set(sec["units"].values()) == {seam}


def test_an_env_file_only_install_uses_the_shipped_unit_text(tmp_path):
    # the settle drain configured by its env file alone (the #70 criterion) still gets compared
    _env(tmp_path, ".config/vigil/settle-drain.env", "VIGIL_SETTLE_DELEGATION=/x\n")
    sec, issues = _agree(tmp_path)
    assert sec["units"] == {"vigil-settle-drain.service": str(tmp_path / ".sigil" / "credit-lease")} and not issues


def test_an_env_file_override_on_one_unit_is_a_hard_issue(tmp_path):
    _install(tmp_path, *_MONEY)
    _env(tmp_path, ".config/vigil/backup.env", f"VIGIL_BACKUP_PASSPHRASE=x\nVIGIL_BASE_DIR={tmp_path / 'other'}\n")
    sec, issues = _agree(tmp_path)
    assert sec["units"]["vigil-backup.service"] == str(tmp_path / "other")
    assert len(issues) == 1 and "disagree on the seam base" in issues[0]
    assert all(u in issues[0] for u in _MONEY) and "VIGIL_BACKUP_PASSPHRASE" not in issues[0]


def test_overriding_every_unit_identically_agrees(tmp_path):
    _install(tmp_path, *_MONEY)
    seam = tmp_path / "mnt" / "seam"
    _env(tmp_path, ".sigil/cockpit.env", f"VIGIL_BASE_DIR={seam}\n")
    _env(tmp_path, ".config/vigil/settle-drain.env", f"VIGIL_BASE_DIR={seam}\n")
    _env(tmp_path, ".config/vigil/backup.env", f"VIGIL_BACKUP_PASSPHRASE=x\nVIGIL_BASE_DIR={seam}\n")
    sec, issues = _agree(tmp_path)
    assert issues == [] and set(sec["units"].values()) == {str(seam)}


def test_a_relative_value_resolves_against_the_working_dir(tmp_path):
    # the pre-E3a backup.env example (VIGIL_BASE_DIR=.vigil-live) under WorkingDirectory=%h/vigil
    _install(tmp_path, "sigil-cockpit.service", "vigil-backup.service")
    _env(tmp_path, ".config/vigil/backup.env", "VIGIL_BACKUP_PASSPHRASE=x\nVIGIL_BASE_DIR=.vigil-live\n")
    sec, issues = _agree(tmp_path)
    assert sec["units"]["vigil-backup.service"] == str(tmp_path / "vigil" / ".vigil-live")
    assert len(issues) == 1


def test_a_literal_percent_h_in_an_env_file_is_not_expanded(tmp_path):
    _install(tmp_path, "sigil-cockpit.service", "vigil-settle-drain.service")
    _env(tmp_path, ".config/vigil/settle-drain.env", "VIGIL_BASE_DIR=%h/.sigil/credit-lease\n")
    sec, issues = _agree(tmp_path)
    assert sec["units"]["vigil-settle-drain.service"] == str(tmp_path / ".sigil" / "%h" / ".sigil" / "credit-lease")
    assert len(issues) == 1


_PRE_E3A = {
    "sigil-cockpit.service": "[Service]\nEnvironmentFile=-%h/.sigil/cockpit.env\nWorkingDirectory=%h/.sigil\n"
                             "ExecStart=%h/.sigil/venv/bin/sigil serve --host ${SIGIL_UI_BIND}\n",
    "vigil-settle-drain.service": "[Service]\nEnvironment=VIGIL_SETTLE_BASE_DIR=%h/.sigil/credit-lease\n"
                                  "EnvironmentFile=-%h/.config/vigil/settle-drain.env\nWorkingDirectory=%h/.sigil\n"
                                  "ExecStart=%h/.sigil/venv/bin/sigil settle-drain drain --spool x \\\n"
                                  "    --base-dir ${VIGIL_SETTLE_BASE_DIR}\n",
}


def test_the_pre_e3a_unit_shapes_disagree(tmp_path):
    """Units installed from an older checkout: the cockpit's CWD-relative default vs the drain's --base-dir."""
    _install(tmp_path, *_PRE_E3A, text=_PRE_E3A)
    sec, issues = _agree(tmp_path)
    assert sec["units"] == {"sigil-cockpit.service": str(tmp_path / ".sigil" / ".vigil-live"),
                            "vigil-settle-drain.service": str(tmp_path / ".sigil" / "credit-lease")}
    assert len(issues) == 1 and "re-copy any unit installed from an older checkout" in issues[0]


def test_a_retired_settle_base_naming_another_tree_is_hard(tmp_path):
    _install(tmp_path, "vigil-settle-drain.service")
    _env(tmp_path, ".config/vigil/settle-drain.env", f"VIGIL_SETTLE_BASE_DIR={tmp_path / 'old'}\n")
    sec, issues = _agree(tmp_path)
    assert len(issues) == 1 and "VIGIL_SETTLE_BASE_DIR" in issues[0] and "REFUSES" in issues[0]
    _env(tmp_path, ".config/vigil/settle-drain.env", f"VIGIL_SETTLE_BASE_DIR={tmp_path / '.sigil/credit-lease'}\n")
    assert _agree(tmp_path)[1] == []                                   # the same directory reconciles


def test_a_symlinked_spelling_of_the_same_dir_agrees(tmp_path):
    real = tmp_path / "vol" / "credit-lease"
    real.mkdir(parents=True)
    (tmp_path / ".sigil").symlink_to(tmp_path / "vol")
    _install(tmp_path, "sigil-cockpit.service", "vigil-settle-drain.service")
    _env(tmp_path, ".config/vigil/settle-drain.env", f"VIGIL_BASE_DIR={real}\n")
    assert _agree(tmp_path)[1] == []


def test_doctor_collect_flips_ok_on_a_disagreement(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SIGIL_HOME", str(home / ".sigil"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    (tmp_path / "base").mkdir()
    baseline = _doc.collect(_REPO)
    assert baseline["seam_base"] == {"units": {}}
    assert not any("seam base" in i for i in baseline["issues"])
    _install(home, *_PRE_E3A, text=_PRE_E3A)
    report = _doc.collect(_REPO)
    seam = [i for i in report["issues"] if i.startswith("seam base:")]
    assert len(seam) == 1 and report["ok"] is False
    assert not any("seam base" in n for n in report["notes"])
