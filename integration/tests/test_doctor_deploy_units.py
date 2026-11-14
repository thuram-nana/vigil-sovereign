"""`vigil doctor` reads the systemd user units a host has installed and reports, as HARD issues:

* a console (`vigil-command.service`) that starts its own cockpit while `sigil-cockpit.service` runs the cockpit
  on 127.0.0.1:8733 — production runs the console proxy-only against the cockpit unit (the shipped drop-in);
* a `~/.sigil/venv` that is not the symlink to the hash-locked `.venv-sovereign`;
* a settle/money setting that differs between the cockpit, the customer edge, the settle drain and ops-sweep,
  read from the env files the installed units load.

Each check is silent until its units/files exist, so a development checkout's doctor output is unchanged.
Framework-free: tmp HOME trees only, no systemd needed.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from vigil_integration import deploy_checks as dc
from vigil_integration import doctor as _doc

_REPO = Path(__file__).resolve().parents[2]
_UNIT_SRC = {
    "vigil-command.service": _REPO / "infra" / "systemd" / "vigil-command.service",
    "sigil-cockpit.service": _REPO / "apps" / "sigil" / "deploy" / "systemd" / "sigil-cockpit.service",
    "sigil-customer.service": _REPO / "apps" / "sigil" / "deploy" / "systemd" / "sigil-customer.service",
    "vigil-settle-drain.service": _REPO / "infra" / "systemd" / "vigil-settle-drain.service",
}
_DROPIN = _REPO / "infra" / "systemd" / "vigil-command.service.d" / "production.conf"


def _never_active(_unit):
    return None


def _install(home: Path, unit: str, *, enable: bool = True) -> Path:
    udir = home / ".config" / "systemd" / "user"
    udir.mkdir(parents=True, exist_ok=True)
    dst = udir / unit
    shutil.copy(_UNIT_SRC[unit], dst)
    if enable:
        wants = udir / "default.target.wants"
        wants.mkdir(exist_ok=True)
        link = wants / unit
        if not link.exists():
            link.symlink_to(dst)
    return dst


def _install_dropin(home: Path) -> None:
    d = home / ".config" / "systemd" / "user" / "vigil-command.service.d"
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy(_DROPIN, d / "production.conf")


def _write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ── 0.3: one cockpit on 127.0.0.1:8733 ───────────────────────────────────────────────────────────────────────
def test_no_units_installed_is_silent(tmp_path):
    assert dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active) == ({"configured": False}, [], [])


def test_console_that_starts_its_own_cockpit_beside_the_cockpit_unit_is_a_hard_issue(tmp_path):
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _write(tmp_path / ".sigil" / "cockpit.env", "SIGIL_UI_BIND=127.0.0.1\nSIGIL_UI_PORT=8733\n")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert sec["console_mode"] == "starts its own cockpit" and sec["ok"] is False
    assert len(issues) == 1
    assert "without --proxy-only" in issues[0] and "cannot bind 127.0.0.1:8733" in issues[0]
    assert "production.conf" in issues[0]


def test_the_shipped_production_dropin_runs_the_console_proxy_only_against_the_cockpit_unit(tmp_path):
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _install_dropin(tmp_path)
    _write(tmp_path / ".sigil" / "cockpit.env", "SIGIL_UI_BIND=127.0.0.1\nSIGIL_UI_PORT=8733\n")
    sec, issues, notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert issues == [] and notes == []
    assert sec["console_mode"] == "proxy-only" and sec["ok"] is True
    assert sec["sovereign_addr"] == "127.0.0.1:8733" and sec["cockpit_addr"] == "127.0.0.1:8733"


def test_a_console_federating_to_an_address_the_cockpit_does_not_bind_is_a_hard_issue(tmp_path):
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _install_dropin(tmp_path)
    _write(tmp_path / ".sigil" / "cockpit.env", "SIGIL_UI_BIND=127.0.0.1\nSIGIL_UI_PORT=8743\n")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert sec["ok"] is False
    assert len(issues) == 1 and "federates /sovereign/* to 127.0.0.1:8733" in issues[0]
    assert "127.0.0.1:8743" in issues[0]


def test_two_cockpits_on_different_ports_are_still_reported(tmp_path):
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _write(tmp_path / ".sigil" / "cockpit.env", "SIGIL_UI_PORT=8743\n")
    _sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert len(issues) == 1 and "two cockpits would then write the same spine" in issues[0]


def test_only_one_unit_enabled_and_nothing_running_is_not_a_clash(tmp_path):
    _install(tmp_path, "vigil-command.service", enable=False)
    _install(tmp_path, "sigil-cockpit.service")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert issues == [] and sec["both_enabled"] is False


def test_a_running_but_not_enabled_console_still_clashes(tmp_path):
    _install(tmp_path, "vigil-command.service", enable=False)
    _install(tmp_path, "sigil-cockpit.service")
    _sec, issues, _notes = dc.cockpit_port_report(
        tmp_path, _REPO, is_active=lambda u: u == "vigil-command.service")
    assert len(issues) == 1 and "without --proxy-only" in issues[0]


def test_proxy_only_console_without_a_cockpit_unit_running_is_a_note(tmp_path):
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service", enable=False)
    _install_dropin(tmp_path)
    _sec, issues, notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert issues == [] and len(notes) == 1 and "neither enabled nor running" in notes[0]


def test_dropin_execstart_reset_and_variable_expansion():
    # the drop-in's empty ExecStart= clears the unit's own; ${VIGIL_CONSOLE_DOMAIN} comes from service.env
    text = _DROPIN.read_text(encoding="utf-8")
    directives = dc._service_directives(text)
    assert [k for k, _v in directives].count("ExecStart") == 2 and directives[0] == ("ExecStart", "")
    line = directives[-1][1]
    assert "--proxy-only" in line and "--sovereign-addr 127.0.0.1:8733" in line and line.startswith("%h/vigil/")
    argv = dc._expand_vars(["--domain", "${VIGIL_CONSOLE_DOMAIN}"], {"VIGIL_CONSOLE_DOMAIN": "console.example.test"})
    assert argv == ["--domain", "console.example.test"]
    assert dc._expand_vars(["--domain", "${VIGIL_CONSOLE_DOMAIN}"], {}) == ["--domain", ""]


# ── 0.4: ~/.sigil/venv is the hash-locked sovereign venv ─────────────────────────────────────────────────────
def test_absent_sovereign_venv_is_silent(tmp_path):
    assert dc.sovereign_venv_report(tmp_path, _REPO) == ({"configured": False}, [], [])


def test_a_separately_installed_venv_is_a_hard_issue(tmp_path):
    (tmp_path / ".sigil" / "venv" / "bin").mkdir(parents=True)
    (tmp_path / ".sigil" / "venv" / "bin" / "sigil").write_text("#!/bin/sh\n")
    sec, issues, _notes = dc.sovereign_venv_report(tmp_path, _REPO)
    assert sec["ok"] is False and sec["symlink"] is False
    assert len(issues) == 1 and "not the symlink to the hash-locked" in issues[0] and "bootstrap.sh" in issues[0]


def test_the_bootstrap_symlink_is_ok(tmp_path):
    repo = tmp_path / "vigil"
    (repo / ".venv-sovereign" / "bin").mkdir(parents=True)
    (repo / ".venv-sovereign" / "bin" / "sigil").write_text("#!/bin/sh\n")
    (tmp_path / ".sigil").mkdir()
    (tmp_path / ".sigil" / "venv").symlink_to(repo / ".venv-sovereign")
    sec, issues, notes = dc.sovereign_venv_report(tmp_path, repo)
    assert sec["ok"] is True and issues == [] and notes == []


def test_a_symlink_to_another_checkouts_locked_venv_is_a_note(tmp_path):
    other = tmp_path / "other"
    (other / ".venv-sovereign" / "bin").mkdir(parents=True)
    (other / ".venv-sovereign" / "bin" / "sigil").write_text("#!/bin/sh\n")
    (tmp_path / ".sigil").mkdir()
    (tmp_path / ".sigil" / "venv").symlink_to(other / ".venv-sovereign")
    sec, issues, notes = dc.sovereign_venv_report(tmp_path, tmp_path / "vigil")
    assert sec["ok"] is True and issues == [] and len(notes) == 1 and "other checkout" in notes[0]


@pytest.mark.parametrize("target", ["venv-unlocked", "missing/.venv-sovereign"])
def test_a_symlink_to_anything_but_a_built_venv_sovereign_is_a_hard_issue(tmp_path, target):
    t = tmp_path / target
    if target == "venv-unlocked":
        (t / "bin").mkdir(parents=True)
        (t / "bin" / "sigil").write_text("#!/bin/sh\n")
    (tmp_path / ".sigil").mkdir()
    (tmp_path / ".sigil" / "venv").symlink_to(t)
    sec, issues, _notes = dc.sovereign_venv_report(tmp_path, _REPO)
    assert sec["ok"] is False and len(issues) == 1


# ── 0.5: settle / money settings that must match ─────────────────────────────────────────────────────────────
def _money_host(home: Path, *, cockpit="", customer="", drain="", sigil_env=None, install=True) -> None:
    if install:
        for u in ("sigil-cockpit.service", "sigil-customer.service", "vigil-settle-drain.service"):
            _install(home, u)
    _write(home / ".sigil" / "cockpit.env", cockpit)
    _write(home / ".sigil" / "customer.env", customer)
    _write(home / ".config" / "vigil" / "settle-drain.env", drain)
    if sigil_env is not None:
        _write(home / ".sigil" / "sigil.env", sigil_env)


def test_only_the_shell_is_not_configured(tmp_path):
    assert dc.must_match_report(tmp_path, _REPO, {}) == ({"configured": False}, [], [])


def test_the_shipped_env_examples_agree(tmp_path):
    # installed exactly as GO-LIVE copies them, the shipped examples hold no disagreement
    sigil = _REPO / "apps" / "sigil" / "deploy"
    _money_host(tmp_path, cockpit=(sigil / "cockpit.env.example").read_text(),
                customer=(sigil / "customer.env.example").read_text(),
                drain=(_REPO / "infra" / "systemd" / "vigil-settle-drain.env.example").read_text())
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {})
    assert issues == [] and sec["ok"] is True
    assert set(sec["processes"]) == {"cockpit", "customer", "settle-drain", "ops-sweep"}


def test_the_settle_record_flag_on_everywhere_agrees(tmp_path):
    on = "VIGIL_SETTLE_SPINE_RECORD=1\n"
    _money_host(tmp_path, cockpit=on, customer="VIGIL_SETTLE_SPINE_RECORD=true\n", drain=on)
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {"VIGIL_SETTLE_SPINE_RECORD": "yes"})
    assert issues == [] and set(sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"].values()) == {"on"}


def test_the_settle_record_flag_on_in_the_cockpit_only_is_a_hard_issue(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {})
    assert sec["ok"] is False and len(issues) == 1
    msg = issues[0]
    assert msg.startswith("VIGIL_SETTLE_SPINE_RECORD must be the same")
    assert "on in cockpit" in msg and "off in customer, settle-drain, ops-sweep" in msg


def test_ops_sweep_alone_disagreeing_is_a_hard_issue(tmp_path):
    on = "VIGIL_SETTLE_SPINE_RECORD=1\n"
    _money_host(tmp_path, cockpit=on, customer=on, drain=on)
    _sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {})
    assert len(issues) == 1 and "off in ops-sweep" in issues[0]


def test_one_value_in_sigil_env_reaches_every_unit(tmp_path):
    # the remedy the issue names: set it once in $SIGIL_HOME/sigil.env, which every sigil process reads
    _money_host(tmp_path, sigil_env="VIGIL_SETTLE_SPINE_RECORD=1\nVIGIL_BILLING_TARGET_MARGIN=0.37\n")
    ops = {"VIGIL_SETTLE_SPINE_RECORD": "1", "VIGIL_BILLING_TARGET_MARGIN": "0.37"}
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, ops)
    assert issues == [] and set(sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"].values()) == {"on"}


def test_a_unit_env_file_overrides_sigil_env(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=0\n", sigil_env="VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {"VIGIL_SETTLE_SPINE_RECORD": "1"})
    assert sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"]["cockpit"] == "off"
    assert len(issues) == 1 and "off in cockpit" in issues[0]


def test_sigil_env_is_read_at_each_processs_own_sigil_home(tmp_path):
    data = tmp_path / "data" / ".sigil"
    _write(data / "sigil.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    _money_host(tmp_path, cockpit=f"SIGIL_HOME={data}\n")
    sec, _issues, _notes = dc.must_match_report(tmp_path, _REPO, {})
    flags = sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"]
    assert flags["cockpit"] == "on" and flags["settle-drain"] == "off"


def test_a_pricing_setting_set_in_the_cockpit_only_is_a_hard_issue_and_its_value_is_never_printed(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_BILLING_TARGET_MARGIN=0.37\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {})
    assert len(issues) == 1
    assert issues[0].startswith("VIGIL_BILLING_TARGET_MARGIN must be the same")
    assert "set in cockpit; unset in settle-drain, ops-sweep" in issues[0]
    assert "0.37" not in issues[0] and "0.37" not in repr(sec)
    assert "customer" not in sec["flags"]["VIGIL_BILLING_TARGET_MARGIN"]   # the customer edge does not settle


def test_two_different_pricing_values_are_a_hard_issue(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_BILLING_CANCEL_SETTLEMENT=refund\n",
                drain="VIGIL_BILLING_CANCEL_SETTLEMENT=metered\n")
    _sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {"VIGIL_BILLING_CANCEL_SETTLEMENT": "refund"})
    assert len(issues) == 1 and "different values in cockpit, ops-sweep / settle-drain" in issues[0]
    assert "refund" not in issues[0] and "metered" not in issues[0].split("(")[1].split(")")[0]


def test_the_env_file_named_by_the_installed_unit_and_its_dropins_is_the_one_read(tmp_path):
    # the real env files the units load: an installed drop-in pointing the drain at another env file wins
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n", customer="VIGIL_SETTLE_SPINE_RECORD=1\n",
                drain="")
    _write(tmp_path / ".config" / "systemd" / "user" / "vigil-settle-drain.service.d" / "env.conf",
           "[Service]\nEnvironmentFile=-%h/secrets/settle.env\n")
    _write(tmp_path / "secrets" / "settle.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {"VIGIL_SETTLE_SPINE_RECORD": "1"})
    assert issues == [], issues
    assert "~/secrets/settle.env" in sec["processes"]["settle-drain"]["env_files"]


def test_the_user_managers_environment_reaches_every_unit(tmp_path):
    _money_host(tmp_path)
    _write(tmp_path / ".config" / "environment.d" / "50-vigil.conf", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {"VIGIL_SETTLE_SPINE_RECORD": "1"})
    assert issues == [] and set(sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"].values()) == {"on"}


def test_an_env_file_present_without_an_installed_unit_still_takes_part(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n", install=False)
    (tmp_path / ".sigil" / "customer.env").unlink()
    (tmp_path / ".config" / "vigil" / "settle-drain.env").unlink()
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO, {})
    assert set(sec["processes"]) == {"cockpit", "ops-sweep"} and len(issues) == 1


# ── wired into `vigil doctor` ────────────────────────────────────────────────────────────────────────────────
def _isolated(monkeypatch, tmp_path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SIGIL_HOME", str(home / ".sigil"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    (tmp_path / "base").mkdir()
    for k in ("VIGIL_SETTLE_SPINE_RECORD", "VIGIL_BILLING_TARGET_MARGIN", "VIGIL_RUN_FLOOR_CREDITS",
              "VIGIL_BILLING_CANCEL_SETTLEMENT", "SERVICE_RESULT"):
        monkeypatch.delenv(k, raising=False)
    return home


def test_doctor_is_unchanged_on_a_host_without_these_units(tmp_path, monkeypatch):
    _isolated(monkeypatch, tmp_path)
    report = _doc.collect(_REPO)
    for key in ("cockpit_port", "sovereign_venv", "must_match_flags"):
        assert report[key] == {"configured": False}
    assert "Deployment units" not in _doc.render(report)


def test_doctor_reports_each_finding_as_a_hard_issue(tmp_path, monkeypatch):
    home = _isolated(monkeypatch, tmp_path)
    baseline = _doc.collect(_REPO)
    _install(home, "vigil-command.service")
    _money_host(home, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n")
    (home / ".sigil" / "venv" / "bin").mkdir(parents=True)
    report = _doc.collect(_REPO)
    new = [i for i in report["issues"] if i not in baseline["issues"]]
    assert report["ok"] is False and len(new) == 3, new
    assert any("without --proxy-only" in i for i in new)
    assert any("hash-locked" in i for i in new)
    assert any(i.startswith("VIGIL_SETTLE_SPINE_RECORD must be the same") for i in new)
    text = _doc.render(report)
    assert "Deployment units" in text and "DISAGREE" in text


def test_ops_sweep_reads_the_shell_and_sigil_env_as_doctor_does(tmp_path, monkeypatch):
    home = _isolated(monkeypatch, tmp_path)
    _money_host(home, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n", customer="VIGIL_SETTLE_SPINE_RECORD=1\n",
                drain="VIGIL_SETTLE_SPINE_RECORD=1\n")
    assert any("off in ops-sweep" in i for i in _doc.collect(_REPO)["issues"])
    _write(home / ".sigil" / "sigil.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    assert _doc.collect(_REPO)["must_match_flags"]["ok"] is True
