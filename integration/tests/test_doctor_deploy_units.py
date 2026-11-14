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

from vigil_integration import cli as _cli
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
# A stand-in for a setting's value: the check compares values as opaque strings and never prints them.
_VALUE = "owner-set-value"


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


def _install_dropin(home: Path, *, domain: "str | None" = "console.example.test") -> None:
    """The shipped production drop-in, with the console's service.env (GO-LIVE §6) naming ``domain`` (None: no
    service.env at all)."""
    d = home / ".config" / "systemd" / "user" / "vigil-command.service.d"
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy(_DROPIN, d / "production.conf")
    if domain is not None:
        _write(home / "vigil" / ".vigil-live" / "service.env", f"VIGIL_CONSOLE_DOMAIN={domain}\n")


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


@pytest.mark.parametrize("bind", ["::1", "0:0:0:0:0:0:0:1"])
def test_a_console_on_ipv4_loopback_and_a_cockpit_on_ipv6_loopback_is_a_hard_issue(tmp_path, bind):
    # the drop-in federates to 127.0.0.1:8733; a cockpit bound to [::1]:8733 refuses that connection
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _install_dropin(tmp_path)
    _write(tmp_path / ".sigil" / "cockpit.env", f"SIGIL_UI_BIND={bind}\nSIGIL_UI_PORT=8733\n")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert sec["ok"] is False and sec["cockpit_addr"] == "[::1]:8733"
    assert len(issues) == 1 and "federates /sovereign/* to 127.0.0.1:8733" in issues[0] and "[::1]:8733" in issues[0]


@pytest.mark.parametrize("client,server,same", [
    ("127.0.0.1", "127.0.0.1", True), ("::1", "0:0:0:0:0:0:0:1", True), ("[::1]", "::1", True),
    ("localhost", "127.0.0.1", True), ("localhost", "::1", True), ("LOCALHOST", "127.0.0.1", True),
    ("127.0.0.1", "::1", False), ("::1", "127.0.0.1", False), ("127.0.0.1", "127.0.0.2", False),
    ("localhost", "127.0.0.2", False), ("10.0.0.5", "127.0.0.1", False),
])
def test_same_host_is_only_an_address_a_connection_reaches(client, server, same):
    assert dc._same_host(client, server) is same


def test_an_env_file_value_wins_over_an_environment_directive(tmp_path):
    # systemd: EnvironmentFile= overrides Environment= for the same variable; the cockpit binds cockpit.env's port
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _install_dropin(tmp_path)
    _write(tmp_path / ".config" / "systemd" / "user" / "sigil-cockpit.service.d" / "port.conf",
           "[Service]\nEnvironment=SIGIL_UI_PORT=8743\n")
    _write(tmp_path / ".sigil" / "cockpit.env", "SIGIL_UI_BIND=127.0.0.1\nSIGIL_UI_PORT=8733\n")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert sec["cockpit_addr"] == "127.0.0.1:8733" and issues == []


def test_a_masked_console_unit_is_not_an_installed_one(tmp_path):
    # `vigil panic` masks vigil-command (a link to /dev/null): there is no console to clash with
    _install(tmp_path, "sigil-cockpit.service")
    udir = tmp_path / ".config" / "systemd" / "user"
    (udir / "vigil-command.service").symlink_to("/dev/null")
    assert dc.UnitView("vigil-command.service", home=tmp_path).masked is True
    assert dc.cockpit_port_report(tmp_path, _REPO, is_active=lambda _u: True) == ({"configured": False}, [], [])


def _install_console_dropin(home: Path, exec_args: str) -> None:
    d = home / ".config" / "systemd" / "user" / "vigil-command.service.d"
    _write(d / "production.conf", "[Service]\nExecStart=\n"
           f"ExecStart=%h/vigil/.venv-offense/bin/vigil up --proxy-only --port 8770 --no-browser {exec_args}\n")


@pytest.mark.parametrize("addr,clash", [("127.0.0.1:8743", False), ("127.0.0.1:8733", True)])
def test_the_console_federation_address_falls_back_to_vigil_sovereign_addr(tmp_path, addr, clash):
    # no --sovereign-addr on the command line: `vigil up` takes VIGIL_SOVEREIGN_ADDR from its environment
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _install_console_dropin(tmp_path, "--domain console.example.test")
    _write(tmp_path / "vigil" / ".vigil-live" / "service.env", f"VIGIL_SOVEREIGN_ADDR={addr}\n")
    _write(tmp_path / ".sigil" / "cockpit.env", "SIGIL_UI_BIND=127.0.0.1\nSIGIL_UI_PORT=8743\n")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert sec["sovereign_addr"] == addr
    assert (len(issues) == 1) is clash


def test_an_empty_console_domain_is_a_hard_issue(tmp_path):
    # the drop-in passes --domain ${VIGIL_CONSOLE_DOMAIN}; service.env without it hands `vigil up` an empty domain
    _install(tmp_path, "vigil-command.service")
    _install(tmp_path, "sigil-cockpit.service")
    _install_dropin(tmp_path, domain=None)
    _write(tmp_path / "vigil" / ".vigil-live" / "service.env", "CRUCIBLE_API_KEY=x\n")
    _write(tmp_path / ".sigil" / "cockpit.env", "SIGIL_UI_BIND=127.0.0.1\nSIGIL_UI_PORT=8733\n")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert sec["ok"] is False and sec["domain"] == "empty"
    assert len(issues) == 1 and "empty --domain" in issues[0] and "VIGIL_CONSOLE_DOMAIN" in issues[0]
    assert "~/vigil/.vigil-live/service.env" in issues[0]


def test_an_empty_console_domain_is_reported_without_a_cockpit_unit(tmp_path):
    _install(tmp_path, "vigil-command.service")
    _install_dropin(tmp_path, domain="")
    sec, issues, _notes = dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active)
    assert sec["configured"] is True and sec["cockpit_installed"] is False and len(issues) == 1
    _install_dropin(tmp_path)                                 # the hostname set: nothing to report
    assert dc.cockpit_port_report(tmp_path, _REPO, is_active=_never_active) == ({"configured": False}, [], [])


@pytest.mark.parametrize("value", ["", "   "])
def test_vigil_up_refuses_an_empty_domain(value, capsys):
    with pytest.raises(SystemExit) as e:
        _cli.build_parser().parse_args(["up", "--proxy-only", "--domain", value])
    assert e.value.code == 2 and "--domain" in capsys.readouterr().err


def test_vigil_up_keeps_a_named_domain_and_no_domain():
    assert _cli.build_parser().parse_args(["up", "--domain", "console.example.test"]).domain == "console.example.test"
    assert not _cli.build_parser().parse_args(["up"]).domain


# ── 0.4: ~/.sigil/venv is the hash-locked sovereign venv ─────────────────────────────────────────────────────
def test_absent_sovereign_venv_is_silent(tmp_path):
    assert dc.sovereign_venv_report(tmp_path, _REPO) == ({"configured": False}, [], [])


def test_an_absent_venv_that_installed_units_run_is_a_hard_issue(tmp_path):
    # ./bootstrap.sh run with SIGIL_HOME exported links $SIGIL_HOME/venv, not ~/.sigil/venv: every unit fails to exec
    _install(tmp_path, "sigil-cockpit.service")
    _install(tmp_path, "vigil-settle-drain.service")
    _install(tmp_path, "vigil-command.service")                 # runs the offense venv: not counted
    (tmp_path / ".sigil").mkdir()
    sec, issues, _notes = dc.sovereign_venv_report(tmp_path, _REPO)
    assert sec["ok"] is False and sec["exists"] is False
    assert sec["units"] == ["sigil-cockpit.service", "vigil-settle-drain.service"]
    assert len(issues) == 1 and "does not exist" in issues[0] and "SIGIL_HOME unset" in issues[0]


def test_a_unit_whose_dropin_runs_another_venv_does_not_count(tmp_path):
    _install(tmp_path, "sigil-cockpit.service")
    _write(tmp_path / ".config" / "systemd" / "user" / "sigil-cockpit.service.d" / "venv.conf",
           "[Service]\nExecStart=\nExecStart=/opt/sigil/bin/sigil serve\n")
    assert dc.units_running_the_sovereign_venv(tmp_path) == []
    assert dc.sovereign_venv_report(tmp_path, _REPO) == ({"configured": False}, [], [])


def _separate_venv(home: Path) -> None:
    (home / ".sigil" / "venv" / "bin").mkdir(parents=True)
    (home / ".sigil" / "venv" / "bin" / "sigil").write_text("#!/bin/sh\n")


def test_a_separately_installed_venv_that_units_run_is_a_hard_issue(tmp_path):
    _install(tmp_path, "sigil-cockpit.service")
    _separate_venv(tmp_path)
    sec, issues, notes = dc.sovereign_venv_report(tmp_path, _REPO)
    assert sec["ok"] is False and sec["symlink"] is False and notes == []
    assert len(issues) == 1 and "not the symlink to the hash-locked" in issues[0] and "bootstrap.sh" in issues[0]
    assert "sigil-cockpit.service" in issues[0]


def test_a_separately_installed_venv_on_a_development_install_is_a_note(tmp_path):
    # no installed unit runs it (a developer's venv): reported, never blocking bring-up
    _separate_venv(tmp_path)
    sec, issues, notes = dc.sovereign_venv_report(tmp_path, _REPO)
    assert issues == [] and sec["ok"] is True and sec["symlink"] is False
    assert len(notes) == 1 and "not the symlink to the hash-locked" in notes[0] and "before installing" in notes[0]


def test_the_bootstrap_symlink_is_ok(tmp_path):
    repo = tmp_path / "vigil"
    (repo / ".venv-sovereign" / "bin").mkdir(parents=True)
    (repo / ".venv-sovereign" / "bin" / "sigil").write_text("#!/bin/sh\n")
    (tmp_path / ".sigil").mkdir()
    (tmp_path / ".sigil" / "venv").symlink_to(repo / ".venv-sovereign")
    _install(tmp_path, "sigil-cockpit.service")
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


@pytest.mark.parametrize("units", [True, False], ids=["units-installed", "development"])
@pytest.mark.parametrize("target", ["venv-unlocked", "missing/.venv-sovereign"])
def test_a_symlink_to_anything_but_a_built_venv_sovereign(tmp_path, target, units):
    t = tmp_path / target
    if target == "venv-unlocked":
        (t / "bin").mkdir(parents=True)
        (t / "bin" / "sigil").write_text("#!/bin/sh\n")
    (tmp_path / ".sigil").mkdir()
    (tmp_path / ".sigil" / "venv").symlink_to(t)
    if units:
        _install(tmp_path, "sigil-customer.service")
    sec, issues, notes = dc.sovereign_venv_report(tmp_path, _REPO)
    assert sec["ok"] is (not units)
    assert (len(issues), len(notes)) == ((1, 0) if units else (0, 1))


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


def test_no_settling_unit_is_not_configured(tmp_path):
    assert dc.must_match_report(tmp_path, _REPO) == ({"configured": False}, [], [])
    _write(tmp_path / ".sigil" / "sigil.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")   # a sigil.env alone is no unit
    assert dc.must_match_report(tmp_path, _REPO) == ({"configured": False}, [], [])


def test_the_shipped_env_examples_agree(tmp_path):
    # installed exactly as GO-LIVE copies them, the shipped examples hold no disagreement
    sigil = _REPO / "apps" / "sigil" / "deploy"
    _money_host(tmp_path, cockpit=(sigil / "cockpit.env.example").read_text(),
                customer=(sigil / "customer.env.example").read_text(),
                drain=(_REPO / "infra" / "systemd" / "vigil-settle-drain.env.example").read_text())
    sec, issues, notes = dc.must_match_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and sec["ok"] is True
    assert set(sec["processes"]) == {"cockpit", "customer", "settle-drain", "ops-sweep"}


def test_the_settle_record_flag_on_everywhere_agrees(tmp_path):
    on = "VIGIL_SETTLE_SPINE_RECORD=1\n"
    _money_host(tmp_path, cockpit=on, customer="VIGIL_SETTLE_SPINE_RECORD=true\n", drain=on,
                sigil_env="VIGIL_SETTLE_SPINE_RECORD=on\n")
    sec, issues, notes = dc.must_match_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and set(sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"].values()) == {"on"}
    assert sec["ops_sweep_agrees"] is True


def test_the_settle_record_flag_on_in_the_cockpit_only_is_a_hard_issue(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    assert sec["ok"] is False and len(issues) == 1
    msg = issues[0]
    assert msg.startswith("VIGIL_SETTLE_SPINE_RECORD must be the same")
    assert "on in cockpit" in msg and "off in customer, settle-drain" in msg
    assert "~/.sigil/sigil.env" in msg                     # the one file every unit here reads beneath its env file


def test_ops_sweep_alone_disagreeing_is_a_note_naming_what_its_shell_must_export(tmp_path):
    # GO-LIVE §6, the flag in each unit env file: the units agree, so nothing blocks bring-up; a shell that reads
    # only sigil.env would settle without the record, so the doctor says what that shell must export
    on = "VIGIL_SETTLE_SPINE_RECORD=1\n"
    _money_host(tmp_path, cockpit=on, customer=on, drain=on)
    sec, issues, notes = dc.must_match_report(tmp_path, _REPO)
    assert issues == [] and sec["ok"] is True and sec["ops_sweep_agrees"] is False
    assert len(notes) == 1
    assert notes[0].startswith("VIGIL_SETTLE_SPINE_RECORD differs between the units that settle and `sigil ops-sweep`")
    assert "on in cockpit, customer, settle-drain" in notes[0] and "off in ops-sweep" in notes[0]
    assert "`export VIGIL_SETTLE_SPINE_RECORD=1`" in notes[0] and "~/.sigil/sigil.env" in notes[0]


def test_a_pricing_value_missing_from_the_ops_sweep_shell_is_a_note_that_never_prints_it(tmp_path):
    v = f"VIGIL_BILLING_TARGET_MARGIN={_VALUE}\n"
    _money_host(tmp_path, cockpit=v, drain=v)
    sec, issues, notes = dc.must_match_report(tmp_path, _REPO)
    assert issues == [] and len(notes) == 1
    assert "set in cockpit, settle-drain; unset in ops-sweep" in notes[0]
    assert "export the same VIGIL_BILLING_TARGET_MARGIN as ~/.sigil/cockpit.env" in notes[0]
    assert _VALUE not in notes[0] and _VALUE not in repr(sec)


def test_one_value_in_sigil_env_reaches_every_unit(tmp_path):
    # the remedy the issue names: set it once in $SIGIL_HOME/sigil.env, which every sigil process reads
    _money_host(tmp_path, sigil_env=f"VIGIL_SETTLE_SPINE_RECORD=1\nVIGIL_BILLING_TARGET_MARGIN={_VALUE}\n")
    sec, issues, notes = dc.must_match_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and set(sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"].values()) == {"on"}


def test_a_unit_env_file_overrides_sigil_env(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=0\n", sigil_env="VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    assert sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"]["cockpit"] == "off"
    assert len(issues) == 1 and "off in cockpit" in issues[0]


def test_sigil_env_is_read_at_each_processs_own_sigil_home(tmp_path):
    data = tmp_path / "data" / ".sigil"
    _write(data / "sigil.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    _money_host(tmp_path, cockpit=f"SIGIL_HOME={data}\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    flags = sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"]
    assert flags["cockpit"] == "on" and flags["settle-drain"] == "off"
    assert flags["ops-sweep"] == "on"                      # the ops-sweep shell is read at the COCKPIT's SIGIL_HOME
    assert sec["processes"]["ops-sweep"]["sigil_env"] == "~/data/.sigil/sigil.env"
    assert len(issues) == 1 and "different SIGIL_HOMEs" in issues[0] and "cockpit: ~/data/.sigil" in issues[0]


def test_golive_durable_volume_with_the_flag_once_in_its_sigil_env_agrees_everywhere(tmp_path):
    # GO-LIVE §2 (SIGIL_HOME on the durable volume, in each unit env file) + §6 (the flag once in its sigil.env)
    vol = tmp_path / "mnt" / ".sigil"
    _write(vol / "sigil.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    home_line = f"SIGIL_HOME={vol}\n"
    _money_host(tmp_path, cockpit=home_line, customer=home_line, drain=home_line)
    sec, issues, notes = dc.must_match_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and set(sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"].values()) == {"on"}


def test_a_pricing_setting_set_in_the_cockpit_only_is_a_hard_issue_and_its_value_is_never_printed(tmp_path):
    _money_host(tmp_path, cockpit=f"VIGIL_BILLING_TARGET_MARGIN={_VALUE}\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    assert len(issues) == 1
    assert issues[0].startswith("VIGIL_BILLING_TARGET_MARGIN must be the same")
    assert "set in cockpit; unset in settle-drain" in issues[0]
    assert _VALUE not in issues[0] and _VALUE not in repr(sec)
    assert "customer" not in sec["flags"]["VIGIL_BILLING_TARGET_MARGIN"]   # the customer edge does not settle


def test_two_different_pricing_values_are_a_hard_issue(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_BILLING_CANCEL_SETTLEMENT=refund\n",
                drain="VIGIL_BILLING_CANCEL_SETTLEMENT=metered\n")
    _sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    assert len(issues) == 1 and "different values in cockpit / settle-drain" in issues[0]
    assert "refund" not in issues[0] and "metered" not in issues[0].split("(")[1].split(")")[0]


def test_the_env_file_named_by_the_installed_unit_and_its_dropins_is_the_one_read(tmp_path):
    # the real env files the units load: an installed drop-in pointing the drain at another env file wins
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n", customer="VIGIL_SETTLE_SPINE_RECORD=1\n",
                drain="")
    _write(tmp_path / ".config" / "systemd" / "user" / "vigil-settle-drain.service.d" / "env.conf",
           "[Service]\nEnvironmentFile=-%h/secrets/settle.env\n")
    _write(tmp_path / "secrets" / "settle.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    assert issues == [], issues
    assert "~/secrets/settle.env" in sec["processes"]["settle-drain"]["env_files"]


def test_the_user_managers_environment_reaches_every_unit(tmp_path):
    _money_host(tmp_path)
    _write(tmp_path / ".config" / "environment.d" / "50-vigil.conf", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    flags = sec["flags"]["VIGIL_SETTLE_SPINE_RECORD"]
    assert issues == [] and {flags[p] for p in ("cockpit", "customer", "settle-drain")} == {"on"}


def test_env_files_present_without_installed_units_still_take_part(tmp_path):
    _money_host(tmp_path, cockpit="VIGIL_SETTLE_SPINE_RECORD=1\n", install=False)
    (tmp_path / ".config" / "vigil" / "settle-drain.env").unlink()
    sec, issues, _notes = dc.must_match_report(tmp_path, _REPO)
    assert set(sec["processes"]) == {"cockpit", "customer", "ops-sweep"}
    assert len(issues) == 1 and "off in customer; on in cockpit" in issues[0]


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


def test_a_development_venv_never_blocks_bring_up(tmp_path, monkeypatch):
    # apps/sigil's developer layout with no sovereign unit installed: a note, no new hard issue
    home = _isolated(monkeypatch, tmp_path)
    baseline = _doc.collect(_REPO)
    _separate_venv(home)
    report = _doc.collect(_REPO)
    assert [i for i in report["issues"] if i not in baseline["issues"]] == []
    assert any("not the symlink to the hash-locked" in n for n in report["notes"])
    assert "~/.sigil/venv: NOT a symlink" in _doc.render(report)


def _settle_findings(report):
    return ([i for i in report["issues"] if "VIGIL_SETTLE_SPINE_RECORD" in i],
            [n for n in report["notes"] if "VIGIL_SETTLE_SPINE_RECORD" in n])


@pytest.mark.parametrize("doctor_env", [{}, {"VIGIL_SETTLE_SPINE_RECORD": "1"}, {"VIGIL_SETTLE_SPINE_RECORD": "0"},
                                        {"SIGIL_HOME": "/nonexistent/elsewhere"}],
                         ids=["vigil-ready", "shell-exports-on", "shell-exports-off", "shell-other-home"])
def test_the_doctors_own_environment_never_decides_the_settle_verdict(tmp_path, monkeypatch, doctor_env):
    # GO-LIVE §6 with the flag in each unit env file, judged from vigil-ready.service (no SIGIL_HOME, no flag) and
    # from shells that export either value: the units agree, so it is never a hard issue, and the verdict is the same
    home = _isolated(monkeypatch, tmp_path)
    monkeypatch.delenv("SIGIL_HOME", raising=False)
    for k, v in doctor_env.items():
        monkeypatch.setenv(k, v)
    on = "VIGIL_SETTLE_SPINE_RECORD=1\n"
    _money_host(home, cockpit=on, customer=on, drain=on)
    report = _doc.collect(_REPO)
    hard, notes = _settle_findings(report)
    assert hard == [] and report["must_match_flags"]["ok"] is True
    assert len(notes) == 1 and "`export VIGIL_SETTLE_SPINE_RECORD=1`" in notes[0]
    assert "an ops-sweep shell reading only sigil.env differs" in _doc.render(report)


def test_golive_durable_volume_layout_passes_under_vigil_ready(tmp_path, monkeypatch):
    # GO-LIVE §2 + §6 alternative 1, as vigil-ready.service runs the doctor: no SIGIL_HOME in its environment
    home = _isolated(monkeypatch, tmp_path)
    monkeypatch.delenv("SIGIL_HOME", raising=False)
    vol = tmp_path / "mnt" / ".sigil"
    _write(vol / "sigil.env", "VIGIL_SETTLE_SPINE_RECORD=1\n")
    line = f"SIGIL_HOME={vol}\n"
    _money_host(home, cockpit=line, customer=line, drain=line)
    report = _doc.collect(_REPO)
    assert _settle_findings(report) == ([], [])
    assert report["must_match_flags"]["ok"] is True and report["must_match_flags"]["ops_sweep_agrees"] is True
    assert "an ops-sweep shell reading only sigil.env agrees" in _doc.render(report)
