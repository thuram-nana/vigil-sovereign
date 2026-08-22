"""W7-8 — install + enable the backup timers in the PRODUCTION posture, and verify them in `doctor`.

The defect this closes: the systemd backup/drill units ship in the repo but nothing installs or enables
them, and the `backups` posture control counted "at least one timer enabled" as ON — so a backup that had
never actually run still satisfied the production gate. These tests pin the tightened contract:

  * BACKUP DURABILITY is judged over a required set — at least one of {vigil-backup, vigil-backup-push}
    PLUS vigil-backup-drill (the recovery drill that proves the round-trip);
  * ON requires those timers ENABLED *and* with a SUCCESSFUL last run;
  * PENDING = enabled but NEVER FIRED (the case the old code wrongly reported ON);
  * OFF = a required timer disabled; UNKNOWN = systemctl absent or a canonical unit missing (fail-closed);
  * `vigil doctor` reports EACH timer's enabled state + last successful run;
  * the PRODUCTION gate REFUSES on both a never-fired (PENDING) and a disabled (OFF) timer, with a
    positive control (enabled+fired ⇒ ON ⇒ passes) proving the gate is not simply always-refusing;
  * bootstrap.sh installs the units and enables the backup + drill timers in the production posture.

`test_production_gate_refuses_on_never_fired_and_disabled_timer` is the test that FAILS WITHOUT THE CHANGE:
on the old "at-least-one-enabled ⇒ ON" probe, an enabled-but-never-fired backup passed the gate.

Every state assertion carries its own NEGATIVE CONTROL — flip exactly one input and the state flips — so
the probe is proven to READ enablement + last-run, not print a constant. Pure integration/offense-plane:
imports only `vigil_integration.doctor`, so it runs in the required sovereign-leg CI job with no
`framework`/`sigil` import (FATAL-2 intact) and needs no `pytest.importorskip`.
"""
from __future__ import annotations

import pathlib
from types import SimpleNamespace

import pytest

from vigil_integration import doctor as dmod

_REPO = pathlib.Path(dmod.__file__).resolve().parents[2]

# the canonical backup/durability units the tightened probe judges, plus a non-durability cadence timer so
# the "count enabled across ALL timers" line is exercised with more than the required set.
_ALL = ("vigil-backup.timer", "vigil-backup-push.timer", "vigil-backup-drill.timer", "vigil-reprove.timer")


def _fake_systemctl(enabled=(), fired=()):
    """A fake `systemctl` covering BOTH probes the timer scan makes:

      * `is-enabled <timer>`   → "enabled" iff <timer> in `enabled`, else "disabled" (rc 4, like the real
        tool for a not-installed unit);
      * `show <service> -p ExecMainExitTimestamp -p ExecMainStatus -p Result` → a NON-EMPTY exit timestamp
        + status 0 + Result=success iff the paired timer is in `fired` (a successful last run), else an
        EMPTY timestamp (the real signal for a oneshot that has never completed a run).
    """
    enabled, fired = set(enabled), set(fired)

    def _run(argv, capture_output=True, text=True, timeout=None, **kw):
        verb, unit = argv[1], argv[2]
        if verb == "is-enabled":
            on = unit in enabled
            return SimpleNamespace(returncode=0 if on else 4,
                                   stdout=("enabled" if on else "disabled") + "\n", stderr="")
        if verb == "show":
            timer = unit[: -len(".service")] + ".timer"
            if timer in fired:
                body = ("ExecMainExitTimestamp=Thu 2026-08-21 03:00:11 UTC\n"
                        "ExecMainStatus=0\nResult=success\n")
            else:                                    # never fired: EMPTY timestamp (status/Result default)
                body = "ExecMainExitTimestamp=\nExecMainStatus=0\nResult=success\n"
            return SimpleNamespace(returncode=0, stdout=body, stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unknown verb")

    return _run


def _mk_units(tmp_path: pathlib.Path, names=_ALL) -> pathlib.Path:
    sysd = tmp_path / "infra" / "systemd"
    sysd.mkdir(parents=True, exist_ok=True)
    for n in names:
        (sysd / n).write_text("[Timer]\n", encoding="utf-8")
    return tmp_path


def _systemctl_present(monkeypatch):
    monkeypatch.setattr(dmod.shutil, "which",
                        lambda n: "/usr/bin/systemctl" if n == "systemctl" else None)


# --------------------------------------------------------------------------- state machine of _posture_backups

def test_backups_off_when_no_timer_enabled(monkeypatch, tmp_path):
    repo = _mk_units(tmp_path)
    _systemctl_present(monkeypatch)
    monkeypatch.setattr(dmod.subprocess, "run", _fake_systemctl())
    state, detail = dmod._posture_backups(repo)
    assert state == "OFF" and "NOT running" in detail
    # NEGATIVE CONTROL: enable + fire the durability set → ON (proves OFF was read, not constant).
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    assert dmod._posture_backups(repo)[0] == "ON"


def test_backups_pending_when_enabled_but_never_fired(monkeypatch, tmp_path):
    # the crux of W7-8: an enabled timer that has NEVER FIRED is PENDING, not ON — a backup that never ran
    # is not durability. On the OLD contract this exact state returned ON.
    repo = _mk_units(tmp_path)
    _systemctl_present(monkeypatch)
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    state, detail = dmod._posture_backups(repo)
    assert state == "PENDING"
    assert state != "ON"
    assert "not yet proven" in detail.lower() and "vigil-backup.timer" in detail
    # NEGATIVE CONTROL: give BOTH a successful last run → ON.
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    assert dmod._posture_backups(repo)[0] == "ON"


def test_backups_on_requires_the_last_run_not_just_enablement(monkeypatch, tmp_path):
    repo = _mk_units(tmp_path)
    _systemctl_present(monkeypatch)
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    state, detail = dmod._posture_backups(repo)
    assert state == "ON" and "engaged" in detail and "last ran" in detail
    # NEGATIVE CONTROL: drop just the DRILL's successful run → PENDING (ON needs EVERY required timer fired).
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer"}))
    assert dmod._posture_backups(repo)[0] == "PENDING"


def test_drill_is_required_a_backup_alone_is_not_durability(monkeypatch, tmp_path):
    repo = _mk_units(tmp_path)
    _systemctl_present(monkeypatch)
    # backup enabled + fired, but the recovery DRILL is disabled → OFF (a backup you never restore is a hope).
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer"}, fired={"vigil-backup.timer"}))
    assert dmod._posture_backups(repo)[0] == "OFF"
    # NEGATIVE CONTROL: enable + fire the drill too → ON.
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    assert dmod._posture_backups(repo)[0] == "ON"


def test_backup_push_counts_as_the_backup_alternative(monkeypatch, tmp_path):
    # vigil-backup and vigil-backup-push are ALTERNATIVES — the off-host push satisfies the backup leg even
    # with the air-gapped local backup timer disabled.
    repo = _mk_units(tmp_path)
    _systemctl_present(monkeypatch)
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup-push.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup-push.timer", "vigil-backup-drill.timer"}))
    assert dmod._posture_backups(repo)[0] == "ON"
    # NEGATIVE CONTROL: disable BOTH backup alternatives (drill alone) → OFF.
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup-drill.timer"},
                                        fired={"vigil-backup-drill.timer"}))
    assert dmod._posture_backups(repo)[0] == "OFF"


def test_backups_unknown_when_systemctl_absent(monkeypatch, tmp_path):
    repo = _mk_units(tmp_path)
    monkeypatch.setattr(dmod.shutil, "which", lambda n: None)     # systemctl not on PATH
    assert dmod._posture_backups(repo)[0] == "UNKNOWN"
    # NEGATIVE CONTROL: with systemctl present + the set engaged → ON (proves UNKNOWN was the absence, not a
    # constant).
    _systemctl_present(monkeypatch)
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    assert dmod._posture_backups(repo)[0] == "ON"


def test_backups_unknown_when_a_canonical_unit_is_missing_from_the_tree(monkeypatch, tmp_path):
    # fail-closed: the drill unit file is absent → the probe can't confirm durability → UNKNOWN, naming it
    # (never silently treats a missing required control as satisfied).
    repo = _mk_units(tmp_path, names=("vigil-backup.timer", "vigil-reprove.timer"))
    _systemctl_present(monkeypatch)
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer"}, fired={"vigil-backup.timer"}))
    state, detail = dmod._posture_backups(repo)
    assert state == "UNKNOWN" and "vigil-backup-drill.timer" in detail


# --------------------------------------------------------------------------- doctor reports each timer (AC 2)

def test_doctor_reports_each_timer_enabled_state_and_last_run(monkeypatch, tmp_path):
    repo = _mk_units(tmp_path)
    _systemctl_present(monkeypatch)
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer"}, fired={"vigil-backup.timer"}))
    rep = dmod._backup_timers_report(repo)
    by = {t["name"]: t for t in rep}
    assert set(by) == set(_ALL)                                  # EVERY timer is reported
    # the fired+enabled one carries a real last-run; the untouched one is disabled with no last-run.
    assert by["vigil-backup.timer"]["enabled"] is True
    assert by["vigil-backup.timer"]["last_run"] and by["vigil-backup.timer"]["last_ok"] is True
    assert by["vigil-backup-push.timer"]["enabled"] is False
    assert by["vigil-backup-push.timer"]["last_run"] is None and by["vigil-backup-push.timer"]["last_ok"] is False
    # the human render carries a per-timer section naming each timer + its last successful run.
    txt = dmod.render({"backup_timers": rep})
    assert "Backup / cadence timers" in txt
    assert "vigil-backup.timer" in txt and "last ran" in txt
    assert "vigil-backup-push.timer" in txt and "disabled" in txt


# --------------------------------------------------------------------------- PRODUCTION gate wiring (AC 3/5/6)

def _all_other_controls_satisfied(monkeypatch, tmp_path) -> pathlib.Path:
    """Provision the FOUR non-backup production preconditions (vault/sovereignty/entitlement/charter) so the
    gate outcome is driven ONLY by the `backups` control, and lay down the backup timer unit FILES so the
    probe can evaluate them. The caller sets the fake systemctl to choose the backups state."""
    repo = _mk_units(tmp_path)
    # vault SEALED
    home = tmp_path / ".sigil"
    (home / "vault").mkdir(parents=True)
    (home / "vault" / dmod._VAULT_SEAL_PUB).write_bytes(b"pub")
    (home / "vault" / dmod._VAULT_SEAL_PRIV).write_bytes(b"priv")
    monkeypatch.setenv("SIGIL_HOME", str(home))
    # sovereignty non-PERMISSIVE
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    # entitlement ACTIVE
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    # charter PRESENT
    cruc = tmp_path / "cruc"
    (cruc / "targets" / "acme").mkdir(parents=True)
    (cruc / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    (cruc / "targets" / "acme" / "charter.md").write_text("# charter\n", encoding="utf-8")
    auth = cruc / "framework" / "v2" / ".authority"
    auth.mkdir(parents=True)
    (auth / "acme.authority.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CRUCIBLE_ROOT", str(cruc))
    monkeypatch.setenv("VIGIL_ENGAGEMENT", "acme")
    _systemctl_present(monkeypatch)
    return repo


def test_production_gate_refuses_on_never_fired_and_disabled_timer(monkeypatch, tmp_path):
    repo = _all_other_controls_satisfied(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_POSTURE", "production")

    # (a) enabled but NEVER FIRED ⇒ PENDING ⇒ gate REFUSES on `backups` ALONE.
    #     THIS FAILS WITHOUT THE CHANGE: the old probe returned ON for at-least-one-enabled, so a backup
    #     that had never actually run would satisfy the gate and `res["ok"]` would be True.
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    res = dmod.evaluate_production_gate(repo)
    assert res["ok"] is False
    assert [e["control"] for e in res["unmet"]] == ["backups"]
    bk = next(c for c in res["controls"] if c["control"] == "backups")
    assert bk["state"] == "PENDING" and bk["met"] is False

    # (b) NEGATIVE CONTROL, same run: DISABLE the timers ⇒ OFF ⇒ still refused (the gate is not a no-op).
    monkeypatch.setattr(dmod.subprocess, "run", _fake_systemctl())
    res2 = dmod.evaluate_production_gate(repo)
    assert res2["ok"] is False
    assert next(c for c in res2["controls"] if c["control"] == "backups")["state"] == "OFF"

    # (c) POSITIVE CONTROL, same run: enable + FIRE both ⇒ ON ⇒ backups is met and the gate passes.
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    res3 = dmod.evaluate_production_gate(repo)
    assert next(c for c in res3["controls"] if c["control"] == "backups")["state"] == "ON"
    assert res3["ok"] is True, [f"{e['control']}={e['state']}" for e in res3["unmet"]]


# --------------------------------------------------------------------------- the units + bootstrap ship (AC 1)

def test_required_backup_timer_units_ship_in_repo():
    sysd = _REPO / "infra" / "systemd"
    for timer in (*dmod._BACKUP_TIMER_ALTERNATIVES, *dmod._BACKUP_TIMER_REQUIRED):
        assert (sysd / timer).is_file(), f"required backup timer unit missing from the repo: {timer}"
        service = timer[: -len(".timer")] + ".service"
        assert (sysd / service).is_file(), f"the paired service the timer triggers is missing: {service}"


def test_bootstrap_installs_and_enables_the_backup_timers():
    text = (_REPO / "bootstrap.sh").read_text(encoding="utf-8")
    # installs the infra/systemd vigil units (not only the sigil cockpit/consolidate ones)
    assert "infra/systemd" in text, "bootstrap does not install the infra/systemd units"
    # enables the backup + drill timers, and does so under the production posture selector
    assert "vigil-backup.timer" in text and "vigil-backup-drill.timer" in text
    assert "enable --now" in text
    assert "VIGIL_POSTURE" in text or "--production" in text, \
        "bootstrap does not gate timer enablement on the production posture"
