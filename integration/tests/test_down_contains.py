"""W10-5 (#477) — `vigil down` actually CONTAINS; the systemd unit cannot revive the stack.

The defect: `vigil-command.service` sets `Restart=always`/`RestartSec=5`, so a bare pid-kill of the
orchestrator (the unit's MainPID) is undone by systemd within ~5 s. Containment must therefore
stop-AND-disable the unit — a clean `systemctl stop` (which does not trigger `Restart=`) plus a
`disable` (so a reboot does not restore it). And the `StartLimit*` knobs must live in `[Unit]`, where
systemd reads them, not `[Service]`, where they are silently ignored.

These tests are framework-FREE (they exercise the pure-stdlib containment path + parse the unit file),
so they run in the sovereign CI leg by construction. The end-to-end live-systemd assertion (install,
start, `vigil down`, still-down-30 s-later) is `test_down_stays_down_under_live_systemd`, gated behind
`VIGIL_LIVE_SYSTEMD=1` because it needs a real user systemd session.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_down_contains.py -q
"""
from __future__ import annotations

import os
import types
from pathlib import Path

import pytest

from vigil_integration import uiproxy

_REPO = Path(__file__).resolve().parents[2]
_UNIT_FILE = _REPO / "infra" / "systemd" / "vigil-command.service"


class FakeSystemctl:
    """A stand-in for ``subprocess.run(["systemctl", "--user", <verb>, ...])`` that records the verbs
    issued and answers `cat`/`is-active` per the configured (known, active) state."""

    def __init__(self, *, known: bool = True, active: bool = True) -> None:
        self.known = known
        self.active = active
        self.calls: list[list[str]] = []

    def __call__(self, argv, capture_output=None, text=None, timeout=None):
        self.calls.append(list(argv))
        assert argv[:2] == ["systemctl", "--user"], argv
        verb = argv[2]
        rc, out = 0, ""
        if verb == "cat":
            rc, out = (0, "unit body") if self.known else (1, "")
        elif verb == "is-active":
            out = "active" if self.active else "inactive"
            rc = 0 if self.active else 3
        # disable / stop / mask succeed (rc 0)
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")

    @property
    def verbs(self) -> list[str]:
        return [c[2] for c in self.calls]


# --------------------------------------------------------------------------------------------------
# _contain_service_unit — the branch matrix
# --------------------------------------------------------------------------------------------------

def test_manual_down_disables_and_stops_a_managed_active_unit(monkeypatch):
    # THE FIX. A manual `vigil down` on a running, systemd-managed unit must DISABLE it (no boot
    # restore) and STOP it cleanly (a clean stop does not trigger Restart=). On the pre-fix tree
    # run_down never touched systemctl, so this assertion FAILS without the change.
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    ctl = FakeSystemctl(known=True, active=True)
    actions = uiproxy._contain_service_unit(mask=False, run=ctl, env={})
    assert "disable" in ctl.verbs
    assert "stop" in ctl.verbs
    assert any("disabled" in a for a in actions)
    assert any("stopped" in a for a in actions)


def test_execstop_skips_the_stop_to_avoid_a_recursive_deadlock():
    # NEGATIVE CONTROL: a naive "always stop" implementation would deadlock when run as the unit's own
    # ExecStop (systemd is already stopping us, TimeoutStopSec would elapse). When $SERVICE_RESULT is
    # present we must DISABLE but NOT issue `stop` (and not even probe is-active).
    ctl = FakeSystemctl(known=True, active=True)
    actions = uiproxy._contain_service_unit(mask=False, run=ctl, env={"SERVICE_RESULT": "success"})
    assert "disable" in ctl.verbs
    assert "stop" not in ctl.verbs
    assert "is-active" not in ctl.verbs
    assert any("ExecStop" in a for a in actions)


def test_unknown_unit_issues_no_disable_or_stop(monkeypatch):
    # NEGATIVE CONTROL: containment is CONDITIONAL, not a blind always-fire. When systemd does not know
    # the unit (started by hand / no user manager), no disable/stop/mask is issued — the pid-kill is the
    # whole containment.
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    ctl = FakeSystemctl(known=False)
    actions = uiproxy._contain_service_unit(mask=False, run=ctl, env={})
    assert ctl.verbs == ["cat"]  # only the existence probe ran
    assert "disable" not in ctl.verbs and "stop" not in ctl.verbs and "mask" not in ctl.verbs
    assert actions == []


def test_managed_but_inactive_unit_is_disabled_not_stopped(monkeypatch):
    # A known-but-already-down unit is disabled (so a reboot cannot restore it) but not stopped (nothing
    # to stop). Proves the stop is gated on liveness, not fired unconditionally.
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    ctl = FakeSystemctl(known=True, active=False)
    uiproxy._contain_service_unit(mask=False, run=ctl, env={})
    assert "disable" in ctl.verbs
    assert "is-active" in ctl.verbs
    assert "stop" not in ctl.verbs


def test_panic_masks_the_unit(monkeypatch):
    # Panic is stricter than down: it MASKS the unit so even a manual `systemctl start` is refused.
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    ctl = FakeSystemctl(known=True, active=True)
    actions = uiproxy._contain_service_unit(mask=True, run=ctl, env={})
    assert "mask" in ctl.verbs
    assert any("masked" in a for a in actions)


def test_no_user_manager_is_a_clean_noop_not_a_failure():
    # If systemctl is absent entirely, _systemctl returns rc 127 and _unit_is_known is False → no
    # containment attempted, no exception. Containment must never fail the down/panic path.
    def _absent(argv, **_kw):
        raise FileNotFoundError("systemctl")

    assert uiproxy._contain_service_unit(mask=False, run=_absent, env={}) == []


# --------------------------------------------------------------------------------------------------
# run_down / run_panic — containment happens, before the pid-kill
# --------------------------------------------------------------------------------------------------

def test_run_down_contains_the_unit_a_bare_pidkill_would_be_revived(tmp_path, monkeypatch, capsys):
    # THE FIX, at the verb level. No pids file ⇒ the pid-kill is a no-op, isolating the systemd half.
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    ctl = FakeSystemctl(known=True, active=True)
    rc = uiproxy.run_down(base_dir=str(tmp_path), run=ctl)
    assert rc == 0
    # a bare pid-kill would revive within RestartSec — the fix converts down into disable + clean stop.
    assert "disable" in ctl.verbs and "stop" in ctl.verbs


def test_run_panic_masks_and_stops_the_unit(tmp_path, monkeypatch):
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    # run_panic now also resets the sidecar timers' Persistent= catch-up stamps (W10-5b, #478); isolate
    # XDG_DATA_HOME so the stamp writes land in tmp, never the real ~/.local/share/systemd/timers.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemctl(known=True, active=True)
    rc = uiproxy.run_panic(base_dir=str(tmp_path), run=ctl)
    assert rc == 0
    assert {"disable", "mask", "stop"} <= set(ctl.verbs)


def test_run_down_started_by_hand_still_reaps_pids(tmp_path, monkeypatch):
    # No systemd unit; a tracked (already-dead) pid entry still drives the pid-kill path to completion.
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    pids = tmp_path / "ui" / "pids"
    pids.parent.mkdir(parents=True)
    pids.write_text('[{"name": "orchestrator", "pid": 2147480000}]', encoding="utf-8")
    ctl = FakeSystemctl(known=False)  # started by hand → no unit
    rc = uiproxy.run_down(base_dir=str(tmp_path), run=ctl)
    assert rc == 0
    assert not pids.exists()  # pids file consumed
    assert "disable" not in ctl.verbs


# --------------------------------------------------------------------------------------------------
# the unit file: StartLimit* must live in [Unit], not [Service]
# --------------------------------------------------------------------------------------------------

def _section_of_keys(unit_text: str) -> dict[str, str]:
    """Map each assigned KEY to the [Section] it appears under."""
    section = ""
    where: dict[str, str] = {}
    for raw in unit_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" in line:
            key = line.split("=", 1)[0].strip()
            where.setdefault(key, section)  # first occurrence wins (systemd uses last, but placement is
            where[key] = section            # what matters); record the section it is written under
    return where


def test_startlimit_directives_are_in_the_unit_section():
    # systemd reads StartLimitIntervalSec/StartLimitBurst from [Unit]; in [Service] they are IGNORED, so
    # the crash-loop burst cap never engages. On the pre-fix tree these sat in [Service] → this FAILS.
    assert _UNIT_FILE.is_file(), _UNIT_FILE
    where = _section_of_keys(_UNIT_FILE.read_text(encoding="utf-8"))
    assert where.get("StartLimitIntervalSec") == "Unit", where
    assert where.get("StartLimitBurst") == "Unit", where


def test_unit_execstop_is_vigil_down():
    # `vigil down` IS the containment path, so it must be what systemd runs on stop.
    text = _UNIT_FILE.read_text(encoding="utf-8")
    assert "ExecStop=" in text and "vigil down" in text


# --------------------------------------------------------------------------------------------------
# live systemd — the real "still down 30 s later" assertion (skipped without a user systemd session)
# --------------------------------------------------------------------------------------------------

@pytest.mark.skipif(os.environ.get("VIGIL_LIVE_SYSTEMD") != "1",
                    reason="needs a real user systemd session (set VIGIL_LIVE_SYSTEMD=1)")
def test_down_stays_down_under_live_systemd(tmp_path):  # pragma: no cover — live-only residual
    """Install a minimal proxy unit modelled on vigil-command.service (Restart=always, RestartSec=1),
    start it, run our containment, and assert it is still inactive after a wait that exceeds several
    restart windows. Proves the clean-stop + disable actually defeats Restart=always."""
    import subprocess
    import time

    unit_dir = Path(os.environ["HOME"]) / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit = "vigil-down-selftest.service"
    (unit_dir / unit).write_text(
        "[Unit]\nDescription=vigil down containment self-test\n"
        "StartLimitIntervalSec=0\n\n"
        "[Service]\nType=simple\nExecStart=/bin/sh -c 'while :; do sleep 1; done'\n"
        "Restart=always\nRestartSec=1\n\n[Install]\nWantedBy=default.target\n",
        encoding="utf-8")

    def sc(*a, check=True):
        return subprocess.run(["systemctl", "--user", *a], capture_output=True, text=True, check=check)

    try:
        sc("daemon-reload")
        sc("enable", "--now", unit)
        time.sleep(2)
        assert sc("is-active", unit, check=False).stdout.strip() == "active"
        # our containment primitive, retargeted at the self-test unit:
        monkey_unit = uiproxy._SERVICE_UNIT
        uiproxy._SERVICE_UNIT = unit
        try:
            uiproxy._contain_service_unit(mask=False, env={})
        finally:
            uiproxy._SERVICE_UNIT = monkey_unit
        time.sleep(30)  # several RestartSec windows
        assert sc("is-active", unit, check=False).stdout.strip() in ("inactive", "failed", "dead")
    finally:
        sc("stop", unit, check=False)
        sc("disable", unit, check=False)
        (unit_dir / unit).unlink(missing_ok=True)
        sc("daemon-reload", check=False)
