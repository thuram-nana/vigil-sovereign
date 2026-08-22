"""W10-5b (#478) — `vigil panic` stops AND DISABLES every cadence SIDECAR, not just the command unit.

The defect completed by W10-5 (#477) contained only `vigil-command.service`. But VIGIL ships a fleet of
systemd USER *cadence sidecars* whose timers keep ACTING during an incident:

  * `vigil-reprove.timer`     (6 h)   RE-FIRES the retained corpus AGAINST THE LIVE TARGET.
  * `vigil-posture.timer`     (30 m)  RE-SCANS the authorized target.
  * `vigil-ha-mirror.timer`   (15 m)  rsyncs `~/.sigil` OFF-HOST.            ← the shortest interval
  * `vigil-backup-push.timer` (daily) pushes an encrypted backup OFF-HOST.
  * `vigil-backup` / `-drill` / `-integrity` timers run purely locally.

All carry `Persistent=true`, so merely disabling them is not enough — a later RE-ENABLE would fire every
run missed during the incident (a catch-up burst straight back at the target / the off-host store). The
witness co-sign instances (`vigil-witness@<port>.service`) carry `Restart=on-failure`.

`vigil panic` must therefore STOP + DISABLE every timer AND its oneshot service, RESET each timer's
`Persistent=` catch-up stamp, stop every live witness instance, and VERIFY nothing is left active or
enabled. `vigil down` deliberately does NOT touch the sidecars (it is the routine UI stop, not the
emergency hard-stop) — proven here too.

These tests are framework-FREE (they exercise the pure-stdlib containment path with a fake `systemctl`
+ a tmp XDG stamp dir), so they run in the required sovereign CI leg ("integration two-env boundary
(P5)") by construction — no `framework` import, so no offense-leg registration is needed. The
end-to-end live-systemd measurement (a real timer that never fires again after panic, over a window
longer than the shortest interval) is `test_sidecar_stays_down_under_live_systemd`, gated behind
`VIGIL_LIVE_SYSTEMD=1` because it needs a real user systemd session.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_panic_sidecars.py -q
"""
from __future__ import annotations

import os
import time
import types
from pathlib import Path

import pytest

from vigil_integration import uiproxy

_REPO = Path(__file__).resolve().parents[2]
_RUNBOOK = _REPO / "docs" / "runbooks" / "PANIC-AND-CONTAINMENT.md"
_DECISION = _REPO / "docs" / "decisions" / "W10-5b-panic-disables-sidecars.md"


class FakeSystemd:
    """A stand-in for ``subprocess.run(["systemctl", "--user", <verb>, ...])`` that models per-unit
    active/enabled state, honours stop/disable transitions, answers is-active/is-enabled/show and the
    two witness `list-*` enumerations, and records the ORDERED (verb, unit) calls so the documented
    containment order can be asserted."""

    def __init__(self, *, manager: bool = True, witnesses=()) -> None:
        self.manager = manager
        # WORST CASE to contain: every cadence timer + its oneshot service (+ any witness) starts
        # ACTIVE and ENABLED.
        seed = set(uiproxy._SIDECAR_TIMERS) | set(uiproxy._SIDECAR_SERVICES) | set(witnesses)
        self.active = set(seed)
        self.enabled = set(seed)
        self.witnesses = set(witnesses)
        self.calls: list[tuple[str, str | None]] = []

    def __call__(self, argv, capture_output=None, text=None, timeout=None):
        assert argv[:2] == ["systemctl", "--user"], argv
        rest = argv[2:]
        verb = rest[0]
        if not self.manager:
            # No user manager: mirror a bus-connect failure — every call is non-zero, and `show`
            # (the reachability probe) fails, so containment is a clean no-op.
            self.calls.append((verb, rest[-1] if len(rest) > 1 and not rest[-1].startswith("-") else None))
            return types.SimpleNamespace(returncode=1, stdout="", stderr="Failed to connect to bus")
        if verb == "show":
            self.calls.append((verb, None))
            return types.SimpleNamespace(returncode=0, stdout="Version=254", stderr="")
        if verb == "list-units":
            self.calls.append((verb, None))
            body = "\n".join(f"{u} loaded active running witness" for u in sorted(self.witnesses & self.active))
            return types.SimpleNamespace(returncode=0, stdout=body, stderr="")
        if verb == "list-unit-files":
            self.calls.append((verb, None))
            body = "\n".join(f"{u} enabled" for u in sorted(self.witnesses & self.enabled))
            return types.SimpleNamespace(returncode=0, stdout=body, stderr="")
        unit = rest[-1]
        self.calls.append((verb, unit))
        rc, out = 0, ""
        if verb == "stop":
            self.active.discard(unit)
        elif verb == "disable":
            self.enabled.discard(unit)
        elif verb == "cat":
            out = "unit body"  # every unit is "known"
        elif verb == "is-active":
            out, rc = ("active", 0) if unit in self.active else ("inactive", 3)
        elif verb == "is-enabled":
            out, rc = ("enabled", 0) if unit in self.enabled else ("disabled", 1)
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")

    def verbs_for(self, unit: str) -> list[str]:
        return [v for (v, u) in self.calls if u == unit]

    def ordered_units(self, verb: str) -> list[str]:
        return [u for (v, u) in self.calls if v == verb and u is not None]


# --------------------------------------------------------------------------------------------------
# THE FIX — every cadence sidecar is stopped + disabled, target-reaching ones FIRST
# --------------------------------------------------------------------------------------------------

def test_panic_stops_and_disables_every_cadence_sidecar(tmp_path, monkeypatch):
    # THE FIX. On the pre-#478 tree there was no `_contain_sidecar_units` and `vigil panic` touched
    # ONLY the command unit — so none of these stop/disable verbs were ever issued for the sidecars.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    actions = uiproxy._contain_sidecar_units(run=ctl)

    for timer in uiproxy._SIDECAR_TIMERS:
        assert "stop" in ctl.verbs_for(timer), timer
        assert "disable" in ctl.verbs_for(timer), timer
    for svc in uiproxy._SIDECAR_SERVICES:
        assert "stop" in ctl.verbs_for(svc), svc      # interrupt an in-flight oneshot
        assert "disable" in ctl.verbs_for(svc), svc
    assert any("stopped vigil-reprove.timer" in a for a in actions)


def test_documented_order_contains_target_and_offhost_timers_first(tmp_path, monkeypatch):
    # The order is DOCUMENTED, not incidental: the timers that re-drive the target or replicate data
    # off-host are contained before the purely-local ones, so the most dangerous cadence stops first.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    uiproxy._contain_sidecar_units(run=ctl)
    stopped_timers = [u for u in ctl.ordered_units("stop") if u.endswith(".timer")]
    assert stopped_timers[0] == "vigil-reprove.timer"          # re-fires against the LIVE target
    assert (stopped_timers.index("vigil-ha-mirror.timer")      # off-host rsync (15 min)
            < stopped_timers.index("vigil-backup.timer"))      # ... before the local-only backup
    assert (stopped_timers.index("vigil-backup-push.timer")    # off-host push
            < stopped_timers.index("vigil-backup-drill.timer"))


def test_sidecar_service_list_mirrors_the_timer_list():
    # The two lists are derived from one source so they can never drift — each timer has its service.
    assert uiproxy._SIDECAR_SERVICES == tuple(
        t[: -len(".timer")] + ".service" for t in uiproxy._SIDECAR_TIMERS)
    assert len(uiproxy._SIDECAR_TIMERS) == 7  # reprove, posture, ha-mirror, backup-push, backup, drill, integrity


# --------------------------------------------------------------------------------------------------
# Persistent= catch-up — reset so a re-enable does not replay the missed runs (AC)
# --------------------------------------------------------------------------------------------------

def test_panic_resets_the_persistent_catchup_stamp_for_every_timer(tmp_path, monkeypatch):
    # AC: the Persistent=true catch-up is handled EXPLICITLY. Seed a STALE stamp for the shortest-
    # interval timer (as if it last fired 6 h ago) — a re-enable with Persistent=true would otherwise
    # replay every 15-min window since. Panic must move every stamp forward to ~now.
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    stamps = xdg / "systemd" / "timers"
    stamps.mkdir(parents=True)
    stale = stamps / "stamp-vigil-ha-mirror.timer"
    stale.write_text("", encoding="utf-8")
    old = time.time() - 6 * 3600
    os.utime(stale, (old, old))

    ctl = FakeSystemd()
    uiproxy._contain_sidecar_units(run=ctl)

    for timer in uiproxy._SIDECAR_TIMERS:
        p = xdg / "systemd" / "timers" / f"stamp-{timer}"
        assert p.exists(), timer
        assert abs(p.stat().st_mtime - time.time()) < 120, timer   # refreshed to ~now
    assert stale.stat().st_mtime > old + 3600                        # the stale stamp moved forward


def test_stamp_path_honours_xdg_data_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "x"))
    p = uiproxy._timer_stamp_path("vigil-reprove.timer")
    assert p == tmp_path / "x" / "systemd" / "timers" / "stamp-vigil-reprove.timer"
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    p = uiproxy._timer_stamp_path("vigil-reprove.timer")
    assert p == tmp_path / "home" / ".local" / "share" / "systemd" / "timers" / "stamp-vigil-reprove.timer"


# --------------------------------------------------------------------------------------------------
# verify — the negative control: it is NOT a no-op
# --------------------------------------------------------------------------------------------------

def test_verify_reports_a_leak_when_a_unit_survives(tmp_path, monkeypatch):
    # NEGATIVE CONTROL: the verification is a real check, not a rubber stamp. With NOTHING contained,
    # every timer is still active+enabled, so verify must report leaks (a green "verified" here would
    # be the exact fail-open the issue warns about — an operator believing they are contained).
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    ctl = FakeSystemd()
    leaks = uiproxy._verify_sidecar_containment(run=ctl)
    assert leaks
    assert any("vigil-reprove.timer" in leak for leak in leaks)
    assert any("vigil-ha-mirror.timer" in leak for leak in leaks)


def test_verify_is_clean_after_containment(tmp_path, monkeypatch):
    # The positive: once contained, verify finds nothing active or enabled — the measured proof (in
    # the hermetic path) that no timer can fire again to reach the target or push data off-host.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    ctl = FakeSystemd()
    uiproxy._contain_sidecar_units(run=ctl)
    assert uiproxy._verify_sidecar_containment(run=ctl) == []


# --------------------------------------------------------------------------------------------------
# conditional, not blind — no user manager / template / unseen instances
# --------------------------------------------------------------------------------------------------

def test_no_user_manager_contains_nothing(tmp_path, monkeypatch):
    # NEGATIVE CONTROL: containment is CONDITIONAL. With no user manager, only the reachability probe
    # (`show`) runs — never a blind stop/disable — and both containment and verify are clean no-ops.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    ctl = FakeSystemd(manager=False)
    assert uiproxy._contain_sidecar_units(run=ctl) == []
    assert uiproxy._verify_sidecar_containment(run=ctl) == []
    assert [v for (v, _u) in ctl.calls] == ["show", "show"]  # one probe per function, nothing else


def test_only_live_witness_instances_are_contained(tmp_path, monkeypatch):
    # NEGATIVE CONTROL: witness instances are enumerated, not guessed. A port we actually ran is
    # stopped+disabled; the bare TEMPLATE (nothing to stop) and a port we never ran are left alone.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    ctl = FakeSystemd(witnesses={"vigil-witness@8801.service"})
    uiproxy._contain_sidecar_units(run=ctl)
    assert {"stop", "disable"} <= set(ctl.verbs_for("vigil-witness@8801.service"))
    assert ctl.verbs_for("vigil-witness@.service") == []   # the template itself is never targeted
    assert ctl.verbs_for("vigil-witness@9999.service") == []  # a port we never ran is never touched


# --------------------------------------------------------------------------------------------------
# run_panic wires it together; run_down deliberately does NOT
# --------------------------------------------------------------------------------------------------

def test_run_panic_contains_the_sidecars_and_verifies(tmp_path, monkeypatch, capsys):
    # THE FIX at the entrypoint level. On the pre-#478 tree `run_panic` never issued a single verb for
    # the reprove / ha-mirror timers, so both asserts below FAIL without the change.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    ctl = FakeSystemd()
    rc = uiproxy.run_panic(base_dir=str(tmp_path), run=ctl)
    assert rc == 0
    assert {"stop", "disable"} <= set(ctl.verbs_for("vigil-reprove.timer"))
    assert {"stop", "disable"} <= set(ctl.verbs_for("vigil-ha-mirror.timer"))
    out = capsys.readouterr().out
    assert "containment verified" in out


def test_run_down_leaves_the_sidecars_alone(tmp_path, monkeypatch):
    # `vigil down` is the ROUTINE UI stop, not the emergency hard-stop: it must NOT disable an
    # operator's backup/reprove/HA timers. It touches the command unit only.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("SERVICE_RESULT", raising=False)
    ctl = FakeSystemd()
    uiproxy.run_down(base_dir=str(tmp_path), run=ctl)
    for timer in uiproxy._SIDECAR_TIMERS:
        assert ctl.verbs_for(timer) == [], timer  # down never touched a single sidecar timer


# --------------------------------------------------------------------------------------------------
# doc-truth — the runbook + decision record are TRUE of the code (claims-registry substitute, #398)
# --------------------------------------------------------------------------------------------------

def test_runbook_names_every_sidecar_and_drops_the_stale_residual():
    text = _RUNBOOK.read_text(encoding="utf-8")
    for unit in uiproxy._SIDECAR_TIMERS:
        assert unit in text, f"runbook must name {unit}"
    assert "vigil-witness@" in text
    # the #477 runbook's "panic does not YET disable the sidecar timers" residual must be gone
    assert "does not yet disable the sidecar" not in text.lower()


def test_decision_record_exists_and_pins_the_claim():
    text = _DECISION.read_text(encoding="utf-8")
    assert "#478" in text and "W10-5b" in text
    assert "398" in text  # references the pending claims registry it will fold into
    assert "Persistent" in text


# --------------------------------------------------------------------------------------------------
# live systemd — the real "no run fires after panic over a >interval window" measurement
# --------------------------------------------------------------------------------------------------

@pytest.mark.skipif(os.environ.get("VIGIL_LIVE_SYSTEMD") != "1",
                    reason="needs a real user systemd session (set VIGIL_LIVE_SYSTEMD=1)")
def test_sidecar_stays_down_under_live_systemd(tmp_path):  # pragma: no cover — live-only residual
    """Install a minimal Persistent timer (every minute) whose oneshot appends a line to a witness
    file — a stand-in for "traffic reached the target / data pushed off-host". Enable it, let it fire
    once, then run our containment retargeted at it, and assert NO further line appears over a window
    that exceeds the timer interval — the negative control from the AC (measured, not assumed). The
    real cadence VIGIL ships (ha-mirror, 15 min) is the same shape with a longer interval."""
    import subprocess

    unit_dir = Path(os.environ["HOME"]) / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    witness = tmp_path / "target-hits.log"
    svc = "vigil-sidecar-selftest.service"
    tmr = "vigil-sidecar-selftest.timer"
    (unit_dir / svc).write_text(
        "[Unit]\nDescription=vigil sidecar containment self-test\n\n"
        f"[Service]\nType=oneshot\nExecStart=/bin/sh -c 'echo hit >> {witness}'\n",
        encoding="utf-8")
    (unit_dir / tmr).write_text(
        "[Unit]\nDescription=vigil sidecar self-test timer\n\n"
        "[Timer]\nOnCalendar=*:*:0/20\nPersistent=true\nUnit=" + svc + "\n\n"
        "[Install]\nWantedBy=timers.target\n",
        encoding="utf-8")

    def sc(*a, check=True):
        return subprocess.run(["systemctl", "--user", *a], capture_output=True, text=True, check=check)

    orig_timers, orig_services = uiproxy._SIDECAR_TIMERS, uiproxy._SIDECAR_SERVICES
    try:
        sc("daemon-reload")
        sc("enable", "--now", tmr)
        time.sleep(25)  # let it fire at least once
        assert witness.exists() and witness.read_text().count("hit") >= 1
        before = witness.read_text().count("hit")
        uiproxy._SIDECAR_TIMERS = (tmr,)
        uiproxy._SIDECAR_SERVICES = (svc,)
        actions = uiproxy._contain_sidecar_units()
        assert any("stopped" in a for a in actions)
        assert uiproxy._verify_sidecar_containment() == []  # nothing active or enabled
        time.sleep(70)  # several timer windows
        assert witness.read_text().count("hit") == before  # NO further fire reached the "target"
    finally:
        uiproxy._SIDECAR_TIMERS, uiproxy._SIDECAR_SERVICES = orig_timers, orig_services
        sc("stop", tmr, check=False)
        sc("disable", tmr, check=False)
        (unit_dir / svc).unlink(missing_ok=True)
        (unit_dir / tmr).unlink(missing_ok=True)
        sc("daemon-reload", check=False)
