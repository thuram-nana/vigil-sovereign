"""`vigil panic` also contains the sovereign plane and the drains.

After the command unit, the cadence sidecars and the tracked pids, panic stops AND disables: every drain and sovereign
timer (settle, billing, Stripe billing, findings, checkpoint, consolidate — each with its Persistent= catch-up stamp
reset), the customer and public edges, every live phone bridge (`sigil-bridge@<addr>`), and the cockpit LAST (the
writer; it finishes the requests it already accepted — each stop waits longer than the unit's own TimeoutStopSec, and a
stop still draining is reported as such). The checkpoint and consolidate passes are stopped; a DRAIN pass already in
flight is never interrupted — panic waits for it ONCE, bounded, after everything else is contained (and the tracked
pids are killed), and reports a pass still running after the bound; a fleet kill waits once after every revocation.
A panic running inside the command unit's own cgroup (the console's PANIC button) contains everything else first and
stops the command unit last. The post-condition check covers every one of these units, running (`deactivating`
included) or enabled — except a drain still finishing a pass, which is reported as finishing, never as a leak to
stop by hand (only a drain left enabled is one). `vigil down` touches none of them.

Framework-free (a fake `systemctl`, an injected clock): runs in the integration two-env boundary leg.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_panic_sovereign.py -q
"""
from __future__ import annotations

import re
import types
from pathlib import Path

import pytest

from vigil_integration import fleet_monitor, uiproxy

_REPO = Path(__file__).resolve().parents[2]
_RUNBOOK = _REPO / "docs" / "runbooks" / "PANIC-AND-CONTAINMENT.md"
_BRIDGES = ("sigil-bridge@10.0.0.2.service", "sigil-bridge@100.64.1.5.service")


class FakeSystemd:
    """``systemctl --user`` with per-unit active/enabled state, ordered call log, the bridge enumerations, and drain
    passes that stay ``active`` for a number of is-active polls (``busy``), ignoring ``stop`` (a drain is never
    stopped by panic — if it were, the call log shows it)."""

    def __init__(self, *, manager=True, busy=None, bridges=_BRIDGES):
        self.manager = manager
        units = (set(uiproxy._SOVEREIGN_TIMERS) | set(uiproxy._DRAIN_SERVICES) | set(uiproxy._SOVEREIGN_ONESHOTS)
                 | set(uiproxy._SOVEREIGN_EDGES) | {uiproxy._SOVEREIGN_WRITER} | set(bridges)
                 | set(uiproxy._SIDECAR_TIMERS) | set(uiproxy._SIDECAR_SERVICES))
        self.active, self.enabled = set(units), set(units)
        self.bridges = set(bridges)
        self.busy = dict(busy or {})         # drain -> remaining is-active polls it stays active
        for d in uiproxy._DRAIN_SERVICES:
            if d not in self.busy:
                self.active.discard(d)       # an idle drain: its timer is what is active
        self.calls: list = []

    def __call__(self, argv, capture_output=None, text=None, timeout=None):
        assert argv[:2] == ["systemctl", "--user"], argv
        rest = argv[2:]
        verb = rest[0]
        ok = types.SimpleNamespace
        if not self.manager:
            self.calls.append((verb, None))
            return ok(returncode=1, stdout="", stderr="Failed to connect to bus")
        if verb == "show":
            return ok(returncode=0, stdout="Version=254", stderr="")
        if verb in ("list-units", "list-unit-files"):
            glob = rest[-1]
            pool = self.bridges if glob == uiproxy._BRIDGE_GLOB else set()
            live = (pool & self.active) if verb == "list-units" else (pool & self.enabled)
            return ok(returncode=0, stdout="\n".join(f"{u} loaded active running x" for u in sorted(live)), stderr="")
        unit = rest[-1]
        self.calls.append((verb, unit))
        if verb == "stop":
            if unit in self.busy:
                return ok(returncode=0, stdout="", stderr="")   # recorded; the assertion below forbids it
            self.active.discard(unit)
        elif verb == "disable":
            self.enabled.discard(unit)
        elif verb == "cat":
            return ok(returncode=0, stdout="unit", stderr="")
        elif verb == "is-active":
            if unit in self.busy:
                self.busy[unit] -= 1
                if self.busy[unit] < 0:
                    del self.busy[unit]
                    self.active.discard(unit)
            return ok(returncode=0 if unit in self.active else 3,
                      stdout="active" if unit in self.active else "inactive", stderr="")
        elif verb == "is-enabled":
            return ok(returncode=0 if unit in self.enabled else 1,
                      stdout="enabled" if unit in self.enabled else "disabled", stderr="")
        return ok(returncode=0, stdout="", stderr="")

    def verbs_for(self, unit):
        return [v for (v, u) in self.calls if u == unit]

    def order(self, verb):
        return [u for (v, u) in self.calls if v == verb and u is not None]


class Clock:
    def __init__(self):
        self.t = 0.0
        self.slept: list = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def _contain(ctl, clock=None, wait_s=None):
    """Containment, then the one bounded drain wait — what `run_panic` does for the sovereign plane."""
    clock = clock or Clock()
    return (uiproxy._contain_sovereign_units(run=ctl)
            + uiproxy.await_drains(run=ctl, wait_s=wait_s, sleep=clock.sleep, clock=clock.now))


def test_panic_stops_and_disables_every_sovereign_unit_and_drain_timer(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    _contain(ctl)
    for unit in (*uiproxy._SOVEREIGN_TIMERS, *uiproxy._SOVEREIGN_EDGES, uiproxy._SOVEREIGN_WRITER, *_BRIDGES,
                 *uiproxy._SOVEREIGN_ONESHOTS):
        assert "stop" in ctl.verbs_for(unit) and "disable" in ctl.verbs_for(unit), unit
    for drain in uiproxy._DRAIN_SERVICES:
        assert "disable" in ctl.verbs_for(drain), drain
    assert uiproxy._verify_sovereign_containment(run=ctl) == []
    for timer in uiproxy._SOVEREIGN_TIMERS:                       # no catch-up burst on a later re-enable
        assert (tmp_path / "xdg" / "systemd" / "timers" / f"stamp-{timer}").exists(), timer


def test_the_inventory_is_the_shipped_units():
    shipped = {p.name for d in ("infra/systemd", "apps/sigil/deploy/systemd") for p in (_REPO / d).iterdir()}
    for unit in (*uiproxy._SOVEREIGN_TIMERS, *uiproxy._DRAIN_SERVICES, *uiproxy._SOVEREIGN_ONESHOTS,
                 *uiproxy._SOVEREIGN_EDGES, uiproxy._SOVEREIGN_WRITER, uiproxy._BRIDGE_TEMPLATE):
        assert unit in shipped, unit
    drains = {"vigil-settle-drain.service", "vigil-billing-drain.service", "vigil-billing-drain-stripe.service",
              "vigil-finding-drain.service"}
    assert set(uiproxy._DRAIN_SERVICES) == drains


def test_timers_first_then_edges_then_bridges_then_the_cockpit_last(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    _contain(ctl)
    stops = ctl.order("stop")
    last_timer = max(stops.index(t) for t in uiproxy._SOVEREIGN_TIMERS)
    first_edge = min(stops.index(e) for e in uiproxy._SOVEREIGN_EDGES)
    assert last_timer < first_edge                                # no new drain pass starts mid-panic
    assert max(stops.index(e) for e in (*uiproxy._SOVEREIGN_EDGES, *_BRIDGES)) < stops.index(uiproxy._SOVEREIGN_WRITER)
    assert all(stops.index(uiproxy._SOVEREIGN_WRITER) < stops.index(o) for o in uiproxy._SOVEREIGN_ONESHOTS)


def test_a_drain_pass_in_flight_is_waited_for_and_never_stopped(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd(busy={"vigil-settle-drain.service": 3})
    clock = Clock()
    actions = _contain(ctl, clock)
    assert "stop" not in ctl.verbs_for("vigil-settle-drain.service")      # a settle is never interrupted
    assert clock.slept and clock.t <= uiproxy._DRAIN_WAIT_S               # it waited, within the bound
    assert "vigil-settle-drain.service" not in ctl.active
    assert not any("still finishing" in a for a in actions)
    assert uiproxy._verify_sovereign_containment(run=ctl) == []


def test_a_drain_pass_still_running_after_the_bound_is_reported_not_interrupted(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd(busy={"vigil-billing-drain.service": 10_000})
    clock = Clock()
    actions = _contain(ctl, clock, wait_s=10.0)
    assert 10.0 <= clock.t < 13.0                                        # bounded: panic is never blocked
    assert "stop" not in ctl.verbs_for("vigil-billing-drain.service")
    assert any("vigil-billing-drain.service is still finishing a pass" in a for a in actions)
    # a pass still finishing is reported above as such, NOT as a leak to stop by hand: it must never be interrupted
    assert uiproxy._verify_sovereign_containment(run=ctl) == []


def test_a_drain_left_enabled_is_still_a_leak(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    real = ctl.__call__

    def stuck(argv, **kw):                       # the drain service refuses to be disabled
        if argv[2:] == ["disable", "vigil-settle-drain.service"]:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="refused")
        return real(argv, **kw)
    ctl.enabled.add("vigil-settle-drain.service")
    _contain(stuck)
    assert uiproxy._verify_sovereign_containment(run=stuck) == ["vigil-settle-drain.service is still enabled"]


def test_the_bridge_template_is_never_stopped_or_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd(bridges=(*_BRIDGES, uiproxy._BRIDGE_TEMPLATE))
    assert uiproxy._BRIDGE_TEMPLATE not in uiproxy._bridge_instances(run=ctl)
    _contain(ctl)
    assert ctl.verbs_for(uiproxy._BRIDGE_TEMPLATE) == []
    assert all("disable" in ctl.verbs_for(b) for b in _BRIDGES)


def test_no_user_manager_contains_nothing():
    ctl = FakeSystemd(manager=False)
    assert _contain(ctl) == [] and uiproxy._verify_sovereign_containment(run=ctl) == []


def test_run_panic_contains_the_sovereign_plane_and_verifies(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    clock = Clock()
    rc = uiproxy.run_panic(base_dir=str(tmp_path), run=ctl, sleep=clock.sleep, clock=clock.now)
    out = capsys.readouterr().out
    assert rc == 0
    assert f"stopped {uiproxy._SOVEREIGN_WRITER}" in out and "stopped sigil-customer.service" in out
    assert "containment verified (nothing active or enabled)" in out
    assert "sovereign unit and drain is stopped + disabled" in out


def test_a_sovereign_leak_is_reported_by_run_panic(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    real = ctl.__call__

    def stubborn(argv, **kw):                    # the cockpit refuses to stop
        if argv[2:] == ["stop", uiproxy._SOVEREIGN_WRITER]:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="refused")
        return real(argv, **kw)
    clock = Clock()
    uiproxy.run_panic(base_dir=str(tmp_path), run=stubborn, sleep=clock.sleep, clock=clock.now)
    err = capsys.readouterr().err
    assert f"{uiproxy._SOVEREIGN_WRITER} is still active" in err and "do NOT assume" in err


def test_vigil_down_leaves_the_sovereign_plane_alone(tmp_path, monkeypatch):
    ctl = FakeSystemd()
    monkeypatch.setattr(uiproxy, "_kill_tracked_pids", lambda base, label="": (0, 0))
    uiproxy.run_down(base_dir=str(tmp_path), run=ctl)
    for unit in (*uiproxy._SOVEREIGN_TIMERS, *uiproxy._SOVEREIGN_EDGES, uiproxy._SOVEREIGN_WRITER, *_BRIDGES):
        assert ctl.verbs_for(unit) == [], unit


def test_the_runbook_names_the_sovereign_units_and_the_drain_rule():
    text = _RUNBOOK.read_text(encoding="utf-8")
    for unit in (*uiproxy._SOVEREIGN_TIMERS, *uiproxy._SOVEREIGN_EDGES, uiproxy._SOVEREIGN_WRITER, "sigil-bridge@"):
        assert unit in text, unit
    assert "never interrupted" in text


def test_a_unit_left_enabled_is_reported_by_run_panic(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    real = ctl.__call__

    def sticky(argv, **kw):                      # the cockpit stops but cannot be disabled: it would return at boot
        if argv[2:] == ["disable", uiproxy._SOVEREIGN_WRITER]:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="read-only unit dir")
        return real(argv, **kw)
    clock = Clock()
    uiproxy.run_panic(base_dir=str(tmp_path), run=sticky, sleep=clock.sleep, clock=clock.now,
                      inside_command_unit=False)
    captured = capsys.readouterr()
    assert f"{uiproxy._SOVEREIGN_WRITER} is still enabled" in captured.err and "do NOT assume" in captured.err
    assert f"could not disable {uiproxy._SOVEREIGN_WRITER}" in captured.out
    assert "containment verified" not in captured.out


def test_the_tracked_pids_are_killed_before_the_one_drain_wait(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    events: list = []
    clock = Clock()
    ctl = FakeSystemd(busy={"vigil-billing-drain.service": 10_000})
    real = ctl.__call__

    def logged(argv, **kw):
        if argv[2:3] == ["stop"]:
            events.append(("stop", argv[-1], clock.t))
        return real(argv, **kw)

    def sleep(s):
        events.append(("sleep", None, clock.t))
        clock.sleep(s)
    monkeypatch.setattr(uiproxy, "_kill_tracked_pids",
                        lambda base, label="": (events.append(("kill_pids", None, clock.t)), (0, 0))[1])
    uiproxy.run_panic(base_dir=str(tmp_path), run=logged, drain_wait_s=10.0, sleep=sleep, clock=clock.now,
                      inside_command_unit=False)
    kinds = [k for k, _u, _t in events]
    kill = kinds.index("kill_pids")
    assert events[kill][2] == 0.0                                       # no drain wait before the hard kill
    assert kinds.count("kill_pids") == 1 and "sleep" not in kinds[:kill]
    last_stop = max(i for i, (k, _u, _t) in enumerate(events) if k == "stop")
    assert kinds.index("sleep") > last_stop                            # the wait comes after every stop
    assert 10.0 <= clock.t < 13.0                                      # once, bounded
    assert "vigil-billing-drain.service is still finishing a pass" in capsys.readouterr().out


def test_a_fleet_kill_waits_for_the_drains_once_after_every_revocation(monkeypatch):
    order: list = []
    waits: list = []

    def panic(*, base_dir, **kw):
        waits.append(kw.get("drain_wait_s"))
        order.append(("panic", base_dir))
        return 0

    def drains():
        order.append(("drain_wait", None))
        return ["WARNING: vigil-settle-drain.service is still finishing a pass after 90 s"]
    monkeypatch.setattr(uiproxy, "run_panic", panic)
    monkeypatch.setattr(uiproxy, "await_drains", drains)
    roster = [fleet_monitor.FleetInstance(instance_id=f"i{i}", base_dir=f"/b{i}") for i in range(3)]
    rep = fleet_monitor.fan_out_kill(roster, signed_revocation="SIGNED",
                                     revoke_fn=lambda sig, path: order.append(("revoke", path)))
    assert waits == [0.0, 0.0, 0.0]                                   # no per-instance wait
    assert [k for k, _ in order] == ["panic", "revoke"] * 3 + ["drain_wait"]
    assert rep["drains"] == {"waited": True, "still_running": [
        "WARNING: vigil-settle-drain.service is still finishing a pass after 90 s"]}


class _Killed(BaseException):
    """What SIGTERM from KillMode=control-group does to a panic inside the unit it stops: the process ends."""


def test_a_panic_inside_the_command_unit_contains_everything_before_stopping_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd(busy={"vigil-settle-drain.service": 10_000})
    ctl.active.add(uiproxy._SERVICE_UNIT)
    real = ctl.__call__
    killed: list = []

    def own_cgroup(argv, **kw):
        if argv[2:] == ["stop", uiproxy._SERVICE_UNIT]:
            ctl.calls.append(("stop", uiproxy._SERVICE_UNIT))
            raise _Killed()                       # this process ends here, with the unit
        return real(argv, **kw)
    monkeypatch.setattr(uiproxy, "_kill_tracked_pids", lambda base, label="": (killed.append(base), (0, 0))[1])
    clock = Clock()
    with pytest.raises(_Killed):
        uiproxy.run_panic(base_dir=str(tmp_path), run=own_cgroup, sleep=clock.sleep, clock=clock.now,
                          inside_command_unit=True)
    captured = capsys.readouterr()
    for unit in (*uiproxy._SIDECAR_TIMERS, *uiproxy._SOVEREIGN_TIMERS, *uiproxy._SOVEREIGN_EDGES, *_BRIDGES,
                 uiproxy._SOVEREIGN_WRITER):
        assert "stop" in ctl.verbs_for(unit) and "disable" in ctl.verbs_for(unit), unit
    calls = ctl.calls
    assert calls.index(("mask", uiproxy._SERVICE_UNIT)) < calls.index(("stop", uiproxy._SIDECAR_TIMERS[0]))
    assert calls[-1] == ("stop", uiproxy._SERVICE_UNIT)                       # its own unit is stopped LAST
    assert clock.slept == []                                     # no drain wait while the command unit still runs
    assert "vigil-settle-drain.service is still finishing a pass" in captured.out
    # verified and reported before the self-stop (a drain still finishing is no leak: it is reported as finishing)
    assert "containment verified" in captured.out and captured.err == ""
    assert captured.out.index("containment verified") < captured.out.index("stopping it now ends this process")
    assert "stopping it now ends this process" in captured.out
    assert killed == []                                          # the pid kill would end this process: it comes last


def test_a_panic_outside_the_command_unit_stops_it_first(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    ctl.active.add(uiproxy._SERVICE_UNIT)
    monkeypatch.setattr(uiproxy, "_kill_tracked_pids", lambda base, label="": (0, 0))
    clock = Clock()
    uiproxy.run_panic(base_dir=str(tmp_path), run=ctl, sleep=clock.sleep, clock=clock.now, inside_command_unit=False)
    assert ctl.order("stop")[0] == uiproxy._SERVICE_UNIT


@pytest.mark.parametrize("text, inside", [
    ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/vigil-command.service\n", True),
    ("12:pids:/user.slice\n1:name=systemd:/user.slice/user-1000.slice/user@1000.service/vigil-command.service\n",
     True),
    ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/sigil-cockpit.service\n", False),
    ("0::/user.slice/user-1000.slice/session-3.scope\n", False),
    ("", False),
])
def test_the_command_unit_cgroup_is_recognised(text, inside):
    assert uiproxy._in_unit_cgroup(uiproxy._SERVICE_UNIT, cgroup_text=text) is inside


def _stop_timeouts() -> dict:
    out = {}
    for d in ("apps/sigil/deploy/systemd", "infra/systemd"):
        for p in (_REPO / d).glob("*.service"):
            m = re.search(r"^TimeoutStopSec=(\d+)\s*$", p.read_text(encoding="utf-8"), re.M)
            out[p.name] = int(m.group(1)) if m else None
    return out


def test_each_sovereign_stop_waits_longer_than_the_unit_drains(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    timeouts = _stop_timeouts()
    contained = (*uiproxy._SOVEREIGN_EDGES, uiproxy._SOVEREIGN_WRITER, uiproxy._BRIDGE_TEMPLATE,
                 *uiproxy._SOVEREIGN_ONESHOTS)
    for unit in contained:              # longer than the unit's TimeoutStopSec, or systemd's 90 s default
        assert uiproxy._SOVEREIGN_STOP_TIMEOUT_S > (timeouts[unit] or 90), unit
    asked: dict = {}
    ctl = FakeSystemd()
    real = ctl.__call__

    def record(argv, capture_output=None, text=None, timeout=None):
        if argv[2:3] == ["stop"]:
            asked[argv[-1]] = timeout
        return real(argv, capture_output=capture_output, text=text, timeout=timeout)
    uiproxy._contain_sovereign_units(run=record)
    for unit in (*uiproxy._SOVEREIGN_EDGES, uiproxy._SOVEREIGN_WRITER, *_BRIDGES):
        assert asked[unit] == uiproxy._SOVEREIGN_STOP_TIMEOUT_S, unit


def test_a_stop_still_draining_is_reported_as_stopping_and_as_a_leak(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    ctl = FakeSystemd()
    real = ctl.__call__

    def slow(argv, capture_output=None, text=None, timeout=None):
        rest = argv[2:]
        if rest == ["stop", "sigil-customer.service"]:
            raise uiproxy.subprocess.TimeoutExpired(argv, timeout)
        if rest == ["is-active", "sigil-customer.service"]:
            return types.SimpleNamespace(returncode=0, stdout="deactivating", stderr="")
        return real(argv, capture_output=capture_output, text=text, timeout=timeout)
    actions = uiproxy._contain_sovereign_units(run=slow)
    assert any(a.startswith("WARNING: sigil-customer.service is still stopping after") for a in actions)
    assert not any("could not stop sigil-customer.service" in a for a in actions)
    assert "sigil-customer.service is still deactivating" in uiproxy._verify_sovereign_containment(run=slow)


def test_a_fleet_drain_wait_that_fails_is_reported_not_raised(monkeypatch):
    def boom():
        raise OSError("no bus")
    monkeypatch.setattr(uiproxy, "run_panic", lambda **kw: 0)
    roster = [fleet_monitor.FleetInstance(instance_id="i0", base_dir="/b0")]
    rep = fleet_monitor.fan_out_kill(roster, signed_revocation="SIGNED", revoke_fn=lambda sig, path: None,
                                     drain_wait_fn=boom)
    assert rep["drains"]["waited"] is True
    assert rep["drains"]["still_running"] == ["could not check the drains: OSError: no bus"]
