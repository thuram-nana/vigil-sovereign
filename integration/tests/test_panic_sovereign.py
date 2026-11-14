"""`vigil panic` also contains the sovereign plane and the drains.

After the command unit and the cadence sidecars, panic stops AND disables: every drain and sovereign timer (settle,
billing, Stripe billing, findings, checkpoint, consolidate — each with its Persistent= catch-up stamp reset), the
customer and public edges, every live phone bridge (`sigil-bridge@<addr>`), and the cockpit LAST (the writer; it
finishes the requests it already accepted). The checkpoint and consolidate passes are stopped; a DRAIN pass already
in flight is never interrupted — panic waits for it, bounded, and reports a pass still running after the bound. The
post-condition check covers every one of these units. `vigil down` touches none of them.

Framework-free (a fake `systemctl`, an injected clock): runs in the integration two-env boundary leg.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_panic_sovereign.py -q
"""
from __future__ import annotations

import types
from pathlib import Path

from vigil_integration import uiproxy

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
    clock = clock or Clock()
    return uiproxy._contain_sovereign_units(run=ctl, wait_s=wait_s, sleep=clock.sleep, clock=clock.now)


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
    leaks = uiproxy._verify_sovereign_containment(run=ctl)
    assert leaks == ["vigil-billing-drain.service is still active"]       # surfaced, never assumed contained


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
