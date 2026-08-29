"""Wave 4 (parity) — the console lifecycle/emergency wrappers: daemon status strip, emergency-stop, panic,
down, services down/render. Each shells the exec-only `vigil`; panic/down are DETACHED (they contain this
console). Fail-closed on a bad action / unresolvable bin. The verbs' own correctness is covered by their CLI
suites; this checks the wrappers + argv."""
from __future__ import annotations

import subprocess

from framework.v2.console import actions


class _P:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


# --- the intended RBAC tier of every new route (mutation-sensitive: a silent mis-tier fails here) -----

def test_wave4_route_tiers_are_exactly_as_designed():
    from vigil_core.rbac import offense_perm_for
    assert offense_perm_for("/api/daemons/status") == "read"           # read-only strip
    assert offense_perm_for("/api/emergency-stop") == "read"           # TRIP is the safe direction
    assert offense_perm_for("/api/panic") == "read"                    # HALT is the safe direction
    assert offense_perm_for("/api/emergency-stop/leave") == "offense_authority"  # LIFTING restriction = owner
    assert offense_perm_for("/api/down") == "run_engagement"           # contain the console = operator
    assert offense_perm_for("/api/services/down") == "offense_authority"   # gateway lifecycle = owner
    assert offense_perm_for("/api/services/render") == "offense_authority"


# --- daemon status strip ---------------------------------------------------------

def test_daemons_status_parses_json(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P(0, '{"statuses": [{"unit": "u", "state": "HEALTHY"}], "delivery_stale": false}'))
    r = actions.daemons_status()
    assert r["ok"] is True and r["statuses"][0]["unit"] == "u"


def test_daemons_status_alarm_is_not_ok_but_keeps_statuses(monkeypatch):
    # exit 1 = an alarm is present; the read still succeeded → ok:false with the statuses populated
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P(1, '{"statuses": [{"unit": "backup", "state": "STALE"}]}'))
    r = actions.daemons_status()
    assert r["ok"] is False and r["statuses"][0]["state"] == "STALE"


def test_daemons_status_failclosed_missing_bin(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    assert actions.daemons_status()["ok"] is False


# --- emergency-stop --------------------------------------------------------------

def test_emergency_stop_rejects_a_bad_action():
    assert actions.run_emergency_stop("nope")["ok"] is False


def test_emergency_stop_argv_per_action(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}

    def _rec(a, **k):
        seen["argv"] = a
        return _P(0, "ok")
    monkeypatch.setattr(subprocess, "run", _rec)
    actions.run_emergency_stop("status");  assert seen["argv"][1:] == ["emergency-stop", "--status"]
    actions.run_emergency_stop("enter");   assert seen["argv"][1:3] == ["emergency-stop", "--reason"]
    actions.run_emergency_stop("leave");   assert seen["argv"][1:] == ["emergency-stop", "--leave"]


# --- panic / down: DETACHED spawn ------------------------------------------------

def test_panic_and_down_are_detached_and_return_initiated(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    calls = {}

    def _popen(argv, **kw):
        calls["argv"], calls["kw"] = argv, kw
        return object()
    monkeypatch.setattr(subprocess, "Popen", _popen)
    r = actions.run_panic("because")
    assert r["ok"] is True and r["initiated"] is True
    assert calls["argv"][1:] == ["panic", "--reason", "because"]
    assert calls["kw"].get("start_new_session") is True          # survives THIS console's death
    calls.clear()
    r = actions.run_down()
    assert r["ok"] is True and calls["argv"][1:] == ["down"] and calls["kw"].get("start_new_session") is True


def test_panic_failclosed_missing_bin(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    assert actions.run_panic("x")["ok"] is False


def test_detached_spawn_oserror_failclosed(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    def _boom(*a, **k):
        raise OSError("no exec")
    monkeypatch.setattr(subprocess, "Popen", _boom)
    assert actions.run_down()["ok"] is False


# --- services down / render ------------------------------------------------------

def test_services_lifecycle_rejects_bad_action():
    assert actions.run_services_lifecycle("up")["ok"] is False       # 'up' is the SEPARATE in-process action


def test_services_lifecycle_argv(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}

    def _rec(a, **k):
        seen["argv"] = a
        return _P(0, "ok")
    monkeypatch.setattr(subprocess, "run", _rec)
    actions.run_services_lifecycle("down");   assert seen["argv"][1:] == ["services", "down"]
    actions.run_services_lifecycle("render"); assert seen["argv"][1:] == ["services", "render"]
