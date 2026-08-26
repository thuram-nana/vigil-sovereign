"""WS1b-2 (SOVEREIGN CONSOLE) — the boot bring-up unit: docker services + engine images come up on boot,
IN PARALLEL with the UI, best-effort. These validate the structural invariants a systemd smoke test can't,
so a future edit can't silently make the bring-up block the UI or fail the whole boot.
"""
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_UNIT = _REPO / "infra" / "systemd" / "vigil-bringup.service"


def _unit() -> str:
    return _UNIT.read_text(encoding="utf-8")


def test_is_a_oneshot_that_does_not_restart_loop():
    u = _unit()
    assert "Type=oneshot" in u, "a bring-up that builds images must be oneshot, not a restarting service"
    assert "RemainAfterExit=yes" in u


def test_bring_up_is_best_effort_via_the_dash_prefix():
    u = _unit()
    # the ExecStart `-` prefix: a non-zero exit (docker not ready yet / a build failure) does NOT fail the
    # unit — a missing engine image is a convenience, not a security gate.
    line = next(ln for ln in u.splitlines() if ln.startswith("ExecStart="))
    assert line.startswith("ExecStart=-"), "ExecStart must be best-effort (leading `-`) so a build failure never fails boot"
    assert "services up --all" in line, "must bring up EVERYTHING (gateway + all root services + engine images)"


def test_build_has_room_and_cannot_hang_forever():
    u = _unit()
    to = [ln for ln in u.splitlines() if ln.startswith("TimeoutStartSec=")]
    assert to, "a from-scratch image build is minutes — it needs a generous, explicit TimeoutStartSec"
    secs = int(to[0].split("=", 1)[1])
    assert secs >= 1800, f"TimeoutStartSec={secs} is too short for a first-boot Kali/AEGIS build (SIGKILL risk)"


def test_runs_in_parallel_with_the_ui_no_ordering_dependency():
    # The load-bearing design invariant (WS1b red-pen D1): the bring-up must NOT be ordered before/after or
    # depend on vigil-command.service, or a slow first-boot build would block the cockpit.
    for ln in _unit().splitlines():
        s = ln.strip()
        if s.startswith("#"):
            continue
        if s.startswith(("Before=", "After=", "Requires=", "Wants=", "BindsTo=", "PartOf=")):
            assert "vigil-command" not in s, f"the bring-up must run PARALLEL to the UI, not ordered with it: {s!r}"


def test_starts_at_boot():
    assert "WantedBy=default.target" in _unit()


def test_start_limits_live_in_the_unit_section():
    # StartLimit* are silently ignored outside [Unit] (the W10-5 gotcha).
    unit_section = _unit().split("[Service]", 1)[0]
    assert "StartLimitIntervalSec=" in unit_section and "StartLimitBurst=" in unit_section
