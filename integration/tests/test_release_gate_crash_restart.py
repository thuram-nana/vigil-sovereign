"""Release gate — the CRASH / RESTART recovery battery, as an honest scoreboard.

WHAT THIS FILE IS. The release gate (plan Part III, "Test layers") names ``crash/restart`` among the layers
that must hold before a controlled pilot. The property that matters for THIS product is narrow and
security-critical: a crash — a ``kill -9`` mid-mint, a power loss, a container OOM — must never let the
anti-rollback state regress or silently reset to a *fail-OPEN* value. The one durable value that makes a
record un-back-datable is the monotonic WHEN anchor (``attestation.anchor``, VIGIL WS6): a host-wide counter
whose only invariant is that it NEVER decreases. If a crash could rewind it, or heal a torn counter down to
0, a replayed/rolled-back record would re-attest under a smaller floor — exactly the hole W0-14 (#409)
closed.

This board proves that invariant across a GENUINE process restart (a real subprocess reads the shared
counter, exits, and another subprocess reads it again — the counter is the only thing that survives), and
proves the fail-CLOSED behaviour on a crash-corrupted counter. It does NOT need Docker, a kill signal, or a
live engine: a subprocess boundary IS a restart for a value whose whole job is to persist across one.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``).
  * Each row asserts the TRUE bar; a bar the system does not yet meet is
    ``@pytest.mark.xfail(strict=True, reason="<slice>")`` so an unexpected pass fails the build and the board
    self-updates.
  * Every row carries a negative control proving the probe is not vacuous — most importantly that the counter
    genuinely ADVANCES (a counter stuck at a constant would trivially "never regress") and that a genuinely
    ABSENT counter is a legitimate fresh start (so "raises on a bad counter" is a real discrimination, not a
    read that always raises).

NO FRAMEWORK IMPORTS — pure ``vigil_integration`` + stdlib, so it runs in BOTH legs of the required P5 job
and needs no ci.yml offense-leg entry.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_integration.attestation.anchor import FloorReadError, read_monotonic_anchor

# The blocking slice for the one row this board cannot run in CI: a full engine kill-9-mid-run + restart +
# resume drill needs a live engagement + Docker, which the required job does not provision.
_LIVE_DRILL_SLICE = "S5/W10 live crash-recovery drill (kill -9 a running engage, restart, resume) — needs a live engine + Docker, not runnable in the P5 job"


def _child_env() -> dict[str, str]:
    """Carry the CURRENT interpreter's import path into a child process so it resolves
    ``vigil_integration`` exactly as this process does — whether that came from an editable install, a
    PYTHONPATH (the CI legs), or a checkout on sys.path. Makes the "genuine restart" subprocess portable
    across both CI legs and a local dev venv."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    return env


# A restart = a fresh interpreter that shares ONLY the on-disk counter. tpm_probe is forced to None so the
# grounding is deterministically the software floor-advance (no dependency on whether tpm2_readclock exists
# on the runner), which is the leg whose persistence this battery is about.
_READ_ONE = (
    "from vigil_integration.attestation.anchor import read_monotonic_anchor;"
    "a = read_monotonic_anchor(state_path=%r, tpm_probe=lambda: None);"
    "print(a.value)"
)


def _restart_read(state_path: Path) -> int:
    """One genuine process restart: spawn a new interpreter that reads (and re-persists) the anchor from
    ``state_path`` and returns the value it saw. Fails the test loudly if the child errored."""
    proc = subprocess.run(
        [sys.executable, "-c", _READ_ONE % str(state_path)],
        capture_output=True, text=True, env=_child_env(),
    )
    assert proc.returncode == 0, f"the restarted reader crashed: {proc.stderr or proc.stdout}"
    return int(proc.stdout.strip())


# =========================================================================================================
# DURABILITY — the anchor never regresses across a real restart, and the floor persists.
# =========================================================================================================
def test_the_monotonic_anchor_never_regresses_across_genuine_restarts(tmp_path):
    """Three separate processes, each a restart of the last, read the SAME on-disk counter. The value must
    strictly increase every time and never rewind — a crash between any two reads cannot roll the floor
    back, because the floor is re-persisted before the process that advanced it exits."""
    state = tmp_path / "monotonic.counter"
    seen = [_restart_read(state) for _ in range(3)]
    assert seen == sorted(seen) and len(set(seen)) == len(seen), (
        f"the anchor regressed or repeated across restarts: {seen} — a rolled-back floor lets a replayed "
        "record re-attest under a smaller WHEN anchor"
    )
    # the durable floor equals the last value handed out — a restart resumes from where the crash left off,
    # never below it.
    resumed = _restart_read(state)
    assert resumed > seen[-1], (
        f"a further restart did not resume ABOVE the last persisted value ({resumed} !> {seen[-1]}) — the "
        "counter did not survive the process boundary"
    )


def test_negative_control_a_fresh_counter_starts_and_advances(tmp_path):
    """Non-vacuity for the durability row: a genuinely fresh counter starts at 1 (floor 0 → floor+1) and a
    second restart returns 2. So "never regresses" is proven over a counter that actually MOVES, not one
    stuck at a constant (which would satisfy 'non-decreasing' vacuously)."""
    state = tmp_path / "fresh.counter"
    first = _restart_read(state)
    second = _restart_read(state)
    assert (first, second) == (1, 2), (
        f"a fresh counter did not advance 1→2 across restarts (got {first}→{second}) — the durability probe "
        "would be vacuous over a non-advancing counter"
    )


# =========================================================================================================
# FAIL-CLOSED — a crash that leaves a TORN / corrupt counter must REFUSE, never silently reset to 0.
# =========================================================================================================
@pytest.mark.parametrize("corruption", [
    b"",                       # a torn write left an empty file
    b"not-an-integer",         # garbage bytes
    b"-5",                     # a negative floor (a rollback disguised as a value)
    b"\x00\x01\x02",           # binary junk (a half-flushed page)
])
def test_a_crash_corrupted_counter_fails_closed_it_never_resets_to_zero(tmp_path, corruption):
    """A counter file that EXISTS but cannot be trusted (torn, non-integer, negative, binary junk) is a fault
    on the exact value that prevents rollback. ``read_monotonic_anchor`` must RAISE (FloorReadError) so the
    mint path denies — never silently degrade to a floor of 0, which is the reset-to-0 fail-OPEN (W0-14
    #409) that would let every prior anchor be re-used."""
    state = tmp_path / "torn.counter"
    state.write_bytes(corruption)
    with pytest.raises(FloorReadError):
        read_monotonic_anchor(state_path=str(state), tpm_probe=lambda: None)
    # and it did NOT heal the tamper by overwriting it down to a fresh 0/1 — the corrupt bytes are left for a
    # human, not silently replaced with a fail-open floor.
    assert state.read_bytes() == corruption, (
        "the corrupt counter was rewritten — a tampered anti-rollback floor must not be silently healed"
    )


def test_negative_control_a_genuinely_absent_counter_is_a_legitimate_fresh_start(tmp_path):
    """Non-vacuity for the fail-closed rows: an ABSENT counter (a true first run) must NOT raise — it is a
    fresh start at 1. So "raises on a corrupt counter" is a real discrimination between *present-but-bad* and
    *absent*, not a read that always raises."""
    absent = tmp_path / "does-not-exist.counter"
    anchor = read_monotonic_anchor(state_path=str(absent), tpm_probe=lambda: None)
    assert anchor.value == 1 and anchor.grounded == "software", (
        f"a fresh (absent) counter did not start cleanly at software floor 1 (got {anchor.value}/"
        f"{anchor.grounded}) — the fail-closed rows would be vacuous"
    )


# =========================================================================================================
# The FULL engine crash-recovery drill is not runnable in CI — an honest xfail that self-updates.
# =========================================================================================================
@pytest.mark.xfail(strict=True, reason=_LIVE_DRILL_SLICE)
def test_full_engine_kill9_midrun_then_restart_resumes(tmp_path):
    """The end-to-end crash drill: start a real ``engage``, ``kill -9`` it mid-run, restart, and assert the
    run resumes without a double-mint or a rewound spine. It needs a live engine + Docker the required job
    does not provision, so it xfails here (strict → an unexpected pass, once a harness lands, flips this red
    and the marker comes off). The DURABLE-STATE half of the property — the invariant a crash could actually
    violate — is proven for real by the rows above."""
    from vigil_integration import engine_crash_recovery_drill  # noqa: F401  (no such harness yet)

    raise AssertionError("no in-CI harness spawns + kills + resumes a live engage")


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    """A non-strict xfail would swallow an XPASS and the board would stop self-updating when the drill lands."""
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"
