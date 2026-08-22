"""W13-6 (#499) — the OFFENSE-leg proof that restricted mode's REFUSAL routes through the EXISTING gate.

This is the companion to test_restricted_mode.py. It imports ``framework`` (behind an ``importorskip``), so
it runs ONLY in the offense leg of the "integration two-env boundary (P5)" CI job — it is listed there
explicitly (the ``test_ci_framework_tests_run_in_offense_leg`` guard enforces that).

It proves the HARD CONSTRAINT of #499: restricted mode builds NO new gate. Entering restricted mode trips
the EXISTING ``framework.v2.authority.killswitch.KillSwitch`` (the same primitive ``vigil panic`` trips), and
the ALREADY-EXISTING ``authorize_action`` authority gate then REFUSES a target-touching / mutating action —
fail-closed, with the kill-switch's own ``halted`` denial code. The NEGATIVE CONTROL in the SAME run shows
the gate is not a no-op: with the kill-switch clear the identical in-scope, in-window action is ALLOWED.

It fails without the change: restricted_mode.py does not exist on a tree without the fix (ImportError).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.authority.gate")

from framework.v2.authority.gate import authorize_action  # noqa: E402
from framework.v2.authority.killswitch import KillSwitch  # noqa: E402
from framework.v2.authority.models import (  # noqa: E402
    ActionRequest,
    AuthorityState,
    EngagementAuthority,
    TargetEnvironment,
)

from vigil_integration import restricted_mode as rm  # noqa: E402

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _authority() -> EngagementAuthority:
    return EngagementAuthority(
        engagement_slug="eng",
        environment=TargetEnvironment.TWIN,
        scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
    )


def _mutating_request() -> ActionRequest:
    # An in-scope, in-window, target-touching action — the exact thing restricted mode must refuse.
    return ActionRequest(target="https://app.example.com/x", destructive=False)


def _setup_authority_dir(tmp_path: Path) -> tuple[Path, "callable"]:
    """A real offense authority dir with one engagement, plus the kill-switch path resolver for it."""
    adir = tmp_path / ".authority"
    adir.mkdir()
    (adir / "eng.authority.json").write_text("{}", encoding="utf-8")  # presence is what enumeration reads
    return adir, (lambda slug: adir / f"{slug}.halt")


def test_mutating_action_refused_in_restricted_mode_via_the_existing_gate(tmp_path: Path):
    adir, ks_path_for = _setup_authority_dir(tmp_path)
    ks = KillSwitch("eng", path=ks_path_for("eng"))
    base = tmp_path / "home"

    # NEGATIVE CONTROL (same run): normal mode — the EXISTING gate ALLOWS the in-scope action.
    normal = authorize_action(_authority(), _mutating_request(), killswitch=ks, now=_NOW)
    assert normal.allowed is True, "the gate must allow an in-scope, in-window action in normal mode"
    assert rm.is_restricted(base) is False

    # Enter restricted mode: this trips the REAL kill-switch (via the shared primitive) AND records the
    # transition on the chain. No new gate is created.
    t = rm.enter_restricted_mode(
        base_dir=base, trigger="emergency_stop", reason="drill",
        trip_kwargs={"authority_dir": adir, "ks_path_for": ks_path_for},
    )
    assert t.action == rm.ENTER
    assert rm.is_restricted(base) is True
    assert ks.is_tripped() is True, "entering restricted mode must trip the existing kill-switch"

    # The mutating / target-touching action is now REFUSED — by the EXISTING authority gate, with the
    # kill-switch's own denial code. This is the same gate; only the kill-switch state changed.
    refused = authorize_action(_authority(), _mutating_request(), killswitch=ks, now=_NOW)
    assert refused.allowed is False, "restricted mode must refuse a mutating action"
    assert refused.state is AuthorityState.HALTED
    assert refused.denial_code == "halted"

    # Meanwhile the read-only diagnostic surface stays open — asserted per capability.
    assert rm.restricted_mode_permits(rm.DIAGNOSTICS) is True
    assert rm.restricted_mode_permits(rm.EVIDENCE_EXPORT) is True
    assert rm.restricted_mode_permits("exploit_execution") is False


def test_integrity_failure_trips_the_real_gate(tmp_path: Path):
    # End-to-end: an integrity FAILURE (not a manual emergency-stop) also refuses the mutating action
    # through the existing gate — the integrity trigger and the refusal are wired to the same kill-switch.
    adir, ks_path_for = _setup_authority_dir(tmp_path)
    ks = KillSwitch("eng", path=ks_path_for("eng"))
    home = tmp_path / "spine"
    home.mkdir()
    (home / "spine.jsonl").write_text('{"seq":0,"cert_digest":"deadbeef"}\n', encoding="utf-8")
    base = tmp_path / "home"

    # NEGATIVE CONTROL: before the integrity guard runs, the gate allows.
    assert authorize_action(_authority(), _mutating_request(), killswitch=ks, now=_NOW).allowed is True

    result = rm.enforce_integrity_or_restrict(
        home=home, base_dir=base,
        trip_kwargs={"authority_dir": adir, "ks_path_for": ks_path_for},
    )
    assert result.restricted is True and result.report.ok is False
    assert ks.is_tripped() is True

    refused = authorize_action(_authority(), _mutating_request(), killswitch=ks, now=_NOW)
    assert refused.allowed is False and refused.denial_code == "halted"
