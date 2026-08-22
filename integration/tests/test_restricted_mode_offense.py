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
    # is_restricted reads the SAME live kill-switch the gate consults (not just the ledger snapshot).
    assert rm.is_restricted(base, authority_dir=adir, ks_path_for=ks_path_for) is True
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


def test_is_restricted_false_once_the_real_gate_is_cleared(tmp_path: Path):
    # MEDIUM #1, proven against the REAL KillSwitch: the ledger's last transition is ENTER, but an
    # operator clears the kill-switch during recovery (opening the gate, recording no LEAVE). Reading the
    # ledger alone would falsely report `restricted`; is_restricted consults the SAME live kill-switch the
    # refusal path does, so once the gate is open it reports False. Reported-restricted ⇒ gate closed.
    adir, ks_path_for = _setup_authority_dir(tmp_path)
    ks = KillSwitch("eng", path=ks_path_for("eng"))
    base = tmp_path / "home"

    rm.enter_restricted_mode(
        base_dir=base, trigger="emergency_stop",
        trip_kwargs={"authority_dir": adir, "ks_path_for": ks_path_for},
    )
    assert ks.is_tripped() is True
    # Gate CLOSED: reported restricted.
    assert rm.is_restricted(base, authority_dir=adir, ks_path_for=ks_path_for) is True

    # Operator clears the real kill-switch (recovery). No LEAVE is recorded — the ledger still says ENTER.
    ks.clear(cleared_by="operator")
    assert ks.is_tripped() is False
    assert rm.current_state(base).entered is True, "the ledger still records ENTER — only the gate changed"

    # The mutating action is now ALLOWED again by the EXISTING gate (the gate is genuinely open)...
    assert authorize_action(_authority(), _mutating_request(), killswitch=ks, now=_NOW).allowed is True
    # ...so is_restricted MUST NOT report restricted while the gate is open.
    assert rm.is_restricted(base, authority_dir=adir, ks_path_for=ks_path_for) is False


def test_guarded_authorize_records_each_real_gate_refusal_on_the_chain(tmp_path: Path):
    # MEDIUM #2, end-to-end over the REAL gate: guarded_authorize consults the existing authorize_action
    # and records EACH refusal (kill-switch tripped ⇒ `halted`) on the same hash chain as the transition.
    adir, ks_path_for = _setup_authority_dir(tmp_path)
    ks = KillSwitch("eng", path=ks_path_for("eng"))
    base = tmp_path / "home"

    rm.enter_restricted_mode(
        base_dir=base, trigger="emergency_stop",
        trip_kwargs={"authority_dir": adir, "ks_path_for": ks_path_for},
    )

    req = ActionRequest(target="https://app.example.com/x", action_kind="exploit", destructive=False)
    decision = rm.guarded_authorize(_authority(), req, killswitch=ks, base_dir=base, now=_NOW)
    assert decision.allowed is False and decision.denial_code == "halted"  # the EXISTING gate decided

    refusals = [e for e in rm.read_transitions(base) if e.action == rm.REFUSE]
    assert len(refusals) == 1, "the real-gate refusal must be recorded on the chain"
    assert refusals[0].trigger == "halted" and "app.example.com/x" in refusals[0].reason

    # NEGATIVE CONTROL (same run): once the gate is cleared, the same call is ALLOWED and records NO
    # refusal — guarded_authorize records only what the existing gate actually refuses.
    ks.clear(cleared_by="operator")
    allowed = rm.guarded_authorize(_authority(), req, killswitch=ks, base_dir=base, now=_NOW)
    assert allowed.allowed is True
    assert len([e for e in rm.read_transitions(base) if e.action == rm.REFUSE]) == 1
