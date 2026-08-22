"""W13-6 (#499) — RESTRICTED MODE: a safe landing state between fully-operational and fully-stopped.

These are the IMPORT-CLEAN tests (stdlib + vigil_core + the import-clean integrity_verifier), so they run
in the sovereign leg of the two-env CI job as well as everywhere else — restricted_mode.py loads in BOTH
processes (FATAL-2), exactly like vigil_core.gate. The OFFENSE-leg companion
(test_restricted_mode_offense.py) proves the REFUSAL of a mutating action routes through the REAL existing
kill-switch + authority gate.

They fail without the change: restricted_mode.py does not exist on a tree without the fix, so every import
below raises ImportError (observed). Each behavioural test also carries a NEGATIVE CONTROL asserted in the
SAME run, so no gate/assertion is a no-op.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration import restricted_mode as rm


def _no_trip(reason: str, **_kw) -> list[str]:
    """A trip seam that records nothing — the transition ledger is exercised on its own here; the REAL
    kill-switch → gate refusal is proven in the offense companion."""
    return []


# ── integrity failure lands in restricted mode (not full-stop, not full-operational) ────────────────
def test_integrity_failure_drops_into_restricted_mode(tmp_path: Path):
    home = tmp_path / "spine"
    home.mkdir()
    # A malformed/tampered spine record → the EXISTING integrity audit FAILs the chain check.
    (home / "spine.jsonl").write_text('{"seq":0,"cert_digest":"deadbeef"}\n', encoding="utf-8")
    base = tmp_path / "home"

    result = rm.enforce_integrity_or_restrict(home=home, base_dir=base, trip_fn=_no_trip)

    assert result.report.ok is False, "the tampered spine must FAIL the integrity audit"
    assert result.restricted is True, "an integrity failure must land in restricted mode"
    # Not full-operational:
    assert rm.is_restricted(base) is True
    # Not full-stop: enforce_integrity_or_restrict never raised/crashed — it returned a handled result,
    # and it did not touch the process (no panic). The transition is recorded with the integrity trigger.
    assert result.transition is not None and result.transition.trigger == "integrity"


def test_clean_integrity_leaves_the_system_operational(tmp_path: Path):
    # NEGATIVE CONTROL: a clean/absent spine must NOT drop into restricted mode — the guard is not a
    # blanket trip. A fresh home has no spine yet (ABSENT, not FAIL).
    home = tmp_path / "spine"
    home.mkdir()
    base = tmp_path / "home"
    result = rm.enforce_integrity_or_restrict(home=home, base_dir=base, trip_fn=_no_trip)
    assert result.report.ok is True
    assert result.restricted is False
    assert rm.is_restricted(base) is False


# ── restricted mode surface asserted PER CAPABILITY (diagnosis/export allowed, mutating refused) ────
def test_restricted_mode_permits_only_the_diagnostic_surface():
    # Allowed: read-only diagnosis, evidence access, audit export, authorization repair.
    for allowed in (rm.DIAGNOSTICS, rm.EVIDENCE_EXPORT, rm.AUDIT_EXPORT, rm.AUTHORIZATION_REPAIR):
        assert rm.restricted_mode_permits(allowed) is True, f"{allowed} must stay available"

    # NEGATIVE CONTROL (same run): every mutating / target-touching action is refused — including every
    # offense entitlement Capability — and an unknown action fails closed.
    mutating = ("exploit_execution", "active_recon", "full_chain_exploitation", "autonomous_planning",
                "engage", "patch", "write", "definitely-not-a-real-action")
    for action in mutating:
        assert rm.restricted_mode_permits(action) is False, f"{action} must be refused in restricted mode"


def test_restricted_mode_permits_reads_enum_value():
    # An enum-like capability is normalized by its .value (mirrors framework Capability), so a diagnostic
    # enum is permitted and an offense enum is refused — asserted per capability in one run.
    class _Cap:
        def __init__(self, value): self.value = value

    assert rm.restricted_mode_permits(_Cap("diagnostics")) is True
    assert rm.restricted_mode_permits(_Cap("exploit_execution")) is False


# ── emergency-stop enters restricted mode; transitions on the chain, survive restart ────────────────
def test_emergency_stop_enters_restricted_mode_recorded_on_chain(tmp_path: Path):
    base = tmp_path / "home"
    assert rm.is_restricted(base) is False  # NEGATIVE CONTROL: operational before we enter

    t = rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", reason="drill", trip_fn=_no_trip)
    assert t.action == rm.ENTER and t.trigger == "emergency_stop"
    assert rm.is_restricted(base) is True

    # Recorded on the (hash) chain: the transition is a verifiable chain link on disk.
    transitions = rm.read_transitions(base)
    assert [x.action for x in transitions] == [rm.ENTER]
    assert transitions[0].entry_hash  # a real chain-link hash was written


def test_restricted_mode_survives_restart(tmp_path: Path):
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)
    # "Restart" = a completely fresh read of the on-disk ledger (no in-memory state carried over).
    assert rm.is_restricted(base) is True
    assert rm.current_state(base).entered is True


def test_leave_is_recorded_on_the_chain_and_restores_operational(tmp_path: Path):
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)
    assert rm.is_restricted(base) is True

    left = rm.leave_restricted_mode(base_dir=base, reason="repaired", cleared_by="alice")
    assert left.action == rm.LEAVE
    assert rm.is_restricted(base) is False  # NEGATIVE CONTROL: leaving flips the mode back
    # Both enter and leave are on the chain, in order.
    assert [x.action for x in rm.read_transitions(base)] == [rm.ENTER, rm.LEAVE]


# ── the ledger is tamper-evident (the record is not a no-op file) ────────────────────────────────────
def test_tampered_transition_ledger_is_rejected(tmp_path: Path):
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)
    rm.leave_restricted_mode(base_dir=base)

    ledger = base / "restricted-mode" / "transitions.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    # Flip the recorded trigger on the enter line WITHOUT recomputing the digest → the chain must reject it.
    lines[0] = lines[0].replace("emergency_stop", "operator")
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="tampered|broken"):
        rm.read_transitions(base)


def test_deleting_an_interior_transition_breaks_the_chain(tmp_path: Path):
    # NEGATIVE CONTROL for the chain linkage: dropping a line (a rollback of history) is detected.
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)
    rm.leave_restricted_mode(base_dir=base)
    rm.enter_restricted_mode(base_dir=base, trigger="operator", trip_fn=_no_trip)

    ledger = base / "restricted-mode" / "transitions.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    del lines[1]  # drop the middle (leave) transition
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="broken|deleted|reordered"):
        rm.read_transitions(base)


# ── blocking_work: AUTO-invoke the integrity trigger on every monitor tick / at boot ────────────────
@pytest.mark.xfail(reason="W13-6 follow-on: enforce_integrity_or_restrict is implemented and tested, but "
                          "AUTO-invoking it on every integrity-monitor tick and at process boot (so a "
                          "production box lands in restricted mode with no operator in the loop) is not yet "
                          "wired — the monitor still only alarms. See docs/decisions/W13-6-restricted-mode.md.",
                   strict=True)
def test_integrity_monitor_auto_enters_restricted_mode_on_failure(tmp_path: Path):
    from vigil_integration import integrity_verifier as iv

    home = tmp_path / "spine"
    home.mkdir()
    (home / "spine.jsonl").write_text('{"seq":0,"cert_digest":"deadbeef"}\n', encoding="utf-8")
    base = tmp_path / "home"

    # A single monitor pass over a broken spine should, on its own, land the box in restricted mode.
    iv.run_integrity_once(home=home, now=1.0)  # today: alarms only; does not enter restricted mode
    assert rm.is_restricted(base) is True
