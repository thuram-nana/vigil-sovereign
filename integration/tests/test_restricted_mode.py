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


def _gate_closed() -> bool:
    """The read-side twin of :func:`_no_trip`: the live-gate seam for the ledger-mechanics tests, which
    run in the sovereign leg where ``framework`` is not importable. It stands in for a CLOSED gate so
    ``is_restricted`` reflects the ledger's intent; the REAL live-gate coupling (reported-restricted ⇒
    gate closed, using the actual KillSwitch) is proven in the offense companion."""
    return True


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
    assert rm.is_restricted(base, gate_closed_fn=_gate_closed) is True
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
    assert rm.is_restricted(base, gate_closed_fn=_gate_closed) is True

    # Recorded on the (hash) chain: the transition is a verifiable chain link on disk.
    transitions = rm.read_transitions(base)
    assert [x.action for x in transitions] == [rm.ENTER]
    assert transitions[0].entry_hash  # a real chain-link hash was written


def test_restricted_mode_survives_restart(tmp_path: Path):
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)
    # "Restart" = a completely fresh read of the on-disk ledger (no in-memory state carried over).
    assert rm.is_restricted(base, gate_closed_fn=_gate_closed) is True
    assert rm.current_state(base).entered is True


def test_leave_is_recorded_on_the_chain_and_restores_operational(tmp_path: Path):
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)
    assert rm.is_restricted(base, gate_closed_fn=_gate_closed) is True

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


# ── is_restricted reflects the LIVE gate, not just the ledger snapshot (MEDIUM #1) ──────────────────
def test_is_restricted_cannot_be_true_while_the_gate_is_open(tmp_path: Path):
    # The invariant: reported-restricted ⇒ gate closed. The ledger's last transition is an ENTER, but an
    # operator has since CLEARED the kill-switch (a recovery step that opens the gate and records no
    # LEAVE). Trusting the ledger alone would report `restricted` while the gate is OPEN — the exact
    # false-safe state this must not produce. is_restricted consults the live gate, so it returns False.
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)

    # NEGATIVE CONTROL (same run): with the gate CLOSED the same ledger reports restricted...
    assert rm.is_restricted(base, gate_closed_fn=lambda: True) is True
    # ...but with the gate OPEN (kill-switch cleared) it MUST NOT — even though the ledger still says ENTER.
    current = rm.current_state(base)
    assert current is not None and current.entered is True, \
        "the ledger still records ENTER — only the live gate changed"
    assert rm.is_restricted(base, gate_closed_fn=lambda: False) is False


def test_killswitches_all_tripped_reads_each_engagement(tmp_path: Path):
    # The live-gate reader over an injected KillSwitch: all-tripped only when EVERY engagement's switch is
    # tripped; one open switch opens the gate. Vacuously closed when nothing is provisioned.
    adir = tmp_path / ".authority"
    adir.mkdir()
    (adir / "a.authority.json").write_text("{}", encoding="utf-8")
    (adir / "b.authority.json").write_text("{}", encoding="utf-8")
    tripped: set[str] = set()

    class _KS:
        def __init__(self, slug, path=None):
            self.slug = slug

        def is_tripped(self):
            return self.slug in tripped

    # NEGATIVE CONTROL: nothing tripped ⇒ gate open.
    assert rm.killswitches_all_tripped(authority_dir=adir, killswitch_cls=_KS) == (False, 2)
    tripped.add("a")
    assert rm.killswitches_all_tripped(authority_dir=adir, killswitch_cls=_KS) == (False, 2)  # b still open
    tripped.add("b")
    assert rm.killswitches_all_tripped(authority_dir=adir, killswitch_cls=_KS) == (True, 2)
    # No engagement provisioned ⇒ vacuously closed (nothing a gate could authorize).
    assert rm.killswitches_all_tripped(authority_dir=tmp_path / "empty", killswitch_cls=_KS) == (True, 0)


# ── each refused action is recorded ON THE CHAIN, per-refusal (MEDIUM #2) ────────────────────────────
def test_refusal_is_recorded_on_the_chain_per_refusal(tmp_path: Path):
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)

    # A fake CLOSED gate: any action is refused with the kill-switch's `halted` code.
    class _Decision:
        allowed = False
        denial_code = "halted"
        reason = "engagement halted: emergency stop"

    class _Req:
        def __init__(self, action_kind, target):
            self.action_kind = action_kind
            self.target = target

    def _authorize(authority, request, *, killswitch, actions_taken, now):
        return _Decision()

    # Two distinct refused actions while restricted.
    d1 = rm.guarded_authorize(object(), _Req("exploit", "https://app.example.com/a"),
                              killswitch=object(), base_dir=base, authorize_fn=_authorize)
    d2 = rm.guarded_authorize(object(), _Req("recon", "https://app.example.com/b"),
                              killswitch=object(), base_dir=base, authorize_fn=_authorize)
    assert d1.allowed is False and d2.allowed is False  # the existing gate decided; we only recorded

    events = rm.read_transitions(base)
    refusals = [e for e in events if e.action == rm.REFUSE]
    assert len(refusals) == 2, "each refused action must be recorded on the chain, not just the transition"
    assert all(r.trigger == "halted" for r in refusals)
    assert "app.example.com/a" in refusals[0].reason and "exploit" in refusals[0].reason
    assert "app.example.com/b" in refusals[1].reason

    # The refusals sit on the SAME hash chain as the ENTER transition, in order, and re-verify.
    assert [e.action for e in events] == [rm.ENTER, rm.REFUSE, rm.REFUSE]
    # A REFUSE never changes the mode: current_state still points at the ENTER transition.
    assert rm.current_state(base).action == rm.ENTER


def test_a_refused_action_cannot_be_excised_without_breaking_the_chain(tmp_path: Path):
    # NEGATIVE CONTROL: because refusals are on the SAME chain as the transitions, deleting a refusal
    # line to hide it breaks the chain — a tampered audit is rejected, not silently trusted.
    base = tmp_path / "home"
    rm.enter_restricted_mode(base_dir=base, trigger="emergency_stop", trip_fn=_no_trip)
    rm.record_refusal(base, action="exploit", target="https://app.example.com/a", denial_code="halted")
    rm.record_refusal(base, action="recon", target="https://app.example.com/b", denial_code="halted")

    ledger = base / "restricted-mode" / "transitions.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    del lines[1]  # drop the first refusal to hide it
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
    assert rm.is_restricted(base, gate_closed_fn=_gate_closed) is True
