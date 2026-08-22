"""vigil_core.doctor — the ONE doctor check registry both trust planes share (W6-6).

`vigil doctor` (offense/integration) and `sigil doctor` (sovereign) used to be two disjoint self-checks
with no shared idea of what a "failed control" is. This module is now the single source of truth: the
ordered ``REQUIRED_CONTROLS`` registry, the opt-in fail-closed ``evaluate`` gate decision, and the
``overall_ok`` roll-up that turns a registry of checks into ONE honest exit code.

These tests pin the load-bearing properties directly (no process env mutated except a scoped
monkeypatch): the gate is OPT-IN (inert unless the production posture is armed), FAIL-CLOSED (a missing or
UNKNOWN control is UNMET), and a NEGATIVE CONTROL — every control satisfied ⇒ the gate passes, so it is not
simply always-refusing. The whole file is pure-`vigil_core`; it runs in the required "vigil_core — shared
integrity substrate" CI job.
"""
from __future__ import annotations

import pytest

from vigil_core import doctor as dmod
from vigil_core.posture import POSTURE_ENV


# ---------------------------------------------------------------- the registry is the single source of truth

def test_registry_is_the_seven_named_controls_in_order():
    names = [c for (c, _good, _req) in dmod.REQUIRED_CONTROLS]
    assert names == ["vault", "sovereignty", "entitlement", "backups", "charter", "legacy-owner-token",
                     "egress-supervisor"]


def _good_states() -> dict:
    """The state that makes each registry control MET — one value out of each good-set."""
    return {c: (sorted(good)[0], "") for (c, good, _req) in dmod.REQUIRED_CONTROLS}


# ---------------------------------------------------------------- evaluate(): opt-in + fail-closed + negative

def test_gate_is_inert_when_not_armed(monkeypatch):
    monkeypatch.delenv(POSTURE_ENV, raising=False)
    # every control is UNKNOWN (the worst case), yet an UNARMED gate is ok and names no unmet control.
    res = dmod.evaluate({}, armed=None)
    assert res["armed"] is False
    assert res["ok"] is True
    assert res["unmet"] == []


def test_gate_fails_closed_on_missing_or_unknown_control():
    # armed + a control absent from the map, and one explicitly UNKNOWN ⇒ both UNMET (never treated as good).
    states = _good_states()
    states.pop("vault")                    # absent entirely
    states["charter"] = ("UNKNOWN", "unreadable")
    res = dmod.evaluate(states, armed=True)
    assert res["armed"] is True and res["ok"] is False
    unmet = {u["control"] for u in res["unmet"]}
    assert unmet == {"vault", "charter"}


def test_gate_passes_when_every_control_is_satisfied():
    # NEGATIVE CONTROL: the gate is not always-refusing — a fully-good posture, armed, PASSES.
    res = dmod.evaluate(_good_states(), armed=True)
    assert res["armed"] is True
    assert res["ok"] is True
    assert res["unmet"] == []
    assert all(c["met"] for c in res["controls"])


def test_gate_accepts_mapping_and_bare_string_states():
    # a `_collect_posture` entry (a {"state","detail"} mapping) and a bare state string both normalise.
    states = _good_states()
    states["vault"] = {"state": "SEALED", "detail": "sealed"}
    states["sovereignty"] = "AIR_GAPPED"
    res = dmod.evaluate(states, armed=True)
    assert res["ok"] is True


# ---------------------------------------------------------------- overall_ok(): required flips, advisory does not

def test_overall_ok_ignores_failed_advisory_checks():
    checks = [dmod.Check(id="required-good", ok=True, required=True),
              dmod.Check(id="advisory-bad", ok=False, required=False)]
    assert dmod.overall_ok(checks) is True


def test_overall_ok_fails_on_a_failed_required_check():
    checks = [dmod.Check(id="required-bad", ok=False, required=True),
              dmod.Check(id="advisory-bad", ok=False, required=False)]
    assert dmod.overall_ok(checks) is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
