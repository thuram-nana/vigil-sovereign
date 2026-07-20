"""
Workflow / state-machine abuse detector — driven against REAL loopback targets.

The broken order/coupon workflow forgets three guards: it ships without payment
(step-skip), re-applies a coupon on every replay (sequential replay), and
persists a negative cart quantity (parameter tampering). The guarded twin
enforces all three. The detector must CONFIRM each abuse against the broken app
via the achieved-state / predicate oracle over the observed post-state, and
return NOTHING against the guarded twin — the negative control that proves the
authority is not a rubber-stamp.

The verdict is a pure predicate over the post-state the target actually landed
in, so it is deterministic — never a timing measurement, never the detector's
own say-so.
"""

from __future__ import annotations

from typing import Any, Mapping

import pytest

from framework.v2.scanner import checks as checks_mod
from framework.v2.scanner.bizlogic import (
    BUG_CLASS,
    BrokenWorkflowHandler,
    GuardedWorkflowHandler,
    TamperProbe,
    WorkflowSpec,
    WorkflowStep,
    confirm_against_local_workflow,
    demo_spec,
    detect_workflow_abuse,
    probe_replay,
    probe_step_skip,
    probe_tamper,
)
from framework.v2.verify.confirmation import ConfirmedFinding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
    is_known_bug_class,
    normalize_bug_class,
)


# ---------------------------------------------------------------------------
# An in-memory workflow target — a real state machine perform() mutates and
# read_state() observes. Faster than the loopback demo and just as real: the
# oracle judges the post-state the machine produced, not an assertion.
# ---------------------------------------------------------------------------


class _Workflow:
    def __init__(self, *, enforce: bool) -> None:
        self.enforce = enforce
        self.reset()

    def reset(self) -> None:
        self.qty = 0
        self.checked_out = False
        self.paid = False
        self.shipped = False
        self.redeemed = 0

    def state(self) -> dict[str, Any]:
        return {
            "qty": self.qty, "checked_out": self.checked_out, "paid": self.paid,
            "shipped": self.shipped, "redeemed": self.redeemed,
        }

    def perform(self, step: WorkflowStep, params: Mapping[str, Any]) -> dict[str, Any]:
        name = step.name
        if name == "add":
            qty = int(params.get("qty", 1))
            if self.enforce and qty <= 0:
                return {"status": 400}
            self.qty = qty
        elif name == "checkout":
            if self.enforce and self.qty <= 0:
                return {"status": 400}
            self.checked_out = True
        elif name == "pay":
            if self.enforce and not self.checked_out:
                return {"status": 400}
            self.paid = True
        elif name == "ship":
            if self.enforce and not self.paid:
                return {"status": 403}
            self.shipped = True
        elif name == "redeem":
            if self.enforce and self.redeemed >= 1:
                return {"status": 409}
            self.redeemed += 1
        return {"status": 200}


def _spec() -> WorkflowSpec:
    """Mirror of demo_spec() but over the in-memory field names (`redeemed`)."""
    return WorkflowSpec(
        name="unit-order-workflow",
        steps=(
            WorkflowStep(name="add", params={"qty": 1}, effect={"gt": [{"var": "qty"}, 0]}),
            WorkflowStep(name="checkout", requires=("add",),
                         effect={"eq": [{"var": "checked_out"}, True]}),
            WorkflowStep(name="pay", requires=("checkout",),
                         effect={"eq": [{"var": "paid"}, True]}),
            WorkflowStep(name="ship", requires=("pay",),
                         effect={"eq": [{"var": "shipped"}, True]}),
            WorkflowStep(name="redeem", once=True,
                         effect={"gt": [{"var": "redeemed"}, 0]},
                         replay_effect={"gt": [{"var": "redeemed"}, 1]}),
        ),
        tamper_probes=(
            TamperProbe(step="add", overrides={"qty": -5},
                        danger={"eq": [{"var": "qty"}, -5]}),
        ),
    )


def _driver(wf: _Workflow):
    return wf.perform, wf.state, wf.reset


# ---------------------------------------------------------------------------
# 1. Vocabulary wiring — the class routes to the predicate/achieved-state oracle
# ---------------------------------------------------------------------------


def test_bug_class_routes_to_achieved_state_oracle() -> None:
    assert BUG_CLASS == "business_logic"
    assert is_known_bug_class("business_logic")
    assert BUG_CLASS_ORACLES["business_logic"] == (OracleKind.ACHIEVED_STATE,)
    assert OracleVerifier().oracles_for("business_logic") == (OracleKind.ACHIEVED_STATE,)


@pytest.mark.parametrize(
    "alias",
    ["workflow_violation", "workflow_abuse", "state_machine_abuse",
     "parameter_tampering", "business_logic_abuse", "insufficient_workflow_validation"],
)
def test_aliases_fold_onto_business_logic(alias: str) -> None:
    assert normalize_bug_class(alias) == "business_logic"
    assert is_known_bug_class(alias)


# ---------------------------------------------------------------------------
# 2. The broken workflow — each abuse is oracle-confirmed
# ---------------------------------------------------------------------------


def test_step_skip_confirms_on_broken_workflow() -> None:
    wf = _Workflow(enforce=False)
    perform, read_state, reset = _driver(wf)
    spec = _spec()
    f = probe_step_skip(spec, spec.step("ship"), perform, read_state, reset)
    assert isinstance(f, ConfirmedFinding)
    assert f.confirmed is True
    assert f.bug_class == "business_logic"
    assert f.confirmed_by == OracleKind.ACHIEVED_STATE
    assert f.confidence >= OracleVerifier().high_confidence
    # confirmation rested on the REAL post-state: ship took effect with no payment
    assert wf.shipped is True and wf.paid is False


def test_replay_confirms_on_broken_workflow() -> None:
    wf = _Workflow(enforce=False)
    perform, read_state, reset = _driver(wf)
    spec = _spec()
    f = probe_replay(spec, spec.step("redeem"), perform, read_state, reset)
    assert isinstance(f, ConfirmedFinding)
    assert f.bug_class == "business_logic"
    assert wf.redeemed == 2  # applied twice — the one-time guard is missing


def test_tamper_confirms_negative_quantity_on_broken_workflow() -> None:
    wf = _Workflow(enforce=False)
    perform, read_state, reset = _driver(wf)
    spec = _spec()
    f = probe_tamper(spec, spec.tamper_probes[0], perform, read_state, reset)
    assert isinstance(f, ConfirmedFinding)
    assert f.bug_class == "business_logic"
    assert wf.qty == -5  # the negative quantity was persisted


def test_detect_all_abuses_on_broken_workflow() -> None:
    wf = _Workflow(enforce=False)
    perform, read_state, reset = _driver(wf)
    findings = detect_workflow_abuse(_spec(), perform, read_state, reset=reset)
    # three step-skips (checkout/pay/ship each guard a predecessor) + replay + tamper
    assert len(findings) == 5
    assert all(isinstance(f, ConfirmedFinding) for f in findings)
    assert {f.confirmed_by for f in findings} == {OracleKind.ACHIEVED_STATE}
    titles = " || ".join(f.title for f in findings)
    assert "step-skip" in titles and "replayed" in titles and "tampering" in titles


# ---------------------------------------------------------------------------
# 3. The guarded twin — NOTHING fires (negative control, no rubber-stamp)
# ---------------------------------------------------------------------------


def test_guarded_workflow_confirms_nothing() -> None:
    wf = _Workflow(enforce=True)
    perform, read_state, reset = _driver(wf)
    spec = _spec()
    assert probe_step_skip(spec, spec.step("ship"), perform, read_state, reset) is None
    assert probe_replay(spec, spec.step("redeem"), perform, read_state, reset) is None
    assert probe_tamper(spec, spec.tamper_probes[0], perform, read_state, reset) is None
    assert detect_workflow_abuse(spec, perform, read_state, reset=reset) == []


def test_step_without_requires_is_not_a_skip_candidate() -> None:
    wf = _Workflow(enforce=False)
    perform, read_state, reset = _driver(wf)
    spec = _spec()
    # `add` has no prerequisites, so there is nothing to skip — no finding even
    # though the app is broken.
    assert probe_step_skip(spec, spec.step("add"), perform, read_state, reset) is None


# ---------------------------------------------------------------------------
# 4. The loopback proof — a REAL HTTP target drives real confirmed findings
# ---------------------------------------------------------------------------


def test_confirm_against_local_broken_workflow() -> None:
    findings = confirm_against_local_workflow(BrokenWorkflowHandler)
    assert len(findings) == 5
    assert all(f.confirmed and f.confirmed_by == OracleKind.ACHIEVED_STATE for f in findings)


def test_confirm_against_local_guarded_workflow_is_empty() -> None:
    assert confirm_against_local_workflow(GuardedWorkflowHandler) == []


# ---------------------------------------------------------------------------
# 5. Determinism — same target, same run, byte-identical serialised findings
# ---------------------------------------------------------------------------


def test_detection_is_deterministic() -> None:
    def run() -> list[str]:
        wf = _Workflow(enforce=False)
        perform, read_state, reset = _driver(wf)
        return [f.model_dump_json() for f in
                detect_workflow_abuse(_spec(), perform, read_state, reset=reset)]

    assert run() == run()


# ---------------------------------------------------------------------------
# 6. Opt-in — the detector is NOT wired into the default scan roster
# ---------------------------------------------------------------------------


def test_bizlogic_is_not_in_default_checks() -> None:
    # Like scanner.race and checks.IdorCheck, this needs an operator-declared
    # workflow spec, so it is opt-in and MUST NOT ride the default roster — that
    # is what keeps the benchmark gate byte-identical (0 extra requests).
    ids = {getattr(c, "id", None) for c in checks_mod.DEFAULT_CHECKS}
    assert "business-logic" not in ids and "bizlogic" not in ids
    bug_classes = {getattr(c, "bug_class", None) for c in checks_mod.DEFAULT_CHECKS}
    assert "business_logic" not in bug_classes


def test_demo_spec_shape() -> None:
    spec = demo_spec()
    assert {s.name for s in spec.steps} == {"add", "checkout", "pay", "ship", "redeem"}
    assert spec.step("redeem").once is True
    assert spec.tamper_probes[0].step == "add"
