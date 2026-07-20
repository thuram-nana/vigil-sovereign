"""
Offline unit tests for RealisticExecutor.

These exercise the harness shape — built-in scenarios load, lookup
works, default fallback fires — without requiring live URK or any
LLM at all.  The integration test under live URK lives in
`framework/v2/planner/tests/test_full_integration.py` and is
explicitly opt-in.
"""

from __future__ import annotations

import pytest

from framework.v2.agents.executor_proto import Executor
from framework.v2.agents.models import HypothesisPayload, PlanPayload
from framework.v2.agents.realistic_executor import (
    BUILT_IN_SCENARIOS, RealisticExecutor, Scenario,
)


# ---------------------------------------------------------------------------
# scenario shape
# ---------------------------------------------------------------------------


def test_built_in_has_three_distinct_strengths() -> None:
    strengths = {s.evidence_strength for s in BUILT_IN_SCENARIOS}
    assert strengths == {"strong", "weak", "mixed"}, (
        f"expected exactly strong+weak+mixed, got {strengths}"
    )


def test_built_in_keys_are_unique() -> None:
    keys = [(s.bug_class, s.surface) for s in BUILT_IN_SCENARIOS]
    assert len(keys) == len(set(keys)), f"duplicate scenario keys: {keys}"


def test_strong_scenario_has_substantive_evidence() -> None:
    """The strong scenario must carry the multi-step evidence that
    closed the Session-3 critique-rejection gap.  Specifically: the
    body_excerpt must be 200+ chars (was empty in DeterministicExecutor)
    and the note must include at least one negative-control reference."""
    strong = next(s for s in BUILT_IN_SCENARIOS if s.evidence_strength == "strong")
    body = strong.outcome.body_excerpt
    note = strong.outcome.note
    assert len(body) >= 200, f"strong body_excerpt only {len(body)} chars"
    assert "Negative control" in note or "negative control" in note, (
        "strong note must walk a negative control"
    )
    assert "DB" in note or "psql" in note, (
        "strong note must include a DB attestation"
    )


def test_weak_scenario_evidence_is_thin() -> None:
    """The weak scenario must be deliberately light — no reproduction,
    no impact walk.  This documents the gate-still-discriminates
    invariant: the harness does NOT rubber-stamp every claim."""
    weak = next(s for s in BUILT_IN_SCENARIOS if s.evidence_strength == "weak")
    note = weak.outcome.note
    assert "No reproduction" in note or "Single observation" in note


def test_mixed_scenario_documents_uncertainty() -> None:
    """The mixed scenario must contain explicit equivocation so
    critique can defensibly land either way."""
    mixed = next(s for s in BUILT_IN_SCENARIOS if s.evidence_strength == "mixed")
    note = mixed.outcome.note
    assert "Honest equivocation" in note or "could be noise" in note.lower()


# ---------------------------------------------------------------------------
# RealisticExecutor lookup
# ---------------------------------------------------------------------------


def _hyp(bug_class: str, surface: str) -> HypothesisPayload:
    return HypothesisPayload(
        handle="H-001", bug_class=bug_class, surface=surface,
        given="g", if_action="if", then_observation="t", because_model="b",
        refute_on="r", cheap_test="c", confidence=0.5, status="open",
    )


def _plan() -> PlanPayload:
    return PlanPayload(plan_id="P-001", next_action="probe")


def test_executor_returns_built_in_scenarios_by_default() -> None:
    ex = RealisticExecutor()
    keys = ex.keys()
    assert ("webhook-forgery", "/payment/cryptomus/callback") in keys
    assert ("information-disclosure", "/robots.txt") in keys
    assert ("timing-side-channel", "/api/login") in keys


def test_executor_returns_strong_outcome_for_strong_key() -> None:
    ex = RealisticExecutor()
    out = ex.execute(
        _hyp("webhook-forgery", "/payment/cryptomus/callback"), _plan(),
    )
    assert out.success is True
    assert out.finding is not None
    assert out.finding.severity == "Critical"
    assert len(out.body_excerpt) >= 200


def test_executor_returns_weak_outcome_for_weak_key() -> None:
    ex = RealisticExecutor()
    out = ex.execute(_hyp("information-disclosure", "/robots.txt"), _plan())
    assert out.success is True
    assert out.finding is not None
    assert out.finding.severity == "Low"


def test_executor_returns_default_for_unknown_key() -> None:
    ex = RealisticExecutor()
    out = ex.execute(_hyp("nonexistent-class", "/nowhere"), _plan())
    assert out.success is False
    assert out.finding is None


def test_executor_extra_scenarios_override_built_ins() -> None:
    from framework.v2.agents.executor_proto import ExecutionOutcome
    custom = Scenario(
        bug_class="webhook-forgery",
        surface="/payment/cryptomus/callback",
        evidence_strength="weak",
        outcome=ExecutionOutcome(success=False, status_code=403, note="custom override"),
    )
    ex = RealisticExecutor(extra_scenarios=[custom])
    out = ex.execute(
        _hyp("webhook-forgery", "/payment/cryptomus/callback"), _plan(),
    )
    assert out.success is False
    assert out.note == "custom override"


def test_executor_use_built_ins_false_isolates() -> None:
    ex = RealisticExecutor(use_built_ins=False)
    assert ex.keys() == []
    out = ex.execute(
        _hyp("webhook-forgery", "/payment/cryptomus/callback"), _plan(),
    )
    assert out.success is False  # default fallback


def test_executor_satisfies_protocol() -> None:
    ex = RealisticExecutor()
    assert isinstance(ex, Executor)
