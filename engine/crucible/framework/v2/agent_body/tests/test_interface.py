"""X3 — the AgentBody interface is abstract, and run_cycle enforces gate-before-execute structurally."""

from __future__ import annotations

from typing import Optional

import pytest

from framework.v2.agent_body.interface import (
    ActionOutcome,
    AgentBody,
    GateDecision,
    Observation,
    ProposedAction,
    Thought,
)


def test_agent_body_is_abstract() -> None:
    with pytest.raises(TypeError):
        AgentBody()  # type: ignore[abstract]


class _RecordingBody(AgentBody):
    """A minimal test double: it always proposes, and its gate verdict is configurable so we can prove
    run_cycle never reaches execute on a denial. It records whether execute ran."""

    def __init__(self, *, gate_ok: bool) -> None:
        self._gate_ok = gate_ok
        self.executed = False
        self.learned: list[ActionOutcome] = []

    def think(self, observation: Observation) -> Thought:
        return Thought(intent="probe")

    def propose(self, thought: Thought) -> Optional[ProposedAction]:
        return ProposedAction(kind="http_get", target="https://in-scope.example")

    def gate(self, action: ProposedAction) -> GateDecision:
        return GateDecision(authorized=self._gate_ok, reason="test-configured")

    def execute(self, action: ProposedAction, decision: GateDecision) -> ActionOutcome:
        assert decision.authorized, "execute must never run on an unauthorized decision"
        self.executed = True
        return ActionOutcome(executed=True, ok=True)

    def learn(self, outcome: ActionOutcome) -> None:
        self.learned.append(outcome)


def test_run_cycle_executes_only_when_gate_authorizes() -> None:
    body = _RecordingBody(gate_ok=True)
    outcome = body.run_cycle(Observation())
    assert body.executed is True
    assert outcome.executed is True and outcome.ok is True
    assert body.learned and body.learned[-1] is outcome        # learn always observes the outcome


def test_run_cycle_blocks_execution_on_gate_denial() -> None:
    body = _RecordingBody(gate_ok=False)
    outcome = body.run_cycle(Observation())
    assert body.executed is False                              # execute was never reached
    assert outcome.executed is False
    assert "gate denied" in outcome.blocked_reason
    assert body.learned and body.learned[-1].executed is False  # learn still saw the block


def test_proposing_nothing_ends_the_cycle_without_executing() -> None:
    class _Idle(_RecordingBody):
        def propose(self, thought: Thought) -> Optional[ProposedAction]:
            return None

    body = _Idle(gate_ok=True)
    outcome = body.run_cycle(Observation())
    assert body.executed is False
    assert outcome.executed is False and "no action proposed" in outcome.blocked_reason


def test_gate_decision_defaults_to_deny() -> None:
    """Fail-closed default: a GateDecision with no explicit verdict is a DENY."""
    assert GateDecision().authorized is False
