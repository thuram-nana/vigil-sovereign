"""agent_body — the pluggable agent-BODY contract (X3).

[SCAFFOLD — research-gated] Interface only. Formalizes think→propose→gate→execute→learn so a next-gen
body is swappable without relaxing safety: every proposed action passes the conjunctive gate, nothing
self-authorizes, the oracle is the sole authority. See agent_body/interface.py.
"""

from __future__ import annotations

from .interface import (
    ActionOutcome,
    AgentBody,
    GateDecision,
    Observation,
    ProposedAction,
    Thought,
)

__all__ = [
    "AgentBody",
    "Observation",
    "Thought",
    "ProposedAction",
    "GateDecision",
    "ActionOutcome",
]
