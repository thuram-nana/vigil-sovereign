"""agent_body.interface — the pluggable agent-BODY contract (X3).

[SCAFFOLD — research-gated] This is an INTERFACE ONLY. It changes no behaviour and wires no engine; it
names the contract a next-generation agent body must satisfy so that a future body (a different planner,
a different tool-runtime) can be swapped in WITHOUT relaxing any safety property.

THE LOOP
--------
Every body — the current Strix-based body is one implementation — runs the same cycle:

    think  →  propose  →  gate  →  execute  →  learn

  * think    — form intent/next step from the current observation (read-only).
  * propose  — emit a concrete ``ProposedAction`` (WHAT it wants to do). Proposing is not doing.
  * gate     — the proposed action is submitted to the CONJUNCTIVE gate (scope ∧ tier ∧ approval ∧ …).
               The body does NOT decide; it receives a ``GateDecision``.
  * execute  — run the action ONLY if the gate authorized it. A denied action is never executed.
  * learn    — update internal state from the ``ActionOutcome`` (re-rank/defer only — see invariants).

THE CONTRACT (non-negotiable — a body that breaks any of these is not a valid body)
-----------------------------------------------------------------------------------
  1. Nothing self-authorizes. Every proposed action passes the conjunctive gate before execution;
     the body cannot mark its own action authorized. ``run_cycle`` enforces this structurally: it will
     not call ``execute`` unless ``gate`` returned ``authorized=True``.
  2. The ORACLE is the sole authority for whether a finding is real. A body proposes and acts; it never
     mints a fact, never promotes a lead to a finding, never grants a tier. Learning may re-rank or
     defer what to try next — it can never manufacture certainty or widen scope.
  3. Fail-closed: an absent/ambiguous gate decision is treated as DENY, not allow.

Because this is a scaffold, ``AgentBody`` is abstract and cannot be instantiated. ``run_cycle`` is a
concrete TEMPLATE METHOD that composes the abstract steps and enforces invariant (1) — so any body a
future author plugs in inherits the gate-before-execute guarantee for free.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Observation:
    """What the body currently sees (spine state, last result, target behaviour). Read-only input."""

    state: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Thought:
    """The body's intent for this cycle — the reasoning that leads to a proposal. Carries no authority."""

    intent: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProposedAction:
    """WHAT the body wants to do — never pre-authorized. ``kind``/``target``/``params`` are what the gate
    adjudicates. A body cannot set an 'authorized' flag here; authorization is the gate's output only."""

    kind: str
    target: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GateDecision:
    """The gate's verdict on a proposed action. ``authorized`` is produced by the conjunctive gate, NOT
    by the body. Fail-closed: the default is DENY."""

    authorized: bool = False
    reason: str = ""


@dataclass(frozen=True)
class ActionOutcome:
    """The result of an executed (or blocked) action — the input to ``learn``."""

    executed: bool = False
    ok: bool = False
    detail: dict[str, Any] = field(default_factory=dict)
    blocked_reason: str = ""


class AgentBody(ABC):
    """The contract a pluggable agent body must satisfy. Abstract — a scaffold, not a runtime.

    The current production body (the Strix-based tool-runtime) is ONE implementation of this contract; it
    already routes actions through the conjunctive gate and never self-authorizes. This interface simply
    makes that contract explicit and swappable, so a next-gen body inherits the same guarantees."""

    @abstractmethod
    def think(self, observation: Observation) -> Thought:
        """Form intent from the current observation. Read-only — no side effects, no authority."""

    @abstractmethod
    def propose(self, thought: Thought) -> Optional[ProposedAction]:
        """Emit a concrete action to attempt, or None to end the cycle. Proposing is not doing."""

    @abstractmethod
    def gate(self, action: ProposedAction) -> GateDecision:
        """Submit the action to the CONJUNCTIVE gate and return its decision. The body must NOT decide
        authorization itself — a real body delegates to the actual gate-of-record. Fail-closed."""

    @abstractmethod
    def execute(self, action: ProposedAction, decision: GateDecision) -> ActionOutcome:
        """Run an AUTHORIZED action. Implementations must assume ``run_cycle`` already enforced the gate;
        a defensive re-check is encouraged but the template method guarantees this is only reached when
        ``decision.authorized`` is True."""

    @abstractmethod
    def learn(self, outcome: ActionOutcome) -> None:
        """Update internal state from the outcome. Re-rank/defer ONLY — never mint a fact, promote a
        lead, grant a tier, or widen scope. The oracle remains the sole authority."""

    def run_cycle(self, observation: Observation) -> ActionOutcome:
        """TEMPLATE METHOD (concrete) — composes one think→propose→gate→execute→learn cycle and enforces
        the core invariant: EXECUTE IS UNREACHABLE UNLESS THE GATE AUTHORIZED THE ACTION. A body cannot
        override this to bypass the gate without overriding the whole method (a visible, reviewable act).

        Returns the cycle's outcome. If nothing was proposed, or the gate denied the action, the outcome
        is a non-executed record carrying the reason — and ``learn`` still observes it."""
        thought = self.think(observation)
        action = self.propose(thought)
        if action is None:
            outcome = ActionOutcome(executed=False, ok=False, blocked_reason="no action proposed")
            self.learn(outcome)
            return outcome
        decision = self.gate(action)
        if not decision.authorized:
            outcome = ActionOutcome(
                executed=False, ok=False,
                blocked_reason=f"gate denied: {decision.reason or 'not authorized'}")
            self.learn(outcome)
            return outcome
        outcome = self.execute(action, decision)
        self.learn(outcome)
        return outcome
