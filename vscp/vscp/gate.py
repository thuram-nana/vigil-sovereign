"""A thin, fail-closed gate SEQUENCER for VSCP — a facade, never a policy engine.

This mirrors the ``sovereign_bridge`` invariant (W13-2): a facade SEQUENCES existing
deciders and returns the composed verdict; it holds NO authorization policy of its own.
Every ALLOW/DENY VSCP returns comes from a gate — the RBAC-of-record
(:func:`vigil_core.rbac.role_can`) and the findings boundary — not from anything this
sequencer decides by inspecting the request.

VSCP cannot import the product's ``sovereign_bridge`` module directly: it lives in the
``vigil_integration`` package whose ``__init__`` eagerly loads assessment-finding code,
which would breach VSCP's own isolation (see :mod:`vscp.isolation`). So VSCP composes the
SAME underlying gate-of-record primitives that ``sovereign_bridge`` itself delegates to
(``vigil_core``), through this minimal harness. The harness is ~40 lines of pure
sequencing and carries no policy — duplicating a *sequencer* is not a second *policy
engine*, which is the property the constraint actually forbids.

Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

__all__ = ["GateOutcome", "Gate", "Decision", "compose"]


@dataclass(frozen=True)
class GateOutcome:
    """What ONE gate returned. ``allow`` is the gate's verdict; the sequencer reads it,
    it never overrides it."""

    allow: bool
    reason: str = ""
    code: str = ""


@dataclass(frozen=True)
class Gate:
    """A named delegation to an existing decider. ``decide(request) -> GateOutcome``."""

    name: str
    decide: Callable[[Any], GateOutcome]


@dataclass(frozen=True)
class Decision:
    """The composed verdict. Invariant: ``allowed`` <=> ``denied_by is None`` — every
    non-ALLOW names the gate that produced it, so no verdict is the facade's own policy."""

    allowed: bool
    reason: str
    denied_by: str | None
    code: str

    @property
    def effect(self) -> str:
        return "allow" if self.allowed else "deny"


def compose(request: Any, gates: Sequence[Gate]) -> Decision:
    """Sequence the gates in order; the FIRST non-ALLOW wins; a gate that raises is a DENY
    attributed to it (fail-closed). An empty chain is refused — a facade with nothing to
    delegate to would BE a decision point of its own."""
    if not gates:
        return Decision(
            allowed=False,
            reason="no gates to delegate to (an empty chain would be a decision point of its own)",
            denied_by="<config>",
            code="EMPTY_CHAIN",
        )
    for gate in gates:
        try:
            outcome = gate.decide(request)
        except Exception as exc:  # noqa: BLE001 — a raised gate is a DENY attributed to it, never a pass
            return Decision(
                allowed=False,
                reason=f"gate {gate.name!r} raised (fail-closed): {type(exc).__name__}: {exc}",
                denied_by=gate.name,
                code="GATE_ERROR",
            )
        if not isinstance(outcome, GateOutcome):
            return Decision(
                allowed=False,
                reason=f"gate {gate.name!r} returned an unrecognised outcome (fail-closed)",
                denied_by=gate.name,
                code="GATE_ERROR",
            )
        if not outcome.allow:
            return Decision(
                allowed=False,
                reason=outcome.reason or f"denied by {gate.name}",
                denied_by=gate.name,
                code=outcome.code or f"{gate.name.upper()}_DENY",
            )
    return Decision(allowed=True, reason="all gates allow", denied_by=None, code="ALLOW")
