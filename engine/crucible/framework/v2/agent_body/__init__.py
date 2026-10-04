"""agent_body — the pluggable agent-BODY contract (X3).

[SCAFFOLD — research-gated] Interface only. Formalizes think→propose→gate→execute→learn so a next-gen
body is swappable without relaxing safety: every proposed action passes the conjunctive gate, nothing
self-authorizes, the oracle is the sole authority. See agent_body/interface.py.

M4.3 adds a deterministic safety kernel for narrowly-typed DEFENSIVE containment actions (see
agent_body/defensive.py). It is ADDITIVE and DEFAULT-OFF: the existing kinds (``http_get`` and the rest) are
untouched and byte-identical; a capability token is required ONLY by the new defensive kinds.

The defensive symbols are exported LAZILY (PEP 562): they are imported only on first attribute access, so
importing the lightweight ``agent_body.interface`` (the sovereign side's FATAL-2 path — ABC + dataclasses,
no offense engine, no vigil_core) stays as minimal as before. ``from framework.v2.agent_body import
gate_defensive_action`` loads the kernel (and vigil_core) on demand.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .interface import (
    ActionOutcome,
    AgentBody,
    GateDecision,
    Observation,
    ProposedAction,
    Thought,
)

# M4.3 — the defensive containment safety kernel's public names, resolved lazily via __getattr__ below so the
# lightweight interface import never eagerly pulls vigil_core / the kernel.
_DEFENSIVE_EXPORTS = frozenset({
    "DefensiveCapabilityError",
    "DEFENSIVE_KINDS",
    "ISOLATE_ENDPOINT",
    "REVOKE_SESSION",
    "BLOCK_IP",
    "QUARANTINE_HOST",
    "register_defensive_kind",
    "is_defensive_kind",
    "defensive_kinds",
    "defensive_target_digest",
    "mint_defensive_capability",
    "DefensiveRateLimiter",
    "gate_defensive_action",
    "CapabilityGatedBody",
})

__all__ = [
    "AgentBody",
    "Observation",
    "Thought",
    "ProposedAction",
    "GateDecision",
    "ActionOutcome",
    *sorted(_DEFENSIVE_EXPORTS),
]


def __getattr__(name: str):
    """PEP 562 lazy export: the M4.3 defensive seam is imported ONLY on first access, so importing the
    lightweight interface (the sovereign side's FATAL-2 path) never eagerly pulls vigil_core or the kernel."""
    if name in _DEFENSIVE_EXPORTS:
        from . import defensive
        return getattr(defensive, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)


if TYPE_CHECKING:  # make the lazy names visible to type checkers / IDEs without eager import at runtime.
    from .defensive import (  # noqa: F401
        BLOCK_IP,
        DEFENSIVE_KINDS,
        ISOLATE_ENDPOINT,
        QUARANTINE_HOST,
        REVOKE_SESSION,
        CapabilityGatedBody,
        DefensiveCapabilityError,
        DefensiveRateLimiter,
        defensive_kinds,
        defensive_target_digest,
        gate_defensive_action,
        is_defensive_kind,
        mint_defensive_capability,
        register_defensive_kind,
    )
