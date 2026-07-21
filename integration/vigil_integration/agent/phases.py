"""
agent.phases — the offensive phase machine mapped onto WARDEN authority tiers (VIGIL-FUSION F2).

redamon gates tools by a soft Python "phase-aware executor". VIGIL maps the same phase ladder onto the
Rust WARDEN kernel's tiers so the phase gate is enforced fail-closed by the kernel, not by a Python
check the LLM could talk its way past:

    informational  → A1   (passive/recon: low blast radius)
    exploitation   → A2   (active exploitation)
    post_exploitation → A3 (lateral movement / persistence / impact)

A destructive/high-blast tool floors at A3 regardless of phase (it also needs the m-of-n
threshold-destruction gate, I4). Phase escalation is MONOTONE and one-step-at-a-time: the machine
refuses a downgrade or a skip, and any forward escalation is an authority-tier crossing that must be
approved through the conjunctive gate (the signed-operator leg), never on the LLM's say-so alone.

Pure/deterministic. Import-clean (stdlib only).
"""

from __future__ import annotations

from .state import Phase

# Phase → WARDEN tier. A0 is reserved for pure no-target observe (never a tool that touches a target).
_PHASE_TIER: dict[Phase, str] = {
    Phase.INFORMATIONAL: "A1",
    Phase.EXPLOITATION: "A2",
    Phase.POST_EXPLOITATION: "A3",
}
_ORDER: list[Phase] = [Phase.INFORMATIONAL, Phase.EXPLOITATION, Phase.POST_EXPLOITATION]

TIER_ORDER = ("A0", "A1", "A2", "A3")


def phase_index(p: Phase) -> int:
    return _ORDER.index(p)


def phase_tier(p: Phase) -> str:
    """The WARDEN tier a tool call must clear to run in phase ``p`` (before any destructive floor)."""
    return _PHASE_TIER[p]


def is_escalation(current: Phase, target: Phase) -> bool:
    return phase_index(target) > phase_index(current)


def can_transition(current: Phase, target: Phase) -> tuple[bool, str]:
    """``(allowed, reason)`` for a proposed phase transition. Monotone, one step at a time — a
    downgrade or a skip is refused fail-closed. An allowed transition is still an authority escalation
    that the caller routes through the conjunctive gate for signed approval."""
    if target == current:
        return False, f"no-op: already in phase {current.value}"
    if phase_index(target) < phase_index(current):
        return False, (f"refusing to DOWNGRADE phase {current.value}→{target.value} "
                       "(escalation is monotone)")
    if phase_index(target) - phase_index(current) > 1:
        return False, (f"refusing to SKIP phases {current.value}→{target.value} "
                       "(escalate one step at a time)")
    return True, f"escalation {current.value}→{target.value} (needs signed approval at {phase_tier(target)})"


def tool_tier(phase: Phase, *, destructive: bool = False) -> str:
    """The WARDEN tier a tool needs: the phase tier, floored at A3 for a destructive/high-blast tool
    (which additionally requires the m-of-n threshold-destruction authorization)."""
    tier = phase_tier(phase)
    if destructive and TIER_ORDER.index(tier) < TIER_ORDER.index("A3"):
        return "A3"
    return tier
