"""
entitlement.registry — the capability ladder.

Two facts live here, and only here:

  1. REQUIRED_TIER: the minimum clearance tier each capability demands.
  2. _TIER_RANK: the monotone ordering of tiers.

Everything else (the gate, the models) derives from these. Adding a
capability means adding a REQUIRED_TIER entry; the module refuses to
import if any Capability lacks one, so a forgotten mapping fails loud
at startup rather than silently defaulting a dangerous capability to
BASELINE.
"""

from __future__ import annotations

from .models import Capability, CapabilityTier

# Monotone ordering. A grant of tier T permits every capability whose
# required tier rank is <= rank(T).
_TIER_RANK: dict[CapabilityTier, int] = {
    CapabilityTier.BASELINE: 0,
    CapabilityTier.STANDARD: 1,
    CapabilityTier.OFFENSIVE: 2,
    CapabilityTier.ADVANCED: 3,
}


# The minimum tier each capability requires.
REQUIRED_TIER: dict[Capability, CapabilityTier] = {
    # baseline — runs with no entitlement
    Capability.CORE_REASONING: CapabilityTier.BASELINE,
    Capability.PASSIVE_INTAKE: CapabilityTier.BASELINE,
    # standard
    Capability.ACTIVE_RECON: CapabilityTier.STANDARD,
    Capability.AUTONOMOUS_PLANNING: CapabilityTier.STANDARD,
    # defensive — AEGIS Gateway active enforcement (blocking a PROVEN attack on the operator's own
    # app). STANDARD, not offensive: it attacks no one, but active blocking is a deliberate,
    # higher-impact action than read-only observe, so a GOVERNED deployment gates it (an ungoverned
    # one permits it, flagged, like every non-baseline capability).
    Capability.AEGIS_RESPOND: CapabilityTier.STANDARD,
    # offensive
    Capability.EXPLOIT_EXECUTION: CapabilityTier.OFFENSIVE,
    Capability.DEEP_STATIC_ANALYSIS: CapabilityTier.OFFENSIVE,
    Capability.DEFENDER_TELEMETRY: CapabilityTier.OFFENSIVE,
    # advanced — most dangerous, entitlement-locked
    Capability.FULL_CHAIN_EXPLOITATION: CapabilityTier.ADVANCED,
    Capability.DEFENDER_EVASION: CapabilityTier.ADVANCED,
    Capability.SELF_IMPROVEMENT_MERGE: CapabilityTier.ADVANCED,
}


# Fail loud at import if a capability is unmapped. A new dangerous
# capability with no tier must not silently inherit BASELINE.
_missing = [c for c in Capability if c not in REQUIRED_TIER]
if _missing:  # pragma: no cover - guards against developer error
    raise RuntimeError(
        f"registry.REQUIRED_TIER is missing capabilities: {_missing}. "
        f"Every Capability must declare its required tier."
    )


# Capabilities available with no entitlement at all.
BASELINE_CAPABILITIES: frozenset[Capability] = frozenset(
    c for c, t in REQUIRED_TIER.items() if t == CapabilityTier.BASELINE
)


def tier_rank(tier: CapabilityTier) -> int:
    return _TIER_RANK[tier]


def required_tier(capability: Capability) -> CapabilityTier:
    return REQUIRED_TIER[capability]


def tier_permits(granted_tier: CapabilityTier, capability: Capability) -> bool:
    """True iff a grant of `granted_tier` clears the capability's
    required tier on the monotone ladder."""
    return tier_rank(granted_tier) >= tier_rank(required_tier(capability))


def is_baseline(capability: Capability) -> bool:
    return capability in BASELINE_CAPABILITIES


def effective_capabilities(
    granted_tier: CapabilityTier,
    explicit_allowlist: list[Capability],
) -> frozenset[Capability]:
    """The capabilities an entitlement actually confers.

    Tier sets the ceiling; the explicit allowlist applies
    least-privilege within it. An empty allowlist means 'everything the
    tier permits'. A non-empty allowlist restricts to the listed
    capabilities — but only those that are also within the tier (a
    listed capability above the tier is ignored, never elevated)."""
    within_tier = frozenset(c for c in Capability if tier_permits(granted_tier, c))
    if not explicit_allowlist:
        return within_tier
    return within_tier & frozenset(explicit_allowlist)
