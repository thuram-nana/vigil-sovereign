"""
defender.scoring — self-assessed detectability of an action.

Combine an action's modelled telemetry with a detection ruleset to a
`DetectionScore`: which rules fire, and a single detectability number
(noisy-OR over hit severities). This is honest self-assessment — "how
loud am I" — not a step toward being quieter by illegitimate means.

Gated on Capability.DEFENDER_TELEMETRY (OFFENSIVE tier): even pure
self-assessment is a capability an un-entitled deployment should not run
under enforcement. Ungoverned dev checkouts are permitted with a warning
(the standard activation model).
"""

from __future__ import annotations

from ..entitlement import Capability, require_capability
from .models import (
    ActionDescriptor,
    DetectionHit,
    DetectionScore,
    Severity,
)
from .rules import DetectionRuleset, default_ruleset
from .telemetry import model_telemetry

_SEVERITY_WEIGHT: dict[Severity, float] = {
    "info": 0.05,
    "low": 0.15,
    "medium": 0.40,
    "high": 0.70,
    "critical": 0.90,
}

_SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _detectability(hits: list[DetectionHit]) -> float:
    survival = 1.0
    for hit in hits:
        survival *= 1.0 - _SEVERITY_WEIGHT[hit.severity]
    return round(1.0 - survival, 6)


def _loudest(hits: list[DetectionHit]) -> tuple[str, Severity]:
    loudest: DetectionHit | None = None
    for hit in hits:
        if loudest is None or _SEVERITY_RANK[hit.severity] > _SEVERITY_RANK[loudest.severity]:
            loudest = hit
    if loudest is None:
        return "", "info"
    return loudest.channel, loudest.severity


def score_action(
    descriptor: ActionDescriptor,
    ruleset: DetectionRuleset | None = None,
    *,
    check_capability: bool = True,
) -> DetectionScore:
    """Score one action's detectability against `ruleset` (default set if
    None). Raises EntitlementViolation under enforcement without the
    DEFENDER_TELEMETRY capability."""
    if check_capability:
        require_capability(Capability.DEFENDER_TELEMETRY)

    rs = ruleset if ruleset is not None else default_ruleset()
    signals = model_telemetry(descriptor)
    hits = rs.evaluate(signals)
    channel, severity = _loudest(hits)
    return DetectionScore(
        kind=descriptor.kind,
        signals_emitted=len(signals),
        hits=hits,
        detectability=_detectability(hits),
        loudest_channel=channel,
        loudest_severity=severity,
    )
