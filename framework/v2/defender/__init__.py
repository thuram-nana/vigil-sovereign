"""
defender — DEL, the Defender Emulation Layer (Milestone M4).

DEFENSIVE SUBSET ONLY. This package answers one question: *given an
action the framework is about to take, what telemetry would it emit, and
which detections would fire?* That self-awareness is the purple-team
capability that makes an authorised red team worth deploying against a
hardened adversary — it lets the operator understand their own footprint
and operate a deliberate TEST vs EMULATE posture.

What this package does NOT contain, by deliberate policy
(ROADMAP-FLAGSHIP.md § 1, § 4): a working library that *defeats* a named
production defender. Knowing you tripped a WAF rule is defensive
awareness; a turnkey bypass for that rule is offensive capability and
stays an entitlement-locked, human-authored interface
(Capability.DEFENDER_EVASION), not something generated here. Posture
guidance in this package is honest self-assessment ("this action is
high-fidelity detectable"), never an evasion recipe.

Self-detection scoring is gated on Capability.DEFENDER_TELEMETRY.

Public surface:

    from framework.v2.defender import (
        ActionDescriptor, ActionKind, Posture,
        TelemetryModel, DetectionRuleset, DetectionScore, PostureAnnotation,
        model_telemetry, score_action, annotate_action,
    )
"""

from __future__ import annotations

from .models import (
    ActionDescriptor,
    ActionKind,
    ActionSignal,
    DetectionHit,
    DetectionRule,
    DetectionScore,
    Posture,
    PostureAnnotation,
)
from .posture import annotate_action
from .rules import DetectionRuleset, default_ruleset
from .scoring import score_action
from .telemetry import TelemetryModel, model_telemetry

__all__ = [
    "ActionDescriptor",
    "ActionKind",
    "ActionSignal",
    "DetectionHit",
    "DetectionRule",
    "DetectionScore",
    "Posture",
    "PostureAnnotation",
    "TelemetryModel",
    "model_telemetry",
    "DetectionRuleset",
    "default_ruleset",
    "score_action",
    "annotate_action",
]
