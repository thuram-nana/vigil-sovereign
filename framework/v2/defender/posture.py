"""
defender.posture — annotate an action's detectability under a posture.

This is where DEL's policy line is enforced in code: the guidance it
produces is *self-assessment*, never an evasion recipe.

  TEST     — the default for authorised owner-testing. Footprint is
             intended; guidance reinforces correlatability (stable
             source, recognisable UA) so the operator can grep their own
             traffic. The constitution (§ VI) wants this.
  EMULATE  — the operator wants to understand detectability as an
             adversary would experience it. Guidance states, honestly,
             which detections fire and how loud the action is — and
             explicitly refuses to generate a bypass. Reducing footprint
             legitimately is a scope/timing decision coordinated with the
             engagement owner, not a payload trick DEL hands out.
"""

from __future__ import annotations

from .models import ActionDescriptor, DetectionScore, Posture, PostureAnnotation
from .rules import DetectionRuleset
from .scoring import score_action

_OBSIDIAN_UA_RULE = "R-UA-OBSIDIAN"


def _test_guidance(score: DetectionScore) -> list[str]:
    guidance = [
        "TEST posture: full footprint is intended. Keep a stable source IP "
        "and the recognisable user-agent so the operator can correlate this "
        "traffic in their own logs (constitution § VI.4).",
    ]
    if any(h.rule_id == _OBSIDIAN_UA_RULE for h in score.hits):
        guidance.append(
            "The OBSIDIAN user-agent 'detection' fired as intended — that is "
            "correlatability working, not a footprint to hide."
        )
    return guidance


def _emulate_guidance(score: DetectionScore) -> list[str]:
    guidance: list[str] = []
    real_hits = [h for h in score.hits if h.severity != "info"]
    if not real_hits:
        guidance.append(
            "No modelled detection above 'info' fired against the supplied "
            "ruleset. Treat this as a lower bound on footprint, not proof of "
            "stealth: the ruleset may be incomplete, and absence of a modelled "
            "hit is not absence of detection."
        )
    else:
        for h in real_hits:
            guidance.append(
                f"Detectable: rule {h.rule_id} ({h.title}) would fire on the "
                f"{h.channel} channel at severity '{h.severity}'. A defender "
                f"running this rule will see this action."
            )
        guidance.append(
            f"Overall self-assessed detectability {score.detectability:.2f} "
            f"(loudest: {score.loudest_channel or 'n/a'} / {score.loudest_severity}). "
            "DEL reports footprint; it does not generate evasion. To lower "
            "footprint legitimately, adjust scope/timing/rate with the engagement "
            "owner — not by defeating the detection."
        )
    return guidance


def annotate_action(
    descriptor: ActionDescriptor,
    posture: Posture,
    ruleset: DetectionRuleset | None = None,
    *,
    check_capability: bool = True,
) -> PostureAnnotation:
    """Score the action and attach posture-appropriate, defensive-only
    guidance."""
    score = score_action(descriptor, ruleset, check_capability=check_capability)
    guidance = (
        _test_guidance(score) if posture is Posture.TEST else _emulate_guidance(score)
    )
    return PostureAnnotation(posture=posture, score=score, guidance=guidance)
