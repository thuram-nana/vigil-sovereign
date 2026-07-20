"""
defender.gap_report — "what would catch me": detection gaps + candidate rules.

The defensive deliverable of a stealth-aware engagement. Given the actions on the
chosen (quietest) attack path, model each one's telemetry, run it through the
operator's detection ruleset, and report which techniques the current rules would
MISS. For each miss, synthesize a candidate Sigma-style rule that WOULD catch it —
so the operator leaves the engagement with concrete detections to add, not just a
list of what got through.

This is explicitly NOT evasion or co-evolution: there is no learned adversary
racing a learned defender. It reuses the DEL's own telemetry model and rules to
tell the blue team where their coverage has holes and how to close them
(constitution § VI — defensive awareness).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import ActionDescriptor, ActionSignal, DetectionRule, RuleCondition
from .rules import DetectionRuleset, default_ruleset
from .telemetry import model_telemetry

# Fields common to almost all traffic — keying a rule on these would false-fire
# on benign requests, so the synthesizer skips them.
_GENERIC_FIELDS = frozenset({"method", "status", "user_agent", "requests", "path", "outcome"})


@dataclass
class DetectionGap:
    """One technique's detection status: the telemetry it emits, whether the
    current ruleset catches it, and (if not) a candidate rule that would."""

    label: str
    signals: list[ActionSignal] = field(default_factory=list)
    covered_by: list[str] = field(default_factory=list)
    candidate_rule: DetectionRule | None = None
    note: str = ""

    @property
    def covered(self) -> bool:
        return bool(self.covered_by)


def synthesize_rule(signals: list[ActionSignal]) -> DetectionRule | None:
    """Propose a specific detection rule from a technique's telemetry: threshold a
    distinctive numeric field, or match a distinctive categorical one. Returns
    None when the telemetry carries only generic fields — itself a finding (the
    technique cannot be distinguished without richer logging)."""
    for sig in signals:
        for fname, val in sorted(sig.fields.items()):
            if fname in _GENERIC_FIELDS:
                continue
            if isinstance(val, bool):
                continue
            if isinstance(val, int) and val > 0:
                threshold = max(1, int(val * 0.8))  # tight enough to catch this instance
                return DetectionRule(
                    id=f"R-SYNTH-{fname.upper()}",
                    title=f"Synthesized: {fname} >= {threshold} on {sig.channel}",
                    channel=sig.channel, severity="medium",
                    conditions=[RuleCondition(field=fname, op="gte", value=threshold)],
                    description=(f"Auto-synthesized to catch a technique that trips {fname}={val} "
                                f"below existing thresholds on the {sig.channel} channel."),
                )
            if isinstance(val, str) and val:
                return DetectionRule(
                    id=f"R-SYNTH-{fname.upper()}",
                    title=f"Synthesized: {fname} == {val!r} on {sig.channel}",
                    channel=sig.channel, severity="medium",
                    conditions=[RuleCondition(field=fname, op="eq", value=val)],
                    description=f"Auto-synthesized to flag {fname}={val!r} on the {sig.channel} channel.",
                )
    return None


def detection_gaps(
    descriptors: list[ActionDescriptor],
    *,
    ruleset: DetectionRuleset | None = None,
    ignore_info: bool = True,
) -> list[DetectionGap]:
    """For each action, whether the ruleset catches it and — if not — a candidate
    rule that would. ``ignore_info`` drops info-severity hits (the deliberately-
    correlatable OBSIDIAN UA 'detection' is a feature, not real coverage)."""
    ruleset = ruleset or default_ruleset()
    gaps: list[DetectionGap] = []
    for descriptor in descriptors:
        signals = model_telemetry(descriptor)
        hits = ruleset.evaluate(signals)
        real = [h for h in hits if not (ignore_info and h.severity == "info")]
        gap = DetectionGap(label=descriptor.target_surface or descriptor.kind.value, signals=signals)
        if real:
            gap.covered_by = [h.rule_id for h in real]
            gap.note = f"covered by {gap.covered_by}"
        else:
            gap.candidate_rule = synthesize_rule(signals)
            gap.note = ("no current rule catches this technique's telemetry"
                        + ("" if gap.candidate_rule else " and it emits only generic fields — needs richer logging"))
        gaps.append(gap)
    return gaps
