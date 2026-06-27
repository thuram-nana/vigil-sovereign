"""
analysis.seed — turn DAA findings into testable hypotheses.

This is the payoff of deep sensing: a static-analysis finding is a
*lead*, and a lead becomes useful when it is phrased as a falsifiable
hypothesis the rest of the framework can act on. This module maps each
high-signal `AnalysisFinding` to a blackboard `HypothesisPayload` — the
same shape the hypothesis-agent emits — so DAA findings flow straight
into the existing exploit/critique pipeline. The exploit agent already
knows how to claim and test an open hypothesis; seeding the blackboard
from DAA is all that is needed to ground hypotheses in real sinks.

Kept out of `analysis/__init__` on purpose: it imports the agents layer,
and the DAA core must stay importable without it.

A seeded hypothesis is a starting point, not a confirmed bug — it enters
the pipeline at status 'open' and must survive execution and the
critique-agent like any other. Static analysis cannot prove reachability;
the framework confirms it.
"""

from __future__ import annotations

from collections.abc import Callable

from ..agents.blackboard import Blackboard
from ..agents.models import HypothesisPayload
from .models import AnalysisFinding, AnalysisReport

# Map DAA rule ids to the bug class the resulting hypothesis carries.
_RULE_BUG_CLASS: dict[str, str] = {
    "DAA-EVAL": "Code Injection",
    "DAA-EXEC": "Code Injection",
    "DAA-SHELL-TRUE": "OS Command Injection",
    "DAA-PICKLE": "Insecure Deserialization",
    "DAA-YAML-LOAD": "Insecure Deserialization",
    "DAA-WEAK-HASH": "Weak Cryptography",
    "DAA-SECRET": "Hardcoded Secret",
    "DAA-TLS-VERIFY-OFF": "Improper Certificate Validation",
    "DAA-REQUESTS-INSECURE": "Improper Certificate Validation",
    "DAA-DEBUG-TRUE": "Security Misconfiguration",
    "DAA-MD-INNERHTML": "Cross-Site Scripting",
}

_SEVERITY_CONFIDENCE: dict[str, float] = {
    "critical": 0.9, "high": 0.75, "medium": 0.5, "low": 0.3, "info": 0.1,
}

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


def _bug_class(finding: AnalysisFinding) -> str:
    if finding.rule_id in _RULE_BUG_CLASS:
        return _RULE_BUG_CLASS[finding.rule_id]
    # External-analyzer findings: prefer the CWE, else a generic label.
    return finding.cwe or "Static-Analysis Lead"


def seed_from_finding(finding: AnalysisFinding, handle: str) -> HypothesisPayload:
    """Map one DAA finding to a falsifiable hypothesis."""
    where = f"{finding.path}:{finding.line}"
    return HypothesisPayload(
        handle=handle,
        surface=where,
        bug_class=_bug_class(finding),
        given=f"static analysis ({finding.analyzer}/{finding.rule_id}) flagged {where}",
        if_action=f"trace attacker-controlled input into the sink at {where}",
        then_observation="the sink is reachable with attacker-controlled input",
        because_model=finding.message,
        refute_on="the value reaching the sink is constant or fully validated, "
        "not attacker-controlled",
        cheap_test=f"read {where} and follow the dataflow into the flagged construct",
        confidence=_SEVERITY_CONFIDENCE.get(finding.severity, 0.4),
        status="open",
    )


def seeds_from_analysis(
    report: AnalysisReport,
    *,
    min_severity: str = "medium",
    handle_prefix: str = "DAA",
) -> list[HypothesisPayload]:
    """Hypotheses for every finding at or above `min_severity`, ordered as
    the report orders them (severity-first). Handles are stable and
    sequential for determinism."""
    floor = _SEVERITY_RANK.get(min_severity, 2)
    selected = [f for f in report.findings if _SEVERITY_RANK.get(f.severity, 0) >= floor]
    return [
        seed_from_finding(f, f"{handle_prefix}-{i:03d}")
        for i, f in enumerate(selected, start=1)
    ]


def post_seeds(bb: Blackboard, engagement_slug: str, seeds: list[HypothesisPayload]) -> list[int]:
    """Post seed hypotheses to the engagement blackboard as the 'daa'
    agent. Returns the new event ids. The exploit agent will pick these
    up as open hypotheses on its next step."""
    ids: list[int] = []
    for seed in seeds:
        ids.append(
            bb.post(
                engagement=engagement_slug,
                kind="hypothesis",
                agent_name="daa",
                payload=seed.model_dump(),
            )
        )
    return ids


class DaaHypothesisSeeder:
    """Run analysis and seed the blackboard in one step. `analyze` is the
    injected analysis call (typically `analysis.run_analysis` bound to a
    target), kept as a parameter so this stays testable without a live
    capability check or filesystem."""

    def __init__(
        self,
        bb: Blackboard,
        analyze: Callable[[], AnalysisReport],
        *,
        min_severity: str = "medium",
    ) -> None:
        self._bb = bb
        self._analyze = analyze
        self._min_severity = min_severity

    def seed(self, engagement_slug: str) -> list[int]:
        report = self._analyze()
        seeds = seeds_from_analysis(report, min_severity=self._min_severity)
        return post_seeds(self._bb, engagement_slug, seeds)
