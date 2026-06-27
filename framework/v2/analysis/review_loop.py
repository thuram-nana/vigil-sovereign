"""
analysis.review_loop — autonomous white-box source review.

Ties the real pieces together into the "reasoning over deep analysis"
loop, end to end:

    DAA dataflow findings (provable source->sink, semgrep/Joern)
        --for each, under budget, kill-switch armed-->
    live URK critique (claude-code backend)  --> confirm / refute
        --> ReviewReport of evidence-backed, model-confirmed findings

Every safety rail already in the framework applies:
  - whole-tree analysis is gated on DEEP_STATIC_ANALYSIS (via run_analysis);
  - the engagement kill-switch is checked before EVERY model call, so an
    operator can halt a running review instantly and persistently;
  - a hard review budget caps model calls (each costs ~30-60s + tokens).

Decoupled and testable: the model step is a `Reviewer` callable. The
default routes through URK's `critique` binding (live when
CRUCIBLE_LLM_BACKEND=claude-code, DryRun otherwise); tests inject a
deterministic fake. The loop itself sends no traffic to any target — it
reads source and reasons about it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..authority.killswitch import KillSwitch
from .models import AnalysisFinding, AnalysisTarget
from .orchestrator import run_analysis

# A reviewer takes (claim, evidence, context) and returns an outcome.
Reviewer = Callable[[str, str, str], "CritiqueOutcome"]

_DATAFLOW_ANALYZERS = frozenset({"semgrep", "joern"})


class CritiqueOutcome(BaseModel):
    """Normalized result of one review step."""

    model_config = ConfigDict(extra="forbid")

    decision: str = Field(description="confirm | objections | more_evidence_needed | ...")
    coverage_gaps: list[str] = Field(default_factory=list)
    deception_check: str = ""
    is_dryrun: bool = True


class ReviewedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: AnalysisFinding
    claim: str
    decision: str
    confirmed: bool
    coverage_gaps: list[str] = Field(default_factory=list)
    deception_check: str = ""


class ReviewReport(BaseModel):
    """Outcome of an autonomous source-review run."""

    model_config = ConfigDict(extra="forbid")

    target_root: str
    total_findings: int = Field(ge=0)
    reviews_run: int = Field(ge=0)
    confirmed_count: int = Field(ge=0)
    reviewed: list[ReviewedFinding] = Field(default_factory=list)
    halted: bool = False
    halt_reason: str = ""
    used_live_reasoning: bool = False

    def confirmed(self) -> list[ReviewedFinding]:
        return [r for r in self.reviewed if r.confirmed]


def kernel_reviewer(claim: str, evidence: str, context: str) -> CritiqueOutcome:
    """Default reviewer: URK's critique binding. Live when
    CRUCIBLE_LLM_BACKEND=claude-code, DryRun otherwise."""
    from ..kernel.critique import critique

    result, trace = critique(claim=claim, evidence=evidence, context=context)
    decision = getattr(result.decision, "value", str(result.decision))
    return CritiqueOutcome(
        decision=decision,
        coverage_gaps=list(result.coverage_gaps),
        deception_check=result.deception_check,
        is_dryrun=trace.is_dryrun,
    )


def _claim_for(f: AnalysisFinding) -> str:
    return f"{f.message} (at {f.path}:{f.line}{', ' + f.cwe if f.cwe else ''})"


def _source_window(root: Path, f: AnalysisFinding, ctx: int = 10) -> str:
    """The actual source lines around the finding, with line numbers, so the
    reviewer can examine real code (the critique-agent demands this — a
    one-line summary draws a 'code not examined' coverage gap)."""
    src = root if root.is_file() else root / f.path
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(0, f.line - ctx - 1)
    hi = min(len(lines), f.line + ctx)
    out = []
    for i in range(lo, hi):
        marker = ">>" if (i + 1) == f.line else "  "
        out.append(f"{marker} {i + 1:4}| {lines[i]}")
    return "\n".join(out)


def _evidence_for(f: AnalysisFinding, root: Path) -> str:
    window = _source_window(root, f)
    return (
        f"DAA {f.analyzer} finding (rule {f.rule_id}, severity {f.severity}). "
        f"This is a dataflow/taint result where available — untrusted input "
        f"reaching the sink (line marked >>), not a pattern match.\n\n"
        f"Source ({f.path}):\n{window or f.snippet or '(unavailable)'}"
    )


def _prioritized(findings: list[AnalysisFinding]) -> list[AnalysisFinding]:
    """Review dataflow (semgrep/Joern) findings first; fall back to the rest
    so a run with only lexical findings still does something."""
    dataflow = [f for f in findings if f.analyzer in _DATAFLOW_ANALYZERS]
    return dataflow if dataflow else findings


def run_source_review(
    target: AnalysisTarget,
    *,
    engagement_slug: str = "source-review",
    max_reviews: int = 5,
    reviewer: Reviewer | None = None,
    killswitch: KillSwitch | None = None,
    analyzers: list | None = None,
    check_capability: bool = True,
) -> ReviewReport:
    """Run DAA over `target`, then have the reviewer confirm/refute each
    finding (highest-signal first) up to `max_reviews`, checking the
    kill-switch before each model call."""
    report = run_analysis(target, analyzers=analyzers, check_capability=check_capability)
    findings = _prioritized(report.findings)
    ks = killswitch if killswitch is not None else KillSwitch(engagement_slug)
    review = reviewer if reviewer is not None else kernel_reviewer
    root = Path(target.root).expanduser().resolve()

    reviewed: list[ReviewedFinding] = []
    halted = False
    halt_reason = ""
    used_live = False

    for f in findings:
        if len(reviewed) >= max_reviews:
            break
        if ks.is_tripped():
            halted = True
            halt_reason = ks.reason() or "kill-switch tripped"
            break
        claim = _claim_for(f)
        outcome = review(claim, _evidence_for(f, root), f"Source review of {f.path}")
        used_live = used_live or (not outcome.is_dryrun)
        reviewed.append(ReviewedFinding(
            finding=f,
            claim=claim,
            decision=outcome.decision,
            confirmed=(outcome.decision == "confirm"),
            coverage_gaps=outcome.coverage_gaps,
            deception_check=outcome.deception_check,
        ))

    return ReviewReport(
        target_root=target.root,
        total_findings=len(report.findings),
        reviews_run=len(reviewed),
        confirmed_count=sum(1 for r in reviewed if r.confirmed),
        reviewed=reviewed,
        halted=halted,
        halt_reason=halt_reason,
        used_live_reasoning=used_live,
    )
