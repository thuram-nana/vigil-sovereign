"""
analysis.orchestrator — run analyzers and merge their findings.

Runs every supplied analyzer that is available, records the ones that are
not (with a reason), de-duplicates findings across analyzers, and returns
one `AnalysisReport`. Whole-tree analysis is gated on
Capability.DEEP_STATIC_ANALYSIS (OFFENSIVE tier) — white-box source
analysis is a real capability an un-entitled deployment should not run
under enforcement.

An analyzer that errors mid-run is recorded as skipped with the error,
not allowed to abort the whole report: partial deep analysis still feeds
the kernel.
"""

from __future__ import annotations

from ..common import logging as clog
from ..common.errors import CrucibleError
from ..entitlement import Capability, require_capability
from .analyzers.builtin import PatternAnalyzer
from .analyzers.external import SemgrepAnalyzer
from .models import (
    AnalysisFinding,
    AnalysisReport,
    AnalysisTarget,
    Analyzer,
    SkippedAnalyzer,
)

_log = clog.get_logger("analysis")

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


def default_analyzers() -> list[Analyzer]:
    """Built-in pattern analyzer (always available) plus the Semgrep
    adapter (available iff semgrep is installed)."""
    return [PatternAnalyzer(), SemgrepAnalyzer()]


def _dedup(findings: list[AnalysisFinding]) -> list[AnalysisFinding]:
    seen: set[str] = set()
    out: list[AnalysisFinding] = []
    for f in findings:
        key = f.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def run_analysis(
    target: AnalysisTarget,
    analyzers: list[Analyzer] | None = None,
    *,
    check_capability: bool = True,
) -> AnalysisReport:
    """Run analyzers over the target and return a merged report."""
    if check_capability:
        require_capability(Capability.DEEP_STATIC_ANALYSIS)

    used = analyzers if analyzers is not None else default_analyzers()
    files_scanned = len(target.iter_files())

    ran: list[str] = []
    skipped: list[SkippedAnalyzer] = []
    collected: list[AnalysisFinding] = []

    for analyzer in used:
        available, reason = analyzer.is_available()
        if not available:
            skipped.append(SkippedAnalyzer(name=analyzer.name, reason=reason))
            continue
        try:
            collected.extend(analyzer.analyze(target))
            ran.append(analyzer.name)
        except CrucibleError as e:
            _log.warning("analysis.analyzer_failed", analyzer=analyzer.name, error=str(e))
            skipped.append(SkippedAnalyzer(name=analyzer.name, reason=f"error: {e}"))

    merged = _dedup(collected)
    merged.sort(key=lambda f: (-_SEVERITY_RANK.get(f.severity, 0), f.path, f.line, f.rule_id))

    return AnalysisReport(
        root=target.root,
        files_scanned=files_scanned,
        analyzers_run=ran,
        analyzers_skipped=skipped,
        findings=merged,
    )
