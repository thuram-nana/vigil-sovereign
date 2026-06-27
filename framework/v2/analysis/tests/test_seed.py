"""Tests for analysis.seed — DAA findings -> blackboard hypotheses."""

from __future__ import annotations

from pathlib import Path

from ...agents.blackboard import open_blackboard
from ...agents.models import HypothesisPayload
from ..analyzers.builtin import PatternAnalyzer
from ..models import AnalysisFinding, AnalysisReport, AnalysisTarget
from ..seed import (
    DaaHypothesisSeeder,
    post_seeds,
    seed_from_finding,
    seeds_from_analysis,
)


def _finding(rule_id: str, severity: str, **kw: object) -> AnalysisFinding:
    base = dict(
        analyzer="pattern", rule_id=rule_id, severity=severity,
        path="app/views.py", line=42, message="dangerous sink",
    )
    base.update(kw)
    return AnalysisFinding(**base)  # type: ignore[arg-type]


def _report(*findings: AnalysisFinding) -> AnalysisReport:
    return AnalysisReport(root=".", files_scanned=1, analyzers_run=["pattern"], findings=list(findings))


def test_seed_from_finding_shape() -> None:
    seed = seed_from_finding(_finding("DAA-SHELL-TRUE", "high"), "DAA-001")
    assert seed.bug_class == "OS Command Injection"
    assert seed.surface == "app/views.py:42"
    assert seed.status == "open"
    assert 0.0 < seed.confidence <= 1.0
    # It is a valid blackboard hypothesis payload.
    assert HypothesisPayload.model_validate(seed.model_dump())


def test_bug_class_fallback_to_cwe() -> None:
    seed = seed_from_finding(_finding("semgrep.some-rule", "high", analyzer="semgrep", cwe="CWE-89"), "X")
    assert seed.bug_class == "CWE-89"


def test_severity_filter_and_handles() -> None:
    report = _report(
        _finding("DAA-EVAL", "high", line=1),
        _finding("DAA-DEBUG-TRUE", "low", line=2),
        _finding("DAA-WEAK-HASH", "low", line=3),
    )
    seeds = seeds_from_analysis(report, min_severity="medium")
    assert [s.handle for s in seeds] == ["DAA-001"]   # only the high finding
    assert seeds[0].bug_class == "Code Injection"


def test_low_threshold_includes_all() -> None:
    report = _report(_finding("DAA-EVAL", "high", line=1), _finding("DAA-DEBUG-TRUE", "low", line=2))
    seeds = seeds_from_analysis(report, min_severity="low")
    assert len(seeds) == 2


def test_post_seeds_lands_open_hypotheses(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    seeds = seeds_from_analysis(_report(_finding("DAA-EVAL", "high")), min_severity="medium")
    ids = post_seeds(bb, "acme", seeds)
    assert len(ids) == 1
    rows = bb.read(engagement="acme", kinds=["hypothesis"])
    assert len(rows) == 1
    assert rows[0].payload["status"] == "open"
    assert rows[0].agent_name == "daa"


def test_seeder_runs_analysis_and_posts(tmp_path: Path, planted_tree: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")

    def analyze() -> AnalysisReport:
        findings = PatternAnalyzer().analyze(AnalysisTarget(root=str(planted_tree)))
        return AnalysisReport(
            root=str(planted_tree), files_scanned=2, analyzers_run=["pattern"], findings=findings
        )

    seeder = DaaHypothesisSeeder(bb, analyze, min_severity="high")
    ids = seeder.seed("acme")
    assert ids  # the planted eval()/shell=True/secret findings seeded hypotheses
    rows = bb.read(engagement="acme", kinds=["hypothesis"])
    bug_classes = {r.payload["bug_class"] for r in rows}
    assert "OS Command Injection" in bug_classes or "Code Injection" in bug_classes
