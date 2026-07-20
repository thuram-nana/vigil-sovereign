"""Tests for the DAA orchestrator — merging, skipping, gating."""

from __future__ import annotations

from pathlib import Path

import pytest

from ...common.errors import BackendError, EntitlementViolation
from ...entitlement import policy as ent_policy
from ..analyzers.builtin import PatternAnalyzer
from ..models import AnalysisFinding, AnalysisTarget
from ..orchestrator import run_analysis


class _UnavailableAnalyzer:
    name = "fake-unavailable"

    def is_available(self) -> tuple[bool, str]:
        return False, "not installed"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        raise AssertionError("must not be called when unavailable")


class _ErroringAnalyzer:
    name = "fake-erroring"

    def is_available(self) -> tuple[bool, str]:
        return True, "ok"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        raise BackendError("boom")


def test_run_with_builtin_only(planted_tree: Path) -> None:
    report = run_analysis(
        AnalysisTarget(root=str(planted_tree)), analyzers=[PatternAnalyzer()]
    )
    assert "pattern" in report.analyzers_run
    assert report.files_scanned >= 2
    assert any(f.rule_id == "DAA-EVAL" for f in report.findings)


def test_findings_sorted_by_severity(planted_tree: Path) -> None:
    report = run_analysis(
        AnalysisTarget(root=str(planted_tree)), analyzers=[PatternAnalyzer()]
    )
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    seq = [ranks[f.severity] for f in report.findings]
    assert seq == sorted(seq, reverse=True)


def test_unavailable_analyzer_is_skipped(planted_tree: Path) -> None:
    report = run_analysis(
        AnalysisTarget(root=str(planted_tree)),
        analyzers=[PatternAnalyzer(), _UnavailableAnalyzer()],
    )
    skipped = {s.name for s in report.analyzers_skipped}
    assert "fake-unavailable" in skipped
    assert "pattern" in report.analyzers_run


def test_erroring_analyzer_is_skipped_not_fatal(planted_tree: Path) -> None:
    report = run_analysis(
        AnalysisTarget(root=str(planted_tree)),
        analyzers=[PatternAnalyzer(), _ErroringAnalyzer()],
    )
    skipped = {s.name for s in report.analyzers_skipped}
    assert "fake-erroring" in skipped
    # The good analyzer's findings still made it into the report.
    assert report.findings


def test_dedup_across_analyzers(planted_tree: Path) -> None:
    # Two pattern analyzers produce identical findings; dedup collapses them.
    report = run_analysis(
        AnalysisTarget(root=str(planted_tree)),
        analyzers=[PatternAnalyzer(), PatternAnalyzer()],
    )
    keys = [f.dedup_key() for f in report.findings]
    assert len(keys) == len(set(keys))


def test_gated_under_enforcement(planted_tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    ent_policy.reset_policy()
    with pytest.raises(EntitlementViolation):
        run_analysis(AnalysisTarget(root=str(planted_tree)), analyzers=[PatternAnalyzer()])
