"""Tests for eval.regression — the SIL merge-gate verdict."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ..models import (
    BenchmarkCorpus,
    BenchmarkTarget,
    GroundTruthFinding,
    ProducedFinding,
)
from ..regression import compare_runs
from ..scoring import score_run

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _corpus() -> BenchmarkCorpus:
    return BenchmarkCorpus(
        name="c",
        targets=[
            BenchmarkTarget(
                slug="t",
                name="T",
                ground_truth=[
                    GroundTruthFinding(id="g1", bug_class="IDOR", surface="/a"),
                    GroundTruthFinding(id="g2", bug_class="SSRF", surface="/b"),
                ],
            )
        ],
    )


def _run(run_id: str, produced: list[ProducedFinding]) -> object:
    return score_run(
        run_id=run_id, corpus=_corpus(), produced_by_slug={"t": produced}, created_at=_NOW
    )


def test_no_regression_when_identical() -> None:
    p = [ProducedFinding(bug_class="IDOR", surface="/a")]
    report = compare_runs(_run("base", p), _run("cand", p))
    assert report.passed is True
    assert report.detection_rate_delta == 0.0


def test_improvement_passes() -> None:
    base = _run("base", [ProducedFinding(bug_class="IDOR", surface="/a")])
    cand = _run(
        "cand",
        [
            ProducedFinding(bug_class="IDOR", surface="/a"),
            ProducedFinding(bug_class="SSRF", surface="/b"),
        ],
    )
    report = compare_runs(base, cand)
    assert report.passed is True
    assert report.detection_rate_delta == 0.5
    assert "t::g2" in report.newly_detected_ground_truth


def test_detection_drop_fails() -> None:
    base = _run(
        "base",
        [
            ProducedFinding(bug_class="IDOR", surface="/a"),
            ProducedFinding(bug_class="SSRF", surface="/b"),
        ],
    )
    cand = _run("cand", [ProducedFinding(bug_class="IDOR", surface="/a")])
    report = compare_runs(base, cand)
    assert report.passed is False
    assert report.newly_missed_ground_truth == ["t::g2"]
    assert report.detection_rate_delta == -0.5


def test_traded_finding_fails_even_if_aggregate_flat() -> None:
    # Baseline detects g1; candidate detects g2 instead. Aggregate
    # detection rate is identical (0.5) but a specific finding regressed.
    base = _run("base", [ProducedFinding(bug_class="IDOR", surface="/a")])
    cand = _run("cand", [ProducedFinding(bug_class="SSRF", surface="/b")])
    report = compare_runs(base, cand)
    assert report.detection_rate_delta == 0.0
    assert report.passed is False
    assert report.newly_missed_ground_truth == ["t::g1"]
    assert report.newly_detected_ground_truth == ["t::g2"]


def test_tolerance_allows_small_drop() -> None:
    base = _run(
        "base",
        [
            ProducedFinding(bug_class="IDOR", surface="/a"),
            ProducedFinding(bug_class="SSRF", surface="/b"),
        ],
    )
    cand = _run("cand", [ProducedFinding(bug_class="IDOR", surface="/a")])
    # Even with a generous detection tolerance, the specific newly-missed
    # finding still fails the gate — that signal is not tolerance-gated.
    report = compare_runs(base, cand, max_detection_drop=1.0)
    assert report.passed is False
    assert report.newly_missed_ground_truth == ["t::g2"]


def test_precision_drop_fails() -> None:
    # Same detection, but candidate adds a false positive -> precision drop.
    base = _run("base", [ProducedFinding(bug_class="IDOR", surface="/a")])
    cand = _run(
        "cand",
        [
            ProducedFinding(bug_class="IDOR", surface="/a"),
            ProducedFinding(bug_class="XSS", surface="/z"),  # FP
        ],
    )
    report = compare_runs(base, cand)
    assert report.precision_delta < 0
    assert report.passed is False


def test_negative_tolerance_rejected() -> None:
    p = [ProducedFinding(bug_class="IDOR", surface="/a")]
    with pytest.raises(ValueError):
        compare_runs(_run("b", p), _run("c", p), max_detection_drop=-0.1)
