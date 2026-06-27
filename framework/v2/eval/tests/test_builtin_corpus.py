"""The shipped starter corpus loads, validates, and drives the harness."""

from __future__ import annotations

from datetime import datetime, timezone

from ..corpus import builtin_corpus
from ..models import BenchmarkTarget, ProducedFinding
from ..regression import compare_runs
from ..scoring import score_run

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_builtin_corpus_loads_and_validates() -> None:
    corpus = builtin_corpus()
    assert corpus.name == "crucible-starter"
    assert len(corpus.targets) == 3
    assert corpus.total_ground_truth() == 9


def _perfect_producer(target: BenchmarkTarget) -> list[ProducedFinding]:
    return [
        ProducedFinding(bug_class=g.bug_class, surface=g.surface, detection_keys=g.detection_keys)
        for g in target.ground_truth
    ]


def test_perfect_producer_scores_full_detection() -> None:
    corpus = builtin_corpus()
    produced = {t.slug: _perfect_producer(t) for t in corpus.targets}
    run = score_run(run_id="perfect", corpus=corpus, produced_by_slug=produced, created_at=_NOW)
    assert run.aggregate.detection_rate == 1.0
    assert run.aggregate.false_positives == 0


def test_empty_producer_scores_zero() -> None:
    corpus = builtin_corpus()
    run = score_run(run_id="empty", corpus=corpus, produced_by_slug={}, created_at=_NOW)
    assert run.aggregate.detection_rate == 0.0


def test_regression_gate_on_builtin_corpus() -> None:
    corpus = builtin_corpus()
    full = {t.slug: _perfect_producer(t) for t in corpus.targets}
    baseline = score_run(run_id="base", corpus=corpus, produced_by_slug=full, created_at=_NOW)

    # Candidate drops the SQLi detection on the marketplace target.
    degraded = {t.slug: _perfect_producer(t) for t in corpus.targets}
    degraded["synthetic-rails-marketplace"] = [
        f for f in degraded["synthetic-rails-marketplace"] if f.bug_class != "SQLi"
    ]
    candidate = score_run(run_id="cand", corpus=corpus, produced_by_slug=degraded, created_at=_NOW)

    report = compare_runs(baseline, candidate)
    assert report.passed is False
    assert "synthetic-rails-marketplace::sqli-search" in report.newly_missed_ground_truth
