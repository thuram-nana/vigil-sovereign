"""Tests for eval.scoring — matching and per-target / run scoring."""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import (
    BenchmarkCorpus,
    BenchmarkTarget,
    GroundTruthFinding,
    ProducedFinding,
)
from ..scoring import score_run, score_target


def _gt(id: str, bug_class: str, surface: str, **kw: object) -> GroundTruthFinding:
    return GroundTruthFinding(id=id, bug_class=bug_class, surface=surface, **kw)  # type: ignore[arg-type]


def _target(*gt: GroundTruthFinding) -> BenchmarkTarget:
    return BenchmarkTarget(slug="t", name="T", ground_truth=list(gt))


def test_perfect_detection() -> None:
    target = _target(
        _gt("g1", "IDOR", "/api/orders/{id}"),
        _gt("g2", "SQLi", "/search"),
    )
    produced = [
        ProducedFinding(bug_class="IDOR", surface="/api/orders/{id}"),
        ProducedFinding(bug_class="SQLi", surface="/search"),
    ]
    s = score_target(target, produced)
    assert s.true_positives == 2
    assert s.false_positives == 0
    assert s.false_negatives == 0
    assert s.detection_rate == 1.0
    assert s.precision == 1.0
    assert s.f1 == 1.0


def test_false_negative_when_missed() -> None:
    target = _target(_gt("g1", "IDOR", "/a"), _gt("g2", "SSRF", "/b"))
    s = score_target(target, [ProducedFinding(bug_class="IDOR", surface="/a")])
    assert s.true_positives == 1
    assert s.false_negatives == 1
    assert s.missed_ground_truth_ids == ["g2"]
    assert s.detection_rate == 0.5


def test_false_positive_when_no_ground_truth() -> None:
    target = _target(_gt("g1", "IDOR", "/a"))
    produced = [
        ProducedFinding(bug_class="IDOR", surface="/a"),
        ProducedFinding(bug_class="XSS", surface="/c"),  # spurious
    ]
    s = score_target(target, produced)
    assert s.true_positives == 1
    assert s.false_positives == 1
    assert s.precision == 0.5


def test_bug_class_must_match() -> None:
    target = _target(_gt("g1", "IDOR", "/a"))
    s = score_target(target, [ProducedFinding(bug_class="SQLi", surface="/a")])
    assert s.true_positives == 0
    assert s.false_positives == 1


def test_surface_containment_matches() -> None:
    target = _target(_gt("g1", "IDOR", "/api/orders/{id}"))
    # produced surface is a superset string of the ground-truth surface
    s = score_target(
        target, [ProducedFinding(bug_class="idor", surface="GET /api/orders/{id} (BOLA)")]
    )
    assert s.true_positives == 1


def test_detection_key_matches_without_surface() -> None:
    target = _target(_gt("g1", "MassAssignment", "/profile", detection_keys=["is_admin"]))
    s = score_target(
        target,
        [ProducedFinding(bug_class="massassignment", surface="", detection_keys=["is_admin"])],
    )
    assert s.true_positives == 1


def test_duplicate_produced_is_false_positive() -> None:
    target = _target(_gt("g1", "IDOR", "/a"))
    produced = [
        ProducedFinding(bug_class="IDOR", surface="/a"),
        ProducedFinding(bug_class="IDOR", surface="/a"),  # same bug reported twice
    ]
    s = score_target(target, produced)
    assert s.true_positives == 1
    assert s.false_positives == 1


def test_normalization_ignores_formatting() -> None:
    target = _target(_gt("g1", "SQL-injection", "/x"))
    s = score_target(target, [ProducedFinding(bug_class="sql injection", surface="/x")])
    assert s.true_positives == 1


def test_score_run_missing_target_counts_as_missed() -> None:
    corpus = BenchmarkCorpus(
        name="c",
        targets=[
            BenchmarkTarget(slug="a", name="A", ground_truth=[_gt("g1", "IDOR", "/a")]),
            BenchmarkTarget(slug="b", name="B", ground_truth=[_gt("g2", "SSRF", "/b")]),
        ],
    )
    # Only target 'a' produced findings; 'b' is absent from the dict.
    run = score_run(
        run_id="r1",
        corpus=corpus,
        produced_by_slug={"a": [ProducedFinding(bug_class="IDOR", surface="/a")]},
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert run.aggregate.ground_truth_count == 2
    assert run.aggregate.true_positives == 1
    assert run.aggregate.detection_rate == 0.5
