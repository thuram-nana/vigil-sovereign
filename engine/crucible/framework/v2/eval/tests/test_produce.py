"""Tests for eval.produce — the live blackboard -> harness adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ...agents.blackboard import open_blackboard
from ...agents.models import FindingPayload
from ..harness import run_harness
from ..models import BenchmarkCorpus, BenchmarkTarget, GroundTruthFinding
from ..produce import BlackboardFindingProducer, map_finding, map_findings

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _finding(status: str, **kw: object) -> FindingPayload:
    base = dict(
        finding_slug="001-idor",
        title="IDOR on orders",
        severity="High",
        bug_class="IDOR",
        surface="/api/orders/{id}",
        summary="Any user can read any order",
        critique_status=status,
    )
    base.update(kw)
    return FindingPayload.model_validate(base)


def test_map_finding_confidence_by_status() -> None:
    # "confirmed" is the honest prior 0.9, never a false certainty of 1.0
    # (no map_finding path emits 1.0); a calibrator learns the real number.
    assert map_finding(_finding("confirmed")).confidence == 0.9
    assert map_finding(_finding("pending")).confidence == 0.6
    assert map_finding(_finding("objections")).confidence == 0.2


def test_map_finding_carries_hypothesis_as_detection_key() -> None:
    pf = map_finding(_finding("confirmed", derived_from_hypothesis="H-007"))
    assert pf.detection_keys == ["H-007"]
    assert pf.bug_class == "IDOR"
    assert pf.surface == "/api/orders/{id}"


def test_map_findings_confirmed_only_filter() -> None:
    findings = [_finding("confirmed"), _finding("pending"), _finding("objections")]
    assert len(map_findings(findings)) == 1                      # default confirmed-only
    assert len(map_findings(findings, confirmed_only=False)) == 3


def _post_finding(bb: object, slug: str, payload: FindingPayload) -> None:
    bb.post(  # type: ignore[attr-defined]
        engagement=slug, kind="finding", agent_name="exploit",
        payload=payload.model_dump(),
    )


def test_producer_reads_confirmed_findings(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    _post_finding(bb, "acme-shop", _finding("confirmed"))
    _post_finding(bb, "acme-shop", _finding("pending", finding_slug="002-ssrf",
                                            bug_class="SSRF", surface="/webhook"))

    producer = BlackboardFindingProducer(bb)
    target = BenchmarkTarget(slug="acme-shop", name="Acme")
    produced = producer(target)

    # Only the confirmed IDOR finding is produced (pending SSRF filtered out).
    assert len(produced) == 1
    assert produced[0].bug_class == "IDOR"


def test_producer_missing_engagement_is_empty(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    producer = BlackboardFindingProducer(bb)
    assert producer(BenchmarkTarget(slug="never-engaged", name="X")) == []


def test_producer_drives_harness_end_to_end(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    _post_finding(bb, "acme-shop", _finding("confirmed"))

    corpus = BenchmarkCorpus(
        name="c",
        targets=[
            BenchmarkTarget(
                slug="acme-shop",
                name="Acme",
                ground_truth=[
                    GroundTruthFinding(id="g1", bug_class="IDOR", surface="/api/orders/{id}"),
                    GroundTruthFinding(id="g2", bug_class="SSRF", surface="/webhook"),
                ],
            )
        ],
    )
    run = run_harness(corpus, BlackboardFindingProducer(bb), run_id="live-1", created_at=_NOW)
    # The confirmed IDOR is rediscovered; the SSRF (never found) is missed.
    assert run.aggregate.true_positives == 1
    assert run.aggregate.detection_rate == 0.5
    assert run.per_target[0].missed_ground_truth_ids == ["g2"]
