"""Tests for improve.horizon and improve.patcher."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ...common.errors import EvalError
from ..horizon import ingest_horizon, load_horizon_feed
from ..models import CapabilityGap, GapKind, HorizonItem
from ..patcher import draft_proposals, render_proposal_markdown
from ..reviewer import review_snapshot
from ..models import EngagementSnapshot, HypothesisRecord

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _item(id: str, severity: str) -> HorizonItem:
    return HorizonItem(
        id=id, source="nvd", summary=f"{id} summary", bug_class="SSRF",
        severity=severity, published_at=_NOW,
    )


# ---- horizon --------------------------------------------------------------


def test_ingest_severity_to_priority_and_order() -> None:
    gaps = ingest_horizon([_item("CVE-1", "low"), _item("CVE-2", "critical")], now=_NOW)
    assert gaps[0].title.startswith("Horizon: CVE-2")  # critical first
    assert gaps[0].priority == 95
    assert all(g.kind is GapKind.HORIZON for g in gaps)


def test_load_horizon_feed_roundtrip(tmp_path: Path) -> None:
    feed = [
        {
            "id": "CVE-2026-1", "source": "nvd", "summary": "x", "bug_class": "SSRF",
            "severity": "high", "published_at": "2026-01-01T00:00:00Z",
        }
    ]
    p = tmp_path / "feed.json"
    p.write_text(json.dumps(feed), encoding="utf-8")
    items = load_horizon_feed(p)
    assert len(items) == 1
    assert items[0].id == "CVE-2026-1"


def test_load_horizon_feed_rejects_non_array(tmp_path: Path) -> None:
    p = tmp_path / "feed.json"
    p.write_text(json.dumps({"not": "an array"}), encoding="utf-8")
    with pytest.raises(EvalError):
        load_horizon_feed(p)


# ---- patcher --------------------------------------------------------------


def _gap(kind: GapKind, **kw: object) -> CapabilityGap:
    base = dict(
        id=f"gap-{kind.value}-x", kind=kind, priority=50, title=f"{kind.value} title",
        source="t", discovered_at=_NOW,
    )
    base.update(kw)
    return CapabilityGap(**base)  # type: ignore[arg-type]


def test_draft_one_proposal_per_gap() -> None:
    gaps = [_gap(GapKind.COVERAGE_GAP, bug_class="SSRF"), _gap(GapKind.HORIZON)]
    proposals = draft_proposals(gaps, now=_NOW)
    assert len(proposals) == 2
    assert all(p.id.startswith("prop-") for p in proposals)


def test_min_priority_filter() -> None:
    gaps = [
        _gap(GapKind.COVERAGE_GAP, priority=80),
        _gap(GapKind.REFUTED_THREAD, priority=30, id="gap-refuted_thread-y"),
    ]
    proposals = draft_proposals(gaps, now=_NOW, min_priority=50)
    assert len(proposals) == 1
    assert proposals[0].title.startswith("coverage_gap")


def test_change_type_mapping() -> None:
    cov = draft_proposals([_gap(GapKind.COVERAGE_GAP, bug_class="SSRF")], now=_NOW)[0]
    assert cov.change.change_type == "add_technique"
    hor = draft_proposals([_gap(GapKind.HORIZON)], now=_NOW)[0]
    assert hor.change.change_type == "add_signature"
    code = draft_proposals([_gap(GapKind.UNREACHED_HYPOTHESIS)], now=_NOW)[0]
    assert code.change.change_type == "code_fix"


def test_proposal_is_described_only_by_default() -> None:
    p = draft_proposals([_gap(GapKind.HORIZON)], now=_NOW)[0]
    assert p.change.patch == ""
    md = render_proposal_markdown(p)
    assert "Described-only" in md
    assert "No diff was authored by SIL" in md


def test_content_digest_stable_across_status_change() -> None:
    p = draft_proposals([_gap(GapKind.HORIZON)], now=_NOW)[0]
    d1 = p.content_digest()
    from ..models import ProposalStatus

    p2 = p.model_copy(update={"status": ProposalStatus.APPROVED})
    assert p2.content_digest() == d1  # status is not part of the signed content


def test_end_to_end_review_to_proposals() -> None:
    snap = EngagementSnapshot(
        slug="acme",
        hypotheses=[HypothesisRecord(handle="H1", bug_class="IDOR", surface="/a", status="open", executed=False)],
        known_archetype_bug_classes=["SSRF"],
    )
    gaps = review_snapshot(snap, now=_NOW)
    proposals = draft_proposals(gaps, now=_NOW)
    assert len(proposals) == len(gaps) >= 2
