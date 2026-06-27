"""Tests for improve.reviewer — deterministic gap mining."""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import EngagementSnapshot, GapKind, HypothesisRecord
from ..reviewer import review_snapshot

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _kinds(gaps: list) -> set[GapKind]:
    return {g.kind for g in gaps}


def test_coverage_gap_for_untested_known_class() -> None:
    snap = EngagementSnapshot(
        slug="t",
        archetype="php-smarty-smm-panel",
        hypotheses=[HypothesisRecord(handle="H1", bug_class="IDOR", surface="/a", status="confirmed", executed=True)],
        known_archetype_bug_classes=["IDOR", "SSRF", "race"],
    )
    gaps = review_snapshot(snap, now=_NOW)
    coverage = [g for g in gaps if g.kind is GapKind.COVERAGE_GAP]
    classes = {g.bug_class for g in coverage}
    assert classes == {"SSRF", "race"}  # IDOR was tried, so not a gap


def test_unreached_surface() -> None:
    snap = EngagementSnapshot(
        slug="t",
        hypotheses=[HypothesisRecord(handle="H1", bug_class="IDOR", surface="/api/orders", status="open", executed=True)],
        discovered_surfaces=["/api/orders", "/admin/config"],
    )
    gaps = review_snapshot(snap, now=_NOW)
    surfaces = {g.surface for g in gaps if g.kind is GapKind.UNREACHED_SURFACE}
    assert surfaces == {"/admin/config"}


def test_unreached_hypothesis() -> None:
    snap = EngagementSnapshot(
        slug="t",
        hypotheses=[
            HypothesisRecord(handle="H1", bug_class="SSRF", surface="/x", status="open", executed=False),
            HypothesisRecord(handle="H2", bug_class="IDOR", surface="/y", status="confirmed", executed=True),
        ],
    )
    gaps = review_snapshot(snap, now=_NOW)
    unreached = [g for g in gaps if g.kind is GapKind.UNREACHED_HYPOTHESIS]
    assert len(unreached) == 1
    assert unreached[0].title.endswith("H1")


def test_refuted_thread() -> None:
    snap = EngagementSnapshot(
        slug="t",
        hypotheses=[HypothesisRecord(handle="H9", bug_class="SQLi", surface="/s", status="refuted", executed=True)],
    )
    gaps = review_snapshot(snap, now=_NOW)
    assert GapKind.REFUTED_THREAD in _kinds(gaps)


def test_no_gaps_when_fully_covered() -> None:
    snap = EngagementSnapshot(
        slug="t",
        hypotheses=[
            HypothesisRecord(handle="H1", bug_class="IDOR", surface="/a", status="confirmed", executed=True),
        ],
        discovered_surfaces=["/a"],
        known_archetype_bug_classes=["IDOR"],
    )
    gaps = review_snapshot(snap, now=_NOW)
    assert gaps == []


def test_determinism_stable_ids() -> None:
    snap = EngagementSnapshot(
        slug="t",
        hypotheses=[HypothesisRecord(handle="H1", bug_class="SSRF", surface="/x", status="open", executed=False)],
        known_archetype_bug_classes=["race"],
    )
    a = review_snapshot(snap, now=_NOW)
    b = review_snapshot(snap, now=_NOW)
    assert [g.id for g in a] == [g.id for g in b]


def test_priority_ordering_descending() -> None:
    snap = EngagementSnapshot(
        slug="t",
        hypotheses=[HypothesisRecord(handle="H1", bug_class="SQLi", surface="/s", status="refuted", executed=True)],
        known_archetype_bug_classes=["SSRF"],  # coverage gap (priority 80) > refuted (30)
    )
    gaps = review_snapshot(snap, now=_NOW)
    priorities = [g.priority for g in gaps]
    assert priorities == sorted(priorities, reverse=True)
    assert gaps[0].kind is GapKind.COVERAGE_GAP
