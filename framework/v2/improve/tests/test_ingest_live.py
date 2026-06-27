"""Tests for improve.ingest_live — live blackboard/MLS -> EngagementSnapshot."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...agents.blackboard import open_blackboard
from ...agents.models import HypothesisPayload, ObservationPayload
from ...memory.store import open_store
from ..ingest_live import (
    archetype_bug_classes,
    discovered_surfaces,
    hypothesis_records,
    snapshot_from_blackboard,
)
from ..reviewer import review_snapshot

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _hyp(handle: str, bug_class: str, surface: str, status: str) -> HypothesisPayload:
    return HypothesisPayload(
        handle=handle, surface=surface, bug_class=bug_class,
        given="g", if_action="a", then_observation="t", because_model="b",
        refute_on="r", cheap_test="c", status=status,  # type: ignore[arg-type]
    )


def _post_hyp(bb: Any, slug: str, h: HypothesisPayload) -> None:
    bb.post(engagement=slug, kind="hypothesis", agent_name="hypothesis", payload=h.model_dump())


def _post_obs(bb: Any, slug: str, surface: str) -> None:
    obs = ObservationPayload(source="recon", surface=surface, summary="seen")
    bb.post(engagement=slug, kind="observation", agent_name="recon", payload=obs.model_dump())


def test_hypothesis_records_status_and_executed(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    _post_hyp(bb, "t", _hyp("H1", "IDOR", "/a", "open"))
    _post_hyp(bb, "t", _hyp("H2", "SSRF", "/b", "refuted"))
    _post_hyp(bb, "t", _hyp("H3", "SQLi", "/c", "tested"))
    records = {r.handle: r for r in hypothesis_records(bb, "t")}
    assert records["H1"].status == "open" and records["H1"].executed is False
    assert records["H2"].status == "refuted" and records["H2"].executed is True
    # tested-but-inconclusive normalizes to open status but counts as executed
    assert records["H3"].status == "open" and records["H3"].executed is True


def test_discovered_surfaces_unique(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    _post_obs(bb, "t", "/admin")
    _post_obs(bb, "t", "/admin")  # duplicate
    _post_obs(bb, "t", "/api/orders")
    assert discovered_surfaces(bb, "t") == ["/admin", "/api/orders"]


def test_archetype_bug_classes_empty_store_is_graceful(tmp_path: Path) -> None:
    store = open_store(tmp_path / "mls.sqlite")
    assert archetype_bug_classes(store, "php-smarty-smm-panel") == []


def test_snapshot_drives_reviewer(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    # H1 confirmed+executed (covered); H2 open+unexecuted (unreached).
    _post_hyp(bb, "acme", _hyp("H1", "IDOR", "/a", "confirmed"))
    _post_hyp(bb, "acme", _hyp("H2", "SSRF", "/b", "open"))
    _post_obs(bb, "acme", "/admin")  # discovered, never tested -> unreached surface

    snap = snapshot_from_blackboard(
        bb, "acme", archetype="php-smarty-smm-panel",
        extra_known_classes=["race"],  # known class never tried -> coverage gap
    )
    assert snap.slug == "acme"
    assert "race" in snap.known_archetype_bug_classes

    gaps = review_snapshot(snap, now=_NOW)
    kinds = {g.kind.value for g in gaps}
    assert "unreached_hypothesis" in kinds   # H2
    assert "unreached_surface" in kinds       # /admin
    assert "coverage_gap" in kinds            # race
