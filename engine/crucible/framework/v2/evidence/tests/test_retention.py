"""Tests for evidence.retention — the read-only keep-set analyzer (V13 phase 1).

Hermetic: every case builds a synthetic ``targets/`` tree in a tmp dir and passes it to
``analyze_retention`` explicitly, so nothing depends on CRUCIBLE_ROOT or a real engagement.
The analyzer must never delete or write anything — these tests only read back a classification.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.evidence.retention import analyze_engagement, analyze_retention


def _write(p: Path, data: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _engagement(root: Path, slug: str, *, report_findings: list[dict] | None, action_dirs: dict[str, int]) -> None:
    """Create targets/<slug> with an optional report snapshot and evidence/<action_id>/body of N bytes."""
    tdir = root / slug
    tdir.mkdir(parents=True, exist_ok=True)
    if report_findings is not None:
        (tdir / f"{slug}.report.json").write_text(
            json.dumps({"active_findings": report_findings}), encoding="utf-8")
    for aid, nbytes in action_dirs.items():
        _write(tdir / "evidence" / aid / "response.body", b"x" * nbytes)


def test_orphan_evidence_is_a_sweep_candidate_backed_evidence_is_kept(tmp_path: Path) -> None:
    root = tmp_path / "targets"
    _engagement(
        root, "alpha",
        report_findings=[{"action_id": "a1", "check_id": "sqli"}],   # a1 backs a finding
        action_dirs={"a1": 10, "a2": 20, "a3": 30},                  # a2, a3 are orphan scan traffic
    )
    eng = analyze_engagement("alpha", targets_root=root)
    assert eng.report_present is True
    assert eng.keep_action_ids == {"a1"}
    assert eng.keep_dirs == ["a1"]
    assert eng.sweep_candidate_dirs == ["a2", "a3"]
    assert eng.keep_bytes == 10
    assert eng.sweep_candidate_bytes == 50
    assert eng.total_action_dirs == 3


def test_missing_report_keeps_everything_fail_safe(tmp_path: Path) -> None:
    root = tmp_path / "targets"
    _engagement(root, "beta", report_findings=None, action_dirs={"b1": 5, "b2": 7})
    eng = analyze_engagement("beta", targets_root=root)
    assert eng.report_present is False
    assert eng.sweep_candidate_dirs == []          # nothing is swept without a keep-set
    assert eng.keep_dirs == ["b1", "b2"]
    assert eng.sweep_candidate_bytes == 0
    assert eng.keep_bytes == 12


def test_multiple_findings_and_repo_totals(tmp_path: Path) -> None:
    root = tmp_path / "targets"
    _engagement(
        root, "alpha",
        report_findings=[{"action_id": "a1"}, {"action_id": "a2"}],  # two backed dirs
        action_dirs={"a1": 1, "a2": 1, "a3": 100},                   # a3 orphan
    )
    _engagement(root, "beta", report_findings=[], action_dirs={"b1": 40})  # report present, no findings -> b1 orphan
    (root / "_template").mkdir(parents=True, exist_ok=True)                 # must be skipped
    rep = analyze_retention(targets_root=root)
    by_slug = {e.slug: e for e in rep.engagements}
    assert set(by_slug) == {"alpha", "beta"}                        # _template excluded
    assert by_slug["alpha"].sweep_candidate_dirs == ["a3"]
    assert by_slug["beta"].report_present is True
    assert by_slug["beta"].sweep_candidate_dirs == ["b1"]           # present-but-empty report keeps nothing
    assert rep.total_sweep_candidate_dirs == 2
    assert rep.total_sweep_candidate_bytes == 140
    assert rep.total_keep_dirs == 2


def test_analyzer_deletes_nothing(tmp_path: Path) -> None:
    root = tmp_path / "targets"
    _engagement(root, "alpha", report_findings=[{"action_id": "a1"}], action_dirs={"a1": 3, "a2": 4})
    before = sorted(p for p in (root / "alpha" / "evidence").rglob("*"))
    analyze_retention(targets_root=root)
    after = sorted(p for p in (root / "alpha" / "evidence").rglob("*"))
    assert before == after and len(before) > 0     # every evidence file still present after analysis


def test_empty_or_absent_targets_root_is_empty_report(tmp_path: Path) -> None:
    assert analyze_retention(targets_root=tmp_path / "does-not-exist").engagements == []
    (tmp_path / "empty").mkdir()
    assert analyze_retention(targets_root=tmp_path / "empty").engagements == []
