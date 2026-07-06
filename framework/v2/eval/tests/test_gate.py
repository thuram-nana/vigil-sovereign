"""
The regression gate (A4) — zero-tolerance on CRUCIBLE accuracy regressions.

A benchmark nobody enforces rots. These tests pin the gate's asymmetry: a new
false positive, a newly-missed finding, or a precision drop FAILS; fewer FPs / more
TPs are improvements, not failures; a missing app/tool is a warning (environment
gap), never a code-regression failure.
"""

from __future__ import annotations

from framework.v2.eval.gate import Baseline, ToolScore, gate, snapshot
from framework.v2.eval.validation import MeasuredBoard, RunMetrics, Scoreboard


def _mb(tool: str, tp: int, fp: int, fn: int, target: str = "app") -> MeasuredBoard:
    return MeasuredBoard(
        scoreboard=Scoreboard(tool=tool, target=target, true_positives=tp,
                              false_positives=fp, false_negatives=fn),
        metrics=RunMetrics(tool=tool, target=target),
    )


def _baseline(tp=9, fp=0, fn=0) -> Baseline:
    return Baseline(scores={"app": {"crucible": ToolScore(tp=tp, fp=fp, fn=fn)}})


def test_gate_passes_when_candidate_matches_baseline() -> None:
    v = gate({"app": [_mb("crucible", 9, 0, 0)]}, _baseline())
    assert v.passed
    assert not v.regressions


def test_gate_fails_on_new_false_positive() -> None:
    v = gate({"app": [_mb("crucible", 9, 1, 0)]}, _baseline())
    assert not v.passed
    assert any("NEW FP" in r for r in v.regressions)


def test_gate_fails_on_newly_missed_finding() -> None:
    v = gate({"app": [_mb("crucible", 8, 0, 1)]}, _baseline())
    assert not v.passed
    assert any("NEWLY MISSED" in r for r in v.regressions)


def test_gate_fails_on_precision_drop() -> None:
    # same tp but extra fp lowers precision -> the FP check and the precision check
    # both fire; the point is: the gate fails.
    v = gate({"app": [_mb("crucible", 9, 2, 0)]}, _baseline())
    assert not v.passed
    assert any("precision" in r.lower() for r in v.regressions)


def test_fewer_fps_is_improvement_not_failure() -> None:
    v = gate({"app": [_mb("crucible", 9, 0, 0)]}, _baseline(tp=9, fp=1, fn=0))
    assert v.passed
    assert v.improvements


def test_more_tps_is_improvement_not_failure() -> None:
    v = gate({"app": [_mb("crucible", 10, 0, 0)]}, _baseline(tp=9))
    assert v.passed
    assert v.improvements


def test_missing_app_is_warning_not_failure() -> None:
    v = gate({}, _baseline())  # candidate ran nothing (e.g. Docker down)
    assert v.passed  # environment gap, not a code regression
    assert v.warnings


def test_missing_tool_is_warning_not_failure() -> None:
    v = gate({"app": [_mb("wapiti", 3, 5, 0)]}, _baseline())  # crucible didn't run
    assert v.passed
    assert any("crucible" in w for w in v.warnings)


def test_only_gated_tools_are_checked() -> None:
    # an incumbent with tons of FPs does not fail the gate (we gate CRUCIBLE only)
    results = {"app": [_mb("crucible", 9, 0, 0), _mb("wapiti", 2, 20, 5)]}
    v = gate(results, _baseline())
    assert v.passed


def test_snapshot_roundtrips_and_gates_clean(tmp_path) -> None:
    results = {"app": [_mb("crucible", 9, 0, 0)]}
    bl = snapshot(results, label="x")
    p = bl.dump(tmp_path / "b.json")
    reloaded = Baseline.load(p)
    assert reloaded.scores["app"]["crucible"].tp == 9
    assert gate(results, reloaded).passed
