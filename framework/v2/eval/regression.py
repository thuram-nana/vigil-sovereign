"""
eval.regression — compare two scored runs for regression.

SIL (Pillar 3) gates a self-improvement merge on this verdict: a
candidate build must not detect fewer ground-truth findings, must not
drop precision, and must not newly-miss any specific finding the
baseline detected. The default thresholds are strict (zero tolerance);
a caller may loosen them deliberately.

"Newly missed" is the sharp signal: aggregate detection rate can hold
steady while a build trades one bug for another. A specific finding the
baseline caught and the candidate dropped is a regression even if the
totals look flat.
"""

from __future__ import annotations

from .models import EvalRun, RegressionReport


def _detected_keys(run: EvalRun) -> set[str]:
    """Set of 'slug::gt_id' detected in a run (qualified so ground-truth
    ids need only be unique within a target)."""
    keys: set[str] = set()
    for ts in run.per_target:
        for m in ts.matched:
            keys.add(f"{ts.slug}::{m.ground_truth_id}")
    return keys


def compare_runs(
    baseline: EvalRun,
    candidate: EvalRun,
    *,
    max_detection_drop: float = 0.0,
    max_precision_drop: float = 0.0,
) -> RegressionReport:
    """Build a regression verdict. `max_*_drop` are the largest tolerated
    decreases (>= 0). With both 0.0, any decrease fails."""
    if max_detection_drop < 0 or max_precision_drop < 0:
        raise ValueError("max_*_drop thresholds must be non-negative")

    det_delta = round(
        candidate.aggregate.detection_rate - baseline.aggregate.detection_rate, 6
    )
    prec_delta = round(
        candidate.aggregate.precision - baseline.aggregate.precision, 6
    )

    base_keys = _detected_keys(baseline)
    cand_keys = _detected_keys(candidate)
    newly_missed = sorted(base_keys - cand_keys)
    newly_detected = sorted(cand_keys - base_keys)

    reasons: list[str] = []
    passed = True

    if det_delta < -max_detection_drop:
        passed = False
        reasons.append(
            f"detection rate dropped by {-det_delta:.4f} "
            f"(tolerance {max_detection_drop:.4f})"
        )
    if prec_delta < -max_precision_drop:
        passed = False
        reasons.append(
            f"precision dropped by {-prec_delta:.4f} "
            f"(tolerance {max_precision_drop:.4f})"
        )
    if newly_missed:
        passed = False
        reasons.append(
            f"{len(newly_missed)} ground-truth finding(s) detected by baseline "
            f"are now missed: {newly_missed}"
        )

    if passed:
        gain = (
            f"+{det_delta:.4f} detection, +{prec_delta:.4f} precision"
            if (det_delta or prec_delta)
            else "no metric change"
        )
        reasons.append(f"no regression ({gain}); {len(newly_detected)} new detection(s)")

    return RegressionReport(
        baseline_run_id=baseline.run_id,
        candidate_run_id=candidate.run_id,
        passed=passed,
        detection_rate_delta=det_delta,
        precision_delta=prec_delta,
        newly_missed_ground_truth=newly_missed,
        newly_detected_ground_truth=newly_detected,
        reasons=reasons,
    )
