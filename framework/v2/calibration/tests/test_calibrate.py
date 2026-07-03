"""Tests for calibration.calibrate — PAV, ECE improvement, fallback, oracle prior."""

from __future__ import annotations

from ..calibrate import (
    MAX_PROB,
    Calibrator,
    brier_score,
    fit,
    measure_ece,
    pav,
    reliability_report,
)
from ..models import Outcome, OutcomeLabel, Prediction


# ---------------------------------------------------------------------------
# Deterministic synthetic ledgers
# ---------------------------------------------------------------------------


def _pair(fid, score, label, oracle=False):
    return (
        Prediction(finding_id=fid, raw_score=score, feature_hash="h",
                   model_version="v1", oracle_confirmed=oracle),
        Outcome(finding_id=fid, label=label),
    )


def _skewed_pairs():
    """Monotone but badly *overconfident* scores: at raw score s the true
    exploitable-rate is far lower. Isotonic should pull each score down toward
    its observed rate, improving ECE. Fully deterministic — no randomness."""
    # raw score -> (n_total, n_exploitable)
    groups = {
        0.20: (10, 0),   # true rate 0.0
        0.40: (10, 1),   # true rate 0.1
        0.60: (10, 3),   # true rate 0.3
        0.80: (10, 5),   # true rate 0.5
        0.95: (10, 7),   # true rate 0.7
    }
    pairs = []
    i = 0
    for score, (n, k) in groups.items():
        for j in range(n):
            label = OutcomeLabel.EXPLOITABLE if j < k else OutcomeLabel.FALSE_POSITIVE
            pairs.append(_pair(f"f{i}", score, label))
            i += 1
    return pairs


# ---------------------------------------------------------------------------
# PAV
# ---------------------------------------------------------------------------


def test_pav_output_is_non_decreasing() -> None:
    ys = [0.5, 0.1, 0.9, 0.2, 0.8, 0.0]
    ws = [1.0] * len(ys)
    fitted = pav(ys, ws)
    assert len(fitted) == len(ys)
    assert all(fitted[i] <= fitted[i + 1] + 1e-12 for i in range(len(fitted) - 1))


def test_pav_already_monotone_is_unchanged() -> None:
    ys = [0.0, 0.2, 0.4, 0.6, 1.0]
    fitted = pav(ys, [1.0] * len(ys))
    assert fitted == ys


def test_pav_pools_to_weighted_mean() -> None:
    # Two violating points pool to their mean.
    fitted = pav([1.0, 0.0], [1.0, 1.0])
    assert fitted == [0.5, 0.5]


# ---------------------------------------------------------------------------
# Calibrate monotonicity
# ---------------------------------------------------------------------------


def test_calibrate_is_monotone_in_score() -> None:
    cal = fit(_skewed_pairs())
    assert cal.method == "isotonic"
    xs = [i / 100 for i in range(101)]
    ys = [cal.calibrate(x) for x in xs]
    assert all(ys[i] <= ys[i + 1] + 1e-12 for i in range(len(ys) - 1))


def test_calibrate_maps_threshold_to_observed_rate() -> None:
    cal = fit(_skewed_pairs())
    # At raw 0.95 the observed rate was 0.7, not 0.95.
    assert abs(cal.calibrate(0.95) - 0.7) < 1e-9
    assert abs(cal.calibrate(0.20) - 0.0) < 1e-9


# ---------------------------------------------------------------------------
# ECE / Brier improvement
# ---------------------------------------------------------------------------


def test_ece_improves_after_calibration() -> None:
    pairs = _skewed_pairs()
    cal = fit(pairs)
    ece_raw = measure_ece(pairs, None)
    ece_cal = measure_ece(pairs, cal)
    assert ece_cal < ece_raw
    # The overconfident raw scores are meaningfully miscalibrated...
    assert ece_raw > 0.2
    # ...and calibration nearly eliminates it.
    assert ece_cal < 0.05


def test_brier_improves_after_calibration() -> None:
    pairs = _skewed_pairs()
    cal = fit(pairs)
    assert brier_score(pairs, cal) < brier_score(pairs, None)


def test_reliability_report_shape() -> None:
    pairs = _skewed_pairs()
    rep = reliability_report(pairs, None, n_bins=10)
    assert rep.n == len(pairs)
    assert len(rep.bins) == 10
    # bin gaps count-weighted reproduce the reported ECE
    total = sum(b.count for b in rep.bins)
    recomputed = sum((b.count / total) * b.gap for b in rep.bins)
    assert abs(recomputed - rep.ece) < 1e-9


# ---------------------------------------------------------------------------
# Identity fallback under sparse data
# ---------------------------------------------------------------------------


def test_identity_fallback_under_sparse_data() -> None:
    pairs = [_pair("f0", 0.9, OutcomeLabel.EXPLOITABLE),
             _pair("f1", 0.1, OutcomeLabel.FALSE_POSITIVE)]
    cal = fit(pairs)
    assert cal.method == "identity"
    # Passthrough: calibrate == score.
    for s in (0.0, 0.3, 0.77, 1.0):
        assert cal.calibrate(s) == s
    # Oracle confirmation gives no invented boost under sparse data.
    assert cal.calibrate(0.5, oracle_confirmed=True) == 0.5


def test_disputed_outcomes_excluded_from_label_count() -> None:
    # 7 real labels + many DISPUTED -> still below MIN_LABELS(8) -> identity.
    pairs = [_pair(f"e{i}", 0.5, OutcomeLabel.EXPLOITABLE) for i in range(7)]
    pairs += [_pair(f"d{i}", 0.5, OutcomeLabel.DISPUTED) for i in range(50)]
    cal = fit(pairs)
    assert cal.method == "identity"
    assert cal.n_labels == 7


# ---------------------------------------------------------------------------
# Oracle prior — learned, never hardcoded 1.0
# ---------------------------------------------------------------------------


def test_oracle_prior_is_learned_from_outcomes() -> None:
    pairs = _skewed_pairs()
    # Add oracle-confirmed findings that are only 80% exploitable — the old
    # code would have called every one of these 1.0.
    for i in range(10):
        label = OutcomeLabel.EXPLOITABLE if i < 8 else OutcomeLabel.FALSE_POSITIVE
        pairs.append(_pair(f"o{i}", 0.5, label, oracle=True))
    cal = fit(pairs)
    assert cal.oracle_prior is not None
    assert abs(cal.oracle_prior - 0.8) < 1e-9


def test_oracle_confirmation_boosts_but_never_certain() -> None:
    pairs = _skewed_pairs()
    for i in range(10):
        label = OutcomeLabel.EXPLOITABLE if i < 8 else OutcomeLabel.FALSE_POSITIVE
        pairs.append(_pair(f"o{i}", 0.5, label, oracle=True))
    cal = fit(pairs)
    base = cal.calibrate(0.6, oracle_confirmed=False)
    boosted = cal.calibrate(0.6, oracle_confirmed=True)
    assert boosted > base            # confirmation raises confidence...
    assert boosted <= MAX_PROB       # ...but never claims certainty (no 1.0).
    assert boosted < 1.0


def test_no_oracle_prior_when_too_few_oracle_labels() -> None:
    pairs = _skewed_pairs()  # zero oracle-confirmed samples
    cal = fit(pairs)
    assert cal.oracle_prior is None
    # With no learned prior, confirmation cannot boost.
    assert cal.calibrate(0.6, oracle_confirmed=True) == cal.calibrate(0.6, False)


def test_calibrator_json_round_trip() -> None:
    cal = fit(_skewed_pairs())
    cal2 = Calibrator.model_validate_json(cal.model_dump_json())
    assert cal2.method == "isotonic"
    assert cal2.calibrate(0.8) == cal.calibrate(0.8)
