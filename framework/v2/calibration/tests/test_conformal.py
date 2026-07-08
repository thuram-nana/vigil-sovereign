"""
Anti-hallucination P7 — conformal coverage bands, honestly gated.

A point posterior does not say how often reality lands near it. Split-conformal turns the
ledger's labelled outcomes into a marginal (1−α) coverage band — but ONLY when enough labels
back it. Under MIN_LABELS it must NOT fabricate a guarantee; it falls back to the Bayesian
credible interval and says so. The load-bearing test is exactly that gate.
"""

from __future__ import annotations

from framework.v2.calibration.calibrate import MIN_LABELS
from framework.v2.calibration.conformal import (
    ConformalBand,
    band_for_prediction,
    conformal_band,
    conformal_halfwidth,
)
from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction


def _pair(fid: str, score: float, label: OutcomeLabel, oracle: bool = False):
    return (Prediction(finding_id=fid, raw_score=score, feature_hash="h",
                       model_version="v1", oracle_confirmed=oracle),
            Outcome(finding_id=fid, label=label))


def _well_separated(n_each: int = 5):
    """n_each exploitable at high scores + n_each false-positive at low scores — a set an
    isotonic fit models well, so nonconformity is small and the band is non-trivial."""
    hi = [0.80, 0.85, 0.90, 0.95, 0.88, 0.82, 0.91]
    lo = [0.10, 0.15, 0.05, 0.20, 0.12, 0.08, 0.18]
    pairs = []
    for i in range(n_each):
        pairs.append(_pair(f"pos-{i}", hi[i % len(hi)], OutcomeLabel.EXPLOITABLE))
        pairs.append(_pair(f"neg-{i}", lo[i % len(lo)], OutcomeLabel.FALSE_POSITIVE))
    return pairs


# ---- the finite-sample quantile --------------------------------------------


def test_conformal_halfwidth_quantile_and_edges() -> None:
    assert conformal_halfwidth([], 0.1) == 1.0                       # no data → widest
    scores = [0.1, 0.2, 0.3, 0.4, 0.5]
    assert conformal_halfwidth(scores, 0.5) == 0.3                   # k=ceil(6*.5)=3 → 3rd
    assert conformal_halfwidth(scores, 0.2) == 0.5                   # k=ceil(6*.8)=5 → 5th
    assert conformal_halfwidth(scores, 0.01) == 1.0                  # k>n → widest (honest)


# ---- the HONEST GATE: fallback under sparse labels --------------------------


def test_falls_back_to_bayesian_band_under_min_labels() -> None:
    pairs = [_pair(f"f{i}", 0.6, OutcomeLabel.EXPLOITABLE) for i in range(MIN_LABELS - 1)]
    band = conformal_band(0.7, pairs, alpha=0.1, fallback=(0.55, 0.85))
    assert band.method == "bayesian_fallback" and band.coverage_guaranteed is False
    assert (band.lower, band.upper) == (0.55, 0.85)                  # the Bayesian interval, verbatim
    assert "no conformal coverage guarantee" in band.note and band.n_labels == MIN_LABELS - 1


def test_disputed_labels_do_not_count_toward_the_gate() -> None:
    # DISPUTED outcomes have target None → excluded → still below the gate → fallback.
    pairs = ([_pair(f"d{i}", 0.6, OutcomeLabel.DISPUTED) for i in range(20)]
             + [_pair(f"e{i}", 0.7, OutcomeLabel.EXPLOITABLE) for i in range(3)])
    band = conformal_band(0.7, pairs, alpha=0.1, fallback=(0.5, 0.9))
    assert band.coverage_guaranteed is False and band.n_labels == 3   # only the 3 real labels count


# ---- a genuine conformal band when the labels back it -----------------------


def test_conformal_band_when_enough_labels() -> None:
    band = conformal_band(0.9, _well_separated(5), alpha=0.2)         # 10 labels ≥ MIN_LABELS
    assert isinstance(band, ConformalBand)
    assert band.method == "split_conformal" and band.coverage_guaranteed is True
    assert band.coverage == 0.8 and band.n_labels == 10
    assert band.lower <= 0.9 <= band.upper                           # brackets the point
    assert (band.upper - band.lower) < 2.0 and 0.0 <= band.lower and band.upper <= 1.0
    # a well-separated set fits tightly → the band is non-trivial (not the whole [0,1])
    assert (band.upper - band.lower) < 1.0


def test_band_widens_as_alpha_shrinks() -> None:
    pairs = _well_separated(6)   # 12 labels
    wide = conformal_band(0.5, pairs, alpha=0.05)
    narrow = conformal_band(0.5, pairs, alpha=0.4)
    assert (wide.upper - wide.lower) >= (narrow.upper - narrow.lower)  # higher coverage → wider


# ---- prediction integration: the band centres on the SAME estimator as q ----


def test_band_for_prediction_centres_on_the_querys_own_estimate() -> None:
    # the query's raw_score IS f(query) — the estimator whose residuals set q — so the
    # (1-alpha) guarantee genuinely transfers to the emitted band (the review fix).
    query = Prediction(finding_id="q", raw_score=0.75, feature_hash="h",
                       model_version="v1", oracle_confirmed=False)
    rich = band_for_prediction(query, _well_separated(5), alpha=0.2)
    assert rich.method == "split_conformal" and rich.coverage_guaranteed is True
    assert rich.lower <= 0.75 <= rich.upper                      # centred on f(query)=raw_score
    # sparse → honest fallback, no guarantee
    sparse = band_for_prediction(query, [_pair("x", 0.8, OutcomeLabel.EXPLOITABLE)],
                                 alpha=0.1, fallback=(0.5, 0.95))
    assert sparse.method == "bayesian_fallback" and sparse.coverage_guaranteed is False
    assert (sparse.lower, sparse.upper) == (0.5, 0.95)
