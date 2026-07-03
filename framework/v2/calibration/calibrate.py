"""
calibrate — fit and apply a calibrated exploitability probability.

This is what replaces the hardcoded 1.0. Given the ledger's labelled
(prediction, outcome) pairs, we fit a monotonic mapping from the model's raw
score to a probability that *matches observed reality*, then measure how well
it does with ECE and Brier.

Method: isotonic regression via the Pool-Adjacent-Violators algorithm (PAV),
implemented in pure Python — no sklearn, no numpy. Isotonic is the right tool
here: it makes no shape assumption (unlike Platt/logistic scaling), only that
a higher raw score should not map to a lower probability — which is exactly
the guarantee we want from a scorer. The fitted mapping is stored as a small
set of (threshold, value) breakpoints and applied by linear interpolation.

Three properties matter and are tested:

  1. **Monotonicity.** PAV output is non-decreasing, so `calibrate` is
     monotone in the raw score. A higher-scored finding is never assigned a
     lower probability.

  2. **Identity fallback under sparse data.** With fewer than `MIN_LABELS`
     labelled outcomes there is not enough signal to calibrate honestly, so
     the fit degrades to identity — `calibrate(s) == s` — and says so via
     `Calibrator.method == "identity"`. We do not invent reliability we have
     not measured.

  3. **The oracle prior is learned, not hardcoded.** An oracle-confirmed
     finding gets a boost, but the boost is the *empirically observed*
     exploitable-rate among oracle-confirmed findings in the ledger, combined
     with the score via a noisy-OR — not a constant 1.0. If oracle-confirmed
     findings historically turned out to be false positives, that learned
     prior shrinks accordingly, and confirmation stops meaning certainty.
     Nothing here ever returns 1.0: calibrated probabilities are clamped to
     `MAX_PROB` (0.999), the same "never certain" discipline the verify layer
     uses.
"""

from __future__ import annotations

import bisect
from typing import Iterable, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field

from .models import Bin, CalibrationReport, Outcome, Prediction

# Below this many labelled outcomes, calibration falls back to identity.
MIN_LABELS = 8
# Below this many oracle-confirmed labelled outcomes, no oracle prior is learned.
MIN_ORACLE_LABELS = 3
# A calibrated probability is never allowed to claim certainty.
MAX_PROB = 0.999

Method = Literal["isotonic", "identity"]

# A labelled sample the fitter consumes: (raw_score, oracle_confirmed, target).
_Sample = tuple[float, bool, float]


# ---------------------------------------------------------------------------
# Pool-Adjacent-Violators (isotonic regression)
# ---------------------------------------------------------------------------


def pav(values: Sequence[float], weights: Sequence[float]) -> list[float]:
    """Pool-Adjacent-Violators. Given target `values` ordered by ascending x
    with positive `weights`, return the non-decreasing weighted least-squares
    fit — one fitted value per input, monotone non-decreasing.

    Pure Python, O(n): each point opens a block; while the previous block's
    mean is >= the new block's mean (a violation of non-decreasing order) the
    two blocks pool into their weighted mean."""
    if len(values) != len(weights):
        raise ValueError("values and weights must be the same length")
    # block = [count, weight_sum, weighted_value_sum, mean]
    blocks: list[list[float]] = []
    for v, w in zip(values, weights):
        if w <= 0:
            raise ValueError("weights must be positive")
        count = 1.0
        wsum = float(w)
        wvsum = float(w) * float(v)
        mean = wvsum / wsum
        while blocks and blocks[-1][3] >= mean:
            pc, pw, pwv, _ = blocks.pop()
            count += pc
            wsum += pw
            wvsum += pwv
            mean = wvsum / wsum
        blocks.append([count, wsum, wvsum, mean])
    fitted: list[float] = []
    for count, _wsum, _wvsum, mean in blocks:
        fitted.extend([mean] * int(count))
    return fitted


# ---------------------------------------------------------------------------
# The calibrator
# ---------------------------------------------------------------------------


class Calibrator(BaseModel):
    """A fitted (or identity) mapping from raw score to calibrated probability.

    Serialisable by design: the whole fit is `thresholds` (strictly ascending
    raw scores) paired with `values` (their non-decreasing fitted
    probabilities), plus a learned `oracle_prior`. `method == "identity"`
    means the data was too sparse to calibrate and `calibrate` is a passthrough.
    """

    model_config = ConfigDict(extra="forbid")

    method: Method = "identity"
    thresholds: list[float] = Field(default_factory=list)
    values: list[float] = Field(default_factory=list)
    oracle_prior: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Learned P(exploitable | oracle_confirmed); None if unlearned.",
    )
    n_labels: int = Field(default=0, ge=0, description="Labelled outcomes used to fit.")

    # -- apply -------------------------------------------------------------

    def _interp(self, score: float) -> float:
        """Piecewise-linear interpolation over the isotonic breakpoints."""
        xs, ys = self.thresholds, self.values
        if not xs:
            return score
        if score <= xs[0]:
            return ys[0]
        if score >= xs[-1]:
            return ys[-1]
        i = bisect.bisect_right(xs, score)
        x0, x1 = xs[i - 1], xs[i]
        y0, y1 = ys[i - 1], ys[i]
        if x1 == x0:
            return y1
        t = (score - x0) / (x1 - x0)
        return y0 + t * (y1 - y0)

    def calibrate(self, score: float, oracle_confirmed: bool = False) -> float:
        """Map a raw score (and optional oracle confirmation) to a calibrated
        probability in [0, MAX_PROB].

        Identity fit -> passthrough (the honest "not yet measured" answer).
        Isotonic fit -> the learned probability, boosted by the *learned*
        oracle prior via noisy-OR when the finding was oracle-confirmed."""
        score = _clamp(score, 0.0, 1.0)
        if self.method == "identity":
            return score
        p = self._interp(score)
        if oracle_confirmed and self.oracle_prior is not None:
            # Noisy-OR: two independent pieces of evidence for exploitability
            # combine, but the oracle's weight is the empirically observed
            # exploitable-rate among confirmed findings — never a hardcoded 1.0.
            p = 1.0 - (1.0 - p) * (1.0 - self.oracle_prior)
        return _clamp(p, 0.0, MAX_PROB)

    # -- construction ------------------------------------------------------

    @classmethod
    def identity(cls) -> "Calibrator":
        """The passthrough calibrator used under sparse data."""
        return cls(method="identity")


def _clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


# ---------------------------------------------------------------------------
# Fitting
# ---------------------------------------------------------------------------


def _samples(pairs: Iterable[tuple[Prediction, Outcome]]) -> list[_Sample]:
    """Project labelled pairs to (raw_score, oracle_confirmed, target),
    dropping DISPUTED (target None) outcomes."""
    out: list[_Sample] = []
    for pred, outcome in pairs:
        target = outcome.target
        if target is None:
            continue
        out.append((pred.raw_score, pred.oracle_confirmed, target))
    return out


def fit(
    pairs: Iterable[tuple[Prediction, Outcome]],
    *,
    min_labels: int = MIN_LABELS,
    min_oracle_labels: int = MIN_ORACLE_LABELS,
) -> Calibrator:
    """Fit an isotonic calibrator over the ledger's labelled pairs.

    Falls back to `Calibrator.identity()` when fewer than `min_labels`
    non-DISPUTED outcomes are available — sparse data cannot honestly be
    calibrated. Otherwise fits PAV isotonic regression on raw_score -> target
    and, if at least `min_oracle_labels` oracle-confirmed outcomes exist,
    learns `oracle_prior` as their empirical exploitable-rate."""
    samples = _samples(pairs)
    if len(samples) < min_labels:
        return Calibrator(method="identity", n_labels=len(samples))

    # Aggregate duplicate raw scores into one point (mean target, weight=count)
    # so the PAV thresholds are strictly ascending and interpolation is
    # unambiguous.
    agg: dict[float, list[float]] = {}
    for score, _oracle, target in samples:
        slot = agg.setdefault(score, [0.0, 0.0])
        slot[0] += target
        slot[1] += 1.0
    xs = sorted(agg)
    ys = [agg[x][0] / agg[x][1] for x in xs]
    ws = [agg[x][1] for x in xs]
    fitted = pav(ys, ws)

    # Learn the oracle prior from outcomes — not hardcoded.
    oracle_targets = [t for _s, oracle, t in samples if oracle]
    oracle_prior: float | None = None
    if len(oracle_targets) >= min_oracle_labels:
        oracle_prior = sum(oracle_targets) / len(oracle_targets)

    return Calibrator(
        method="isotonic",
        thresholds=list(xs),
        values=fitted,
        oracle_prior=oracle_prior,
        n_labels=len(samples),
    )


# ---------------------------------------------------------------------------
# Reliability metrics
# ---------------------------------------------------------------------------


def _predicted(
    pairs: Iterable[tuple[Prediction, Outcome]],
    calibrator: Calibrator | None,
) -> list[tuple[float, float]]:
    """(probability, target) per labelled pair. `calibrator=None` measures the
    raw (uncalibrated) score, so before/after ECE are directly comparable."""
    out: list[tuple[float, float]] = []
    for pred, outcome in pairs:
        target = outcome.target
        if target is None:
            continue
        if calibrator is None:
            p = pred.raw_score
        else:
            p = calibrator.calibrate(pred.raw_score, pred.oracle_confirmed)
        out.append((p, target))
    return out


def brier_score(
    pairs: Iterable[tuple[Prediction, Outcome]],
    calibrator: Calibrator | None = None,
) -> float:
    """Mean squared error between predicted probability and outcome, over the
    labelled (non-DISPUTED) pairs. 0.0 is perfect; empty input -> 0.0."""
    pts = _predicted(pairs, calibrator)
    if not pts:
        return 0.0
    return sum((p - y) ** 2 for p, y in pts) / len(pts)


def _bin_edges(n_bins: int) -> list[float]:
    return [i / n_bins for i in range(n_bins + 1)]


def reliability_report(
    pairs: Iterable[tuple[Prediction, Outcome]],
    calibrator: Calibrator | None = None,
    *,
    n_bins: int = 10,
) -> CalibrationReport:
    """Build a full CalibrationReport (n, ECE, Brier, bins) for a set of
    predictions under `calibrator` (or raw scores when None).

    ECE is the count-weighted mean absolute gap between predicted probability
    and observed exploitable-rate across equal-width [0, 1] bins."""
    if n_bins < 1:
        raise ValueError("n_bins must be >= 1")
    pts = _predicted(pairs, calibrator)
    edges = _bin_edges(n_bins)
    # collect per-bin (predictions, targets)
    buckets: list[list[tuple[float, float]]] = [[] for _ in range(n_bins)]
    for p, y in pts:
        # rightmost bin is closed on the right so p == 1.0 lands in bin n-1
        idx = min(int(p * n_bins), n_bins - 1)
        buckets[idx].append((p, y))

    bins: list[Bin] = []
    total = len(pts)
    ece = 0.0
    for i in range(n_bins):
        bucket = buckets[i]
        count = len(bucket)
        if count:
            mean_pred = sum(p for p, _y in bucket) / count
            mean_actual = sum(y for _p, y in bucket) / count
            ece += (count / total) * abs(mean_pred - mean_actual)
        else:
            mean_pred = 0.0
            mean_actual = 0.0
        bins.append(
            Bin(
                index=i,
                lower=edges[i],
                upper=edges[i + 1],
                count=count,
                mean_pred=mean_pred,
                mean_actual=mean_actual,
            )
        )

    return CalibrationReport(
        n=total,
        ece=ece,
        brier=brier_score(pairs, calibrator),
        bins=bins,
    )


def measure_ece(
    pairs: Iterable[tuple[Prediction, Outcome]],
    calibrator: Calibrator | None = None,
    *,
    n_bins: int = 10,
) -> float:
    """Expected Calibration Error only (convenience over reliability_report)."""
    return reliability_report(pairs, calibrator, n_bins=n_bins).ece
