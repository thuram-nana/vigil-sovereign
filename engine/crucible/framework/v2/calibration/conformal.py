"""
calibration.conformal — a coverage band with an HONEST guarantee, or none at all.

A point posterior says "0.82"; it does not say how often reality lands near it. Split-
conformal prediction turns the outcome ledger's LABELLED history into a finite-sample
marginal coverage band: from the nonconformity of past predictions (how far each landed
from its realised outcome) it derives a half-width ``q`` such that a fresh prediction's true
outcome falls within ±q about (1−α) of the time.

The load-bearing honesty is the GATE. Under fewer than ``MIN_LABELS`` labelled outcomes
there is no basis for a coverage claim, so this does NOT fabricate one — it falls back to
the Bayesian credible interval already on the posterior and marks
``coverage_guaranteed=False``. A band is only ever labelled guaranteed when the labels
actually back it; the layer never emits a false coverage guarantee.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

from .calibrate import MIN_LABELS, Calibrator
from .models import Outcome, Prediction


@dataclass
class ConformalBand:
    """A [lower, upper] band around a point estimate. ``coverage_guaranteed`` is the only
    thing a consumer should trust for a guarantee: True iff enough labels backed a genuine
    split-conformal band; False when it fell back to the Bayesian credible interval."""

    lower: float
    upper: float
    alpha: float
    coverage: float                 # target marginal coverage = 1 - alpha
    coverage_guaranteed: bool       # True only when >= min_labels labels back it
    n_labels: int
    method: str                     # "split_conformal" | "bayesian_fallback"
    note: str = ""


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def conformal_halfwidth(scores: list[float], alpha: float) -> float:
    """The finite-sample split-conformal quantile of nonconformity ``scores`` at level
    (1−α). Returns 1.0 — the widest, [0,1]-spanning half-width — when n is too small for the
    requested α (an honest "no tighter band is justified" rather than a false tight one)."""
    n = len(scores)
    if n == 0:
        return 1.0
    k = math.ceil((n + 1) * (1.0 - alpha))     # rank of the conformal quantile (1-indexed)
    if k > n:
        return 1.0
    return sorted(scores)[k - 1]


def conformal_band(
    point: float,
    pairs: Iterable[tuple[Prediction, Outcome]],
    *,
    alpha: float = 0.1,
    calibrator: Calibrator | None = None,
    min_labels: int = MIN_LABELS,
    fallback: tuple[float, float] | None = None,
) -> ConformalBand:
    """A conformal coverage band around ``point`` from the ledger's labelled ``pairs``.

    Nonconformity per past prediction is ``|target − prob|`` (one minus the probability it
    assigned the realised class), where ``prob`` is the prediction's OWN ``raw_score`` —
    or, if a ``calibrator`` is supplied, its calibrated probability.

    CONTRACT — the guarantee is only real if you honour it: split-conformal proves
    ``P(|Y_new − f(X_new)| ≤ q) ≥ 1−α`` for a band centred on ``f(X_new)``, the SAME
    estimator ``f`` whose residuals form the calibration scores. So ``point`` MUST be that
    estimator's prediction for the query (its raw_score, or the calibrated probability when
    a calibrator is given) — NOT some other number (e.g. an unrelated posterior), or the
    emitted band carries no coverage. Use :func:`band_for_prediction`, which computes
    ``point`` correctly, unless you are supplying ``f(query)`` yourself.

    The (1−α) guarantee also rests on exchangeability, so ``prob`` must be a FIXED scoring
    rule, not one refit on these very labels: we never fit a calibrator on ``pairs`` here
    (that overlap would bias the scores optimistically). Pass a ``calibrator`` only if it
    was fit on data DISJOINT from ``pairs``. Gated on ``min_labels``: under that many labels
    it returns ``fallback`` (the caller's Bayesian credible interval) marked NOT guaranteed.
    Deterministic; sources no randomness."""
    pairs = list(pairs)
    samples = [(p.raw_score, p.oracle_confirmed, o.target)
               for p, o in pairs if o.target is not None]
    n = len(samples)
    lo_fb, hi_fb = fallback if fallback is not None else (0.0, 1.0)
    if n < min_labels:
        return ConformalBand(
            lower=_clamp01(lo_fb), upper=_clamp01(hi_fb), alpha=alpha, coverage=round(1 - alpha, 4),
            coverage_guaranteed=False, n_labels=n, method="bayesian_fallback",
            note=(f"{n} < MIN_LABELS ({min_labels}) labelled outcome(s) — no conformal "
                  f"coverage guarantee; showing the Bayesian credible interval instead"))
    # a FIXED scoring rule (never refit on these labels) keeps the coverage guarantee honest.
    prob = (lambda s, o: calibrator.calibrate(s, o)) if calibrator is not None else (lambda s, o: s)
    scores = [abs(t - prob(s, oracle)) for s, oracle, t in samples]
    q = conformal_halfwidth(scores, alpha)
    trivial = q >= 1.0
    note = (f"split-conformal ±{q:.3f} at {int(round((1 - alpha) * 100))}% target coverage "
            f"over {n} labelled outcome(s)"
            + ("; band spans [0,1] — n too small for this alpha to tighten it" if trivial else ""))
    return ConformalBand(
        lower=_clamp01(point - q), upper=_clamp01(point + q), alpha=alpha,
        coverage=round(1 - alpha, 4), coverage_guaranteed=True, n_labels=n,
        method="split_conformal", note=note)


def band_for_prediction(
    query: Prediction,
    pairs: Iterable[tuple[Prediction, Outcome]],
    *,
    alpha: float = 0.1,
    calibrator: Calibrator | None = None,
    min_labels: int = MIN_LABELS,
    fallback: tuple[float, float] | None = None,
) -> ConformalBand:
    """A coverage band around a QUERY prediction's exploitability estimate — the sound way
    to get a conformal band from this ledger.

    The band centres on ``f(query)`` = the query's ``raw_score`` (or its calibrated
    probability when a disjoint-fit ``calibrator`` is given), i.e. the SAME estimator whose
    residuals over ``pairs`` set the half-width. That is what makes the (1−α) marginal
    coverage transfer to the emitted band.

    NOTE: this deliberately does NOT accept an arbitrary SCE ``HypothesisPosterior`` — the
    ledger scores an EXPLOITABILITY predictor, and a band whose half-width comes from that
    predictor's residuals is only valid centred on that predictor's output. Centring on an
    unrelated posterior would void the guarantee, so we bind to the prediction instead."""
    point = (calibrator.calibrate(query.raw_score, query.oracle_confirmed)
             if calibrator is not None else query.raw_score)
    return conformal_band(point, pairs, alpha=alpha, calibrator=calibrator,
                          min_labels=min_labels, fallback=fallback)
