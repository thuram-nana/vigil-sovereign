"""
calibration.meta_monitor — learning about learning.

CRUCIBLE learns (bandit, calibrator, conformal bands) but nothing watched whether the LEARNERS
themselves are healthy. The meta-monitor reads the outcome ledger and asks: do we have enough
independent labels to trust anything? is the calibrator's probability actually calibrated (ECE)?
do the conformal bands realise their target coverage on held-out data? It turns those into a
``MetaSignal`` that modulates EFFORT and ABSTENTION only.

Hard rule: this NEVER gates or skips an attack surface (coverage doctrine), never promotes a
finding, and never feeds an LLM signal into the deterministic path. When the learners are
unhealthy it recommends "gather more independent evidence" or "trust the confidence less /
abstain more" — it can only make the system MORE cautious, never more confident.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .calibrate import MIN_LABELS, reliability_report
from .conformal import conformal_halfwidth
from .models import label_to_target

_ECE_GATE = 0.15   # above this the calibrator's probabilities are materially miscalibrated


@dataclass
class MetaSignal:
    """A learner-health diagnostic. ``recommend`` is advisory and can only make the system
    MORE cautious: 'ok' / 'gather_evidence' (too few labels) / 'trust_confidence_less'
    (miscalibrated or under-covering)."""

    n_labels: int
    ece: float
    brier: float
    coverage_target: float
    coverage_realized: float | None    # None when there is too little held-out data to measure
    calibrated: bool
    recommend: str
    notes: str


def _targets(pairs: list) -> list[tuple[float, float]]:
    """(raw_score, binary target) for the non-DISPUTED pairs, in order."""
    out = []
    for pred, outcome in pairs:
        t = label_to_target(outcome.label)
        if t is not None:
            out.append((float(pred.raw_score), float(t)))
    return out


def _realized_coverage(labeled: list[tuple[float, float]], alpha: float,
                       min_labels: int) -> float | None:
    """Genuine realized coverage via a TEMPORAL split: fit the conformal half-width on the
    first half, then measure the fraction of the held-out second half the band covers. Needs
    >= 2*min_labels labelled points; None otherwise (honestly unmeasurable)."""
    if len(labeled) < 2 * min_labels:
        return None
    mid = len(labeled) // 2
    train, test = labeled[:mid], labeled[mid:]
    if not test:
        return None
    q = conformal_halfwidth([abs(t - p) for p, t in train], alpha)
    # A trivial band (q >= 1.0 spans all of [0,1]) covers everything by construction and
    # conveys ZERO coverage information — the train half was too small for this alpha to
    # tighten it. Report coverage as UNMEASURED (None), never a false 1.0 (the same guard
    # conformal.py carries; this keeps the module's 'no false coverage guarantee' doctrine).
    if q >= 1.0:
        return None
    covered = sum(1 for p, t in test if abs(t - p) <= q)
    return round(covered / len(test), 4)


def assess_learner_health(ledger: Any, *, alpha: float = 0.1,
                          min_labels: int = MIN_LABELS, ece_gate: float = _ECE_GATE) -> MetaSignal:
    """Diagnose the learners from the outcome ledger. Fails HONEST under sparse data (recommend
    'gather_evidence'); recommends 'trust_confidence_less' when miscalibrated or under-covering;
    else 'ok'. Never gates a surface. Pure and read-only."""
    pairs = list(ledger.pairs())
    report = reliability_report(pairs)          # n counts only non-DISPUTED contributors
    n = report.n
    target = round(1.0 - alpha, 4)

    if n < min_labels:
        return MetaSignal(n_labels=n, ece=report.ece, brier=report.brier, coverage_target=target,
                          coverage_realized=None, calibrated=False, recommend="gather_evidence",
                          notes=(f"only {n} independent labelled outcome(s) (< {min_labels}) — "
                                 f"too few to trust calibration or coverage; gather more "
                                 f"independent evidence and treat confidence as identity"))

    realized = _realized_coverage(_targets(pairs), alpha, min_labels)
    calibrated = report.ece <= ece_gate
    if not calibrated:
        rec, note = ("trust_confidence_less",
                     f"ECE {report.ece:.3f} > {ece_gate} — probabilities are miscalibrated; "
                     f"discount confidence and prefer more evidence")
    elif realized is not None and realized < target - 0.10:
        rec, note = ("trust_confidence_less",
                     f"realized coverage {realized:.2f} < target {target:.2f} — bands under-cover; "
                     f"abstain more on borderline claims")
    else:
        rec, note = ("ok", "calibration and coverage are within tolerance")
    return MetaSignal(n_labels=n, ece=report.ece, brier=report.brier, coverage_target=target,
                      coverage_realized=realized, calibrated=calibrated, recommend=rec, notes=note)


# ---- policy generalization: an OPTIONAL learned prior source ----------------


class PolicyProvider(Protocol):
    """A source of a learned prior/value for a (context, arm) decision. Injecting one lets the
    planner/scheduler ORDER work by learned value — it NEVER gates (a zero prior deprioritises,
    never skips) and defaults to nothing (current behaviour) when no provider is supplied."""

    def value(self, context: str, arm: str) -> float: ...


class BanditPolicyProvider:
    """A PolicyProvider backed by the existing Thompson bandit's posterior mean — reuses the RL
    substrate rather than adding a second policy. Generalises the bandit's check-ordering value
    to any (context, arm) decision point (planner leaf, agent scheduling)."""

    def __init__(self, bandit: Any) -> None:
        self._bandit = bandit

    def value(self, context: str, arm: str) -> float:
        try:
            return float(self._bandit.expected_value(context, arm))
        except Exception:
            return 0.5   # neutral prior on any failure — deprioritises, never skips


def rank_by_policy(context: str, arms: list[str], provider: PolicyProvider | None) -> list[str]:
    """Order ``arms`` by learned value (descending) when a provider is given; otherwise return
    them UNCHANGED (default behaviour). This ORDERS effort — it never drops an arm, so no
    attack surface is ever skipped (coverage doctrine). Stable for equal values."""
    if provider is None:
        return list(arms)
    return sorted(arms, key=lambda a: -provider.value(context, a))
