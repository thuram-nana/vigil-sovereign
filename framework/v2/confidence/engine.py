"""
confidence.engine — assess a ScientificHypothesis into a ConfidenceReport.

The math, all stdlib:
  * each competing explanation (focal + alternatives + a residual "none of these")
    accumulates a log-score = ln(prior) + Σ (weight × independence × ln LR);
  * a numerically-stable softmax (log-sum-exp) over those scores gives a posterior
    DISTRIBUTION that sums to 1 (competing explanations normalise against each other);
  * the focal posterior gets a Beta credible interval whose width shrinks with the
    effective evidence count (reusing the world-model's own `_belief_sd`);
  * `value_of_next_evidence` ranks candidate not-yet-run observations by expected
    information gain about the focal (reusing the planner's `expected_information_gain`)
    — "what single observation would change my mind the most / reach the target".

This is what turns "XSS detected, confidence 1.0" into "posterior 0.992; alternative
'reflected-but-escaped' 0.006; one more execution-context observation exceeds 0.999".
"""

from __future__ import annotations

import math

from ..planner.goal_tree import expected_information_gain
from ..worldmodel.models import _belief_sd
from .models import (
    ConfidenceReport,
    EvidenceValuation,
    HypothesisPosterior,
    ScientificHypothesis,
)

_EPS = 1e-9


def _norm_priors(h: ScientificHypothesis) -> tuple[float, list[float], float]:
    """Normalise focal + alternatives + residual priors to a MECE distribution
    summing to 1. If no residual was given, the leftover mass becomes the residual."""
    focal_p = max(h.prior, 0.0)
    alt_p = [max(a.prior, 0.0) for a in h.alternatives]
    residual = max(h.residual_prior, 0.0)
    if residual == 0.0:
        residual = max(0.0, 1.0 - focal_p - sum(alt_p))
    total = focal_p + sum(alt_p) + residual
    if total <= 0.0:
        n = 2 + len(alt_p)
        return (1.0 / n, [1.0 / n] * len(alt_p), 1.0 / n)
    return (focal_p / total, [p / total for p in alt_p], residual / total)


def _logscore(prior: float, woe_sum: float) -> float:
    return math.log(max(prior, _EPS)) + woe_sum


def _softmax(scores: list[float]) -> list[float]:
    m = max(scores)
    exps = [math.exp(s - m) for s in scores]
    z = sum(exps) or 1.0
    return [e / z for e in exps]


def _credible_interval(posterior: float, effective_n: float, z: float = 1.96) -> tuple[float, float]:
    """A Beta credible interval on the focal posterior, using the effective evidence
    count as pseudo-observations — reuses the world-model belief SD so more evidence
    ⇒ a tighter interval."""
    alpha = 1.0 + effective_n * posterior
    beta = 1.0 + effective_n * (1.0 - posterior)
    mean = alpha / (alpha + beta)
    sd = _belief_sd(alpha, beta)
    return (max(0.0, mean - z * sd), min(1.0, mean + z * sd))


def _value_of_next_evidence(posterior: float, h: ScientificHypothesis,
                            candidates) -> EvidenceValuation | None:
    """The candidate observation with the highest expected information gain about the
    focal hypothesis — the single most decisive test to run next."""
    best: EvidenceValuation | None = None
    for c in candidates or []:
        eig = expected_information_gain(posterior, tpr=c.tpr, fpr=c.fpr)
        p_fire = posterior * c.tpr + (1.0 - posterior) * c.fpr
        post_fire = (posterior * c.tpr / p_fire) if p_fire > _EPS else posterior
        post_not = (posterior * (1.0 - c.tpr) / (1.0 - p_fire)) if (1.0 - p_fire) > _EPS else posterior
        val = EvidenceValuation(
            id=c.id, statement=c.statement, eig_bits=round(eig, 5),
            eig_per_cost=round(eig / c.cost, 5),
            posterior_if_fires=round(post_fire, 5), posterior_if_not=round(post_not, 5),
        )
        if best is None or val.eig_per_cost > best.eig_per_cost:
            best = val
    return best


def assess(
    focal: ScientificHypothesis,
    *,
    candidates=None,
    target_confidence: float = 0.99,
) -> ConfidenceReport:
    """Turn a hypothesis + its evidence + its competing alternatives into a posterior
    distribution, a credible interval, and the most valuable next observation."""
    focal_p0, alt_p0, residual_p0 = _norm_priors(focal)

    focal_woe = sum(e.effective_woe for e in focal.evidence)
    alt_woe = [sum(e.effective_woe for e in a.evidence) for a in focal.alternatives]

    scores = [_logscore(focal_p0, focal_woe)]
    scores += [_logscore(p, w) for p, w in zip(alt_p0, alt_woe)]
    scores.append(_logscore(residual_p0, 0.0))  # residual: baseline, no evidence
    post = _softmax(scores)
    focal_post = post[0]
    alt_post = post[1:-1]
    residual_post = post[-1]

    focal_n = sum(e.weight * e.independence for e in focal.evidence)
    ci_lo, ci_hi = _credible_interval(focal_post, focal_n)

    def _hp(hid, stmt, prior, posterior, ev_count, eff_n, lo, hi):
        lo_odds = math.log(max(posterior, _EPS) / max(1.0 - posterior, _EPS))
        return HypothesisPosterior(id=hid, statement=stmt, prior=round(prior, 5),
                                   posterior=round(posterior, 5), log_odds=round(lo_odds, 4),
                                   ci_low=round(lo, 5), ci_high=round(hi, 5),
                                   evidence_count=ev_count, effective_n=round(eff_n, 3))

    focal_hp = _hp(focal.id, focal.statement, focal_p0, focal_post, len(focal.evidence), focal_n, ci_lo, ci_hi)
    alt_hps = []
    for a, p0, p, w in zip(focal.alternatives, alt_p0, alt_post, alt_woe):
        an = sum(e.weight * e.independence for e in a.evidence)
        alo, ahi = _credible_interval(p, an)
        alt_hps.append(_hp(a.id, a.statement, p0, p, len(a.evidence), an, alo, ahi))
    alt_hps.sort(key=lambda x: -x.posterior)

    best_next = _value_of_next_evidence(focal_post, focal, candidates)
    reaches = focal_post >= target_confidence

    top_alt = alt_hps[0] if alt_hps else None
    narrative = (
        f"{focal.id}: posterior {focal_post:.3f} "
        f"(CI {ci_lo:.3f}–{ci_hi:.3f}) from {len(focal.evidence)} observation(s)"
    )
    if top_alt:
        narrative += f"; top alternative '{top_alt.id}' {top_alt.posterior:.3f}"
    narrative += f"; residual {residual_post:.3f}."
    if not reaches and best_next:
        narrative += (f" Most decisive next test: '{best_next.id}' "
                      f"(+{best_next.eig_bits:.3f} bits → {best_next.posterior_if_fires:.3f} if it fires).")
    elif reaches:
        narrative += f" Exceeds target {target_confidence:.3f}."

    return ConfidenceReport(
        focal=focal_hp, alternatives=alt_hps, residual=round(residual_post, 5),
        target_confidence=target_confidence, reaches_target=reaches,
        best_next=best_next, narrative=narrative,
    )
