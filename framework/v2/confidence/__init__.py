"""
framework.v2.confidence — the Scientific Confidence Engine (SCE).

Makes every conclusion behave like a scientist's claim instead of a scanner's
verdict. A `ScientificHypothesis` carries an explicit prior, an `Evidence` ledger
(each datum weighted by likelihood-ratio × reliability × independence), a set of
competing `alternatives` (+ a residual "none of these" mass, so the explanations are
MECE), and — via `engine.assess` — a Bayesian posterior by log-odds accumulation, a
credible interval that tightens with evidence, and the single highest-value next
observation ("what would change my mind"). It reuses the world-model's Beta-belief
form and the planner's expected-information-gain, and wraps `kernel.Hypothesis`.

Standalone by design: the vuln-hunting decision gate reuses this too, so it is a
sibling of `intel/`, not a submodule of it.
"""

from .models import (
    AlternativeHypothesis,
    CandidateObservation,
    ConfidenceReport,
    Evidence,
    EvidenceValuation,
    HypothesisPosterior,
    Provenance,
    ScientificHypothesis,
)
from .engine import assess

__all__ = [
    "AlternativeHypothesis", "CandidateObservation", "ConfidenceReport", "Evidence",
    "EvidenceValuation", "HypothesisPosterior", "Provenance", "ScientificHypothesis",
    "assess",
]
