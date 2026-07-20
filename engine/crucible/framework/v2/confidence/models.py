"""
confidence.models — the typed claims of the Scientific Confidence Engine.

`Evidence` is one datum bearing on a hypothesis, weighted by a likelihood ratio (how
much more likely the observation is under the hypothesis than under the baseline) ×
reliability × independence. A `ScientificHypothesis` is the focal falsifiable claim
plus its competing `alternatives` and a residual "none of these" mass — a MECE set of
explanations. `assess` (engine.py) turns these into a `ConfidenceReport`.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, Field


class Provenance(BaseModel):
    """Where a piece of evidence came from — every datum is traceable."""

    model_config = ConfigDict(extra="forbid")

    source: str = ""
    ref: str = ""          # an obs_id / oracle_context id / URL — the raw artifact
    note: str = ""


class Evidence(BaseModel):
    """One observation bearing on a hypothesis' truth.

    ``likelihood_ratio`` = P(observation | hypothesis) / P(observation | baseline):
    > 1 supports, < 1 refutes, = 1 is uninformative. ``weight`` is a reliability
    pseudo-count (a flaky source contributes less). ``independence`` in [0, 1]
    discounts redundancy — the 5th copy of the same signal (independence → 0) barely
    moves the posterior. The signed weight-of-evidence it contributes is
    ``weight × independence × ln(likelihood_ratio)``."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0, description="Monotonic order (not wallclock).")
    observation: str
    likelihood_ratio: float = Field(gt=0.0)
    weight: float = Field(default=1.0, ge=0.0)
    independence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: Provenance = Field(default_factory=Provenance)

    @property
    def effective_woe(self) -> float:
        """Signed weight-of-evidence (nats) this datum contributes to the log-odds."""
        return self.weight * self.independence * math.log(self.likelihood_ratio)


class AlternativeHypothesis(BaseModel):
    """A competing explanation for the same observations, with its own prior and its
    own evidence ledger. The posterior normalises focal + alternatives + residual."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    prior: float = Field(default=0.1, ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(default_factory=list)


class CandidateObservation(BaseModel):
    """A test not yet run — used to compute 'what would change my mind'. ``tpr`` =
    P(this observation fires | focal hypothesis true); ``fpr`` = P(fires | false)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    tpr: float = Field(default=0.9, ge=0.0, le=1.0)
    fpr: float = Field(default=0.05, ge=0.0, le=1.0)
    cost: float = Field(default=1.0, gt=0.0)


class ScientificHypothesis(BaseModel):
    """The focal falsifiable claim. ``residual_prior`` is the mass on 'none of these /
    benign', so focal.prior + Σ alternatives.prior + residual_prior is (normalised to)
    1 — the explanations are mutually exclusive and collectively exhaustive."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    surface: str = ""
    bug_class: str = ""
    prior: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(default_factory=list)
    alternatives: list[AlternativeHypothesis] = Field(default_factory=list)
    residual_prior: float = Field(default=0.0, ge=0.0, le=1.0)
    refute_on: str = ""   # what single observation would falsify this ("change my mind")

    @classmethod
    def from_kernel_hypothesis(cls, h: object, *, prior: float | None = None) -> "ScientificHypothesis":
        """Adapt a ``kernel.Hypothesis`` (given/if/then/because + refute_on + confidence)
        into a scientific hypothesis — its ``confidence`` seeds the prior, its
        ``refute_on`` carries over as the falsification test."""
        statement = getattr(h, "then_observation", None) or getattr(h, "statement", "") or str(h)
        return cls(
            id=str(getattr(h, "id", "H")),
            statement=str(statement),
            surface=str(getattr(h, "surface", "")),
            bug_class=str(getattr(h, "bug_class", "")),
            prior=float(prior if prior is not None else getattr(h, "confidence", 0.5)),
            refute_on=str(getattr(h, "refute_on", "")),
        )


# ---------------------------------------------------------------------------
# outputs
# ---------------------------------------------------------------------------


class HypothesisPosterior(BaseModel):
    """One explanation's posterior after evidence, with a credible interval."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    prior: float
    posterior: float
    log_odds: float
    ci_low: float
    ci_high: float
    evidence_count: int
    effective_n: float


class EvidenceValuation(BaseModel):
    """The value of running a candidate observation next — its expected information
    gain (bits) about the focal hypothesis, and where it would move the posterior."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    eig_bits: float
    eig_per_cost: float
    posterior_if_fires: float
    posterior_if_not: float


class ConfidenceReport(BaseModel):
    """The scientist's verdict: the focal posterior + credible interval, the competing
    explanations, the residual mass, whether the target confidence is reached, and the
    single most valuable next observation. ``narrative`` renders it in one line."""

    model_config = ConfigDict(extra="forbid")

    focal: HypothesisPosterior
    alternatives: list[HypothesisPosterior] = Field(default_factory=list)
    residual: float = 0.0
    target_confidence: float = 0.99
    reaches_target: bool = False
    best_next: EvidenceValuation | None = None
    narrative: str = ""
