"""
intel.fuse — batch Bayesian evidence fusion in the world-model's OWN Beta form.

`fuse_observations` folds many independent observations of the SAME claim into one
posterior. It de-dupes per source (a source repeating itself is not independent
corroboration), drops worthless sources (reliability ≈ 0 → "unknown stays unknown"),
and combines the rest with a noisy-OR on each side (corroboration vs refutation), so
three independent confirmations *saturate* (they do not run away) and a confirmation
plus a refutation land at a contested 0.5. The result is expressed as `alpha, beta`
in the world-model's Beta parameterisation, so streaming projection and this batch
path agree at the extremes.

This is the offline/backfill path (Path B). The streaming default (Path A) is simply
projecting each observation and letting `graph._update_belief` fuse for free.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

from ..worldmodel.models import _belief_sd
from .models import Observation

_EPS = 1e-9


class FusedBelief(BaseModel):
    """A fused posterior over one claim, in the world-model's Beta(alpha, beta) form."""

    model_config = ConfigDict(extra="forbid")

    alpha: float = Field(gt=0.0)
    beta: float = Field(gt=0.0)
    n_observations: int = Field(ge=0)
    effective_n: float = Field(ge=0.0)
    corroboration: float = Field(ge=0.0, le=1.0)
    refutation: float = Field(ge=0.0, le=1.0)
    contested: bool = False
    provenance: list[str] = Field(default_factory=list)

    @property
    def belief_mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def belief_sd(self) -> float:
        return _belief_sd(self.alpha, self.beta)

    def as_confidence(self) -> float:
        return self.belief_mean


def _noisy_or(strengths: list[float]) -> float:
    prod = 1.0
    for s in strengths:
        prod *= (1.0 - min(max(s, 0.0), 0.999))
    return 1.0 - prod


def fuse_observations(observations: Sequence[Observation], *, contest_threshold: float = 0.3) -> FusedBelief:
    """Fuse observations of ONE claim into a Beta posterior. Observations of different
    claims are a caller error (assert on claim_key)."""
    obs = list(observations)
    if obs:
        keys = {o.claim_key for o in obs}
        if len(keys) != 1:
            raise ValueError(f"fuse_observations got {len(keys)} distinct claims; group by claim_key first")

    # de-dupe per source: a source's latest observation only (self-repetition ≠ corroboration)
    latest: dict[str, Observation] = {}
    for o in sorted(obs, key=lambda x: x.seq):
        if o.reliability() <= _EPS:
            continue  # worthless source contributes nothing
        latest[o.source] = o
    kept = list(latest.values())

    affirm: list[float] = []
    refute: list[float] = []
    weight = 0.0
    for o in kept:
        r = o.reliability()
        t = o.truth_confidence()
        weight += r
        strength = min(0.999, 2.0 * r * abs(t - 0.5))   # directed support magnitude
        (affirm if t >= 0.5 else refute).append(strength)

    C = _noisy_or(affirm)
    R = _noisy_or(refute)
    alpha = 1.0 + weight * C
    beta = 1.0 + weight * R
    return FusedBelief(
        alpha=alpha, beta=beta, n_observations=len(obs), effective_n=round(weight, 4),
        corroboration=round(C, 5), refutation=round(R, 5),
        contested=(C >= contest_threshold and R >= contest_threshold),
        provenance=sorted(o.obs_id for o in kept),
    )
