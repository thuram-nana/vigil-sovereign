"""
intel.learn — cross-engagement source-yield learning.

Which recon source is worth querying depends on the target. Certificate
Transparency is gold against a sprawling SaaS estate and nearly worthless against
a single appliance; RDAP pays off where ownership is the question. This module
records how much VERIFIED value each source produced — per target archetype — and
turns that history into calibrated priors the `ReconPlanner` consumes, so a source
that has never paid off against this kind of target is deprioritised without ever
being disabled.

The signal is deliberately conservative and Bayesian-shrunk: with little history a
source sits at the neutral default; only consistent yield (and, more heavily,
confirmed findings downstream of assets it discovered) moves its prior. New
sources and new archetypes are treated as "unknown", never "bad" — the planner
still explores them (VOI is highest exactly where the prior is uncertain).

Storage is the `intel_source_yield` table (schema v2); this module is the policy
over it. Reuses the same memory Store the rest of the learning substrate uses.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict

from .models import IntelSourceKind
from .store import IntelStore

_DEFAULT_PRIOR = 0.5
_SHRINK_PSEUDO_QUERIES = 3.0   # imaginary queries at the default prior (Bayesian shrinkage)
_FINDING_WEIGHT = 2.0          # a confirmed finding counts far more than a raw observation


class SourceYield(BaseModel):
    """A source's learned track record against one archetype."""

    model_config = ConfigDict(extra="forbid")

    source_kind: str
    archetype: str = ""
    queries: int = 0
    observations_yielded: int = 0
    entities_yielded: int = 0
    findings_downstream: int = 0

    @property
    def coverage_rate(self) -> float:
        """Distinct assets surfaced per query."""
        return self.entities_yielded / self.queries if self.queries else 0.0

    @property
    def value_rate(self) -> float:
        """Confirmed findings per query — the strongest signal of real worth."""
        return self.findings_downstream / self.queries if self.queries else 0.0

    def raw_signal(self) -> float:
        """Squashed per-query yield in (0, 1): coverage plus heavily-weighted value."""
        x = self.coverage_rate + _FINDING_WEIGHT * self.value_rate
        return 1.0 - math.exp(-x)   # diminishing returns, bounded


def _view(store: IntelStore, source_kind: str, archetype: str) -> SourceYield:
    row = store.source_yield(source_kind, archetype=archetype)
    return SourceYield(source_kind=source_kind, archetype=archetype,
                       queries=row["queries"], observations_yielded=row["observations_yielded"],
                       entities_yielded=row["entities_yielded"],
                       findings_downstream=row["findings_downstream"])


def source_prior(store: IntelStore, source_kind: IntelSourceKind | str, *,
                 archetype: str = "", default: float = _DEFAULT_PRIOR) -> float:
    """Calibrated prior that ``source_kind`` will reveal new surface against
    ``archetype``. Bayesian shrinkage toward ``default``: with no history the prior
    IS the default (unknown, not bad); consistent yield pulls it toward the squashed
    per-query rate. Never 0 or 1 — the planner must keep exploring."""
    sk = source_kind.value if isinstance(source_kind, IntelSourceKind) else str(source_kind)
    y = _view(store, sk, archetype)
    if y.queries <= 0:
        return default
    shrunk = (default * _SHRINK_PSEUDO_QUERIES + y.raw_signal() * y.queries) / (
        _SHRINK_PSEUDO_QUERIES + y.queries)
    return round(min(0.95, max(0.05, shrunk)), 5)


def planner_priors(store: IntelStore, source_kinds: list[IntelSourceKind], *,
                   archetype: str = "", default: float = _DEFAULT_PRIOR) -> dict[str, float]:
    """Priors for every source, keyed by source_kind value — pass straight to
    `ReconPlanner.plan(priors=...)`."""
    return {sk.value: source_prior(store, sk, archetype=archetype, default=default)
            for sk in source_kinds}


# -- attribution: crediting sources for what they produced ---------------------


def credit_discovery(store: IntelStore, result, *, archetype: str = "") -> None:
    """Credit each source for a recon run, coherently under ONE archetype: its
    collector invocations (queries), observations contributed, and distinct entities
    it helped resolve. Fed an `IngestResult` (uses queries/per_source/entities per
    source); keeping queries and yield on the same row is what makes `source_prior`
    able to learn a rate at all."""
    queries = getattr(result, "queries_per_source", {}) or {}
    per_source = getattr(result, "per_source", {}) or {}
    entities = getattr(result, "entities_per_source", {}) or {}
    sources = set(queries) | set(per_source) | set(entities)
    for sk in sorted(sources):
        store.bump_source_yield(sk, archetype=archetype,
                                queries=queries.get(sk, 0),
                                observations=per_source.get(sk, 0),
                                entities=entities.get(sk, 0))
    store.commit()


def credit_finding(store: IntelStore, source_kinds: list[str], *, archetype: str = "") -> None:
    """Credit the sources that discovered a confirmed-finding asset. This is the gold
    signal — it flows through `value_rate` into future priors, so sources whose
    discoveries turn into real bugs rise fastest."""
    for sk in set(source_kinds):
        store.bump_source_yield(sk, archetype=archetype, findings=1)
    store.commit()
