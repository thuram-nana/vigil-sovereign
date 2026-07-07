"""
intel.planner — ReconPlanner: spend the next recon query where it buys the most.

Recon has a budget; sources have different costs and different odds of revealing
*new* attack surface. The planner ranks every (collector, subject) task by
EXPECTED INFORMATION GAIN per unit cost about the question "is there undiscovered
surface reachable here?" — reusing the planner kernel's
`expected_information_gain` (the same VOI math the vuln-planner uses on leaves).

This is genuinely not "run the cheapest source" or "run the highest-prior source":
a near-certain belief (we already enumerated this domain's certs) has little left
to learn and scores low even if cheap; an uncertain, high-cost source can outrank
it. Priors come, when available, from cross-engagement source-yield learning
(Phase D) — a source that has paid off against this archetype gets a higher prior
of undiscovered surface — and are damped for tasks already run this session.

The planner never fetches anything. It emits an ordered `ReconPlan`; `IntelIngest`
executes the chosen tasks. Deterministic: ties break on cost, then subject, then
collector name.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..planner.goal_tree import expected_information_gain
from .collectors.base import Collector
from .models import IntelSourceKind
from .refs import EntityRef

_DEFAULT_PRIOR = 0.5
_DAMP_ALREADY_RUN = 0.08   # a task already run this session has little left to reveal


class ReconTask(BaseModel):
    """One candidate recon query, valued by expected information gain."""

    model_config = ConfigDict(extra="forbid")

    collector: str
    source_kind: IntelSourceKind
    subject: EntityRef
    prior: float = Field(ge=0.0, le=1.0)
    eig_bits: float
    eig_per_cost: float
    cost: float
    rationale: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.subject.node_id, self.collector)


class ReconPlan(BaseModel):
    """An ordered recon plan — highest value-of-information first."""

    model_config = ConfigDict(extra="forbid")

    tasks: list[ReconTask] = Field(default_factory=list)

    def best(self) -> ReconTask | None:
        return self.tasks[0] if self.tasks else None

    def next_n(self, n: int) -> list[ReconTask]:
        return self.tasks[:max(0, n)]

    def total_eig(self) -> float:
        return round(sum(t.eig_bits for t in self.tasks), 5)


class ReconPlanner:
    """Ranks recon tasks by VOI. Stateless; `plan` is pure over its inputs."""

    def __init__(self, collectors: list[Collector], *, default_prior: float = _DEFAULT_PRIOR) -> None:
        self._collectors = list(collectors)
        self._default_prior = default_prior

    def plan(
        self,
        subjects: list[EntityRef],
        *,
        priors: dict[str, float] | None = None,
        already_run: set[tuple[str, str]] | None = None,
    ) -> ReconPlan:
        """Build the ordered plan over ``subjects`` × applicable collectors.

        ``priors`` maps a source_kind value → prior belief that querying it reveals
        new surface (from source-yield learning). ``already_run`` is a set of
        ``(subject_node_id, collector_name)`` tasks completed this session — their
        prior collapses so the planner stops re-querying an exhausted source."""
        priors = priors or {}
        already_run = already_run or set()
        tasks: list[ReconTask] = []
        for subject in subjects:
            for c in self._collectors:
                if not c.accepts(subject):
                    continue
                base = priors.get(c.source_kind.value, self._default_prior)
                ran = (subject.node_id, c.name) in already_run
                prior = _DAMP_ALREADY_RUN if ran else min(max(base, 0.0), 1.0)
                eig = expected_information_gain(prior, tpr=c.tpr, fpr=c.fpr)
                cost = max(1e-6, c.cost)
                rationale = (
                    f"{c.source_kind.value} on {subject.node_id}: "
                    f"prior {prior:.2f}, EIG {eig:.3f} bits / cost {cost:.1f}"
                    + (" (already run — damped)" if ran else "")
                )
                tasks.append(ReconTask(
                    collector=c.name, source_kind=c.source_kind, subject=subject,
                    prior=round(prior, 5), eig_bits=round(eig, 5),
                    eig_per_cost=round(eig / cost, 5), cost=cost, rationale=rationale))
        # highest EIG-per-cost first; deterministic tie-break
        tasks.sort(key=lambda t: (-t.eig_per_cost, t.cost, t.subject.node_id, t.collector))
        return ReconPlan(tasks=tasks)
