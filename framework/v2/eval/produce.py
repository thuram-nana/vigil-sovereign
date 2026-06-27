"""
eval.produce — bridge live engagement output into the eval harness.

The eval core (models/scoring/regression/harness) is deliberately
decoupled from the rest of the framework: it scores `ProducedFinding`s
against ground truth without knowing how they were produced. This module
is the adapter that closes the loop — it reads the findings a real
engagement recorded on the blackboard and maps them to `ProducedFinding`,
so the harness measures the actual framework rather than a fixture.

Kept out of `eval/__init__` on purpose: importing it pulls the agents
layer, and the eval core must stay importable without it.

Mapping decisions:
  - Only critique-CONFIRMED findings count by default. The framework's
    own gate is that the critique-agent must confirm a finding before it
    reaches a report; eval should measure what the framework would
    actually report, not pending or objected-to claims. Override with
    `confirmed_only=False` to score raw recall before the critique gate.
  - Confidence is derived from the critique status, and the originating
    hypothesis handle is carried as a detection key so surface-light
    findings can still match ground truth that supplies the same key.
"""

from __future__ import annotations

from collections.abc import Callable

from ..agents.blackboard import Blackboard, BlackboardError
from ..agents.models import FindingPayload
from .models import BenchmarkTarget, ProducedFinding

# critique_status -> confidence the produced finding carries.
_CONFIDENCE: dict[str, float] = {
    "confirmed": 1.0,
    "pending": 0.6,
    "objections": 0.2,
}


def map_finding(payload: FindingPayload) -> ProducedFinding:
    """Map one blackboard finding to a ProducedFinding."""
    keys = [payload.derived_from_hypothesis] if payload.derived_from_hypothesis else []
    return ProducedFinding(
        bug_class=payload.bug_class,
        surface=payload.surface,
        summary=payload.title or payload.summary,
        confidence=_CONFIDENCE.get(payload.critique_status, 0.5),
        detection_keys=keys,
    )


def map_findings(
    findings: list[FindingPayload], *, confirmed_only: bool = True
) -> list[ProducedFinding]:
    """Map blackboard findings, optionally restricting to critique-confirmed."""
    selected = [
        f for f in findings if (not confirmed_only or f.critique_status == "confirmed")
    ]
    return [map_finding(f) for f in selected]


def read_blackboard_findings(bb: Blackboard, engagement_slug: str) -> list[FindingPayload]:
    """Read and validate the finding events for an engagement. Returns an
    empty list if the engagement does not exist on the blackboard."""
    try:
        rows = bb.read(engagement=engagement_slug, kinds=["finding"])
    except BlackboardError:
        return []
    out: list[FindingPayload] = []
    for row in rows:
        try:
            out.append(FindingPayload.model_validate(row.payload))
        except Exception:
            # A malformed finding row is skipped, not fatal to the run.
            continue
    return out


class BlackboardFindingProducer:
    """A `FindingProducer` that sources its findings from a live
    blackboard. Maps each benchmark target to an engagement slug (default:
    the target's own slug) and returns that engagement's confirmed
    findings as ProducedFindings.

    Usage:
        producer = BlackboardFindingProducer(bb)
        run = run_harness(corpus, producer, run_id="...")
    """

    def __init__(
        self,
        bb: Blackboard,
        *,
        slug_resolver: Callable[[BenchmarkTarget], str] | None = None,
        confirmed_only: bool = True,
    ) -> None:
        self._bb = bb
        self._resolver = slug_resolver or (lambda t: t.slug)
        self._confirmed_only = confirmed_only

    def __call__(self, target: BenchmarkTarget) -> list[ProducedFinding]:
        slug = self._resolver(target)
        findings = read_blackboard_findings(self._bb, slug)
        return map_findings(findings, confirmed_only=self._confirmed_only)
