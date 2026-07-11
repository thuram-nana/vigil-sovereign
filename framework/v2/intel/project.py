"""
intel.project — THE KEYSTONE. Project an Observation onto the world-model.

This one seam is what makes the intelligence engine "reason, not collect": the moment
an Observation is projected, corroboration, refutation, and provenance are handled for
FREE by the world-model's existing Beta-belief upsert (`graph._seed_belief` /
`_update_belief`). A re-observed DNS record's `belief_mean` rises; a refuted one falls
— the thing a max-confidence scalar structurally cannot express. Every projected fact
traces back through `obs_id` to its raw artifact.

`observation_to_evidence` is the adapter to the OTHER type family: it turns an
Observation ("what is true") into a `confidence.Evidence` ("what bears on this claim's
truth") so the Scientific Confidence Engine can reason over the same facts.
"""

from __future__ import annotations

from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, Node
from .fuse import FusedBelief
from .models import Observation

_EPS = 1e-9


def _c_eff(observation: Observation) -> float:
    """The effective confidence a projection asserts: the source's truth-confidence
    pulled toward 0.5 by its reliability. A perfectly reliable A/1 affirm ≈ the raw
    confidence; a shaky source barely moves off 0.5 (it barely updates belief)."""
    r = observation.reliability()
    t = observation.truth_confidence()
    return min(1.0, max(0.0, 0.5 + r * (t - 0.5)))


def project_observation(world: WorldModel, obs: Observation, *, seq: int | None = None) -> bool:
    """Project one Observation onto the world-model (Path A, streaming). Returns True
    if it was applied, False if dropped (a reliability-0 source → unknown stays
    unknown). Order-independent: the Beta update is commutative, so replaying the same
    observations in any order yields the same belief.

    Mints the subject node (and, for an edge claim, the object node) first — `add_edge`
    requires both endpoints — then upserts with `confidence=c_eff`, so `_seed_belief` /
    `_update_belief` accumulate the Beta belief + provenance automatically."""
    if obs.reliability() <= _EPS:
        return False
    s = seq if seq is not None else obs.seq
    c = _c_eff(obs)

    def _node(ref) -> None:
        world.add_node(Node(
            id=ref.node_id, kind=ref.kind, attrs=dict(obs.attrs) if ref is obs.subject else {},
            provenance=f"intel:{obs.obs_id}", confidence=c, first_seen=s, last_seen=s,
        ))

    _node(obs.subject)
    if obs.relation is not None and obs.object is not None:
        _node(obs.object)
        world.add_edge(Edge(
            src=obs.subject.node_id, dst=obs.object.node_id, kind=obs.relation,
            attrs=dict(obs.attrs),   # carry the rationale (e.g. infer's via_host/fanout) onto the edge
            provenance=f"intel:{obs.obs_id}", confidence=c, first_seen=s, last_seen=s,
        ))
    return True


def project_fused(world: WorldModel, obs: Observation, fused: FusedBelief, *, seq: int) -> None:
    """Project a BATCH-fused posterior (Path B / backfill): write the Beta(alpha, beta)
    directly rather than re-deriving it observation-by-observation. Used when replaying
    a durable observation log."""
    world.add_node(Node(
        id=obs.subject.node_id, kind=obs.subject.kind, attrs=dict(obs.attrs),
        provenance=f"intel-fused:{obs.obs_id}", confidence=fused.as_confidence(),
        alpha=fused.alpha, beta=fused.beta, first_seen=seq, last_seen=seq,
    ))
    if obs.relation is not None and obs.object is not None:
        world.add_node(Node(id=obs.object.node_id, kind=obs.object.kind, attrs={},
                            provenance=f"intel-fused:{obs.obs_id}", confidence=fused.as_confidence(),
                            first_seen=seq, last_seen=seq))
        world.add_edge(Edge(
            src=obs.subject.node_id, dst=obs.object.node_id, kind=obs.relation, attrs={},
            provenance=f"intel-fused:{obs.obs_id}", confidence=fused.as_confidence(),
            alpha=fused.alpha, beta=fused.beta, first_seen=seq, last_seen=seq))


_FINDING_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def _coerce_severity(value: Any, *, default: str = "Info") -> str:
    """Map a free-form severity onto the FindingPayload Literal, defaulting safely.
    ``bb.post`` validates the finding payload, so an out-of-set severity would silently drop
    the event — this keeps a lead event honest and always emittable."""
    s = str(value or "").strip().title()
    return s if s in _FINDING_SEVERITIES else default


def observation_to_finding_payload(obs: Observation, *, critique_status: str = "llm_advisory") -> dict:
    """Adapt a LEAD intel ``Observation`` into a ``FindingPayload``-shaped dict, graded as a LEAD.

    THE producer-unification seam: a raw sensor observation is a LEAD, not a fact. The dict this
    returns carries NO ``oracle_context`` and ``verified_by_oracle=False``, so the report grader
    (``report.grounding.grade_finding``) renders it as an unconfirmed lead and can NEVER dress it
    as a fact — a sensor observation, by construction, cannot carry a re-firing oracle proof.
    That preserves prove-don't-guess while letting a fused-sensor producer reach the unified
    report. Deterministic: a pure function of the observation (no wallclock, no rng).

    ``critique_status`` defaults to ``llm_advisory`` — the REPORTABLE-but-lead bucket the report's
    ``_reportable_from_blackboard`` picks up (``pending`` / ``objections`` would be dropped)."""
    bug_class = str(obs.attrs.get("bug_class") or obs.source_kind.value)
    subject = obs.subject.node_id
    return {
        "finding_slug": (f"lead:{obs.obs_id}"[:120]) or bug_class,
        "title": f"{obs.source_kind.value} lead — {subject}",
        "severity": _coerce_severity(obs.attrs.get("severity")),
        "bug_class": bug_class,
        "surface": subject,
        "summary": (obs.evidence or obs.source or bug_class).strip() or bug_class,
        "critique_status": critique_status,
        "critique_dryrun": False,
        "oracle_context": None,
        "verified_by_oracle": False,
        "confidence": None,
        "oracle_kind": None,
        "oracle_rationale": "",
    }


def observation_to_evidence(obs: Observation, *, baseline: float = 0.5):
    """Adapt an Observation into a `confidence.Evidence` — the seam between the graph
    substrate (Observations) and the Scientific Confidence Engine (Evidence). The
    likelihood ratio is the odds of the effective confidence against the baseline; the
    weight is the source's reliability."""
    from ..confidence.models import Evidence, Provenance

    c = _c_eff(obs)
    odds = max(_EPS, c) / max(_EPS, 1.0 - c)
    base_odds = max(_EPS, baseline) / max(_EPS, 1.0 - baseline)
    lr = max(_EPS, odds / base_odds)
    return Evidence(
        seq=obs.seq, observation=obs.evidence or f"{obs.source_kind.value}:{obs.claim_key}",
        likelihood_ratio=lr, weight=max(_EPS, obs.reliability()), independence=1.0,
        provenance=Provenance(source=obs.source, ref=obs.obs_id, note=obs.collector),
    )
