"""C4 — internal attack paths / lateral movement over the FUSED world.

The pre-fusion chaining (:meth:`scanner.orchestrator.AutonomousCampaign.chain_findings`) reasons
over the web/scan findings, but it runs BEFORE sensor fusion, so it never sees the cloud / IAM
facts the fusion oracles confirm. This module closes that gap: AFTER fusion, it bridges the
GROUNDED cloud oracle facts into attacker-traversable edges, then re-runs the SAME deterministic
path search from the attacker to the crown jewels — surfacing the internal lateral-movement routes
that only exist once the cloud posture is folded in.

INVARIANT (near-zero-FP / oracle authority). Every edge this module materialises traces to a
FIRED oracle fact already in the world (``GROUNDING_GROUNDED``, ``oracle:*`` provenance). It mints
NO facts and invents NO trust it cannot ground:

  * ``finding:active_exposure:<res>`` (the ACTIVE_EXPOSURE oracle: an UNAUTHENTICATED GET actually
    reached the resource) -> ``attacker --REACHED--> res``. Anonymous reachability means ANYONE —
    including the external attacker — reaches it; the edge is a direct consequence of the fired
    oracle, exactly as the base chain records ``attacker.reach`` for a confirmed web finding.
  * ``finding:policy_path:<res>`` (the POLICY_PATH oracle: principal P holds a grant path over the
    resource dominating the requested access) -> ``P --HAS_GRANT--> res``. A faithful restatement
    of the grant the oracle confirmed for P.

The attacker -> principal frontier is NEVER fabricated here. ``best_paths`` returns a route only
when the attacker can already reach P via edges ANOTHER confirmed fact / chain operator established
(a held credential VALID_ON P, an owned host with a session, an assume-role edge, …), so a dangling
confirmed grant — a principal the attacker cannot reach — yields NO path. Pure + deterministic
(id-sorted traversal, caller-supplied monotonic ``seq``, no wallclock / rng); idempotent (edge
identity is ``(src, dst, kind)``, so a re-run upserts rather than duplicates)."""

from __future__ import annotations

from typing import Any

from ..worldmodel.attacker import ATTACKER_ID, AttackerState
from ..worldmodel.models import (
    GROUNDING_GROUNDED,
    Edge,
    EdgeKind,
    Node,
    NodeKind,
)
from ..worldmodel.pathsearch import best_paths
from .detection_cost import path_detection_cost
from .orchestrator import _CROWN_KINDS, _TRAVERSABLE, AttackPath, ChainedConclusion

_ACTIVE_EXPOSURE_PREFIX = "finding:active_exposure:"
_POLICY_PATH_PREFIX = "finding:policy_path:"


def _subject_of(world: Any, finding_id: str) -> str | None:
    """The subject node id a finding EVIDENCES — the single grounded ``finding -> subject`` edge
    :func:`engage_fusion._project_oracle_fact` writes. ``None`` if the edge is absent (defensive)."""
    for e in world.out_edges(finding_id, [EdgeKind.EVIDENCES]):
        return e.dst
    return None


def bridge_confirmed_cloud_facts(world: Any, *, seq_base: int) -> int:
    """Materialise attacker-traversable edges from the GROUNDED cloud oracle facts already folded
    into ``world`` so the deterministic path search can find internal lateral routes. Returns the
    number of edges added. Pure + idempotent (see the module invariant).

    Reads ONLY ``GROUNDING_GROUNDED`` findings; every edge it adds restates the oracle fact it came
    from (``active_exposure`` -> ``attacker REACHED res``; ``policy_path`` -> ``principal HAS_GRANT
    res``) and grounds it with the confirming ``oracle:*`` provenance. It never asserts that the
    attacker controls a principal — that frontier must come from another confirmed edge."""
    added = 0
    seq = int(seq_base)
    for f in world.nodes_of_kind(NodeKind.FINDING):
        if f.grounding != GROUNDING_GROUNDED:
            continue
        res_id = _subject_of(world, f.id)
        if not res_id or not world.has_node(res_id):
            continue
        if f.id.startswith(_ACTIVE_EXPOSURE_PREFIX):
            # the anonymously-reachable resource is reached by the external attacker directly.
            AttackerState(world).ensure(seq=seq)
            world.add_edge(Edge(
                src=ATTACKER_ID, dst=res_id, kind=EdgeKind.REACHED,
                attrs={"via": "active_exposure"}, provenance="oracle:active_exposure",
                confidence=float(f.confidence or 0.95), first_seen=seq, last_seen=seq))
            added += 1
            seq += 1
        elif f.id.startswith(_POLICY_PATH_PREFIX):
            principal = str(f.attrs.get("principal") or "").strip()
            if not principal:
                continue
            p_id = f"principal:{principal.lower()}"   # matches intel.from_cloud._principal keying
            if not world.has_node(p_id):
                # the IAM topology usually already minted the principal (a LEAD); mint an
                # intel-grounded fallback so the grounded grant edge never dangles.
                world.add_node(Node(
                    id=p_id, kind=NodeKind.PRINCIPAL, attrs={"detail": "policy-path principal"},
                    provenance=f"intel:fusion:{p_id}", confidence=0.6,
                    first_seen=seq, last_seen=seq))
            world.add_edge(Edge(
                src=p_id, dst=res_id, kind=EdgeKind.HAS_GRANT,
                attrs={"access": f.attrs.get("access"), "via": "policy_path"},
                provenance="oracle:policy_path", confidence=float(f.confidence or 0.95),
                first_seen=seq, last_seen=seq))
            added += 1
            seq += 1
    return added


def lateral_paths(world: Any, *, impact_model: Any, seq_base: int, k: int = 8) -> list[AttackPath]:
    """Internal lateral-movement routes over the FUSED world (slice C4). Bridge the GROUNDED cloud
    oracle facts into traversable edges (:func:`bridge_confirmed_cloud_facts`), ensure the attacker
    principal exists (a seedless fusion-only run may not have run the pre-fusion chain), then extract
    the best attacker -> crown-jewel paths with the SAME deterministic search + detection-cost /
    impact ranking the pre-fusion chain uses.

    Returns :class:`AttackPath` objects, stealthiest-first. Empty when the fused facts unlock no
    attacker-reachable route — a confirmed grant to a principal the attacker cannot reach yields NO
    path (near-zero-FP). Best-effort caller: the engage loop wraps this so a reasoning failure never
    sinks the engagement."""
    AttackerState(world).ensure(seq=int(seq_base))
    bridge_confirmed_cloud_facts(world, seq_base=int(seq_base) + 1)
    if world.get_node(ATTACKER_ID) is None:
        return []
    paths: list[AttackPath] = []
    for p in best_paths(world, ATTACKER_ID, _CROWN_KINDS, k=k, edge_kinds=_TRAVERSABLE):
        steps = [
            ChainedConclusion(
                src=e.src, edge=e.kind.value, dst=e.dst,
                technique=str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])),
            )
            for e in p.edges
        ]
        if not steps:
            continue
        cost = path_detection_cost([s.technique for s in steps])
        value = impact_model.impact_of(world.get_node(p.nodes[-1])) if p.nodes else 1.0
        paths.append(AttackPath(steps=steps, detection_cost=round(cost, 3),
                                value=round(float(value), 4)))
    paths.sort(key=lambda ap: ap.detection_cost)
    return paths
