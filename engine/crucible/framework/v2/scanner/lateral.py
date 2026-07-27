"""C4 — internal attack paths / lateral movement over the FUSED world.

The pre-fusion chaining (:meth:`scanner.orchestrator.AutonomousCampaign.chain_findings`) reasons
over the web/scan findings, but it runs BEFORE sensor fusion, so it never sees the cloud / IAM
facts the fusion oracles confirm. This module closes that gap: AFTER fusion, it bridges the
GROUNDED cloud oracle facts into attacker-traversable edges, then re-runs the SAME deterministic
path search from the attacker to the crown jewels — surfacing the internal lateral-movement routes
that only exist once the cloud posture is folded in.

INVARIANT (near-zero-FP / oracle authority). Every edge this module MATERIALISES traces to a FIRED
cloud oracle fact already in the world — admitted by the EXACT confirming provenance
(``oracle:active_exposure`` / ``oracle:policy_path``), not merely the GROUNDED tier and not the
finding-ID prefix (both of which a non-cloud-oracle finding could satisfy). It mints NO facts and
invents NO trust it cannot ground:

  * ``oracle:active_exposure`` (the ACTIVE_EXPOSURE oracle: an UNAUTHENTICATED GET actually reached
    the resource) -> ``attacker --REACHED--> res``. Anonymous reachability means ANYONE — including
    the external attacker — reaches it; the edge is a direct consequence of the fired oracle, exactly
    as the base chain records ``attacker.reach`` for a confirmed web finding.
  * ``oracle:policy_path`` (the POLICY_PATH oracle: principal P holds a grant path over the resource
    dominating the requested access) -> ``P --HAS_GRANT--> res``. A faithful restatement of the grant
    the oracle confirmed for P.

The attacker -> principal frontier is NEVER fabricated here. ``best_paths`` returns a route only when
the attacker can already reach P via edges ANOTHER confirmed fact / chain operator established (a held
credential VALID_ON P, an owned host with a session, an assume-role edge, …), so a dangling confirmed
grant — a principal the attacker cannot reach — yields NO path. Pure + deterministic (id-sorted
traversal, caller-supplied monotonic ``seq``, no wallclock / rng); idempotent (edge identity is
``(src, dst, kind)``, so a re-run upserts rather than duplicates).

HONEST SCOPE (what a surfaced route is grounded in). The EDGES this module writes are oracle-grounded
as above. A surfaced ``AttackPath`` may ALSO traverse pre-existing edges the fusion/intel layer folded
in — notably the operator's declared IAM topology (``CAN_ASSUME`` / ``MEMBER_OF`` / ``HAS_GRANT`` from
``intel.from_cloud``, an ``intel``-tier restatement of the operator's OWN export). Those interior hops
are real ground truth about the operator's environment, not a fabrication, but they are NOT themselves
oracle-fired — so a route is "grounded in the confirmed cloud facts + the operator's declared topology",
which is a weaker claim than "every hop independently oracle-proven". We never assert the latter."""

from __future__ import annotations

from typing import Any

from ..worldmodel.attacker import ATTACKER_ID, AttackerState
from ..worldmodel.models import (
    Edge,
    EdgeKind,
    Node,
    NodeKind,
)
from ..worldmodel.pathsearch import best_paths
from .detection_cost import path_detection_cost
from .orchestrator import _CROWN_KINDS, _TRAVERSABLE, AttackPath, ChainedConclusion

# The EXACT provenance of each cloud oracle whose fact C4 bridges. We gate on this string — the oracle
# that actually FIRED — NOT on the finding's grounding TIER (``GROUNDING_GROUNDED`` also admits
# ``cert:`` / ``finding:`` / ``evidence:``) and NOT on the finding-ID prefix (the ``finding:<kind>:<key>``
# id namespace is SHARED with the web scanner's ``bug_class`` minter, so a web finding could carry a
# colliding ``finding:active_exposure:*`` id at a different provenance). Provenance-exact admission is
# the honest equivalent of "a fired cloud oracle confirmed this" — it keeps the bridge from ever
# restamping a non-cloud-oracle finding as ``oracle:*`` and matches this module's stated invariant.
_ACTIVE_EXPOSURE_ORACLE = "oracle:active_exposure"
_POLICY_PATH_ORACLE = "oracle:policy_path"


def _subject_of(world: Any, finding_id: str) -> str | None:
    """The subject node id a finding EVIDENCES. Returns the subject ONLY when the finding has EXACTLY
    ONE ``EVIDENCES`` edge — the unambiguous single fact :func:`engage_fusion._project_oracle_fact`
    writes. TWO subjects mean a finding-ID key collision (two resources of different KINDS sharing a
    ``key``, since the finding id omits the resource kind), where the finding's ``principal`` attr
    (last-writer-wins on the collided node) may no longer correspond to a given subject — so we return
    ``None`` and the caller SKIPS it (fail-closed: a false negative, never a cross-wired grant).
    ``None`` too when the edge is absent (defensive)."""
    subs = [e.dst for e in world.out_edges(finding_id, [EdgeKind.EVIDENCES])]
    return subs[0] if len(subs) == 1 else None


def bridge_confirmed_cloud_facts(world: Any, *, seq_base: int) -> int:
    """Materialise attacker-traversable edges from the GROUNDED cloud oracle facts already folded
    into ``world`` so the deterministic path search can find internal lateral routes. Returns the
    number of edges added. Pure + idempotent (see the module invariant).

    Admits a finding ONLY when its provenance is the EXACT cloud oracle that fired
    (``oracle:active_exposure`` / ``oracle:policy_path``) — not merely the GROUNDED tier and not the
    finding-ID prefix. Every edge it adds restates that oracle's fact (``active_exposure`` -> ``attacker
    REACHED res``; ``policy_path`` -> ``principal HAS_GRANT res``). It never asserts that the attacker
    controls a principal — that frontier must come from another confirmed edge."""
    added = 0
    seq = int(seq_base)
    for f in world.nodes_of_kind(NodeKind.FINDING):
        if f.provenance not in (_ACTIVE_EXPOSURE_ORACLE, _POLICY_PATH_ORACLE):
            continue
        res_id = _subject_of(world, f.id)
        if not res_id or not world.has_node(res_id):
            continue
        if f.provenance == _ACTIVE_EXPOSURE_ORACLE:
            # the anonymously-reachable resource is reached by the external attacker directly.
            AttackerState(world).ensure(seq=seq)
            world.add_edge(Edge(
                src=ATTACKER_ID, dst=res_id, kind=EdgeKind.REACHED,
                attrs={"via": "active_exposure"}, provenance="oracle:active_exposure",
                confidence=float(f.confidence or 0.95), first_seen=seq, last_seen=seq))
            added += 1
            seq += 1
        else:  # _POLICY_PATH_ORACLE
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
