"""
intel.infer — sound derivation over the asset graph.

Collectors observe; resolution clusters; this module REASONS — it reads the accreted
world-model and derives facts that are true by composition but were never directly
observed. Two rules ship, both strictly within the asset/owner tiers:

  * TRANSITIVE OWNERSHIP: if an owner (ASN/org) owns a netblock, a host sits inside
    that netblock, and a domain resolves to that host, then the owner owns the domain.
    Attribution across hops — the thing an attacker's recon does by hand.

  * CO-HOSTING: two DISTINCT assets that resolve to the same host share infrastructure.
    This is weaker than "same asset" (entity resolution already merges the strong
    cases); it is a symmetric relation, and its strength is DISCOUNTED by fanout, so a
    shared-hosting IP serving hundreds of unrelated domains yields only a faint link.

The load-bearing safety property: inference stays on the intelligence substrate. It
emits `ASSET_OWNS` and `CO_HOSTED_WITH` — never `EdgeKind.OWNS`, `REACHED`, or any
attacker-state edge. A derivation that produced attacker reachability would hallucinate
access the operator has not proven; this module structurally cannot, because it only
ever writes those two asset-tier edge kinds.

Everything obeys the one-substrate principle: a derived fact is an ordinary
`Observation` (source_kind INFERENCE, a moderate reliability so derived facts are
believed LESS than observed ones, provenance ``infer:<rule>``). The caller projects
them like any other observation, and the Beta belief does the rest. A derived fact's
confidence is the WEAKEST-LINK of its premises times a per-rule discount — a chain is
never more certain than its shakiest hop.
"""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict

from ..worldmodel.graph import WorldModel
from ..worldmodel.models import EdgeKind, NodeKind
from .models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from .refs import EntityRef

# Derived facts are trustworthy but never as strong as a direct observation.
_INFER_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C2)
_OWNERSHIP_DISCOUNT = 0.85   # a clean transitive-ownership chain
_COHOST_DISCOUNT = 0.7       # co-hosting is a weaker, sharing relation

# The ONLY edge kinds inference may emit — asset-tier, never attacker-state.
_ALLOWED_DERIVED_EDGES = frozenset({EdgeKind.ASSET_OWNS, EdgeKind.CO_HOSTED_WITH})


def _mk(subject: EntityRef, relation: EdgeKind, obj: EntityRef, *, confidence: float,
        rule: str, seq: int, attrs: dict | None = None) -> Observation:
    """Mint a derived Observation. Refuses to emit any non-asset-tier edge kind — the
    structural guard that keeps inference off the attacker-state graph."""
    if relation not in _ALLOWED_DERIVED_EDGES:
        raise ValueError(
            f"intel.infer may only derive {_ALLOWED_DERIVED_EDGES}; refusing to emit "
            f"{relation!r} (deriving an attacker-state edge would hallucinate reachability)")
    oid = f"infer:{rule}:{seq}:{subject.node_id}|{relation.value}|{obj.node_id}"
    return Observation(
        obs_id=oid, source="infer", source_kind=IntelSourceKind.INFERENCE, collector="infer",
        subject=subject, relation=relation, object=obj, attrs=attrs or {},
        source_reliability=_INFER_RELIABILITY, confidence=min(1.0, max(0.0, confidence)),
        seq=seq, raw_ref=f"infer:{rule}", evidence=f"derived by {rule}")


def _ref(node_id: str) -> EntityRef:
    kind, key = node_id.split(":", 1)
    return EntityRef(kind=NodeKind(kind), key=key)


def _edge_belief(world: WorldModel, src: str, dst: str, kind: EdgeKind) -> float:
    e = world.get_edge(src, dst, kind)
    return e.belief_mean if e is not None else 0.0


def derive_transitive_ownership(world: WorldModel, *, seq: int) -> list[Observation]:
    """owner→netblock (ASSET_OWNS/ANNOUNCES) ∧ host∈netblock ∧ domain→host (RESOLVES_TO)
    ⟹ owner ASSET_OWNS domain. Weakest-link belief × ownership discount."""
    # owner → netblock, from either an org's ASSET_OWNS or an ASN's ANNOUNCES.
    owner_blocks: list[tuple[str, str, float]] = []
    for e in world.all_edges():
        if e.kind in (EdgeKind.ASSET_OWNS, EdgeKind.ANNOUNCES) and e.dst.startswith("netblock:"):
            owner_blocks.append((e.src, e.dst, e.belief_mean))

    # domain → host (resolution), grouped by host.
    host_domains: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for e in world.all_edges():
        if e.kind is EdgeKind.RESOLVES_TO and e.dst.startswith("host:"):
            host_domains[e.dst].append((e.src, e.belief_mean))

    out: list[Observation] = []
    emitted: set[tuple[str, str]] = set()
    for owner_id, nb_id, own_belief in sorted(owner_blocks):
        try:
            net = ipaddress.ip_network(nb_id.split(":", 1)[1], strict=False)
        except ValueError:
            continue
        for host_id, domains in sorted(host_domains.items()):
            try:
                if ipaddress.ip_address(host_id.split(":", 1)[1]) not in net:
                    continue
            except ValueError:
                continue
            for dom_id, res_belief in sorted(domains):
                key = (owner_id, dom_id)
                if key in emitted:
                    continue
                emitted.add(key)
                conf = min(own_belief, res_belief) * _OWNERSHIP_DISCOUNT
                out.append(_mk(_ref(owner_id), EdgeKind.ASSET_OWNS, _ref(dom_id),
                               confidence=conf, rule="transitive_ownership", seq=seq,
                               attrs={"via_host": host_id, "via_netblock": nb_id}))
    return out


def derive_co_hosting(world: WorldModel, *, seq: int) -> list[Observation]:
    """Distinct domains resolving to the same host share infrastructure. Symmetric
    CO_HOSTED_WITH; strength discounted by fanout (a busy shared host links its tenants
    only faintly)."""
    host_domains: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for e in world.all_edges():
        if e.kind is EdgeKind.RESOLVES_TO and e.dst.startswith("host:"):
            host_domains[e.dst].append((e.src, e.belief_mean))

    out: list[Observation] = []
    for host_id, domains in sorted(host_domains.items()):
        uniq = sorted({d: b for d, b in domains}.items())
        fanout = len(uniq)
        if fanout < 2:
            continue
        fanout_factor = 1.0 / (1.0 + math.log2(fanout))   # busy host → faint link
        for i in range(len(uniq)):
            for j in range(i + 1, len(uniq)):
                a_id, a_b = uniq[i]
                b_id, b_b = uniq[j]
                conf = min(a_b, b_b) * _COHOST_DISCOUNT * fanout_factor
                # symmetric: emit the canonical (sorted) direction only; consumers treat
                # CO_HOSTED_WITH as undirected.
                out.append(_mk(_ref(a_id), EdgeKind.CO_HOSTED_WITH, _ref(b_id),
                               confidence=conf, rule="co_hosting", seq=seq,
                               attrs={"via_host": host_id, "fanout": fanout}))
    return out


def derive_registrant_ownership(world: WorldModel, *, seq: int) -> list[Observation]:
    """Domains sharing a registrant email are owned by the same registrant — attributed
    to a synthetic IDENTITY owner via ASSET_OWNS (NEVER merged: two domains with one
    registrant are the same OWNER, not the same asset). Strongly fanout-discounted, so a
    privacy-proxy address on thousands of domains attributes almost nothing — the same
    anti-catastrophe rule the resolver uses."""
    by_email: dict[str, list[str]] = defaultdict(list)
    for n in world.all_nodes():
        if n.kind is NodeKind.DOMAIN:
            em = str(n.attrs.get("registrant_email", "")).strip().lower()
            if em and "@" in em:
                by_email[em].append(n.id)

    out: list[Observation] = []
    for email, domains in sorted(by_email.items()):
        doms = sorted(set(domains))
        fanout = len(doms)
        if fanout < 2:
            continue   # need ≥2 domains to attribute SHARED ownership
        factor = 1.0 / (1.0 + math.log2(fanout))   # privacy proxies (huge fanout) → ~0
        identity = EntityRef(kind=NodeKind.IDENTITY, key=email)
        for dom_id in doms:
            out.append(_mk(identity, EdgeKind.ASSET_OWNS, _ref(dom_id),
                           confidence=0.7 * factor, rule="registrant_ownership", seq=seq,
                           attrs={"registrant_email": email}))
    return out


def derive(world: WorldModel, *, seq: int) -> list[Observation]:
    """Run all derivation rules over ``world`` and return the derived Observations
    (NOT projected — the caller projects them so the one-substrate belief update owns
    the write). Deterministic and read-only on ``world``."""
    return (derive_transitive_ownership(world, seq=seq)
            + derive_co_hosting(world, seq=seq)
            + derive_registrant_ownership(world, seq=seq))


def derive_and_project(world: WorldModel, *, seq: int) -> int:
    """Convenience: derive over ``world`` and project the results back onto it. Returns
    the number of derived facts newly applied.

    A derivation is a deterministic FUNCTION of the graph, not independent evidence — so
    re-deriving the same fact must not re-corroborate it (that would inflate belief in a
    fixpoint loop). An already-derived edge (one whose provenance is exactly this derived
    obs) is therefore skipped, making the pass idempotent and fixpoint-safe."""
    from .project import project_observation

    derived = derive(world, seq=seq)
    applied = 0
    for i, obs in enumerate(derived):
        if obs.relation is not None and obs.object is not None:
            existing = world.get_edge(obs.subject.node_id, obs.object.node_id, obs.relation)
            if existing is not None and existing.provenance == f"intel:{obs.obs_id}":
                continue   # this exact derivation is already recorded — no new information
        if project_observation(world, obs, seq=seq + i):
            applied += 1
    return applied
