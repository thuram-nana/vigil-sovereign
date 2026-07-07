"""
intel.resolve — entity resolution: many references, one asset.

`api.company.com`, `backend.company.com`, `10.15.4.2`, and cert `XYZ` may be ONE asset.
`resolve()` merges the references that co-refer WITH A CONFIDENCE, and — the crucial
correctness property — links owners (ASN / netblock / org) to assets via `ASSET_OWNS`
rather than merging them in. It is deterministic and fully explainable: every merge
cites the exact `SignalHit` that justified it, and re-running over the same
observations reproduces identical clusters and ids (audit-grade).

Two steps:
  1. merge asset refs (domains/hosts) via fanout-discounted co-reference signals over a
     log-likelihood-ratio threshold (a weighted union-find);
  2. attach DEDICATED linking artifacts — a cert/host whose every presenter/resolver
     already sits in ONE cluster joins that cluster; a shared-infrastructure artifact
     (high fanout, spanning clusters) does not (the anti-catastrophe rule).
"""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field

from ..worldmodel.models import EdgeKind, NodeKind
from .models import Observation
from .refs import EntityRef
from .signals import SignalHit, SignalKind, signal_llr

MERGE_THRESHOLD_BITS = 4.0
POSSIBLE_THRESHOLD_BITS = 1.5


def _prob(llr_bits: float) -> float:
    """LLR (bits, prior odds 1:1) → posterior probability of co-reference."""
    return 1.0 / (1.0 + 2.0 ** (-llr_bits))


class MergeEvent(BaseModel):
    """One union step, citing the signal that triggered it — the derivation record."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    a: EntityRef
    b: EntityRef
    total_llr_bits: float
    probability: float
    trigger: SignalKind
    hits: list[SignalHit] = Field(default_factory=list)
    seq: int


class Entity(BaseModel):
    """A cluster of asset references believed to be one asset."""

    model_config = ConfigDict(extra="forbid")

    canonical_id: str
    tier: str = "asset"
    primary_kind: NodeKind
    members: list[EntityRef]
    confidence: float = Field(ge=0.0, le=1.0)   # bottleneck of the merge tree
    merge_log: list[MergeEvent] = Field(default_factory=list)
    owned_by: list[str] = Field(default_factory=list)   # owner-entity canonical ids (ASSET_OWNS)

    def explain(self) -> list[str]:
        return [f"{m.a.node_id} + {m.b.node_id} via {m.trigger.value} "
                f"({m.total_llr_bits:.1f} bits, p={m.probability:.3f})" for m in self.merge_log]


class OwnsLink(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: EntityRef
    entity_canonical_id: str
    via: str


class ResolveResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entities: list[Entity] = Field(default_factory=list)
    same_as: list[SignalHit] = Field(default_factory=list)   # soft "possible" links (not merged)
    owns: list[OwnsLink] = Field(default_factory=list)
    merge_log: list[MergeEvent] = Field(default_factory=list)


class _UF:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic: smaller id becomes the root
            lo, hi = sorted((ra, rb))
            self.parent[hi] = lo


def resolve(observations: list[Observation], *, seq: int = 0) -> ResolveResult:
    """Cluster asset references from a batch of observations. Deterministic + explainable."""
    presents: dict[str, set[EntityRef]] = defaultdict(set)   # cert node_id -> presenters
    resolves: dict[str, set[EntityRef]] = defaultdict(set)   # host node_id -> resolving domains
    cnames: list[tuple[EntityRef, EntityRef]] = []
    announces: list[tuple[EntityRef, EntityRef]] = []        # (asn, netblock)
    refs: dict[str, EntityRef] = {}

    for o in observations:
        refs[o.subject.node_id] = o.subject
        if o.object is not None:
            refs[o.object.node_id] = o.object
        if o.relation is EdgeKind.PRESENTS_CERT and o.object is not None:
            presents[o.object.node_id].add(o.subject)
        elif o.relation is EdgeKind.RESOLVES_TO and o.object is not None:
            resolves[o.object.node_id].add(o.subject)
        elif o.relation is EdgeKind.ANNOUNCES and o.object is not None:
            announces.append((o.subject, o.object))
        elif o.relation is EdgeKind.SAME_AS and o.object is not None:
            cnames.append((o.subject, o.object))  # explicit alias (e.g. CNAME) asserted as SAME_AS

    # --- pairwise co-reference signals (asset-tier only) --------------------
    pair_hits: dict[tuple[str, str], list[SignalHit]] = defaultdict(list)

    def _pair(a: EntityRef, b: EntityRef) -> tuple[str, str]:
        return tuple(sorted((a.node_id, b.node_id)))  # type: ignore[return-value]

    def _add(a, b, kind, bits, via, fanout):
        if a.node_id == b.node_id or not (a.is_asset_tier and b.is_asset_tier):
            return
        pair_hits[_pair(a, b)].append(SignalHit(kind=kind, a=a, b=b, llr_bits=bits, via=via, fanout=fanout))

    for cert_id, pres in presents.items():
        pl = sorted(pres, key=lambda r: r.node_id)
        fo = len(pl)
        bits = signal_llr(SignalKind.SHARED_CERT, fanout=fo)
        for i in range(len(pl)):
            for j in range(i + 1, len(pl)):
                _add(pl[i], pl[j], SignalKind.SHARED_CERT, bits, cert_id, fo)
    for host_id, doms in resolves.items():
        dl = sorted(doms, key=lambda r: r.node_id)
        fo = len(dl)
        bits = signal_llr(SignalKind.SHARED_IP, fanout=fo)
        for i in range(len(dl)):
            for j in range(i + 1, len(dl)):
                _add(dl[i], dl[j], SignalKind.SHARED_IP, bits, host_id, fo)
    for a, b in cnames:
        _add(a, b, SignalKind.CNAME, signal_llr(SignalKind.CNAME), "cname", 1)

    # --- weighted union-find over merge-threshold pairs ---------------------
    uf = _UF()
    for r in refs.values():
        if r.is_asset_tier:
            uf.find(r.node_id)
    merge_log: list[MergeEvent] = []
    same_as: list[SignalHit] = []
    edge_prob: dict[tuple[str, str], float] = {}
    ev = 0

    def _order(hs: list[SignalHit]) -> list[SignalHit]:
        # strongest first, with a total tie-break so hits order / trigger / citation are
        # input-order-independent (audit-grade determinism).
        return sorted(hs, key=lambda h: (-h.llr_bits, h.kind.value, h.via, h.a.node_id, h.b.node_id))

    for pair, raw_hits in sorted(pair_hits.items()):
        hits = _order(raw_hits)
        total = sum(h.llr_bits for h in hits)
        if total >= MERGE_THRESHOLD_BITS:
            trigger = hits[0]
            ev += 1
            p = _prob(total)
            edge_prob[pair] = p
            merge_log.append(MergeEvent(
                event_id=f"m{ev}", a=trigger.a, b=trigger.b, total_llr_bits=round(total, 3),
                probability=round(p, 5), trigger=trigger.kind, hits=hits, seq=seq))
            uf.union(pair[0], pair[1])
        elif total >= POSSIBLE_THRESHOLD_BITS:
            same_as.append(hits[0])

    # --- clusters + attach dedicated linking artifacts ----------------------
    # Seeds are the "named" assets. A host that is a RESOLUTION TARGET is an artifact
    # attached to the cluster of its resolvers (dedicated), not a seed of its own — so
    # a dedicated IP joins its domains, while a shared-hosting IP joins no one.
    _SEED_KINDS = {NodeKind.DOMAIN, NodeKind.WEBAPP, NodeKind.SERVICE,
                   NodeKind.APPLICATION, NodeKind.ENDPOINT}
    clusters: dict[str, list[EntityRef]] = defaultdict(list)
    for r in refs.values():
        is_res_target = r.kind is NodeKind.HOST and r.node_id in resolves
        if r.is_asset_tier and (r.kind in _SEED_KINDS or (r.kind is NodeKind.HOST and not is_res_target)):
            clusters[uf.find(r.node_id)].append(r)

    node_to_root = {r.node_id: uf.find(r.node_id) for c in clusters.values() for r in c}

    def _attach(artifact: EntityRef, linked: set[EntityRef]) -> None:
        roots = {node_to_root.get(r.node_id) for r in linked if r.node_id in node_to_root}
        roots.discard(None)
        if len(roots) == 1:  # dedicated to exactly one cluster
            clusters[next(iter(roots))].append(artifact)
    for cert_id, pres in presents.items():
        _attach(refs.get(cert_id) or EntityRef(kind=NodeKind.CERTIFICATE, key=cert_id.split(":", 1)[-1]), pres)
    for host_id, doms in resolves.items():
        _attach(refs.get(host_id) or EntityRef(kind=NodeKind.HOST, key=host_id.split(":", 1)[-1]), doms)

    # --- build entities (anchor the canonical id on the primary asset, not an artifact) ---
    _ANCHOR = {NodeKind.DOMAIN: 0, NodeKind.WEBAPP: 1, NodeKind.APPLICATION: 2,
               NodeKind.SERVICE: 3, NodeKind.ENDPOINT: 4, NodeKind.HOST: 5, NodeKind.CERTIFICATE: 9}
    entities: list[Entity] = []
    for root, members in sorted(clusters.items()):
        uniq = sorted({m.node_id: m for m in members}.values(),
                      key=lambda r: (_ANCHOR.get(r.kind, 7), r.node_id))
        canonical = f"ent:{uniq[0].node_id}"
        cluster_ids = {m.node_id for m in uniq}
        cl_merges = [m for m in merge_log if m.a.node_id in cluster_ids and m.b.node_id in cluster_ids]
        if cl_merges:
            conf = min(min(m.probability for m in cl_merges), 0.99)
        elif len(uniq) > 1:
            conf = 0.9   # a dedicated artifact attached, no scored merge edge
        else:
            conf = 0.6   # a lone unresolved reference
        entities.append(Entity(canonical_id=canonical, primary_kind=uniq[0].kind, members=uniq,
                               confidence=round(conf, 5), merge_log=cl_merges))

    # --- owner links (ASSET_OWNS): ASN announces a netblock that contains a host ----
    owns: list[OwnsLink] = []
    for asn, netblock in sorted(announces, key=lambda t: (t[0].node_id, t[1].node_id)):
        try:
            net = ipaddress.ip_network(netblock.key, strict=False)
        except ValueError:
            continue
        for ent in entities:
            for m in ent.members:
                if m.kind is NodeKind.HOST:
                    try:
                        if ipaddress.ip_address(m.key) in net:
                            if asn.node_id not in ent.owned_by:   # dedup on the OWNER id
                                ent.owned_by.append(asn.node_id)
                            owns.append(OwnsLink(owner=asn, entity_canonical_id=ent.canonical_id, via=netblock.node_id))
                            break
                    except ValueError:
                        continue

    # audit-grade determinism: owner lists + links independent of announcement order.
    for ent in entities:
        ent.owned_by = sorted(set(ent.owned_by))
    owns.sort(key=lambda o: (o.entity_canonical_id, o.owner.node_id, o.via))
    return ResolveResult(entities=entities, same_as=same_as, owns=owns, merge_log=merge_log)
