"""
worldmodel.impact — business-impact modelling for mission-aware decision support.

The attack graph already knows the STRUCTURE of every route to a crown jewel and its
epistemic confidence. What it did not know is WORTH: two datastores were interchangeable,
and every path scored `value = 1.0`. This module supplies that missing axis — a per-node
business-impact weight — and the read-only decision helpers that consume it:

  * `ImpactModel` — criticality by node id (highest priority) or node kind, from an
    optional `targets/<slug>/impact.yaml`; a UNIFORM model (every node worth 1.0) when
    no config exists, so the default behaviour is byte-identical to before.
  * `path_value` — a route's worth = the impact of the crown jewel it reaches; this
    feeds `AttackPath.value` and therefore the existing portfolio optimiser's `value_of`.
  * `rank_choke_points` — the remediation levers ranked by the IMPACT they disconnect,
    not merely the count (fix the one edge that severs access to the payments store first).
  * `what_if_remediate` — a pure counterfactual: if these edges were fixed, which crown
    jewels become unreachable, and how much impact is removed — reusing `_reaches`, no
    graph mutation, no traffic.

Everything here is read-only over the world-model and additive: absent an impact.yaml,
paths and portfolios score exactly as they did.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from .graph import WorldModel
from .models import Edge, EdgeKind, Node, NodeKind
from .pathsearch import ChokePoint, _reaches, choke_points

_DEFAULT_IMPACT = 1.0


class ImpactModel:
    """Per-node business criticality. Lookup order: exact node id → node kind → default.
    Values are relative worths (any positive scale)."""

    def __init__(self, *, kinds: dict[str, float] | None = None,
                 nodes: dict[str, float] | None = None, default: float = _DEFAULT_IMPACT) -> None:
        self._kinds = {str(k).lower(): float(v) for k, v in (kinds or {}).items()}
        self._nodes = {str(k): float(v) for k, v in (nodes or {}).items()}
        self._default = float(default)

    @classmethod
    def uniform(cls) -> "ImpactModel":
        return cls()

    @classmethod
    def from_slug(cls, slug: str) -> "ImpactModel":
        """Load `targets/<slug>/impact.yaml` if present, else a uniform model. Total —
        a malformed/missing file degrades to uniform rather than raising."""
        try:
            from ..common import paths
            fp = Path(paths.target_dir(slug)) / "impact.yaml"
            if not fp.is_file():
                return cls.uniform()
            import yaml
            doc = yaml.safe_load(fp.read_text(encoding="utf-8")) or {}
            return cls(kinds=doc.get("kinds") or {}, nodes=doc.get("nodes") or {},
                       default=float(doc.get("default", _DEFAULT_IMPACT)))
        except Exception:
            return cls.uniform()

    def impact_of(self, node: Node | None) -> float:
        if node is None:
            return self._default
        if node.id in self._nodes:
            return self._nodes[node.id]
        return self._kinds.get(node.kind.value, self._default)

    def impact_of_id(self, world: WorldModel, node_id: str) -> float:
        return self.impact_of(world.get_node(node_id))


def path_value(world: WorldModel, path_node_ids: list[str], impact: ImpactModel) -> float:
    """A route's business worth = the impact of the crown jewel it terminates at."""
    if not path_node_ids:
        return impact._default
    return impact.impact_of(world.get_node(path_node_ids[-1]))


class RankedChoke(BaseModel):
    """A choke point weighted by the business impact it gates, not just the count."""

    model_config = ConfigDict(extra="forbid")

    edge: Edge
    betweenness: int
    disconnects: list[str] = Field(default_factory=list)
    is_bridge: bool = False
    impact_disconnected: float = 0.0   # Σ impact of the crown jewels this edge alone severs


def rank_choke_points(
    world: WorldModel,
    src: str,
    objective_kinds: Iterable[NodeKind],
    impact: ImpactModel,
    *,
    edge_kinds: Iterable[EdgeKind] | None = None,
    k: int = 8,
) -> list[RankedChoke]:
    """Choke points ranked by the IMPACT they disconnect. Reuses `choke_points` for the
    structural analysis (betweenness + exact 1-cut), then weights each by the business
    worth of the crown jewels it severs — so the top lever is the one whose removal
    protects the most value. Ties fall back to bridge-ness then betweenness."""
    chokes = choke_points(world, src, objective_kinds, edge_kinds=edge_kinds, k=k)
    ranked = [
        RankedChoke(
            edge=c.edge, betweenness=c.betweenness, disconnects=c.disconnects,
            is_bridge=c.is_bridge,
            impact_disconnected=round(sum(impact.impact_of_id(world, oid) for oid in c.disconnects), 4),
        )
        for c in chokes
    ]
    ranked.sort(key=lambda r: (-r.impact_disconnected, -r.betweenness, r.edge.key))
    return ranked


class WhatIfResult(BaseModel):
    """The counterfactual outcome of remediating a set of edges."""

    model_config = ConfigDict(extra="forbid")

    remediated_edges: list[str] = Field(default_factory=list)
    now_unreachable: list[str] = Field(default_factory=list)   # crown jewels severed
    still_reachable: list[str] = Field(default_factory=list)
    impact_removed: float = 0.0
    impact_remaining: float = 0.0


def _fmt_key(k) -> str:
    """A readable rendering of an edge key tuple (src, dst, kind)."""
    if isinstance(k, (tuple, list)) and len(k) == 3:
        return f"{k[0]} --{k[2]}--> {k[1]}"
    return str(k)


def what_if_remediate(
    world: WorldModel,
    src: str,
    objective_kinds: Iterable[NodeKind],
    remediated_edge_keys: set,
    *,
    edge_kinds: Iterable[EdgeKind] | None = None,
    impact: ImpactModel | None = None,
) -> WhatIfResult:
    """Pure counterfactual: with ``remediated_edge_keys`` removed, which crown jewels can
    the attacker no longer reach from ``src``, and how much impact is removed? Reuses
    `_reaches` (read-only, never mutates the graph); sends no traffic."""
    impact = impact or ImpactModel.uniform()
    objectives: list[str] = []
    seen: set[str] = set()
    for kind in objective_kinds:
        for node in world.nodes_of_kind(kind):
            if node.id != src and node.id not in seen:
                seen.add(node.id)
                objectives.append(node.id)

    unreachable, reachable = [], []
    for oid in sorted(objectives):
        if _reaches(world, src, oid, edge_kinds, set(remediated_edge_keys)):
            reachable.append(oid)
        else:
            unreachable.append(oid)
    return WhatIfResult(
        remediated_edges=[_fmt_key(k) for k in sorted(remediated_edge_keys, key=str)],
        now_unreachable=unreachable, still_reachable=reachable,
        impact_removed=round(sum(impact.impact_of_id(world, o) for o in unreachable), 4),
        impact_remaining=round(sum(impact.impact_of_id(world, o) for o in reachable), 4),
    )
