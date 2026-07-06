"""
planner.goal_tree — mutable goal tree backing the planner's search.

A goal tree decomposes the engagement's worst-case adversary
objectives into testable leaves. The planner walks the tree
best-first using:

    score(leaf) = (prior_p_success * value) / (estimated_requests + 1)

Leaves are dispatched to the MAO exploit-agent (via Hypothesis events
posted to the blackboard). When the result comes back the leaf is
marked succeeded / failed and the planner re-scores.

Trees are mutable: discoveries open new sub-goals (`expand_node`),
prunes kill dead branches (`prune_node`), and supersession at the
blackboard layer keeps an audit trail.
"""

from __future__ import annotations

import itertools
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Iterator, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

if TYPE_CHECKING:  # avoid a hard import-time dependency on the world-model.
    from collections.abc import Callable

    from ..worldmodel.graph import WorldModel
    from ..worldmodel.models import Edge, NodeKind


# ---------------------------------------------------------------------------
# World-model-aware leaf scoring (optional, additive)
# ---------------------------------------------------------------------------


def surface_to_node_id(world: "WorldModel", surface: str) -> str | None:
    """Best-effort map a leaf's ``surface`` string onto a world-model node id.

    A leaf's surface is free text (a full URL like ``https://h/api/x``, a path
    like ``/api/x``, or a bare node id). The world-model keys nodes by id and
    records URLs/hosts/paths in each node's ``attrs`` bag. This helper resolves
    a surface to a node id deterministically (nodes are scanned in id-sorted
    order, first match wins) using, in priority order:

      1. a direct node-id match (``surface`` *is* a node id);
      2. an exact ``attrs['url'] == surface`` match;
      3. a host+path match against ``attrs['url']`` (or path-only when the
         surface carries no host), or ``attrs['path'] == path``;
      4. a host match against ``attrs['host']`` or the node id.

    Returns ``None`` when nothing plausibly matches — the caller then treats
    the leaf as off-path (no boost). Pure and read-only on ``world``."""
    if not surface:
        return None
    if world.has_node(surface):
        return surface

    if "://" in surface:
        parsed = urlparse(surface)
        host = parsed.hostname
        path = parsed.path or None
    elif surface.startswith("/"):
        host, path = None, surface
    else:
        host, path = surface, None

    # Pass 2: exact url match.
    for node in world.all_nodes():
        if node.attrs.get("url") == surface:
            return node.id

    # Pass 3/4: host+path / path-only / host-only best-effort matches.
    for node in world.all_nodes():
        attrs = node.attrs
        url = attrs.get("url")
        if isinstance(url, str):
            u = urlparse(url)
            if host is not None and u.hostname == host and (
                path is None or u.path == path
            ):
                return node.id
            if host is None and path is not None and u.path == path:
                return node.id
        if isinstance(attrs.get("path"), str) and path is not None and attrs["path"] == path:
            return node.id
        if host is not None and (attrs.get("host") == host or node.id == host):
            return node.id
    return None


def _path_node_boosts(
    world: "WorldModel",
    *,
    source: str,
    objective_kinds: "Iterable[NodeKind]",
    boost: float,
    k: int,
    weight_fn: "Callable[[Edge], float] | None",
    edge_kinds: "Iterable | None",
) -> dict[str, float]:
    """Map each world-model node that lies on one of the ``k`` best routes
    from ``source`` to a crown-jewel (a node whose kind is in
    ``objective_kinds``) to a score **multiplier** ``>= 1.0``.

    The multiplier rewards two things: *proximity* (nodes nearer the objective
    matter more — you are one hop from the prize) and *path quality* (a route
    on a higher-ranked, higher-confidence best-path matters more than a
    marginal one). Concretely, for a node at position ``pos`` (0 = source) on
    the rank-``r`` best path of ``n`` nodes with weakest-link confidence
    ``c``::

        multiplier = 1 + boost * ((pos + 1) / n) * (c / (r + 1))

    A node on several paths keeps its strongest (max) multiplier. Returns an
    empty dict when the source is absent or no crown-jewel is reachable — the
    caller then falls back to the plain greedy score. Deterministic and
    read-only on ``world``."""
    from ..worldmodel import pathsearch

    if not world.has_node(source):
        return {}
    paths = pathsearch.best_paths(
        world, source, objective_kinds, weight_fn, k=k, edge_kinds=edge_kinds,
    )
    boosts: dict[str, float] = {}
    for rank, path in enumerate(paths):
        node_ids = path.nodes
        n = len(node_ids)
        conf = path.min_confidence
        for pos, nid in enumerate(node_ids):
            proximity = (pos + 1) / n
            quality = conf / (rank + 1)
            val = 1.0 + boost * proximity * quality
            if val > boosts.get(nid, 1.0):
                boosts[nid] = val
    return boosts


# ---------------------------------------------------------------------------
# Expected-information-gain (value-of-information) leaf scoring
# ---------------------------------------------------------------------------


def _bernoulli_entropy(p: float) -> float:
    """Binary Shannon entropy H(p) in bits. 0 at p in {0, 1}, max 1 at p=0.5."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))


def expected_information_gain(prior: float, *, tpr: float = 0.9, fpr: float = 0.02) -> float:
    """Expected information gain (bits) of running a probe against a Bernoulli
    belief ``prior`` that a bug is present.

    The probe fires with true-positive rate ``tpr`` and false-positive rate
    ``fpr``; its binary outcome (fire / no-fire) is observed, and
    ``EIG = H(prior) - E_outcome[H(posterior)]``. This is genuinely NOT the
    greedy ``prior``: a near-certain belief (prior ~0.99) has little to learn
    (low EIG) while a coin-flip belief (prior ~0.5) has the most (high EIG). So a
    planner maximising EIG probes to REDUCE UNCERTAINTY, not to chase high priors."""
    p = min(max(prior, 0.0), 1.0)
    h_prior = _bernoulli_entropy(p)
    p_fire = p * tpr + (1.0 - p) * fpr
    if p_fire <= 0.0 or p_fire >= 1.0:
        return 0.0  # the probe outcome is a foregone conclusion -> no information
    post_fire = (p * tpr) / p_fire
    post_nofire = (p * (1.0 - tpr)) / (1.0 - p_fire)
    e_post = p_fire * _bernoulli_entropy(post_fire) + (1.0 - p_fire) * _bernoulli_entropy(post_nofire)
    return max(0.0, h_prior - e_post)


GoalStatus = Literal[
    "open",         # not yet attempted
    "claimed",      # planner picked this as the next branch
    "in_progress",  # MAO is testing it
    "succeeded",    # confirmed bug
    "failed",       # refuted / not exploitable here
    "pruned",       # killed by pruner / preconditions falsified
    "deferred",     # deliberately not pursued this engagement
]


class CostEstimate(BaseModel):
    requests: int = 1
    tokens: float = 200.0
    minutes: float = 1.0


class CostActual(BaseModel):
    requests: int = 0
    tokens: float = 0.0
    seconds: float = 0.0


class GoalNode(BaseModel):
    """One node in the goal tree."""

    id: int
    parent_id: int | None = None
    label: str
    kind: Literal["root", "goal", "subgoal", "leaf"] = "subgoal"
    status: GoalStatus = "open"
    prior_p_success: float = Field(ge=0.0, le=1.0, default=0.5)
    value: float = Field(default=1.0, description="Relative impact / importance.")
    estimate: CostEstimate = Field(default_factory=CostEstimate)
    actual: CostActual = Field(default_factory=CostActual)
    children: list[int] = Field(default_factory=list)
    attempts: int = 0
    last_failure_reason: str = ""
    bug_class: str = ""        # filled for leaves
    surface: str = ""          # filled for leaves
    notes: str = ""

    def is_leaf(self) -> bool:
        return self.kind == "leaf"

    def score(self) -> float:
        if self.status not in ("open", "claimed"):
            return 0.0
        cost = max(1, self.estimate.requests)
        return (self.prior_p_success * self.value) / cost

    def eig_score(self, *, tpr: float = 0.9, fpr: float = 0.02) -> float:
        """Value-of-information score: expected information gain (about whether
        this leaf's bug is present) times the leaf's value, per unit cost. Unlike
        :meth:`score` (greedy on prior), this rewards resolving UNCERTAIN,
        consequential leaves — probing where a confirmation is most informative."""
        if self.status not in ("open", "claimed"):
            return 0.0
        cost = max(1, self.estimate.requests)
        eig = expected_information_gain(self.prior_p_success, tpr=tpr, fpr=fpr)
        return (eig * self.value) / cost


@dataclass
class GoalTree:
    """In-memory goal tree.  Persists via to_json / from_json (resume)."""

    nodes: dict[int, GoalNode] = field(default_factory=dict)
    _id_counter: itertools.count = field(default_factory=lambda: itertools.count(1))

    def add(
        self,
        *,
        label: str,
        parent_id: int | None = None,
        kind: Literal["root", "goal", "subgoal", "leaf"] = "subgoal",
        prior: float = 0.5,
        value: float = 1.0,
        bug_class: str = "",
        surface: str = "",
        estimate: CostEstimate | None = None,
    ) -> int:
        if parent_id is not None and parent_id not in self.nodes:
            raise KeyError(f"parent {parent_id} not in tree")
        new_id = next(self._id_counter)
        node = GoalNode(
            id=new_id, parent_id=parent_id, label=label, kind=kind,
            prior_p_success=prior, value=value,
            bug_class=bug_class, surface=surface,
            estimate=estimate or CostEstimate(),
        )
        self.nodes[new_id] = node
        if parent_id is not None:
            self.nodes[parent_id].children.append(new_id)
        return new_id

    def get(self, node_id: int) -> GoalNode:
        return self.nodes[node_id]

    def root(self) -> GoalNode | None:
        for n in self.nodes.values():
            if n.parent_id is None and n.kind == "root":
                return n
        return None

    def open_leaves(self) -> Iterator[GoalNode]:
        for n in self.nodes.values():
            if n.kind == "leaf" and n.status == "open":
                yield n

    def best_open_leaf(self) -> GoalNode | None:
        scored = [(l.score(), l) for l in self.open_leaves()]
        if not scored:
            return None
        scored.sort(key=lambda t: t[0], reverse=True)
        return scored[0][1]

    def best_open_leaf_pathaware(
        self,
        *,
        world: "WorldModel | None" = None,
        objective_kinds: "Iterable[NodeKind] | None" = None,
        source: str | None = None,
        boost: float = 2.0,
        k: int = 3,
        weight_fn: "Callable[[Edge], float] | None" = None,
        edge_kinds: "Iterable | None" = None,
    ) -> GoalNode | None:
        """World-model-aware leaf selection.

        Identical to :meth:`best_open_leaf` (myopic greedy on
        ``prior * value / cost``) **unless** a ``world`` + ``objective_kinds``
        + ``source`` are supplied. When they are, each open leaf whose
        ``surface`` maps (via :func:`surface_to_node_id`) onto a node lying on
        a high-value :func:`worldmodel.pathsearch.best_paths` route from
        ``source`` to a crown-jewel gets its greedy score multiplied by a
        path-membership/proximity factor (see :func:`_path_node_boosts`).
        Leaves off every path — and every leaf when the source can't reach a
        crown-jewel — keep their plain greedy score, so this degrades exactly
        to :meth:`best_open_leaf`.

        Falls back to :meth:`best_open_leaf` verbatim when the world model is
        not supplied, so the default (world=None) path is byte-for-byte the
        legacy behaviour. Deterministic: ties break on ascending leaf id."""
        if world is None or not objective_kinds or source is None:
            return self.best_open_leaf()

        boosts = _path_node_boosts(
            world,
            source=source,
            objective_kinds=objective_kinds,
            boost=boost,
            k=k,
            weight_fn=weight_fn,
            edge_kinds=edge_kinds,
        )
        if not boosts:
            # No crown-jewel reachable: nothing to bias toward — behave greedily.
            return self.best_open_leaf()

        # (-effective_score, leaf_id) sorts to max score, then lowest id.
        scored: list[tuple[float, int, GoalNode]] = []
        for leaf in self.open_leaves():
            base = leaf.score()
            nid = surface_to_node_id(world, leaf.surface)
            mult = boosts.get(nid, 1.0) if nid is not None else 1.0
            scored.append((-(base * mult), leaf.id, leaf))
        if not scored:
            return None
        scored.sort(key=lambda t: (t[0], t[1]))
        return scored[0][2]

    def best_open_leaf_voi(
        self,
        *,
        world: "WorldModel | None" = None,
        objective_kinds: "Iterable[NodeKind] | None" = None,
        source: str | None = None,
        boost: float = 2.0,
        k: int = 3,
        weight_fn: "Callable[[Edge], float] | None" = None,
        edge_kinds: "Iterable | None" = None,
        tpr: float = 0.9,
        fpr: float = 0.02,
    ) -> GoalNode | None:
        """Select the open leaf with the highest EXPECTED-INFORMATION-GAIN per
        unit cost (optionally weighted by a world-model path boost, exactly as in
        :meth:`best_open_leaf_pathaware`).

        This is a genuinely different objective from the greedy
        ``prior * value / cost``: it runs the probe that most reduces uncertainty
        about a consequential fact, so an uncertain (near-0.5-prior) high-value
        leaf can outrank a near-certain one greedy would pick first. Deterministic:
        ties break on ascending leaf id."""
        boosts: dict[str, float] = {}
        if world is not None and objective_kinds and source is not None:
            boosts = _path_node_boosts(
                world, source=source, objective_kinds=objective_kinds,
                boost=boost, k=k, weight_fn=weight_fn, edge_kinds=edge_kinds,
            )
        scored: list[tuple[float, int, GoalNode]] = []
        for leaf in self.open_leaves():
            base = leaf.eig_score(tpr=tpr, fpr=fpr)
            nid = surface_to_node_id(world, leaf.surface) if (world is not None and boosts) else None
            mult = boosts.get(nid, 1.0) if nid is not None else 1.0
            scored.append((-(base * mult), leaf.id, leaf))
        if not scored:
            return None
        scored.sort(key=lambda t: (t[0], t[1]))
        return scored[0][2]

    def mark_status(
        self, node_id: int, status: GoalStatus, *, reason: str = "",
    ) -> None:
        node = self.nodes[node_id]
        node.status = status
        if status == "failed" and reason:
            node.last_failure_reason = reason
        if status in ("claimed", "in_progress"):
            node.attempts += 1

    def charge(
        self, node_id: int, *,
        requests: int = 0, tokens: float = 0.0, seconds: float = 0.0,
    ) -> None:
        a = self.nodes[node_id].actual
        a.requests += requests
        a.tokens += tokens
        a.seconds += seconds

    def expand(
        self,
        node_id: int,
        children: list[dict[str, str | float]],
    ) -> list[int]:
        """Add children to a non-leaf node. Used by URK rollout
        (`hypothesize`-driven expansion).  Each child dict carries
        keys: label, prior, value, bug_class, surface, kind."""
        added: list[int] = []
        for c in children:
            cid = self.add(
                parent_id=node_id,
                label=str(c.get("label", "?")),
                kind=c.get("kind", "leaf"),  # type: ignore[arg-type]
                prior=float(c.get("prior", 0.4)),
                value=float(c.get("value", 1.0)),
                bug_class=str(c.get("bug_class", "")),
                surface=str(c.get("surface", "")),
            )
            added.append(cid)
        return added

    def prune(self, node_id: int, *, reason: str = "") -> int:
        """Mark a node and all its descendants pruned. Returns count."""
        n = 0
        stack = [node_id]
        while stack:
            cur = stack.pop()
            node = self.nodes.get(cur)
            if node is None:
                continue
            if node.status not in ("succeeded", "failed", "pruned"):
                node.status = "pruned"
                if reason:
                    node.last_failure_reason = reason
                n += 1
            stack.extend(node.children)
        return n

    def stats(self) -> dict[str, int]:
        out = {s: 0 for s in (
            "open", "claimed", "in_progress", "succeeded",
            "failed", "pruned", "deferred",
        )}
        out["total"] = 0
        out["leaves"] = 0
        for n in self.nodes.values():
            out["total"] += 1
            out[n.status] = out.get(n.status, 0) + 1
            if n.kind == "leaf":
                out["leaves"] += 1
        return out

    # ---- serialisation (used by resume) ----

    def to_json(self) -> str:
        payload = {
            "nodes": {
                str(nid): n.model_dump() for nid, n in self.nodes.items()
            },
            "next_id": next(self._id_counter),
        }
        # rewind the counter so subsequent IDs are correct after dumping
        self._id_counter = itertools.count(payload["next_id"])
        return json.dumps(payload, indent=2, default=str)

    @classmethod
    def from_json(cls, text: str) -> GoalTree:
        payload = json.loads(text)
        nodes = {int(k): GoalNode.model_validate(v)
                 for k, v in payload["nodes"].items()}
        tree = cls(nodes=nodes)
        tree._id_counter = itertools.count(int(payload.get("next_id", 1)))
        return tree
