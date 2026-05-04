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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Literal

from pydantic import BaseModel, Field


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
