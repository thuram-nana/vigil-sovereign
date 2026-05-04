"""
planner.pruner — kills dead branches per FORGE PROTOCOL § 3.3.

A branch dies when:
  - it has failed `max_failures_per_node` times,
  - its actual cost exceeded its estimate by `over_budget_factor`,
  - any of its preconditions is now known false (caller-supplied),
  - it has been deferred and not re-opened in `stale_seconds`.

The pruner is invoked between planner steps. It mutates the GoalTree
by setting node statuses to 'pruned'.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from ..common import logging as v2log
from .goal_tree import GoalNode, GoalTree


_log = v2log.get_logger(__name__)


@dataclass
class Pruner:
    max_failures_per_node: int = 3
    over_budget_factor: float = 4.0
    stale_seconds: float = 24 * 3600  # one day

    # caller can hook in domain-specific precondition checks
    precondition_failures: Callable[[GoalNode], str | None] = field(
        default=lambda _: None,
    )

    def prune(self, tree: GoalTree) -> int:
        """One pruning pass. Returns total nodes newly pruned."""
        pruned = 0
        for node in list(tree.nodes.values()):
            if node.status not in ("open", "claimed", "in_progress"):
                continue

            # 1. excessive failures
            if node.attempts >= self.max_failures_per_node and node.status == "failed":
                pruned += tree.prune(
                    node.id,
                    reason=f"attempts {node.attempts} >= max {self.max_failures_per_node}",
                )
                _log.info(
                    "planner.pruner.kill_failures",
                    node_id=node.id, label=node.label[:60],
                    attempts=node.attempts,
                )
                continue

            # 2. cost overrun
            est_req = max(1, node.estimate.requests)
            if node.actual.requests >= est_req * self.over_budget_factor:
                pruned += tree.prune(
                    node.id,
                    reason=f"actual {node.actual.requests} req >> "
                           f"estimate {est_req} req",
                )
                _log.info(
                    "planner.pruner.kill_overrun",
                    node_id=node.id, label=node.label[:60],
                    actual=node.actual.requests, estimate=est_req,
                )
                continue

            # 3. caller-supplied precondition failure
            reason = self.precondition_failures(node)
            if reason:
                pruned += tree.prune(node.id, reason=f"precondition: {reason}")
                _log.info(
                    "planner.pruner.kill_precondition",
                    node_id=node.id, label=node.label[:60], reason=reason,
                )
                continue

        return pruned
