"""
planner — ACP, the Autonomous Campaign Planner.

Owns the engagement loop: best-first search over a goal tree, with
budget enforcement, branch pruning, watchdog-bounded execution, and
60-second checkpoints to disk so a kill-and-resume across processes
loses no progress.

Public surface:

    from framework.v2.planner import (
        Planner, Budget, GoalTree, Pruner, Watchdog,
        seed_tree, snapshot, restore_tree, restore_budget,
    )

The planner reads the active LLM backend through URK; with no
configured backend it runs in DryRun and the search uses fixture
priors.  See V2-LIMITATIONS.md for what an unexercised live URK
implies for ACP's "autonomous" claim.
"""

from __future__ import annotations

from .budget import Budget
from .goal_tree import GoalNode, GoalTree
from .planner import Planner, RunReport, StepResult
from .pruner import Pruner
from .resume import (
    CheckpointState, restore_budget, restore_tree, snapshot,
)
from .seed import seed_tree
from .watchdog import Watchdog


__all__ = [
    "Budget",
    "CheckpointState",
    "GoalNode",
    "GoalTree",
    "Planner",
    "Pruner",
    "RunReport",
    "StepResult",
    "Watchdog",
    "restore_budget",
    "restore_tree",
    "seed_tree",
    "snapshot",
]
