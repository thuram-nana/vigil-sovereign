"""
planner.resume — checkpoint and restore planner state.

Per FORGE PROTOCOL § 3.3: engagements are checkpointed every 60s to
`targets/<slug>/.planner-state.json` (gitignored). An engagement can
be killed and resumed across sessions without loss of progress.

State carried forward:
  - the goal tree (nodes, statuses, costs)
  - the budget (used / remaining)
  - the agent cursors (so MAO doesn't reprocess events)
  - the planner cursor on the blackboard

Not carried: the in-flight HTTP request that was mid-flight when the
process died (those are charged but their results are lost; the
planner re-attempts via the normal claim mechanism).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common import paths
from .budget import Budget
from .goal_tree import GoalTree


CHECKPOINT_INTERVAL_S: float = 60.0


@dataclass
class CheckpointState:
    slug: str
    saved_at: str
    tree_json: str
    budget: dict[str, float | int]
    blackboard_cursor: int
    notes: str = ""

    def to_disk(self, path: Path | None = None) -> Path:
        out = path or paths.planner_state(self.slug)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps({
                "slug": self.slug,
                "saved_at": self.saved_at,
                "tree": self.tree_json,
                "budget": self.budget,
                "blackboard_cursor": self.blackboard_cursor,
                "notes": self.notes,
            }, indent=2),
            encoding="utf-8",
        )
        return out

    @classmethod
    def from_disk(cls, slug: str, path: Path | None = None) -> CheckpointState | None:
        p = path or paths.planner_state(slug)
        if not p.is_file():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(
            slug=data["slug"],
            saved_at=data["saved_at"],
            tree_json=data["tree"],
            budget=data["budget"],
            blackboard_cursor=int(data.get("blackboard_cursor", 0)),
            notes=data.get("notes", ""),
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def snapshot(
    *,
    slug: str,
    tree: GoalTree,
    budget: Budget,
    blackboard_cursor: int,
    notes: str = "",
) -> CheckpointState:
    return CheckpointState(
        slug=slug,
        saved_at=now_iso(),
        tree_json=tree.to_json(),
        budget=budget.to_dict(),
        blackboard_cursor=blackboard_cursor,
        notes=notes,
    )


def restore_tree(state: CheckpointState) -> GoalTree:
    return GoalTree.from_json(state.tree_json)


def restore_budget(
    state: CheckpointState,
    *,
    rate_requests_per_min: int = 60,
) -> Budget:
    """Rebuild a Budget from a checkpoint dict.  Wall-clock is reset on
    restore — the operator may resume hours later, and we don't want
    paused time to count against the budget."""
    b = state.budget
    bud = Budget(
        request_max=int(b["request_max"]),
        token_max=float(b["token_max"]),
        wall_clock_max_seconds=float(b["wall_clock_max_seconds"]),
        rate_requests_per_min=rate_requests_per_min,
        request_used=int(b["request_used"]),
        token_used=float(b["token_used"]),
    )
    bud.start()
    return bud
