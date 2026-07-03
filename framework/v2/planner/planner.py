"""
planner.planner — Autonomous Campaign Planner core.

Best-first search over the goal tree, budget-aware, watchdog-bounded.
The planner runs MAO via its coordinator and reads the blackboard to
learn whether each dispatched leaf succeeded.

Per FORGE PROTOCOL § 3.3:

  - The planner never operates outside the charter scope. Every leaf
    has its surface checked against the charter scope before
    dispatch.
  - The planner respects opsec posture (handed via the Coordinator).
  - The planner asks for operator confirmation before any action
    whose worst-case outcome is destructive — this is enforced
    upstream by `URK.opsec()` and `common/ethics.py`. The planner
    itself does not make destructive decisions.
  - The watchdog has the authority to halt the planner; the planner
    does NOT have authority to disable the watchdog.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from ..worldmodel.graph import WorldModel
    from ..worldmodel.models import NodeKind

from ..agents.blackboard import Blackboard
from ..agents.coordinator import Coordinator
from ..common import ethics
from ..common import logging as v2log
from ..common import paths
from ..common.errors import OutOfScope
from . import executor as planner_executor
from . import resume
from .budget import Budget
from .goal_tree import GoalTree
from .pruner import Pruner
from .watchdog import Watchdog


_log = v2log.get_logger(__name__)


@dataclass
class StepResult:
    """One planner step's outcome."""

    leaf_id: int | None = None
    leaf_label: str = ""
    dispatched: bool = False
    resolved: bool = False
    success: bool = False
    halted: bool = False
    halt_reason: str = ""
    no_more_leaves: bool = False
    pruned_this_step: int = 0
    error: str = ""


@dataclass
class RunReport:
    steps: int = 0
    dispatched: int = 0
    resolved: int = 0
    succeeded: int = 0
    halted: bool = False
    halt_reason: str = ""
    seconds: float = 0.0
    final_stats: dict[str, int] = field(default_factory=dict)


class Planner:
    """Owns the search loop. Drives MAO via the coordinator."""

    def __init__(
        self,
        *,
        blackboard: Blackboard,
        coordinator: Coordinator,
        engagement_slug: str,
        tree: GoalTree,
        budget: Budget,
        pruner: Pruner | None = None,
        watchdog: Watchdog | None = None,
        coordinator_ticks_per_step: int = 8,
        scope_check: bool = True,
        checkpoint_interval_s: float = resume.CHECKPOINT_INTERVAL_S,
        world: "WorldModel | None" = None,
        objectives: "Iterable[NodeKind] | None" = None,
        world_source: str | None = None,
    ) -> None:
        self.bb = blackboard
        self.coord = coordinator
        self.slug = engagement_slug
        self.engagement_id = blackboard.engagement_id(engagement_slug)
        self.tree = tree
        self.budget = budget
        self.pruner = pruner or Pruner()
        self.watchdog = watchdog or Watchdog(
            engagement_slug=engagement_slug, tree=tree, budget=budget,
        )
        self.ticks_per_step = coordinator_ticks_per_step
        self.scope_check = scope_check
        # Optional world-model-aware planning. When all three are supplied the
        # planner biases leaf selection toward leaves on high-value attack
        # paths to a crown-jewel; otherwise it stays myopic-greedy (unchanged).
        self.world = world
        self.objectives = list(objectives) if objectives is not None else None
        self.world_source = world_source
        self._cursor = 0  # blackboard cursor
        self._last_checkpoint_at = 0.0
        self.checkpoint_interval_s = checkpoint_interval_s

    # ---- main loop ----

    def step(self) -> StepResult:
        """One planner iteration.

        Order is intentional:
          1. watchdog (halt before doing anything)
          2. budget (refuse if exhausted)
          3. pruner pass
          4. pick best open leaf
          5. scope-check the leaf's surface vs charter
          6. dispatch (post Hypothesis)
          7. tick the coordinator so MAO processes it
          8. resolve from the blackboard
          9. update tree + charge budget
          10. checkpoint if interval elapsed
        """
        if self.watchdog.halted:
            return StepResult(halted=True, halt_reason=self.watchdog.halt_reason)

        ex, reason = self.budget.exhausted()
        if ex:
            return StepResult(halted=True, halt_reason=f"budget: {reason}")

        pruned = self.pruner.prune(self.tree)

        # World-model-aware selection when a world + objectives + foothold are
        # wired in; otherwise byte-for-byte the legacy greedy selection.
        if (
            self.world is not None
            and self.objectives
            and self.world_source is not None
        ):
            leaf = self.tree.best_open_leaf_pathaware(
                world=self.world,
                objective_kinds=self.objectives,
                source=self.world_source,
            )
        else:
            leaf = self.tree.best_open_leaf()
        if leaf is None:
            return StepResult(no_more_leaves=True, pruned_this_step=pruned)

        # Scope check: refuse leaves whose surface is out-of-scope per the
        # signed charter. If the charter is unsigned (draft), this is the
        # planner doing belt-and-braces; the action layer would catch it
        # too via require_in_scope.
        leaf_url = self._surface_to_url(leaf.surface)
        if self.scope_check and leaf_url:
            try:
                ethics.require_in_scope(self.slug, leaf_url)
            except OutOfScope as e:
                self.tree.mark_status(leaf.id, "pruned", reason=f"out-of-scope: {e}")
                _log.warning(
                    "planner.scope_drift_blocked",
                    leaf_id=leaf.id, url=leaf_url, error=str(e),
                )
                self.watchdog.record_step(node_id=leaf.id, error=True)
                return StepResult(
                    leaf_id=leaf.id, leaf_label=leaf.label,
                    dispatched=False, error=f"out-of-scope: {e}",
                    pruned_this_step=pruned,
                )
            except Exception:
                pass  # missing/draft charter — let the action layer enforce.

        # Pre-charge dry-run: would dispatching breach budget?
        if not self.budget.can_charge(requests=leaf.estimate.requests, tokens=leaf.estimate.tokens):
            return StepResult(halted=True, halt_reason="budget would be breached by next leaf")

        # 1. claim
        self.tree.mark_status(leaf.id, "claimed")

        # 2. dispatch
        try:
            event_id = planner_executor.dispatch_leaf(
                blackboard=self.bb, engagement_slug=self.slug, leaf=leaf,
            )
        except Exception as e:
            self.tree.mark_status(leaf.id, "failed", reason=f"dispatch error: {e}")
            self.watchdog.record_step(node_id=leaf.id, error=True)
            return StepResult(
                leaf_id=leaf.id, leaf_label=leaf.label,
                dispatched=False, error=str(e), pruned_this_step=pruned,
            )

        # 3. let MAO process it
        self.tree.mark_status(leaf.id, "in_progress")
        coord_report = self.coord.run_until_quiet(max_ticks=self.ticks_per_step)

        # 4. resolve
        outcome = planner_executor.resolve_leaf(
            blackboard=self.bb, engagement_slug=self.slug, leaf=leaf,
        )

        # 5. update tree
        if outcome.resolved:
            if outcome.success:
                self.tree.mark_status(leaf.id, "succeeded")
            else:
                self.tree.mark_status(
                    leaf.id, "failed", reason=outcome.refute_reason,
                )
        else:
            # the action chain didn't reach a Result this tick — leave it claimed
            # so subsequent steps can re-resolve.
            pass

        self.tree.charge(
            leaf.id,
            requests=outcome.requests or leaf.estimate.requests,
            tokens=leaf.estimate.tokens,
            seconds=outcome.seconds,
        )
        # Charge engagement-level budget too.
        self.budget.charge(
            requests=outcome.requests or leaf.estimate.requests,
            tokens=leaf.estimate.tokens,
        )

        # 6. watchdog records + check
        self.watchdog.record_step(
            node_id=leaf.id, error=not outcome.resolved or not outcome.success,
        )
        self.watchdog.check(
            target_urls_in_step=([leaf_url] if leaf_url else []),
        )

        # 7. checkpoint
        self._maybe_checkpoint()

        return StepResult(
            leaf_id=leaf.id, leaf_label=leaf.label,
            dispatched=True, resolved=outcome.resolved,
            success=outcome.success, pruned_this_step=pruned,
        )

    def run(
        self,
        *,
        max_steps: int | None = None,
        max_seconds: float | None = None,
    ) -> RunReport:
        report = RunReport()
        if not self.budget.started_at:
            self.budget.start()
        t0 = time.monotonic()

        n = 0
        while True:
            n += 1
            if max_steps is not None and n > max_steps:
                report.halted = True
                report.halt_reason = f"max_steps={max_steps}"
                break
            if max_seconds is not None and (time.monotonic() - t0) >= max_seconds:
                report.halted = True
                report.halt_reason = f"max_seconds={max_seconds}"
                break
            sr = self.step()
            report.steps += 1
            if sr.halted:
                report.halted = True
                report.halt_reason = sr.halt_reason
                break
            if sr.no_more_leaves:
                report.halt_reason = "no more open leaves"
                break
            if sr.dispatched:
                report.dispatched += 1
            if sr.resolved:
                report.resolved += 1
            if sr.success:
                report.succeeded += 1

        report.seconds = time.monotonic() - t0
        report.final_stats = self.tree.stats()
        # final checkpoint
        try:
            self._save_checkpoint()
        except Exception as e:
            _log.warning("planner.checkpoint_final_error", error=str(e))
        _log.info(
            "planner.run_complete",
            slug=self.slug, steps=report.steps,
            dispatched=report.dispatched, resolved=report.resolved,
            succeeded=report.succeeded, halted=report.halted,
            reason=report.halt_reason, seconds=int(report.seconds),
        )
        return report

    # ---- helpers ----

    def _surface_to_url(self, surface: str) -> str:
        """Heuristically build a URL from a leaf's surface for scope-check.
        Returns empty string when there's nothing concrete enough to check."""
        if not surface:
            return ""
        if surface.startswith(("http://", "https://")):
            return surface
        if surface.startswith("/"):
            # need a host; try the engagement's blackboard for an early observation
            for ev in self.bb.read(engagement=self.slug, kinds=["observation"], limit=1):
                from urllib.parse import urlparse
                if ev.payload.get("surface", "").startswith(("http://", "https://")):
                    host = urlparse(ev.payload["surface"]).hostname
                    if host:
                        return f"https://{host}{surface}"
            return ""
        return ""

    def _maybe_checkpoint(self) -> None:
        now = time.monotonic()
        if self._last_checkpoint_at == 0.0:
            self._last_checkpoint_at = now
            return
        if now - self._last_checkpoint_at >= self.checkpoint_interval_s:
            try:
                self._save_checkpoint()
            except Exception as e:
                _log.warning("planner.checkpoint_error", error=str(e))
            self._last_checkpoint_at = now

    def _save_checkpoint(self) -> Path:
        cursor = self.bb.latest_event_id(engagement=self.engagement_id)
        state = resume.snapshot(
            slug=self.slug, tree=self.tree, budget=self.budget,
            blackboard_cursor=cursor,
        )
        return state.to_disk()
