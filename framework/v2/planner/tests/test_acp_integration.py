"""
Integration tests for the Autonomous Campaign Planner (ACP).

Replaces the original FORGE PROTOCOL § 3.3 acceptance ("4-hour live run
against DVWA/Juice Shop") with a fixture-replay simulation per the
operator's revised acceptance:

    "a simulated 4-hour run against a local Juice Shop instance OR
     against a fixture-replay harness if Juice Shop isn't running.
     The fixture-replay harness simulates target responses from
     canned HTTP captures so the planner can be exercised end-to-end
     without a live target."

We do not have Juice Shop running here, so this file uses the
DeterministicExecutor harness from MAO and runs the planner against
a synthetic engagement with budgets compressed into seconds.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.coordinator import Coordinator
from framework.v2.agents.critique_agent import CritiqueAgent
from framework.v2.agents.executor_proto import (
    DeterministicExecutor, ExecutionOutcome,
)
from framework.v2.agents.exploit_agent import ExploitAgent
from framework.v2.agents.hypothesis_agent import HypothesisAgent
from framework.v2.agents.memory_agent import MemoryAgent
from framework.v2.agents.models import FindingPayload
from framework.v2.agents.reporter_agent import ReporterAgent
from framework.v2.common import paths
from framework.v2.planner import (
    Budget, GoalTree, Planner, Pruner, Watchdog,
    restore_budget, restore_tree, seed_tree, snapshot,
)
from framework.v2.planner.resume import CheckpointState


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    tdir = tmp_path / "targets"
    monkeypatch.setattr(paths, "targets_root", lambda: tdir)
    monkeypatch.setattr(paths, "target_dir", lambda slug: tdir / slug)
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr(paths, "planner_state",
                         lambda slug: tdir / slug / ".planner-state.json")
    return tmp_path


def _build_engagement(
    *,
    slug: str,
    tmp_path: Path,
    outcomes: dict[tuple[str, str], ExecutionOutcome] | None = None,
):
    """Stand up a complete ACP+MAO engagement against a deterministic
    executor. Returns (planner, blackboard, agents, executor) so tests
    can inspect each layer."""
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id(slug)

    executor = DeterministicExecutor(outcomes=outcomes or {})
    hyp = HypothesisAgent(bb, slug)
    exp = ExploitAgent(bb, slug, executor=executor, max_per_step=2)
    crit = CritiqueAgent(bb, slug)
    rpt = ReporterAgent(bb, slug)
    mem = MemoryAgent(bb, slug, archetype="(test)", target_url="https://x.invalid")

    coord = Coordinator(
        blackboard=bb, engagement_slug=slug,
        agents=[hyp, exp, crit, rpt, mem],
        max_ticks=200, quiet_ticks=2,
    )

    tree = seed_tree(
        archetype_slug="generic-web", target_url="https://x.invalid",
        surfaces=["/api/v2/orders/123"],
    )

    budget = Budget(
        request_max=200, token_max=10_000.0,
        wall_clock_max_seconds=5.0,  # compressed "4-hour" budget
        rate_requests_per_min=240,
    )
    pruner = Pruner(max_failures_per_node=2, over_budget_factor=4.0)
    watchdog = Watchdog(engagement_slug=slug, tree=tree, budget=budget)

    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug,
        tree=tree, budget=budget,
        pruner=pruner, watchdog=watchdog,
        coordinator_ticks_per_step=4,
        scope_check=False,  # synthetic surfaces
        checkpoint_interval_s=0.5,
    )
    return planner, bb, [hyp, exp, crit, rpt, mem], executor


# ---------------------------------------------------------------------------
# Acceptance: simulated 4-hour run with budget exhaustion
# ---------------------------------------------------------------------------


def test_simulated_run_terminates_cleanly_on_no_more_leaves(
    isolated_paths: Path,
) -> None:
    """Run the planner against a small tree where every leaf either
    confirms or refutes deterministically. Verify it terminates on
    'no more open leaves' and produces real findings."""

    confirming_finding = FindingPayload(
        finding_slug="planner-001",
        title="planner-driven IDOR confirmed",
        severity="High", bug_class="IDOR", surface="/api/v2/orders/123",
        summary=(
            "Reproduced twice end-to-end with a working PoC: this finding "
            "is intentionally past the critique-agent's confirm threshold."
        ),
        impact="cross-tenant data exposure",
    )
    outcomes = {
        ("IDOR", "/api/v2/orders/123"): ExecutionOutcome(
            success=True, status_code=200, finding=confirming_finding,
            note="confirmed",
        ),
    }

    planner, bb, agents, _ = _build_engagement(
        slug="acp-quiet", tmp_path=isolated_paths, outcomes=outcomes,
    )
    # Generous budget for this test — we want to verify clean termination
    # when leaves are exhausted, not when budget runs out.
    planner.budget.request_max = 1000
    planner.budget.token_max = 100_000.0
    report = planner.run(max_steps=200)

    assert report.steps > 0
    assert report.dispatched > 0
    # at least one leaf succeeded (the IDOR one)
    assert report.succeeded >= 1
    # tree saw the success
    stats = report.final_stats
    assert stats["succeeded"] >= 1
    # halt reason is "no more open leaves" — the budget did not run out
    assert "no more" in report.halt_reason

    # confirmed finding made it through critique → blackboard has it
    confirmed = [
        f for f in bb.read(engagement="acp-quiet", kinds=["finding"])
        if f.payload.get("critique_status") == "confirmed"
    ]
    assert len(confirmed) >= 1

    # report file written
    report_path = paths.target_dir("acp-quiet") / "reports" / "technical.md"
    assert report_path.is_file()

    bb.close()
    for a in agents:
        if hasattr(a, "close"):
            a.close()


def test_simulated_run_halts_on_budget(isolated_paths: Path) -> None:
    """Tight budget; verify the planner halts on it and reports the reason."""
    planner, bb, agents, _ = _build_engagement(
        slug="acp-budget", tmp_path=isolated_paths,
    )
    # crush the budget so it trips on the first dispatch
    planner.budget.request_max = 2
    report = planner.run(max_steps=200)

    assert report.halted
    assert "budget" in report.halt_reason or "request" in report.halt_reason

    bb.close()
    for a in agents:
        if hasattr(a, "close"):
            a.close()


def test_checkpoint_is_written(isolated_paths: Path) -> None:
    """Checkpoint file exists after a run and contains valid state."""
    planner, bb, agents, _ = _build_engagement(
        slug="acp-ckpt", tmp_path=isolated_paths,
    )
    planner.run(max_steps=10)

    ckpt_path = paths.planner_state("acp-ckpt")
    assert ckpt_path.is_file()
    state = CheckpointState.from_disk("acp-ckpt", ckpt_path)
    assert state is not None
    # tree round-trip
    t2 = restore_tree(state)
    assert t2.stats()["total"] >= 1
    # budget round-trip
    b2 = restore_budget(state)
    assert b2.request_used >= 0

    bb.close()
    for a in agents:
        if hasattr(a, "close"):
            a.close()


def test_resume_across_kill_preserves_progress(isolated_paths: Path) -> None:
    """Run planner, kill it mid-flight, build a new planner from the
    checkpoint, verify tree statuses persist across the restart."""
    planner, bb, agents, _ = _build_engagement(
        slug="acp-resume", tmp_path=isolated_paths,
    )
    # Take a few steps to mark some leaves
    for _ in range(5):
        sr = planner.step()
        if sr.no_more_leaves or sr.halted:
            break
    # Snapshot now
    cursor_before = bb.latest_event_id(engagement="acp-resume")
    state = snapshot(
        slug="acp-resume", tree=planner.tree,
        budget=planner.budget, blackboard_cursor=cursor_before,
    )
    state.to_disk()

    # Capture status before kill
    pre_kill_stats = planner.tree.stats()

    # Simulate kill: drop references; rebuild from checkpoint
    bb.close()

    loaded = CheckpointState.from_disk("acp-resume")
    assert loaded is not None
    restored_tree = restore_tree(loaded)
    restored_budget = restore_budget(loaded)

    # Stats should match
    post_resume_stats = restored_tree.stats()
    assert pre_kill_stats["total"] == post_resume_stats["total"]
    assert pre_kill_stats["succeeded"] == post_resume_stats["succeeded"]
    assert pre_kill_stats["failed"] == post_resume_stats["failed"]

    # Budget request_used preserved
    assert restored_budget.request_used == planner.budget.request_used


def test_watchdog_halt_authority(isolated_paths: Path) -> None:
    """The watchdog can halt the planner. The planner cannot clear
    `halted`. Verify both directions."""
    planner, bb, agents, _ = _build_engagement(
        slug="acp-wd", tmp_path=isolated_paths,
    )
    # Force the watchdog to halt
    planner.watchdog._halt("test-injected halt")
    assert planner.watchdog.halted
    assert planner.watchdog.halt_reason == "test-injected halt"

    # Try to find an API on the planner that clears the watchdog. None exists.
    for attr in ("clear_watchdog", "reset_watchdog", "unhalt", "resume_watchdog"):
        assert not hasattr(planner, attr), (
            f"planner exposes {attr} — watchdog authority is broken"
        )
    # Try to set the watchdog's _halted False from the planner interface —
    # there's no setter; even direct reach-in is by design only.
    # The contract is API-level: the planner has no method to unhalt.

    report = planner.run(max_steps=5)
    assert report.halted
    assert "test-injected halt" in report.halt_reason

    bb.close()
    for a in agents:
        if hasattr(a, "close"):
            a.close()


def test_pruner_runs_inside_planner_step(isolated_paths: Path) -> None:
    """Pre-charge a leaf past its estimate so the pruner kills it on
    the next planner step."""
    planner, bb, agents, _ = _build_engagement(
        slug="acp-pruner", tmp_path=isolated_paths,
    )
    # Find some leaf and over-charge it
    leaf = next(planner.tree.open_leaves())
    leaf.estimate.requests = 1
    planner.tree.charge(leaf.id, requests=10)  # 10 >> 1*4 (over_budget_factor=4)

    sr = planner.step()
    assert sr.pruned_this_step >= 1
    assert planner.tree.get(leaf.id).status == "pruned"

    bb.close()
    for a in agents:
        if hasattr(a, "close"):
            a.close()
