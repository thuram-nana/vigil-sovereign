"""Unit tests for the planner's individual components."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from framework.v2.planner.budget import Budget
from framework.v2.planner.goal_tree import (
    CostEstimate, GoalNode, GoalTree,
)
from framework.v2.planner.pruner import Pruner
from framework.v2.planner.resume import (
    restore_budget, restore_tree, snapshot,
)


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


def test_budget_starts_unstarted() -> None:
    b = Budget()
    assert b.elapsed_seconds() == 0.0
    assert not b.exhausted()[0]


def test_budget_request_cap_fail_closed() -> None:
    b = Budget(request_max=10, wall_clock_max_seconds=10_000)
    b.start()
    b.charge(requests=10)
    ex, reason = b.exhausted()
    assert ex
    assert "request" in reason


def test_budget_token_cap_fail_closed() -> None:
    b = Budget(token_max=100.0, wall_clock_max_seconds=10_000)
    b.start()
    b.charge(tokens=100.0)
    ex, _ = b.exhausted()
    assert ex


def test_budget_wall_clock_cap() -> None:
    b = Budget(wall_clock_max_seconds=0.05)
    b.start()
    time.sleep(0.06)
    ex, reason = b.exhausted()
    assert ex
    assert "wall-clock" in reason


def test_budget_can_charge_pre_check() -> None:
    b = Budget(request_max=5)
    b.start()
    b.charge(requests=3)
    assert b.can_charge(requests=2) is True
    assert b.can_charge(requests=3) is False


def test_budget_round_trip_to_dict() -> None:
    b = Budget(request_max=100, token_max=200.0)
    b.start()
    b.charge(requests=10, tokens=30.0)
    d = b.to_dict()
    assert d["request_max"] == 100
    assert d["request_used"] == 10
    assert d["token_used"] == pytest.approx(30.0)


# ---------------------------------------------------------------------------
# GoalTree
# ---------------------------------------------------------------------------


def test_tree_basic_construction() -> None:
    t = GoalTree()
    root = t.add(label="root", kind="root", prior=1.0, value=1.0)
    g = t.add(label="goal", kind="goal", parent_id=root)
    leaf = t.add(label="leaf", kind="leaf", parent_id=g, bug_class="IDOR", surface="/x")
    assert t.root().id == root
    assert t.get(g).children == [leaf]
    assert next(t.open_leaves()).id == leaf


def test_tree_score_picks_best() -> None:
    t = GoalTree()
    root = t.add(label="r", kind="root")
    cheap_high = t.add(
        label="cheap-high", kind="leaf", parent_id=root,
        prior=0.9, value=2.0, estimate=CostEstimate(requests=1),
    )
    cheap_low = t.add(
        label="cheap-low", kind="leaf", parent_id=root,
        prior=0.1, value=1.0, estimate=CostEstimate(requests=1),
    )
    expensive_high = t.add(
        label="expensive-high", kind="leaf", parent_id=root,
        prior=0.9, value=2.0, estimate=CostEstimate(requests=20),
    )
    best = t.best_open_leaf()
    assert best.id == cheap_high


def test_tree_status_transitions() -> None:
    t = GoalTree()
    r = t.add(label="r", kind="root")
    leaf = t.add(label="l", kind="leaf", parent_id=r)
    t.mark_status(leaf, "claimed")
    assert t.get(leaf).status == "claimed"
    assert t.get(leaf).attempts == 1
    t.mark_status(leaf, "failed", reason="refuted")
    assert t.get(leaf).last_failure_reason == "refuted"


def test_tree_prune_kills_subtree() -> None:
    t = GoalTree()
    r = t.add(label="r", kind="root")
    g = t.add(label="g", kind="goal", parent_id=r)
    l1 = t.add(label="l1", kind="leaf", parent_id=g)
    l2 = t.add(label="l2", kind="leaf", parent_id=g)
    n = t.prune(g, reason="dead branch")
    assert n == 3  # g + l1 + l2
    assert t.get(g).status == "pruned"
    assert t.get(l1).status == "pruned"
    assert t.get(l2).status == "pruned"


def test_tree_serialise_round_trip() -> None:
    t = GoalTree()
    r = t.add(label="r", kind="root")
    leaf = t.add(label="leaf", kind="leaf", parent_id=r, bug_class="IDOR")
    t.mark_status(leaf, "succeeded")
    js = t.to_json()
    t2 = GoalTree.from_json(js)
    assert t2.get(leaf).label == "leaf"
    assert t2.get(leaf).status == "succeeded"
    assert t2.get(leaf).bug_class == "IDOR"


def test_tree_stats() -> None:
    t = GoalTree()
    r = t.add(label="r", kind="root")
    a = t.add(label="a", kind="leaf", parent_id=r)
    b = t.add(label="b", kind="leaf", parent_id=r)
    t.mark_status(a, "succeeded")
    t.mark_status(b, "failed")
    s = t.stats()
    assert s["total"] == 3
    assert s["leaves"] == 2
    assert s["succeeded"] == 1
    assert s["failed"] == 1


# ---------------------------------------------------------------------------
# Pruner
# ---------------------------------------------------------------------------


def test_pruner_kills_overrun() -> None:
    t = GoalTree()
    r = t.add(label="r", kind="root")
    leaf = t.add(
        label="l", kind="leaf", parent_id=r,
        estimate=CostEstimate(requests=2),
    )
    t.charge(leaf, requests=10)  # 5x estimate, default factor 4
    p = Pruner()
    p.prune(t)
    assert t.get(leaf).status == "pruned"


def test_pruner_kills_precondition_failures() -> None:
    t = GoalTree()
    r = t.add(label="r", kind="root")
    leaf = t.add(label="l", kind="leaf", parent_id=r, bug_class="X")
    p = Pruner(precondition_failures=lambda n: "missing prereq" if n.bug_class == "X" else None)
    p.prune(t)
    assert t.get(leaf).status == "pruned"
    assert "precondition" in t.get(leaf).last_failure_reason


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------


def test_snapshot_round_trip(tmp_path: Path) -> None:
    t = GoalTree()
    r = t.add(label="r", kind="root")
    leaf = t.add(label="l", kind="leaf", parent_id=r)
    t.mark_status(leaf, "succeeded")
    b = Budget(request_max=100, token_max=200.0)
    b.start()
    b.charge(requests=10, tokens=50.0)

    state = snapshot(slug="test-eng", tree=t, budget=b, blackboard_cursor=42)
    out = state.to_disk(path=tmp_path / "ckpt.json")
    assert out.is_file()

    from framework.v2.planner.resume import CheckpointState
    loaded = CheckpointState.from_disk(slug="test-eng", path=tmp_path / "ckpt.json")
    assert loaded is not None
    assert loaded.blackboard_cursor == 42

    t2 = restore_tree(loaded)
    assert t2.get(leaf).status == "succeeded"

    b2 = restore_budget(loaded)
    assert b2.request_used == 10
    assert b2.token_used == pytest.approx(50.0)
    # wall-clock RESET on restore (per design)
    assert b2.elapsed_seconds() < 1.0
