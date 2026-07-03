"""
Behavioural tests for world-model-aware leaf selection.

The myopic planner picks the single highest ``prior*value/cost`` open leaf
(``GoalTree.best_open_leaf``). This wave adds an *optional* path-aware
selector (``GoalTree.best_open_leaf_pathaware`` / the ``world`` param on the
``Planner``) that, given a WorldModel + crown-jewel objective kinds + a
foothold, biases selection toward leaves lying on a high-value attack path
to a DATASTORE crown-jewel.

These tests prove:
  * with ``world=None`` the path-aware selector returns *exactly* what the
    greedy selector returns (backward compatibility);
  * with a world model wired in, a lower-base-score leaf that sits on the
    best path to a DATASTORE crown-jewel is preferred over a higher-base-score
    off-path leaf;
  * the ``surface_to_node_id`` helper resolves URLs/paths/ids to node ids;
  * the Planner threads the world model through ``step()`` and selects the
    on-path leaf.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.planner.goal_tree import (
    CostEstimate, GoalTree, surface_to_node_id,
)
from framework.v2.worldmodel import Edge, EdgeKind, Node, NodeKind, WorldModel


# ---------------------------------------------------------------------------
# world-model fixture: entry --REACHABLE_FROM--> web(on-path) --> db (crown)
# with an off-path node web2 that no path to a crown-jewel traverses.
# ---------------------------------------------------------------------------


def _build_world() -> WorldModel:
    w = WorldModel()

    def node(nid: str, kind: NodeKind, **attrs: object) -> None:
        w.add_node(Node(
            id=nid, kind=kind, attrs=attrs,
            provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0,
        ))

    def edge(src: str, dst: str, conf: float) -> None:
        w.add_edge(Edge(
            src=src, dst=dst, kind=EdgeKind.REACHABLE_FROM,
            provenance="obs-1", confidence=conf, first_seen=0, last_seen=0,
        ))

    node("entry", NodeKind.ENDPOINT, url="https://t.invalid/entry")
    node("web_on", NodeKind.WEBAPP, url="https://t.invalid/on-path")
    node("db", NodeKind.DATASTORE, url="https://t.invalid/db")
    # An off-path node the crown-jewel route never touches.
    node("web_off", NodeKind.WEBAPP, url="https://t.invalid/off-path")

    edge("entry", "web_on", 0.9)
    edge("web_on", "db", 0.9)
    return w


def _tree_with_two_leaves() -> tuple[GoalTree, int, int]:
    """A tree whose greedy winner is the OFF-path leaf (higher base score),
    while the ON-path leaf has a lower base score. Returns (tree, on, off)."""
    t = GoalTree()
    root = t.add(label="root", kind="root")
    on_path = t.add(
        label="on-path", kind="leaf", parent_id=root,
        prior=0.3, value=1.0, surface="/on-path",
        estimate=CostEstimate(requests=1),
    )  # base score = 0.30
    off_path = t.add(
        label="off-path", kind="leaf", parent_id=root,
        prior=0.5, value=1.0, surface="/off-path",
        estimate=CostEstimate(requests=1),
    )  # base score = 0.50 -> greedy winner
    return t, on_path, off_path


# ---------------------------------------------------------------------------
# surface_to_node_id helper
# ---------------------------------------------------------------------------


def test_surface_maps_by_exact_url() -> None:
    w = _build_world()
    assert surface_to_node_id(w, "https://t.invalid/on-path") == "web_on"


def test_surface_maps_by_path_only() -> None:
    w = _build_world()
    assert surface_to_node_id(w, "/db") == "db"


def test_surface_maps_by_direct_node_id() -> None:
    w = _build_world()
    assert surface_to_node_id(w, "entry") == "entry"


def test_surface_unmatched_returns_none() -> None:
    w = _build_world()
    assert surface_to_node_id(w, "https://other.invalid/nope") is None
    assert surface_to_node_id(w, "") is None


# ---------------------------------------------------------------------------
# selector: greedy vs path-aware
# ---------------------------------------------------------------------------


def test_greedy_prefers_higher_base_score() -> None:
    t, on_path, off_path = _tree_with_two_leaves()
    # Baseline: myopic greedy picks the higher-base-score OFF-path leaf.
    assert t.best_open_leaf().id == off_path


def test_pathaware_with_world_none_equals_greedy() -> None:
    t, on_path, off_path = _tree_with_two_leaves()
    greedy = t.best_open_leaf()
    aware = t.best_open_leaf_pathaware(world=None)
    assert aware is not None and greedy is not None
    assert aware.id == greedy.id == off_path


def test_pathaware_prefers_on_path_leaf() -> None:
    w = _build_world()
    t, on_path, off_path = _tree_with_two_leaves()
    # Sanity: greedy would pick off_path.
    assert t.best_open_leaf().id == off_path
    # Path-aware, biased toward the DATASTORE crown-jewel from foothold
    # "entry", must flip to the lower-base-score ON-path leaf.
    chosen = t.best_open_leaf_pathaware(
        world=w, objective_kinds=[NodeKind.DATASTORE], source="entry",
    )
    assert chosen is not None
    assert chosen.id == on_path


def test_pathaware_no_reachable_crownjewel_falls_back_to_greedy() -> None:
    w = _build_world()
    t, on_path, off_path = _tree_with_two_leaves()
    # No PRINCIPAL crown-jewel exists in this world -> no boosts -> greedy.
    chosen = t.best_open_leaf_pathaware(
        world=w, objective_kinds=[NodeKind.PRINCIPAL], source="entry",
    )
    assert chosen is not None
    assert chosen.id == t.best_open_leaf().id == off_path


def test_pathaware_missing_source_falls_back_to_greedy() -> None:
    w = _build_world()
    t, on_path, off_path = _tree_with_two_leaves()
    chosen = t.best_open_leaf_pathaware(
        world=w, objective_kinds=[NodeKind.DATASTORE], source="nonexistent",
    )
    assert chosen is not None
    assert chosen.id == off_path


def test_pathaware_empty_tree_returns_none() -> None:
    w = _build_world()
    t = GoalTree()
    t.add(label="root", kind="root")  # no leaves
    assert t.best_open_leaf_pathaware(
        world=w, objective_kinds=[NodeKind.DATASTORE], source="entry",
    ) is None


# ---------------------------------------------------------------------------
# Planner integration: the world model threads through step()
# ---------------------------------------------------------------------------


def _isolate_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2.common import paths
    tdir = tmp_path / "targets"
    monkeypatch.setattr(paths, "targets_root", lambda: tdir)
    monkeypatch.setattr(paths, "target_dir", lambda slug: tdir / slug)
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr(
        paths, "planner_state", lambda slug: tdir / slug / ".planner-state.json"
    )


def test_planner_step_uses_pathaware_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Planner wired with a world model + DATASTORE objective + foothold
    selects the on-path leaf on its first step, even though the off-path leaf
    has a higher base score. Proves the wiring in planner.step()."""
    _isolate_paths(tmp_path, monkeypatch)

    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.coordinator import Coordinator
    from framework.v2.agents.executor_proto import DeterministicExecutor
    from framework.v2.agents.exploit_agent import ExploitAgent
    from framework.v2.agents.hypothesis_agent import HypothesisAgent
    from framework.v2.planner import Budget, Planner, Pruner, Watchdog

    slug = "wm-scoring"
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id(slug)

    executor = DeterministicExecutor(outcomes={})
    hyp = HypothesisAgent(bb, slug)
    exp = ExploitAgent(bb, slug, executor=executor, max_per_step=2)
    coord = Coordinator(
        blackboard=bb, engagement_slug=slug, agents=[hyp, exp],
        max_ticks=50, quiet_ticks=2,
    )

    w = _build_world()
    t, on_path, off_path = _tree_with_two_leaves()
    budget = Budget(request_max=1000, token_max=100_000.0, wall_clock_max_seconds=30.0)

    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug,
        tree=t, budget=budget,
        pruner=Pruner(), watchdog=Watchdog(engagement_slug=slug, tree=t, budget=budget),
        coordinator_ticks_per_step=2, scope_check=False,
        world=w, objectives=[NodeKind.DATASTORE], world_source="entry",
    )

    sr = planner.step()
    # The planner claimed/dispatched the ON-path leaf, not the greedy off-path.
    assert sr.leaf_id == on_path
    assert sr.leaf_label == "on-path"

    bb.close()


def test_planner_without_world_uses_greedy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no world model, the planner picks the greedy (off-path) leaf —
    identical to legacy behaviour."""
    _isolate_paths(tmp_path, monkeypatch)

    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.coordinator import Coordinator
    from framework.v2.agents.executor_proto import DeterministicExecutor
    from framework.v2.agents.exploit_agent import ExploitAgent
    from framework.v2.agents.hypothesis_agent import HypothesisAgent
    from framework.v2.planner import Budget, Planner, Pruner, Watchdog

    slug = "wm-scoring-greedy"
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id(slug)

    executor = DeterministicExecutor(outcomes={})
    hyp = HypothesisAgent(bb, slug)
    exp = ExploitAgent(bb, slug, executor=executor, max_per_step=2)
    coord = Coordinator(
        blackboard=bb, engagement_slug=slug, agents=[hyp, exp],
        max_ticks=50, quiet_ticks=2,
    )

    t, on_path, off_path = _tree_with_two_leaves()
    budget = Budget(request_max=1000, token_max=100_000.0, wall_clock_max_seconds=30.0)

    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug,
        tree=t, budget=budget,
        pruner=Pruner(), watchdog=Watchdog(engagement_slug=slug, tree=t, budget=budget),
        coordinator_ticks_per_step=2, scope_check=False,
    )

    sr = planner.step()
    assert sr.leaf_id == off_path

    bb.close()
