"""
Behavioural tests for the budget-bounded MULTI-STEP lookahead leaf selector
(``GoalTree.best_open_leaf_lookahead`` / the ``use_lookahead`` flag on ``Planner``).

The myopic selectors (greedy / path-aware / VoI) pick the single best open leaf. The
lookahead selector instead returns the leaf that BEGINS the best SEQUENCE of leaves
affordable within the remaining request budget, where a sequence earns a bonus for
COMPLETING a crown-jewel attack path. These tests prove:

  * with no world / objectives / source it is byte-identical to the myopic pick;
  * when the budget FORCES a choice, it commits to finishing the best affordable route
    rather than spending the budget on the single highest-scoring (off-path) leaf — so its
    pick differs from both greedy and the myopic path-aware selector;
  * when the route is unaffordable it defers to the myopic single-best pick;
  * it is deterministic; and the Planner threads ``use_lookahead`` through ``step()``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.planner.goal_tree import CostEstimate, GoalTree
from framework.v2.worldmodel import Edge, EdgeKind, Node, NodeKind, WorldModel


# ---------------------------------------------------------------------------
# fixture: a TWO-hop crown-jewel route entry -> mid -> db(DATASTORE), plus an
# off-path node the route never touches. Completing the route needs BOTH the
# leaf on `mid` and the leaf on `db` — a genuine multi-leaf sequence.
# ---------------------------------------------------------------------------


def _world() -> WorldModel:
    w = WorldModel()

    def node(nid: str, kind: NodeKind, url: str) -> None:
        w.add_node(Node(id=nid, kind=kind, attrs={"url": url},
                        provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))

    def edge(src: str, dst: str, conf: float) -> None:
        w.add_edge(Edge(src=src, dst=dst, kind=EdgeKind.REACHABLE_FROM,
                        provenance="obs-1", confidence=conf, first_seen=0, last_seen=0))

    node("entry", NodeKind.ENDPOINT, "https://t.invalid/entry")
    node("mid", NodeKind.WEBAPP, "https://t.invalid/mid")
    node("db", NodeKind.DATASTORE, "https://t.invalid/db")
    node("off", NodeKind.WEBAPP, "https://t.invalid/off")   # off every crown-jewel route
    edge("entry", "mid", 0.9)
    edge("mid", "db", 0.9)
    return w


def _tree() -> tuple[GoalTree, dict[str, int]]:
    """Leaves: two ON-path leaves (mid, db) whose confirmation together COMPLETES the crown-jewel
    route, and one high-score OFF-path leaf that BOTH the greedy AND the myopic path-aware
    selector prefer (its raw 0.9 beats each on-path leaf's path-boosted score). Only the
    lookahead, valuing route COMPLETION, drops the off-path leaf to finish the route. Added mid,
    db, off so id(mid) < id(db) < id(off)."""
    t = GoalTree()
    root = t.add(label="root", kind="root")
    mid = t.add(label="on-mid", kind="leaf", parent_id=root, prior=0.3, value=1.0,
                surface="/mid", estimate=CostEstimate(requests=1))   # boosted base ~0.66
    db = t.add(label="on-db", kind="leaf", parent_id=root, prior=0.3, value=1.0,
               surface="/db", estimate=CostEstimate(requests=1))     # boosted base ~0.84
    off = t.add(label="off", kind="leaf", parent_id=root, prior=0.9, value=1.0,
                surface="/off", estimate=CostEstimate(requests=1))   # base 0.90 -> myopic winner
    return t, {"mid": mid, "db": db, "off": off}


_OBJ = [NodeKind.DATASTORE]


# ---------------------------------------------------------------------------
# selector behaviour
# ---------------------------------------------------------------------------


def test_lookahead_world_none_equals_greedy() -> None:
    t, ids = _tree()
    # No world context -> the sequence carries no path bonus, so the first leaf IS the myopic
    # (greedy) pick: byte-identical backward compatibility.
    chosen = t.best_open_leaf_lookahead(world=None)
    assert chosen is not None and chosen.id == t.best_open_leaf().id == ids["off"]


def test_lookahead_no_reachable_crownjewel_falls_back_to_greedy() -> None:
    w = _world()
    t, ids = _tree()
    # An objective kind no node has -> no path -> defer to the myopic pick (greedy off-path).
    chosen = t.best_open_leaf_lookahead(
        world=w, objective_kinds=[NodeKind.CLOUD_RESOURCE], source="entry", budget_requests=4)
    assert chosen is not None and chosen.id == t.best_open_leaf().id == ids["off"]


def test_lookahead_commits_budget_to_completing_the_route() -> None:
    w = _world()
    t, ids = _tree()
    # Greedy squanders the budget on the high-score OFF-path leaf...
    assert t.best_open_leaf().id == ids["off"]
    # ...AND so does the myopic path-aware selector (off's raw 0.9 beats each on-path leaf's
    # path-boosted score)...
    aware = t.best_open_leaf_pathaware(world=w, objective_kinds=_OBJ, source="entry")
    assert aware is not None and aware.id == ids["off"]
    # ...but the lookahead, given a budget that fits exactly the two-leaf route, DROPS the
    # off-path leaf and commits to COMPLETING the route — executing that plan's highest-value
    # step (db, nearest the crown jewel) now. A pick neither myopic selector makes.
    chosen = t.best_open_leaf_lookahead(
        world=w, objective_kinds=_OBJ, source="entry", budget_requests=2, depth=2)
    assert chosen is not None
    assert chosen.id != ids["off"]              # did not squander budget off-path
    assert chosen.id in (ids["mid"], ids["db"])  # committed to the route
    assert chosen.id == ids["db"]               # the plan's highest-value step (db)


def test_lookahead_defers_when_route_unaffordable() -> None:
    w = _world()
    t, ids = _tree()
    aware = t.best_open_leaf_pathaware(world=w, objective_kinds=_OBJ, source="entry")
    # Budget for only ONE leaf: the two-leaf route can never complete, so no route bonus is
    # reachable and the lookahead defers to the myopic single-best pick (the off-path leaf).
    chosen = t.best_open_leaf_lookahead(
        world=w, objective_kinds=_OBJ, source="entry", budget_requests=1, depth=3)
    assert chosen is not None and aware is not None
    assert chosen.id == aware.id == ids["off"]


def test_lookahead_is_deterministic() -> None:
    w = _world()
    t, ids = _tree()
    a = t.best_open_leaf_lookahead(world=w, objective_kinds=_OBJ, source="entry", budget_requests=2)
    b = t.best_open_leaf_lookahead(world=w, objective_kinds=_OBJ, source="entry", budget_requests=2)
    assert a is not None and b is not None and a.id == b.id == ids["db"]


def _world_3hop() -> WorldModel:
    """A THREE-hop crown-jewel route entry -> a -> b -> db(DATASTORE): completing it needs the
    three on-path leaves a, b, db — a route a lossy beam would prune before it could complete."""
    w = WorldModel()

    def node(nid: str, kind: NodeKind, url: str) -> None:
        w.add_node(Node(id=nid, kind=kind, attrs={"url": url},
                        provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))

    def edge(src: str, dst: str, conf: float) -> None:
        w.add_edge(Edge(src=src, dst=dst, kind=EdgeKind.REACHABLE_FROM,
                        provenance="obs-1", confidence=conf, first_seen=0, last_seen=0))

    node("entry", NodeKind.ENDPOINT, "https://t.invalid/entry")
    node("a", NodeKind.WEBAPP, "https://t.invalid/a")
    node("b", NodeKind.WEBAPP, "https://t.invalid/b")
    node("db", NodeKind.DATASTORE, "https://t.invalid/db")
    edge("entry", "a", 0.9)
    edge("a", "b", 0.9)
    edge("b", "db", 0.9)
    return w


def test_lookahead_completes_multi_hop_route_beam_would_prune() -> None:
    # Regression for the W1.2 review finding: a route's low-value PREFIX subsets ({a}, {a,b})
    # carry no completion bonus, so a lossy greedy beam prunes them before the route can complete
    # and the selector degrades to the myopic (off-path) pick. Exact route-subset evaluation must
    # instead commit to finishing the affordable 3-hop route.
    w = _world_3hop()
    t = GoalTree()
    root = t.add(label="root", kind="root")
    a = t.add(label="a", kind="leaf", parent_id=root, prior=0.2, value=1.0,
              surface="/a", estimate=CostEstimate(requests=1))
    b = t.add(label="b", kind="leaf", parent_id=root, prior=0.2, value=1.0,
              surface="/b", estimate=CostEstimate(requests=1))
    db = t.add(label="db", kind="leaf", parent_id=root, prior=0.2, value=1.0,
               surface="/db", estimate=CostEstimate(requests=1))
    off1 = t.add(label="off1", kind="leaf", parent_id=root, prior=0.95, value=1.0,
                 surface="/off1", estimate=CostEstimate(requests=1))
    off2 = t.add(label="off2", kind="leaf", parent_id=root, prior=0.95, value=1.0,
                 surface="/off2", estimate=CostEstimate(requests=1))

    # Both myopic selectors chase a high-prior OFF-path leaf.
    assert t.best_open_leaf().id == off1
    assert t.best_open_leaf_pathaware(world=w, objective_kinds=_OBJ, source="entry").id in (off1, off2)

    # Budget fits exactly the 3-leaf route; lookahead commits to COMPLETING it (executing its
    # highest-value step, db — nearest the crown jewel), not the greedy off-path leaf. With the
    # earlier beam this returned off1 at the default width.
    chosen = t.best_open_leaf_lookahead(
        world=w, objective_kinds=_OBJ, source="entry", budget_requests=3, depth=3)
    assert chosen is not None
    assert chosen.id in (a, b, db)          # committed to the route
    assert chosen.id not in (off1, off2)    # did NOT degrade to the myopic off-path pick
    assert chosen.id == db                  # the plan's highest-value step


def test_lookahead_empty_tree_returns_none() -> None:
    w = _world()
    t = GoalTree()
    t.add(label="root", kind="root")   # no leaves
    assert t.best_open_leaf_lookahead(
        world=w, objective_kinds=_OBJ, source="entry", budget_requests=4) is None


# ---------------------------------------------------------------------------
# Planner integration: use_lookahead threads through step()
# ---------------------------------------------------------------------------


def _isolate_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2.common import paths
    tdir = tmp_path / "targets"
    monkeypatch.setattr(paths, "targets_root", lambda: tdir)
    monkeypatch.setattr(paths, "target_dir", lambda slug: tdir / slug)
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr(paths, "planner_state", lambda slug: tdir / slug / ".planner-state.json")


def test_planner_step_uses_lookahead(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A Planner with use_lookahead=True + a world + DATASTORE objective + foothold and a budget
    that fits exactly the two-leaf route dispatches the ROUTE-COMPLETING on-path leaf first, not
    the greedy off-path leaf. Proves the wiring in planner.step()."""
    _isolate_paths(tmp_path, monkeypatch)

    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.coordinator import Coordinator
    from framework.v2.agents.executor_proto import DeterministicExecutor
    from framework.v2.agents.exploit_agent import ExploitAgent
    from framework.v2.agents.hypothesis_agent import HypothesisAgent
    from framework.v2.planner import Budget, Planner, Pruner, Watchdog

    slug = "lookahead"
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id(slug)

    executor = DeterministicExecutor(outcomes={})
    coord = Coordinator(
        blackboard=bb, engagement_slug=slug,
        agents=[HypothesisAgent(bb, slug), ExploitAgent(bb, slug, executor=executor, max_per_step=2)],
        max_ticks=50, quiet_ticks=2,
    )

    w = _world()
    t, ids = _tree()
    budget = Budget(request_max=2, token_max=100_000.0, wall_clock_max_seconds=30.0)
    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug, tree=t, budget=budget,
        pruner=Pruner(), watchdog=Watchdog(engagement_slug=slug, tree=t, budget=budget),
        coordinator_ticks_per_step=2, scope_check=False,
        world=w, objectives=_OBJ, world_source="entry",
        use_lookahead=True, lookahead_depth=2,
    )

    sr = planner.step()
    assert sr.leaf_id == ids["db"]   # committed to completing the route, not the greedy off-path

    bb.close()


def test_planner_default_is_not_lookahead(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default Planner (use_lookahead unset) keeps legacy greedy selection — dispatches the
    off-path leaf, byte-identical to before this change."""
    _isolate_paths(tmp_path, monkeypatch)

    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.coordinator import Coordinator
    from framework.v2.agents.executor_proto import DeterministicExecutor
    from framework.v2.agents.exploit_agent import ExploitAgent
    from framework.v2.agents.hypothesis_agent import HypothesisAgent
    from framework.v2.planner import Budget, Planner, Pruner, Watchdog

    slug = "lookahead-off"
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id(slug)

    coord = Coordinator(
        blackboard=bb, engagement_slug=slug,
        agents=[HypothesisAgent(bb, slug),
                ExploitAgent(bb, slug, executor=DeterministicExecutor(outcomes={}), max_per_step=2)],
        max_ticks=50, quiet_ticks=2,
    )
    t, ids = _tree()
    budget = Budget(request_max=1000, token_max=100_000.0, wall_clock_max_seconds=30.0)
    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug, tree=t, budget=budget,
        pruner=Pruner(), watchdog=Watchdog(engagement_slug=slug, tree=t, budget=budget),
        coordinator_ticks_per_step=2, scope_check=False,
    )
    assert planner.use_lookahead is False
    sr = planner.step()
    assert sr.leaf_id == ids["off"]

    bb.close()
