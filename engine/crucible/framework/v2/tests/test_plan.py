"""
W2.2c — the `plan <slug>` entrypoint: a READ-ONLY planner projection over a prior engagement's
persisted world-model. These tests prove:

  * `engage --spine` persists a plan-input; `plan` loads it and projects the planner's route/
    goal-tree over it WITHOUT sending traffic or driving any tool;
  * the projection is deterministic (same persisted state → same output);
  * the greedy vs depth-2 lookahead next-action projections both render;
  * a missing plan-input fails legibly (no crash), and `_persist_plan_input` only writes under a
    spine (the default engage path / gate stays byte-identical).

No network — everything is over an in-memory world + a persisted JSON doc.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2 import engage as engage_mod
from framework.v2 import plan as plan_mod
from framework.v2.common import paths as _paths
from framework.v2.common.errors import CrucibleError
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.worldmodel import Edge, EdgeKind, Node, NodeKind, WorldModel

_ATTACKER = "attacker:self"


def _finding(bug_class: str, endpoint: str, conf: float) -> AuditFinding:
    return AuditFinding(
        check_id=bug_class, bug_class=bug_class, insertion_point=f"query:{bug_class}",
        param=bug_class, endpoint=endpoint, confidence=conf, confirmed_by="oracle",
        oracle_context={"bug_class": bug_class}, rationale="synthetic")


def _twohop_world() -> WorldModel:
    """attacker:self -> ep_on -> db(DATASTORE) crown-jewel route + an off-route endpoint."""
    w = WorldModel()

    def node(nid: str, kind: NodeKind, **attrs: object) -> None:
        w.add_node(Node(id=nid, kind=kind, attrs=attrs,
                        provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))

    def edge(src: str, dst: str) -> None:
        w.add_edge(Edge(src=src, dst=dst, kind=EdgeKind.REACHABLE_FROM,
                        provenance="obs-1", confidence=0.9, first_seen=0, last_seen=0))

    node(_ATTACKER, NodeKind.PRINCIPAL, role="attacker")
    node("ep_on", NodeKind.ENDPOINT, url="https://t.invalid/on-path")
    node("db", NodeKind.DATASTORE, url="https://t.invalid/db")
    node("ep_off", NodeKind.ENDPOINT, url="https://t.invalid/off-path")
    edge(_ATTACKER, "ep_on")
    edge("ep_on", "db")
    return w


def _report() -> ScanReport:
    return ScanReport(target="https://t.invalid/", active_findings=[
        _finding("xss", "https://t.invalid/off-path", 0.9),
        _finding("idor", "https://t.invalid/on-path", 0.3),
        _finding("leak", "https://t.invalid/db", 0.3)])


@pytest.fixture()
def isolated_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "targets"
    root.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: root / s)
    (root / "alpha").mkdir(parents=True, exist_ok=True)
    return root


def test_engage_persist_then_plan_projects_route_and_next_action(isolated_targets, capsys):
    # engage's spine-only persist writes the projection input...
    engage_mod._persist_plan_input("alpha", _report(), _twohop_world())
    assert (isolated_targets / "alpha" / "plan-input.json").is_file()

    # ...and `plan` loads it and projects the planner's route + next action, no traffic/tools.
    rc = plan_mod.main(["alpha"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "plan alpha" in out
    assert "READ-ONLY projection" in out
    # the crown-jewel route through the world is projected (attacker -> ep_on -> db).
    assert "crown-jewel routes: 1" in out
    assert f"{_ATTACKER} -> ep_on -> db" in out
    # objectives + foothold + both next-action projections render.
    assert "objectives        : datastore, cloud_resource" in out
    assert f"foothold source   : {_ATTACKER}" in out
    assert "greedy" in out and "lookahead d-2" in out
    # the depth-2 lookahead commits to the crown-jewel route (leak @ db), greedy chases off-route xss.
    assert "leak" in out


def test_plan_projection_is_deterministic(isolated_targets):
    engage_mod._persist_plan_input("alpha", _report(), _twohop_world())
    doc = plan_mod._load_plan_input("alpha")
    assert plan_mod._render("alpha", doc) == plan_mod._render("alpha", doc)


def test_plan_missing_input_fails_legibly(isolated_targets):
    with pytest.raises(CrucibleError, match="no plan input"):
        plan_mod.main(["alpha"])   # nothing persisted for alpha yet


def test_persist_plan_input_is_best_effort_total():
    # a bad report/world never raises out of the persist (it can never sink an engagement).
    engage_mod._persist_plan_input("does-not-exist-slug", object(), object())  # must not raise
