"""
Business-impact decision support: a per-node worth axis that feeds path value, ranks
remediation levers by the impact they sever, and answers "if we fix this, what can the
attacker no longer reach?" — all read-only, and byte-identical to before when no
impact.yaml is present (uniform = every crown jewel worth 1.0).
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.impact import (
    ImpactModel,
    path_value,
    rank_choke_points,
    what_if_remediate,
)
from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind

_EK = EdgeKind.REACHABLE_FROM


def _n(world, nid, kind):
    world.add_node(Node(id=nid, kind=kind, provenance="test", confidence=1.0,
                        first_seen=1, last_seen=1))


def _e(world, src, dst):
    return world.add_edge(Edge(src=src, dst=dst, kind=_EK, provenance="test",
                               confidence=1.0, first_seen=1, last_seen=1)).key


def _diamond() -> tuple[WorldModel, dict]:
    # attacker → gw → {dbA, dbB};  attacker → dbC (direct)
    w = WorldModel()
    for nid, k in [("host:attacker", NodeKind.HOST), ("host:gw", NodeKind.HOST),
                   ("datastore:A", NodeKind.DATASTORE), ("datastore:B", NodeKind.DATASTORE),
                   ("datastore:C", NodeKind.DATASTORE)]:
        _n(w, nid, k)
    keys = {
        "att_gw": _e(w, "host:attacker", "host:gw"),
        "gw_A": _e(w, "host:gw", "datastore:A"),
        "gw_B": _e(w, "host:gw", "datastore:B"),
        "att_C": _e(w, "host:attacker", "datastore:C"),
    }
    return w, keys


# ---- the impact model -------------------------------------------------------


def test_uniform_is_the_default_and_scores_one() -> None:
    w, _ = _diamond()
    m = ImpactModel.uniform()
    assert m.impact_of(w.get_node("datastore:A")) == 1.0
    assert path_value(w, ["host:attacker", "datastore:A"], m) == 1.0


def test_impact_lookup_order_id_then_kind_then_default() -> None:
    m = ImpactModel(kinds={"datastore": 5.0, "host": 0.5}, nodes={"datastore:A": 10.0}, default=1.0)
    w, _ = _diamond()
    assert m.impact_of(w.get_node("datastore:A")) == 10.0   # id override wins
    assert m.impact_of(w.get_node("datastore:B")) == 5.0    # kind default
    assert m.impact_of(w.get_node("host:gw")) == 0.5        # kind default
    assert m.impact_of(None) == 1.0                          # global default


def test_from_slug_loads_yaml_else_uniform(tmp_path, monkeypatch) -> None:
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "target_dir", lambda s: tmp_path / s)
    (tmp_path / "acme").mkdir(parents=True)
    (tmp_path / "acme" / "impact.yaml").write_text(
        "default: 1.0\nkinds:\n  datastore: 8\nnodes:\n  'datastore:A': 20\n", encoding="utf-8")
    m = ImpactModel.from_slug("acme")
    w, _ = _diamond()
    assert m.impact_of(w.get_node("datastore:A")) == 20.0 and m.impact_of(w.get_node("datastore:B")) == 8.0
    # a slug with no impact.yaml → uniform, never raises
    assert ImpactModel.from_slug("nonexistent").impact_of(w.get_node("datastore:A")) == 1.0


# ---- impact-ranked choke points --------------------------------------------


def test_choke_points_ranked_by_impact_not_count() -> None:
    w, keys = _diamond()
    # A is the crown jewel that matters; the att→gw edge severs A and B at once.
    m = ImpactModel(kinds={"datastore": 1.0}, nodes={"datastore:A": 100.0})
    ranked = rank_choke_points(w, "host:attacker", [NodeKind.DATASTORE], m, edge_kinds=[_EK])
    top = ranked[0]
    assert top.edge.key == keys["att_gw"]                       # the shared choke
    assert set(top.disconnects) == {"datastore:A", "datastore:B"}
    assert top.impact_disconnected == 101.0                     # 100 (A) + 1 (B)


# ---- what-if remediation ----------------------------------------------------


def test_what_if_remediation_disconnects_the_right_jewels() -> None:
    w, keys = _diamond()
    m = ImpactModel(nodes={"datastore:A": 10.0, "datastore:B": 3.0, "datastore:C": 1.0})
    r = what_if_remediate(w, "host:attacker", [NodeKind.DATASTORE], {keys["att_gw"]},
                          edge_kinds=[_EK], impact=m)
    assert set(r.now_unreachable) == {"datastore:A", "datastore:B"}
    assert r.still_reachable == ["datastore:C"]
    assert r.impact_removed == 13.0 and r.impact_remaining == 1.0


def test_what_if_is_read_only() -> None:
    w, keys = _diamond()
    before = w.edge_count
    what_if_remediate(w, "host:attacker", [NodeKind.DATASTORE], set(keys.values()), edge_kinds=[_EK])
    assert w.edge_count == before   # never mutates the graph
