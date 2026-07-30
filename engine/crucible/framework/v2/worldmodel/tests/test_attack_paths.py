"""P4 — attack-path + chokepoint triage over a pure signed-spine → WorldModel projection.

A deterministic foothold → app → db chain (db is the crown jewel). Asserts: the projection is a pure,
byte-identical function of the spine; a shortest attack path reaches the jewel; the chokepoint analysis
identifies the single edge whose removal disconnects the jewel; and the top-remediation what-if confirms it.
"""
from __future__ import annotations

import json

from framework.v2.worldmodel import attack_paths as ap
from framework.v2.worldmodel.impact import ImpactModel
from framework.v2.worldmodel.models import EdgeKind, NodeKind
from framework.v2.worldmodel.spine_projector import project_spine


def _fact_asset(seq, nid):
    return {"seq": seq, "hash": f"h{seq}", "kind": "asset", "node_id": nid, "node_kind": "host",
            "status": "fact", "evidence_ref": f"e{seq}", "signature_ref": f"s{seq}"}


def _fact_reach(seq, src, dst):
    return {"seq": seq, "hash": f"h{seq}", "kind": "relation", "src": src, "dst": dst,
            "edge_kind": EdgeKind.REACHED.value, "status": "fact",
            "evidence_ref": f"e{seq}", "signature_ref": f"s{seq}", "confidence": 0.9}


def _spine():
    return [
        _fact_asset(1, "host:foothold"), _fact_asset(2, "host:app"), _fact_asset(3, "host:db"),
        _fact_reach(4, "host:foothold", "host:app"),
        _fact_reach(5, "host:app", "host:db"),
    ]


def _report(spine):
    world = project_spine(spine)
    imp = ImpactModel.uniform() if hasattr(ImpactModel, "uniform") else ImpactModel({})
    return ap.build_report(world, source="host:foothold", objective_kinds=[NodeKind.HOST],
                           edge_kinds=[EdgeKind.REACHED], impact=imp, k=5)


def test_projection_is_a_pure_byte_identical_spine_function():
    # same spine, shuffled input order → identical report (deterministic; two-pass, (seq,hash,body) sorted).
    import random
    a = _spine()
    b = list(a)
    random.Random(0).shuffle(b)
    ra, rb = _report(a), _report(b)
    assert json.dumps(ra, sort_keys=True) == json.dumps(rb, sort_keys=True)


def test_shortest_path_reaches_the_crown_jewel():
    rep = _report(_spine())
    assert rep["source_present"] is True
    paths = rep["shortest_attack_paths"]
    assert paths, "a foothold→app→db chain must yield at least one attack path"
    # every host is an objective here, so the NEAREST jewel (host:app) is the top path; the 2-hop jewel
    # host:db must still be reachable — it appears in the reachable blast radius and in an enumerated path.
    assert "host:db" in json.dumps(rep["blast_radius"]), "the db jewel must be in the reachable blast radius"
    assert any("host:db" in json.dumps(p) for p in paths), "an enumerated attack path must reach host:db"


def test_chokepoint_and_what_if_disconnect_the_jewel():
    rep = _report(_spine())
    chokes = rep["chokepoints"]
    assert chokes, "the linear chain has a bridge edge — a chokepoint must be ranked"
    # cutting the #1 chokepoint makes the jewel unreachable (top_remediation what-if)
    wi = rep["top_remediation"]
    assert wi is not None
    assert "host:db" in wi["now_unreachable"], "remediating the top chokepoint must disconnect host:db"
