"""G1 — the embedded graph store is a DETERMINISTIC, ONE-WAY projection of the spine.

These tests pin the two load-bearing properties:
  * determinism — same events in → byte-identical partition out (no wallclock/RNG);
  * one-way     — the store projects only; it exposes no tier/grant/authorize/promote surface, and a
                  projection never becomes an authority (dropping it loses nothing).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from framework.v2.graph.store import (
    EmbeddedGraphStore,
    GraphStore,
    Neo4jGraphStore,
    open_graph_store,
    project_events,
)


@dataclass
class _FakeEvent:
    """Duck-typed to agents.blackboard.BlackboardEventRow (we consume the shape, never import it)."""

    id: int
    engagement_id: int
    kind: str
    agent_name: str
    payload: dict[str, Any]
    parent_id: Optional[int] = None
    supersedes_id: Optional[int] = None
    posted_at: str = "IGNORED-WALLCLOCK"   # present on the real row; MUST NOT affect the projection


def _spine() -> list[_FakeEvent]:
    return [
        _FakeEvent(1, 7, "recon", "scout", {"host": "t"}),
        _FakeEvent(2, 7, "hypothesis", "planner", {"h": "sqli"}, parent_id=1),
        _FakeEvent(3, 7, "hypothesis", "planner", {"h": "sqli-refined"}, parent_id=1, supersedes_id=2),
    ]


def test_projection_builds_event_agent_nodes_and_relation_edges() -> None:
    g = project_events(_spine())
    node_ids = {n["id"] for n in g["nodes"]}
    assert {"event:7:1", "event:7:2", "event:7:3", "agent:scout", "agent:planner"} <= node_ids
    rels = {(e["rel"], e["src"], e["dst"]) for e in g["edges"]}
    assert ("parent", "event:7:2", "event:7:1") in rels
    assert ("supersedes", "event:7:3", "event:7:2") in rels
    assert ("posted", "agent:planner", "event:7:2") in rels


def test_projection_is_deterministic_and_ignores_wallclock() -> None:
    a = project_events(_spine())
    b = project_events(list(reversed(_spine())))   # input order must not matter (sorted by spine id)
    assert a == b
    # a differing posted_at (wallclock) must not change the projection
    ev = _spine()
    ev[0].posted_at = "a-totally-different-time"
    assert project_events(ev) == a


def test_embedded_store_writes_byte_identical_partitions(tmp_path: Path) -> None:
    s1 = EmbeddedGraphStore(tmp_path / "a")
    s2 = EmbeddedGraphStore(tmp_path / "b")
    s1.project_from_spine(_spine(), partition="sess-1")
    s2.project_from_spine(list(reversed(_spine())), partition="sess-1")
    b1 = (tmp_path / "a" / "sess-1.json").read_bytes()
    b2 = (tmp_path / "b" / "sess-1.json").read_bytes()
    assert b1 == b2                                   # deterministic on disk
    assert json.loads(b1)["nodes"]                    # and non-empty


def test_reprojection_is_idempotent(tmp_path: Path) -> None:
    s = EmbeddedGraphStore(tmp_path)
    s.project_from_spine(_spine(), partition="p")
    first = (tmp_path / "p.json").read_bytes()
    s.project_from_spine(_spine(), partition="p")     # full rebuild, no accumulation
    assert (tmp_path / "p.json").read_bytes() == first
    assert len(s.nodes("p")) == 5


def test_partitions_are_isolated(tmp_path: Path) -> None:
    s = EmbeddedGraphStore(tmp_path)
    s.project_from_spine(_spine(), partition="alpha")
    s.project_from_spine([_FakeEvent(1, 9, "note", "x", {})], partition="beta")
    assert len(s.nodes("alpha")) == 5
    assert len(s.nodes("beta")) == 2                  # 1 event + 1 agent
    assert set(s.partitions()) == {"alpha", "beta"}


def test_drop_partition_never_affects_others(tmp_path: Path) -> None:
    s = EmbeddedGraphStore(tmp_path)
    s.project_from_spine(_spine(), partition="alpha")
    s.project_from_spine(_spine(), partition="beta")
    s.drop_partition("alpha")
    assert s.nodes("alpha") == []                     # gone
    assert len(s.nodes("beta")) == 5                  # untouched


def test_store_exposes_no_authority_surface() -> None:
    """The one-way invariant, enforced structurally: a projection can never mint a tier/grant/fact.

    If a future edit adds any such method to the store, this test fails loudly — the guard is the point."""
    s = open_graph_store  # factory returns the embedded store
    store = s("/tmp/does-not-need-to-exist-for-attr-check") if False else EmbeddedGraphStore
    forbidden = {"grant", "promote", "authorize", "set_tier", "tier", "mint", "confirm", "certify"}
    surface = set(dir(EmbeddedGraphStore)) | set(dir(GraphStore))
    assert forbidden.isdisjoint(surface), f"graph store must not expose an authority surface: {forbidden & surface}"
    _ = store  # silence unused


def test_projection_is_total_on_partial_rows(tmp_path: Path) -> None:
    """A malformed/partial event (dict form, missing fields) never raises — the projection is total."""
    s = EmbeddedGraphStore(tmp_path)
    s.project_from_spine([{"id": "not-an-int", "kind": "x"}], partition="p")
    assert isinstance(s.nodes("p"), list)             # produced a graph, did not crash


def test_neo4j_backend_is_a_gated_stub() -> None:
    import pytest

    with pytest.raises(NotImplementedError, match="infra-gated"):
        Neo4jGraphStore(uri="bolt://localhost:7687")


def test_embedded_store_satisfies_the_protocol(tmp_path: Path) -> None:
    assert isinstance(EmbeddedGraphStore(tmp_path), GraphStore)
