"""H2 — the Neo4jGraphStore CLIENT BODY is real and reviewable, exercised over a FAKE driver.

The `neo4j` driver package and a live Neo4j service are both ABSENT in this environment (the honest
*deploy* residual). So this test proves the two things software CAN prove here:

  * the storage-specific Cypher (`_tx_rebuild` / `_tx_nodes` / `_tx_edges`) is idempotent MERGE +
    DETACH-DELETE, scoped by a per-partition label, over the SAME pure `project_events` core the embedded
    store uses — round-tripped through a small in-memory fake transaction so the shape is verified without
    a service; and
  * a real integration test against a running Neo4j exists but is gated behind a LOUD skip (below).

The pure-projection core stays covered by `test_store.py` (the embedded path). Nothing here mints a fact,
grants a tier, or touches the spine — the store is projection-only by construction.
"""
from __future__ import annotations

import os
import re
from typing import Any

import pytest

from framework.v2.graph.store import (
    Neo4jGraphStore,
    _tx_edges,
    _tx_nodes,
    _tx_rebuild,
    project_events,
)

_LABEL_RE = re.compile(r"`(part_[^`]*)`")


def _spine() -> list[dict[str, Any]]:
    return [
        {"id": 1, "engagement_id": 7, "kind": "recon", "agent_name": "scout",
         "payload": {"host": "t"}, "parent_id": None, "supersedes_id": None},
        {"id": 2, "engagement_id": 7, "kind": "hypothesis", "agent_name": "planner",
         "payload": {"h": "sqli"}, "parent_id": 1, "supersedes_id": None},
        {"id": 3, "engagement_id": 7, "kind": "hypothesis", "agent_name": "planner",
         "payload": {"h": "sqli-refined"}, "parent_id": 1, "supersedes_id": 2},
    ]


# --- a tiny in-memory fake of the neo4j managed-transaction API ------------------------------------
# It interprets ONLY the fixed query templates the store issues, so the client body round-trips through
# it exactly as it would through a real bolt session — no Cypher engine, no service.

class _FakeResult(list):
    """An iterable of dict-like records (each supports rec["k"])."""


class _FakeTx:
    def __init__(self, store: dict) -> None:
        self._store = store          # {label: {"nodes": {id: props}, "edges": {(rel,src,dst): rec}}}
        self.calls: list[tuple[str, dict]] = []

    def run(self, cypher: str, **params: Any) -> _FakeResult:
        self.calls.append((cypher, params))
        m = _LABEL_RE.search(cypher)
        label = m.group(1) if m else None
        if cypher.startswith("CALL db.labels()"):
            return _FakeResult({"label": lbl} for lbl in sorted(self._store))
        part = self._store.setdefault(label, {"nodes": {}, "edges": {}})
        if "DETACH DELETE" in cypher and cypher.strip().startswith("MATCH (n:"):
            part["nodes"].clear()
            part["edges"].clear()
            return _FakeResult()
        if "MERGE (n:" in cypher:
            part["nodes"][params["id"]] = dict(params["props"])
            return _FakeResult()
        if "MERGE (s)-[r:REL" in cypher:
            key = (params["rel"], params["src"], params["dst"])
            part["edges"][key] = {"rel": params["rel"], "src": params["src"], "dst": params["dst"]}
            return _FakeResult()
        if "RETURN n ORDER BY n.id" in cypher:
            return _FakeResult({"n": p} for _, p in sorted(part["nodes"].items()))
        if "RETURN r.rel AS rel" in cypher:
            return _FakeResult(rec for _, rec in sorted(part["edges"].items()))
        raise AssertionError(f"unexpected cypher: {cypher}")


class _FakeSession:
    def __init__(self, tx: _FakeTx) -> None:
        self._tx = tx

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute_write(self, fn, *args):
        return fn(self._tx, *args)

    def execute_read(self, fn, *args):
        return fn(self._tx, *args)


class _FakeDriver:
    def __init__(self) -> None:
        self.store: dict = {}
        self.tx = _FakeTx(self.store)
        self.closed = False

    def session(self, **_: Any) -> _FakeSession:
        return _FakeSession(self.tx)

    def close(self) -> None:
        self.closed = True


# --- tests ----------------------------------------------------------------------------------------

def test_client_body_round_trips_the_pure_projection_over_a_fake_driver() -> None:
    drv = _FakeDriver()
    s = Neo4jGraphStore(driver=drv)
    s.project_from_spine(_spine(), partition="sess-1")

    expected = project_events(_spine())
    # nodes/edges read back through the SAME pure projection the embedded store persists.
    assert s.nodes("sess-1") == expected["nodes"]
    assert s.edges("sess-1") == expected["edges"]
    assert set(s.partitions()) == {"sess-1"}


def test_rebuild_is_idempotent_and_full(  # re-projecting a shrunk event list drops the surplus
) -> None:
    drv = _FakeDriver()
    s = Neo4jGraphStore(driver=drv)
    s.project_from_spine(_spine(), partition="p")
    first_nodes = s.nodes("p")
    s.project_from_spine(_spine(), partition="p")            # MERGE ⇒ no duplication
    assert s.nodes("p") == first_nodes
    # a shrunk projection is a FULL rebuild (leading DETACH DELETE), matching the embedded overwrite.
    s.project_from_spine(_spine()[:1], partition="p")
    assert len(s.nodes("p")) == 2                            # 1 event + 1 agent


def test_tx_rebuild_emits_detach_delete_then_bound_merges() -> None:
    tx = _FakeTx({})
    graph = project_events(_spine())
    _tx_rebuild(tx, "`part_p`", graph)
    cyphers = [c for c, _ in tx.calls]
    # first statement clears the partition; every value rides a bound param (no value interpolation).
    assert "DETACH DELETE" in cyphers[0]
    assert cyphers[0].strip().startswith("MATCH (n:`part_p`)")
    node_merges = [(c, p) for c, p in tx.calls if "MERGE (n:" in c]
    edge_merges = [(c, p) for c, p in tx.calls if "MERGE (s)-[r:REL" in c]
    assert len(node_merges) == len(graph["nodes"])
    assert len(edge_merges) == len(graph["edges"])
    for c, p in node_merges:
        assert "$id" in c and "$props" in c and "id" in p and "props" in p
    for c, p in edge_merges:
        assert "$src" in c and "$dst" in c and "$rel" in c


def test_partition_label_is_backtick_scoped_and_isolated() -> None:
    drv = _FakeDriver()
    s = Neo4jGraphStore(driver=drv)
    s.project_from_spine(_spine(), partition="alpha")
    s.project_from_spine(_spine()[:1], partition="beta")
    # partitions are separate labels; dropping one never touches the other (no spine involvement at all).
    s.drop_partition("alpha")
    assert s.nodes("alpha") == []
    assert len(s.nodes("beta")) == 2
    drop_calls = [c for c, _ in drv.tx.calls if "DETACH DELETE" in c and "part_alpha" in c]
    assert drop_calls, "drop_partition must DETACH DELETE the partition label"


def test_no_authority_surface() -> None:
    # the store is projection-only: it exposes no promote/grant/tier/authorize method (one-way invariant).
    for banned in ("promote", "grant", "tier", "authorize", "mint"):
        assert not hasattr(Neo4jGraphStore, banned)


def test_read_bodies_parse_driver_records() -> None:
    # _tx_nodes/_tx_edges convert bolt records into the plain projection dicts callers expect.
    graph = project_events(_spine())
    store: dict = {}
    tx = _FakeTx(store)
    _tx_rebuild(tx, "`part_p`", graph)
    assert _tx_nodes(tx, "`part_p`") == graph["nodes"]
    assert _tx_edges(tx, "`part_p`") == graph["edges"]


def test_construct_without_driver_is_infra_gated() -> None:
    # neo4j the driver package is ABSENT here → constructing a LIVE store raises the honest deploy residual.
    pytest.importorskip  # noqa: B018 — reference to keep the intent explicit
    try:
        import neo4j  # type: ignore  # noqa: F401
    except ImportError:
        with pytest.raises(NotImplementedError) as ei:
            Neo4jGraphStore("bolt://127.0.0.1:7687")
        assert "neo4j" in str(ei.value) and "deploy" in str(ei.value).lower()
    else:  # pragma: no cover - only when the driver IS installed
        with pytest.raises(ValueError):
            Neo4jGraphStore()  # no uri, no driver


@pytest.mark.skipif(
    True,
    reason=(
        "LOUD SKIP (H2 deploy residual): the live Neo4j integration test needs BOTH `pip install neo4j` "
        "AND a running Neo4j service (export NEO4J_URI / NEO4J_AUTH). Neither is present in this "
        "environment. The client body's SHAPE is fully covered above over a fake driver; this test is the "
        "on-hardware/on-service parity check that runs once a graph DB is provisioned — see "
        "docs/DEFERRED-INFRA.md (G1/H2)."
    ),
)
def test_live_neo4j_round_trip() -> None:  # pragma: no cover - requires a live service
    neo4j = pytest.importorskip("neo4j", reason="neo4j driver not installed (H2 deploy residual)")
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        pytest.skip("NEO4J_URI not set — no live Neo4j service (H2 deploy residual)")
    user = os.environ.get("NEO4J_USER", "neo4j")
    pw = os.environ.get("NEO4J_PASSWORD", "")
    s = Neo4jGraphStore(uri, auth=(user, pw))
    try:
        s.project_from_spine(_spine(), partition="ci-h2")
        assert s.nodes("ci-h2") == project_events(_spine())["nodes"]
        assert s.edges("ci-h2") == project_events(_spine())["edges"]
    finally:
        s.drop_partition("ci-h2")
        s.close()
