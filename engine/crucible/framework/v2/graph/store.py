"""graph.store — an embedded, file-backed GRAPH STORE that is a one-way projection of the spine.

[BUILT] the embedded (JSON, file-backed) implementation runs today with no external database.
[SCAFFOLD] a Neo4j backend behind the same interface is a documented stub (see ``Neo4jGraphStore``).

WHY THIS EXISTS
---------------
The event spine (``agents/blackboard.py`` — an append-only log of ``BlackboardEventRow``s) is the
single source of truth. A graph is a convenient *view* over it: nodes for events and the agents that
posted them, edges for the parent / supersedes / posted relationships. This module builds that view.

THE ONE-WAY INVARIANT (load-bearing — do not weaken)
----------------------------------------------------
``project_from_spine(events, partition=...)`` is a PURE, DERIVED, ONE-WAY projection:

  * It is a pure function of the passed event list. Same events in → byte-identical partition out.
    No wallclock, no RNG, no ambient state — the projection is deterministic and replay-safe.
  * It is a full rebuild of the partition from the events given (an append-only log projects
    cleanly; there is no incremental mutation to get wrong).
  * Nothing produced here is EVER read back into a tier, a grant, an authorization, or a FACT.
    The graph authorizes nothing and mints nothing. It is rebuildable, disposable state; deleting a
    partition loses no authority (the spine is untouched). This store has NO promote/grant/tier/
    authorize method, on purpose — a projection that could feed a decision would be a covert channel
    around the oracle. The oracle remains the sole authority; this is a lens, never a source.

PARTITIONS
----------
A ``partition`` key (default ``"default"``) scopes a projection — one partition per session, mirroring
``console/sessions.py``'s per-session ``seq``/``slug`` model. Partitions are isolated: projecting one
never touches another, and dropping one (a rebuildable projection) is safe.

DETERMINISM
-----------
Nodes are emitted sorted by id; edges sorted by ``(rel, src, dst)``. Serialization is canonical
(``json.dumps(..., sort_keys=True)``). The projection uses only the event fields (id / engagement_id /
kind / agent_name / payload / parent_id / supersedes_id) — never ``posted_at`` (wallclock), matching the
"no wallclock in digests" discipline the evidence/spine-chain layers already keep.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol, runtime_checkable

_MAX_PARTITION = 128


# --- the event shape we CONSUME (not import) -------------------------------------------------------
# We duck-type the ``agents.blackboard.BlackboardEventRow`` shape so this store stays fully decoupled
# from the spine implementation (and importable standalone). An event may be that dataclass, any object
# exposing the same attributes, or a plain dict with the same keys.

_EVENT_FIELDS = ("id", "engagement_id", "kind", "agent_name", "payload", "parent_id", "supersedes_id")


def _field(ev: Any, name: str) -> Any:
    if isinstance(ev, dict):
        return ev.get(name)
    return getattr(ev, name, None)


def _normalize_event(ev: Any) -> dict[str, Any]:
    """Project one spine event to the minimal, wallclock-free dict the graph is built from.

    ``id`` is the spine's logical clock (a monotonic int) — the deterministic ordering coordinate; a
    missing/unparseable id sorts to 0 so the projection is still total (never raises on a partial row)."""
    try:
        eid = int(_field(ev, "id"))
    except (TypeError, ValueError):
        eid = 0
    try:
        engagement = int(_field(ev, "engagement_id"))
    except (TypeError, ValueError):
        engagement = 0

    def _int_or_none(v: Any) -> Optional[int]:
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    return {
        "id": eid,
        "engagement_id": engagement,
        "kind": str(_field(ev, "kind") or ""),
        "agent_name": str(_field(ev, "agent_name") or ""),
        "payload": _field(ev, "payload"),
        "parent_id": _int_or_none(_field(ev, "parent_id")),
        "supersedes_id": _int_or_none(_field(ev, "supersedes_id")),
    }


def _payload_digest(payload: Any) -> str:
    """A stable content digest of an event payload (canonical JSON → sha256). Used as node content so
    an altered payload changes the projection — never the raw payload, keeping the graph compact and
    non-secret-bearing. Falls back to a repr digest for a non-JSON-able payload."""
    try:
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    except (TypeError, ValueError):
        raw = repr(payload).encode("utf-8", errors="replace")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def project_events(events: Iterable[Any]) -> dict[str, list[dict[str, Any]]]:
    """The PURE core of the projection: events → ``{"nodes": [...], "edges": [...]}``.

    Deterministic and side-effect-free (no I/O, no wallclock, no RNG). Exposed separately so the
    projection can be unit-tested and reused by any backend without a filesystem. The embedded and
    (stubbed) Neo4j stores both build on this exact function — the *storage* differs, the *graph*
    does not."""
    norm = sorted((_normalize_event(e) for e in events), key=lambda e: (e["id"], e["engagement_id"]))

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _agent_node(name: str) -> str:
        nid = f"agent:{name}"
        nodes.setdefault(nid, {"id": nid, "type": "agent", "name": name})
        return nid

    for ev in norm:
        nid = f"event:{ev['engagement_id']}:{ev['id']}"
        nodes[nid] = {
            "id": nid,
            "type": "event",
            "seq": ev["id"],                 # spine logical clock — the deterministic coordinate
            "engagement_id": ev["engagement_id"],
            "kind": ev["kind"],
            "agent": ev["agent_name"],
            "payload_digest": _payload_digest(ev["payload"]),
        }
        if ev["agent_name"]:
            anode = _agent_node(ev["agent_name"])
            edges[("posted", anode, nid)] = {"rel": "posted", "src": anode, "dst": nid}
        if ev["parent_id"] is not None:
            parent = f"event:{ev['engagement_id']}:{ev['parent_id']}"
            edges[("parent", nid, parent)] = {"rel": "parent", "src": nid, "dst": parent}
        if ev["supersedes_id"] is not None:
            older = f"event:{ev['engagement_id']}:{ev['supersedes_id']}"
            edges[("supersedes", nid, older)] = {"rel": "supersedes", "src": nid, "dst": older}

    ordered_nodes = [nodes[k] for k in sorted(nodes)]
    ordered_edges = [edges[k] for k in sorted(edges)]
    return {"nodes": ordered_nodes, "edges": ordered_edges}


# --- the interface ---------------------------------------------------------------------------------


@runtime_checkable
class GraphStore(Protocol):
    """The contract every backend satisfies. Deliberately a READ + PROJECT surface only: there is no
    method that writes a tier, a grant, or a fact. A projection informs a human/UI; it never authorizes."""

    def project_from_spine(self, events: Iterable[Any], *, partition: str = "default") -> None:
        """One-way, deterministic rebuild of ``partition`` from the given append-only event list."""

    def nodes(self, partition: str = "default") -> list[dict[str, Any]]:
        ...

    def edges(self, partition: str = "default") -> list[dict[str, Any]]:
        ...

    def partitions(self) -> list[str]:
        ...

    def drop_partition(self, partition: str) -> None:
        """Drop a rebuildable projection. NEVER touches the spine or a fact."""


class _BaseGraphStore(ABC):
    """Shared partition-id hygiene for concrete backends (a path-safe, bounded partition key)."""

    @staticmethod
    def _safe_partition(raw: str) -> str:
        s = str(raw or "default")
        # a partition becomes a filename / DB label — no separators, traversal, or control chars.
        cleaned = "".join(c for c in s if c.isalnum() or c in "-_.")
        # Do NOT strip trailing/leading dots: that collapsed DISTINCT session ids (e.g. "abc" and "abc.")
        # onto one partition file — a cross-session leak + collateral drop (red-pen MED). The charset above
        # already excludes separators, so f"{cleaned}.json" can never traverse; only an all-dots key is
        # degenerate, so fold just that to "default". Distinct valid ids now map to distinct partitions.
        if not cleaned or set(cleaned) <= {"."}:
            cleaned = "default"
        if len(cleaned) > _MAX_PARTITION:
            raise ValueError(f"partition id too long (> {_MAX_PARTITION})")
        return cleaned

    @abstractmethod
    def project_from_spine(self, events: Iterable[Any], *, partition: str = "default") -> None: ...

    @abstractmethod
    def nodes(self, partition: str = "default") -> list[dict[str, Any]]: ...

    @abstractmethod
    def edges(self, partition: str = "default") -> list[dict[str, Any]]: ...


class EmbeddedGraphStore(_BaseGraphStore):
    """[BUILT] The default backend — an embedded, file-backed graph. No external database.

    Each partition is one canonical JSON document at ``<base_dir>/<partition>.json`` holding
    ``{"nodes": [...], "edges": [...]}``. ``project_from_spine`` writes it atomically (unique temp +
    ``os.replace``) so a crash mid-write never leaves a torn partition. Reads are pure file reads.

    Determinism: the file bytes are a pure function of the event list (canonical JSON, sorted keys),
    so two projections of the same events produce byte-identical files — a property the tests assert."""

    def __init__(self, base_dir: str | os.PathLike[str]) -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._base, 0o700)   # a projection can mirror non-public engagement structure
        except OSError:
            pass

    def _path(self, partition: str) -> Path:
        return self._base / (self._safe_partition(partition) + ".json")

    def project_from_spine(self, events: Iterable[Any], *, partition: str = "default") -> None:
        graph = project_events(events)
        blob = json.dumps(graph, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        p = self._path(partition)
        fd, tmp = tempfile.mkstemp(prefix=".graph.", suffix=".tmp", dir=str(self._base))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(blob)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, p)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _read(self, partition: str) -> dict[str, list[dict[str, Any]]]:
        try:
            data = json.loads(self._path(partition).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"nodes": [], "edges": []}
        if not isinstance(data, dict):
            return {"nodes": [], "edges": []}
        return {"nodes": list(data.get("nodes", []) or []), "edges": list(data.get("edges", []) or [])}

    def nodes(self, partition: str = "default") -> list[dict[str, Any]]:
        return self._read(partition)["nodes"]

    def edges(self, partition: str = "default") -> list[dict[str, Any]]:
        return self._read(partition)["edges"]

    def partitions(self) -> list[str]:
        return sorted(p.stem for p in self._base.glob("*.json"))

    def drop_partition(self, partition: str) -> None:
        """Drop a rebuildable projection file. The spine (the authority) is never touched."""
        try:
            self._path(partition).unlink(missing_ok=True)
        except OSError:
            pass


# --- Neo4j transaction bodies (module-level, driver-agnostic) --------------------------------------
# These take a neo4j managed-transaction handle ``tx`` (anything exposing ``.run(cypher, **params)``) and
# a backtick-quoted per-partition ``label``. They are the ENTIRE storage-specific surface of the Neo4j
# backend — pulled out of the class so they can be exercised over a fake tx (no live service) while the
# graph they persist is the SAME pure ``project_events`` output the embedded store writes. Cypher labels
# and relationship types cannot be parameterised, so the (already charset-restricted, backtick-quoted)
# label is interpolated; every value the projection carries rides a bound ``$param``.

def _tx_rebuild(tx: Any, label: str, graph: dict[str, list[dict[str, Any]]]) -> None:
    """Full, idempotent rebuild of one partition inside a single managed transaction.

    Mirrors the embedded store's semantics exactly: a partition is a FULL rebuild from the given events,
    so we first ``DETACH DELETE`` the partition's existing nodes, then ``MERGE`` each node/edge. MERGE is
    idempotent — re-running the same projection converges to the same graph (no duplicate nodes/edges),
    and the leading clear makes a re-projection of a SHRUNKEN event list drop the stale surplus, matching
    ``EmbeddedGraphStore``'s canonical-file overwrite."""
    tx.run(f"MATCH (n:{label}) DETACH DELETE n")
    for node in graph["nodes"]:
        # node id is the MERGE key (one node per id); all other fields are set as properties.
        tx.run(f"MERGE (n:{label} {{id: $id}}) SET n += $props", id=node["id"], props=dict(node))
    for edge in graph["edges"]:
        # relationship TYPE cannot be parameterised, so we use one type REL carrying a ``rel`` property
        # ("posted"/"parent"/"supersedes"); the (rel, src, dst) triple is the MERGE key, so an edge is
        # never duplicated. Endpoints are matched WITHIN this partition's label — never across partitions.
        tx.run(
            f"MATCH (s:{label} {{id: $src}}), (d:{label} {{id: $dst}}) "
            f"MERGE (s)-[r:REL {{rel: $rel}}]->(d)",
            src=edge["src"], dst=edge["dst"], rel=edge["rel"],
        )


def _tx_nodes(tx: Any, label: str) -> list[dict[str, Any]]:
    result = tx.run(f"MATCH (n:{label}) RETURN n ORDER BY n.id")
    return [dict(rec["n"]) for rec in result]


def _tx_edges(tx: Any, label: str) -> list[dict[str, Any]]:
    result = tx.run(
        f"MATCH (s:{label})-[r:REL]->(d:{label}) "
        f"RETURN r.rel AS rel, s.id AS src, d.id AS dst ORDER BY rel, src, dst"
    )
    return [{"rel": rec["rel"], "src": rec["src"], "dst": rec["dst"]} for rec in result]


class Neo4jGraphStore(_BaseGraphStore):
    """[BUILT client body — infra-gated deploy] A Neo4j-backed projection behind the SAME interface.

    The CLIENT BODY is real and reviewable: ``project_from_spine`` / ``nodes`` / ``edges`` /
    ``drop_partition`` / ``partitions`` issue idempotent MERGE / DETACH-DELETE Cypher over the pure
    ``project_events`` core the embedded store uses, scoped by a per-partition label. What is NOT present
    HERE is the *deploy*: the ``neo4j`` driver package and a running Neo4j service are both ABSENT in this
    environment (SCOUT). So:

      * Constructing WITHOUT an injected driver imports ``neo4j`` lazily — which raises a clear,
        actionable error until ``pip install neo4j`` + a live service exist (the ``deploy`` residual).
      * The storage-specific Cypher lives in module-level ``_tx_*`` transaction bodies, so the client
        body's SHAPE is exercised over a fake transaction (no live service) — the pure-projection core
        stays covered by the embedded test, and a real integration test is gated behind a LOUD skip.

    ONE-WAY INVARIANT (unchanged): this backend still only PROJECTS. It exposes no tier/grant/authorize
    method; dropping a partition (``DETACH DELETE``) never touches the spine (the authority). The graph
    is rebuildable, disposable state — a lens, never a source.

    DEPLOY RUNBOOK (see docs/DEFERRED-INFRA.md → G1 / H2):
      1. Provision Neo4j (or a bolt-compatible service); export ``NEO4J_URI`` / ``NEO4J_AUTH``.
      2. ``pip install neo4j`` into the offense venv.
      3. ``Neo4jGraphStore(os.environ["NEO4J_URI"], auth=(...))`` — no other call-site edits.
    """

    def __init__(
        self,
        uri: str | None = None,
        auth: Any = None,
        *,
        driver: Any = None,
        database: str | None = None,
    ) -> None:
        """Open (or adopt) a Neo4j driver. Pass a live ``uri``/``auth`` for production; pass an injected
        ``driver`` (any object exposing ``session()`` → a context manager with ``execute_write`` /
        ``execute_read``) to exercise the client body without a service. ``database`` selects a named DB.

        With no injected driver and no ``neo4j`` package installed, construction raises a clear error —
        the ``deploy`` residual — never a silent misbehaviour."""
        self._database = database
        if driver is not None:
            self._driver = driver
            return
        try:
            from neo4j import GraphDatabase  # type: ignore[import-not-found]
        except ImportError as e:  # the `neo4j` package is ABSENT here — the honest deploy residual.
            raise NotImplementedError(
                "infra-gated (deploy): Neo4jGraphStore's client body is BUILT, but running it needs the "
                "`neo4j` driver (`pip install neo4j`) and a live Neo4j service. Use EmbeddedGraphStore "
                "(the working default) until the graph DB is provisioned — see docs/DEFERRED-INFRA.md (G1/H2)."
            ) from e
        if not uri:
            raise ValueError("Neo4jGraphStore needs a bolt URI (e.g. NEO4J_URI) or an injected driver")
        self._driver = GraphDatabase.driver(uri, auth=auth)

    def _label(self, partition: str) -> str:
        """The backtick-quoted, per-partition Cypher label. ``_safe_partition`` already restricts the key
        to ``[A-Za-z0-9-_.]`` (no backticks, no separators), so backtick-quoting cannot be broken out of —
        the label is injected into Cypher (labels are not parameterisable) but is not attacker-controllable."""
        return f"`part_{self._safe_partition(partition)}`"

    def _session(self) -> Any:
        return (self._driver.session(database=self._database)
                if self._database else self._driver.session())

    def project_from_spine(self, events: Iterable[Any], *, partition: str = "default") -> None:
        """One-way, deterministic rebuild of ``partition`` from the given append-only event list — the
        SAME pure ``project_events`` output the embedded store persists, written into Neo4j via an
        idempotent MERGE inside one managed (atomic) transaction."""
        graph = project_events(events)
        label = self._label(partition)
        with self._session() as session:
            session.execute_write(_tx_rebuild, label, graph)

    def nodes(self, partition: str = "default") -> list[dict[str, Any]]:
        label = self._label(partition)
        with self._session() as session:
            return session.execute_read(_tx_nodes, label)

    def edges(self, partition: str = "default") -> list[dict[str, Any]]:
        label = self._label(partition)
        with self._session() as session:
            return session.execute_read(_tx_edges, label)

    def partitions(self) -> list[str]:
        """List projected partitions by scanning labels with the ``part_`` prefix (stripping it)."""
        with self._session() as session:
            labels = session.execute_read(
                lambda tx: [rec["label"] for rec in tx.run("CALL db.labels() YIELD label RETURN label")])
        return sorted(lbl[len("part_"):] for lbl in labels if lbl.startswith("part_"))

    def drop_partition(self, partition: str) -> None:
        """Drop a rebuildable projection (``DETACH DELETE`` the partition's nodes). The spine (the
        authority) is never touched."""
        label = self._label(partition)
        with self._session() as session:
            session.execute_write(lambda tx: tx.run(f"MATCH (n:{label}) DETACH DELETE n"))

    def close(self) -> None:
        """Close the underlying driver (best-effort)."""
        try:
            self._driver.close()
        except Exception:  # noqa: BLE001 — a close error must never mask the caller's own flow
            pass


def open_graph_store(base_dir: str | os.PathLike[str]) -> GraphStore:
    """Factory for the default (embedded) backend — the one call sites should use today."""
    return EmbeddedGraphStore(base_dir)
