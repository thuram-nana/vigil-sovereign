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


class Neo4jGraphStore(_BaseGraphStore):
    """[SCAFFOLD — infra-gated] A Neo4j-backed projection behind the SAME interface.

    NOT required to run anything today — the embedded store is the working default. This class exists so
    that, when a Neo4j (or other property-graph) service is provisioned, the swap is a one-line backend
    change with no call-site edits. It reuses the pure ``project_events`` core verbatim; only the storage
    (MERGE nodes/edges into the graph DB, scoped by a per-partition label) would differ.

    ACTIVATION RUNBOOK (see docs/DEFERRED-INFRA.md → G1):
      1. Provision Neo4j (or a bolt-compatible service); export ``NEO4J_URI`` / ``NEO4J_AUTH``.
      2. ``pip install neo4j`` into the offense venv.
      3. Implement the three ``NotImplementedError`` bodies below with idempotent MERGE Cypher, using a
         partition label so ``drop_partition`` is ``MATCH (n:`part_<partition>`) DETACH DELETE n``.
      4. The one-way invariant is UNCHANGED: this backend still only projects; it exposes no
         tier/grant/authorize method, and dropping a partition never touches the spine.
    """

    def __init__(self, uri: str | None = None, auth: Any = None) -> None:  # pragma: no cover - stub
        raise NotImplementedError(
            "infra-gated: Neo4jGraphStore requires a running Neo4j service and the `neo4j` driver. "
            "Use EmbeddedGraphStore (the working default) until the graph DB is provisioned — "
            "see docs/DEFERRED-INFRA.md (G1)."
        )

    def project_from_spine(self, events: Iterable[Any], *, partition: str = "default") -> None:  # pragma: no cover
        raise NotImplementedError("infra-gated: see docs/DEFERRED-INFRA.md (G1)")

    def nodes(self, partition: str = "default") -> list[dict[str, Any]]:  # pragma: no cover - stub
        raise NotImplementedError("infra-gated: see docs/DEFERRED-INFRA.md (G1)")

    def edges(self, partition: str = "default") -> list[dict[str, Any]]:  # pragma: no cover - stub
        raise NotImplementedError("infra-gated: see docs/DEFERRED-INFRA.md (G1)")


def open_graph_store(base_dir: str | os.PathLike[str]) -> GraphStore:
    """Factory for the default (embedded) backend — the one call sites should use today."""
    return EmbeddedGraphStore(base_dir)
