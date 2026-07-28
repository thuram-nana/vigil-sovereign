"""graph — an embedded, file-backed one-way projection of the event spine (G1).

The graph is a rebuildable VIEW over the append-only spine. It authorizes nothing and mints nothing;
the oracle remains the sole authority. See ``graph/store.py`` for the one-way invariant.
"""

from __future__ import annotations

from .store import (
    EmbeddedGraphStore,
    GraphStore,
    Neo4jGraphStore,
    open_graph_store,
    project_events,
)

__all__ = [
    "GraphStore",
    "EmbeddedGraphStore",
    "Neo4jGraphStore",
    "open_graph_store",
    "project_events",
]
