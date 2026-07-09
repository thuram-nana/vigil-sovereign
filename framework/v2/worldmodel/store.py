"""
worldmodel.store — JSON persistence for the world-model.

A world-model must survive a process restart: an engagement runs for
days, and the accreted attack-graph is expensive to rebuild. Persistence
is deliberately plain — a single JSON document with two sorted arrays —
so it is diffable, auditable, and portable.

`to_json` emits a canonical, deterministic document (nodes sorted by id;
edges sorted by (src, dst, kind)); the same graph always serialises to
the same bytes, which keeps snapshots diff-friendly and tests exact.
`from_json` validates every record through the Pydantic models, so a
corrupt or hand-edited file fails loudly with a WorldModelError rather
than loading a malformed graph.

Loading replays nodes first, then edges, through WorldModel.add_node /
add_edge — so an on-disk file with an edge to a missing node is rejected
by the same integrity check that guards live insertion.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from ..common import paths
from .graph import WorldModel, WorldModelError
from .models import Edge, Node

SCHEMA_VERSION = 1


def to_dict(model: WorldModel) -> dict[str, object]:
    """Serialise to a plain, deterministic dict (nodes then edges, both
    sorted). Suitable for json.dump or embedding in a larger snapshot."""
    return {
        "schema_version": SCHEMA_VERSION,
        "nodes": [n.model_dump(mode="json") for n in model.all_nodes()],
        "edges": [e.model_dump(mode="json") for e in model.all_edges()],
    }


def to_json(model: WorldModel, *, indent: int | None = 2) -> str:
    """Serialise to a deterministic JSON string. `indent=None` gives a
    compact single line; the default is human-diffable pretty-print.
    Keys are sorted so byte output is stable across runs."""
    return json.dumps(to_dict(model), indent=indent, sort_keys=True, ensure_ascii=False)


def from_dict(data: dict[str, object]) -> WorldModel:
    """Rebuild a WorldModel from a to_dict document. Validates every
    record and enforces edge->node integrity via the live insert path."""
    if not isinstance(data, dict):
        raise WorldModelError("world-model document must be a JSON object")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise WorldModelError(
            f"unsupported world-model schema_version {version!r} "
            f"(expected {SCHEMA_VERSION})"
        )
    raw_nodes = data.get("nodes", [])
    raw_edges = data.get("edges", [])
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise WorldModelError("world-model 'nodes' and 'edges' must be arrays")

    model = WorldModel()
    try:
        for raw in raw_nodes:
            model.add_node(Node.model_validate(raw))
        for raw in raw_edges:
            model.add_edge(Edge.model_validate(raw))
    except ValidationError as e:
        raise WorldModelError(f"world-model record failed schema validation: {e}") from e
    return model


def from_json(text: str) -> WorldModel:
    """Rebuild a WorldModel from a JSON string produced by to_json."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise WorldModelError(f"world-model document is not valid JSON: {e}") from e
    return from_dict(data)


def save(model: WorldModel, path: Path | str, *, indent: int | None = 2) -> None:
    """Write the world-model to `path` (parent dirs created)."""
    p = Path(path)
    paths.secure_write(p, to_json(model, indent=indent))   # X2: owner-only (holds intel/PII)


def load(path: Path | str) -> WorldModel:
    """Read a world-model from `path`. Missing file -> WorldModelError."""
    p = Path(path)
    if not p.is_file():
        raise WorldModelError(f"no world-model file at {p}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise WorldModelError(f"cannot read world-model at {p}: {e}") from e
    return from_json(text)
