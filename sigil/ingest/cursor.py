"""Per-source ingestion cursor — how many transcript records of each file are already
in the spine. Makes ongoing ingestion incremental (append-only): re-runs resume where
they left off instead of re-reading a growing transcript from the top."""
from __future__ import annotations

import json

from ..config import CACHE_DIR

_PATH = CACHE_DIR / "ingest_cursor.json"


def load() -> dict[str, int]:
    if _PATH.exists():
        try:
            return json.loads(_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def save(cur: dict[str, int]) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.write_text(json.dumps(cur), encoding="utf-8")


def clear() -> None:
    if _PATH.exists():
        _PATH.unlink()
