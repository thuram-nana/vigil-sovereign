"""The threat-feed CACHE — a tiny, atomic, last-good JSON store. Offense-free, stdlib only.

One small JSON document on disk, written by the cadence refresh and read by the edge route. Writes are
ATOMIC (temp file + ``os.replace``) so a crash mid-write never leaves the edge reading half a file, and a
read NEVER raises: a missing, unreadable, or malformed cache reads back as ``None`` (the edge then serves the
honest "warming up" state). Mirrors the CVE catalogue's "egress on a cadence, read-only at request time"
split, but the payload is small and append-free, so a flat JSON file is the right tool, not SQLite.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

# A cache file larger than this is treated as corrupt (the real document is a few KiB). Bounds a read.
_MAX_CACHE_BYTES = 4 * 1024 * 1024


class ThreatFeedCache:
    """A single-document JSON cache at ``path``. The document is always ``{"as_of": <epoch>, "data": {...}}``;
    callers write/read the inner ``data`` dict and get the ``as_of`` stamp for free."""

    def __init__(self, path: "str | Path") -> None:
        self.path = Path(path)

    def write(self, data: dict, *, now: "float | None" = None) -> float:
        """Atomically replace the cache with ``data`` stamped ``as_of=now``. Returns the stamp. Creates the
        parent dir if needed. The temp file is created in the SAME directory so ``os.replace`` is atomic
        (a cross-filesystem rename is not)."""
        as_of = time.time() if now is None else float(now)
        doc = {"as_of": as_of, "data": data}
        parent = self.path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(doc, ensure_ascii=False).encode("utf-8")
        fd, tmp = tempfile.mkstemp(dir=str(parent) if str(parent) not in ("", ".") else None,
                                   prefix=".threatfeed.", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return as_of

    def read(self) -> "dict | None":
        """Return the stored document ``{"as_of", "data"}`` or None. NEVER raises: a missing / oversize /
        unreadable / malformed / wrong-shape file all read back as None (the edge then serves honest-empty)."""
        try:
            if not self.path.exists() or self.path.stat().st_size > _MAX_CACHE_BYTES:
                return None
            raw = self.path.read_bytes()
        except OSError:
            return None
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except (ValueError, TypeError):
            return None
        if not isinstance(doc, dict) or not isinstance(doc.get("data"), dict):
            return None
        try:
            doc["as_of"] = float(doc.get("as_of") or 0.0)
        except (TypeError, ValueError):
            doc["as_of"] = 0.0
        return doc

    def read_data(self) -> "tuple[dict | None, float]":
        """Convenience: ``(data_dict_or_None, as_of_epoch)``."""
        doc = self.read()
        if doc is None:
            return None, 0.0
        data = doc.get("data")
        return (data if isinstance(data, dict) else None), float(doc.get("as_of") or 0.0)

    def is_stale(self, ttl_seconds: float, *, now: "float | None" = None) -> bool:
        """True when there is no cache yet OR it is older than ``ttl_seconds`` (so the caller refreshes, and
        the edge can mark the served snapshot ``stale``)."""
        doc = self.read()
        if doc is None:
            return True
        n = time.time() if now is None else float(now)
        return (n - float(doc.get("as_of") or 0.0)) > float(ttl_seconds)
