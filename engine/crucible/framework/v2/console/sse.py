"""
console.sse — tail the append-only structured log for the live view.

The framework's `common.logging` sink writes one compact JSON object per line to a
per-engagement file (`targets/<slug>/.crucible-v2.log`) or the ambient
`framework/v2/.crucible-v2.log`, opening/closing per event (so concurrent tailing is
safe). This module does an incremental, non-blocking read of that file — it never
writes, never blocks the engine, and simply surfaces what is already on disk as a
stream of events for Server-Sent Events.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import paths


def log_path_for(slug: str | None) -> Path:
    """The JSONL log a live view should tail: the engagement's log when a slug is
    given, else the ambient log next to the v2 package (CLI start/done + unbound
    subsystems)."""
    if slug:
        return Path(paths.crucible_v2_log(slug))
    return Path(paths.v2_root()) / ".crucible-v2.log"


def stream_path(*, run: str | None = None, slug: str | None = None) -> Path:
    """Resolve which JSONL a live stream should tail: a console run's progress log
    (`?run=`) takes precedence over an engagement log (`?slug=`), else the ambient log."""
    if run:
        from .actions import run_dir

        return run_dir(run) / "progress.jsonl"
    return log_path_for(slug)


class EventTailer:
    """Incremental reader over an append-only JSONL log. ``read_new()`` returns the
    events appended since the last call (whole lines only; a partial trailing line is
    buffered until its newline arrives). Robust to the file not existing yet, being
    truncated/rotated (position resets), or containing a malformed line (skipped)."""

    def __init__(self, path: Path, *, from_end: bool = True) -> None:
        self._path = Path(path)
        self._pos = 0
        self._buf = ""
        if from_end:
            self._pos = self._size()

    def _size(self) -> int:
        try:
            return self._path.stat().st_size
        except OSError:
            return 0

    def read_new(self) -> list[dict[str, Any]]:
        size = self._size()
        if size < self._pos:
            # truncated/rotated — start over from the top
            self._pos = 0
            self._buf = ""
        if size == self._pos:
            return []
        try:
            with self._path.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(self._pos)
                chunk = f.read()
                self._pos = f.tell()
        except OSError:
            return []
        self._buf += chunk
        lines = self._buf.split("\n")
        self._buf = lines.pop()  # last element is the (possibly partial) trailing line
        out: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue  # a malformed line never breaks the stream
            if isinstance(obj, dict):
                out.append(obj)
        return out
