"""Durable, atomic file replacement — the one implementation the spine's crash-safe swaps share.

Extracted verbatim from `checkpoint._atomic_write_text` (FIX 3) so the signed head, the manifest, and
any future single-file cutover all use ONE audited routine rather than drifting copies. The contract:
a reader observes either the whole old file or the whole new file (never a torn one), and the new
content survives a crash at any point — a crash mid-write leaves the PREVIOUS valid file intact.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def fsync_dir(directory: Path | str) -> None:
    """fsync a directory so a rename/create inside it is itself durable across a crash. A no-op-on-error
    on filesystems that don't support directory fsync (the rename still lands; only its durability window
    widens)."""
    try:
        dfd = os.open(str(directory), os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:  # pragma: no cover — dir fsync unsupported on some filesystems
        pass


def atomic_write_text(path: Path | str, data: str, *, prefix: str = ".tmp-") -> None:
    """Durably + atomically replace `path` with `data`: write a temp file in the SAME dir, fsync it,
    `os.replace()` over the target (atomic on POSIX), then fsync the directory so the rename survives a
    crash. A crash at any point leaves the previous valid file intact, never a partially-written one."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=prefix, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    fsync_dir(path.parent)
