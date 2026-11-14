"""Point-in-time consistent reads of a spine unit — the helpers the upgrade drill, the backup capture and the staged
restore share.

A consistent copy is taken under a SHARED flock on the store's cross-process writer lockfile (writers hold it
EXCLUSIVELY per append) and proven by a content digest taken before and after the read: a writer that works outside
that lock (a concurrent ``sigil sign`` rewriting the head and the floor) changes the digest and the caller retries.
The digest skips files that are never read back as state: lockfiles, the ``*.idx`` read-index sidecars a reader
writes beside a segment, and the transient temp file of an atomic write (``.<name>.tmp``).

Sovereign plane; stdlib only.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator


@contextmanager
def shared_writer_lock(spine_dir: Path, data_name: str) -> Iterator[None]:
    """Hold a SHARED flock on the store's cross-process lockfile (``<ns>.lock``; writers take it EXCLUSIVELY per
    append) so a snapshot is consistent. Opened READ-ONLY and never created (the real home may be read-only);
    best-effort: no lockfile ⇒ no writer has ever run here ⇒ nothing to exclude."""
    fd = None
    lock = spine_dir / f"{Path(data_name).stem}.lock"
    try:
        if lock.is_file():
            import fcntl
            fd = os.open(str(lock), os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_SH)
    except Exception:  # noqa: BLE001 — best effort (non-POSIX / unreadable lock): the digest still proves it
        if fd is not None:
            os.close(fd)
        fd = None
    try:
        yield
    finally:
        if fd is not None:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def tree_digest(files: "Iterable[tuple[Path, Path]]") -> str:
    """A streamed content digest over ``(absolute path, relative path)`` pairs, in the order given: each relative
    path and the file's bytes. The caller chooses (and orders) the files."""
    h = hashlib.sha256()
    for p, rel in files:
        h.update(str(rel).encode("utf-8", "surrogateescape") + b"\0")
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        h.update(b"\0")
    return h.hexdigest()


def transient(name: str) -> bool:
    """A file never read back as state: a lockfile, a reader's ``*.idx`` sidecar, or an atomic write's temp file."""
    return name.endswith((".lock", ".idx")) or (name.startswith(".") and name.endswith(".tmp"))


def unit_files(root: Path) -> "list[tuple[Path, Path]]":
    """Every regular, non-transient file of one unit (a file or a directory tree), sorted, as ``(path, rel)``.
    Symlinks are never followed. A single file is its own unit (``rel`` is its name)."""
    root = Path(root)
    if root.is_symlink():
        return []
    if root.is_file():
        return [(root, Path(root.name))]
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file() or transient(p.name):
            continue
        out.append((p, p.relative_to(root)))
    return out


def unit_digest(root: Path) -> str:
    """The content digest of one unit (see :func:`unit_files`); an absent unit digests as ``"<absent>"``."""
    root = Path(root)
    if not (root.exists() or root.is_symlink()):
        return "<absent>"
    return tree_digest(unit_files(root))
