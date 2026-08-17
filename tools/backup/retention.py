"""A-S3 — backup retention (pure stdlib), shared by both planes' backup CLIs and the systemd timer.

``prune`` operates on a backup ROOT holding timestamped subdirectories named ``YYYYmmdd-HHMMSS`` (the format
``vigil backup --out`` writes). It applies a retention policy — keep the last N, and/or keep anything within D
days — and deletes the rest. It is deliberately conservative, because a retention bug deletes exactly the
disaster-recovery artifact you most need:

  * it ONLY ever considers directories whose name matches the timestamp glob — an arbitrary sibling file/dir
    (a ``latest`` symlink, a ``MANIFEST.json``, a ``README``) is NEVER a deletion candidate;
  * it NEVER deletes the newest backup, whatever the policy says (``keep_last=0`` still keeps the newest);
  * it refuses to delete the SOLE remaining backup (a root with 0 or 1 timestamped dirs prunes nothing);
  * with NEITHER ``keep_days`` NOR ``keep_last`` given it is a no-op (it refuses to prune without an explicit
    policy — a missing policy must not mean "delete everything");
  * ``dry_run`` returns exactly what WOULD be deleted, touching nothing.

It never follows symlinks and never calls ``rmtree`` on a path that is not itself a timestamp-glob directory.
"""
from __future__ import annotations

import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# The timestamped-subdir name format ``vigil backup`` writes: YYYYmmdd-HHMMSS (fixed width → lexicographic
# order IS chronological). The anchors make this the WHOLE name — a dir like ``20260101-000000-note`` or a
# stray file is never matched, so it can never be a deletion candidate.
_TS_RE = re.compile(r"^\d{8}-\d{6}$")
_TS_FMT = "%Y%m%d-%H%M%S"


def timestamp_name(when: Optional[datetime] = None) -> str:
    """The canonical timestamped-subdir name for ``when`` (default: now, UTC). Used by the backup CLI so the
    names it writes are exactly the ones ``prune`` recognises."""
    return (when or datetime.now(timezone.utc)).strftime(_TS_FMT)


def _timestamp_dirs(root: Path) -> list[Path]:
    """Every timestamp-glob directory directly under ``root``, ascending (chronological). Symlinked dirs are
    excluded — a retention pass must never traverse or delete through a link."""
    out = [p for p in root.iterdir()
           if p.is_dir() and not p.is_symlink() and _TS_RE.match(p.name)]
    return sorted(out, key=lambda p: p.name)


def _parse_ts(name: str) -> Optional[datetime]:
    try:
        return datetime.strptime(name, _TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def prune(
    directory,
    *,
    keep_days: Optional[int] = None,
    keep_last: Optional[int] = None,
    dry_run: bool = False,
    now: Optional[datetime] = None,
) -> list[Path]:
    """Delete timestamped backup subdirs of ``directory`` outside the retention policy; return the deleted
    (or, under ``dry_run``, would-be-deleted) paths, oldest first. A dir SURVIVES iff it is the newest, OR
    among the last ``keep_last``, OR within ``keep_days`` of ``now``. No policy → no-op. Never deletes the
    newest or the sole remaining backup, and only ever touches timestamp-glob directories."""
    root = Path(directory)
    if not root.is_dir():
        return []
    dirs = _timestamp_dirs(root)
    if len(dirs) <= 1:
        return []                               # sole remaining (or none) → never prune
    if keep_days is None and keep_last is None:
        return []                               # no explicit policy → refuse to prune anything

    newest = dirs[-1]
    survivors: set[Path] = {newest}             # the newest ALWAYS survives, whatever the policy
    if keep_last is not None:
        n = max(int(keep_last), 1)              # keep_last=0 still keeps the newest (never zero survivors)
        survivors.update(dirs[-n:])
    if keep_days is not None:
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=int(keep_days))
        for p in dirs:
            ts = _parse_ts(p.name)
            if ts is not None and ts >= cutoff:
                survivors.add(p)

    to_delete = [p for p in dirs if p not in survivors]
    deleted: list[Path] = []
    for p in to_delete:
        # paranoia backstop: only ever rmtree a real, non-symlink, timestamp-glob dir (never the newest).
        if p == newest or p.is_symlink() or not p.is_dir() or not _TS_RE.match(p.name):
            continue
        if not dry_run:
            shutil.rmtree(p)
        deleted.append(p)
    return deleted
