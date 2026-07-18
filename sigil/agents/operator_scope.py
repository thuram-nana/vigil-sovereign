"""OperatorScope (Phase 7, WS-B B-ii) — the capability-scoped two-ring sandbox that bounds where the
Operator may read and auto-write. Wraps the currently-UNGUARDED local-path branch of
`sources.read_source` so the Operator can never touch an arbitrary path.

Two rings:
  • read_roots — the Operator may READ here (A0/A1).
  • auto_write_roots — the narrower set where an A1 reversible write may AUTO-apply; a write/delete
    inside a read root but OUTSIDE an auto-write root must be QUEUED for approval, not auto-run.

Every path is realpath-resolved (symlinks followed) and must be *within* an allowed root — a `..`,
a symlink escaping the root, or an absolute path elsewhere resolves outside and is refused. EMPTY
roots = deny-all (fail-closed), the inverse of `read_source`'s current unguarded default. The
resolved real path is returned so the caller opens exactly what was vetted (no re-resolve → no
TOCTOU gap between the check and the open)."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional


def _within(p: Path, root: Path) -> bool:
    return p == root or p.is_relative_to(root)


class OperatorScope:
    def __init__(self, read_roots: Optional[List[str]] = None,
                 auto_write_roots: Optional[List[str]] = None):
        self.read_roots = [Path(r).resolve() for r in (read_roots or [])]
        self.auto_write_roots = [Path(r).resolve() for r in (auto_write_roots or [])]

    @staticmethod
    def _realpath(path: str) -> Optional[Path]:
        """Resolve symlinks + `..` (strict=False so a not-yet-existing write target still resolves
        via its existing parents). None on an unresolvable path."""
        try:
            return Path(path).resolve()
        except (OSError, RuntimeError, ValueError):
            return None

    def resolve(self, path: str, need: str = "read") -> Optional[Path]:
        """Return the vetted REAL path iff it is within the ring for `need` ('read' | 'write'), else
        None. Open THIS returned path (never re-resolve `path`) to avoid a check/open TOCTOU."""
        rp = self._realpath(path)
        if rp is None:
            return None
        roots = self.auto_write_roots if need == "write" else self.read_roots
        return rp if any(_within(rp, root) for root in roots) else None

    def in_read(self, path: str) -> bool:
        return self.resolve(path, "read") is not None

    def in_auto_write(self, path: str) -> bool:
        return self.resolve(path, "write") is not None
