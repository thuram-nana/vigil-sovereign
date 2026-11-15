#!/usr/bin/env python3
"""Is a release an EDGE-ONLY change — one the edge swap alone can deliver, with no full upgrade?

    python3 tools/deploy/edge_only.py <installed-ref> <release-ref>

Exit 0 and print the edges to swap ("customer", "public" or both) when every file that differs between the two
refs is either
  * a static file the edges serve: apps/sigil/sigil/ui/customer_app/** (the customer edge) or
    apps/sigil/sigil/ui/public_site/** (the public site) — the edges read them once at startup, so a new edge
    process serves them and nothing else needs to restart; or
  * a file no running VIGIL process reads: VERSION and CHANGELOG.md (read only by `--version` and people),
    packages/vigil-brand/** (the logo's author-time source), and anything under a tests/ directory;
and at least one served file changed. Exit 1 (and name the files) when anything else changed — Python code, the
console kit, configuration, docs/ (some of it is read at run time), units: that release needs the full upgrade
(docs/runbooks/RELEASE-UPGRADE-ROLLBACK.md). Exit 3 when nothing differs, 2 on a usage or git error.

A rename is checked on both sides (`--no-renames`), so moving a file out of a served tree counts against it.
Reads git only; changes nothing. stdlib only.
"""
from __future__ import annotations

import subprocess
import sys

EDGES = {
    "customer": "apps/sigil/sigil/ui/customer_app/",
    "public": "apps/sigil/sigil/ui/public_site/",
}
INERT_FILES = frozenset({"VERSION", "CHANGELOG.md"})
INERT_PREFIXES = ("packages/vigil-brand/",)


def _inert(path: str) -> bool:
    return path in INERT_FILES or path.startswith(INERT_PREFIXES) or "/tests/" in f"/{path}"


def classify(paths: "list[str]") -> "tuple[list[str], list[str]]":
    """(edges whose served files changed, paths that rule the fast path out)."""
    edges: set[str] = set()
    blockers: list[str] = []
    for p in paths:
        edge = next((e for e, prefix in EDGES.items() if p.startswith(prefix)), None)
        if edge is not None:
            edges.add(edge)
        elif not _inert(p):
            blockers.append(p)
    return sorted(edges), blockers


def changed_paths(old: str, new: str) -> "list[str]":
    out = subprocess.run(["git", "diff", "--name-only", "--no-renames", "-z", old, new],
                         capture_output=True, check=True, timeout=60).stdout
    return [p for p in out.decode("utf-8", errors="surrogateescape").split("\0") if p]


def main(argv: "list[str]") -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        paths = changed_paths(argv[0], argv[1])
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as e:
        print(f"edge_only: cannot diff {argv[0]}..{argv[1]}: {e}", file=sys.stderr)
        return 2
    if not paths:
        print("edge_only: nothing differs")
        return 3
    edges, blockers = classify(paths)
    if blockers:
        print("edge_only: NOT edge-only — the full upgrade is needed; these files are not served static files:")
        for p in blockers:
            print(f"  {p}")
        return 1
    if not edges:
        print("edge_only: only files no running process reads changed — nothing to swap")
        return 3
    print("edge-only: " + " ".join(edges))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
