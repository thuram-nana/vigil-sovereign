"""remediation.graph_context — cross-file (call-graph) context for the deep-fix coder (PCR / W2).

The one-file-plus-same-dir-siblings neighborhood (codefix_runner._gather_repo_context default) is blind to a
fix that must change a CALLER three modules away or understand a DEFINITION in another package. This provider
uses the framework's symbol index (``framework.v2.analysis.index.build_symbol_index`` — a stdlib-AST index of
function/class defs, imports, and call sites) to rank the finding file's real neighborhood:

  1. **callee definitions** — the files that DEFINE the functions the finding's file calls (what a correct fix
     depends on),
  2. **callers** — the files that CALL functions defined in the finding's file (the regression surface a fix
     must not break),
  3. **import targets** — in-repo modules the finding's file imports.

It returns a RANKED LIST OF REPO-RELATIVE PATHS; the caller (``_gather_repo_context(extra_paths=…)``) does the
safe read (``is_safe_repo_path`` + symlink/realpath containment + byte budget), so path safety lives in ONE
place. Fail-SOFT: any error (no framework, unindexable tree) returns ``None`` so the coder falls back to the
same-dir-sibling default — a graph miss never breaks a fix.

Two-env clean: the framework import is FUNCTION-LOCAL (offense path only); module scope is stdlib only.
"""
from __future__ import annotations

import os
from typing import Optional

_MAX_GRAPH_PATHS = 12       # cap the neighborhood the coder is shown (codefix_runner budgets bytes/files too)


def _import_relpaths(repo: str, module: str) -> list[str]:
    """Best-effort map an imported dotted module to in-repo file(s): a.b.c -> a/b/c.py | a/b/c/__init__.py |
    a/b.py (the `from a.b import c` case). Only paths that EXIST under repo are returned (stdlib/third-party
    modules simply yield nothing)."""
    parts = [p for p in str(module or "").split(".") if p]
    out: list[str] = []
    for cut in (len(parts), len(parts) - 1):   # full module, then its parent (from-import symbol case)
        if cut <= 0:
            continue
        base = os.path.join(*parts[:cut])
        for cand in (base + ".py", os.path.join(base, "__init__.py")):
            if os.path.isfile(os.path.join(repo, cand)) and cand not in out:
                out.append(cand)
    return out


_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")


def graph_context_paths(repo: str, primary: str, *, max_paths: int = _MAX_GRAPH_PATHS) -> Optional[list[str]]:
    """Language-dispatching ranked repo-relative neighborhood of ``primary``, excluding ``primary`` itself.
    Python (.py) uses the framework symbol index (callee defs, callers, import targets); JS/TS routes to the
    self-contained import-graph resolver. ``None`` on any failure or unsupported language (⇒ same-dir-sibling
    default). Never raises."""
    if not repo or "://" in repo or not primary:
        return None
    if primary.endswith(_JS_EXTS):                                   # Wave D: JS/TS import graph
        from .js_graph_context import js_graph_context_paths        # noqa: PLC0415 — stdlib-only sibling
        return js_graph_context_paths(repo, primary, max_paths=max_paths)
    if not primary.endswith(".py"):                                  # only python + js/ts have a resolver
        return None
    try:
        from framework.v2.analysis.index import build_symbol_index   # noqa: PLC0415 — FATAL-2: offense-only, lazy
        from framework.v2.analysis.models import AnalysisTarget      # noqa: PLC0415
    except Exception:  # noqa: BLE001 — no framework ⇒ no graph context, fall back
        return None
    try:
        idx = build_symbol_index(AnalysisTarget(root=repo))
    except Exception:  # noqa: BLE001 — an unindexable tree ⇒ fall back
        return None

    try:
        defs_in_primary = {s.name for s in idx.of_kind("function") if s.path == primary}
        defs_in_primary |= {s.name for s in idx.of_kind("class") if s.path == primary}
        calls_in_primary = {s.name for s in idx.of_kind("call") if s.path == primary}
        imports_in_primary = [s.name for s in idx.of_kind("import") if s.path == primary]

        ranked: list[str] = []
        seen = {primary}

        def _push(path: str) -> None:
            if path and path not in seen and len(ranked) < max_paths:
                seen.add(path)
                ranked.append(path)

        # 1) files that DEFINE what primary calls (callee definitions)
        for name in sorted(calls_in_primary):
            for sym in idx.find_function(name):
                _push(sym.path)
        # 2) files that CALL what primary defines (the regression/caller surface)
        for name in sorted(defs_in_primary):
            for sym in idx.find_callsites(name):
                _push(sym.path)
        # 3) in-repo import targets
        for mod in imports_in_primary:
            for rp in _import_relpaths(repo, mod):
                _push(rp)

        return ranked or None
    except Exception:  # noqa: BLE001 — never let ranking break a fix
        return None
