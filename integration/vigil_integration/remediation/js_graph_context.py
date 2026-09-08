"""remediation.js_graph_context — cross-file (import-graph) context for the deep-fix coder, JS/TS (PCR / Wave D).

No framework symbol index exists for JS/TS (the framework AST index is Python-only), so this is a
SELF-CONTAINED, dependency-free (stdlib regex + a bounded ``os.walk``) import-graph resolver. Given the
finding's JS/TS file it ranks the file's real cross-file neighborhood:

  1. **import targets** — the in-repo modules the finding's file imports (what a correct fix depends on),
  2. **callers** — the in-repo files that import the finding's file (the regression surface a fix must not
     break).

It returns a RANKED LIST OF REPO-RELATIVE PATHS; the caller (``codefix_runner._gather_repo_context``) does the
safe read (containment + byte budget), so path safety lives in ONE place. Fail-SOFT: any error returns
``None`` so the coder falls back to the same-dir-sibling default — a graph miss never breaks a fix.

Best-effort by nature: a regex import scan misses computed/dynamic specifiers and tsconfig path aliases, but
that only means falling back to siblings; it never breaks a fix, and it READS (never executes) the untrusted
repo. Bounded (file count + per-file bytes) and TOTAL (never raises).
"""
from __future__ import annotations

import os
import re
from typing import Optional

_MAX_GRAPH_PATHS = 12          # cap the neighborhood shown (codefix_runner budgets bytes/files too)
_MAX_CALLER_WALK = 4000        # bound the reverse-import scan over an untrusted tree
_MAX_FILE_BYTES = 262_144      # per-file bounded read
_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "coverage", "out"}

# module specifiers pulled from: `... from '<s>'`, side-effect `import '<s>'`, `require('<s>')`, dynamic
# `import('<s>')`, and `export ... from '<s>'`. Only the quoted specifier is captured.
_IMPORT_SPEC = re.compile(
    r"""(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"]([^'"\n]+)['"]""")


def _read(path: str) -> str:
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read(_MAX_FILE_BYTES)
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _specs(text: str) -> list[str]:
    """Relative module specifiers (``./x`` / ``../x``) imported by ``text``. Bare specs (node_modules,
    ``@scope/pkg``) and path aliases are skipped — they are not in-repo files."""
    out: list[str] = []
    for m in _IMPORT_SPEC.finditer(text):
        s = m.group(1)
        if s.startswith("."):
            out.append(s)
    return out


def _resolve(repo: str, from_file: str, spec: str) -> Optional[str]:
    """Resolve a relative specifier from ``from_file`` (repo-relative) to an existing in-repo file, applying
    node/TS resolution (extensionless, explicit ext, or ``/index.*``). Returns a repo-relative path that stays
    INSIDE the repo, or ``None``."""
    base = os.path.normpath(os.path.join(os.path.dirname(from_file), spec))
    if base.startswith("..") or os.path.isabs(base):     # escaped the repo root — reject (containment)
        return None
    cands: list[str] = [base + ext for ext in ("",) + _JS_EXTS + (".json",)]
    cands += [os.path.join(base, "index" + ext) for ext in _JS_EXTS]
    for c in cands:
        if not c or c == "." or c.startswith(".."):
            continue
        try:
            if os.path.isfile(os.path.join(repo, c)):
                return c
        except OSError:
            continue
    return None


def _iter_js_files(repo: str):
    """Bounded walk yielding repo-relative JS/TS file paths, skipping VCS/vendor/build dirs."""
    seen = 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if not f.endswith(_JS_EXTS):
                continue
            seen += 1
            if seen > _MAX_CALLER_WALK:
                return
            yield os.path.relpath(os.path.join(root, f), repo)


def js_graph_context_paths(repo: str, primary: str, *, max_paths: int = _MAX_GRAPH_PATHS) -> Optional[list[str]]:
    """Ranked repo-relative neighborhood of ``primary`` for JS/TS: its in-repo import targets first, then the
    files that import it (callers), excluding ``primary``. ``None`` on any failure (⇒ same-dir-sibling
    fallback). Never raises."""
    try:
        if not repo or "://" in repo or not primary or not primary.endswith(_JS_EXTS):
            return None
        prim_abs = os.path.join(repo, primary)
        if not os.path.isfile(prim_abs):
            return None

        ranked: list[str] = []
        seen = {primary}

        def _push(path: Optional[str]) -> None:
            if path and path not in seen and len(ranked) < max_paths:
                seen.add(path)
                ranked.append(path)

        # 1) import targets of primary (deps a correct fix depends on)
        for spec in _specs(_read(prim_abs)):
            _push(_resolve(repo, primary, spec))

        # 2) callers — files whose imports resolve to primary (the regression surface)
        if len(ranked) < max_paths:
            for cand in _iter_js_files(repo):
                if cand == primary or cand in seen:
                    continue
                for spec in _specs(_read(os.path.join(repo, cand))):
                    if _resolve(repo, cand, spec) == primary:
                        _push(cand)
                        break
                if len(ranked) >= max_paths:
                    break

        return ranked or None
    except Exception:  # noqa: BLE001 — a graph miss must fall back to siblings, never break a fix
        return None
