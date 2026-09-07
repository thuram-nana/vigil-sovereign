"""remediation.buildsys — detect a repo's dependency-light build/test command for the deep-fix gate.

The deep-fix ladder runs a fix's patched clone through a BUILD/TEST gate (Axis A — it BLOCKS a fix that
breaks the code; it never certifies one). That runs inside the network-isolated bwrap sandbox
(`live.sandbox_exec.run_sandboxed`), which binds only `/usr` + the clone — NO network, so `pip install` /
`npm install` cannot run. So this detector is deliberately CONSERVATIVE: it returns a command only when it is
plausibly runnable with no third-party deps (e.g. Python `compileall`, `node --check`), and returns nothing
("skip the axis honestly") otherwise. A returned command is a `/bin/sh -c` string executed with CWD = the
clone; it never contains repo-supplied text (only the fixed literals below), so it is injection-free.

Pure + total: reads only the presence of well-known files; never imports `framework`; never runs anything.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class BuildPlan:
    build_cmd: str = ""      # a dependency-light sanity/compile check (Axis A gate); "" = none detected
    test_cmd: str = ""       # the repo's test command, ONLY when dep-light enough to run offline; "" = skip
    language: str = ""
    note: str = ""           # human-readable: what will run, or why the test axis is skipped


def _has(repo: str, *names: str) -> bool:
    return any(os.path.exists(os.path.join(repo, n)) for n in names)


def _any_ext(repo: str, ext: str, *, max_walk: int = 4000) -> bool:
    """Is there at least one file with ``ext`` anywhere in the tree? Bounded walk; skips VCS/vendor dirs."""
    seen = 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build")]
        for f in files:
            seen += 1
            if seen > max_walk:
                return False
            if f.endswith(ext):
                return True
    return False


def detect_build_plan(repo: str) -> BuildPlan:
    """Best-effort, offline-safe (build_cmd, test_cmd) for ``repo``. Conservative by design: it prefers a
    dependency-FREE compile/syntax check as the gate and skips the actual test suite unless it is dep-light,
    because a fresh clone in a no-network sandbox usually lacks third-party test deps — and a spuriously
    failing test would BLOCK a correct fix. Total: an unreadable repo yields an empty plan."""
    try:
        if not repo or "://" in repo or not os.path.isdir(repo):
            return BuildPlan(note="no local repo to analyze")
    except OSError:
        return BuildPlan(note="repo not readable")

    # ---- Python: compileall is stdlib-only and catches a patch that broke syntax/indentation ----
    if _has(repo, "pyproject.toml", "setup.py", "setup.cfg", "tox.ini", "pytest.ini") or _any_ext(repo, ".py"):
        # `compileall -q .` byte-compiles every .py under the clone with the sandbox's system python — no
        # third-party deps needed. It is the dependency-free Axis-A gate. We do NOT auto-run pytest: a fresh
        # clone lacks its deps offline, so a pytest error would falsely block a good fix — skip it honestly
        # (an operator can still pass an explicit test_cmd via the deep-fix config when deps are vendored).
        return BuildPlan(build_cmd="python3 -m compileall -q .", test_cmd="", language="python",
                         note="python: byte-compile gate (compileall); test suite skipped (offline sandbox has no third-party deps)")

    # ---- JavaScript/TypeScript: node --check per JS file is dep-free syntax validation ----
    if _has(repo, "package.json") or _any_ext(repo, ".js"):
        # `node --check` validates syntax without executing or needing node_modules; run it over tracked .js.
        return BuildPlan(
            build_cmd="find . -path ./node_modules -prune -o -name '*.js' -print0 | xargs -0 -r -n1 node --check",
            test_cmd="", language="javascript",
            note="javascript: node --check syntax gate; npm test skipped (offline sandbox has no node_modules)")

    # ---- Go: `go build ./...` needs the module cache but no network for stdlib-only; still skip by default ----
    if _has(repo, "go.mod"):
        return BuildPlan(build_cmd="", test_cmd="", language="go",
                         note="go: build/test skipped (needs the module cache; not run in the offline sandbox)")

    return BuildPlan(note="no known build system detected — build/test axis skipped (apply-check only)")
