"""Static guard: the E2E harness must stay OUT of the two FATAL-2 venvs.

The harness is only a browser/HTTP client of http://127.0.0.1:8770. No file under
tests/e2e/ may import `framework`, `strix`, or `vigil_integration` (the sovereign
integration package) — doing so would drag sovereign/offense code into the
browser-client venv and break the FATAL-2 isolation.

This test needs no browser and no running stack; it reads the harness sources.
"""
from __future__ import annotations

import ast
import pathlib

HARNESS_DIR = pathlib.Path(__file__).resolve().parent
FORBIDDEN_ROOTS = {"framework", "strix", "vigil_integration"}


def _imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


def test_no_fatal2_imports_anywhere_in_harness():
    offenders: dict[str, set[str]] = {}
    for py in sorted(HARNESS_DIR.glob("*.py")):
        roots = _imported_roots(py.read_text(encoding="utf-8"))
        bad = roots & FORBIDDEN_ROOTS
        if bad:
            offenders[py.name] = bad
    assert not offenders, (
        "FATAL-2 violation: E2E harness files import sovereign/offense code: "
        f"{offenders}"
    )
