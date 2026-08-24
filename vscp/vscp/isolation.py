"""VSCP isolation invariants — the CI-enforced proof surface (W13-7 / #500).

VSCP (the Vigil Sovereign Control Plane) is a SIBLING application to the VIGIL
assessment product. The operator decision for #500 is that it must be provably
ISOLATED from that product: a separate database, separate credentials / signing
material, and NO import path or network path to assessment findings.

This module hosts the pure, **stdlib-only** checkers that make that isolation
FALSIFIABLE. Both the VSCP-own test suite (``vscp/tests/test_isolation.py``) and the
load-bearing proof in the required integration CI job
(``integration/tests/test_vscp_isolation.py``) call THESE functions, so the property
is enforced identically wherever it is checked, and a single edit here cannot weaken
one site without weakening the other.

There is deliberately NO knob that turns any of these checks off (mirroring the
``sovereign_bridge`` "no ``skip_security_checks`` flag anywhere" invariant): a checker
that could be disabled would not be a proof.
"""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

__all__ = [
    "ALLOWED_FIRST_PARTY_ROOTS",
    "FORBIDDEN_IMPORT_ROOTS",
    "ImportViolation",
    "module_import_roots",
    "classify_import_root",
    "find_forbidden_import",
    "scan_tree_for_import_violations",
    "stdlib_roots",
]

# Import roots VSCP source is ALLOWED to depend on beyond the standard library: the
# shared, offense-free integrity substrate ``vigil_core`` (Ed25519 crypto, the signed
# hash-chain, the RBAC vocabulary — NEVER findings; ``vigil_core`` itself imports no
# ``framework`` / ``strix`` / ``sigil``, asserted by its own suite) and VSCP's own
# package. Everything else must be the standard library, or it is a violation.
ALLOWED_FIRST_PARTY_ROOTS: frozenset[str] = frozenset({"vigil_core", "vscp"})

# Import roots that belong to the PRODUCT (assessment engine) or its trust planes. Any
# of these appearing in VSCP source is an isolation breach — this is the concrete
# meaning of "NO import path to assessment findings":
#
#   * ``framework``          — the CRUCIBLE offensive assessment engine (where findings,
#                              oracles and the offense blackboard live);
#   * ``strix``              — the offensive agent runtime;
#   * ``sigil``              — the sovereign personal core (owner-key process);
#   * ``vigil_integration``  — the offense<->sovereign seam. Included WHOLESALE and on
#                              purpose: its package ``__init__`` eagerly imports the
#                              inert-finding machinery (``vigil_integration.inert_finding``),
#                              so importing ANY of its submodules — even the innocuous-
#                              looking ``sovereign_bridge`` facade — would execute that
#                              ``__init__`` and thereby create a live import path to
#                              assessment-finding code. VSCP therefore reuses the gate /
#                              crypto / chain primitives from ``vigil_core`` directly and
#                              never touches this seam.
FORBIDDEN_IMPORT_ROOTS: frozenset[str] = frozenset(
    {"framework", "strix", "sigil", "vigil_integration"}
)


def stdlib_roots() -> frozenset[str]:
    """The set of top-level standard-library module names on this interpreter, plus the
    built-ins. ``sys.stdlib_module_names`` is frozen per build (Python >= 3.10)."""
    return frozenset(sys.stdlib_module_names) | frozenset(sys.builtin_module_names)


@dataclass(frozen=True)
class ImportViolation:
    """One offending import found in a VSCP source file."""

    file: str
    root: str
    reason: str


def module_import_roots(source: str, *, filename: str = "<vscp>") -> set[str]:
    """The set of TOP-LEVEL import roots a Python source string depends on.

    ``import a.b.c`` and ``from a.b import x`` both contribute the root ``a``. A
    ``from . import x`` / ``from .sub import y`` relative import stays inside the VSCP
    package, so it contributes the root ``vscp`` (never an external dependency). A
    syntactically invalid source raises ``SyntaxError`` — a file VSCP ships must parse.
    """
    tree = ast.parse(source, filename=filename)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                # relative import — resolves within the VSCP package itself
                roots.add("vscp")
            elif node.module:
                roots.add(node.module.split(".")[0])
    return roots


def classify_import_root(root: str) -> str | None:
    """Return a human-readable violation reason for ``root``, or ``None`` if the root is
    allowed. Fail-closed: a root that is neither forbidden, first-party-allowed, nor a
    standard-library module is itself a violation (an unexpected external dependency is
    refused, so the allowlist can never be silently widened by a new third-party import).
    """
    if root in FORBIDDEN_IMPORT_ROOTS:
        return (
            f"imports {root!r}, which belongs to the assessment product / its trust "
            "planes — a forbidden import path to assessment findings (W13-7 isolation)"
        )
    if root in ALLOWED_FIRST_PARTY_ROOTS:
        return None
    if root in stdlib_roots():
        return None
    return (
        f"imports {root!r}, which is not on the VSCP allowlist (standard library, "
        "'vigil_core', or 'vscp'): an unexpected external dependency is refused fail-closed"
    )


def find_forbidden_import(source: str, *, filename: str = "<vscp>") -> str | None:
    """The first FORBIDDEN import root in a source string, or ``None``. This is the exact
    predicate the negative control drives: a synthetic source that imports ``framework``
    (or any product root) must return that root, proving the scanner is not a no-op."""
    for root in sorted(module_import_roots(source, filename=filename)):
        if root in FORBIDDEN_IMPORT_ROOTS:
            return root
    return None


def _iter_python_files(root: Path) -> Iterable[Path]:
    for p in sorted(root.rglob("*.py")):
        # Skip caches; ship-relevant source only.
        if "__pycache__" in p.parts:
            continue
        yield p


def scan_tree_for_import_violations(root: Path) -> list[ImportViolation]:
    """Scan every ``*.py`` under ``root`` (the VSCP package) and return every import that
    violates the isolation allow/deny rules. An empty list means the tree is clean.

    Pure AST + file reads: it imports none of the scanned code, so scanning VSCP can
    never itself drag a forbidden module into the process running the check.
    """
    violations: list[ImportViolation] = []
    root = Path(root)
    for path in _iter_python_files(root):
        source = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        for import_root in sorted(module_import_roots(source, filename=str(path))):
            reason = classify_import_root(import_root)
            if reason is not None:
                violations.append(ImportViolation(file=rel, root=import_root, reason=reason))
    return violations
