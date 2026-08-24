"""W16-16 (#522) — every registered capability has at least one INVOCATION PATH, or CI goes red.

The measured defect (OUTSTANDING A-8): six cloud/Kubernetes exploitation CONFIRMATIONS, the H4 audit
package, and the live AI-Gauntlet shipped tested but reachable from NO verb/route/button — imported only by
their own tests. A capability nothing can call is not a capability; it is dead code wearing a claim.

This is the STRUCTURAL guard. It enumerates the registered capabilities and asserts each is really wired:

  * CLOUD/K8s CONFIRMATIONS are enumerated AUTOMATICALLY from the authoritative capability matrix
    (docs/capability-matrix/evidence-branches.json): any evidence branch whose ``implementation_refs`` name a
    ``integration/vigil_integration/live/*_verify.py:<fn>`` producer is a confirmation, and its ``<fn>`` MUST
    be referenced by some production (non-test, non-self) .py file. So a NEW confirmation branch added later
    with no caller reddens this test with no edit here — that is criterion (b).

  * NAMED product capabilities are enumerated from docs/capability-matrix/invocation-paths.json (the H4 audit
    package, the AI-Gauntlet, web_redrive, the posture verb). A ``symbol`` entry is checked the same way; a
    ``cli_verb`` entry is checked against the live argparse dispatch.

"Referenced" is decided by the PYTHON AST, never by string search: a ``Name``/``Attribute``/``ImportFrom``
that names the symbol counts; a mention inside a comment or docstring does NOT (the confirmations mention each
other in docstrings — those must not read as wiring). So deleting the real call that wires a shipped capability
reddens this test even if a prose mention of it survives — criterion (c). The self-contained negative control
(test_ast_detector_is_not_a_no_op) proves the detector distinguishes a wired symbol from an orphaned one.

SOVEREIGN-SAFE / FRAMEWORK-FREE by construction: this file imports only stdlib (ast, json, pathlib) plus, for
the cli_verb check, ``vigil_integration.cli`` whose module scope is stdlib-only. It never imports ``framework``
or ``strix``, so it runs in the required P5 "integration two-env boundary" job and needs NO offense-leg
run-list entry (the test_ci_framework_tests_run_in_offense_leg guard does not implicate it).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# The product source roots a real caller could live under (excludes tests + vendored code). Callers for the
# capabilities in scope live in integration/ (cli.py, proof/) and engine/crucible/framework (evidence/cli.py)
# and tools/livefire; the wider roots make the guard sound if a caller moves.
_ROOTS = [
    _REPO / "integration" / "vigil_integration",
    _REPO / "engine" / "crucible" / "framework",
    _REPO / "gateway" / "vigil_gateway",
    _REPO / "tools",
]

_MATRIX = _REPO / "docs" / "capability-matrix" / "evidence-branches.json"
_INVOCATION = _REPO / "docs" / "capability-matrix" / "invocation-paths.json"


def _is_test_file(p: Path) -> bool:
    parts = p.parts
    return p.name.startswith("test_") or "tests" in parts or "test" in parts


def _referenced_names(tree: ast.AST) -> set[str]:
    """Every symbol NAME this module references as real code (not in a comment/docstring): imported names,
    Name loads, and attribute accesses. AST-derived, so string literals / docstrings never contribute."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                names.add(a.name)
                if a.asname:
                    names.add(a.asname)
        elif isinstance(node, ast.Import):
            for a in node.names:
                names.add((a.asname or a.name).split(".")[0])
    return names


def _build_index() -> dict[Path, set[str]]:
    """Parse every production .py file under the roots ONCE; map file -> set of referenced symbol names.

    ``__init__.py`` files are EXCLUDED: a package facade that re-exports a symbol (``from .x import fn`` +
    ``__all__``) makes it importable but does NOT invoke it — counting a re-export as an invocation path is
    exactly the false-negative that would let an orphaned-but-re-exported capability (e.g. the H4 audit
    package, re-exported by evidence/__init__.py) slip through. A real caller lives in a non-facade module."""
    index: dict[Path, set[str]] = {}
    for root in _ROOTS:
        if not root.is_dir():
            continue
        for py in root.rglob("*.py"):
            if _is_test_file(py) or "vendor" in py.parts or py.name == "__init__.py":
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except (SyntaxError, ValueError):
                continue
            index[py] = _referenced_names(tree)
    return index


_INDEX = _build_index()


def _production_callers(symbol: str, def_file: Path) -> list[Path]:
    """Production files (excluding the symbol's own definition file) that AST-reference ``symbol``."""
    def_resolved = def_file.resolve()
    return sorted(f for f, names in _INDEX.items()
                  if f.resolve() != def_resolved and symbol in names)


# --------------------------------------------------------------------------------------------------------
# enumerate the CLOUD/K8s confirmations from the authoritative evidence-branch matrix (automatic).
# --------------------------------------------------------------------------------------------------------

def _confirmation_producers() -> list[tuple[str, Path, str]]:
    """(branch_id, def_file, symbol) for every evidence branch whose implementation_refs name a
    live/*_verify.py producer. This is the automatic enumeration: a new confirmation branch appears here with
    no edit to this test."""
    matrix = json.loads(_MATRIX.read_text(encoding="utf-8"))
    out: list[tuple[str, Path, str]] = []
    for branch in matrix.get("branches", []):
        for ref in branch.get("implementation_refs", []):
            path_part, _, symbol = str(ref).partition(":")
            if not symbol:
                continue
            p = Path(path_part)
            if (p.parts[-2:-1] == ("live",) and p.name.endswith("_verify.py")
                    and p.parts[:3] == ("integration", "vigil_integration", "live")):
                out.append((branch["id"], _REPO / p, symbol))
    return out


def test_capability_matrix_lists_the_confirmation_families():
    # Guard the enumeration source itself: the six known cloud/K8s confirmation branches must be present, so a
    # matrix edit that silently drops one cannot make the enumeration vacuous.
    ids = {bid for bid, _, _ in _confirmation_producers()}
    for required in (
        "cloud_exploit.imds.credential_capture",
        "cloud_exploit.secret.credential_validity",
        "cloud_exploit.gcp.sa_impersonation",
        "cloud_exploit.iam.privilege_escalation",
        "k8s_exploit.rbac.anonymous_privileged_binding",
        "k8s_exploit.rbac.dangerous_verb_grant",
    ):
        assert required in ids, f"confirmation branch {required} vanished from evidence-branches.json"


@pytest.mark.parametrize("branch_id,def_file,symbol", _confirmation_producers(),
                         ids=[f"{b}:{s}" for b, _, s in _confirmation_producers()])
def test_each_cloud_confirmation_has_an_invocation_path(branch_id: str, def_file: Path, symbol: str):
    # The heart of #522: a confirmation whose only references are its own module + tests is ORPHANED.
    assert def_file.is_file(), f"{branch_id}: producer file {def_file} does not exist"
    callers = _production_callers(symbol, def_file)
    assert callers, (
        f"ORPHAN: {branch_id} producer {symbol}() (in {def_file.relative_to(_REPO)}) has NO production "
        f"invocation path — no verb/route/button/pipeline references it. Wire it (e.g. `vigil cloud-exploit "
        f"{symbol}`) or remove the capability. This is exactly the W16-16 defect the test exists to catch.")


# --------------------------------------------------------------------------------------------------------
# enumerate the NAMED product capabilities from the invocation-paths registry (claim-registered).
# --------------------------------------------------------------------------------------------------------

def _named_capabilities() -> list[dict]:
    reg = json.loads(_INVOCATION.read_text(encoding="utf-8"))
    return list(reg.get("capabilities", []))


def test_every_cloud_confirmation_is_registered_in_invocation_paths():
    # "claim registered": every enumerated confirmation must ALSO be documented in invocation-paths.json, so
    # the human-readable registry cannot drift behind the automatic enumeration.
    registered_branches = {c.get("evidence_branch") for c in _named_capabilities() if c.get("evidence_branch")}
    for branch_id, _, _ in _confirmation_producers():
        assert branch_id in registered_branches, (
            f"{branch_id} is enumerated from evidence-branches.json but NOT registered in "
            f"invocation-paths.json — add it so the claim is registered.")


@pytest.mark.parametrize("cap", [c for c in _named_capabilities() if c.get("kind") == "symbol"],
                         ids=[c["id"] for c in _named_capabilities() if c.get("kind") == "symbol"])
def test_named_symbol_capability_has_an_invocation_path(cap: dict):
    path_part, _, symbol = str(cap["entry"]).partition(":")
    def_file = _REPO / path_part
    assert def_file.is_file(), f"{cap['id']}: entry file {def_file} does not exist"
    callers = _production_callers(symbol, def_file)
    assert callers, (
        f"ORPHAN: named capability {cap['id']} entry {symbol}() has NO production invocation path. "
        f"Declared invocation: {cap.get('invocation')!r} at {cap.get('invocation_ref')!r}.")


@pytest.mark.parametrize("cap", [c for c in _named_capabilities() if c.get("kind") == "cli_verb"],
                         ids=[c["id"] for c in _named_capabilities() if c.get("kind") == "cli_verb"])
def test_named_cli_verb_capability_is_registered(cap: dict):
    cli_name, _, verb = str(cap["verb"]).partition(":")
    assert cli_name == "vigil", f"{cap['id']}: only the `vigil` CLI verb check is implemented"
    from vigil_integration import cli as _cli  # module scope is stdlib-only (framework-free)
    import argparse
    parser = _cli.build_parser()
    sub = [a for a in parser._subparsers._group_actions
           if isinstance(a, argparse._SubParsersAction)][0]
    assert verb in sub.choices, f"ORPHAN: `vigil {verb}` is not a registered dispatch verb"


def test_new_cloud_exploit_verb_wires_all_six_confirmations():
    # Belt-and-braces: the new verb IS the invocation path for the six confirmations — assert it is registered
    # and that its handler references every one of the six producer symbols (a real Name reference, so a
    # future refactor that drops one is caught here too).
    from vigil_integration import cli as _cli
    import argparse
    parser = _cli.build_parser()
    sub = [a for a in parser._subparsers._group_actions
           if isinstance(a, argparse._SubParsersAction)][0]
    assert "cloud-exploit" in sub.choices and "gauntlet" in sub.choices
    cli_names = _INDEX[(_REPO / "integration" / "vigil_integration" / "cli.py")]
    for sym in ("imds_verify", "secret_verify", "gcp_impersonation_verify",
                "iam_escalation_verify", "rbac_verify", "grant_verify",
                "run_gauntlet_report"):
        assert sym in cli_names, f"cli.py no longer references {sym} — the invocation path was removed"


# --------------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL — the AST caller-detector is not a no-op (self-contained, deterministic).
# --------------------------------------------------------------------------------------------------------

def test_ast_detector_is_not_a_no_op(tmp_path: Path):
    """Prove the detector actually distinguishes wired from orphaned, and that a docstring mention does NOT
    count as wiring (so deleting the real call reddens even when prose survives)."""
    def_file = tmp_path / "def_mod.py"
    def_file.write_text("def widget():\n    return 1\n", encoding="utf-8")

    # (1) a file that mentions `widget` ONLY in a docstring/comment must NOT count as a caller.
    prose = tmp_path / "prose.py"
    prose.write_text('"""this module talks about widget() a lot."""\n# widget widget widget\nX = 1\n',
                     encoding="utf-8")
    # (2) a real caller that imports and calls it MUST count.
    caller = tmp_path / "caller.py"
    caller.write_text("from def_mod import widget\n\ndef go():\n    return widget()\n", encoding="utf-8")

    def refs(p: Path) -> set[str]:
        return _referenced_names(ast.parse(p.read_text(encoding="utf-8")))

    assert "widget" not in refs(prose), "a docstring/comment mention must NOT read as an invocation path"
    assert "widget" in refs(caller), "a real import+call MUST be detected as an invocation path"

    # And end-to-end over the same index logic: with only `prose.py` present, `widget` is ORPHANED; adding
    # `caller.py` flips it to wired. This is the (c) negative control in miniature.
    idx = {prose: refs(prose)}
    orphaned = [f for f, n in idx.items() if f != def_file and "widget" in n]
    assert orphaned == [], "detector wrongly counted a prose-only mention as a caller (would hide orphans)"
    idx[caller] = refs(caller)
    wired = [f for f, n in idx.items() if f != def_file and "widget" in n]
    assert wired == [caller], "detector failed to see the real caller (would false-positive orphans)"
