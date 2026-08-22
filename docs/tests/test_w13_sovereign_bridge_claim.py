"""Doc-truth pin for W13-2 (#495): the sovereign_bridge facade decision record is TRUE of the code.

This rides the already-required "the briefing explains every agent and capability" job (`pytest docs/tests
-q`), which installs only pytest and reads files — so this test imports nothing beyond the standard library
(no `vigil_integration`, which is not on the path there). It asserts the claims written in
`docs/decisions/W13-2-sovereign-bridge-facade.md` are backed by the actual source, so the decision record (the
claim registered for [W0-3] #398) cannot silently drift from the code.

Until the claims registry (#398) lands, the decision record is the source of truth for the claim, and this is
the offline pin that keeps it honest.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_DECISION = _REPO / "docs" / "decisions" / "W13-2-sovereign-bridge-facade.md"
_FACADE = _REPO / "integration" / "vigil_integration" / "sovereign_bridge.py"
_PURE_TEST = _REPO / "integration" / "tests" / "test_sovereign_bridge.py"
_OFFENSE_TEST = _REPO / "integration" / "tests" / "test_sovereign_bridge_offense.py"
_CI = _REPO / ".github" / "workflows" / "ci.yml"

_FORBIDDEN_IDENT_FRAGMENTS = (
    "skipsecuritychecks", "skipsecurity", "skipgate", "skipwarden", "bypassgate", "bypasssecurity",
    "bypasswarden", "disablesecurity", "disablegate", "disablewarden", "disableauthorization",
)


def test_decision_record_exists_and_registers_the_claim():
    assert _DECISION.is_file(), "the W13-2 decision record must exist"
    text = _DECISION.read_text(encoding="utf-8")
    assert "#495" in text, "the decision record must name its issue (#495)"
    assert "#398" in text, "the claim must be marked for the claims registry ([W0-3] #398)"
    assert "sovereign_bridge" in text and "facade" in text.lower()


def test_facade_module_exists_and_exposes_the_claimed_entry_points():
    assert _FACADE.is_file(), "the sovereign_bridge facade module must exist"
    src = _FACADE.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(_FACADE))
    funcs = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name in ("authorize", "compose_authorization", "build_offense_bridge"):
        assert name in funcs, f"the decision record claims a {name}() entry point; it is absent from the code"
    classes = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    for cls in ("SovereignBridge", "SovereignDecision", "Gate", "GateOutcome"):
        assert cls in classes, f"the facade must define {cls}"


def test_production_profile_rejects_observe_only_is_in_the_code():
    src = _FACADE.read_text(encoding="utf-8")
    # The guard the decision record claims: production profile + OBSERVE_ONLY is refused.
    assert "_PRODUCTION_PROFILES" in src
    assert re.search(r"profile\s+in\s+_PRODUCTION_PROFILES\s+and\s+mode\s+is\s+EnforcementMode\.OBSERVE_ONLY",
                     src), "the production-rejects-OBSERVE_ONLY guard named in the decision record is missing"


def test_facade_source_has_no_skip_security_checks_equivalent_identifier():
    # The decision record claims there is no skip_security_checks-equivalent flag. Check the facade itself via
    # AST (so the module's own docstring naming the forbidden flag does not count as an identifier).
    tree = ast.parse(_FACADE.read_text(encoding="utf-8"), filename=str(_FACADE))
    idents: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs):
                idents.add(arg.arg)
            if a.vararg:
                idents.add(a.vararg.arg)
            if a.kwarg:
                idents.add(a.kwarg.arg)
        elif isinstance(node, ast.Name):
            idents.add(node.id)
        elif isinstance(node, ast.Attribute):
            idents.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            idents.add(node.arg)
    offenders = [i for i in idents if any(f in i.replace("_", "").lower() for f in _FORBIDDEN_IDENT_FRAGMENTS)]
    assert not offenders, f"facade defines a security-bypass-shaped identifier: {offenders}"


def test_claimed_test_files_exist():
    assert _PURE_TEST.is_file(), "the sovereign-leg proof named in the decision record must exist"
    assert _OFFENSE_TEST.is_file(), "the offense-leg proof named in the decision record must exist"


def test_offense_test_is_listed_in_a_ci_run_list():
    if not _CI.exists():  # pragma: no cover — pre-merge refs without the workflow present
        pytest.skip("ci.yml not present on this ref")
    ci = _CI.read_text(encoding="utf-8")
    # It must appear on a real run-list line (not a comment, not an --ignore) so it actually runs in CI.
    listed = any(
        "test_sovereign_bridge_offense.py" in line
        and not line.strip().startswith("#")
        and "--ignore=" not in line
        for line in ci.splitlines()
    )
    assert listed, "test_sovereign_bridge_offense.py must be on an offense-leg run-list line in ci.yml"
