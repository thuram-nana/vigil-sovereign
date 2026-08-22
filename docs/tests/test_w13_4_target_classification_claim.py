"""Doc-truth pin for W13-4 (#497): the target-classification decision record is TRUE of the code.

This rides the already-required "the briefing explains every agent and capability" job (`pytest docs/tests
-q`), which installs only pytest and reads files — so this test imports nothing beyond the standard library.
It asserts the claims written in `docs/decisions/W13-4-target-classification.md` are backed by the actual
source, so the decision record (the claim registered for [W0-3] #398) cannot silently drift from the code.

Until the claims registry (#398) lands, the decision record is the source of truth for the claim, and this is
the offline pin that keeps it honest.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_DECISION = _REPO / "docs" / "decisions" / "W13-4-target-classification.md"
_MODULE = _REPO / "packages" / "core" / "vigil_core" / "vigil_core" / "target_classification.py"
_PURE_TEST = _REPO / "packages" / "core" / "vigil_core" / "tests" / "test_target_classification.py"
_GATE_TEST = _REPO / "integration" / "tests" / "test_target_classification_gate.py"
_FACADE = _REPO / "integration" / "vigil_integration" / "sovereign_bridge.py"

# The taxonomy the decision record claims. Kept in sync with the enum by the assertion below.
_CLAIMED_CLASSES = {
    "LOOPBACK", "PRIVATE_NETWORK", "OWN_INFRA", "AUTHORIZED_THIRD_PARTY",
    "PUBLIC_INTERNET", "CRITICAL_INFRASTRUCTURE", "OUT_OF_SCOPE", "UNKNOWN",
}
_CLAIMED_MODES = {"LOCAL_OFFLINE", "LOCAL_LAB", "STAGING", "PRODUCTION", "REVIEWER"}
_AUTHORIZED = {"LOOPBACK", "PRIVATE_NETWORK", "OWN_INFRA", "AUTHORIZED_THIRD_PARTY"}


def _enum_members(tree: ast.Module, class_name: str) -> set[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                t.id
                for stmt in node.body
                if isinstance(stmt, ast.Assign)
                for t in stmt.targets
                if isinstance(t, ast.Name)
            }
    return set()


def test_decision_record_exists_and_registers_the_claim():
    assert _DECISION.is_file(), "the W13-4 decision record must exist"
    text = _DECISION.read_text(encoding="utf-8")
    assert "#497" in text, "the decision record must name its issue (#497)"
    assert "#398" in text, "the claim must be marked for the claims registry ([W0-3] #398)"
    assert "UNKNOWN" in text and "never" in text.lower()


def test_module_exists_and_defines_the_claimed_taxonomy_and_modes():
    assert _MODULE.is_file(), "the target_classification module must exist"
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"), filename=str(_MODULE))
    assert _enum_members(tree, "TargetClass") == _CLAIMED_CLASSES, (
        "the TargetClass enum must match the taxonomy the decision record claims"
    )
    assert _enum_members(tree, "DeploymentMode") == _CLAIMED_MODES, (
        "the DeploymentMode enum must match the deployment modes the decision record claims"
    )
    funcs = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name in ("classify_target", "is_authorized", "normalize_target"):
        assert name in funcs, f"the decision record claims a {name}() entry point; it is absent"
    classes = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    for cls in ("TargetClass", "DeploymentMode", "RegisteredAsset", "RegisteredAssetStore"):
        assert cls in classes, f"the module must define {cls}"


def test_unknown_is_not_in_the_authorized_classes_set_in_the_code():
    # The claim's core safety property: AUTHORIZED_CLASSES is exactly the four owned classes — UNKNOWN and
    # every risky/forbidden class are excluded. Read the literal frozenset construction from the source.
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"), filename=str(_MODULE))
    found: set[str] | None = None
    for node in ast.walk(tree):
        # AUTHORIZED_CLASSES carries a type annotation, so it parses as AnnAssign, not Assign.
        is_target = (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "AUTHORIZED_CLASSES"
        ) or (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "AUTHORIZED_CLASSES" for t in node.targets)
        )
        if is_target and node.value is not None:
            # frozenset({TargetClass.X, ...})
            members: set[str] = set()
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                        and sub.value.id == "TargetClass":
                    members.add(sub.attr)
            found = members
    assert found == _AUTHORIZED, f"AUTHORIZED_CLASSES must be exactly {_AUTHORIZED}, got {found}"
    assert "UNKNOWN" not in (found or set()), "UNKNOWN must never be an authorized class"


def test_facade_wires_the_classification_leg_on_by_default():
    src = _FACADE.read_text(encoding="utf-8")
    assert "include_classification: bool = True" in src, (
        "build_offense_bridge must default the classification leg ON (UNKNOWN is never authorized)"
    )
    assert 'Gate("classification"' in src, "the facade must compose a classification leg"


def test_claimed_test_files_exist():
    assert _PURE_TEST.is_file(), "the pure-core classifier proof named in the decision record must exist"
    assert _GATE_TEST.is_file(), "the facade-wiring proof named in the decision record must exist"
