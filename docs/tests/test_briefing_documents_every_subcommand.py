"""W16-STD-7 (#533) — the briefing must document every CRUCIBLE subcommand and subsystem.

WHY THIS TEST EXISTS. The limitations inventory (§17.16 / §17.17) found that the CRUCIBLE subcommands
(the keys of ``_DISPATCH`` in ``engine/crucible/framework/v2/__main__.py``) and the engine's subsystems
(the importable sub-packages of ``framework/v2``) were listed in NO chapter — a reader finished the
briefing not knowing what could be run or what the parts were. ``docs/CLI-REFERENCE.md`` now lists every
one; this test is the pin that keeps that page true of the code, in BOTH directions:

  * FORWARD (``a new one turns it red``): every subcommand the code declares, and every sub-package the
    code ships, must be documented in ``CLI-REFERENCE.md``. Add a ``_DISPATCH`` key or a new
    ``framework/v2`` package without documenting it → red.
  * REVERSE (``the docs cannot describe things that do not exist``): every subcommand the page documents
    as ``crucible <name>`` must be a real ``_DISPATCH`` key. Remove a subcommand from the code but leave
    it in the page → red. This is the negative-control direction the acceptance criteria name.

The subcommand set and the subsystem set are both derived FROM THE CODE at run time (AST for the dispatch
dict, the filesystem for the packages), never hard-coded here, so the test moves with the engine and the
page cannot silently drift from it.

Files only — ``ast`` + ``re`` + ``pathlib``, no import of either trust domain, no tool run, no packet —
so it is correct in the docs-only ``the briefing explains every agent and capability`` required CI job
(which installs only pytest and reads files).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAIN = REPO / "engine" / "crucible" / "framework" / "v2" / "__main__.py"
V2 = REPO / "engine" / "crucible" / "framework" / "v2"
REFERENCE = REPO / "docs" / "CLI-REFERENCE.md"


# --------------------------------------------------------------------------------------------------
# Pure, code-derived enumerations (so the negative controls can perturb the inputs directly).
# --------------------------------------------------------------------------------------------------
def dispatch_subcommands(main_src: str) -> set[str]:
    """The keys of the ``_DISPATCH`` dict literal in ``__main__.py``, resolved by AST (no import)."""
    tree = ast.parse(main_src)
    for node in ast.walk(tree):
        target_names: list[str] = []
        value = None
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]
            value = node.value
        if "_DISPATCH" in target_names and isinstance(value, ast.Dict):
            return {
                k.value
                for k in value.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
    raise AssertionError("could not find the _DISPATCH dict literal in __main__.py")


def subpackages(v2_dir: Path) -> set[str]:
    """The importable sub-packages of framework/v2 (a directory with an ``__init__.py``)."""
    return {p.name for p in v2_dir.iterdir() if p.is_dir() and (p / "__init__.py").is_file()}


def documented_subcommands(doc: str) -> set[str]:
    """Every subcommand the reference documents in the invokable ``crucible <name>`` backtick form."""
    return set(re.findall(r"`crucible ([a-z][a-z0-9-]*)`", doc))


def documented_tokens(doc: str) -> set[str]:
    """Every single-token backticked name in the reference (used to check subsystem coverage)."""
    return set(re.findall(r"`([a-z_][a-z0-9_]*)`", doc))


def undocumented_subcommands(code_subs: set[str], doc: str) -> set[str]:
    """Subcommands the code declares that the reference does NOT document (FORWARD gap)."""
    return code_subs - documented_subcommands(doc)


def fictional_subcommands(doc: str, code_subs: set[str]) -> set[str]:
    """Subcommands the reference documents that the code does NOT have (REVERSE gap)."""
    return documented_subcommands(doc) - code_subs


def undocumented_subsystems(pkgs: set[str], doc: str) -> set[str]:
    """Sub-packages the code ships that the reference does NOT name (FORWARD gap)."""
    return pkgs - documented_tokens(doc)


# --------------------------------------------------------------------------------------------------
# The real checks.
# --------------------------------------------------------------------------------------------------
def test_every_subcommand_is_documented():
    code_subs = dispatch_subcommands(MAIN.read_text(encoding="utf-8"))
    doc = REFERENCE.read_text(encoding="utf-8")
    missing = undocumented_subcommands(code_subs, doc)
    assert not missing, (
        "these CRUCIBLE subcommands exist in _DISPATCH but are not documented in docs/CLI-REFERENCE.md "
        f"as `crucible <name>`: {sorted(missing)}"
    )


def test_no_documented_subcommand_is_fictional():
    code_subs = dispatch_subcommands(MAIN.read_text(encoding="utf-8"))
    doc = REFERENCE.read_text(encoding="utf-8")
    fictional = fictional_subcommands(doc, code_subs)
    assert not fictional, (
        "docs/CLI-REFERENCE.md documents these as `crucible <name>` but they are not _DISPATCH keys — "
        f"the docs describe a command the code does not have: {sorted(fictional)}"
    )


def test_every_subsystem_is_documented():
    pkgs = subpackages(V2)
    doc = REFERENCE.read_text(encoding="utf-8")
    missing = undocumented_subsystems(pkgs, doc)
    assert not missing, (
        "these framework/v2 sub-packages ship in the code but are not named in docs/CLI-REFERENCE.md: "
        f"{sorted(missing)}"
    )


# --------------------------------------------------------------------------------------------------
# Negative controls — prove the gate is not a no-op (a deliberately bad input/state is rejected).
# --------------------------------------------------------------------------------------------------
def test_negative_control_a_new_undocumented_subcommand_is_caught():
    code_subs = dispatch_subcommands(MAIN.read_text(encoding="utf-8"))
    doc = REFERENCE.read_text(encoding="utf-8")
    perturbed = code_subs | {"totally-new-verb"}
    assert "totally-new-verb" in undocumented_subcommands(perturbed, doc), (
        "the forward checker failed to flag a code subcommand missing from the docs — it is a no-op"
    )


def test_negative_control_removing_a_documented_subcommand_from_code_turns_red():
    code_subs = dispatch_subcommands(MAIN.read_text(encoding="utf-8"))
    doc = REFERENCE.read_text(encoding="utf-8")
    assert "report" in code_subs and "report" in documented_subcommands(doc), "fixture drifted"
    # Simulate the code no longer declaring a subcommand the page still documents.
    assert "report" in fictional_subcommands(doc, code_subs - {"report"}), (
        "the reverse checker failed to flag a documented-but-absent subcommand — it is a no-op"
    )


def test_negative_control_a_new_undocumented_subsystem_is_caught():
    pkgs = subpackages(V2)
    doc = REFERENCE.read_text(encoding="utf-8")
    assert "totallynewpkg" in undocumented_subsystems(pkgs | {"totallynewpkg"}, doc), (
        "the subsystem checker failed to flag a new undocumented sub-package — it is a no-op"
    )


def test_the_enumerations_are_read_from_code_not_a_constant():
    # A last guard that the enumerations really come from the code artefacts, so this test cannot pass
    # against a tree where the dispatch dict or the package set was gutted.
    code_subs = dispatch_subcommands(MAIN.read_text(encoding="utf-8"))
    pkgs = subpackages(V2)
    assert len(code_subs) >= 25, f"suspiciously few subcommands parsed: {sorted(code_subs)}"
    assert {"engage", "verify", "scan"} <= code_subs
    assert len(pkgs) >= 25, f"suspiciously few sub-packages found: {sorted(pkgs)}"
    assert {"veracity", "verify", "scanner"} <= pkgs
