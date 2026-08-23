"""The release/upgrade/rollback runbook cannot rot: every CLI command it documents really exists
(W4-4, #444).

Acceptance criteria: the runbook covers release, upgrade and rollback with exact commands; and
"changing a documented command name without updating the runbook turns the doc test red." This guard
extracts every ``vigil`` / ``sigil`` / ``vigil-gateway`` / ``python3 -m framework.v2`` subcommand used
in the runbook's fenced code blocks and asserts each one is a REAL subcommand of that CLI — resolved by
AST from the CLI source, so no trust domain is imported. It rides the required "the briefing explains
every agent and capability" job (``pytest docs/tests -q``, pytest-only), hence stdlib-only here.

FAILS WITHOUT THE FIX: on a tree with no runbook the first test errors on the missing file.

NEGATIVE CONTROLS (same run):
  * rename a CLI command in the source (simulated) and the runbook that still names the old command is
    flagged — proving the guard binds the doc to the code, in both directions;
  * a runbook snippet that invokes a non-existent subcommand is flagged.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RUNBOOK = REPO / "docs" / "runbooks" / "RELEASE-UPGRADE-ROLLBACK.md"

# The CLI source files whose subcommand vocabulary the runbook must not drift from.
VIGIL_CLI = REPO / "integration" / "vigil_integration" / "cli.py"
VIGIL_DISPATCH = REPO / "integration" / "vigil_integration" / "dispatch.py"
SIGIL_CLI = REPO / "apps" / "sigil" / "sigil" / "cli.py"
GATEWAY_CLI = REPO / "gateway" / "vigil_gateway" / "cli.py"
FRAMEWORK_MAIN = REPO / "engine" / "crucible" / "framework" / "v2" / "__main__.py"


# --- AST vocabulary extraction (no import) ---------------------------------------------------


def _add_parser_names(py_path: Path) -> set[str]:
    """Every string-literal first arg of an ``add_parser("name")`` call in the file."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_parser"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.add(node.args[0].value)
    return names


def _passthrough_verbs() -> set[str]:
    """The keys of the ``_ENV`` dict in dispatch.py — the subsystem verbs ``vigil`` forwards."""
    tree = ast.parse(VIGIL_DISPATCH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_ENV" for t in node.targets)
            and isinstance(node.value, ast.Dict)
        ):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return set()


def _dispatch_keys() -> set[str]:
    """The keys of ``_DISPATCH`` in framework/v2/__main__.py — the framework.v2 subcommands."""
    tree = ast.parse(FRAMEWORK_MAIN.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_DISPATCH"
            and isinstance(node.value, ast.Dict)
        ):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_DISPATCH" for t in node.targets)
            and isinstance(node.value, ast.Dict)
        ):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return set()


def cli_vocabularies() -> dict[str, set[str]]:
    return {
        "vigil": _add_parser_names(VIGIL_CLI) | _passthrough_verbs(),
        "sigil": _add_parser_names(SIGIL_CLI),
        "vigil-gateway": _add_parser_names(GATEWAY_CLI),
        "framework.v2": _dispatch_keys(),
    }


# --- runbook command extraction --------------------------------------------------------------

_CLI_NAMES = ("vigil-gateway", "vigil", "sigil")  # longest-first so vigil-gateway wins over vigil
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_CODE_FENCE = re.compile(r"^```")


def _code_block_lines(text: str) -> list[str]:
    out: list[str] = []
    in_block = False
    for ln in text.splitlines():
        if _CODE_FENCE.match(ln.strip()):
            in_block = not in_block
            continue
        if in_block:
            out.append(ln)
    return out


def _leading_command_tokens(line: str) -> list[str]:
    """Strip a ``$ ``/``# `` prompt and leading ``VAR=val`` assignments; return the remaining tokens."""
    s = line.strip()
    if s.startswith(("$ ", "# ")):
        s = s[2:]
    toks = s.split()
    while toks and (_ENV_ASSIGN.match(toks[0]) or toks[0] in ("sudo", "&&", "\\")):
        toks = toks[1:]
    return toks


def documented_commands(text: str) -> list[tuple[str, str]]:
    """Return ``(cli, subcommand)`` pairs invoked in the runbook's code blocks. A ``--flag`` right
    after the CLI (e.g. ``vigil --version``) has no subcommand and is skipped."""
    pairs: list[tuple[str, str]] = []
    for raw in _code_block_lines(text):
        toks = _leading_command_tokens(raw)
        if not toks:
            continue
        # python3 -m framework.v2 <sub>
        if toks[0] in ("python", "python3") and "-m" in toks:
            i = toks.index("-m")
            if i + 1 < len(toks) and toks[i + 1] == "framework.v2":
                sub = toks[i + 2] if i + 2 < len(toks) else ""
                if sub and not sub.startswith("-"):
                    pairs.append(("framework.v2", sub))
            continue
        base = toks[0].rsplit("/", 1)[-1]  # allow a path prefix like .venv-offense/bin/vigil
        for name in _CLI_NAMES:
            if base == name:
                sub = toks[1] if len(toks) > 1 else ""
                if sub and not sub.startswith("-"):
                    pairs.append((name, sub))
                break
    return pairs


def undocumented_or_missing(text: str, vocab: dict[str, set[str]]) -> list[str]:
    """Return every ``cli sub`` in the runbook that is NOT a real subcommand of that CLI."""
    bad: list[str] = []
    for cli, sub in documented_commands(text):
        if sub not in vocab.get(cli, set()):
            bad.append(f"{cli} {sub}")
    return bad


# --- real-tree assertions --------------------------------------------------------------------


def test_runbook_exists_and_covers_release_upgrade_rollback():
    assert RUNBOOK.is_file(), "the release/upgrade/rollback runbook is missing (W4-4)"
    text = RUNBOOK.read_text(encoding="utf-8").lower()
    for topic in ("release", "upgrade", "rollback"):
        assert topic in text, f"runbook does not cover {topic!r}"


def test_runbook_documents_at_least_the_core_commands():
    """The runbook must actually contain commands to validate — a guard over an empty doc is a no-op."""
    pairs = documented_commands(RUNBOOK.read_text(encoding="utf-8"))
    subs = {f"{c} {s}" for c, s in pairs}
    for required in ("vigil upgrade", "sigil restore"):
        assert required in subs, f"runbook does not document {required!r} (pairs seen: {sorted(subs)})"


def test_every_documented_command_is_a_real_cli_subcommand():
    text = RUNBOOK.read_text(encoding="utf-8")
    bad = undocumented_or_missing(text, cli_vocabularies())
    assert not bad, (
        "the runbook documents CLI commands that do not exist (rename in the code or fix the runbook): "
        + ", ".join(sorted(set(bad)))
    )


# --- negative controls -----------------------------------------------------------------------


def test_negative_control_renamed_command_in_source_turns_the_guard_red():
    """Simulate renaming ``upgrade`` out of the vigil CLI: the runbook still says ``vigil upgrade``, so
    the guard must flag it. This is the AC's 'changing a documented command name without updating the
    runbook turns the doc test red', proven in-process."""
    text = RUNBOOK.read_text(encoding="utf-8")
    vocab = cli_vocabularies()
    vocab["vigil"] = vocab["vigil"] - {"upgrade"}  # pretend the command was renamed away
    bad = undocumented_or_missing(text, vocab)
    assert "vigil upgrade" in bad, bad


def test_negative_control_bogus_command_in_a_snippet_is_flagged():
    snippet = "# Changelog\n\n```\nvigil totally-not-a-real-command\nsigil backup /x\n```\n"
    bad = undocumented_or_missing(snippet, cli_vocabularies())
    assert bad == ["vigil totally-not-a-real-command"], bad


def test_negative_control_a_flag_after_the_cli_is_not_treated_as_a_subcommand():
    snippet = "```\nvigil --version\nsigil -V\n```\n"
    assert documented_commands(snippet) == []


def test_vocabularies_are_non_empty():
    """If AST extraction silently returned nothing, the guard would pass vacuously — assert it didn't."""
    vocab = cli_vocabularies()
    for cli in ("vigil", "sigil", "vigil-gateway", "framework.v2"):
        assert vocab[cli], f"extracted no subcommands for {cli!r}"
    assert "sigil" in vocab["vigil"], "vigil passthrough verbs not extracted from dispatch.py"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
