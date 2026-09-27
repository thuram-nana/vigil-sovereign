#!/usr/bin/env python3
"""Fail the nightly volume job unless EVERY ``@pytest.mark.volume`` test actually executed.

The statistical (``volume``) regressions were moved off the per-PR path because their 80-300-run loops
took the required "integration two-env boundary (P5)" job past GitHub's 45m0s maximum. Moving them is only
honest if they genuinely run somewhere, and "runs somewhere" is not the same as "the nightly job is green":

  * ``pytest -m volume`` exits 0 when every test in the file hit a ``pytest.importorskip`` — a missing
    ``framework`` or ``vigil_gateway`` on the path would skip all 56 and leave the job green;
  * ``pytest -m volume`` exits 5 (caught) when the marker selects nothing, but a PARTIAL rename — a marker
    dropped from one test while the rest keep running — exits 0 with that test silently gone.

So this does not count, it CHECKS AGAINST THE SOURCE. It reads every ``@pytest.mark.volume`` function name
straight out of the test files with ``ast`` and requires each one to appear in the JUnit report and to have
executed cleanly. A marker deleted from a test makes the expected set shrink — which the companion guard
``integration/tests/test_ci_volume_tests_run_nightly.py`` catches on the PR side — and a marker kept while
the test stops running makes THIS red.

Usage: assert_volume_tests_ran.py <junit.xml> [tests-dir ...]   (default tests dir: integration/tests)
"""
from __future__ import annotations

import ast
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_DEFAULT_TEST_DIRS = ("integration/tests",)
_NON_EXECUTED = ("skipped", "error", "failure")


def _rel(path: Path) -> str:
    """Repo-relative if we can say so, else the path as given — a label, never a lookup key."""
    try:
        return str(path.resolve().relative_to(_REPO))
    except ValueError:  # pragma: no cover — a tests dir outside the repo (only a caller could do this)
        return str(path)


def _decorator_dotted_name(node: ast.expr) -> str:
    """Render ``pytest.mark.volume`` / ``mark.volume`` as a dotted string; '' for anything else."""
    parts: list[str] = []
    cur: ast.expr | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def volume_test_names(test_dirs: list[Path]) -> dict[str, str]:
    """{test function name: repo-relative file} for every ``@pytest.mark.volume`` test function."""
    found: dict[str, str] = {}
    for d in test_dirs:
        for path in sorted(d.glob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not node.name.startswith("test_"):
                    continue
                for dec in node.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    if _decorator_dotted_name(target).endswith("mark.volume"):
                        found[node.name] = _rel(path)
                        break
    return found


def evaluate(cases: list[ET.Element], expected: dict[str, str]) -> list[str]:
    """Human-readable problems; empty means every volume test ran and none was skipped."""
    problems: list[str] = []
    if not expected:
        return [
            "no @pytest.mark.volume tests were found in the source at all — either the marker was "
            "removed wholesale (the statistical regressions would then run NOWHERE) or this detector is "
            "broken; refusing to pass either way"
        ]
    for name, rel in sorted(expected.items()):
        matches = [
            c for c in cases
            if (c.get("name") == name or (c.get("name") or "").startswith(name + "["))
        ]
        if not matches:
            problems.append(f"volume test {name!r} ({rel}) is NOT in the report — it did not run at all")
            continue
        for c in matches:
            not_run = [child.tag for child in c if child.tag in _NON_EXECUTED]
            if not_run:
                problems.append(
                    f"volume test {c.get('name')!r} ({rel}) did not execute cleanly (found {not_run})"
                )
    return problems


def _testcases(path: str) -> list[ET.Element]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        sys.exit(f"::error::cannot read the volume JUnit report {path!r}: {exc}")
    return list(root.iter("testcase"))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.exit("usage: assert_volume_tests_ran.py <junit.xml> [tests-dir ...]")
    dirs = [Path(d) if Path(d).is_absolute() else _REPO / d for d in (argv[2:] or _DEFAULT_TEST_DIRS)]
    missing_dirs = [str(d) for d in dirs if not d.is_dir()]
    if missing_dirs:
        sys.exit(f"::error::test directory/directories not found: {missing_dirs}")
    expected = volume_test_names(dirs)
    cases = _testcases(argv[1])
    problems = evaluate(cases, expected)
    if problems:
        for p in problems:
            print(f"::error::{p}")
        print(
            "::error::the nightly VOLUME statistical regressions did not actually execute — refusing to "
            "pass this job (a skipped proof and a passing proof are the same colour on a dashboard)"
        )
        return 1
    print(
        f"volume regressions executed: {len(expected)} marked test function(s), "
        f"{len(cases)} parametrised case(s) in the report, 0 skipped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
