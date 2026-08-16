"""Guard: every framework-dependent integration test actually RUNS in CI.

The integration suite is split across two CI legs (see .github/workflows/ci.yml):

  * the SOVEREIGN leg runs ``pytest integration/tests`` in a process where ``framework`` is NOT importable
    (FATAL-2). A file reaches that leg in one of two ways, and a framework-dependent test can hide in each:
      - guarded by ``pytest.importorskip("framework...")`` → collected but SKIPPED there; or
      - a hard module-level ``from framework … import`` → it would ERROR collection, so such files are
        ``--ignore``d in the sovereign leg (a file is ``--ignore``d there *because* it cannot run there).
  * the OFFENSE leg runs an EXPLICIT, hand-maintained file list in a process where ``framework`` IS on the
    path — the only leg where those tests can execute.

So a framework-dependent file that is missing from the offense list *never runs in CI*: an importorskip file
skips in the sovereign leg; a hard-import file is ``--ignore``d there. "A skipped proof and a passing proof
are the same colour on a dashboard" — this silent gap once hid a real ValueError (the cloud_live_posture
3-vs-2 unpacking regression) plus five more posture suites that never ran at all.

This guard makes that whole class loud with two complementary, robust checks (no Python-import parsing, which
cannot reliably tell an unconditional import from a boundary probe such as test_two_env_boundary.py):

  1. every file with a ``pytest.importorskip("framework…")`` is in the offense list; and
  2. every file ``--ignore``d in the sovereign leg is in the offense list.

Together these cover both hiding routes. The guard is itself framework-free (pure file reads), so it runs in
the sovereign leg — keep it OUT of any ``--ignore`` there.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_TESTS_DIR = Path(__file__).resolve().parent
_CI = _REPO / ".github" / "workflows" / "ci.yml"

# Matches `pytest.importorskip("framework...")` / `importorskip('framework...')` — the marker that a test can
# only execute where `framework` is importable (the offense leg). `\s*` spans a wrapped call.
_FRAMEWORK_SKIP = re.compile(r"importorskip\(\s*['\"]framework")
_IGNORE = re.compile(r"--ignore=integration/tests/(test_[A-Za-z0-9_]+\.py)")
_PATH = re.compile(r"integration/tests/(test_[A-Za-z0-9_]+\.py)")


def _framework_importorskip_files() -> list[str]:
    out = []
    for f in sorted(_TESTS_DIR.glob("test_*.py")):
        if f.name == Path(__file__).name:
            continue  # this guard is framework-free by construction
        if _FRAMEWORK_SKIP.search(f.read_text(encoding="utf-8")):
            out.append(f.name)
    return out


def _offense_leg_listed_paths(ci_text: str) -> set[str]:
    """Paths that appear on a real pytest run-list line of ci.yml — i.e. NOT a ``--ignore=`` line and NOT a
    ``#`` comment (F3: a future comment mentioning a full test path must not be miscounted as "listed"). The
    ``.py`` suffix anchors the match so ``test_live_executor.py`` never matches ``test_live_executor_report_builders.py``."""
    listed = set()
    for line in ci_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "--ignore=" in line:
            continue
        m = _PATH.search(line)
        if m:
            listed.add(m.group(1))
    return listed


def _sovereign_ignored_paths(ci_text: str) -> set[str]:
    return {m.group(1) for line in ci_text.splitlines() for m in [_IGNORE.search(line)] if m}


def test_every_framework_importorskip_test_runs_in_the_offense_leg():
    if not _CI.exists():  # pragma: no cover — pre-merge refs without the workflow present
        pytest.skip("ci.yml not present on this ref")
    listed = _offense_leg_listed_paths(_CI.read_text(encoding="utf-8"))
    fw_files = _framework_importorskip_files()
    assert fw_files, "expected to find importorskip('framework') integration tests; the detector may be broken"
    missing = [name for name in fw_files if name not in listed]
    assert not missing, (
        "these integration test files import `framework` behind an importorskip, so they SKIP in the "
        "sovereign leg and must be listed explicitly in the offense leg of .github/workflows/ci.yml or they "
        f"never run in CI: {missing}"
    )


def test_every_sovereign_ignored_test_runs_in_the_offense_leg():
    """A file is ``--ignore``d in the sovereign leg because it cannot run there (a hard module-level framework
    import). It must therefore appear in the offense leg, or it runs in NEITHER — the silent gap this guard
    exists to prevent, for the hard-import class the importorskip check above does not see."""
    if not _CI.exists():  # pragma: no cover
        pytest.skip("ci.yml not present on this ref")
    ci_text = _CI.read_text(encoding="utf-8")
    listed = _offense_leg_listed_paths(ci_text)
    ignored = _sovereign_ignored_paths(ci_text)
    assert ignored, "expected a non-empty sovereign --ignore list; the parser may be broken"
    orphaned = sorted(name for name in ignored if name not in listed)
    assert not orphaned, (
        "these files are --ignore'd in the sovereign leg (so they do not run there) but are absent from the "
        f"offense leg's explicit list, so they run in NEITHER leg: {orphaned}"
    )
