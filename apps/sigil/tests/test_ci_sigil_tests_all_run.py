"""Coverage guard (operator DEFECT 5): every apps/sigil/tests/ file actually RUNS in the sigil-governor CI job.

The ``sigil-governor`` job in ``.github/workflows/ci.yml`` once ran a hand-maintained, EXPLICIT
``python -m pytest apps/sigil/tests/test_A.py test_B.py ...`` file list. That list silently DRIFTED: 56 of
~94 sovereign test files were never named, so they never ran in CI at all — including test_floor_witness,
test_ha_failover_guard, test_backup_staged_restore, test_governance_replay_guard, the test_snapshot_fold_*
family and test_login_pop. "A skipped proof and a passing proof are the same colour on a dashboard."

The structural fix: the job runs the WHOLE ``apps/sigil/tests/`` directory, so a NEW test file is
AUTO-INCLUDED and can only fail LOUDLY, never silently skip. This guard PINS that fix and keeps any future
exclusion honest:

  * it confirms the job runs the whole directory (not a hand list); and
  * ``KNOWN_EXCLUDED`` below is the single source of truth for every ``--ignore``d file + its reason, and the
    guard asserts the ci.yml ``--ignore`` set for apps/sigil/tests EQUALS its keys. So an UNDOCUMENTED ignore
    (excluded in ci.yml, absent here) AND a documented-but-not-wired exclusion (here, absent from ci.yml)
    BOTH fail — an ignore can never re-introduce a silent skip without a reason a reviewer can read.

A file belongs in ``KNOWN_EXCLUDED`` IFF it needs a resource ubuntu-latest CI lacks and is not hermetically
mocked/loopback/guarded (a real subprocess to a non-base CLI, real egress to an external host, audio/vision/
android hardware, an uninstalled heavy Python package imported unguarded). Grep-triage of the whole suite
found NONE — all network is loopback/monkeypatched, heavy deps are lazy or importorskip-guarded, and external
CLIs are base git/python or shutil.which-guarded (node) — so the dict is empty and the entire directory runs.

The guard is pure file reads (framework-free, no test-import parsing), so it runs inside the governor job
itself; it must never be ``--ignore``d. Modelled on
integration/tests/test_ci_framework_tests_run_in_offense_leg.py.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# filename -> reason. See the module docstring for the inclusion bar. Add an entry here IF AND ONLY IF you
# also add a matching `--ignore=apps/sigil/tests/<file>` to the sigil-governor job — the equality assertion
# below fails on either half alone.
KNOWN_EXCLUDED: dict[str, str] = {
    # EMPTY (audit F-05): test_graph is now host-independent (normalize_project collapses ANY host slug by
    # the stable repo basename), and test_robustness's vector tests are importorskip-guarded on qdrant_client
    # — so BOTH run in the sigil-governor job. No file needs excluding.
}

_ME = Path(__file__).name
_TESTS_DIR = Path(__file__).resolve().parent               # apps/sigil/tests
_REPO = Path(__file__).resolve().parents[3]                # apps/sigil/tests -> apps/sigil -> apps -> repo
_CI = _REPO / ".github" / "workflows" / "ci.yml"

# `--ignore=apps/sigil/tests/<file>.py` — the `.py` anchor keeps test_ui from matching test_ui_remote.
_IGNORE = re.compile(r"--ignore=apps/sigil/tests/(test_[A-Za-z0-9_]+\.py)")
# The apps/sigil/tests/ directory as a pytest RUN TARGET (trailing slash then whitespace/EOL) on a real
# `python -m pytest` line — NOT a `--ignore=apps/sigil/tests/<file>.py` (which is followed by a filename).
_DIR_RUN = re.compile(r"python -m pytest\b.*\bapps/sigil/tests/(?:\s|$)")
_JOB_HEADER = re.compile(r"^  sigil-governor:\s*$")
_NEXT_JOB = re.compile(r"^  [A-Za-z0-9_-]+:\s*$")


def _governor_lines() -> list[str]:
    """The non-comment lines of the ``sigil-governor:`` job ONLY (up to the next top-level job key), so an
    ``--ignore`` or ``apps/sigil/tests`` token in some other job can never satisfy or corrupt these checks.
    ``#`` comment lines are dropped (a future comment quoting a path must not be miscounted)."""
    lines = _CI.read_text(encoding="utf-8").splitlines()
    start = next((i for i, ln in enumerate(lines) if _JOB_HEADER.match(ln)), None)
    assert start is not None, "sigil-governor job not found in ci.yml — the parser or the job name changed"
    end = next((j for j in range(start + 1, len(lines)) if _NEXT_JOB.match(lines[j])), len(lines))
    return [ln for ln in lines[start:end] if not ln.strip().startswith("#")]


def _ci_ignored() -> set[str]:
    return {m for ln in _governor_lines() for m in _IGNORE.findall(ln)}


def _all_test_files() -> list[str]:
    return sorted(p.name for p in _TESTS_DIR.glob("test_*.py"))


def test_governor_runs_the_whole_tests_directory():
    """The STRUCTURAL fix: the job must run the whole `apps/sigil/tests/` dir, so a NEW test auto-runs and can
    only fail loudly — never silently skip by being absent from a hand-maintained file list."""
    if not _CI.exists():  # pragma: no cover — pre-merge refs without the workflow present
        pytest.skip("ci.yml not present on this ref")
    assert any(_DIR_RUN.search(ln) for ln in _governor_lines()), (
        "the sigil-governor job must run the WHOLE `apps/sigil/tests/` directory "
        "(`python -m pytest apps/sigil/tests/ ...`); found no such run line — a hand-maintained file list is "
        "exactly the drift this guard exists to prevent"
    )


def test_ci_ignore_set_equals_documented_known_excluded():
    """Every ci.yml `--ignore` has a documented KNOWN_EXCLUDED reason and vice-versa. Either half alone fails,
    so an undocumented ignore (a silent skip with no readable reason) cannot land, and a stale reason cannot
    linger after its ignore is dropped."""
    if not _CI.exists():  # pragma: no cover
        pytest.skip("ci.yml not present on this ref")
    ci_ignored = _ci_ignored()
    documented = set(KNOWN_EXCLUDED)
    undocumented = sorted(ci_ignored - documented)
    assert not undocumented, (
        "these files are --ignore'd in the sigil-governor job but have NO KNOWN_EXCLUDED reason (an "
        f"undocumented silent skip — the DEFECT-5 class): {undocumented}"
    )
    stale = sorted(documented - ci_ignored)
    assert not stale, (
        "these files carry a KNOWN_EXCLUDED reason but are NOT --ignore'd in ci.yml (stale reason, or the "
        f"--ignore was dropped so the file now runs): {stale}"
    )


def test_every_excluded_file_exists_and_has_a_nonempty_reason():
    """A --ignore of a non-existent file protects nothing and rots; a blank reason is not documentation."""
    for name, reason in KNOWN_EXCLUDED.items():
        assert (_TESTS_DIR / name).is_file(), f"KNOWN_EXCLUDED names a non-existent test file: {name}"
        assert reason and reason.strip(), f"KNOWN_EXCLUDED[{name!r}] must carry a real reason, not {reason!r}"


def test_the_guard_itself_is_never_excluded():
    """This guard is framework-free and must RUN in the governor job — it can never be in the ignore set."""
    assert _ME not in KNOWN_EXCLUDED, "the coverage guard must run, never be documented as excluded"
    if _CI.exists():
        assert _ME not in _ci_ignored(), "the coverage guard must never be --ignore'd in ci.yml"


def test_whole_dir_run_covers_every_test_file():
    """Because the job runs the directory, the files that RUN = all test files MINUS the (documented) ignores.
    No test file can be silently omitted: a new file is auto-collected, and the only way to exclude one is a
    KNOWN_EXCLUDED-documented --ignore that this guard already pins."""
    if not _CI.exists():  # pragma: no cover
        pytest.skip("ci.yml not present on this ref")
    all_files = set(_all_test_files())
    assert _ME in all_files, "the guard must be discoverable as a test_*.py in apps/sigil/tests/"
    covered = all_files - _ci_ignored()
    expected = all_files - set(KNOWN_EXCLUDED)
    assert covered == expected, (
        "the set of files that RUN must equal all files minus the documented exclusions; a mismatch means an "
        f"undocumented ignore is hiding a file: runs-but-undocumented={sorted(expected - covered)}, "
        f"excluded-but-undocumented={sorted(covered - expected)}"
    )
