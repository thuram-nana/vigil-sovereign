"""Coverage guard (W1-2): every ``framework/v2/**/tests`` directory actually RUNS in the crucible-core CI job.

The ``crucible-core`` job in ``.github/workflows/ci.yml`` once ran a hand-maintained, EXPLICIT pytest path
list (plus a ``CRUCIBLE_UNCOVERED_SUITES`` patch variable). That list silently DRIFTED: of the 40 test
directories under ``framework/v2`` only a subset were named, so entire suites — ``agents/tools/tests``,
``imports/tests``, ``improve/tests``, ``intake/tests``, ``intruder/tests``, ``knowledge/tests``,
``mcp/tests``, ``plugins/tests``, ``repeater/tests``, ``socialdefense/tests`` and the top-level
``framework/v2/tests`` — never ran in CI at all. "A skipped proof and a passing proof are the same colour on
a dashboard."

The structural fix: the job runs the WHOLE ``framework/v2`` tree (``pytest framework/v2 --ignore=...``), so a
NEW test directory is AUTO-INCLUDED and can only fail LOUDLY, never silently skip. This guard PINS that fix
and keeps every exclusion honest:

  * it confirms the job runs ``framework/v2`` wholesale (not a hand list); and
  * ``KNOWN_EXCLUDED`` below is the single source of truth for every ``--ignore``d path + its reason, and the
    guard asserts the crucible-core ``--ignore`` set EQUALS its keys. So an UNDOCUMENTED ignore (excluded in
    ci.yml, absent here — a silent dark path) AND a stale documented-but-dropped exclusion (here, but not
    ignored in ci.yml) BOTH fail — an ignore can never re-introduce a silent skip without a reason a
    reviewer can read.

A path belongs in ``KNOWN_EXCLUDED`` IFF running it in crucible-core is wrong for a written, reviewable
reason: it runs WHOLESALE in a different required job, or it needs a resource the minimal crucible-core
install deliberately lacks.

The guard is pure file reads (framework-free, no test-import parsing), so it runs inside the crucible-core
job itself under the very ``framework/v2`` run it validates; it must never be ``--ignore``d. Modelled on
apps/sigil/tests/test_ci_sigil_tests_all_run.py.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# crucible-relative ``--ignore=`` path -> reason. A key may be a DIRECTORY (excludes a whole subtree) or a
# single FILE. Add an entry here IF AND ONLY IF you also add a matching ``--ignore=<path>`` to the
# crucible-core run — the equality assertion below fails on either half alone.
KNOWN_EXCLUDED: dict[str, str] = {
    # The eval suite (benchmark corpus, committed recall/precision baselines, determinism re-run + soak) is
    # the one expensive suite (~2.5 min). It runs WHOLESALE in the separate, also-required ``crucible-eval``
    # job so crucible-core's critical path stays short; --ignore'd here to avoid double-running it.
    "framework/v2/eval": "runs wholesale in the required crucible-eval job (expensive corpus/soak); excluded here to avoid double-run",
    # These 4 tests import `vigil_integration` (the integration/ package) at RUN time, unlike their console
    # siblings which module-level `importorskip` it and skip cleanly. crucible-core deliberately does NOT
    # install the integration package (two-env boundary), so they only pass when scanner's
    # test_claim_discipline happens to run first and inserts integration/ onto sys.path — a fragile
    # cross-suite ordering side effect that the wholesale run (filesystem order: console before scanner) does
    # not provide. Excluded so crucible-core stays order-independent (rather than silently relying on suite
    # ordering); the proper home for them is a job that installs the integration package — a separate
    # follow-up. Until then they are honestly documented here, not dark by accident.
    "framework/v2/console/tests/test_chat_inject.py": "imports vigil_integration at run time; crucible-core does not install the integration package (two-env boundary)",
}


def _find_repo_root(start: Path) -> Path:
    for p in [start, *start.parents]:
        if (p / ".github" / "workflows" / "ci.yml").is_file():
            return p
    raise AssertionError("could not locate repo root (.github/workflows/ci.yml) above this test")


_ME = Path(__file__).resolve()
# engine/crucible is the crucible root: the dir that contains `framework/v2`. Paths in ci.yml's crucible-core
# job are relative to it (the job sets `working-directory: engine/crucible`).
_CRUCIBLE_ROOT = _ME.parents[3]
_FRAMEWORK_V2 = _CRUCIBLE_ROOT / "framework" / "v2"
_REPO = _find_repo_root(_ME)
_CI = _REPO / ".github" / "workflows" / "ci.yml"

_JOB_HEADER = re.compile(r"^  crucible-core:\s*$")
_NEXT_JOB = re.compile(r"^  [A-Za-z0-9_-]+:\s*$")
# an --ignore=framework/v2/<path> token
_IGNORE = re.compile(r"--ignore=(framework/v2(?:/[A-Za-z0-9_./-]+)?)")
# `framework/v2` as a wholesale RUN TARGET on a pytest line: the bare token (optionally a trailing slash) NOT
# part of an --ignore= and NOT a deeper path (`framework/v2/foo`).
_WHOLESALE = re.compile(r"(?<!--ignore=)(?<![\w./-])framework/v2/?(?=\s|$)")


def _crucible_core_lines() -> list[str]:
    """Non-comment lines of the ``crucible-core:`` job ONLY (up to the next top-level job key), so an
    ``--ignore`` or ``framework/v2`` token in another job cannot satisfy or corrupt these checks. ``#``
    comment lines are dropped (a comment quoting a path must not be counted)."""
    lines = _CI.read_text(encoding="utf-8").splitlines()
    start = next((i for i, ln in enumerate(lines) if _JOB_HEADER.match(ln)), None)
    assert start is not None, "crucible-core job not found in ci.yml — the parser or the job name changed"
    end = next((j for j in range(start + 1, len(lines)) if _NEXT_JOB.match(lines[j])), len(lines))
    return [ln for ln in lines[start:end] if not ln.strip().startswith("#")]


def _ci_ignored() -> set[str]:
    return {m for ln in _crucible_core_lines() for m in _IGNORE.findall(ln)}


def _all_tests_dirs() -> list[str]:
    """Every ``framework/v2/**/tests`` directory, crucible-relative (e.g. ``framework/v2/kernel/tests`` and
    the top-level ``framework/v2/tests``), discovered from the FILESYSTEM."""
    return sorted(
        p.relative_to(_CRUCIBLE_ROOT).as_posix()
        for p in _FRAMEWORK_V2.rglob("tests")
        if p.is_dir()
    )


def _dir_keys() -> set[str]:
    """KNOWN_EXCLUDED keys that name a DIRECTORY (they exclude a whole subtree)."""
    return {k for k in KNOWN_EXCLUDED if (_CRUCIBLE_ROOT / k).is_dir()}


def _is_under(child: str, parent: str) -> bool:
    """Is crucible-relative path ``child`` inside (or equal to) directory ``parent``?"""
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def test_crucible_core_runs_framework_v2_wholesale():
    """The STRUCTURAL fix: the job must run the whole ``framework/v2`` tree, so a NEW suite auto-runs and can
    only fail loudly — never silently skip by being absent from a hand-maintained path list."""
    if not _CI.exists():  # pragma: no cover — pre-merge refs without the workflow present
        pytest.skip("ci.yml not present on this ref")
    # require the wholesale token on an actual `pytest` command line, so a step NAME or unrelated line that
    # merely mentions the path cannot satisfy the check.
    assert any("pytest" in ln and _WHOLESALE.search(ln) for ln in _crucible_core_lines()), (
        "the crucible-core job must run the WHOLE `framework/v2` tree (`pytest framework/v2 --ignore=...`); "
        "found no such wholesale run target — a hand-maintained path list is exactly the drift this guard "
        "exists to prevent"
    )


def test_ci_ignore_set_equals_documented_known_excluded():
    """Every crucible-core ``--ignore`` has a documented KNOWN_EXCLUDED reason and vice-versa. Either half
    alone fails, so an undocumented ignore (a silent dark path) cannot land, and a stale reason cannot linger
    after its ignore is dropped."""
    if not _CI.exists():  # pragma: no cover
        pytest.skip("ci.yml not present on this ref")
    ci_ignored = _ci_ignored()
    documented = set(KNOWN_EXCLUDED)
    undocumented = sorted(ci_ignored - documented)
    assert not undocumented, (
        "these paths are --ignore'd in crucible-core but have NO KNOWN_EXCLUDED reason (an undocumented "
        f"silent skip): {undocumented}"
    )
    stale = sorted(documented - ci_ignored)
    assert not stale, (
        "these paths carry a KNOWN_EXCLUDED reason but are NOT --ignore'd in crucible-core (stale reason, or "
        f"the --ignore was dropped so the path now runs): {stale}"
    )


def test_every_tests_dir_is_covered_or_documented_excluded():
    """Partition every filesystem ``framework/v2/**/tests`` dir into covered (runs under the wholesale
    target) vs excluded (under a documented KNOWN_EXCLUDED *directory* key). Because the run target is
    wholesale, a new dir is covered by construction; the only way to make one dark is a documented --ignore
    this guard pins. An undocumented dark dir fails via the ignore-set equality test above; a
    documented-but-actually-covered key fails there too (stale)."""
    if not _CI.exists():  # pragma: no cover
        pytest.skip("ci.yml not present on this ref")
    dir_keys = _dir_keys()
    all_dirs = _all_tests_dirs()
    assert all_dirs, "no framework/v2/**/tests dirs found — the filesystem walk is broken"
    covered = [d for d in all_dirs if not any(_is_under(d, k) for k in dir_keys)]
    excluded = [d for d in all_dirs if any(_is_under(d, k) for k in dir_keys)]
    assert set(covered) | set(excluded) == set(all_dirs)
    # Every directory-level exclusion must actually shadow at least one real tests dir; an --ignore of a dir
    # with no tests under it protects nothing and rots.
    for key in dir_keys:
        assert any(_is_under(d, key) for d in all_dirs), (
            f"KNOWN_EXCLUDED directory key {key!r} shadows NO framework/v2/**/tests dir — it is stale"
        )
    # The guard's own directory must be covered — it has to RUN to protect anything.
    my_dir = _ME.relative_to(_CRUCIBLE_ROOT).parent.as_posix()
    assert my_dir in covered, f"the guard's own dir {my_dir!r} is not covered — it would not run"


def test_file_level_exclusions_are_real_files_in_covered_dirs():
    """A FILE-level exclusion (e.g. one flaky/unportable test file) leaves its directory COVERED — only that
    file is dark. Assert each non-directory KNOWN_EXCLUDED key is a real ``test_*.py`` whose parent
    ``tests`` dir is otherwise covered, so a file exclusion can never quietly dark a whole dir."""
    if not _CI.exists():  # pragma: no cover
        pytest.skip("ci.yml not present on this ref")
    dir_keys = _dir_keys()
    covered_dirs = {d for d in _all_tests_dirs() if not any(_is_under(d, k) for k in dir_keys)}
    for key in set(KNOWN_EXCLUDED) - dir_keys:
        path = _CRUCIBLE_ROOT / key
        assert path.is_file() and path.name.startswith("test_") and path.suffix == ".py", (
            f"file-level KNOWN_EXCLUDED key {key!r} is not a real test_*.py file"
        )
        parent = path.parent.relative_to(_CRUCIBLE_ROOT).as_posix()
        assert parent in covered_dirs, (
            f"file-level exclusion {key!r} lives in dir {parent!r} which is NOT covered — exclude the dir "
            "explicitly (with a reason) instead of hiding it behind a single-file ignore"
        )


def test_every_excluded_path_exists_and_has_a_nonempty_reason():
    """An --ignore of a non-existent path protects nothing and rots; a blank reason is not documentation."""
    for path, reason in KNOWN_EXCLUDED.items():
        assert (_CRUCIBLE_ROOT / path).exists(), f"KNOWN_EXCLUDED names a non-existent path: {path}"
        assert reason and reason.strip(), f"KNOWN_EXCLUDED[{path!r}] must carry a real reason, not {reason!r}"


def test_the_guard_itself_is_never_excluded():
    """This guard is framework-free and must RUN in the crucible-core job — it can never be shadowed."""
    rel = _ME.relative_to(_CRUCIBLE_ROOT).as_posix()
    for key in KNOWN_EXCLUDED:
        assert not _is_under(rel, key) and rel != key, (
            f"the coverage guard {rel!r} must run, never be excluded by {key!r}"
        )


# --------------------------------------------------------------------------------------------------
# W1-3: no ci.yml step may PASS on a missing target.
#
# Six steps guarded a real command behind `if [ -d/-f <path> ]; then <cmd>; else echo "... not present on
# this ref (pre-merge) — nothing to test/check"; fi`. With `main` branch protection STRICT (a mergeable PR
# is up to date with main, and every one of these paths is a committed monorepo path), the else branch can
# only fire on a RENAME or DELETION — and it printed a friendly message and exited 0, so the rename turned
# the gate GREEN instead of RED. Each is now a hard failure (`echo "::error::... missing"; exit 1`). This
# guard asserts the soft-skip antipattern does not come back.
# --------------------------------------------------------------------------------------------------
_SOFT_SKIP = re.compile(r"not present on this ref|nothing to (?:test|check)", re.I)


def test_no_ci_step_passes_on_a_missing_target():
    """No ci.yml line may announce a soft skip ("... not present on this ref", "nothing to test/check").
    Such a branch makes a missing/renamed target report SUCCESS. A missing target must be a hard failure
    (`echo "::error::<path> missing from the checkout"; exit 1`)."""
    if not _CI.exists():  # pragma: no cover
        pytest.skip("ci.yml not present on this ref")
    offenders = [
        ln.strip()
        for ln in _CI.read_text(encoding="utf-8").splitlines()
        if not ln.strip().startswith("#") and _SOFT_SKIP.search(ln)
    ]
    assert not offenders, (
        "these ci.yml lines let a step PASS on a missing/renamed target (a soft skip that turns a rename "
        "GREEN instead of RED). Convert to `echo \"::error::<path> missing from the checkout\"; exit 1`:\n"
        + "\n".join(offenders)
    )
