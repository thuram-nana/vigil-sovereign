"""Guard: a ``@pytest.mark.volume`` test cannot be added and then silently never run.

WHY THIS EXISTS. PR #851's required "integration two-env boundary (P5)" job exceeded GitHub's 45m0s hard
maximum and was CANCELED (run 36270471752, 45m23s) because this branch's statistical liveness regressions
— 80-300 live re-drives each, ~25 minutes in total — rode the per-PR path. The fix was to mark them
``volume``, exclude them from the per-PR legs, and run them nightly at their FULL, unreduced counts.

That fix has an obvious failure mode, and this repository has already been burned by its cousin ("a
skipped proof and a passing proof are the same colour on a dashboard"): a future volume test is marked,
drops off the PR leg as designed, and is never added to the nightly — so it runs in NEITHER place while
looking, from the source, exactly like a covered regression. That is worse than leaving it on the PR path,
because the file still reads as if the class is guarded.

So the rule is enforced in both directions, from the committed artifacts alone (pure file reads, no
imports — this guard is framework-free and runs in the SOVEREIGN leg; keep it out of any ``--ignore``):

  1. the marker is REGISTERED, in both places the two CI legs resolve their config from;
  2. every file carrying a volume test is named in the nightly job's ``-m volume`` command;
  3. the nightly workflow is genuinely scheduled, is not ``continue-on-error``, does not swallow the exit
     code, and asserts the tests EXECUTED rather than skipped;
  4. every ci.yml step that collects a volume-carrying test file passes ``-m "not volume"`` — so the
     per-PR exclusion cannot be dropped by accident either, which is what would re-create the 45-minute
     job this whole split exists to end.

NEGATIVE CONTROLS. The checkers below take their inputs as ARGUMENTS so the perturbation can be exercised
in-process rather than merely described: ``test_negative_control_*`` feed them a nightly command with a
file missing, and a ci.yml step with the exclusion stripped, and assert they REPORT the divergence.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_TESTS_DIR = Path(__file__).resolve().parent
_CI = _REPO / ".github" / "workflows" / "ci.yml"
_WORKFLOWS = _REPO / ".github" / "workflows"
_PYPROJECT = _REPO / "integration" / "pyproject.toml"
_CONFTEST = _REPO / "integration" / "conftest.py"
_ASSERT_SCRIPT = "assert_volume_tests_ran.py"

# `@pytest.mark.volume` on its own line (the only form this tree uses).
_VOLUME_MARK = re.compile(r"^\s*@(?:pytest\.)?mark(?:er)?\.volume\b|^\s*@pytest\.mark\.volume\b", re.M)
# `-m volume` / `-m "volume"` — NOT `-m "not volume"`.
_SELECTS_VOLUME = re.compile(r"-m\s+(['\"]?)volume\1(?:\s|$)")
# `-m "not volume"` in any quoting style.
_EXCLUDES_VOLUME = re.compile(r"-m\s+(['\"])not volume\1")
_TEST_PATH = re.compile(r"integration/tests/(test_[A-Za-z0-9_]+\.py)")


# ---------------------------------------------------------------------------------------------------
# pure helpers (argument-taking, so the negative controls can drive them)
# ---------------------------------------------------------------------------------------------------
def volume_marked_files(tests_dir: Path) -> list[str]:
    """Every test file that carries at least one ``@pytest.mark.volume``."""
    out = []
    for f in sorted(tests_dir.glob("test_*.py")):
        if f.name == Path(__file__).name:
            continue  # this guard never carries the marker it polices
        if _VOLUME_MARK.search(f.read_text(encoding="utf-8")):
            out.append(f.name)
    return out


def split_steps(workflow_text: str) -> list[str]:
    """A workflow split into its STEP blocks (a step starts at a 6-space `- name:` / `- uses:`)."""
    boundary = re.compile(r"^ {6}- (?:name|uses):")
    blocks: list[list[str]] = []
    for line in workflow_text.splitlines():
        if boundary.match(line) or not blocks:
            blocks.append([])
        blocks[-1].append(line)
    return ["\n".join(b) for b in blocks]


def _uncommented(block: str) -> str:
    return "\n".join(ln for ln in block.splitlines() if not ln.strip().startswith("#"))


def nightly_volume_steps(workflow_texts: dict[str, str]) -> dict[str, str]:
    """{workflow filename: the step text} for every step whose command SELECTS `-m volume`."""
    hits = {}
    for name, text in workflow_texts.items():
        for step in split_steps(text):
            if _SELECTS_VOLUME.search(_uncommented(step)):
                hits[name] = step
    return hits


def uncovered_by_nightly(volume_files: list[str], nightly_step: str) -> list[str]:
    """Volume-carrying files the nightly `-m volume` command does not name."""
    listed = {m.group(1) for m in _TEST_PATH.finditer(_uncommented(nightly_step))}
    return sorted(f for f in volume_files if f not in listed)


def pr_steps_missing_the_exclusion(ci_text: str, volume_files: list[str]) -> list[str]:
    """Step names in ci.yml that COLLECT a volume-carrying file but do not pass `-m "not volume"`.

    A file reaches a step either by being named on a run line, or by the step collecting the whole
    ``integration/tests`` directory; both are checked, and an ``--ignore=``d or commented mention does
    not count as collecting it.
    """
    offenders = []
    for step in split_steps(ci_text):
        body = _uncommented(step)
        run_lines = [ln for ln in body.splitlines() if "--ignore=" not in ln]
        run_body = "\n".join(run_lines)
        named = any(re.search(rf"integration/tests/{re.escape(f)}", run_body) for f in volume_files)
        whole_dir = re.search(r"pytest[^\n]*\sintegration/tests(?:\s|$|\\)", run_body) is not None
        if not (named or whole_dir):
            continue
        if _EXCLUDES_VOLUME.search(body):
            continue
        first = step.splitlines()[0].strip()
        offenders.append(first)
    return offenders


def _workflow_texts() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(_WORKFLOWS.glob("*.y*ml"))}


# ---------------------------------------------------------------------------------------------------
# the guard
# ---------------------------------------------------------------------------------------------------
def test_the_volume_marker_is_registered_for_both_ci_legs():
    """`-m volume` must select, and `--strict-markers` must not error, under EITHER rootdir.

    The sovereign leg runs ``pytest integration/tests`` (rootdir integration/, configfile
    integration/pyproject.toml); the offense leg's argument set spans docs/ and integration/, so its
    rootdir — and configfile — is the repo root, where that table does not exist. Hence both.
    """
    assert re.search(r"^markers\s*=", _PYPROJECT.read_text(encoding="utf-8"), re.M), (
        "integration/pyproject.toml declares no [tool.pytest.ini_options] markers table"
    )
    assert "volume:" in _PYPROJECT.read_text(encoding="utf-8"), (
        "the `volume` marker is not registered in integration/pyproject.toml"
    )
    conftest = _CONFTEST.read_text(encoding="utf-8")
    assert "addinivalue_line" in conftest and "volume:" in conftest, (
        "integration/conftest.py does not register the `volume` marker — under the offense leg's "
        "repo-root rootdir the pyproject table is not read, so the marker would be unknown there"
    )


def test_every_volume_test_file_is_covered_by_the_nightly_job():
    vol = volume_marked_files(_TESTS_DIR)
    assert vol, (
        "no @pytest.mark.volume test files found — either the statistical regressions lost their marker "
        "(they would then be back on the per-PR path, or gone) or this detector is broken"
    )
    steps = nightly_volume_steps(_workflow_texts())
    assert steps, (
        "no workflow step runs `-m volume`, so every volume-marked test runs in NEITHER the per-PR leg "
        f"(which passes -m \"not volume\") nor a nightly. Uncovered: {vol}"
    )
    uncovered = sorted(set().union(*[set(uncovered_by_nightly(vol, s)) for s in steps.values()]))
    # a file is covered if ANY nightly volume step names it
    uncovered = [f for f in uncovered if all(uncovered_by_nightly([f], s) for s in steps.values())]
    assert not uncovered, (
        "these files carry @pytest.mark.volume tests but no nightly `-m volume` command names them, so "
        f"those regressions run NOWHERE: {uncovered}"
    )


def test_the_nightly_volume_job_is_scheduled_and_fails_loudly():
    steps = nightly_volume_steps(_workflow_texts())
    assert steps, "no nightly `-m volume` step to check"
    for wf_name, step in steps.items():
        text = (_WORKFLOWS / wf_name).read_text(encoding="utf-8")
        assert re.search(r"^\s{2}schedule:", text, re.M), (
            f"{wf_name} runs the volume tests but has no `schedule:` trigger — it would only ever run "
            "when someone remembered to dispatch it by hand"
        )
        assert "continue-on-error: true" not in text, (
            f"{wf_name} sets continue-on-error — a failing statistical regression would report green"
        )
        body = _uncommented(step)
        assert "|| true" not in body and "|| echo" not in body, (
            f"{wf_name}'s volume step swallows the pytest exit code: {body!r}"
        )
        # and the run must be proven to have EXECUTED, not skipped
        assert any(_ASSERT_SCRIPT in _uncommented(s) for s in split_steps(text)), (
            f"{wf_name} runs the volume tests but never asserts they executed — every test in the file "
            f"is behind a pytest.importorskip, so a missing dependency would skip all of them and exit "
            f"0. Add the `{_ASSERT_SCRIPT}` step."
        )
    assert (_REPO / ".github" / "scripts" / _ASSERT_SCRIPT).exists(), (
        f".github/scripts/{_ASSERT_SCRIPT} is missing — the nightly's did-it-actually-run assertion"
    )


def test_every_pr_step_that_collects_a_volume_file_excludes_the_marker():
    """The other direction: the per-PR exclusion cannot be dropped, or the 45-minute job comes back."""
    if not _CI.exists():  # pragma: no cover — pre-merge refs without the workflow present
        pytest.skip("ci.yml not present on this ref")
    vol = volume_marked_files(_TESTS_DIR)
    offenders = pr_steps_missing_the_exclusion(_CI.read_text(encoding="utf-8"), vol)
    assert not offenders, (
        "these ci.yml steps collect a volume-carrying test file without `-m \"not volume\"`, so the "
        "statistical loops ride every pull request again — the exact cause of the CANCELED 45m23s "
        f"required job: {offenders}"
    )


# ---------------------------------------------------------------------------------------------------
# negative controls — the checkers must REPORT a divergence, not wave it through
# ---------------------------------------------------------------------------------------------------
def test_negative_control_a_file_missing_from_the_nightly_is_reported():
    step = "      - name: run volume\n        run: |\n          pytest integration/tests/test_a.py -m volume -q\n"
    assert uncovered_by_nightly(["test_a.py"], step) == []
    assert uncovered_by_nightly(["test_a.py", "test_b.py"], step) == ["test_b.py"]


def test_negative_control_a_commented_mention_does_not_count_as_coverage():
    step = "      - name: run volume\n        # integration/tests/test_b.py used to be here\n        run: |\n          pytest integration/tests/test_a.py -m volume -q\n"
    assert uncovered_by_nightly(["test_b.py"], step) == ["test_b.py"]


def test_negative_control_a_pr_step_without_the_exclusion_is_reported():
    good = (
        "      - name: integration tests\n"
        "        run: |\n"
        "          pytest integration/tests/test_a.py -q -m \"not volume\"\n"
    )
    bad = "      - name: integration tests\n        run: |\n          pytest integration/tests/test_a.py -q\n"
    assert pr_steps_missing_the_exclusion(good, ["test_a.py"]) == []
    assert pr_steps_missing_the_exclusion(bad, ["test_a.py"]) == ["- name: integration tests"]


def test_negative_control_an_ignored_file_is_not_treated_as_collected():
    ignored = (
        "      - name: sovereign leg\n"
        "        run: |\n"
        "          pytest integration/tests/other --ignore=integration/tests/test_a.py -q\n"
    )
    assert pr_steps_missing_the_exclusion(ignored, ["test_a.py"]) == []


def test_negative_control_not_volume_is_not_mistaken_for_selecting_volume():
    assert _SELECTS_VOLUME.search('pytest x -m "not volume" -q') is None
    assert _SELECTS_VOLUME.search("pytest x -m volume -q") is not None
    assert _EXCLUDES_VOLUME.search('pytest x -m "not volume" -q') is not None
