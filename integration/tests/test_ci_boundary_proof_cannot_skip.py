"""Guard (slice W0-13): the REQUIRED two-env boundary job cannot pass on a skipped/un-run proof.

WHY THIS TEST EXISTS. The `integration two-env boundary (P5)` job is a REQUIRED status check — it is the
proof that the sovereign (apps/sigil) and offense (framework/strix) trust domains never co-load in one
interpreter (FATAL-2). It used to install the sovereign package best-effort:

    pip install -e apps/sigil || echo "apps/sigil build skipped — boundary test will skip"

If the Rust WARDEN kernel / the sovereign heavy stack failed to build, that `|| echo` swallowed the failure
and the job went GREEN with the boundary proof unproven — "a skipped proof and a passing proof are the same
colour on a dashboard." This guard makes that whole class loud, OFFLINE, on every pull request, two ways:

  (a) the boundary job must NOT swallow an `apps/sigil` install failure with `||` (the "for-the-install-
      failed proof" pass); and
  (b) the boundary job must run the boundary proof under an execution-enforcement step — the sovereign
      pytest leg writes a JUnit report and a follow-on step feeds it to `assert_boundary_proof_ran.py`,
      which fails the job unless the named proofs actually executed (the "skipped proof" pass). The report
      the enforcer reads must be the one the pytest leg wrote (path consistency).

It also proves the enforcer is not vacuous by feeding it a synthetic JUnit report with a SKIPPED boundary
testcase and asserting it reports the gap (NEGATIVE CONTROL), and the pure text checkers likewise take their
data as arguments so a deliberately-broken workflow block can be exercised in-process.

The guard is framework-free (pure file reads + a stdlib XML parse of a synthetic report), so it runs in the
sovereign leg — keep it OUT of any `--ignore` there.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_CI = _REPO / ".github" / "workflows" / "ci.yml"
_ENFORCER = _REPO / ".github" / "scripts" / "assert_boundary_proof_ran.py"

_BOUNDARY_JOB_NAME = "integration two-env boundary (P5)"
_ENFORCER_BASENAME = "assert_boundary_proof_ran.py"

# The proofs the enforcer must require by name (kept in step with assert_boundary_proof_ran.py::REQUIRED).
_REQUIRED_PROOFS = (
    "test_no_sovereign_member_declares_offense_dependency",
    "test_real_sovereign_venv_cannot_reach_offense",
    "test_keyless_actor_cannot_forge_a_verifiable_governance_event",
)


# --------------------------------------------------------------------------------------------------
# Pure, dependency-free helpers over the workflow text (data passed as arguments so the negative
# controls can perturb them in-process — the test_required_checks_canonical.py idiom).
# --------------------------------------------------------------------------------------------------
def extract_job_block(ci_text: str, job_name: str) -> str:
    """The text of the job whose four-space `name:` equals `job_name`, from its two-space job-id line to
    the next job-id line (or end of file). Empty string if not found."""
    lines = ci_text.splitlines()
    name_re = re.compile(r"^    name:\s*" + re.escape(job_name) + r"\s*$")
    jobkey_re = re.compile(r"^  [A-Za-z0-9_-]+:\s*$")
    start = None
    for i, ln in enumerate(lines):
        if name_re.match(ln):
            j = i
            while j >= 0 and not jobkey_re.match(lines[j]):
                j -= 1
            start = j
            break
    if start is None or start < 0:
        return ""
    end = len(lines)
    for k in range(start + 1, len(lines)):
        if jobkey_re.match(lines[k]):
            end = k
            break
    return "\n".join(lines[start:end])


def swallowed_sigil_installs(job_block: str) -> list[str]:
    """Lines that install `apps/sigil` and swallow the failure with `||` (`|| echo`, `|| true`, `|| :` …).
    Comment lines are ignored so the explanatory comment that quotes the old command is not miscounted."""
    out = []
    for ln in job_block.splitlines():
        if ln.lstrip().startswith("#"):
            continue
        if "pip install" in ln and "apps/sigil" in ln and "||" in ln:
            out.append(ln.strip())
    return out


def _noncomment(job_block: str) -> str:
    return "\n".join(ln for ln in job_block.splitlines() if not ln.lstrip().startswith("#"))


def enforcement_problems(job_block: str) -> list[str]:
    """Problems that would let the boundary proof skip silently; empty means the enforcement is wired."""
    text = _noncomment(job_block)
    problems: list[str] = []
    if _ENFORCER_BASENAME not in text:
        problems.append(
            f"no step invokes {_ENFORCER_BASENAME} — a skipped/un-run boundary proof would pass the job"
        )
        return problems
    written = set(re.findall(r"--junit-xml=\"?([^\s\"]+)\"?", text))
    read = set(re.findall(re.escape(_ENFORCER_BASENAME) + r"\s+\"?([^\s\"]+)\"?", text))
    if not written:
        problems.append("the sovereign pytest leg writes no --junit-xml, so the enforcement has no report to read")
    if not read:
        problems.append(f"{_ENFORCER_BASENAME} is invoked without a report-path argument")
    if written and read and not (read & written):
        problems.append(
            f"the enforcer reads {sorted(read)} but the JUnit report is written to {sorted(written)} — path mismatch"
        )
    return problems


# --------------------------------------------------------------------------------------------------
# The real workflow must satisfy both guarantees.
# --------------------------------------------------------------------------------------------------
def test_boundary_job_does_not_swallow_the_sigil_install():
    block = extract_job_block(_CI.read_text(encoding="utf-8"), _BOUNDARY_JOB_NAME)
    assert block, f"could not locate the {_BOUNDARY_JOB_NAME!r} job in ci.yml"
    offenders = swallowed_sigil_installs(block)
    assert not offenders, (
        "the REQUIRED two-env boundary job swallows an apps/sigil install failure with `||`, so a failed "
        f"build lets the job pass with the boundary proof unproven: {offenders}"
    )


def test_boundary_job_enforces_that_the_proof_actually_ran():
    block = extract_job_block(_CI.read_text(encoding="utf-8"), _BOUNDARY_JOB_NAME)
    assert block, f"could not locate the {_BOUNDARY_JOB_NAME!r} job in ci.yml"
    problems = enforcement_problems(block)
    assert not problems, (
        "the REQUIRED two-env boundary job does not enforce that its boundary proof executed, so a skipped "
        f"proof would pass: {problems}"
    )


def test_enforcer_requires_each_named_boundary_proof():
    assert _ENFORCER.is_file(), f"enforcement helper missing at {_ENFORCER}"
    src = _ENFORCER.read_text(encoding="utf-8")
    for name in _REQUIRED_PROOFS:
        assert name in src, f"the enforcer does not require boundary proof {name!r}"
    # it must treat a non-executed testcase (skipped/error/failure) as a failure, not a pass
    assert "skipped" in src, "the enforcer must treat a skipped boundary proof as a failure"


def test_ci_yaml_parses_and_names_the_boundary_job():
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    assert "jobs" in data and isinstance(data["jobs"], dict)
    names = {job.get("name") for job in data["jobs"].values() if isinstance(job, dict)}
    assert _BOUNDARY_JOB_NAME in names, (
        f"the required job name {_BOUNDARY_JOB_NAME!r} must stay byte-identical (branch protection keys on it)"
    )


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS — the checkers must bite on deliberately-broken workflow text, and the enforcer
# must bite on a report where a boundary proof was skipped / missing (else the guard is vacuous).
# --------------------------------------------------------------------------------------------------
_SWALLOWED_JOB = """  integration:
    name: integration two-env boundary (P5)
    steps:
      - name: install
        run: |
          pip install -e packages/core/vigil_core cryptography
          pip install -e apps/sigil || echo "apps/sigil build skipped — boundary test will skip"
      - name: enforce
        run: python .github/scripts/assert_boundary_proof_ran.py "${RUNNER_TEMP:-/tmp}/sovereign-junit.xml"
  next-job:
    name: something else
"""

_NO_ENFORCEMENT_JOB = """  integration:
    name: integration two-env boundary (P5)
    steps:
      - name: sovereign tests
        run: |
          python -m pytest integration/tests --junit-xml="${RUNNER_TEMP:-/tmp}/sovereign-junit.xml" -q
  next-job:
    name: something else
"""

_PATH_MISMATCH_JOB = """  integration:
    name: integration two-env boundary (P5)
    steps:
      - name: sovereign tests
        run: python -m pytest integration/tests --junit-xml="/tmp/a.xml" -q
      - name: enforce
        run: python .github/scripts/assert_boundary_proof_ran.py "/tmp/b.xml"
  next-job:
    name: something else
"""


def test_negative_control_swallowed_install_is_flagged():
    block = extract_job_block(_SWALLOWED_JOB, _BOUNDARY_JOB_NAME)
    assert swallowed_sigil_installs(block), "the swallow checker failed to flag `pip install … apps/sigil || echo`"


def test_negative_control_missing_enforcement_is_flagged():
    block = extract_job_block(_NO_ENFORCEMENT_JOB, _BOUNDARY_JOB_NAME)
    problems = enforcement_problems(block)
    assert any(_ENFORCER_BASENAME in p for p in problems), "the enforcement checker failed to flag a missing enforcer"


def test_negative_control_report_path_mismatch_is_flagged():
    block = extract_job_block(_PATH_MISMATCH_JOB, _BOUNDARY_JOB_NAME)
    problems = enforcement_problems(block)
    assert any("mismatch" in p for p in problems), "the enforcement checker failed to flag a report-path mismatch"


# --- the enforcer itself must fail on a skipped / missing boundary proof --------------------------
def _load_enforcer():
    spec = importlib.util.spec_from_file_location("assert_boundary_proof_ran", _ENFORCER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _junit(tmp_path, entries: list[tuple[str, str, str | None]]) -> str:
    """Write a minimal JUnit report. entries = (classname, name, skip_reason|None)."""
    cases = []
    for classname, name, skip in entries:
        if skip is None:
            cases.append(f'    <testcase classname="{classname}" name="{name}" time="0.01" />')
        else:
            cases.append(
                f'    <testcase classname="{classname}" name="{name}" time="0.0">'
                f'<skipped type="pytest.skip" message="{skip}"/></testcase>'
            )
    body = "\n".join(cases)
    xml = f'<testsuites>\n  <testsuite name="pytest" tests="{len(entries)}">\n{body}\n  </testsuite>\n</testsuites>\n'
    p = tmp_path / "report.xml"
    p.write_text(xml, encoding="utf-8")
    return str(p)


def _all_passed_entries() -> list[tuple[str, str, str | None]]:
    return [
        ("tests.test_two_env_boundary", "test_no_sovereign_member_declares_offense_dependency", None),
        ("tests.test_two_env_boundary", "test_real_sovereign_venv_cannot_reach_offense", None),
        ("tests.test_offense_worker_keyless", "test_keyless_actor_cannot_forge_a_verifiable_governance_event", None),
    ]


def test_enforcer_passes_when_every_proof_ran(tmp_path):
    mod = _load_enforcer()
    report = _junit(tmp_path, _all_passed_entries())
    assert mod.main(["assert_boundary_proof_ran.py", report]) == 0


def test_enforcer_fails_when_a_boundary_proof_is_skipped(tmp_path):
    mod = _load_enforcer()
    entries = _all_passed_entries()
    # skip the assert_no_offense / sys.modules scan — exactly the importorskip case this slice closes
    entries[1] = (entries[1][0], entries[1][1], "sigil not importable here")
    report = _junit(tmp_path, entries)
    assert mod.main(["assert_boundary_proof_ran.py", report]) == 1


def test_enforcer_fails_when_a_boundary_proof_is_missing(tmp_path):
    mod = _load_enforcer()
    entries = _all_passed_entries()[:2]  # drop the keyless-forge proof entirely
    report = _junit(tmp_path, entries)
    assert mod.main(["assert_boundary_proof_ran.py", report]) == 1
