"""W11-1 (#482): the end-to-end loopback engagement is a REQUIRED CI job that re-verifies offline.

WHY THIS TEST EXISTS. The flagship demonstration of the whole engine — scan a live target, confirm a
real weakness through the oracle, and RE-VERIFY that evidence offline with no trust in the tool that
produced it — lived only as a hand-run recorded in a memory file. A hand-run proves nothing on the next
commit. This test is the OFFLINE pin (it rides the already-required "the briefing explains every agent
and capability" job, so it installs only pytest and reads files) that the mechanized job and its driver
actually exist, are wired into CI, re-verify offline, carry a negative control and a tamper control, and
are a REQUIRED check. It FAILS on any tree where the job or its driver is missing — the failure the AC
asks to be OBSERVED, not assumed (delete the job from ci.yml, or `verify` from the driver, and see).

It does not run the engine (that is the job itself); it proves the committed CI artifacts say what the
claim says, so the prose cannot drift from the pipeline the way the required-check count once did.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CI = REPO / ".github" / "workflows" / "ci.yml"
CANONICAL = REPO / ".github" / "required-status-checks.txt"
DRIVER = REPO / "tools" / "loopback-engagement" / "run_loopback_engagement.sh"
CHECK = REPO / "tools" / "loopback-engagement" / "check.py"

JOB_NAME = "loopback engagement (end-to-end + offline re-verify)"


# --------------------------------------------------------------------------------------------------
# Pure helpers (perturbable in-process by the negative controls below).
# --------------------------------------------------------------------------------------------------
def workflow_has_job_named(text: str, name: str) -> bool:
    """A workflow declares a job whose `name:` is exactly `name` (quoted or bare)."""
    esc = re.escape(name)
    return re.search(rf'^\s*name:\s*["\']?{esc}["\']?\s*$', text, re.MULTILINE) is not None


def missing_tokens(text: str, tokens: list[str]) -> list[str]:
    """Which required tokens are absent from `text` — [] means all present."""
    return [t for t in tokens if t not in text]


def canonical_names(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


# --------------------------------------------------------------------------------------------------
# The job exists, is triggered on PRs, runs the driver, retains the demo, and re-verifies on a clean tree.
# --------------------------------------------------------------------------------------------------
def test_ci_defines_the_required_job():
    text = CI.read_text(encoding="utf-8")
    assert "pull_request:" in text, "ci.yml must run on pull_request for its jobs to be PR status checks"
    assert workflow_has_job_named(text, JOB_NAME), (
        f"ci.yml has no job named {JOB_NAME!r} — the W11-1 end-to-end job is missing"
    )


def test_job_runs_the_driver_and_reverifies_on_a_clean_checkout():
    text = CI.read_text(encoding="utf-8")
    # It invokes the real driver script...
    assert "tools/loopback-engagement/run_loopback_engagement.sh" in text, (
        "the job must run the loopback-engagement driver"
    )
    # ...and re-verifies against a SECOND, independent checkout (the offline-portability proof).
    assert "_clean-reverify" in text and "VIGIL_LE_REVERIFY_DIR" in text, (
        "the job must re-verify the evidence on a clean, independent checkout (VIGIL_LE_REVERIFY_DIR)"
    )


def test_job_retains_the_reviewer_demo_artifact():
    text = CI.read_text(encoding="utf-8")
    assert "upload-artifact" in text and "loopback-engagement-out" in text, (
        "the job output is the reviewer demonstration artifact and must be retained (upload-artifact)"
    )


def test_required_check_is_in_the_canonical_list():
    names = canonical_names(CANONICAL.read_text(encoding="utf-8"))
    assert JOB_NAME in names, (
        f"{JOB_NAME!r} must be a REQUIRED check (in .github/required-status-checks.txt) — AC: the test "
        "runs in a required CI job"
    )


# --------------------------------------------------------------------------------------------------
# The driver actually drives the full chain: scan -> confirmed FACT -> offline re-verify -> controls.
# --------------------------------------------------------------------------------------------------
def test_driver_scans_and_reverifies_offline():
    assert DRIVER.is_file(), "the loopback-engagement driver script is missing"
    text = DRIVER.read_text(encoding="utf-8")
    missing = missing_tokens(text, [
        "framework.v2 scan",        # runs the real scan CLI
        "framework.v2 verify",      # re-verifies the evidence OFFLINE
        "--reverifiable-out",       # produces the re-verifiable certificate artifact
        "--library",                # over the FULL check corpus (conclusive coverage)
    ])
    assert not missing, f"the driver does not perform the full scan+re-verify chain; missing: {missing}"


def test_driver_has_a_negative_control():
    text = DRIVER.read_text(encoding="utf-8")
    # scans the PATCHED twin and asserts a clean result via the negative checker
    missing = missing_tokens(text, ["--safe", "check.py", "negative"])
    assert not missing, f"the driver lacks the patched-twin negative control; missing: {missing}"


def test_driver_has_a_tamper_gate_control():
    text = DRIVER.read_text(encoding="utf-8")
    # forges a certificate and asserts `verify` REJECTS it — proof the re-verify gate is not a no-op
    missing = missing_tokens(text, ["tamper", "REJECTED"])
    assert not missing, f"the driver lacks the tamper control that proves the gate is not a no-op; missing: {missing}"
    assert 'VERIFY_RC" != "0"' in text or "VERIFY_RC != 0" in text, (
        "the tamper leg must assert verify returns NON-zero on a forged certificate"
    )


def test_asserter_requires_conclusive_coverage_for_the_negative():
    """The negative is a SOUND negative only when coverage is conclusive — the asserter enforces both."""
    text = CHECK.read_text(encoding="utf-8")
    assert "full_coverage" in text, "the asserter must key the sound-negative on the full_coverage flag"
    assert "sound negative" in text.lower(), "the asserter must distinguish a sound negative from silence"


# --------------------------------------------------------------------------------------------------
# Negative controls — the pure checkers must REPORT divergence, not wave it through.
# --------------------------------------------------------------------------------------------------
def test_negative_control_missing_job_is_detected():
    # the real tree has it...
    assert workflow_has_job_named(CI.read_text(encoding="utf-8"), JOB_NAME)
    # ...a workflow WITHOUT the job must be reported absent (this is the 'fails without the change' state)
    stripped = "on:\n  pull_request:\njobs:\n  other:\n    name: something else\n    runs-on: ubuntu-latest\n"
    assert not workflow_has_job_named(stripped, JOB_NAME)


def test_negative_control_driver_missing_verify_is_detected():
    text = DRIVER.read_text(encoding="utf-8")
    assert missing_tokens(text, ["framework.v2 verify"]) == []
    # a driver that dropped the offline re-verify must be reported as missing it
    without = text.replace("framework.v2 verify", "framework.v2 scan")
    assert missing_tokens(without, ["framework.v2 verify"]) == ["framework.v2 verify"]


def test_negative_control_bogus_check_not_in_canonical():
    names = canonical_names(CANONICAL.read_text(encoding="utf-8"))
    assert "loopback engagement THAT DOES NOT EXIST" not in names
