"""Guard: the Strix-sandbox live-image-scan scaffold is correctly shaped ([W3-7] residual #653).

The A14 gate scans the ~7GB Kali Strix sandbox image only through its committed SBOM on PR runners
(a live build is impossible there). `.github/workflows/strix-sandbox-image-scan.yml` is the SCAFFOLD
for the residual: a live `docker build` + `trivy image` scan on a self-hosted / large runner, at the
gateway image's exact threshold, ADVISORY. Provisioning that self-hosted runner is a human/infra action
(documented in docs/SUPPLY-CHAIN.md §4a). What this test pins, in required PR CI, is that the scaffold
itself is right:

  * it triggers on schedule + workflow_dispatch and NEVER on pull_request/push (so it can never be, or
    accidentally become, a PR status check — it is enumerated in KNOWN_NONPR_ADVISORY);
  * its job is guarded to a SELF-HOSTED `runs-on` label, so it stays dormant on GitHub-hosted infra;
  * it BUILDS the strix sandbox and `trivy image`-scans it at the SAME threshold as the gateway image
    (HIGH,CRITICAL with --ignore-unfixed);
  * its job name is exactly the one enumerated in KNOWN_NONPR_ADVISORY (the two cannot drift).

STDLIB ONLY. Runs in the required `the briefing explains every agent and capability` CI job
(`pytest docs/tests -q`). Reuses the hand parser from test_required_checks_canonical (same job), so no
YAML dependency is needed.
"""
from __future__ import annotations

from pathlib import Path

# Reuse the battle-tested, dependency-free workflow parser and the advisory ledger from the sibling
# guard (same docs/tests job, so this import adds no dependency).
from test_required_checks_canonical import (  # type: ignore
    KNOWN_NONPR_ADVISORY,
    parse_jobs,
    parse_on_events,
)

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "strix-sandbox-image-scan.yml"

# The exact job name; must equal the KNOWN_NONPR_ADVISORY key so the accounting and the workflow agree.
JOB_NAME = "strix sandbox live image scan (self-hosted, advisory)"


def strix_sandbox_scan_workflow_defects(text: str) -> list[str]:
    """Return a list of shape defects in the Strix-sandbox scan workflow; empty == correctly shaped.
    Pure over its input so the negative controls can perturb the text in-process."""
    defects: list[str] = []

    events = parse_on_events(text)
    for needed in ("schedule", "workflow_dispatch"):
        if needed not in events:
            defects.append(f"workflow must trigger on {needed!r} (events seen: {sorted(events)})")
    for forbidden in ("pull_request", "push"):
        if forbidden in events:
            defects.append(
                f"workflow must NOT trigger on {forbidden!r} — a self-hosted heavy scan must never run on a PR"
            )

    # SELF-HOSTED guard on runs-on.
    runs_on_lines = [l for l in text.splitlines() if l.strip().startswith("runs-on:")]
    if not any("self-hosted" in l for l in runs_on_lines):
        defects.append("job runs-on must include a 'self-hosted' label so it stays dormant on GitHub-hosted infra")

    # Builds the strix sandbox image.
    if "strix build strix-sandbox" not in text and "strix-sandbox" not in text:
        defects.append("workflow must BUILD the strix sandbox image")

    # trivy image scan at the gateway threshold.
    if "trivy image" not in text:
        defects.append("workflow must run `trivy image` against the built image")
    if "--severity HIGH,CRITICAL" not in text:
        defects.append("trivy image scan must use the gateway threshold --severity HIGH,CRITICAL")
    if "--ignore-unfixed" not in text:
        defects.append("trivy image scan must use --ignore-unfixed, matching the gateway image gate")

    return defects


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------------------
# Positive checks — TRUE of the committed scaffold.
# --------------------------------------------------------------------------------------------------
def test_workflow_exists():
    assert WORKFLOW.is_file(), f"missing Strix sandbox scan scaffold: {WORKFLOW.relative_to(REPO)}"


def test_workflow_is_correctly_shaped():
    defects = strix_sandbox_scan_workflow_defects(_text())
    assert not defects, "Strix sandbox scan workflow defects:\n  - " + "\n  - ".join(defects)


def test_job_name_matches_the_nonpr_advisory_ledger():
    names = {name for name, _ in parse_jobs(_text())}
    assert JOB_NAME in names, f"the scan job must be named {JOB_NAME!r}; jobs seen: {sorted(names)}"
    assert JOB_NAME in KNOWN_NONPR_ADVISORY, (
        "the scan job must be enumerated in KNOWN_NONPR_ADVISORY (it never runs on a PR)"
    )


def test_it_is_a_nonpr_job_only():
    events = parse_on_events(_text())
    assert "pull_request" not in events, "the scaffold must never run on a pull_request"


# --------------------------------------------------------------------------------------------------
# Negative controls — the shape guard REJECTS a malformed scaffold in the same run.
# --------------------------------------------------------------------------------------------------
def test_negative_control_missing_self_hosted_guard():
    perturbed = _text().replace("[self-hosted, linux, x64, large]", "ubuntu-latest")
    defects = strix_sandbox_scan_workflow_defects(perturbed)
    assert any("self-hosted" in d for d in defects), defects


def test_negative_control_pull_request_trigger_is_rejected():
    # Inject a pull_request trigger under on: — the guard must reject it.
    perturbed = _text().replace(
        "on:\n  schedule:",
        "on:\n  pull_request:\n    branches: [main]\n  schedule:",
    )
    defects = strix_sandbox_scan_workflow_defects(perturbed)
    assert any("pull_request" in d for d in defects), defects


def test_negative_control_wrong_threshold_is_rejected():
    perturbed = _text().replace("--ignore-unfixed", "")
    defects = strix_sandbox_scan_workflow_defects(perturbed)
    assert any("ignore-unfixed" in d for d in defects), defects


def test_negative_control_real_workflow_is_clean():
    # Sanity: the real text passes, so the negatives above are meaningful, not always-fail.
    assert strix_sandbox_scan_workflow_defects(_text()) == []
