"""Guard: the #653 self-hosted-runner provisioning script cannot drift from its workflow.

`tools/supply-chain/register-strix-sandbox-runner.sh` is the operator-run automation for the
W3-7 residual (#653): it provisions/registers the self-hosted GitHub Actions runner and flips the
opt-in repository variable that arm `.github/workflows/strix-sandbox-image-scan.yml` (the dormant
live `trivy image` build+scan of the ~7GB Strix sandbox image). Because the script and the workflow
MUST agree on exactly three things — the runner labels the job's `runs-on` requires, the name (and
armed value) of the opt-in repository variable the job's `if:` gates on, and the trivy blocking
threshold (`--severity HIGH,CRITICAL` with `--ignore-unfixed`) — this test parses BOTH files and
cross-checks them, so a change to one that is not mirrored in the other fails required CI.

It also pins that the script mints its runner registration token from the GitHub API at runtime
(never a hardcoded token literal) and that every subcommand it advertises is actually dispatched.

All defect detection flows through the single pure checker `runner_script_defects(script_text,
workflow_text) -> list[str]`, so the positive assertions and the negative controls exercise exactly
one implementation. The negative controls perturb the text in-process (no files touched) and PASS by
proving the checker has teeth.

STDLIB ONLY (no pytest plugins, no network, no docker, no YAML dep). Runs in the required
`the briefing explains every agent and capability` CI job (`pytest docs/tests -q`).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "supply-chain" / "register-strix-sandbox-runner.sh"
WORKFLOW = REPO / ".github" / "workflows" / "strix-sandbox-image-scan.yml"

# Subcommands the script advertises in its usage; each must be genuinely dispatched.
EXPECTED_SUBCOMMANDS = ("register-runner", "enable-scan", "local-scan", "deregister")

# The trivy blocking-threshold literals the script must share with the workflow (cross-checked:
# each must appear in the workflow before it is required of the script, so the check is driven by
# the workflow and cannot go stale on its own).
TRIVY_THRESHOLD_FLAGS = ("--severity HIGH,CRITICAL", "--ignore-unfixed")

# The GitHub API endpoint the script must hit to mint a runner registration token at runtime.
REG_TOKEN_ENDPOINT = "actions/runners/registration-token"

# GitHub token prefixes (ghp_/gho_/ghu_/ghs_/ghr_) followed by a long opaque body — a hardcoded
# match here means a secret was baked in instead of minted at runtime.
_HARDCODED_TOKEN_RE = re.compile(r"gh[opsur]_[A-Za-z0-9]{20,}")


# --------------------------------------------------------------------------------------------------
# Pure parsers over the workflow (dependency-free; the workflow shape is simple and pinned by
# test_strix_sandbox_image_scan_workflow.py).
# --------------------------------------------------------------------------------------------------
def workflow_runs_on_labels(workflow_text: str) -> list[str]:
    """The labels from `runs-on: [self-hosted, linux, x64, large]`; [] if unparseable."""
    m = re.search(r"runs-on:\s*\[([^\]]*)\]", workflow_text)
    if not m:
        return []
    return [tok.strip() for tok in m.group(1).split(",") if tok.strip()]


def workflow_opt_in_variable(workflow_text: str) -> tuple[str, str]:
    """The (name, armed_value) from `vars.STRIX_SANDBOX_SCAN == 'enabled'`; ("","") if unparseable."""
    m = re.search(r"vars\.([A-Za-z_][A-Za-z0-9_]*)\s*==\s*'([^']*)'", workflow_text)
    if not m:
        return ("", "")
    return (m.group(1), m.group(2))


# --------------------------------------------------------------------------------------------------
# The single checker. Empty list == the script agrees with the workflow and is well-formed.
# --------------------------------------------------------------------------------------------------
def runner_script_defects(script_text: str, workflow_text: str) -> list[str]:
    """Return a list of defects in the provisioning script relative to the workflow; [] == clean.

    Pure over its two inputs so the negative controls can perturb either text in-process.
    """
    defects: list[str] = []

    # 1. Runner labels: the script must declare EVERY label the workflow's runs-on requires, so
    #    the runner it registers is actually the one the job dispatches to.
    labels = workflow_runs_on_labels(workflow_text)
    if not labels:
        defects.append("could not parse the runner labels from the workflow `runs-on` (cross-check impossible)")
    for label in labels:
        if label not in script_text:
            defects.append(f"script must declare the runner label {label!r} that the workflow `runs-on` requires")

    # 2. Opt-in repository variable: the script must reference the same variable NAME the workflow
    #    gates on, and set it to the same armed VALUE the workflow's `if:` compares against.
    var_name, armed_value = workflow_opt_in_variable(workflow_text)
    if not var_name:
        defects.append("could not parse the opt-in `vars.<NAME> == '<value>'` gate from the workflow `if:`")
    else:
        if var_name not in script_text:
            defects.append(f"script must reference the opt-in repository variable {var_name!r} the workflow gates on")
        if armed_value and armed_value not in script_text:
            defects.append(
                f"script must set {var_name!r} to the armed value {armed_value!r} the workflow `if:` compares against"
            )

    # 3. Trivy threshold: the script's scan must use the SAME blocking flags as the workflow gate.
    for flag in TRIVY_THRESHOLD_FLAGS:
        if flag not in workflow_text:
            defects.append(f"workflow no longer declares the trivy threshold flag {flag!r} — cannot cross-check")
        elif flag not in script_text:
            defects.append(f"script must run trivy at the workflow threshold {flag!r}")

    # 4. Registration token comes from the GitHub API at runtime, and no token is hardcoded.
    if REG_TOKEN_ENDPOINT not in script_text:
        defects.append(f"script must mint a runner registration token from the GitHub API ({REG_TOKEN_ENDPOINT})")
    if _HARDCODED_TOKEN_RE.search(script_text):
        defects.append("script contains a hardcoded GitHub token literal — tokens must be minted at runtime, never baked in")

    # 5. Every advertised subcommand is actually dispatched (a `<name>)` case label in the script).
    for sub in EXPECTED_SUBCOMMANDS:
        if f"{sub})" not in script_text:
            defects.append(f"subcommand {sub!r} is advertised but not dispatched (no `{sub})` case in the script)")

    return defects


def _script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------------------
# Positive checks — TRUE of the committed script + workflow.
# --------------------------------------------------------------------------------------------------
def test_script_exists_and_is_executable():
    assert SCRIPT.is_file(), f"missing provisioning script: {SCRIPT.relative_to(REPO)}"
    assert os.access(SCRIPT, os.X_OK), f"provisioning script must be executable: {SCRIPT.relative_to(REPO)}"


def test_script_agrees_with_workflow_and_is_well_formed():
    defects = runner_script_defects(_script_text(), _workflow_text())
    assert not defects, "register-strix-sandbox-runner.sh defects:\n  - " + "\n  - ".join(defects)


def test_script_advertises_each_subcommand_in_usage():
    # Independent of the checker: the four subcommands are named in the human-facing usage block,
    # so "advertised" is real, not just an internal case label.
    text = _script_text()
    for sub in EXPECTED_SUBCOMMANDS:
        assert sub in text, f"usage/help must mention the {sub!r} subcommand"


# --------------------------------------------------------------------------------------------------
# Negative controls — the checker REJECTS a broken script in the same run (proves it has teeth).
# --------------------------------------------------------------------------------------------------
def test_negative_control_missing_trivy_threshold_is_reported():
    # Strip --ignore-unfixed from the script: the cross-check against the workflow must catch it.
    perturbed = _script_text().replace("--ignore-unfixed", "")
    defects = runner_script_defects(perturbed, _workflow_text())
    assert any("ignore-unfixed" in d for d in defects), defects


def test_negative_control_hardcoded_token_is_reported():
    # Assemble a fake token at runtime (no secret literal in this file) and inject it; the checker
    # must flag a baked-in token.
    fake_token = "ghp_" + ("A" * 36)
    perturbed = _script_text() + f'\nHARDCODED="{fake_token}"\n'
    defects = runner_script_defects(perturbed, _workflow_text())
    assert any("hardcoded GitHub token" in d for d in defects), defects


def test_negative_control_undispatched_subcommand_is_reported():
    # Rename the deregister case label so the subcommand is advertised but no longer dispatched.
    perturbed = _script_text().replace("deregister)", "removed-cmd)")
    defects = runner_script_defects(perturbed, _workflow_text())
    assert any("deregister" in d and "dispatched" in d for d in defects), defects


def test_negative_control_missing_registration_endpoint_is_reported():
    # Blank out the registration-token endpoint; the checker must notice the script can no longer
    # mint a token at runtime.
    perturbed = _script_text().replace(REG_TOKEN_ENDPOINT, "actions/runners/SOME-OTHER-THING")
    defects = runner_script_defects(perturbed, _workflow_text())
    assert any(REG_TOKEN_ENDPOINT in d for d in defects), defects


def test_negative_control_real_script_is_clean():
    # Sanity: the real pair passes, so the negatives above are meaningful (not always-fail).
    assert runner_script_defects(_script_text(), _workflow_text()) == []
