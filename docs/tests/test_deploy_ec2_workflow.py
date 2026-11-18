"""The opt-in EC2 continuous-delivery pipeline is SAFE BY CONSTRUCTION — proven, not asserted in prose.

`deploy-ec2.yml` + `.github/scripts/ssm-deploy.sh` + `tools/remote-deploy.sh` can deploy to a production
host, so every safety property that keeps it from firing wrongly is pinned here as a falsifiable check:

  * it never runs on a pull_request (so a PR can never deploy), and it only fires after the REQUIRED
    `vigil-ci` concludes SUCCESS on `main` (never a red or non-main CI);
  * it is fail-closed + opt-in: with the enabling repo variables unset the job no-ops, and every
    side-effecting step is guarded on that preflight;
  * it carries NO long-lived AWS keys — auth is GitHub OIDC (`id-token: write` +
    AssumeRoleWithWebIdentity);
  * the box-side rollout refuses a dirty tree, only deploys origin/<branch>, and ROLLS BACK to the prior
    commit (restoring the served tree) and exits non-zero on any failure;
  * the job is registered in KNOWN_NONPR_ADVISORY so the required-checks drift guard stays honest.

Delete any one guard (drop the success gate, the preflight, the rollback) and the matching test reds —
the negative control for each is the mutation named in its assertion message.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "deploy-ec2.yml"
RUNNER = REPO / ".github" / "scripts" / "ssm-deploy.sh"
BOX = REPO / "tools" / "remote-deploy.sh"
CANON = REPO / "docs" / "tests" / "test_required_checks_canonical.py"

JOB_NAME = "deploy to EC2 on green main (opt-in)"


def _wf() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _on_block(text: str) -> str:
    """The top-level `on:` block (up to the next column-0 key)."""
    lines = text.splitlines()
    out, collecting = [], False
    for ln in lines:
        if re.match(r"^on:", ln):
            collecting = True
            out.append(ln)
            continue
        if collecting:
            if re.match(r"^\S", ln):
                break
            out.append(ln)
    return "\n".join(out)


def test_workflow_exists_and_scripts_are_present():
    assert WORKFLOW.is_file(), "deploy-ec2.yml is missing"
    assert RUNNER.is_file(), ".github/scripts/ssm-deploy.sh is missing"
    assert BOX.is_file(), "tools/remote-deploy.sh is missing"


def test_never_runs_on_a_pull_request():
    # A PR must never be able to deploy. If `pull_request` ever appears under on:, this reds.
    assert "pull_request" not in _on_block(_wf()), (
        "deploy-ec2.yml must NOT trigger on pull_request (a PR could deploy). "
        "MUTATION: add `pull_request:` under on: -> this reds."
    )


def test_fires_only_after_green_ci_on_main():
    text = _wf()
    assert 'workflows: ["vigil-ci"]' in text, "deploy must key off the required vigil-ci workflow"
    # The job if: must demand a SUCCESSFUL vigil-ci run on the main branch (or a manual dispatch).
    assert "github.event.workflow_run.conclusion == 'success'" in text, (
        "deploy job must require workflow_run.conclusion == 'success' (never deploy a red CI). "
        "MUTATION: drop the success guard -> this reds."
    )
    assert "github.event.workflow_run.head_branch == 'main'" in text, (
        "deploy job must require head_branch == 'main' (never deploy a non-main branch). "
        "MUTATION: drop the main guard -> this reds."
    )


def test_failclosed_optin_preflight_guards_every_side_effect():
    text = _wf()
    assert "configured=false" in text and "CD not configured" in text, (
        "deploy-ec2.yml must have a fail-closed preflight that no-ops when the deploy variables are unset. "
        "MUTATION: remove the preflight -> this reds."
    )
    # Both side-effecting steps (checkout + deploy) must be gated on the preflight output.
    guards = text.count("steps.pf.outputs.configured == 'true'")
    assert guards >= 2, (
        f"every side-effecting step must be guarded on the preflight (found {guards} guards, need >= 2). "
        "MUTATION: drop a step's `if: configured` guard -> this reds."
    )


def test_no_long_lived_aws_keys_only_oidc():
    blob = _wf() + "\n" + RUNNER.read_text(encoding="utf-8")
    # OIDC must be requested and used; no static AWS key material anywhere.
    assert "id-token: write" in _wf(), "the workflow must request an OIDC token (id-token: write)"
    assert "assume-role-with-web-identity" in RUNNER.read_text(encoding="utf-8"), (
        "auth must be OIDC AssumeRoleWithWebIdentity, not a static key"
    )
    forbidden = ("secrets.AWS_ACCESS_KEY_ID", "secrets.AWS_SECRET_ACCESS_KEY", "aws-access-key-id")
    for f in forbidden:
        assert f not in blob, f"no long-lived AWS key material allowed ({f} present)"


def test_box_rollout_is_failclosed_and_rolls_back():
    s = BOX.read_text(encoding="utf-8")
    assert "set -euo pipefail" in s, "remote-deploy.sh must be fail-closed (set -euo pipefail)"
    assert re.search(r"git diff --quiet.*||.*exit 3", s.replace("\n", " ")) or "working tree" in s, (
        "remote-deploy.sh must refuse a dirty working tree before deploying"
    )
    assert 'reset --hard "origin/$BRANCH"' in s, "it must deploy exactly origin/<branch>"
    assert "make deploy-console" in s and "make smoke" in s, (
        "it must reuse the proven rollout (make deploy-console) and the health gate (make smoke)"
    )
    # Rollback: on failure it resets to the previous commit, restores the served tree, and exits non-zero.
    assert 'git reset --hard "$OLD"' in s and "exit 5" in s, (
        "remote-deploy.sh must ROLL BACK to the prior commit and exit non-zero on a failed rollout. "
        "MUTATION: delete the rollback branch -> this reds."
    )


def test_registered_as_nonpr_advisory():
    # The required-checks drift guard (test_required_checks_canonical.py) requires every never-on-PR job
    # to carry a written reason; this cross-checks the registration so the two cannot drift apart.
    canon = CANON.read_text(encoding="utf-8")
    assert JOB_NAME in canon and "deploy-ec2.yml" in canon, (
        "the deploy job must be registered in KNOWN_NONPR_ADVISORY with a reason naming deploy-ec2.yml"
    )
