"""W11-8 (#489) — the deploy-verify pipeline with rollback proof is real and falsifiable.

The pipeline (``sigil.spine.deploy_verify``) reuses W5-7/W5-5's upgrade/rollback machinery (#451/#449) to
tie a deployment to a POST-DEPLOY SMOKE and an AUTOMATIC ROLLBACK: it stands up the prior owner-signed
version, "deploys" the new build with the real ``upgrade()`` orchestrator (which takes + verifies its own
pre-deploy backup — the rollback target), runs a post-deploy smoke, and — if the smoke fails — rolls back to
the prior version and RE-VERIFIES that the owner signature and every record are intact.

This suite pins each falsifiable property and proves each gate is not a no-op:

  * HEALTHY DEPLOY — a deployment whose post-deploy smoke passes STANDS (no rollback), and the deployed store
    verifies under the deployed owner head.
  * NEGATIVE CONTROL (same run) — a deliberately-BROKEN deployment (its deployed store corrupted so the
    post-deploy health smoke fails) is CAUGHT and AUTO-ROLLED-BACK, and the prior version is restored with
    its owner signature + full record set intact. Proven NOT a no-op: the broken deployed store fails
    verification BEFORE the rollback and the restored store passes it AFTER, and the corruption really
    happened.
  * EXIT CODE HONOURED (#457) — ``run_smoke`` derives its verdict SOLELY from the smoke command's exit code
    (0 -> pass, non-zero / missing binary / timeout -> fail), and a non-zero-exit smoke command drives the
    pipeline to roll back while a zero-exit one lets it stand. Proven with a stand-in command, so the
    required PR job needs neither the built venvs nor ``make``.

Every test FAILS on a pre-W11-8 tree: ``sigil.spine.deploy_verify`` does not exist, so the module import
errors (observe it: ``git stash`` the module, run this file, see the collection error, ``git stash pop``).

Run: PYTHONPATH=apps/sigil python -m pytest apps/sigil/tests/test_deploy_verify.py -q
(In CI the required ``SIGIL governor gates (P7 ...)`` job runs the whole ``apps/sigil/tests/`` directory.)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from sigil.spine.deploy_verify import (
    DeployContext,
    break_deployment,
    command_smoke,
    deploy_verify_roundtrip,
    run_full_deploy_verify,
    run_smoke,
    spine_health_smoke,
)
from sigil.spine.store import SpineStore
from sigil.spine.upgrade_harness import build_n_minus_1_signed_spine


# ====================================================================================================
# HEALTHY DEPLOY — passes post-deploy smoke and stands
# ====================================================================================================
def test_healthy_deployment_passes_smoke_and_stands(tmp_path):
    r = deploy_verify_roundtrip(tmp_path, records=12)
    assert r.ok, r.detail
    assert r.outcome == "deployed"
    assert r.post_deploy_smoke_ok is True
    assert r.rolled_back is False
    # the deploy really moved the version boundary (legacy -> segment), i.e. a real upgrade happened
    assert r.prior_layout == "legacy" and r.deployed_layout == "segment"


def test_full_pipeline_verdict_is_green_on_the_live_tree(tmp_path):
    verdict = run_full_deploy_verify(tmp_path, records=10)
    assert verdict["ok"], verdict
    assert verdict["healthy"]["outcome"] == "deployed"
    assert verdict["broken"]["outcome"] == "rolled_back"


# ====================================================================================================
# NEGATIVE CONTROL — a deliberately-broken deployment is caught and auto-rolled-back
# ====================================================================================================
def test_negative_control_broken_deployment_is_caught_and_auto_rolled_back(tmp_path):
    """THE acceptance-criterion negative control: a deliberately-broken deployment (its deployed store
    corrupted) fails the post-deploy smoke and is AUTOMATICALLY rolled back, restoring the prior version
    with the owner signature and every record intact."""
    r = deploy_verify_roundtrip(tmp_path, records=12, break_deploy=True)
    assert r.outcome == "rolled_back"
    assert r.post_deploy_smoke_ok is False, "a broken deployment's post-deploy smoke MUST fail"
    assert r.rolled_back is True
    # the rollback RESTORED the prior version, proven at every gate
    assert r.restored_signature_ok, "the original owner signature must verify over the restored store"
    assert r.restored_chain_ok, "the restored store's hash chain must verify"
    assert r.restored_data_intact, "the restored store must have the prior record count + sequence set"
    assert r.restored_layout == "legacy" and r.restored_layout == r.prior_layout
    assert r.post_rollback_smoke_ok, "the restored prior version must itself pass smoke"
    assert r.ok, r.detail


def test_negative_control_rollback_is_not_a_no_op(tmp_path):
    """Prove the rollback actually CHANGES on-disk state back to the prior version, independently of the
    result's own booleans. First confirm a broken deploy leaves an UNHEALTHY store before any rollback;
    then run the full pipeline and RE-OPEN the store on disk: if the rollback were a no-op, the corrupted
    segment store would still be there and its chain would not verify."""
    # (a) a broken deploy, on its own, leaves the deployed store failing verification
    spine = tmp_path / "isolated" / "spine"
    build_n_minus_1_signed_spine(spine, records=8)
    from sigil.spine.upgrade import upgrade
    upgrade(SpineStore(str(spine / "spine.jsonl"), seg_max_bytes=0), backup_dir=tmp_path / "bk")
    assert break_deployment(spine) is True, "the corruption must actually hit a record (precondition)"
    unhealthy, _ = SpineStore(str(spine / "spine.jsonl")).verify()
    assert unhealthy is False, "a broken deployment must leave the deployed store failing verification"

    # (b) the full pipeline over a broken deploy must end with a HEALTHY, prior-sized store on disk
    r = deploy_verify_roundtrip(tmp_path / "full", records=8, break_deploy=True)
    restored = SpineStore(str(tmp_path / "full" / "spine" / "spine.jsonl"))
    chain_ok, _ = restored.verify()
    assert chain_ok, "after auto-rollback the on-disk store must verify (rollback was not a no-op)"
    assert restored.count() == r.prior_count == 8


# ====================================================================================================
# EXIT CODE HONOURED (#457) — the smoke command's return code is the verdict, and it drives the rollback
# ====================================================================================================
def test_run_smoke_honours_the_command_exit_code():
    ok0 = run_smoke([sys.executable, "-c", "import sys; sys.exit(0)"])
    ok7 = run_smoke([sys.executable, "-c", "import sys; sys.exit(7)"])
    assert ok0.ok is True and ok0.returncode == 0
    assert ok7.ok is False and ok7.returncode == 7, "a non-zero exit MUST be a smoke FAILURE"


def test_run_smoke_fails_closed_on_a_missing_binary():
    r = run_smoke(["this-binary-does-not-exist-zzz", "smoke"])
    assert r.ok is False and r.returncode is None
    assert "not found" in r.detail


def test_a_nonzero_exit_smoke_drives_the_rollback(tmp_path):
    """The end-to-end tie: a post-deploy smoke COMMAND that exits non-zero (the shape ``make smoke`` takes
    when the boundary/CLI check fails) is honoured and rolls the deployment back to the prior version."""
    fail = command_smoke([sys.executable, "-c", "import sys; sys.exit(1)"])
    r = deploy_verify_roundtrip(tmp_path, records=8, smoke=fail)
    assert r.outcome == "rolled_back" and r.rolled_back is True
    assert r.restored_signature_ok and r.restored_data_intact and r.ok


def test_a_zero_exit_smoke_lets_the_deployment_stand(tmp_path):
    ok = command_smoke([sys.executable, "-c", "import sys; sys.exit(0)"])
    r = deploy_verify_roundtrip(tmp_path, records=8, smoke=ok)
    assert r.outcome == "deployed" and r.rolled_back is False and r.ok


def test_spine_health_smoke_is_falsifiable(tmp_path):
    """The default health-probe smoke is not 'always green': it passes on a good store and fails on a
    corrupted one — the property the broken-deployment negative control relies on."""
    spine = tmp_path / "spine"
    store, head, kp, tr = build_n_minus_1_signed_spine(spine, records=6)
    data = spine / "spine.jsonl"
    good = spine_health_smoke(DeployContext(data_path=data, head=head, trust_root=tr, phase="post-deploy"))
    assert good.ok is True
    assert break_deployment(spine) is True
    bad = spine_health_smoke(DeployContext(data_path=data, head=head, trust_root=tr, phase="post-deploy"))
    assert bad.ok is False


# ====================================================================================================
# DOC-TRUTH — the pipeline is documented and its claim registered
# ====================================================================================================
_REPO = Path(__file__).resolve().parents[3]
_DECISION = _REPO / "docs" / "decisions" / "W11-8-deploy-verify-pipeline.md"
_RUNBOOK = _REPO / "docs" / "runbooks" / "RELEASE-UPGRADE-ROLLBACK.md"
_WORKFLOW = _REPO / ".github" / "workflows" / "deploy-verify.yml"


def _norm(s: str) -> str:
    return re.sub(r"[\s#]+", " ", (s or "").replace("`", " ")).strip().lower()


def test_decision_record_exists_and_states_the_pipeline_properties():
    assert _DECISION.exists(), f"the W11-8 deploy-verify decision record is missing: {_DECISION}"
    doc = _norm(_DECISION.read_text(encoding="utf-8"))
    assert "deploy" in doc and "rollback" in doc
    assert "smoke" in doc
    assert "make smoke" in doc
    assert "deploy_verify" in doc


def test_module_docstring_documents_the_pipeline():
    from sigil.spine import deploy_verify
    doc = _norm(deploy_verify.__doc__ or "")
    assert "deploy" in doc and "rollback" in doc and "smoke" in doc


def test_runbook_documents_the_deploy_verify_pipeline():
    text = _norm(_RUNBOOK.read_text(encoding="utf-8"))
    assert "deploy-verify" in text or "deploy verify" in text
    assert "make smoke" in text


def test_the_scheduled_full_make_smoke_workflow_exists_and_runs_make_smoke():
    """The heavy variant is honestly wired: a scheduled/dispatch workflow that runs the REAL ``make smoke``
    (exit code honoured) and drives this pipeline. It is NOT a required PR check (it builds the venvs)."""
    assert _WORKFLOW.exists(), f"the deploy-verify workflow is missing: {_WORKFLOW}"
    wf = _WORKFLOW.read_text(encoding="utf-8")
    assert "make smoke" in wf, "the workflow must invoke `make smoke`"
    assert "schedule:" in wf and "workflow_dispatch" in wf
    assert "pull_request" not in wf, "the heavy full-venv variant must not claim to run on PRs"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
