"""Wave 7 — a paused run is honest end to end: engine emits a terminal run_summary, the supervisor marks it
PAUSED (not done), the API surfaces the pause reason, and the UI shows a Paused step + a Resume affordance,
with approve-then-continue auto-resuming a run that paused awaiting the signature.

Docs-only drift guard (reads files, no framework import)."""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CSS = (REPO / "packages" / "vigil-ui" / "components.css").read_text(encoding="utf-8")
ENGINE = (REPO / "integration" / "vigil_integration" / "live" / "engine.py").read_text(encoding="utf-8")
ACTIONS = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "actions.py").read_text(encoding="utf-8")
API = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "api.py").read_text(encoding="utf-8")


def test_engine_emits_a_terminal_run_summary():
    assert '"run_summary"' in ENGINE and '"paused": report.paused' in ENGINE


def test_supervisor_marks_a_paused_run_paused_not_done():
    assert "def _run_outcome(" in ACTIONS
    assert '_run_outcome(run_id)' in ACTIONS and 'status = "paused"' in ACTIONS


def test_api_surfaces_the_pause_reason():
    assert '"paused": str(meta.get("paused"' in API


def test_ui_shows_paused_and_offers_resume():
    assert 'PBOX.run.status === "paused"' in APPJS, "the paused step-text branch is gone"
    assert 'r.status === "paused"' in APPJS, "runIsRetryable must accept paused (so Resume shows)"
    assert ".pb-step.pb-paused" in CSS, "the paused step needs its own (non-Done) style"


def test_ui_auto_resumes_after_approving_a_paused_run():
    assert "function _afterOffenseApprove(" in APPJS
    # ENH1: the auto-resume guard now fires for a re-approval of BOTH pause reasons.
    assert '_pp === "awaiting_approval"' in APPJS and "pboxRetry();" in APPJS
    assert '_pp === "approval_rejected"' in APPJS, "re-approving an approval_rejected pause must auto-resume"
