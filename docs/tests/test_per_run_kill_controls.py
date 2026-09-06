"""The Live view must kill ONE run without touching its same-prompt siblings.

WHY THIS TEST EXISTS. The operator asked: if the same prompt starts two separate engagements, I must be
able to kill one. The backend already had per-run cancel — `cancel_run(run_id)` (SIGTERM->SIGKILL of the
run's own recorded pid, boot-guarded, idempotent) exposed at `/api/run/<id>/cancel`. But the Live view's
"Stop run" button tripped the per-SLUG kill-switch (`/api/killswitch/<slug>/trip`) instead — which halts
EVERY run of that job (and blocks new tool calls), so two same-prompt runs sharing a slug could not be
killed independently. The fix points "Stop run" at the per-run cancel endpoint and keeps the kill-switch as
a separate, clearly-labelled "Halt engagement" control.

Reads files only (correct for the docs-only CI job). Behavioural proof that cancelling one run leaves the
sibling running is in the offense-leg test test_per_run_cancel_isolation.py.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
SERVER = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "server.py").read_text(encoding="utf-8")
ACTIONS = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "actions.py").read_text(encoding="utf-8")


def test_stop_run_calls_the_per_run_cancel_endpoint():
    # "Stop run" must hit /api/run/<run_id>/cancel — the per-run process kill — not the slug kill-switch.
    assert '/api/run/" + encodeURIComponent(run.run_id) + "/cancel"' in APPJS, \
        "the per-run Stop control no longer targets /api/run/<id>/cancel"
    assert "function cancelThisRun()" in APPJS


def test_halt_engagement_is_a_separate_killswitch_control():
    # The heavier kill-switch stays available, but as its own labelled control — not as "Stop run".
    assert "function haltEngagement()" in APPJS
    assert '/api/killswitch/" + encodeURIComponent(run.slug) + "/trip"' in APPJS
    # the two must be distinct buttons in the header
    assert "onClick: cancelThisRun" in APPJS and "onClick: haltEngagement" in APPJS


def test_run_id_is_surfaced_to_tell_duplicate_runs_apart():
    # Two runs of the SAME prompt/target differ only by run_id — it must be shown so the operator can pick
    # (and kill) the right one.
    assert '"run " + run.run_id' in APPJS


def test_backend_cancel_endpoint_and_function_exist():
    # The UI target must be real: the route is wired and backed by cancel_run.
    assert '/api/run/' in SERVER and "/cancel" in SERVER
    assert "actions.cancel_run(" in SERVER
    assert "def cancel_run(run_id: str)" in ACTIONS
