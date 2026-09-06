"""An engagement can be paused (Stop, memory kept) and resumed from where it left off, or restarted — the
"pause AND end an engagement with memory persisting to continue" requirement.

WHY THIS TEST EXISTS. Stopping a run persists its memory on the signed spine and the engine can `--resume`
from the last checkpoint (retry_run appends --resume for resumable runs), but the Live view exposed no Resume
control and its Stop copy did not say the memory survives — so "stopped" read as "lost". This adds a
Resume/Restart control shown once a run has ended (Resume when the run is resumable, Restart otherwise),
surfaces a "memory kept" affordance, and states in the Stop tooltip that the memory is kept.

Reads files only (docs-only CI job). The control-selection behaviour (running→Stop/Halt, ended+resumable→
Resume, ended+non-resumable→Restart, Resume→runRetry) was verified against the REAL sliced headerContent in a
headless jsdom harness; this is the drift guard. The backend retry/resume path is exercised by the offense
suite (test_engine_resume + the run-action tests).
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
SERVER = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "server.py").read_text(encoding="utf-8")
ACTIONS = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "actions.py").read_text(encoding="utf-8")


def test_live_view_has_a_resume_or_restart_control_when_ended():
    assert 'V.icon("play"), run.resumable ? "Resume run" : "Restart run"' in APPJS, \
        "the Live view no longer offers Resume/Restart on an ended run"
    # only shown once the run has ended
    assert 'const ended = !running' in APPJS
    assert '"cancelled"' in APPJS and '"interrupted"' in APPJS


def test_resume_continues_from_memory_via_retry():
    # Resume routes through runRetry → /api/run/<id>/retry → retry_run (which appends --resume for resumable).
    assert "runRetry(run.run_id" in APPJS
    assert "/retry" in SERVER and "actions.retry_run(" in SERVER
    assert "def retry_run(run_id: str)" in ACTIONS
    assert '--resume' in ACTIONS  # retry_run appends it for a resumable run


def test_stop_says_memory_is_kept_and_ended_shows_it():
    # Stopping must not read as "lost": the Stop tooltip says memory is kept, and an ended run shows it.
    assert "memory (the engagement spine) is KEPT" in APPJS
    assert '"memory kept"' in APPJS
