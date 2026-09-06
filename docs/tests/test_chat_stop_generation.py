"""S4 — the streaming chat reply can be STOPPED (a Stop button + Esc), like Claude Code. An AbortController
aborts the fetch; a deliberate Stop is distinguished from a dropped connection so the turn is never re-sent.

Reads files only (docs-only CI job). The signal-forwarding is verified against the real sliced streamChat in a
headless jsdom harness.
"""
from __future__ import annotations
from pathlib import Path

APPJS = (Path(__file__).resolve().parents[2] / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_abortcontroller_and_signal_wired():
    assert "new AbortController()" in APPJS
    assert "if (signal) opts.signal = signal;" in APPJS, "the stream fetch must accept the abort signal"


def test_stop_button_and_escape():
    assert '"Stop generating (Esc)"' in APPJS, "the streaming bubble needs a Stop button"
    assert 'e.key === "Escape" && C.stream && C.stream.stop' in APPJS, "Esc must stop the stream"


def test_deliberate_stop_never_resends():
    # a Stop sets `aborted`; the catch path must NOT re-POST the turn (no duplicate/second billable call)
    assert "if (aborted) { V.toast(\"Stopped.\", false); return finishSend(); }" in APPJS
