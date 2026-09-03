"""S2 — an agent question in chat can be answered by clicking a suggested option OR typing your own ("Other").
Guards the full wiring: the backend carries `question_options` from the model through the engine event and the
supervisor into the chat bubble record; the frontend renders click-to-pick buttons (+ Other) on the PENDING
question and in the pinned banner, and a pick sends via the SAME reply path (no new endpoint, no relaxed gate).

Reads files only (docs-only CI job). Behaviour is verified by integration/tests/test_ask_user_options.py
(both legs) + a headless jsdom harness for answerOptions.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
STATE = (REPO / "integration" / "vigil_integration" / "agent" / "state.py").read_text(encoding="utf-8")
REACT = (REPO / "integration" / "vigil_integration" / "agent" / "react.py").read_text(encoding="utf-8")
ENGINE = (REPO / "integration" / "vigil_integration" / "live" / "engine.py").read_text(encoding="utf-8")
ACTIONS = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "actions.py").read_text(encoding="utf-8")
CHAT = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "chat.py").read_text(encoding="utf-8")


def test_backend_carries_question_options_end_to_end():
    assert "question_options: list[str] = Field(default_factory=list)" in STATE, "decision field gone"
    assert 'obj.get("options")' in REACT and '"question_options": obj.get("options")' in REACT, "options→field map gone"
    assert '"agent_question_options"' in ENGINE, "engine event no longer carries the options"
    assert 'dec.get("agent_question_options")' in ACTIONS, "supervisor no longer extracts the options"
    assert "options: \"list | None\" = None" in CHAT and 'rec["options"] = opts' in CHAT, "post_agent_question drops options"


def test_prompt_documents_the_options():
    THINK = (REPO / "integration" / "vigil_integration" / "live" / "think_claude.py").read_text(encoding="utf-8")
    assert '"options": [str, ...]' in THINK, "the ask_user prompt no longer documents options"


def test_frontend_renders_click_to_pick_plus_other():
    assert "function answerOptions(opts)" in APPJS
    assert 'input.value = String(opt); doSend();' in APPJS, "an option must fill + send via the reply path"
    assert '"Other…"' in APPJS, "the free-text escape hatch is gone"
    # rendered on the PENDING question bubble and in the banner
    assert "isPendingQ && Array.isArray(m.options)" in APPJS
    assert "answerOptions(_pendingQ.options)" in APPJS
