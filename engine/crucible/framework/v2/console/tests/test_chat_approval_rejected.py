"""ENH1 — a run that paused because a FOUND approval was REJECTED (expired / already used) surfaces a
DISTINCT 'approval_rejected' notice in the chat transcript, telling the operator to APPROVE AGAIN — not the
generic 'awaiting_approval' that reads as an invisible loop.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat

CHAT = "ar-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _seed(cid: str = CHAT) -> None:
    chat._append(cid, {"role": "user", "text": "engage http://127.0.0.1:19010/auth/continue?next=x"})


def test_post_engine_notice_appends_an_approval_rejected_bubble():
    _seed()
    ok = chat.post_engine_notice(CHAT, "I'm paused — my last approval expired or was already used.",
                                 run_id="r1", slug="loopback-abc", kind="approval_rejected")
    assert ok is True
    last = chat.read_session(CHAT)[-1]
    assert last["kind"] == "approval_rejected"
    assert last["role"] == "assistant" and "approval" in last["text"].lower()
    assert last["run_id"] == "r1" and last["slug"] == "loopback-abc"


def test_maybe_surface_posts_approval_rejected_distinct_from_awaiting(monkeypatch):
    _seed()
    meta = {"engine": "integration", "session_id": CHAT, "slug": "loopback-abc"}
    monkeypatch.setattr(actions_mod, "_last_decision", lambda rid: {"choice": "use_tool", "tool": "httpx"})

    # (approval_rejected) → a distinct kind + "expired or was already used" copy.
    monkeypatch.setattr(actions_mod, "_run_outcome", lambda rid: {"paused": "approval_rejected"})
    actions_mod._maybe_surface_agent_question("run-ar", meta)
    last = chat.read_session(CHAT)[-1]
    assert last["kind"] == "approval_rejected"
    assert "expired or was already used" in last["text"].lower()

    # NEGATIVE CONTROL: a plain awaiting_approval pause still posts the awaiting kind (not rejected).
    monkeypatch.setattr(actions_mod, "_run_outcome", lambda rid: {"paused": "awaiting_approval"})
    actions_mod._maybe_surface_agent_question("run-aw", meta)
    last = chat.read_session(CHAT)[-1]
    assert last["kind"] == "awaiting_approval"
    assert "expired or was already used" not in last["text"].lower()
