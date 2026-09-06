"""Wave 8 — a run paused for a SIGNED approval surfaces an awaiting_approval notice in the chat transcript
(not only the floating process box), so the conversation is never silent while it is blocked."""
from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat

CHAT = "aa-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _seed(cid: str = CHAT) -> None:
    chat._append(cid, {"role": "user", "text": "engage http://127.0.0.1:19010/auth/continue?next=x"})


def test_post_engine_notice_appends_an_awaiting_approval_bubble():
    _seed()
    ok = chat.post_engine_notice(CHAT, "I'm paused — my next step (httpx) needs your signed approval.",
                                 run_id="r1", slug="loopback", kind="awaiting_approval")
    assert ok is True
    last = chat.read_session(CHAT)[-1]
    assert last["kind"] == "awaiting_approval"
    assert last["role"] == "assistant" and "approval" in last["text"].lower()
    assert last["run_id"] == "r1" and last["slug"] == "loopback"


def test_post_engine_notice_no_transcript_is_a_no_op():
    # a non-chat engage (session id but no transcript) must never grow one
    assert chat.post_engine_notice("no-such-chat", "x", kind="awaiting_approval") is False


def test_post_engine_notice_empty_text_is_a_no_op():
    _seed()
    assert chat.post_engine_notice(CHAT, "   ", kind="awaiting_approval") is False
