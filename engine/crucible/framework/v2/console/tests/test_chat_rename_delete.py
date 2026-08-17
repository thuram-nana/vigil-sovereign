"""Chat management — rename + delete.

rename appends an append-only ``meta`` title record (the LATEST wins; the transcript is never rewritten;
the turn count is not inflated; a meta record is never returned as a transcript turn). delete removes the
transcript, its staged attachments (``<live>/chats/<id>.attachments/``), and the registry entry —
idempotently, and path-safely (an unsafe id is a clean ValueError → the server maps it to 404).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat

CHAT = "rd-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _seed(cid: str = CHAT) -> None:
    chat._append(cid, {"role": "user", "text": "scan http://127.0.0.1:8080 for me"})
    chat._append(cid, {"role": "assistant", "text": "sure"})


def _row(cid: str = CHAT):
    return next((r for r in chat.list_sessions()["sessions"] if r["id"] == cid), None)


def test_default_title_is_first_user_line():
    _seed()
    row = _row()
    assert row and row["title"].startswith("scan http://127.0.0.1:8080")
    assert row["turns"] == 2


def test_rename_sets_custom_title_latest_wins_not_a_turn():
    _seed()
    chat.rename_session(CHAT, "Auth review")
    chat.rename_session(CHAT, "Auth review v2")          # latest meta wins over the earlier one
    row = _row()
    assert row["title"] == "Auth review v2"
    assert row["turns"] == 2                              # rename did NOT inflate the turn count
    sess = chat.get_session(CHAT)
    assert sess["title"] == "Auth review v2"
    assert all(m.get("kind") != "meta" for m in sess["messages"])   # meta is not a transcript turn
    assert len(sess["messages"]) == 2


def test_rename_via_body_wrapper_strips():
    _seed()
    out = chat.rename({"chat_id": CHAT, "title": "  Renamed  "})
    assert out["ok"] and out["title"] == "Renamed"


def test_rename_refuses_unknown_chat_and_empty_title():
    with pytest.raises(ValueError):
        chat.rename_session("no-such-chat", "x")         # no transcript → refuse (not a create)
    _seed()
    with pytest.raises(ValueError):
        chat.rename_session(CHAT, "   ")                 # empty title → refuse


def test_rename_title_is_capped():
    _seed()
    out = chat.rename_session(CHAT, "z" * 500)
    assert len(out["title"]) == chat._MAX_TITLE


def test_delete_removes_transcript_attachments_and_is_idempotent():
    _seed()
    p = chat._chat_path(CHAT)
    att = chat._chats_dir() / (CHAT + ".attachments")
    (att / "a1").mkdir(parents=True, exist_ok=True)
    (att / "a1" / "f.txt").write_text("x", encoding="utf-8")
    assert p.exists() and att.is_dir()
    out = chat.delete_session(CHAT)
    assert out["ok"] and out["deleted"] is True
    assert not p.exists() and not att.exists()
    assert _row() is None                                 # gone from the listing
    out2 = chat.delete({"chat_id": CHAT})                 # idempotent: deleting an absent chat is a clean ok
    assert out2["ok"] and out2["deleted"] is False


def test_management_refuses_unsafe_ids():
    with pytest.raises(ValueError):
        chat.delete_session("../../etc/passwd")
    with pytest.raises(ValueError):
        chat.rename_session("../evil", "x")
