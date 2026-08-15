"""Chat conversation memory — a reopened chat CONTINUES, it does not restart.

The transcript was always stored and displayed, but the model call carried only the current question,
so every turn was stateless: reopening an old chat and asking a follow-up lost the whole thread (and for
a plain text chat, returned the canned ask-for-a-target reply). These tests pin the fix:

  * _history_messages replays this chat's own prior turns as a bounded, strictly-alternating
    {role, content} array, excluding the current turn;
  * _has_prior_conversation is False on a fresh chat's first message (first-touch unchanged) and True
    once there has been an exchange (so a follow-up reasons instead of hitting the canned reply);
  * end-to-end, the SDK payload for a follow-up actually carries the earlier turns.
"""
from __future__ import annotations

import sys
import types

import pytest

from framework.v2.console import chat


@pytest.fixture(autouse=True)
def _live(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    return tmp_path


def _seed(chat_id, turns):
    for role, text, kind in turns:
        rec = {"role": role, "text": text}
        if kind:
            rec["kind"] = kind
        chat._append(chat_id, rec)


# --- _prior_records / _history_messages ------------------------------------------------------------
def test_history_excludes_the_current_user_turn():
    _seed("c1", [("user", "first question", None), ("assistant", "first answer", "answer"),
                 ("user", "CURRENT question", None)])   # the trailing user turn is the current one
    hist = chat._history_messages("c1")
    assert [m["role"] for m in hist] == ["user", "assistant"]
    assert hist[0]["content"] == "first question" and hist[1]["content"] == "first answer"
    assert all("CURRENT question" not in m["content"] for m in hist), "the current turn leaked into history"


def test_history_is_empty_for_a_fresh_chats_first_message():
    _seed("c2", [("user", "hello", None)])              # only the current turn exists
    assert chat._history_messages("c2") == []


def test_history_merges_consecutive_same_role_and_starts_with_user():
    # a torn/odd transcript: an assistant notice with no preceding user, then two assistant records
    _seed("c3", [("assistant", "orphan notice", "launched"),
                 ("user", "u1", None), ("assistant", "a1", "answer"), ("assistant", "a1b", "launched"),
                 ("user", "current", None)])
    hist = chat._history_messages("c3")
    assert hist[0]["role"] == "user", "history must start with a user turn"
    # strict alternation
    roles = [m["role"] for m in hist]
    assert all(roles[i] != roles[i + 1] for i in range(len(roles) - 1)), "history must strictly alternate"
    assert "a1" in hist[-1]["content"] and "a1b" in hist[-1]["content"], "consecutive assistant turns merge"


def test_history_excludes_the_current_turn_even_with_a_later_record():
    """The current-turn exclusion is the ONLY guard against leaking+duplicating the current question when
    a record lands AFTER it (a late/concurrent assistant write). Without it, the current question appears
    both in history and as the appended final turn. (Red-pen BLOCK-1: this guard was unpinned.)"""
    _seed("c-excl", [("user", "first question", None), ("assistant", "first answer", "answer"),
                     ("user", "CURRENT question", None), ("assistant", "a late/racing write", "answer")])
    hist = chat._history_messages("c-excl")
    assert [m["role"] for m in hist] == ["user", "assistant"]
    assert hist[0]["content"] == "first question"
    assert all("CURRENT question" not in m["content"] for m in hist), "the current question leaked into history"


def test_orphan_user_history_does_not_break_alternation_with_the_current_turn():
    """A torn write can leave a prior user turn with no assistant reply: [user OLD, user CURRENT]. The
    trailing-user pop must ensure history does not END with a user, or appending the current user turn
    yields two consecutive users — which the SDK rejects. (Red-pen BLOCK-1: this guard was unpinned.)"""
    _seed("c-orphan", [("user", "OLD unanswered", None), ("user", "CURRENT question", None)])
    hist = chat._history_messages("c-orphan")
    assert not (hist and hist[-1]["role"] == "user"), \
        "history ended with a user turn — appending the current turn would break alternation"


def test_history_is_budget_bounded():
    big = "X" * 5000
    turns = []
    for i in range(40):
        turns.append(("user", f"u{i} " + big, None))
        turns.append(("assistant", f"a{i} " + big, "answer"))
    turns.append(("user", "current", None))
    _seed("c4", turns)
    hist = chat._history_messages("c4")
    total = sum(len(m["content"]) for m in hist)
    assert total <= chat._HISTORY_TOTAL_CHARS + chat._HISTORY_TURN_CHARS, "history exceeded its budget"
    assert hist[0]["role"] == "user" and hist[-1]["role"] == "assistant"
    # the OLDEST turns are dropped, the most RECENT kept
    assert "u0 " not in hist[0]["content"], "the oldest turn should have been dropped"


# --- _has_prior_conversation -----------------------------------------------------------------------
def test_no_prior_conversation_on_first_message():
    _seed("c5", [("user", "hi", None)])
    assert chat._has_prior_conversation("c5") is False


def test_prior_conversation_after_one_exchange():
    _seed("c6", [("user", "hi", None), ("assistant", "Tell me what to test…", "need_target"),
                 ("user", "current", None)])
    assert chat._has_prior_conversation("c6") is True


# --- end to end: the follow-up reasons, and the payload carries the earlier turns -------------------
def _install_fake_anthropic(monkeypatch):
    """A fake anthropic SDK that records the messages array it is called with and returns a usable reply."""
    captured = {}

    class _Block:
        type = "text"
        def __init__(self, text): self.text = text

    class _Resp:
        stop_reason = "end_turn"
        usage = None
        def __init__(self, text): self.content = [_Block(text)]

    class _Messages:
        def create(self, **kw):
            captured["messages"] = kw.get("messages")
            return _Resp("ANSWER-IN-CONTEXT")

    class _Anthropic:
        def __init__(self, **kw): pass
        messages = _Messages()

    mod = types.ModuleType("anthropic")
    mod.Anthropic = _Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    return captured


def test_followup_carries_prior_turns_into_the_model_call(monkeypatch):
    captured = _install_fake_anthropic(monkeypatch)
    _seed("c7", [("user", "MARKER_ONE the login uses md5", None),
                 ("assistant", "MARKER_TWO that is a weak hash", "answer"),
                 ("user", "MARKER_THREE what should I use instead", None)])
    out = chat._reason("c7", "MARKER_THREE what should I use instead")
    assert out["ok"] and out["reply"] == "ANSWER-IN-CONTEXT"
    msgs = captured["messages"]
    # prior turns are present AND the current turn is the final user message
    roles = [m["role"] for m in msgs]
    assert roles[0] == "user" and roles[-1] == "user"
    assert all(roles[i] != roles[i + 1] for i in range(len(roles) - 1)), "the SDK array must alternate"
    flat = "\n".join(str(m["content"]) if isinstance(m["content"], str)
                     else str(m["content"]) for m in msgs)
    assert "MARKER_ONE" in flat and "MARKER_TWO" in flat, "prior turns were not sent to the model"
    assert "MARKER_THREE" in flat, "the current question was not sent"


def test_a_keyless_followup_keeps_the_helpful_reply_not_a_false_key_nag(monkeypatch):
    """With NO key, a conversational follow-up must NOT route into _reason — otherwise the operator gets
    the attachment-specific "add a key and I can read what you attached" notice for a turn that attached
    nothing. It should keep the helpful ask-for-a-target reply. (Red-pen BLOCK-2.)"""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    first = chat.chat_send({"message": "hey there"})
    assert first["status"] == "need_target"
    second = chat.chat_send({"message": "hi again, what can you do?", "chat_id": first["chat_id"]})
    assert second["status"] == "need_target", "a keyless follow-up regressed into a key nag"
    assert "attached" not in second["reply"].lower(), "claimed an attachment that does not exist"


def test_a_followup_on_a_talked_to_chat_reasons_instead_of_the_canned_reply(monkeypatch):
    captured = _install_fake_anthropic(monkeypatch)
    # first turn: a fresh chat with no target → the canned need_target reply, no reasoning
    first = chat.chat_send({"message": "hey there"})
    assert first["status"] == "need_target"
    assert "messages" not in captured, "a fresh chat's first message must not reason"
    # second turn on the SAME chat, still no target → now it CONTINUES the conversation
    second = chat.chat_send({"message": "so what can you actually do?", "chat_id": first["chat_id"]})
    assert second["status"] == "answer" and second["reply"].startswith("ANSWER-IN-CONTEXT")
    assert captured.get("messages"), "a follow-up on a talked-to chat must reason with history"
