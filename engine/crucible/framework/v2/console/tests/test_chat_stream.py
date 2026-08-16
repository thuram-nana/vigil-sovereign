"""F1 — streamed chat replies. A pure QUESTION turn streams the cloud model's tokens through `emit`, then
persists the SAME record chat_send would (shared `_finish_question_turn`). A launch/clone/need-target turn
is NOT streamable: chat_stream returns {"stream": False, "fallback": True} WITHOUT appending, so the caller
re-POSTs to /api/chat/send. The security gate is SHARED with the blocking path, so a stream cannot bypass
the sovereignty ladder. No network call is ever made.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat

CHAT = "stream-chat"


@pytest.fixture(autouse=True)
def _iso(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    yield tmp_path


# ── a fake anthropic client whose messages.stream() yields text deltas ────────────────────────────────────
@pytest.fixture()
def streamed(monkeypatch: pytest.MonkeyPatch):
    cap: dict = {"kwargs": None}
    mod = types.ModuleType("anthropic")

    class _Final:
        stop_reason = "end_turn"
        usage = None
        content: list = []

    class _Stream:
        def __init__(self, deltas):
            self._deltas = deltas

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        @property
        def text_stream(self):
            return iter(self._deltas)

        def get_final_message(self):
            return _Final()

    class _Block:
        type = "text"

        def __init__(self, text):
            self.text = text

    class _Resp:
        stop_reason = "end_turn"
        usage = None

        def __init__(self, text):
            self.content = [_Block(text)]

    class _Messages:
        def stream(self, **kw):
            cap["kwargs"] = kw
            return _Stream(["Two ", "leads ", "here."])

        def create(self, **kw):                 # the BLOCKING path — same text, so records must match
            cap["create_kwargs"] = kw
            return _Resp("Two leads here.")

    class _Client:
        def __init__(self, api_key=None, **kw):
            self.messages = _Messages()

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    return cap


def _events():
    evs: list = []
    return evs, (lambda ev: evs.append(ev))


def _reason_wanted(monkeypatch, wanted=True):
    # force the "there is something to reason over" decision without needing real attachments
    monkeypatch.setattr(chat, "_reason_wanted", lambda cid, body: wanted)


# ── fallback: a non-question turn is not streamed (no append, caller uses /send) ───────────────────────────

def test_launch_turn_falls_back_without_appending(monkeypatch):
    evs, emit = _events()
    out = chat.chat_stream({"chat_id": CHAT, "message": "assess it", "target": "http://127.0.0.1:8080"}, emit)
    assert out.get("stream") is False and out.get("fallback") is True
    assert evs == []                                        # nothing streamed
    assert chat.read_session(CHAT) == []                   # and NOTHING appended (no double-record on re-POST)


def test_a_url_or_clone_in_the_message_falls_back(monkeypatch):
    # a URL or a git repo in the message is a LAUNCH intent detected BEFORE the append → fallback to /send,
    # nothing streamed, nothing recorded. (A bare filesystem path is intentionally NOT grabbed from prose by
    # `_path_in_message`, so it is a question turn, covered by the need-target test above.)
    _reason_wanted(monkeypatch, wanted=True)   # isolate launch-intent: even "wanted", a launch must fall back
    for i, msg in enumerate(("scan http://127.0.0.1:8080 for xss", "clone https://github.com/org/repo")):
        evs, emit = _events()
        cid = "cu-%d" % i
        out = chat.chat_stream({"chat_id": cid, "message": msg}, emit)
        assert out.get("fallback") is True, msg
        assert evs == [] and chat.read_session(cid) == []


def test_nothing_to_reason_over_answers_need_target_in_place(monkeypatch):
    # G4: a turn with nothing to reason over is handled IN chat_stream (append the user msg + the
    # ask-for-a-target reply), NOT bounced to /send — because chat_stream now appends BEFORE the
    # reason-wanted check (so `_has_prior_conversation` sees the true prior history and the first
    # conversational follow-up streams). No /send fallback here means no double-record.
    _reason_wanted(monkeypatch, wanted=False)
    evs, emit = _events()
    out = chat.chat_stream({"chat_id": CHAT, "message": "hello"}, emit)
    assert out.get("status") == "need_target" and not out.get("fallback")
    # the user message is recorded EXACTLY once (the whole point of G4 — no double-append), plus the
    # need_target reply
    recs = chat.read_session(CHAT)
    assert len([r for r in recs if r.get("role") == "user" and r.get("text") == "hello"]) == 1
    assert len([r for r in recs if r.get("kind") == "need_target"]) == 1
    assert len([e for e in evs if e.get("event") == "done"]) == 1


def test_launch_intent_still_falls_back_without_appending(monkeypatch):
    # the launch/clone/url/path/mode fallbacks stay BEFORE the append, so /send (which appends) never
    # double-records — G4 must not regress this.
    _reason_wanted(monkeypatch, wanted=True)
    for i, body in enumerate(({"message": "assess", "target": "http://127.0.0.1:8080"},
                              {"message": "clone https://github.com/org/repo"},
                              {"message": "look", "mode": "url"})):
        evs, emit = _events()
        body["chat_id"] = "cx-%d" % i                          # unique per case (no id collision)
        out = chat.chat_stream(body, emit)
        assert out.get("fallback") is True and evs == []
        assert chat.read_session(body["chat_id"]) == []      # nothing appended before a fallback


# ── streaming: a question turn streams tokens + a done event, and persists the record ──────────────────────

def test_question_turn_streams_tokens_then_a_done_event(streamed, monkeypatch):
    _reason_wanted(monkeypatch, wanted=True)
    evs, emit = _events()
    out = chat.chat_stream({"chat_id": CHAT, "message": "any weaknesses?"}, emit)
    tokens = [e["text"] for e in evs if e.get("event") == "token"]
    done = [e for e in evs if e.get("event") == "done"]
    assert tokens == ["Two ", "leads ", "here."]           # streamed as they arrived
    assert len(done) == 1
    res = done[0]["result"]
    assert res["status"] == "answer" and res["grounding"] == "lead"
    assert "Two leads here." in res["reply"]
    assert out is not None and out["status"] == "answer"
    # PERSISTED like a /send turn: the transcript carries the user msg + the assistant answer (grounding lead)
    recs = chat.read_session(CHAT)
    assert any(r.get("role") == "user" and r.get("text") == "any weaknesses?" for r in recs)
    ans = [r for r in recs if r.get("role") == "assistant" and r.get("kind") == "answer"]
    assert ans and ans[-1]["grounding"] == "lead" and "Two leads here." in ans[-1]["text"]


def test_stream_uses_the_chosen_cloud_model(streamed, monkeypatch):
    _reason_wanted(monkeypatch, wanted=True)
    evs, emit = _events()
    chat.chat_stream({"chat_id": CHAT, "message": "look", "model": "claude-sonnet-5"}, emit)
    assert streamed["kwargs"]["model"] == "claude-sonnet-5"


# ── the security gate is shared: a cloud pick under a sovereign tier REFUSES, streaming nothing ────────────

def test_air_gapped_cloud_pick_refuses_no_tokens(streamed, monkeypatch):
    _reason_wanted(monkeypatch, wanted=True)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    evs, emit = _events()
    out = chat.chat_stream({"chat_id": CHAT, "message": "look", "model": "claude-opus-5"}, emit)
    assert [e for e in evs if e.get("event") == "token"] == []      # nothing streamed (no egress)
    assert streamed["kwargs"] is None, "messages.stream was called under a forbidden tier — an egress"
    done = [e for e in evs if e.get("event") == "done"]
    assert len(done) == 1
    # the done event carries the honest sovereignty refusal, not an answer
    assert out["status"] in ("unavailable", "need_key") or "tier" in str(out.get("error", "")).lower()


def test_streamed_and_blocking_records_match(streamed, monkeypatch):
    """No drift (red-pen LOW-2): the SAME question answered via chat_stream and via chat_send persists an
    IDENTICAL assistant record — same kind, grounding, and reply text — because both run the shared
    _finish_question_turn over the same model text."""
    _reason_wanted(monkeypatch, wanted=True)
    chat.chat_send({"chat_id": "c-blocking", "message": "any weaknesses?"})
    evs, emit = _events()
    chat.chat_stream({"chat_id": "c-stream", "message": "any weaknesses?"}, emit)

    def _answer(cid):
        recs = [r for r in chat.read_session(cid) if r.get("role") == "assistant" and r.get("kind") == "answer"]
        assert recs, cid
        return recs[-1]

    a_block, a_stream = _answer("c-blocking"), _answer("c-stream")
    assert a_block["grounding"] == a_stream["grounding"] == "lead"
    assert a_block["text"] == a_stream["text"]                       # identical persisted reply


def test_local_pick_answers_non_streamed_through_the_stream_path(monkeypatch):
    """A local model is not a token stream — chat_stream answers it in ONE shot via _reason (→ _reason_local),
    still sovereignty-gated. Here the local backend is unreachable, so it refuses with no egress; the point is
    it flows through chat_stream and emits a single done, never a partial cloud stream."""
    _reason_wanted(monkeypatch, wanted=True)
    import framework.v2.kernel.llm as llm_mod

    class _Backend:
        name = "ollama"; base = "http://localhost:11434"; host = "http://localhost:11434"
        def is_available(self):
            return (False, "connection refused")
        def complete(self, prompt):
            raise AssertionError("must not be called when unavailable")
    monkeypatch.setattr(llm_mod, "get_backend", lambda force=None, refresh=False: _Backend())
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    evs, emit = _events()
    out = chat.chat_stream({"chat_id": CHAT, "message": "review", "model": "ollama"}, emit)
    assert [e for e in evs if e.get("event") == "token"] == []
    assert len([e for e in evs if e.get("event") == "done"]) == 1
    assert out["status"] in ("unavailable", "need_key")
