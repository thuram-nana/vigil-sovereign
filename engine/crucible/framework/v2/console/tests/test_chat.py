"""A4a — the operator chatbot backend: NL front door over the SAME gated launcher + a local transcript.

Proves: a turn persists to .vigil-live/chats/<id>.jsonl (append-only, resumable); a URL in free text is
picked up; a turn with a target routes through actions.launch_assessment (the gated path — never a new
un-gated fire path); a launch refusal is surfaced honestly; sessions list + read round-trip; and an unsafe
chat id is refused (fail-closed → the server maps ValueError to 404).
"""
from __future__ import annotations

import json

import pytest

from framework.v2.console import chat


@pytest.fixture(autouse=True)
def _live(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    return tmp_path


def _stub_launch(monkeypatch, result):
    calls = []
    def _fake(body):
        calls.append(body)
        return result
    monkeypatch.setattr(chat.actions, "launch_assessment", _fake)
    return calls


def test_no_target_asks_for_one_and_does_not_launch(monkeypatch):
    calls = _stub_launch(monkeypatch, {"error": "should not be called"})
    out = chat.chat_send({"message": "please find bugs"})
    assert out["status"] == "need_target" and not calls          # nothing launched
    msgs = chat.read_session(out["chat_id"])
    assert [m["role"] for m in msgs] == ["user", "assistant"]     # both turns persisted
    assert msgs[1]["kind"] == "need_target"


def test_url_in_free_text_is_picked_up_and_routes_through_the_gated_launcher(monkeypatch, tmp_path):
    calls = _stub_launch(monkeypatch, {"run_id": "r1", "slug": "loopback", "stream": "blackboard"})
    out = chat.chat_send({"message": "scan http://127.0.0.1:8080/ for me", "chat_id": "sess1"})
    assert out["status"] == "running" and out["run_id"] == "r1" and out["stream"] == "blackboard"
    assert len(calls) == 1 and calls[0]["mode"] == "url" and calls[0]["target"] == "http://127.0.0.1:8080/"
    assert calls[0]["objective"] == "scan http://127.0.0.1:8080/ for me"       # the message is the objective
    # transcript persisted with the run pointer
    msgs = chat.read_session("sess1")
    assert msgs[-1]["kind"] == "launched" and msgs[-1]["run_id"] == "r1"
    assert (tmp_path / "chats" / "sess1.jsonl").exists()


def test_explicit_target_and_mode_win(monkeypatch):
    calls = _stub_launch(monkeypatch, {"run_id": "r2", "slug": "acme", "stream": "blackboard"})
    chat.chat_send({"message": "test the login", "target": "https://acme.example", "mode": "url",
                    "slug": "acme", "chat_id": "s2"})
    assert calls[0]["target"] == "https://acme.example" and calls[0]["mode"] == "url"


def test_launch_refusal_is_surfaced_not_swallowed(monkeypatch):
    _stub_launch(monkeypatch, {"error": "a remote engage needs a signed charter"})
    out = chat.chat_send({"message": "hit https://evil.example", "chat_id": "s3"})
    assert out["status"] == "refused" and "charter" in out["error"]
    assert chat.read_session("s3")[-1]["kind"] == "refused"


def test_sessions_list_and_read_roundtrip(monkeypatch):
    _stub_launch(monkeypatch, {"run_id": "r", "slug": "x", "stream": "none"})
    chat.chat_send({"message": "first http://127.0.0.1/", "chat_id": "a"})
    chat.chat_send({"message": "second http://127.0.0.1/", "chat_id": "b"})
    ids = {s["id"] for s in chat.list_sessions()["sessions"]}
    assert {"a", "b"} <= ids
    got = chat.get_session("a")
    assert got["chat_id"] == "a" and got["messages"][0]["text"].startswith("first")


def test_unsafe_chat_id_is_refused(monkeypatch):
    _stub_launch(monkeypatch, {})
    for bad in ("../etc/passwd", "a/b", ".hidden"):
        with pytest.raises(ValueError):
            chat.chat_send({"message": "x http://127.0.0.1/", "chat_id": bad})
    with pytest.raises(ValueError):
        chat.get_session("../secrets")


def test_overlong_chat_id_is_a_clean_refusal_not_an_oserror(monkeypatch):
    # red-pen LOW: a character-safe but over-long id must raise ValueError (server → 404), never reach the
    # filesystem and OSError("File name too long") → 500 that discloses the chats-dir path.
    _stub_launch(monkeypatch, {})
    with pytest.raises(ValueError):
        chat.chat_send({"message": "x http://127.0.0.1/", "chat_id": "a" * 260})
    with pytest.raises(ValueError):
        chat.get_session("a" * 260)


def test_transcript_files_are_not_world_readable(monkeypatch, tmp_path):
    import stat
    _stub_launch(monkeypatch, {"run_id": "r", "slug": "x", "stream": "none"})
    chat.chat_send({"message": "one http://127.0.0.1/", "chat_id": "perm"})
    d = tmp_path / "chats"
    f = d / "perm.jsonl"
    assert stat.S_IMODE(d.stat().st_mode) == 0o700       # dir not world/group readable
    assert stat.S_IMODE(f.stat().st_mode) == 0o600       # transcript not world/group readable


def test_transcript_is_append_only_jsonl_and_tolerates_a_torn_line(monkeypatch, tmp_path):
    _stub_launch(monkeypatch, {"run_id": "r", "slug": "x", "stream": "none"})
    chat.chat_send({"message": "one http://127.0.0.1/", "chat_id": "t"})
    p = tmp_path / "chats" / "t.jsonl"
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"role": "user", "text": "torn')          # a crash mid-write leaves a torn line
    msgs = chat.read_session("t")                            # must not raise; torn line skipped
    assert all(isinstance(m, dict) for m in msgs) and msgs[0]["role"] == "user"
    # every good line is valid JSON
    good = [ln for ln in p.read_text().split("\n") if ln.strip()]
    json.loads(good[0])
