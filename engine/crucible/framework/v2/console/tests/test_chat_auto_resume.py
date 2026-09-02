"""Auto-resume-on-reply (the ask_user → answer → resume loop).

The load-bearing properties:
  * ``paused_engage_run`` detects ONLY a chat session's most-recent integration engage run that is
    TERMINAL and whose last OODA decision was ``ask_user`` — never a completed run, never a running run,
    never a non-integration run (fail-closed against a false resume).
  * ``chat.post_agent_question`` surfaces the agent's question as a chat bubble, but ONLY for a real chat
    session (a transcript already on disk) — it never materialises a transcript for an engage launched
    outside chat.
  * ``resume_engage_with_message`` enqueues the reply on the slug's queue AND resumes the run; with no
    paused engagement it reports ``none`` so the caller answers the turn as a normal question; a queue
    failure aborts the resume (never resume into the same unanswered ask_user).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.console import actions
from framework.v2.console import chat
from framework.v2.console import sessions


@pytest.fixture(autouse=True)
def _hermetic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    yield tmp_path


def _seed_run(run_id: str, *, engine: str, status: str, slug: str, last_choice: str,
              agent_question: str = "") -> None:
    """Write a run's meta.json + a progress.jsonl whose last decision is ``last_choice``."""
    rd = actions.run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps(
        {"engine": engine, "status": status, "slug": slug, "session_id": "sess-A"}), encoding="utf-8")
    lines = [
        {"kind": "observation", "payload": {"summary": "crawled the surface"}},
        {"kind": "decision", "payload": {"question": "generic", "choice": "plan_tools", "rationale": "r"}},
        {"kind": "decision", "payload": {"question": "generic", "choice": last_choice,
                                         "rationale": "r2", "agent_question": agent_question}},
    ]
    (rd / "progress.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")


def test_paused_run_at_ask_user_is_detected():
    sessions.link_run("sess-A", "r1", slug="meridian")
    _seed_run("r1", engine="integration", status="done", slug="meridian", last_choice="ask_user",
              agent_question="Which login endpoint should I focus on?")
    got = actions.paused_engage_run("sess-A")
    assert got == {"run_id": "r1", "slug": "meridian"}


def test_completed_run_is_not_a_resume():
    sessions.link_run("sess-A", "r1", slug="meridian")
    _seed_run("r1", engine="integration", status="done", slug="meridian", last_choice="use_tool")
    assert actions.paused_engage_run("sess-A") is None


def test_running_run_is_never_resumed():
    sessions.link_run("sess-A", "r1", slug="meridian")
    _seed_run("r1", engine="integration", status="running", slug="meridian", last_choice="ask_user")
    assert actions.paused_engage_run("sess-A") is None      # a live run steers via engage_instruct


def test_non_integration_newest_is_skipped_to_older_paused_engage():
    sessions.link_run("sess-A", "r0", slug="meridian")      # older integration engage, paused
    sessions.link_run("sess-A", "r1", slug="meridian")      # newest is a plain scan
    _seed_run("r0", engine="integration", status="done", slug="meridian", last_choice="ask_user")
    _seed_run("r1", engine="", status="done", slug="meridian", last_choice="")
    assert actions.paused_engage_run("sess-A") == {"run_id": "r0", "slug": "meridian"}


def test_post_agent_question_only_writes_for_a_real_chat():
    # no transcript yet → refuses to materialise one
    assert chat.post_agent_question("chat-Z", "Which endpoint?", run_id="r1", slug="meridian") is False
    # create a real chat transcript, then it appends the question bubble
    chat._append("chat-Z", {"role": "user", "text": "scan 127.0.0.1"})
    assert chat.post_agent_question("chat-Z", "Which endpoint?", run_id="r1", slug="meridian") is True
    rec = chat.read_session("chat-Z")[-1]
    assert rec["role"] == "assistant" and rec["kind"] == "agent_question"
    assert rec["text"] == "Which endpoint?" and rec["run_id"] == "r1" and rec["slug"] == "meridian"


def test_post_agent_question_refuses_empty():
    chat._append("chat-Y", {"role": "user", "text": "hi"})
    assert chat.post_agent_question("chat-Y", "   ", run_id="r1") is False


def test_resume_with_no_paused_run_reports_none():
    out = actions.resume_engage_with_message("sess-empty", "my answer")
    assert out == {"ok": False, "none": True}


def test_resume_enqueues_then_resumes(monkeypatch):
    sessions.link_run("sess-A", "r1", slug="meridian")
    _seed_run("r1", engine="integration", status="done", slug="meridian", last_choice="ask_user")
    calls = {}

    def _enq(slug, text):
        calls["enq"] = (slug, text)
        return {"ok": True, "seq": 1}

    def _retry(rid):
        calls["retry"] = rid
        return {"ok": True, "run_id": "r2", "resumed": True}

    monkeypatch.setattr(actions, "engage_instruct", _enq)
    monkeypatch.setattr(actions, "retry_run", _retry)
    out = actions.resume_engage_with_message("sess-A", "focus on /login")
    assert out["ok"] is True and out["run_id"] == "r2" and out["slug"] == "meridian"
    assert calls["enq"] == ("meridian", "focus on /login")     # answer enqueued on the slug's queue
    assert calls["retry"] == "r1"                              # the paused run was resumed
    # the resumed run is re-linked to the session so a reload follows it
    assert "r2" in sessions.get_session("sess-A")["session"]["run_ids"]


def test_resume_aborts_when_the_queue_fails(monkeypatch):
    sessions.link_run("sess-A", "r1", slug="meridian")
    _seed_run("r1", engine="integration", status="done", slug="meridian", last_choice="ask_user")
    retried = {"n": 0}
    monkeypatch.setattr(actions, "engage_instruct", lambda slug, text: {"ok": False, "error": "queue down"})
    monkeypatch.setattr(actions, "retry_run", lambda rid: retried.__setitem__("n", retried["n"] + 1) or {"ok": True})
    out = actions.resume_engage_with_message("sess-A", "focus on /login")
    assert out["ok"] is False and "answer" in out["error"]
    assert retried["n"] == 0, "must NOT resume a run whose answer was not enqueued (would re-hit ask_user)"
