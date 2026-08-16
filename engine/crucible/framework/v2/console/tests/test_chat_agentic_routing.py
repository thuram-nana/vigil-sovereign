"""Chat routes its engagements to the agentic engine, and says so HONESTLY (red-pen F1/F2).

  * `chat_send` passes `agentic` through to the launcher, defaulting True but honouring an explicit
    `agentic: False` opt-out (the UI toggle);
  * the launched reply for the agentic (integration) engine does NOT claim "any target-touching step
    waits for approval" (it auto-runs low-tier recon) — it says low-tier recon runs automatically and
    higher-tier/exploit/destructive steps wait for a signed approval, and names it an agentic run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat


CHAT = "route-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _capture_launch(monkeypatch, *, engine="integration"):
    seen = {}

    def _fake(body):
        seen["body"] = body
        return {"run_id": "r1", "slug": "loopback", "stream": "progress", "engine": engine}

    monkeypatch.setattr(actions_mod, "launch_assessment", _fake)
    return seen


def test_chat_defaults_to_the_agentic_engine(monkeypatch):
    seen = _capture_launch(monkeypatch)
    chat.chat_send({"chat_id": CHAT, "message": "test http://127.0.0.1:8080/", "mode": "url",
                    "target": "http://127.0.0.1:8080/"})
    assert seen["body"]["agentic"] is True


def test_chat_honours_the_agentic_opt_out(monkeypatch):
    seen = _capture_launch(monkeypatch)
    chat.chat_send({"chat_id": CHAT, "message": "test http://127.0.0.1:8080/", "mode": "url",
                    "target": "http://127.0.0.1:8080/", "agentic": False})
    assert seen["body"]["agentic"] is False


def test_agentic_launch_reply_is_honest_about_approval(monkeypatch):
    _capture_launch(monkeypatch, engine="integration")
    out = chat.chat_send({"chat_id": CHAT, "message": "test http://127.0.0.1:8080/", "mode": "url",
                          "target": "http://127.0.0.1:8080/"})
    assert out["status"] == "running" and out["engine"] == "integration"
    reply = out["reply"]
    assert "any target-touching step waits" not in reply, "overclaim (low-tier recon auto-runs)"
    assert "low-tier recon runs automatically" in reply
    assert "higher-tier" in reply and "approval" in reply
    assert "agentic" in reply.lower()


def test_scan_launch_reply_does_not_overclaim(monkeypatch):
    _capture_launch(monkeypatch, engine="")   # the lighter scan/offense path
    out = chat.chat_send({"chat_id": CHAT, "message": "test http://127.0.0.1:8080/", "mode": "url",
                          "target": "http://127.0.0.1:8080/"})
    assert "any target-touching step waits" not in out["reply"]
    assert "oracle-confirmed" in out["reply"]
