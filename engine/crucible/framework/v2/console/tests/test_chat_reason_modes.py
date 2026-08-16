"""Chat reasoning modes (Phase B-reason) — Ask / Research / Plan. The reply is a LEAD in every mode;
the mode changes HOW hard the model reasons, not what counts as truth. "ask" is byte-identical to the
prior single-shot call. "research" and "plan" turn on extended (adaptive) thinking and steer the system
prompt. These tests capture the exact ``messages.create`` kwargs from a fake client and pin:
  * ask → no ``thinking`` kwarg, system prompt unchanged;
  * research/plan → ``thinking={"type":"adaptive"}`` and the mode's system-prompt steer present;
  * an unknown mode falls back to ask;
  * ``_reason_wanted`` fires when a Research/Plan mode is selected.
No network call is ever made.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat


CHAT = "mode-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> dict:
    """A fake anthropic client that records the create() kwargs and answers with a fixed text."""
    cap: dict = {}
    mod = types.ModuleType("anthropic")

    class _Block:
        type = "text"

        def __init__(self, text):
            self.text = text

    class _Resp:
        stop_reason = "end_turn"

        def __init__(self, text):
            self.content = [_Block(text)]

    class _Client:
        def __init__(self, api_key=None, **kw):
            cap["client_kw"] = kw
            self.messages = self

        def create(self, **kw):
            cap["create_kw"] = kw
            return _Resp("A lead about the attached material.")

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    return cap


def test_ask_mode_is_unchanged_no_thinking(captured):
    out = chat._reason(CHAT, "any weakness?", reason_mode="ask")
    assert out["ok"] is True
    kw = captured["create_kw"]
    assert "thinking" not in kw, "ask mode must not enable thinking"
    assert kw["system"] == chat._CHAT_SYSTEM, "ask mode must use the base system prompt verbatim"


def test_research_mode_enables_adaptive_thinking_and_steers_the_prompt(captured):
    out = chat._reason(CHAT, "audit the auth", reason_mode="research")
    assert out["ok"] is True
    kw = captured["create_kw"]
    assert kw.get("thinking") == {"type": "adaptive"}
    assert chat._CHAT_SYSTEM in kw["system"] and "RESEARCH MODE" in kw["system"]
    # a generous client timeout is set for a (longer) thinking call
    assert captured["client_kw"].get("timeout")


def test_plan_mode_enables_thinking_and_asks_for_a_plan(captured):
    out = chat._reason(CHAT, "how would we confirm the IDOR?", reason_mode="plan")
    assert out["ok"] is True
    kw = captured["create_kw"]
    assert kw.get("thinking") == {"type": "adaptive"}
    assert "PLAN MODE" in kw["system"]


def test_unknown_mode_falls_back_to_ask(captured):
    chat._reason(CHAT, "q", reason_mode="ultrathink-9000")
    assert "thinking" not in captured["create_kw"]
    assert captured["create_kw"]["system"] == chat._CHAT_SYSTEM


def test_resolve_reason_mode():
    assert chat._resolve_reason_mode("research") == "research"
    assert chat._resolve_reason_mode("PLAN") == "plan"
    assert chat._resolve_reason_mode("nonsense") == "ask"
    assert chat._resolve_reason_mode(None) == "ask"


def test_reason_wanted_fires_for_research_and_plan(monkeypatch):
    # a Research/Plan selection is an explicit ask to reason, even with nothing attached
    assert chat._reason_wanted(CHAT, {"reason_mode": "research"}) is True
    assert chat._reason_wanted(CHAT, {"reason_mode": "plan"}) is True
    # ask (or absent) keeps the prior behaviour: a fresh, unattached, unconnected chat does not reason
    monkeypatch.setattr(chat, "_manifests", lambda cid: [])
    assert chat._reason_wanted(CHAT, {"reason_mode": "ask"}) is False
    assert chat._reason_wanted(CHAT, {}) is False
