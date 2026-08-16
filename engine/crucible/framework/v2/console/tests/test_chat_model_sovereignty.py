"""E3 — per-session model sovereignty. The chat's reasoning model is the operator's choice, and that choice
is a SOVEREIGNTY control: a LOCAL model means an uploaded codebase never leaves the machine. These tests pin:

  * ``chat_models()`` surfaces each model's trust class, whether the current tier permits it (and why not),
    and the plain-language consequence; the default is Opus 5;
  * under AIR_GAPPED a local model is permitted and a cloud model is refused WITH A REASON (told up front,
    not at send time);
  * a CLOUD choice uses the CHOSEN model string (Sonnet), not a hardcoded one;
  * a LOCAL choice routes through the kernel provider layer, needs NO API key, and — the crux — a local
    that cannot be reached (or whose call fails) REFUSES with NO cloud fallback: the direct-SDK path is
    never invoked, so nothing egresses.

No network call is ever made.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat

CHAT = "model-sov-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    # start from a known tier; individual tests override
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_SEALED", raising=False)
    yield tmp_path


# ── the cloud SDK fake — records create() kwargs (incl. the model) and answers with a fixed text ──────────
@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> dict:
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
            self.messages = self

        def create(self, **kw):
            cap["create_kw"] = kw
            return _Resp("A cloud lead.")

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    return cap


# ── a fake kernel provider layer — _reason_local routes HERE, never to the SDK ────────────────────────────
def _fake_llm(monkeypatch, *, available=True, reply="LOCAL ANSWER", raise_on_complete=False):
    seen = {"complete_called": False, "force": None, "prompt": None}
    import framework.v2.kernel.llm as llm_mod

    class _Parsed:
        def __init__(self, r):
            self.reply = r

    class _Result:
        def __init__(self, r):
            self.parsed = _Parsed(r)
            self.trace = None
            self.raw_response = r

    class _Backend:
        name = "ollama"

        def is_available(self):
            return (available, "" if available else "connection refused")

        def complete(self, prompt):
            seen["complete_called"] = True
            seen["prompt"] = prompt
            if raise_on_complete:
                raise RuntimeError("local model exploded")
            return _Result(reply)

    def _get_backend(force=None, refresh=False):
        seen["force"] = force
        return _Backend()

    monkeypatch.setattr(llm_mod, "get_backend", _get_backend)
    return seen


def _forbid_cloud(monkeypatch) -> dict:
    """Trip a flag if the direct-SDK cloud call is ever reached — a local pick must NEVER touch it."""
    flag = {"called": False}

    def _boom(*a, **k):
        flag["called"] = True
        raise AssertionError("the cloud SDK path was reached on a LOCAL model pick — that is a fallback")

    monkeypatch.setattr(chat, "_chat_call_with_backoff", _boom)
    return flag


# ── chat_models() picker data ─────────────────────────────────────────────────────────────────────────────

def test_chat_models_surfaces_trust_class_and_consequence():
    d = chat.chat_models()
    assert d["default"] == "claude-opus-5"
    by = {m["id"]: m for m in d["models"]}
    assert "claude-opus-5" in by and "ollama" in by
    loc = by["ollama"]
    assert loc["kind"] == "local" and loc["trust_class"] == "local"
    assert "nothing leaves this machine" in loc["consequence"]
    cloud = by["claude-opus-5"]
    assert cloud["kind"] == "cloud" and "third-party" in cloud["consequence"]
    for m in d["models"]:
        assert isinstance(m["permitted"], bool) and m["trust_class"] and "why_not" in m


def test_air_gapped_permits_local_and_refuses_cloud_with_a_reason(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    d = chat.chat_models()
    assert d["tier"] == "AIR_GAPPED"
    by = {m["id"]: m for m in d["models"]}
    assert by["ollama"]["permitted"] is True and by["ollama"]["why_not"] == ""
    assert by["claude-opus-5"]["permitted"] is False and by["claude-opus-5"]["why_not"]
    assert by["claude-sonnet-5"]["permitted"] is False


# ── cloud choice uses the CHOSEN model ────────────────────────────────────────────────────────────────────

def test_cloud_choice_uses_the_chosen_model(captured):
    # attachments make this a reasoning turn; the create() call must carry the chosen model string
    out = chat._reason(CHAT, "any weakness?", model="claude-sonnet-5")
    assert out["ok"] is True
    assert captured["create_kw"]["model"] == "claude-sonnet-5"


def test_blank_model_defaults_to_opus5(captured):
    out = chat._reason(CHAT, "hi", model="")
    assert out["ok"] is True and captured["create_kw"]["model"] == "claude-opus-5"


def test_unknown_model_degrades_to_the_default_cloud(captured):
    out = chat._reason(CHAT, "hi", model="totally-made-up-9000")
    assert out["ok"] is True and captured["create_kw"]["model"] == "claude-opus-5"


# ── local choice routes through the provider layer, keyless, NO cloud fallback ────────────────────────────

def test_local_choice_routes_to_provider_layer_no_key_needed(monkeypatch):
    seen = _fake_llm(monkeypatch, available=True, reply="LOCAL ANSWER about the code")
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)   # a local pick must NOT need a cloud key
    out = chat._reason(CHAT, "review the auth", model="ollama")
    assert out["ok"] is True and "LOCAL ANSWER" in out["reply"]
    assert seen["complete_called"] is True and seen["force"] == "ollama"
    assert cloud["called"] is False
    # the honesty note about local's limits + no egress rides the answer
    assert any("nothing left this machine" in n for n in out.get("notes", []))


def test_local_unreachable_refuses_with_no_cloud_fallback(monkeypatch):
    """THE sovereignty guarantee: a local model that cannot be reached REFUSES. It never falls back to a
    cloud model, so nothing egresses — even with a cloud key sitting right there."""
    seen = _fake_llm(monkeypatch, available=False)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")  # a key is present; it must STILL not be used
    out = chat._reason(CHAT, "review the auth", model="ollama")
    assert out["ok"] is False
    assert "cloud" in out["error"].lower() and "reach" in out["error"].lower()
    assert seen["complete_called"] is False        # never even attempted the call
    assert cloud["called"] is False                # and never touched the cloud SDK


def test_local_call_failure_refuses_with_no_cloud_fallback(monkeypatch):
    """A local model that is reachable but whose CALL fails also refuses with no fallback."""
    seen = _fake_llm(monkeypatch, available=True, raise_on_complete=True)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    out = chat._reason(CHAT, "review the auth", model="self-hosted")
    assert out["ok"] is False and "no cloud fallback" in out["error"].lower()
    assert seen["complete_called"] is True and cloud["called"] is False
