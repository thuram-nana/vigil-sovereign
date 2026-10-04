"""M4.1 conformance — the console's cloud/local model calls route through the ONE gateway chokepoint.

Before M4.1 ``chat._reason`` / ``_reason_stream_cloud`` / ``_reason_local`` and ``actions.terminal_propose``
reached the provider SDK (or a local backend) DIRECTLY — no classification, no symmetric redaction, no shared
audit. These tests pin the conformance invariants on the REAL console paths, each with positive + safe-negative
controls:

  * the engine egress adapter redacts a planted secret and records ONE unified audit entry (and the invoke
    runs INSIDE the egress context);
  * each end-to-end path (blocking chat, streaming chat, terminal router) emits a gateway audit record on the
    right path label, proving it actually routed through the chokepoint;
  * a direct bypass of the chokepoint fails closed (the shared fail-closed invariant).
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat
from vigil_core import ai_gateway

CHAT = "egress-chat"
_SECRET = "sk-ant-PLANTED-console-secret-value-xyz987"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    ai_gateway.reset_audit()
    yield tmp_path
    ai_gateway.reset_audit()


def _install_blocking(monkeypatch, cap):
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
            return _Resp("A lead about the attached material.")

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)


# ── the engine egress adapter in isolation: redact + record + run-inside-egress ──────────────────────

def test_egress_via_gateway_redacts_records_and_runs_inside_egress():
    seen = {}

    def _invoke(red):
        seen["in_egress"] = ai_gateway.in_egress()
        actions_mod._gw.assert_in_egress("t")        # a real adapter guards itself; a bypass fails closed
        seen["system"], seen["user"] = red.get("system"), red.get("user")
        return "ok"

    out = actions_mod._egress_via_gateway("be precise", f"use api_key={_SECRET} now",
                                          path="terminal_router", invoke=_invoke)
    assert out == "ok" and seen["in_egress"] is True
    assert _SECRET not in seen["user"] and "<redacted" in seen["user"]   # the secret was masked in flight …
    assert seen["system"] == "be precise"                                # … ordinary text untouched (control)
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "terminal_router" and rec.invoked is True and rec.outcome == "completed"
    assert rec.provider_authoritative is False and rec.provider_in_trust_root is False


def test_egress_via_gateway_refusal_returns_the_sentinel(monkeypatch):
    # SAFE-NEGATIVE control: a sovereignty refusal in the model-route step returns the _GW_REFUSED sentinel
    # (and never runs the invoke), so the caller degrades honestly.
    monkeypatch.setattr(actions_mod, "_gw_assert_permitted",
                        lambda name: (_ for _ in ()).throw(PermissionError("tier AIR_GAPPED refuses")))
    ran = {"n": 0}

    def _invoke(red):
        ran["n"] += 1
        return "should-not-run"

    out = actions_mod._egress_via_gateway("s", "u", path="terminal_router", invoke=_invoke)
    assert out is actions_mod._GW_REFUSED and ran["n"] == 0


# ── end-to-end: each console path emits a gateway record on the right label ──────────────────────────

def test_chat_reason_blocking_routes_through_the_gateway(monkeypatch):
    cap: dict = {}
    _install_blocking(monkeypatch, cap)
    out = chat._reason(CHAT, "any weakness in the attached code?", reason_mode="ask")
    assert out["ok"] is True
    assert cap.get("create_kw"), "the model was never called"
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "chat_reason" and rec.invoked is True and rec.outcome == "completed"


def test_terminal_propose_routes_through_the_gateway(monkeypatch):
    cap: dict = {}
    _install_blocking(monkeypatch, cap)
    actions_mod.terminal_propose("show the last 20 lines of the log")
    assert cap.get("create_kw"), "the model was never called"
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "terminal_router" and rec.invoked is True


def test_chat_stream_routes_through_the_gateway(monkeypatch):
    cap: dict = {}
    mod = types.ModuleType("anthropic")

    class _Final:
        stop_reason = "end_turn"
        usage = None
        content: list = []

    class _Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        @property
        def text_stream(self):
            return iter(["Two ", "leads."])

        def get_final_message(self):
            return _Final()

    class _Msgs:
        def stream(self, **kw):
            cap["kwargs"] = kw
            return _Stream()

        def create(self, **kw):           # not used on the streaming path
            cap["create_kw"] = kw
            return _Final()

    class _Client:
        def __init__(self, api_key=None, **kw):
            self.messages = _Msgs()

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)

    tokens: list = []
    res = chat._reason_stream_cloud(CHAT, "stream it", reason_mode="ask", model="claude-sonnet-5",
                                    emit=lambda ev: tokens.append(ev.get("text")) if ev.get("event") == "token"
                                    else None)
    assert res.get("ok") is True
    assert tokens == ["Two ", "leads."]                     # deltas streamed through the gateway's closure
    assert cap.get("kwargs"), "messages.stream was never called"
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "chat_reason_stream" and rec.invoked is True


# ── BLOCK-1 regression: a recognised secret in a PRIOR turn is MASKED in the egress messages array ────────
# The gateway redacts only the CURRENT turn; history was replayed RAW, so a prior-turn secret of a recognised
# shape leaked UNMASKED to the provider. These pin the fix on BOTH cloud paths (the gap the prior conformance
# test missed: it only checked a record was produced, never that history was masked).

_HIST_CHAT = "egress-history-chat"
_HIST_SECRET = "sk-ant-PRIORTURN-HISTORY-SECRET-abc123XYZ"


def _seed_prior_turn_with_secret(chat_id: str):
    """A prior user turn carrying a recognised secret shape, a prior assistant reply, and a trailing user
    record (which ``_prior_records`` strips — the current turn is the ``_reason`` arg, not a record)."""
    chat._append(chat_id, {"role": "user", "text": f"my config Authorization: Bearer {_HIST_SECRET}"})
    chat._append(chat_id, {"role": "assistant", "text": "noted."})
    chat._append(chat_id, {"role": "user", "text": "placeholder current (stripped as history)"})


def _assert_history_masked(msgs: list):
    blob = json.dumps(msgs, default=str)
    assert _HIST_SECRET not in blob, "prior-turn secret leaked UNMASKED into the egress history array"
    assert "<redacted" in blob, "expected the masked placeholder in the egress history"
    roles = [m["role"] for m in msgs]
    # the conversation is still replayed: a prior user + assistant precede the current (final) user turn
    assert roles[0] == "user" and roles[-1] == "user" and "assistant" in roles[:-1]


def test_chat_reason_blocking_masks_prior_turn_secret_in_history(monkeypatch):
    cap: dict = {}
    _install_blocking(monkeypatch, cap)
    _seed_prior_turn_with_secret(_HIST_CHAT)
    out = chat._reason(_HIST_CHAT, "continue the review please", reason_mode="ask")
    assert out["ok"] is True
    assert cap.get("create_kw"), "the model was never called"
    _assert_history_masked(cap["create_kw"]["messages"])


def test_chat_stream_masks_prior_turn_secret_in_history(monkeypatch):
    cap: dict = {}
    mod = types.ModuleType("anthropic")

    class _Final:
        stop_reason = "end_turn"
        usage = None
        content: list = []

    class _Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        @property
        def text_stream(self):
            return iter(["ok."])

        def get_final_message(self):
            return _Final()

    class _Msgs:
        def stream(self, **kw):
            cap["kwargs"] = kw
            return _Stream()

        def create(self, **kw):
            cap["create_kw"] = kw
            return _Final()

    class _Client:
        def __init__(self, api_key=None, **kw):
            self.messages = _Msgs()

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)

    _seed_prior_turn_with_secret(_HIST_CHAT)
    res = chat._reason_stream_cloud(_HIST_CHAT, "continue it", reason_mode="ask",
                                    model="claude-sonnet-5", emit=lambda ev: None)
    assert res.get("ok") is True
    assert cap.get("kwargs"), "messages.stream was never called"
    _assert_history_masked(cap["kwargs"]["messages"])
