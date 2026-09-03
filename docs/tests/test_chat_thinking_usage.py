"""S7 — a thinking indicator + per-turn token usage / running context meter in chat.

Reads files only (docs-only CI job). The backend surfaces `usage` on the streamed result; the frontend shows
"Thinking…" until the first token and a token meter under the composer.
"""
from __future__ import annotations
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CHAT = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "chat.py").read_text(encoding="utf-8")


def test_backend_surfaces_usage_on_the_streamed_result():
    assert 'res["usage"] = {"input_tokens"' in CHAT, "the streamed result must carry token usage"
    assert 'getattr(u, "output_tokens", None)' in CHAT


def test_frontend_thinking_indicator_and_usage_meter():
    assert 'C.stream.text ? (C.stream.text + " ▌") : "Thinking…"' in APPJS, "no thinking indicator"
    assert "C.lastUsage = r.usage;" in APPJS and "C.ctxTokens" in APPJS, "usage not captured"
    assert 'h("div.chat-usage"' in APPJS, "no token meter under the composer"
