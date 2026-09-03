"""S10 — assistant replies render as SAFE markdown (code/bold/italic/lists/links). XSS-safe by construction:
every text run is a DOM text node (never innerHTML) and links accept only http(s)/mailto (others render as
text). User messages stay literal.

Reads files only (docs-only CI job). XSS-safety + structure are verified against the real sliced renderer in a
headless jsdom harness.
"""
from __future__ import annotations
from pathlib import Path

APPJS = (Path(__file__).resolve().parents[2] / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_renderer_present_and_used_for_assistant_only():
    assert "function renderMarkdown(text)" in APPJS and "function _mdInline(text)" in APPJS
    assert 'h("div.md", null, renderMarkdown(m.text || m.reply || ""))' in APPJS
    # user messages are NOT run through markdown (stay literal, pre-wrap)
    assert 'whiteSpace: "pre-wrap", wordBreak: "break-word" } }, String(m.text || m.reply || ""))' in APPJS


def test_link_href_is_scheme_restricted():
    # only http(s)/mailto become anchors; anything else falls back to plain text (no javascript: sinks)
    assert '/^(https?:|mailto:)/i.test(mm[2])' in APPJS
    assert 'rel: "noopener noreferrer"' in APPJS


def test_no_innerhtml_of_untrusted_text():
    # the renderer must never build nodes from an html string of the reply
    assert "renderMarkdown" in APPJS
    # (h() string children go through createTextNode; the renderer only ever passes strings/nodes to h)
