"""dedupe text extraction falls back to the chat-completions/Claude shape (P8).

Skipped where Strix's report deps (openai-agents/openai) are not installed.
"""

from __future__ import annotations

import pytest

dedupe = pytest.importorskip("strix.report.dedupe", reason="strix/openai-agents deps not installed")


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _ChatResp:
    """A chat-completions-shaped response (what the Claude/LiteLLM route can hand back)."""

    def __init__(self, content, output=None):
        self.choices = [_Choice(content)]
        self.output = output or []


def test_extracts_plain_string_content_on_claude_shape():
    assert dedupe._extract_text(_ChatResp("hello from claude")) == "hello from claude"


def test_extracts_anthropic_content_blocks():
    resp = _ChatResp([{"type": "text", "text": "block one"}, {"type": "text", "text": " block two"}])
    assert dedupe._extract_text(resp) == "block one block two"


def test_empty_responses_output_falls_through_to_choices():
    # the exact regression: output has no ResponseOutputMessage → must NOT return ""
    assert dedupe._extract_text(_ChatResp("fallback text", output=[])) == "fallback text"


def test_blocks_to_text_helper():
    assert dedupe._blocks_to_text("plain") == "plain"
    assert dedupe._blocks_to_text([{"type": "text", "text": "a"}, {"text": "b"}]) == "ab"
    assert dedupe._blocks_to_text(None) == ""
    assert dedupe._blocks_to_text(123) == ""


def test_dict_shaped_response():
    # some routes hand back a plain dict
    resp = {"choices": [{"message": {"content": "dict content"}}]}
    assert dedupe._extract_chat_completions_text(resp) == "dict content"
