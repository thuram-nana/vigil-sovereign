"""reasoning_effort is not silently dropped for a newer Claude model (P8).

Skipped where Strix's config deps (litellm) are not installed.
"""

from __future__ import annotations

import pytest

models = pytest.importorskip("strix.config.models", reason="strix/litellm deps not installed")


def test_anthropic_thinking_families_recognised():
    f = models._anthropic_supports_thinking
    assert f("claude-opus-4-8")
    assert f("anthropic/claude-opus-4-20250514")
    assert f("claude-sonnet-5")
    assert f("claude-sonnet-4")
    assert f("claude-3-7-sonnet")
    assert f("claude-haiku-4-5")                     # Haiku 4.5 DOES support extended thinking
    assert f("anthropic/claude-haiku-4-5-20251001")
    # families WITHOUT extended thinking must not be misreported
    assert not f("claude-3-5-sonnet")
    assert not f("claude-3-5-haiku")                 # Haiku 3.5: no extended thinking
    assert not f("claude-3-haiku")
    assert not f("gpt-4o")
    assert not f("")


def test_reasoning_not_dropped_when_litellm_is_ignorant(monkeypatch):
    import litellm
    # simulate LiteLLM's cost map not knowing the newer Claude model — the disarm precondition
    monkeypatch.setattr(litellm, "model_cost", {}, raising=False)
    assert models.model_supports_reasoning("anthropic/claude-opus-4-8") is True
    # a non-thinking Claude is still correctly treated as non-reasoning
    assert models.model_supports_reasoning("anthropic/claude-3-5-haiku") is False


def test_litellm_known_reasoning_flag_still_respected(monkeypatch):
    import litellm
    monkeypatch.setattr(
        litellm, "model_cost", {"some/model": {"supports_reasoning": True}}, raising=False
    )
    assert models.model_supports_reasoning("some/model") is True
