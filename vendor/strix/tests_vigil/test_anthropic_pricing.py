"""VIGIL Anthropic price table — the budget-disarm fix (P8).

Loaded directly from the file so it runs without Strix's heavy runtime deps: the module under
test imports only ``typing``.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

_MOD = pathlib.Path(__file__).resolve().parents[1] / "strix" / "report" / "anthropic_pricing.py"
_spec = importlib.util.spec_from_file_location("vigil_anthropic_pricing", _MOD)
ap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ap)


def test_opus_cost_is_positive_and_uses_the_right_rate():
    # 1,000,000 input + 1,000,000 output at Opus rates ($15 + $75 per M) = $90.
    cost = ap.estimate_anthropic_cost(
        "anthropic/claude-opus-4-8",
        {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000, "total_tokens": 2_000_000},
    )
    assert cost == pytest.approx(90.0)


def test_the_disarm_scenario_yields_nonzero_cost():
    # The exact bug: a newer Claude model LiteLLM doesn't know. The table must still cost it.
    cost = ap.estimate_anthropic_cost(
        "anthropic/claude-opus-4-8",
        {"prompt_tokens": 5000, "completion_tokens": 2000, "total_tokens": 7000},
    )
    assert cost is not None and cost > 0


def test_cache_tokens_priced_separately_and_not_double_charged():
    # 10k prompt of which 8k are cache reads → 2k fresh input @15/M + 8k cache-read @1.5/M.
    cost = ap.estimate_anthropic_cost(
        "claude-opus-4-8",
        {
            "prompt_tokens": 10_000,
            "completion_tokens": 0,
            "prompt_tokens_details": {"cached_tokens": 8_000},
        },
    )
    expected = (2_000 * 15.0 + 8_000 * 1.5) / 1_000_000
    assert cost == pytest.approx(expected)


def test_sonnet_and_haiku_have_distinct_rates():
    u = {"prompt_tokens": 1_000_000, "completion_tokens": 0}
    assert ap.estimate_anthropic_cost("claude-sonnet-5", u) == pytest.approx(3.0)
    assert ap.estimate_anthropic_cost("claude-haiku-4-5", u) == pytest.approx(1.0)


def test_total_only_usage_still_costs():
    cost = ap.estimate_anthropic_cost("claude-opus-4-8", {"total_tokens": 1_000_000})
    assert cost == pytest.approx(15.0)  # priced at the input rate when no split is available


def test_non_anthropic_returns_none():
    assert ap.estimate_anthropic_cost("openai/gpt-4o", {"prompt_tokens": 1000}) is None
    assert ap.estimate_anthropic_cost("", {"prompt_tokens": 1000}) is None
    assert ap.estimate_anthropic_cost(None, {"prompt_tokens": 1000}) is None


def test_no_tokens_returns_none():
    assert ap.estimate_anthropic_cost("claude-opus-4-8", {}) is None
    assert ap.estimate_anthropic_cost("claude-opus-4-8", {"prompt_tokens": 0, "completion_tokens": 0}) is None


def test_pathological_token_counts_do_not_crash():
    # int(float('inf')) would raise OverflowError; _int must absorb it (red-pen P8 finding 2).
    cost = ap.estimate_anthropic_cost(
        "claude-opus-4-8", {"prompt_tokens": float("inf"), "completion_tokens": 10}
    )
    assert isinstance(cost, float)  # bounded number, never a crash
    # negatives absorbed to zero → no tokens → None, not an exception
    assert ap.estimate_anthropic_cost("claude-opus-4-8", {"prompt_tokens": -5, "completion_tokens": -1}) is None


def test_is_anthropic_model():
    assert ap.is_anthropic_model("anthropic/claude-opus-4-8")
    assert ap.is_anthropic_model("claude-3-5-sonnet")
    assert not ap.is_anthropic_model("openai/gpt-4o")
    assert not ap.is_anthropic_model(None)
