"""The Anthropic price table keeps the budget governor ARMED on Claude.

Strix stops a scan when accumulated LLM cost reaches ``max_budget_usd``. That cost comes from
LiteLLM's reported cost; when LiteLLM does not know a model it reports nothing, and the Anthropic
price table (``report.anthropic_pricing``) is the fallback that keeps the cost nonzero. If a Claude
model the operator actually selects is MISSING from that table, the fallback returns ``None``, the
accumulated cost stays ``$0``, and the ``max_budget_usd`` governor silently DISARMS — an
unbounded-spend footgun. These tests pin: every referenced Claude model (including the flagship
codenames ``claude-fable-5`` / ``claude-mythos-5`` and any future codename) resolves to a nonzero
cost, and a run that exceeds the budget on such a model actually TRIPS the governor.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from agents.usage import Usage
from strix.core.hooks import BudgetExceededError, ReportUsageHooks
from strix.report.anthropic_pricing import estimate_anthropic_cost
from strix.report.state import (
    ReportState,
    litellm_cost_callback,
    set_global_report_state,
)


if TYPE_CHECKING:
    from pathlib import Path


# A million input + a million output tokens: enough that any real per-token rate is well over a $1 cap.
_BIG_USAGE = {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000, "total_tokens": 2_000_000}
# A tiny call: a few hundred tokens, cents of cost — must stay UNDER a $1 cap (the negative control).
_TINY_USAGE = {"prompt_tokens": 200, "completion_tokens": 100, "total_tokens": 300}


@pytest.fixture
def report_state(tmp_path: "Path", monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="budget-test")
    set_global_report_state(state)
    return state


# --------------------------------------------------------------------------------------------------
# The table itself: every Claude model the code references — and any unknown codename — is priced.
# --------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "model",
    [
        "anthropic/claude-fable-5",   # flagship codename in RECOMMENDED_MODEL_NAMES (no opus/sonnet/haiku token)
        "claude-fable-5",
        "anthropic/claude-mythos-5",  # referenced in the CRUCIBLE kernel model list
        "claude-opus-4-8",            # the Strix default backend
        "anthropic/claude-sonnet-4-6",
        "claude-haiku-4-5",
        "claude-nova-9",              # a codename NOT in the table — must still price (safe catch-all)
    ],
)
def test_every_referenced_claude_model_is_priced(model: str) -> None:
    cost = estimate_anthropic_cost(model, _BIG_USAGE)
    assert cost is not None and cost > 0, f"{model!r} must accrue a nonzero cost, got {cost!r}"


def test_non_anthropic_model_is_not_priced() -> None:
    # The Claude catch-all must NOT over-reach: a non-Anthropic model returns None so the callback
    # leaves cost accounting to LiteLLM / the provider (no fabricated Anthropic price for gpt-*).
    assert estimate_anthropic_cost("openai/gpt-4o-mini", _BIG_USAGE) is None
    assert estimate_anthropic_cost("gemini/gemini-3.1-pro-preview", _BIG_USAGE) is None


# --------------------------------------------------------------------------------------------------
# End-to-end: the callback + governor. When LiteLLM does not know the model, only the price-table
# fallback can supply cost — and it must arm the governor.
# --------------------------------------------------------------------------------------------------
def _record_via_callback(model: str, usage_payload: dict) -> None:
    """Drive the real LiteLLM success-callback with LiteLLM's own cost map unavailable, so the only
    possible cost source is the Anthropic price-table fallback."""
    kwargs = {
        "response_cost": None,
        "model": model,
        "litellm_params": {"custom_llm_provider": "anthropic"},
    }
    response = {"usage": usage_payload, "model": model}
    with patch("litellm.completion_cost", side_effect=ValueError(f"unknown model {model}")):
        litellm_cost_callback(kwargs, response)


async def _run_governor(model: str, usage_payload: dict, budget: float) -> None:
    hooks = ReportUsageHooks(model=model, max_budget_usd=budget)
    ctx = MagicMock()
    ctx.context = {"agent_id": "root"}
    agent = MagicMock()
    agent.name = "root"
    response = MagicMock()
    response.usage = Usage(
        requests=1,
        input_tokens=usage_payload["prompt_tokens"],
        output_tokens=usage_payload["completion_tokens"],
        total_tokens=usage_payload["total_tokens"],
    )
    await hooks.on_llm_end(ctx, agent, response)


@pytest.mark.asyncio
async def test_governor_trips_on_flagship_codename_over_budget(report_state: ReportState) -> None:
    # The exact disarm: a recommended flagship codename LiteLLM does not know. Without the price-table
    # entry the accumulated cost is $0 and this run would never stop.
    model = "anthropic/claude-fable-5"
    _record_via_callback(model, _BIG_USAGE)
    assert report_state.get_total_llm_cost() > 1.0, "price table must accrue real cost from tokens"
    with pytest.raises(BudgetExceededError):
        await _run_governor(model, _BIG_USAGE, budget=1.0)


@pytest.mark.asyncio
async def test_governor_does_not_trip_on_cheap_flagship_run(report_state: ReportState) -> None:
    # Negative control: the SAME (armed) model with a tiny call stays under a generous budget, so the
    # governor does not false-trip a cheap run. Cost is nonzero (armed) but well under the cap.
    model = "anthropic/claude-fable-5"
    _record_via_callback(model, _TINY_USAGE)
    cost = report_state.get_total_llm_cost()
    assert 0.0 < cost < 5.0
    await _run_governor(model, _TINY_USAGE, budget=5.0)  # must NOT raise
