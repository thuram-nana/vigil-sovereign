"""
VIGIL Anthropic price table — the fallback that keeps the budget governor armed on Claude.

Strix stops a scan when accumulated LLM cost reaches ``max_budget_usd``. That cost comes from
LiteLLM's reported ``response_cost``/cost map. LiteLLM may not know a newly-released Claude model
(e.g. ``claude-opus-4-8``) and then reports **$0** — which silently DISARMS the budget governor:
a $0 spend never trips the cap, so an autonomous scan runs unbounded. This table gives a
best-effort per-token cost so the accumulated cost is nonzero and the budget still enforces.

Precedence: real provider-reported cost (LiteLLM ``response_cost`` / ``usage.cost``) always wins;
this table is consulted ONLY when every provider path yields nothing (see
``report.state._estimate_response_cost``). Prices are USD per token, from Anthropic's published
per-million rates / 1e6; update as Anthropic revises pricing. Being an estimate, a slightly stale
rate still fixes the disarm (cost becomes nonzero) — the goal is a *bounded* autonomous scan.
"""

from __future__ import annotations

from typing import Any

_M = 1_000_000.0

# (input, output, cache_read, cache_write) — USD per MILLION tokens.
_PRICES_PER_M: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-4": (15.0, 75.0, 1.50, 18.75),
    "claude-opus-3": (15.0, 75.0, 1.50, 18.75),
    "claude-3-opus": (15.0, 75.0, 1.50, 18.75),
    "claude-sonnet-5": (3.0, 15.0, 0.30, 3.75),
    "claude-sonnet-4": (3.0, 15.0, 0.30, 3.75),
    "claude-3-7-sonnet": (3.0, 15.0, 0.30, 3.75),
    "claude-3-5-sonnet": (3.0, 15.0, 0.30, 3.75),
    "claude-haiku-4": (1.0, 5.0, 0.10, 1.25),
    "claude-3-5-haiku": (0.80, 4.0, 0.08, 1.0),
    "claude-3-haiku": (0.25, 1.25, 0.03, 0.30),
}


def is_anthropic_model(model: str | None) -> bool:
    if not model:
        return False
    name = model.strip().lower()
    return "anthropic" in name or "claude" in name


def _match_prices(model: str) -> tuple[float, float, float, float] | None:
    name = model.strip().lower()
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    # longest key first, so "claude-3-5-sonnet" wins over a generic "sonnet" family match
    for key in sorted(_PRICES_PER_M, key=len, reverse=True):
        if key in name:
            return _PRICES_PER_M[key]
    if "opus" in name:
        return _PRICES_PER_M["claude-opus-4"]
    if "sonnet" in name:
        return _PRICES_PER_M["claude-sonnet-5"]
    if "haiku" in name:
        return _PRICES_PER_M["claude-haiku-4"]
    return None


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _cache_read_tokens(usage: dict[str, Any]) -> int:
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        v = details.get("cached_tokens") or details.get("cache_read_input_tokens")
        if v:
            return _int(v)
    return _int(usage.get("cache_read_input_tokens"))


def _cache_write_tokens(usage: dict[str, Any]) -> int:
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        v = details.get("cache_creation_input_tokens") or details.get("cache_write_input_tokens")
        if v:
            return _int(v)
    return _int(usage.get("cache_creation_input_tokens"))


def estimate_anthropic_cost(model: str | None, usage_payload: dict[str, Any]) -> float | None:
    """Best-effort USD cost for an Anthropic model from token counts.

    Returns None if the model is not Anthropic, has no price entry, or carries no token counts.
    Cache-read/write tokens (from ``*_tokens_details`` or the Anthropic-native fields) are priced
    at their own rates, and cached tokens are subtracted from the fresh-input count so they are
    not double-charged.
    """
    if not is_anthropic_model(model):
        return None
    prices = _match_prices(model or "")
    if prices is None:
        return None
    in_price, out_price, cache_read_price, cache_write_price = prices

    prompt = _int(usage_payload.get("prompt_tokens"))
    completion = _int(usage_payload.get("completion_tokens"))
    if not prompt and not completion:
        total = _int(usage_payload.get("total_tokens"))
        if not total:
            return None
        cost = total * in_price / _M   # no split available — price the lot at the input rate
        return cost if cost > 0 else None

    cache_read = _cache_read_tokens(usage_payload)
    cache_write = _cache_write_tokens(usage_payload)
    fresh_input = max(0, prompt - cache_read - cache_write)

    cost = (
        fresh_input * in_price
        + completion * out_price
        + cache_read * cache_read_price
        + cache_write * cache_write_price
    ) / _M
    return cost if cost > 0 else None
