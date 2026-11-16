"""The published rate card: exact milli-credit lines, the owner override, and refusal of malformed rates."""
from __future__ import annotations

import json

import pytest

from vigil_core.model_metering import Usage
from vigil_core.rate_card import (DEFAULT_RATE_CARD, MC_PER_CREDIT, RateCardError, format_credits, rate_card)


def test_published_defaults_are_the_owner_rates_in_credits():
    pub = DEFAULT_RATE_CARD.published()
    assert pub["currency"] == "credits" and pub["credits_per_usd"] == 100
    ai = {r["unit"]: r["credits"] for r in pub["ai"]}
    assert ai == {"input_tokens": "1250.000", "output_tokens": "6250.000", "cache_read_tokens": "125.000",
                  "cache_write_5m_tokens": "1563.000", "cache_write_1h_tokens": "2500.000", "web_searches": "2.500"}
    assert pub["worker"]["credits"] == "1.000" and pub["worker"]["per"] == "minute"
    assert pub["premium"] == []
    assert "usd" not in json.dumps(pub["ai"]).lower()          # every customer-facing amount is in credits


def test_ai_lines_are_exact_to_a_thousandth_of_a_credit():
    lines = DEFAULT_RATE_CARD.ai_lines(Usage(input_tokens=1000, output_tokens=200, cache_read_tokens=4000,
                                             web_search_requests=2))
    by = {ln.unit: ln.amount_mc for ln in lines}
    assert by == {"input_tokens": 1250,          # 1000 x 1250 credits / 1M = 1.25 credits
                  "output_tokens": 1250,         # 200 x 6250 / 1M = 1.25
                  "cache_read_tokens": 500,      # 4000 x 125 / 1M = 0.5
                  "web_searches": 5000}          # 2 x 2.5
    assert [ln.as_dict()["credits"] for ln in lines] == ["1.250", "1.250", "0.500", "5.000"]


def test_a_tiny_request_is_rounded_up_only_below_a_thousandth():
    (line,) = DEFAULT_RATE_CARD.ai_lines(Usage(input_tokens=1))
    assert line.amount_mc == 2                   # 1.25 milli-credits -> 2 mc (0.002 credit), never a whole credit
    assert DEFAULT_RATE_CARD.ai_lines(Usage()) == []


def test_worker_time_is_billed_by_the_second_at_the_minute_rate():
    assert DEFAULT_RATE_CARD.worker_line(60).amount_mc == MC_PER_CREDIT
    assert DEFAULT_RATE_CARD.worker_line(1).amount_mc == 17          # 1000/60 = 16.67 -> 17 mc
    assert DEFAULT_RATE_CARD.worker_line(0).amount_mc == 0
    with pytest.raises(RateCardError):
        DEFAULT_RATE_CARD.worker_line(-1)


def test_an_unpriced_premium_api_is_refused_never_free():
    with pytest.raises(RateCardError, match="no published rate"):
        DEFAULT_RATE_CARD.premium_line("shodan", 1)


def _override(**over):
    doc = {"ai": {"input_tokens": "1250", "output_tokens": "6250", "cache_read_tokens": "125",
                  "cache_write_5m_tokens": "1563", "cache_write_1h_tokens": "2500", "web_searches": "2.5"},
           "worker_minute": "1"}
    doc.update(over)
    return {"VIGIL_RATE_CARD": json.dumps(doc)}


def test_owner_override_replaces_the_card_and_prices_premium_apis():
    card = rate_card(_override(worker_minute="0.5", premium={"intel": {"credits": "3.125", "label": "Threat intel"}}))
    assert card.worker.mc == 500
    line = card.premium_line("intel", 4)
    assert line.amount_mc == 12500 and line.label == "Threat intel"
    assert rate_card({}) is DEFAULT_RATE_CARD


@pytest.mark.parametrize("bad", [
    {"worker_minute": "0"},                                   # free worker time
    {"worker_minute": "0.0001"},                              # finer than 0.001 credit
    {"worker_minute": 1.5},                                   # a float rate
    {"ai": {"input_tokens": "1"}},                            # missing AI units
    {"premium": {"x": {"credits": "0"}}},                     # a free billable call
    {"premium": {"x": {"credits": "1", "per": 0}}},
    {"surprise": 1},                                          # unknown key
])
def test_a_malformed_override_is_refused_whole(bad):
    with pytest.raises(RateCardError):
        rate_card(_override(**bad))
    with pytest.raises(RateCardError):
        rate_card({"VIGIL_RATE_CARD": "{not json"})


def test_a_zero_ai_token_rate_is_refused():
    with pytest.raises(RateCardError, match="greater than zero"):
        rate_card(_override(ai={"input_tokens": "0", "output_tokens": "6250", "cache_read_tokens": "125",
                                "cache_write_5m_tokens": "1563", "cache_write_1h_tokens": "2500",
                                "web_searches": "2.5"}))


def test_format_credits():
    assert format_credits(0) == "0.000" and format_credits(1) == "0.001" and format_credits(123456) == "123.456"
    assert format_credits(-1500) == "-1.500"
    with pytest.raises(RateCardError):
        format_credits(1.5)  # type: ignore[arg-type]


def test_charge_is_the_sum_of_the_lines_with_the_rates_that_applied():
    amount, rates = DEFAULT_RATE_CARD.charge(Usage(input_tokens=1000, output_tokens=200))
    assert amount == 2500                                    # 1.250 + 1.250 credits
    assert rates == {"input_tokens": [1_250_000, 1_000_000], "output_tokens": [6_250_000, 1_000_000]}
    assert DEFAULT_RATE_CARD.charge(Usage()) == (0, {})


def test_request_worst_mc_mirrors_the_gateway_worst_case():
    # 400 cached tokens at the cache-read rate, the other 600 at the dearest shaped-input rate (the 5-minute cache
    # write, 1,563 > 1,250 input), 100 output tokens: (400*125 + 600*1563 + 100*6250) credits per million, rounded
    # up once to 0.001 credit -> 1612.8 mc -> 1613 mc
    assert DEFAULT_RATE_CARD.request_worst_mc(1000, 400, 100) == 1613
    assert DEFAULT_RATE_CARD.request_worst_mc(1000, 5000, 0) == 125      # the cached part is capped at the input
    assert DEFAULT_RATE_CARD.request_worst_mc(0, 0, 0) == 0
    # never below what the same usage is actually charged when it is all fresh input + output
    actual, _ = DEFAULT_RATE_CARD.charge(Usage(input_tokens=1000, output_tokens=100))
    assert DEFAULT_RATE_CARD.request_worst_mc(1000, 0, 100) >= actual
    for bad in (-1, True, 1.0):
        with pytest.raises(RateCardError):
            DEFAULT_RATE_CARD.request_worst_mc(bad, 0, 0)  # type: ignore[arg-type]
