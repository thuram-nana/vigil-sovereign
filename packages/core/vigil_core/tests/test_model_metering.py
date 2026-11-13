"""PRICING M1a — the metering core (vigil_core.model_metering): prices, usage parsing, exact cost and credits.

Pins the arithmetic the sovereign model gateway bills with (design §2): integer nano-USD money, the Opus 4.8
price row, the cumulative-usage rule of a streamed response, the markup / floor / reservation clamp, and the USD
cap a reservation buys — and that every malformed input is REFUSED, never priced at a guess.

Mutation-verify targets (each neuter reds a NAMED test here):
  * add a message_delta's count to the running total instead of replacing it   -> test_stream_delta_counts_are_cumulative
  * drop the 1-hour cache-write split (price every write at 5 minutes)        -> test_cost_is_exact_for_a_hand_worked_response
  * floor-divide the credits instead of ceil                                  -> test_credits_round_up_and_clamp
  * drop the reservation clamp                                                -> test_credits_round_up_and_clamp
  * give the margin a default, or let it reach 0 or 1                        -> test_the_target_margin_is_required_exact_and_bounded
  * read the margin while a retired pricing setting is still present           -> test_a_retired_pricing_setting_is_refused
  * price an unknown model at zero                                            -> test_an_unknown_model_is_refused
  * round a price finer than $0.001/MTok instead of refusing it               -> test_price_rows_are_exact_nano_usd
"""
from __future__ import annotations

import json
import random
from fractions import Fraction

import pytest

from vigil_core import model_metering as mm

OPUS = "claude-opus-4-8"


def test_price_rows_are_exact_nano_usd():
    row = mm.DEFAULT_PRICES[OPUS]
    assert (row.input, row.output, row.cache_read, row.cache_write_5m, row.cache_write_1h, row.web_search) == (
        5_000, 25_000, 500, 6_250, 10_000, 10_000_000)                  # a web search is $0.01
    assert mm.PriceRow.from_usd(1, "0.001", "1", 2, "3.5", 0).output == 1
    # a zero token price is a typo, never a price: it would switch the run's budget off
    for zero in range(5):
        prices = ["1", "1", "1", "1", "1", "1"]
        prices[zero] = "0"
        if zero == 2:
            assert mm.PriceRow.from_usd(*prices).cache_read == 0        # only a cache read may be free
        else:
            with pytest.raises(mm.MeteringError, match="greater than zero"):
                mm.PriceRow.from_usd(*prices)
    for bad in ("0.0001", "-1", "nan", "inf", "abc", 1.5, True, None):
        with pytest.raises(mm.MeteringError):
            mm.PriceRow.from_usd(bad, "1", "1", "1", "1", "1")
        with pytest.raises(mm.MeteringError):
            mm.PriceRow.from_usd("1", "1", "1", "1", "1", bad)


def test_usage_from_a_non_streamed_body():
    u = mm.usage_from_api({"input_tokens": 1200, "output_tokens": 340, "cache_read_input_tokens": 9000,
                           "cache_creation_input_tokens": 700,
                           "cache_creation": {"ephemeral_5m_input_tokens": 500, "ephemeral_1h_input_tokens": 200},
                           "service_tier": "standard", "server_tool_use": {"web_search_requests": 3}})
    assert u == mm.Usage(1200, 340, 9000, 500, 200, 3)
    assert u.total_tokens == 1200 + 340 + 9000 + 700
    assert mm.usage_from_api({}) == mm.Usage()
    assert mm.usage_from_api({"input_tokens": None, "output_tokens": 3}) == mm.Usage(output_tokens=3)


def test_cache_writes_without_a_split_are_five_minute_writes():
    assert mm.usage_from_api({"cache_creation_input_tokens": 400}) == mm.Usage(cache_write_5m_tokens=400)
    # a split that leaves part of the total unattributed: the remainder is a default-TTL write
    u = mm.usage_from_api({"cache_creation_input_tokens": 400,
                           "cache_creation": {"ephemeral_1h_input_tokens": 100}})
    assert (u.cache_write_5m_tokens, u.cache_write_1h_tokens) == (300, 100)
    with pytest.raises(mm.MeteringError, match="exceeds"):
        mm.usage_from_api({"cache_creation_input_tokens": 10,
                           "cache_creation": {"ephemeral_5m_input_tokens": 8, "ephemeral_1h_input_tokens": 8}})


@pytest.mark.parametrize("bad", [
    {"input_tokens": -1}, {"output_tokens": True}, {"output_tokens": 1.0}, {"input_tokens": "12"},
    {"cache_read_input_tokens": 10 ** 13}, {"cache_creation": [1]}, {"cache_creation": {"ephemeral_5m_input_tokens": -4}},
    {"server_tool_use": 2}, {"server_tool_use": {"web_search_requests": -1}},
])
def test_malformed_usage_is_refused(bad):
    with pytest.raises(mm.MeteringError):
        mm.usage_from_api(bad)
    with pytest.raises(mm.MeteringError):
        mm.usage_from_api(["not", "an", "object"])


def test_stream_delta_counts_are_cumulative():
    m = mm.StreamMeter()
    m.feed({"type": "message_start", "message": {"usage": {
        "input_tokens": 50, "output_tokens": 1, "cache_read_input_tokens": 4000,
        "cache_creation_input_tokens": 200, "cache_creation": {"ephemeral_5m_input_tokens": 200}}}})
    m.feed({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "hi"}})
    m.feed({"type": "message_delta", "usage": {"output_tokens": 120}})
    m.feed({"type": "message_delta", "usage": {"output_tokens": 300}})       # cumulative: 300, not 420
    m.feed({"type": "message_delta"})                                       # no usage: nothing changes
    assert m.started and m.usage == mm.Usage(50, 300, 4000, 200, 0)
    # a delta may restate input / cache counts (cumulative too): they replace, the rest stay
    m.feed({"type": "message_delta", "usage": {"input_tokens": 60, "cache_read_input_tokens": 4100}})
    assert m.usage == mm.Usage(60, 300, 4100, 200, 0)
    m.feed({"type": "message_delta", "usage": {"server_tool_use": {"web_search_requests": 2}}})
    m.feed({"type": "message_delta", "usage": {"server_tool_use": {"web_search_requests": 2}}})   # cumulative: 2
    m.feed({"type": "message_stop"})
    assert m.usage == mm.Usage(60, 300, 4100, 200, 0, 2)


def test_a_malformed_stream_event_is_refused():
    m = mm.StreamMeter()
    for bad in ("x", {"type": "message_start"}, {"type": "message_start", "message": {"usage": {"input_tokens": -1}}},
                {"type": "message_delta", "usage": 5}):
        with pytest.raises(mm.MeteringError):
            m.feed(bad)
    assert not m.started


def test_cost_is_exact_for_a_hand_worked_response():
    u = mm.Usage(input_tokens=1_000, output_tokens=2_000, cache_read_tokens=10_000, cache_write_5m_tokens=3_000,
                 cache_write_1h_tokens=1_000)
    # 1000*5000 + 2000*25000 + 10000*500 + 3000*6250 + 1000*10000 nano-USD
    assert mm.cost_nano_usd(u, OPUS, mm.DEFAULT_PRICES) == 88_750_000
    assert mm.format_usd(88_750_000) == "$0.09"
    assert mm.format_usd(0) == "$0.00" and mm.format_usd(1) == "$0.01" and mm.format_usd(10 ** 10) == "$10.00"
    assert mm.cost_nano_usd(u + u, OPUS, mm.DEFAULT_PRICES) == 2 * 88_750_000
    assert mm.cost_nano_usd(mm.Usage(web_search_requests=3), OPUS, mm.DEFAULT_PRICES) == 30_000_000
    assert u.total_tokens == 17_000 and mm.Usage(web_search_requests=5).total_tokens == 0


def test_an_unknown_model_is_refused():
    with pytest.raises(mm.MeteringError, match="no price"):
        mm.cost_nano_usd(mm.Usage(input_tokens=1), "claude-opus-4-7", mm.DEFAULT_PRICES)
    with pytest.raises(mm.MeteringError):
        mm.cost_nano_usd({"input_tokens": 1}, OPUS, mm.DEFAULT_PRICES)       # type: ignore[arg-type]


def test_the_price_override_merges_and_is_all_or_nothing():
    row = {"input": "4", "output": "20", "cache_read": "0.40", "cache_write_5m": "5", "cache_write_1h": "8",
           "web_search_per_1k": "10"}
    t = mm.price_table({mm.PRICES_ENV: json.dumps({"claude-x": row})})
    assert t[OPUS] == mm.DEFAULT_PRICES[OPUS] and t["claude-x"].input == 4_000
    t = mm.price_table({mm.PRICES_ENV: json.dumps({OPUS: row})})
    assert t[OPUS].output == 20_000
    assert mm.price_table({}) == dict(mm.DEFAULT_PRICES) and mm.price_table({mm.PRICES_ENV: "  "}) == dict(mm.DEFAULT_PRICES)
    for bad in ("{", "[]", "{}", json.dumps({OPUS: {**row, "extra": "1"}}), json.dumps({OPUS: {"input": "5"}}),
                json.dumps({"": row}), json.dumps({OPUS: {**row, "output": 2.5}}),
                json.dumps({OPUS: row, "claude-y": {**row, "input": "-1"}})):
        with pytest.raises(mm.MeteringError):
            mm.price_table({mm.PRICES_ENV: bad})


def test_the_target_margin_is_required_exact_and_bounded():
    # no default: the owner's margin is set at deploy, never committed — unset / empty means metered pricing is off
    for env in ({}, {mm.MARGIN_ENV: ""}, {mm.MARGIN_ENV: "   "}):
        with pytest.raises(mm.MeteringError, match="not set"):
            mm.target_margin(env)
        with pytest.raises(mm.MeteringError, match="not set"):
            mm.billing_markup(env)
    assert mm.target_margin({mm.MARGIN_ENV: " 0.5 "}) == Fraction(1, 2)
    assert mm.billing_markup({mm.MARGIN_ENV: "0.5"}) == 2                            # cost / (1 - m)
    assert mm.billing_markup({mm.MARGIN_ENV: "0.25"}) == Fraction(4, 3)              # exact, never rounded
    assert mm.billing_markup({mm.MARGIN_ENV: "0.99"}) == 100
    assert mm.billing_markup({mm.MARGIN_ENV: "0.001"}) == Fraction(1000, 999)
    for bad in ("0", "0.0", "1", "1.0", "-0.1", "1.5", "50", "50%", "0.995", "abc", "nan", "inf", "-inf", "1e400"):
        with pytest.raises(mm.MeteringError):
            mm.target_margin({mm.MARGIN_ENV: bad})
    # the markup a margin gives prices exactly: 1/(1 - 0.25) on $0.03 is 4 credits ($0.04), rounded up
    assert mm.credits_for_cost(3 * mm.CREDIT_NANO_USD, markup=mm.billing_markup({mm.MARGIN_ENV: "0.25"}),
                               floor=0, cap=99) == 4
    assert mm.credits_for_cost(3 * mm.CREDIT_NANO_USD + 1, markup=mm.billing_markup({mm.MARGIN_ENV: "0.25"}),
                               floor=0, cap=99) == 5


def test_a_retired_pricing_setting_is_refused():
    # ONE pricing number: a deploy still carrying an earlier knob is refused, whatever its value, so it can never
    # sit next to the margin unnoticed
    assert mm.OBSOLETE_PRICING_ENVS == ("VIGIL_BILLING_MARKUP_K", "VIGIL_MARGIN_MULTIPLIER_K")
    assert mm.obsolete_pricing_settings({mm.MARGIN_ENV: "0.5"}) == ()
    for name in mm.OBSOLETE_PRICING_ENVS:
        for value in ("", "3", "junk"):
            env = {mm.MARGIN_ENV: "0.5", name: value}
            assert mm.obsolete_pricing_settings(env) == (name,)
            for fn in (mm.target_margin, mm.billing_markup):
                with pytest.raises(mm.MeteringError) as exc:
                    fn(env)
                assert str(exc.value) == (f"{name} is set: remove it; the only pricing input is "
                                          f"VIGIL_BILLING_TARGET_MARGIN")
    both = {n: "1" for n in mm.OBSOLETE_PRICING_ENVS}
    assert mm.obsolete_pricing_settings(both) == mm.OBSOLETE_PRICING_ENVS
    with pytest.raises(mm.MeteringError, match="VIGIL_BILLING_MARKUP_K is set"):
        mm.target_margin(both)                                           # refused even with no margin at all


def test_the_cancel_settlement_defaults_to_metered_and_refuses_an_unknown_value():
    # owner decision 2026-11-13: a cancelled scan pays for what it already used, so unset/empty means metered
    for env in ({}, {mm.CANCEL_ENV: ""}, {mm.CANCEL_ENV: "  "}):
        assert mm.cancel_settlement(env) == "metered"
    assert mm.DEFAULT_CANCEL_SETTLEMENT == "metered"
    # a value that is set but not recognised is a typo: refuse rather than silently pick a policy
    for env in ({mm.CANCEL_ENV: "free"}, {mm.CANCEL_ENV: "1"}, {mm.CANCEL_ENV: "metered,refund"}):
        with pytest.raises(mm.MeteringError, match="must be one of"):
            mm.cancel_settlement(env)
    assert mm.cancel_settlement({mm.CANCEL_ENV: "metered"}) == "metered"
    assert mm.cancel_settlement({mm.CANCEL_ENV: " Refund "}) == "refund"
    assert mm.CANCEL_POLICIES == ("metered", "refund")


def test_the_floor_parses_and_refuses_junk():
    assert mm.run_floor_credits({}) == 25 and mm.run_floor_credits({mm.FLOOR_ENV: "0"}) == 0
    for bad in ("-1", "2.5", "x"):
        with pytest.raises(mm.MeteringError):
            mm.run_floor_credits({mm.FLOOR_ENV: bad})


def test_credits_round_up_and_clamp():
    k = Fraction(6)                                   # an arbitrary markup for the arithmetic
    # $0.08875 x 6 = $0.5325 -> 53.25 credits -> 54
    assert mm.credits_for_cost(88_750_000, markup=k, floor=25, cap=1_000) == 54
    assert mm.credits_for_cost(88_750_000, markup=k, floor=25, cap=50) == 50            # never above the reservation
    assert mm.credits_for_cost(0, markup=k, floor=25, cap=1_000) == 25                  # the floor
    assert mm.credits_for_cost(0, markup=k, floor=25, cap=10) == 10                     # the clamp beats the floor
    assert mm.credits_for_cost(CREDIT := mm.CREDIT_NANO_USD, markup=Fraction(1), floor=0, cap=9) == 1
    assert mm.credits_for_cost(CREDIT + 1, markup=Fraction(1), floor=0, cap=9) == 2
    assert mm.credits_for_cost(5_000_000, markup=Fraction(13, 2), floor=0, cap=99) == 4  # 3.25 -> 4
    for kw in ({"markup": Fraction(1, 2)}, {"markup": 6}, {"floor": -1}, {"cap": True}):
        args = {"markup": k, "floor": 0, "cap": 5, **kw}
        with pytest.raises(mm.MeteringError):
            mm.credits_for_cost(10, **args)
    with pytest.raises(mm.MeteringError):
        mm.credits_for_cost(-1, markup=k, floor=0, cap=5)


def test_the_usd_cap_never_buys_more_than_the_reservation():
    k = Fraction(6)                                   # an arbitrary markup for the arithmetic
    assert mm.usd_cap_nano_for_credits(450, markup=k) == 750_000_000                     # $0.75 for 450 credits
    rng = random.Random(7)
    for _ in range(2_000):
        credits = rng.randint(0, 10 ** 6)
        markup = Fraction(rng.randint(100, 2_000), 100)
        cap = mm.usd_cap_nano_for_credits(credits, markup=markup)
        # spending the whole cap is charged at most the reservation ...
        assert mm.credits_for_cost(cap, markup=markup, floor=0, cap=10 ** 9) <= credits
        # ... and the cap is tight: a little more spend would exceed it
        assert mm.credits_for_cost(cap + markup.denominator + 1, markup=markup, floor=0, cap=10 ** 9) >= credits
    with pytest.raises(mm.MeteringError):
        mm.usd_cap_nano_for_credits(-1, markup=k)


@pytest.mark.parametrize("extra", [
    {"iterations": [{"type": "message"}, {"type": "advisor_message", "model": "claude-fable-5-2"}]},   # a 2nd model
    {"iterations": [{"type": "compaction", "input_tokens": 9}]},                                        # a pass
    {"iterations": [{"type": "message"}, {"type": "message"}]},
    {"iterations": "many"},
    {"iterations": [7]},
    {"service_tier": "priority"},
    {"speed": "fast"},
    {"inference_geo": "us"},
    {"server_tool_use": {"web_search_requests": 1, "code_execution_requests": 2}},
    {"server_tool_use": {"mystery_requests": True}},
])
def test_usage_that_reports_unpriced_spend_is_refused(extra):
    base = {"input_tokens": 10, "output_tokens": 5}
    with pytest.raises(mm.MeteringError):
        mm.usage_from_api({**base, **extra})
    with pytest.raises(mm.MeteringError):
        mm.StreamMeter().feed({"type": "message_start", "message": {"usage": {**base, **extra}}})


def test_usage_shapes_that_carry_no_extra_spend_are_accepted():
    for extra in ({"iterations": None}, {"iterations": []}, {"iterations": [{"type": "message", "input_tokens": 10}]},
                  {"service_tier": "standard"}, {"speed": "standard"}, {"inference_geo": "global"},
                  {"server_tool_use": {"web_search_requests": 2, "web_fetch_requests": 5, "other_requests": 0}}):
        u = mm.usage_from_api({"input_tokens": 10, "output_tokens": 5, **extra})
        assert (u.input_tokens, u.output_tokens) == (10, 5)
    assert mm.usage_from_api({"server_tool_use": {"web_search_requests": 2, "web_fetch_requests": 5}}).web_search_requests == 2


def test_a_stream_total_never_reprices_the_cache_write_split():
    start = {"type": "message_start", "message": {"usage": {
        "input_tokens": 10, "cache_creation_input_tokens": 4_000,
        "cache_creation": {"ephemeral_5m_input_tokens": 3_000, "ephemeral_1h_input_tokens": 1_000}}}}

    def after(delta_usage):
        m = mm.StreamMeter()
        m.feed(start)
        m.feed({"type": "message_delta", "usage": delta_usage})
        return m.usage.cache_write_5m_tokens, m.usage.cache_write_1h_tokens

    assert after({"output_tokens": 9}) == (3_000, 1_000)
    assert after({"cache_creation_input_tokens": 4_000}) == (3_000, 1_000)          # the same total: the split stays
    assert after({"cache_creation_input_tokens": 4_500}) == (3_000, 1_500)          # more: priced at the dearer rate
    assert after({"cache_creation_input_tokens": 9, "cache_creation": {"ephemeral_1h_input_tokens": 9}}) == (0, 9)
    with pytest.raises(mm.MeteringError, match="went down"):
        after({"cache_creation_input_tokens": 3_999})                               # never silently cheaper
    # a stream whose start reported no cache writes at all: a later bare total is a default-TTL write
    m = mm.StreamMeter()
    m.feed({"type": "message_start", "message": {"usage": {"input_tokens": 1}}})
    m.feed({"type": "message_delta", "usage": {"cache_creation_input_tokens": 70}})
    assert (m.usage.cache_write_5m_tokens, m.usage.cache_write_1h_tokens) == (70, 0)
