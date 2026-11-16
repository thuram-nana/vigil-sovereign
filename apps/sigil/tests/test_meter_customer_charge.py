"""Pricing design §0 W2a — the gateway meter records each response's CUSTOMER charge in milli-credits.

Every ``usage`` line a priced meter writes carries ``charge_mc`` (the published rate card applied to the confirmed
usage) and the ``rates`` that applied; every ``open`` line carries ``reserved_mc`` (the request's worst-case customer
charge). Nothing is admitted differently in W2a: admission still runs on the grant's provider-cost cap. Pins:
  * a confirmed response is charged its rate-card lines exactly, and the pending charge returns to zero;
  * a response the meter could not read is charged its reservation (design §10.4) and flagged;
  * the unreported part of a cut-off response, a request whose outcome is unknown (hold), a released request and a
    dead process's leftover (orphan) are never charged (invariant I9);
  * a replay from disk gives the same charged / pending totals as the live meter;
  * a meter with no rate card records no customer charge (its usage is reported unpriced);
  * the statement shows the charge and rates RECORDED with each response, even after the card changes, and its
    lines always add up to the charge (invariant I4).

Mutation-verify targets:
  * charge the held (cut-off) part                     -> test_a_cut_off_response_is_charged_only_what_it_reported
  * charge a hold / an orphan                          -> test_unknown_outcomes_are_never_charged
  * skip max(.., reserved_mc) on an unreadable response -> test_an_unreadable_response_is_charged_its_reservation
  * forget to drop pending_mc on settle                -> test_a_confirmed_response_is_charged_its_rate_card_lines
  * re-price recorded usage with the current card      -> test_the_statement_keeps_the_rates_that_applied
"""
from __future__ import annotations

import json

import pytest

from sigil import model_gateway as gw
from sigil.ui import billing
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant
from vigil_core.rate_card import DEFAULT_RATE_CARD, rate_card

NOW = 2_000.0
OUT_PRICE = 25_000                       # nano-USD per output token (the provider's $25 / MTok)


def _grant(gid: str = "0") -> ModelGrant:
    return ModelGrant(grant_id=gid * 32, org_id="org_a", engagement_slug="cust_x", nonce="n-1",
                      model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 12, not_after=NOW + 86_400,
                      issued_at=NOW - 60)


def _worst(out_tokens: int) -> int:
    return DEFAULT_RATE_CARD.request_worst_mc(2_000, 0, out_tokens)


def _lines(meter_dir, g):
    return [json.loads(x) for x in (meter_dir / f"{g.meter_id}.jsonl").read_text().splitlines()]


def _reserve(m, g, *, max_out: int = 40):
    rid, reserved, why = m.reserve(g, max_out * OUT_PRICE, OUT_PRICE, now=NOW, worst_mc=_worst)
    assert why == "", why
    return rid, reserved


def test_a_confirmed_response_is_charged_its_rate_card_lines(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, _ = _reserve(m, g)
    opened = _lines(tmp_path, g)[-1]
    assert opened["kind"] == "open" and opened["reserved_mc"] == _worst(40)
    assert m.totals(g.meter_id).pending_mc == _worst(40)
    usage = mm.Usage(input_tokens=1_000, output_tokens=200)
    m.commit(g, rid, usage, 123, request_id="req_1", now=NOW)
    used = _lines(tmp_path, g)[-1]
    assert used["charge_mc"] == 2_500 and used["rates"] == {"input_tokens": [1_250_000, 1_000_000],
                                                            "output_tokens": [6_250_000, 1_000_000]}
    t = m.totals(g.meter_id)
    assert (t.charged_mc, t.pending_mc, t.cost_nano) == (2_500, 0, 123)    # cost stays the internal account (I10)


def test_an_unreadable_response_is_charged_its_reservation(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, reserved = _reserve(m, g)
    m.commit(g, rid, mm.Usage(), reserved, request_id="req_x", now=NOW, charge_reservation=True)
    used = _lines(tmp_path, g)[-1]
    assert used["charged_reservation"] is True and used["charge_mc"] == _worst(40) > 0
    assert m.totals(g.meter_id).charged_mc == _worst(40)


def test_a_cut_off_response_is_charged_only_what_it_reported(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, reserved = _reserve(m, g)
    reported = mm.Usage(input_tokens=1_000, output_tokens=8)
    m.commit(g, rid, reported, 5_200_000, request_id="req_c", now=NOW, held_nano=reserved - 5_200_000)
    expected, _ = DEFAULT_RATE_CARD.charge(reported)
    t = m.totals(g.meter_id)
    assert t.charged_mc == expected and t.unconfirmed_nano == reserved - 5_200_000 and t.pending_mc == 0


def test_unknown_outcomes_are_never_charged(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, reserved = _reserve(m, g)
    m.commit(g, rid, mm.Usage(), 0, request_id="", now=NOW, held_nano=reserved)    # what _Ticket.hold writes
    rid2, _ = _reserve(m, g)
    m.release(g, rid2, now=NOW)
    t = m.totals(g.meter_id)
    assert (t.charged_mc, t.pending_mc) == (0, 0)
    assert "charge_mc" not in _lines(tmp_path, g)[-1]                     # a release carries no charge
    # a dead gateway's leftover: the restarted gateway orphans it; the customer is never charged for it
    dead = gw.GrantMeter(tmp_path / "d", gateway=True, rate_card=DEFAULT_RATE_CARD)
    _reserve(dead, g)
    dead.shutdown()
    live = gw.GrantMeter(tmp_path / "d", gateway=True, rate_card=DEFAULT_RATE_CARD)
    try:
        t = live.totals(g.meter_id)
        assert [ln["kind"] for ln in _lines(tmp_path / "d", g)] == ["open", "orphan"]
        assert (t.charged_mc, t.pending_mc) == (0, 0) and t.unconfirmed_nano > 0
    finally:
        live.shutdown()


def test_a_replay_gives_the_live_totals(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, _ = _reserve(m, g)
    m.commit(g, rid, mm.Usage(output_tokens=100), 2_500_000, request_id="r", now=NOW)
    _reserve(m, g)                                                        # still in flight
    live = m.totals(g.meter_id)
    disk = gw.GrantMeter(tmp_path).verify(g.meter_id)
    assert (disk.charged_mc, disk.pending_mc) == (live.charged_mc, live.pending_mc) == (625, _worst(40))


def test_a_meter_without_a_rate_card_records_no_charge(tmp_path):
    m = gw.GrantMeter(tmp_path)
    g = _grant()
    rid, _ = _reserve(m, g)
    m.commit(g, rid, mm.Usage(output_tokens=100), 2_500_000, request_id="r", now=NOW)
    opened, used = _lines(tmp_path, g)
    assert "reserved_mc" not in opened and "charge_mc" not in used and "rates" not in used
    t = m.totals(g.meter_id)
    assert t.charged_mc == 0 and t.unpriced_usage == mm.Usage(output_tokens=100)


def test_the_statement_keeps_the_rates_that_applied(tmp_path, monkeypatch):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, _ = _reserve(m, g)
    m.commit(g, rid, mm.Usage(input_tokens=1_000), 1, request_id="r", now=NOW)
    # the owner later doubles the input rate: recorded usage keeps the rate it was charged at
    doc = {"ai": {"input_tokens": "2500", "output_tokens": "6250", "cache_read_tokens": "125",
                  "cache_write_5m_tokens": "1563", "cache_write_1h_tokens": "2500", "web_searches": "2.5"},
           "worker_minute": "1"}
    monkeypatch.setenv("VIGIL_RATE_CARD", json.dumps(doc))
    (rec,) = m.usage_records(g.meter_id)
    lines, amount = billing._priced_lines(rec, rate_card())
    assert amount == 1_250 and [(ln["unit"], ln["rate"], ln["credits"]) for ln in lines] == [
        ("input_tokens", "1250.000", "1.250")]
    # a record from before W2a has no recorded charge: it is priced with the card in force
    legacy = {"ts": NOW, "usage": mm.Usage(input_tokens=1_000)}
    assert billing._priced_lines(legacy, rate_card())[1] == 2_500


def test_an_unreadable_response_has_its_own_statement_line(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, reserved = _reserve(m, g)
    m.commit(g, rid, mm.Usage(), reserved, request_id="r", now=NOW, charge_reservation=True)
    (rec,) = m.usage_records(g.meter_id)
    lines, amount = billing._priced_lines(rec, DEFAULT_RATE_CARD)
    assert amount == _worst(40) and sum(ln["amount_mc"] for ln in lines) == amount
    assert lines[-1]["unit"] == "reserved_maximum"


@pytest.mark.parametrize("bad", ["{", json.dumps({"ai": {}, "worker_minute": "1"})])
def test_a_malformed_rate_card_stops_the_gateway_config(monkeypatch, bad):
    from vigil_core.rate_card import RateCardError
    monkeypatch.setenv("VIGIL_RATE_CARD", bad)
    with pytest.raises(RateCardError):
        rate_card()
    assert issubclass(RateCardError, ValueError)        # start_from_env refuses to start on a ValueError (logged)
