"""PRICING G1 — the loss alarm (``sigil.gateway_loss``): the 2% rule over the day's confirmed / unconfirmed
provider spend, the threshold edges (exactly 2%, just above), the durable alarm file and the owner acknowledgement.
"""
from __future__ import annotations

import json

from sigil import gateway_loss as gl

# a fixed clock, pinned to noon UTC of a day so the ledger's day never rolls mid-test
NOON = 1_763_380_800.0            # a fixed noon-UTC instant
DAY = gl._utc_day(NOON)           # the UTC day that instant falls on
TOMORROW_DAY = gl._utc_day(NOON + 86_400)


def _clock(t=NOON):
    return lambda: t


def _ledger(tmp_path, t=NOON):
    return gl.LossLedger(tmp_path / "alarms" / "gateway-loss.json", clock=_clock(t))


def test_within_two_percent_nothing_trips():
    led = _ledger_tmp()
    # confirmed 100000 nano, 2% = 2000; unconfirmed 2000 is EXACTLY 2% -> not tripped (strict >)
    led.set_day(DAY, confirmed=100_000, unconfirmed=2_000, now=NOON)
    assert not led.tripped(NOON)
    assert led.state(NOON)["tripped"] is False


def test_just_above_two_percent_trips():
    led = _ledger_tmp()
    led.set_day(DAY, confirmed=100_000, unconfirmed=2_001, now=NOON)   # one nano over 2%
    assert led.tripped(NOON)
    assert led.state(NOON)["tripped"] is True


def test_the_exact_boundary_in_small_integers():
    led = _ledger_tmp()
    led.set_day(DAY, confirmed=50, unconfirmed=1, now=NOON)   # 100*1=100, 2*50=100 -> not > -> clean
    assert not led.tripped(NOON)
    led.set_day(DAY, confirmed=49, unconfirmed=1, now=NOON)   # 100*1=100 > 2*49=98 -> trips
    assert led.tripped(NOON)


def test_any_unconfirmed_with_zero_confirmed_trips():
    led = _ledger_tmp()
    led.set_day(DAY, confirmed=0, unconfirmed=1, now=NOON)
    assert led.tripped(NOON)
    led.set_day(DAY, confirmed=0, unconfirmed=0, now=NOON)    # nothing at all is clean
    assert not led.tripped(NOON)


def test_the_alarm_file_is_written_and_cleared():
    import tempfile
    import pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    led = gl.LossLedger(d / "alarms" / "gateway-loss.json", clock=_clock())
    led.set_day(DAY, confirmed=100, unconfirmed=50, now=NOON)          # 100*50 > 2*100 -> tripped
    rec = gl.read_alarm(d)
    assert rec is not None and rec["tripped"] is True and rec["day"] == DAY
    assert rec["confirmed_nano"] == 100 and rec["unconfirmed_nano"] == 50
    led.set_day(DAY, confirmed=10_000, unconfirmed=50, now=NOON)       # confirmed caught up: within 2% now
    assert gl.read_alarm(d) is None                                    # the file is cleared


def test_a_new_day_starts_clean():
    led = _ledger_tmp()
    led.set_day(DAY, confirmed=0, unconfirmed=100, now=NOON)
    assert led.tripped(NOON)
    tomorrow = NOON + 86_400
    assert not led.tripped(tomorrow)                                   # a different UTC day: nothing recorded yet


def test_an_owner_acknowledgement_resumes_the_day_durably():
    import tempfile
    import pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    alarm = d / "alarms" / "gateway-loss.json"
    led = gl.LossLedger(alarm, clock=_clock())
    led.set_day(DAY, confirmed=0, unconfirmed=100, now=NOON)
    assert led.tripped(NOON) and gl.read_alarm(d) is not None
    entry = led.acknowledge("owner@example", now=NOON)
    assert entry["by"] == "owner@example" and entry["day"] == DAY
    assert not led.tripped(NOON)                                       # resumes
    assert gl.read_alarm(d) is None                                    # the alarm file is cleared
    # a SEPARATE ledger instance (a running gateway) honours the durable ack marker even while still breaching
    other = gl.LossLedger(alarm, clock=_clock())
    other.set_day(DAY, confirmed=0, unconfirmed=200, now=NOON)         # still way over 2%
    assert not other.tripped(NOON)                                     # the durable marker says the day is acked
    assert gl.read_alarm(d) is None
    # the ack log records who/when
    log = alarm.parent / "gateway-loss.ack.jsonl"
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert rows and rows[-1]["by"] == "owner@example"


def test_the_ack_re_arms_the_next_day():
    import tempfile
    import pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    alarm = d / "alarms" / "gateway-loss.json"
    led = gl.LossLedger(alarm, clock=_clock())
    led.set_day(DAY, confirmed=0, unconfirmed=100, now=NOON)
    led.acknowledge("owner", now=NOON)
    tomorrow = NOON + 86_400
    led.set_day(TOMORROW_DAY, confirmed=0, unconfirmed=100, now=tomorrow)
    assert led.tripped(tomorrow)                                       # a new day's own breach is not acked
    assert gl.read_alarm(d) is not None


def test_read_alarm_flags_an_unreadable_record():
    import tempfile
    import pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    p = d / "alarms" / "gateway-loss.json"
    p.parent.mkdir(parents=True)
    p.write_text("{not json")
    assert gl.read_alarm(d) == {"unreadable": True}


# a module-level tmp helper (pytest tmp_path is function-scoped; these use their own)
def _ledger_tmp():
    import tempfile
    import pathlib
    return gl.LossLedger(pathlib.Path(tempfile.mkdtemp()) / "alarms" / "gateway-loss.json", clock=_clock())
