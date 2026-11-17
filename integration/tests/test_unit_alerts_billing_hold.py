"""W5 — the unit-alert monitor pushes a ``billing-hold`` alarm for each customer org on a billing hold.

The sovereign reversal ledger writes ``$SIGIL_HOME/alarms/billing-hold.json``; the alert monitor reads it (inert JSON,
no sovereign import — FATAL-2) and raises one pushed alarm per held org per cycle, until a top-up repays what it owes.
An unreadable record raises one. No record ⇒ the cycle and its summary are exactly as before.

Mutation-verify targets:
  * the probe dropped                           -> test_a_held_org_raises_one_alarm_per_cycle
  * an org missing an owed value passes          -> test_an_unreadable_hold_record_raises_one_alarm
  * the OFF (no record) path grows the summary   -> test_no_hold_record_leaves_the_cycle_unchanged
"""
from __future__ import annotations

import json
from pathlib import Path

from vigil_integration import unit_alerts as ua
from vigil_integration.integrity_verifier import Alarm, AlarmSink

T0 = 1_000_000.0


class _Sink(AlarmSink):
    def __init__(self) -> None:
        self.alarms: list[Alarm] = []
        super().__init__(log_path=None, callbacks=[self.alarms.append], echo=False)


def _all_healthy(state_dir: Path) -> None:
    for u in ua.registry():
        ua.write_unit_heartbeat(state_dir, u.unit, now=T0, ok=True, result="success")


def _hold_file(tmp_path, body) -> Path:
    p = tmp_path / "hold.json"
    p.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return p


def test_no_hold_record_leaves_the_cycle_unchanged(tmp_path):
    _all_healthy(tmp_path)
    sink = _Sink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink, billing_hold_path=tmp_path / "absent.json")
    assert summary["alarms"] == 0 and "billing_holds" not in summary and not sink.alarms


def test_a_held_org_raises_one_alarm_per_cycle(tmp_path):
    _all_healthy(tmp_path)
    hold = _hold_file(tmp_path, {"v": 1, "held": [{"org_id": "org_a", "owed": 300, "since": 1.0},
                                                  {"org_id": "org_b", "owed": 50, "since": 2.0}]})
    sink = _Sink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink, billing_hold_path=hold)
    held = [a for a in sink.alarms if a.kind == ua.BILLING_HOLD_KIND]
    assert len(held) == 2 and summary["billing_holds"] == 2 and summary["alarms"] == 2
    assert {a.checks[0]["org_id"] for a in held} == {"org_a", "org_b"}
    assert any("300 credits" in a.detail for a in held)


def test_the_hold_alarm_is_pushed_to_the_notifier(tmp_path):
    _all_healthy(tmp_path)
    hold = _hold_file(tmp_path, {"v": 1, "held": [{"org_id": "org_a", "owed": 300}]})
    pushed: list = []

    class _T:
        def __call__(self, url, payload, timeout):
            pushed.append(json.loads(payload.decode("utf-8")))
            return 200
    notifier = ua.Notifier([ua.WebhookNotifyTarget("https://hook.example/x", transport=_T())],
                           local_log=tmp_path / "d.jsonl", delivery_heartbeat_path=tmp_path / "dhb.json", echo=False)
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=_Sink(), notifier=notifier, billing_hold_path=hold)
    assert summary["delivered"] >= 1 and any(p.get("kind") == ua.BILLING_HOLD_KIND for p in pushed)


def test_an_unreadable_hold_record_raises_one_alarm(tmp_path):
    _all_healthy(tmp_path)
    hold = _hold_file(tmp_path, "{not json")
    sink = _Sink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink, billing_hold_path=hold)
    held = [a for a in sink.alarms if a.kind == ua.BILLING_HOLD_KIND]
    assert len(held) == 1 and summary["billing_holds"] == 1 and "cannot be read" in held[0].detail


def test_read_billing_holds_parses_and_fails_closed(tmp_path):
    assert ua.read_billing_holds(tmp_path / "absent.json") == []
    good = _hold_file(tmp_path, {"v": 1, "held": [{"org_id": "o", "owed": 5}]})
    assert ua.read_billing_holds(good) == [("o", 5)]
    bad = _hold_file(tmp_path, {"v": 1, "held": [{"org_id": "o"}]})
    assert ua.read_billing_holds(bad) is None                 # a malformed entry -> None (fail-closed)
