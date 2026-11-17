"""PRICING G1 — the model gateway's loss alarm becomes an owner UNIT ALERT. ``unit_alerts.gateway_loss_alarm`` reads
the inert ``$SIGIL_HOME/alarms/gateway-loss.json`` (no sigil import, FATAL-2) and ``run_alert_monitor`` emits and
pushes it exactly once per cycle while it is open.
"""
from __future__ import annotations

import json

from vigil_integration import unit_alerts as ua


def _write(home, record):
    p = home / "alarms" / "gateway-loss.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(record if isinstance(record, str) else json.dumps(record), encoding="utf-8")
    return p


def test_no_alarm_is_no_unit_alert(tmp_path):
    assert ua.gateway_loss_alarm(tmp_path) is None


def test_an_open_alarm_is_an_error_alarm(tmp_path):
    _write(tmp_path, {"v": 1, "tripped": True, "day": "2026-11-17", "confirmed_nano": 1, "unconfirmed_nano": 9})
    alarm = ua.gateway_loss_alarm(tmp_path)
    assert alarm is not None and alarm.severity == "error" and alarm.kind == ua.GATEWAY_LOSS_ALARM_KIND
    assert "2026-11-17" in alarm.detail


def test_an_unreadable_record_is_surfaced(tmp_path):
    _write(tmp_path, "{broken")
    alarm = ua.gateway_loss_alarm(tmp_path)
    assert alarm is not None and "cannot be read" in alarm.detail


def test_the_monitor_emits_and_pushes_the_loss_alarm(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    _write(tmp_path / "home", {"v": 1, "tripped": True, "day": "2026-11-17", "confirmed_nano": 1,
                               "unconfirmed_nano": 9})

    class _Sink:
        def __init__(self):
            self.emitted = []

        def emit(self, alarm):
            self.emitted.append(alarm)

    class _Notifier:
        push_configured = True

        def __init__(self):
            self.pushed = []

        def deliver(self, alarm, *, now=None):
            self.pushed.append(alarm)
            return type("R", (), {"delivered": True})()

    sink, notifier = _Sink(), _Notifier()
    # a fresh state dir so no scheduled-unit heartbeats add alarms of their own
    summary = ua.run_alert_monitor(tmp_path / "state", sink=sink, notifier=notifier)
    loss = [a for a in sink.emitted if a.kind == ua.GATEWAY_LOSS_ALARM_KIND]
    assert len(loss) == 1 and summary["alarms"] >= 1
    assert any(a.kind == ua.GATEWAY_LOSS_ALARM_KIND for a in notifier.pushed)
