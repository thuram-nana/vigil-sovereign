"""W8-1 (#467) — heartbeat staleness alarms for every HA/scheduled unit.

The through-line every test defends: every scheduled unit and timer must have a heartbeat; an ABSENT or STALE
heartbeat is a staleness alarm (fail-CLOSED — the whole point is that a silent HA failure becomes loud); a
unit that RAN and FAILED raises exactly ONE failure alarm; a clean fleet raises NOTHING (the monitor is not a
no-op that always alarms); alerting is push-based to a configured destination; and the alerting path's OWN
failure to deliver is detectable (a dead-man), never swallowed. Everything uses an injected clock and an
in-process fake transport — no real systemd, no real network.

FAILS WITHOUT THE CHANGE: this whole module imports ``vigil_integration.unit_alerts``, which does not exist on
a pre-W8-1 tree — collection ImportErrors. And ``test_registry_covers_every_installed_timer`` fails on any
tree that ships a timer without registering it (the enumeration guard). Boundary-safe (no sigil/framework), so
it runs in the required sovereign integration CI leg.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from vigil_integration import unit_alerts as ua
from vigil_integration.integrity_verifier import Alarm, AlarmSink

_REPO = Path(__file__).resolve().parents[2]
_SYSTEMD = _REPO / "infra" / "systemd"

T0 = 1_000_000.0  # a fixed injected "now"


# ── helpers ─────────────────────────────────────────────────────────────────────────────────────────────
def _write_all_healthy(state_dir: Path, *, now: float = T0) -> None:
    for u in ua.registry():
        ua.write_unit_heartbeat(state_dir, u.unit, now=now, ok=True, result="success")


class _RecordingSink(AlarmSink):
    def __init__(self) -> None:
        self.alarms: list[Alarm] = []
        super().__init__(log_path=None, callbacks=[self.alarms.append], echo=False)


class _FakeTransport:
    """A fake webhook transport (url, payload, timeout) -> status. Records every POST."""

    def __init__(self, status: int = 200, *, raise_exc: Exception | None = None) -> None:
        self.status = status
        self.raise_exc = raise_exc
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, payload: bytes, timeout: float) -> int:
        self.calls.append((url, json.loads(payload.decode("utf-8"))))
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.status


class _FakeExecRunner:
    def __init__(self, rc: int = 0) -> None:
        self.rc = rc
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv: list[str], payload: bytes, timeout: float) -> int:
        self.calls.append((argv, json.loads(payload.decode("utf-8"))))
        return self.rc


def _notifier(state_dir: Path, targets: list) -> ua.Notifier:
    return ua.Notifier(targets, local_log=state_dir / "alert-delivery.jsonl",
                       delivery_heartbeat_path=state_dir / "alert-delivery-heartbeat.json", echo=False)


# ── enumeration guard: every installed timer is monitored ───────────────────────────────────────────────
# The alarm monitor's OWN timer is not a monitored-unit heartbeat: the monitor does not heartbeat-monitor
# itself (that would be circular — a dead monitor cannot alarm on its own death). Its liveness is covered by
# the delivery dead-man (a stale alert-delivery heartbeat, read by a watchdog / `vigil alerts --status`).
_NOT_MONITORED_UNITS = {"vigil-alerts.timer"}


def test_registry_covers_every_installed_timer():
    """Fail-closed enumeration: every ``infra/systemd/vigil-*.timer`` (except the monitor's own) must have a
    registry entry, so a new scheduled unit added without registration fails CI instead of going silently
    unmonitored."""
    installed = sorted(p.name for p in _SYSTEMD.glob("vigil-*.timer") if p.name not in _NOT_MONITORED_UNITS)
    assert installed, "expected vigil-*.timer files under infra/systemd (anchor drift?)"
    registered_timers = {u.timer for u in ua.registry()}
    missing = [t for t in installed if t not in registered_timers]
    assert not missing, f"timers with no unit_alerts registry entry (unmonitored, fail-closed): {missing}"


def test_registered_units_and_timers_actually_exist_on_disk():
    for u in ua.registry():
        assert (_SYSTEMD / u.unit).exists(), f"{u.unit} registered but no unit file"
        assert (_SYSTEMD / u.timer).exists(), f"{u.timer} registered but no timer file"


# ── heartbeat write/read roundtrip ──────────────────────────────────────────────────────────────────────
def test_heartbeat_write_is_atomic_roundtrip(tmp_path):
    ua.write_unit_heartbeat(tmp_path, "vigil-backup.service", now=T0, ok=True, result="success")
    beat = ua.read_unit_heartbeat(tmp_path, "vigil-backup.service")
    assert beat is not None and beat["ok"] is True and beat["epoch"] == T0
    # no leftover temp file
    assert not list(tmp_path.glob("*.tmp"))


def test_unit_heartbeat_cli_maps_service_result(tmp_path):
    # systemd $SERVICE_RESULT == "success" -> ok; anything else -> failed.
    assert ua.cmd_unit_heartbeat("vigil-backup.service", result="success", state_dir=str(tmp_path)) == 0
    assert ua.read_unit_heartbeat(tmp_path, "vigil-backup.service")["ok"] is True
    ua.cmd_unit_heartbeat("vigil-backup.service", result="exit-code", state_dir=str(tmp_path))
    assert ua.read_unit_heartbeat(tmp_path, "vigil-backup.service")["ok"] is False
    # explicit override wins over --result
    ua.cmd_unit_heartbeat("vigil-backup.service", result="success", ok=False, state_dir=str(tmp_path))
    assert ua.read_unit_heartbeat(tmp_path, "vigil-backup.service")["ok"] is False


def test_unit_heartbeat_reads_service_result_from_env(tmp_path, monkeypatch):
    """systemd exports $SERVICE_RESULT into the ExecStopPost env (it is not command-line-expandable), so a
    bare `vigil unit-heartbeat %n` must pick it up."""
    monkeypatch.setenv("SERVICE_RESULT", "success")
    ua.cmd_unit_heartbeat("vigil-ha-mirror.service", state_dir=str(tmp_path))
    assert ua.read_unit_heartbeat(tmp_path, "vigil-ha-mirror.service")["ok"] is True
    monkeypatch.setenv("SERVICE_RESULT", "exit-code")
    ua.cmd_unit_heartbeat("vigil-ha-mirror.service", state_dir=str(tmp_path))
    beat = ua.read_unit_heartbeat(tmp_path, "vigil-ha-mirror.service")
    assert beat["ok"] is False and beat["result"] == "exit-code"


# ── the monitor: negative control + fail-closed ─────────────────────────────────────────────────────────
def test_clean_fleet_raises_no_alarm(tmp_path):
    """NEGATIVE CONTROL that the gate is not a no-op: a fresh, successful heartbeat for every unit fires
    ZERO alarms."""
    _write_all_healthy(tmp_path, now=T0)
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0 + 60, sink=sink)
    assert summary["alarms"] == 0
    assert summary["healthy"] == len(ua.registry())
    assert sink.alarms == []


def test_absent_heartbeat_is_a_staleness_alarm_fail_closed(tmp_path):
    """FAIL-CLOSED: an empty state dir (no unit has ever run) alarms for EVERY unit, never silent-healthy."""
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink)
    assert summary["alarms"] == len(ua.registry())
    assert summary["stale"] == len(ua.registry())  # ABSENT counts under the staleness dead-man
    assert all(a.kind == "unit-heartbeat-stale" for a in sink.alarms)
    states = {s["unit"]: s["state"] for s in summary["statuses"]}
    assert set(states.values()) == {ua.ABSENT}


def test_failing_one_unit_produces_exactly_one_alert(tmp_path):
    """NEGATIVE CONTROL (acceptance): deliberately fail ONE unit; assert EXACTLY one alert, and that it is a
    unit-failed alarm naming that unit — the other (healthy) units are proven NOT rejected in the same run."""
    _write_all_healthy(tmp_path, now=T0)
    ua.write_unit_heartbeat(tmp_path, "vigil-backup.service", now=T0, ok=False, result="exit-code")
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0 + 60, sink=sink)
    assert summary["alarms"] == 1
    assert summary["failed"] == 1
    assert len(sink.alarms) == 1
    a = sink.alarms[0]
    assert a.kind == "unit-failed"
    assert "vigil-backup.service" in a.detail


def test_stopping_a_timer_produces_a_staleness_alarm(tmp_path):
    """NEGATIVE CONTROL (acceptance): a unit whose timer stopped (its heartbeat is older than its bound)
    raises EXACTLY one staleness alarm while every other, fresh unit stays silent."""
    _write_all_healthy(tmp_path, now=T0)
    spec = ua._spec_for("vigil-ha-mirror.service")
    old = T0 - spec.staleness_bound_s() - 1
    ua.write_unit_heartbeat(tmp_path, "vigil-ha-mirror.service", now=old, ok=True, result="success")
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink)
    assert summary["alarms"] == 1
    assert len(sink.alarms) == 1
    a = sink.alarms[0]
    assert a.kind == "unit-heartbeat-stale"
    assert "vigil-ha-mirror.service" in a.detail


def test_staleness_bound_is_per_unit_not_global(tmp_path):
    """A 15-minute mirror and a daily backup cannot share one bound. A heartbeat 30 minutes old exceeds the
    mirror's ~23.5-minute bound (STALE) but is far inside the daily backup's ~36-hour bound (HEALTHY) —
    proving the cadence-derived, per-unit bound, not one global threshold."""
    age = 30 * 60  # 30 minutes (> mirror bound 1410s, << backup bound 131400s)
    ua.write_unit_heartbeat(tmp_path, "vigil-ha-mirror.service", now=T0 - age, ok=True, result="success")
    ua.write_unit_heartbeat(tmp_path, "vigil-backup.service", now=T0 - age, ok=True, result="success")
    mirror = ua.unit_status(tmp_path, ua._spec_for("vigil-ha-mirror.service"), now=T0)
    backup = ua.unit_status(tmp_path, ua._spec_for("vigil-backup.service"), now=T0)
    assert mirror.state == ua.STALE
    assert backup.state == ua.HEALTHY


def test_malformed_heartbeat_is_failclosed_stale_never_crashes(tmp_path):
    p = tmp_path / "vigil-backup.service.hb.json"
    p.write_text('{"unit": "vigil-backup.service", "ok": true}', encoding="utf-8")  # no epoch
    st = ua.unit_status(tmp_path, ua._spec_for("vigil-backup.service"), now=T0)
    assert st.state == ua.STALE and st.is_alarm

    p.write_text("{ this is not json", encoding="utf-8")
    st2 = ua.unit_status(tmp_path, ua._spec_for("vigil-backup.service"), now=T0)
    assert st2.state == ua.ABSENT and st2.is_alarm  # unreadable == never-ran, fail-closed


def test_unknown_unit_is_watched_failclosed(tmp_path):
    summary = ua.run_alert_monitor(tmp_path, watched=["vigil-brand-new.service"], now=T0)
    assert summary["checked"] == 1
    assert summary["alarms"] == 1  # unknown + no heartbeat => still alarmed, never dropped


# ── push notifier + delivery dead-man ───────────────────────────────────────────────────────────────────
def test_push_delivers_and_advances_delivery_heartbeat(tmp_path):
    transport = _FakeTransport(status=200)
    notifier = _notifier(tmp_path, [ua.WebhookNotifyTarget("https://hook.example/alert", transport=transport)])
    alarm = Alarm(ts="t", severity="critical", kind="unit-failed", home=str(tmp_path), detail="x failed")
    res = notifier.deliver(alarm, now=T0)
    assert res.delivered and res.succeeded == 1 and res.push_configured
    assert transport.calls and transport.calls[0][1]["kind"] == "unit-failed"
    # local durable log always written; delivery heartbeat advanced on success
    assert (tmp_path / "alert-delivery.jsonl").exists()
    stale, _ = ua.delivery_is_stale(tmp_path, now=T0 + 60)
    assert stale is False


def test_delivery_failure_is_detectable_deadman(tmp_path):
    """ACCEPTANCE: alert delivery failure is itself detectable. Every push target fails => deliver reports
    NOT delivered, a distinct alert-delivery-failed marker is written locally, and the delivery heartbeat is
    NOT advanced, so the delivery dead-man goes stale."""
    transport = _FakeTransport(raise_exc=OSError("connection refused"))
    notifier = _notifier(tmp_path, [ua.WebhookNotifyTarget("https://down.example/alert", transport=transport)])
    alarm = Alarm(ts="t", severity="critical", kind="unit-failed", home=str(tmp_path), detail="x failed")
    res = notifier.deliver(alarm, now=T0)
    assert res.delivered is False and res.succeeded == 0 and res.failures
    # a distinct delivery-failure marker is on the durable local log
    lines = [json.loads(x) for x in (tmp_path / "alert-delivery.jsonl").read_text().splitlines()]
    kinds = [r.get("kind") for r in lines]
    assert "alert-delivery-failed" in kinds
    # the delivery heartbeat never advanced -> the dead-man is stale (nothing has ever delivered)
    assert not (tmp_path / "alert-delivery-heartbeat.json").exists()
    stale, detail = ua.delivery_is_stale(tmp_path, now=T0)
    assert stale is True


def test_delivery_heartbeat_goes_stale_after_window(tmp_path):
    transport = _FakeTransport(status=204)
    notifier = _notifier(tmp_path, [ua.WebhookNotifyTarget("https://hook.example/a", transport=transport)])
    notifier.deliver(Alarm(ts="t", severity="critical", kind="unit-failed", home="h", detail="d"), now=T0)
    fresh, _ = ua.delivery_is_stale(tmp_path, now=T0 + 100, max_staleness_s=3600)
    stale, _ = ua.delivery_is_stale(tmp_path, now=T0 + 10_000, max_staleness_s=3600)
    assert fresh is False and stale is True


def test_webhook_non_2xx_is_a_delivery_failure(tmp_path):
    transport = _FakeTransport(status=500)
    notifier = _notifier(tmp_path, [ua.WebhookNotifyTarget("https://hook.example/a", transport=transport)])
    res = notifier.deliver(Alarm(ts="t", severity="critical", kind="k", home="h", detail="d"), now=T0)
    assert res.delivered is False and res.succeeded == 0


def test_exec_target_success_and_failure(tmp_path):
    ok_runner = _FakeExecRunner(rc=0)
    bad_runner = _FakeExecRunner(rc=3)
    n_ok = _notifier(tmp_path, [ua.ExecNotifyTarget(["sendmail", "-t"], runner=ok_runner)])
    n_bad = _notifier(tmp_path, [ua.ExecNotifyTarget(["sendmail", "-t"], runner=bad_runner)])
    a = Alarm(ts="t", severity="critical", kind="k", home="h", detail="d")
    assert n_ok.deliver(a, now=T0).delivered is True
    assert ok_runner.calls[0][0] == ["sendmail", "-t"]
    assert n_bad.deliver(a, now=T0).delivered is False


def test_one_bad_target_does_not_silence_the_others(tmp_path):
    good = _FakeTransport(status=200)
    bad = _FakeTransport(raise_exc=OSError("boom"))
    notifier = _notifier(tmp_path, [
        ua.WebhookNotifyTarget("https://bad.example/a", transport=bad),
        ua.WebhookNotifyTarget("https://good.example/a", transport=good),
    ])
    res = notifier.deliver(Alarm(ts="t", severity="critical", kind="k", home="h", detail="d"), now=T0)
    assert res.succeeded == 1 and res.attempted == 2 and res.delivered is True
    assert good.calls  # the good target still received it


def test_monitor_pushes_exactly_one_alarm_per_bad_unit(tmp_path):
    _write_all_healthy(tmp_path, now=T0)
    ua.write_unit_heartbeat(tmp_path, "vigil-backup.service", now=T0, ok=False, result="exit-code")
    transport = _FakeTransport(status=200)
    notifier = _notifier(tmp_path, [ua.WebhookNotifyTarget("https://hook.example/a", transport=transport)])
    summary = ua.run_alert_monitor(tmp_path, now=T0 + 60, notifier=notifier)
    assert summary["alarms"] == 1
    assert summary["delivered"] == 1
    assert len(transport.calls) == 1  # exactly one push for the one failing unit


def test_require_push_alarms_when_no_destination_configured(tmp_path):
    _write_all_healthy(tmp_path, now=T0)
    notifier = _notifier(tmp_path, [])  # no push targets
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0 + 60, sink=sink, notifier=notifier, require_push=True)
    assert summary["push_configured"] is False
    assert any(a.kind == "alert-config" for a in sink.alarms)
    # and WITHOUT --require-push the same clean fleet is silent (the require-push alarm is not a no-op)
    sink2 = _RecordingSink()
    s2 = ua.run_alert_monitor(tmp_path, now=T0 + 60, sink=sink2, notifier=notifier, require_push=False)
    assert s2["alarms"] == 0


def test_monitor_summary_delivery_ok_flags_undeliverable_alarm(tmp_path):
    # A failing unit + a dead push path => there IS an alarm but it could not be delivered => delivery_ok False.
    _write_all_healthy(tmp_path, now=T0)
    ua.write_unit_heartbeat(tmp_path, "vigil-backup.service", now=T0, ok=False, result="exit-code")
    dead = _FakeTransport(raise_exc=OSError("no route"))
    notifier = _notifier(tmp_path, [ua.WebhookNotifyTarget("https://down.example/a", transport=dead)])
    summary = ua.run_alert_monitor(tmp_path, now=T0 + 60, notifier=notifier)
    assert summary["alarms"] == 1 and summary["delivered"] == 0
    assert summary["delivery_ok"] is False


# ── periodic loop determinism ───────────────────────────────────────────────────────────────────────────
def test_loop_uses_injected_clock_and_cadence(tmp_path):
    _write_all_healthy(tmp_path, now=T0)
    ua.write_unit_heartbeat(tmp_path, "vigil-ha-mirror.service", now=T0, ok=True, result="success")
    ticks = iter([T0 + 100, T0 + 100_000])  # cycle 1: mirror fresh; cycle 2: mirror stale (>1410s)
    slept: list[float] = []
    summary = ua.run_alert_monitor_loop(
        tmp_path, cycles=2, interval=5.0, sleep=slept.append, now_fn=lambda: next(ticks))
    assert summary["cycles_run"] == 2
    assert slept == [5.0]  # slept exactly between the two cycles, not after the last
    assert summary["total_alarms"] >= 1  # the mirror went stale on the second cycle


# ── FATAL-2 boundary ────────────────────────────────────────────────────────────────────────────────────
def test_module_never_imports_sigil_or_framework():
    src = (_REPO / "integration" / "vigil_integration" / "unit_alerts.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(import|from)\s+sigil", src, re.M), "FATAL-2: unit_alerts must not import sigil"
    assert not re.search(r"^\s*(import|from)\s+framework", src, re.M), "FATAL-2: must not import framework"
