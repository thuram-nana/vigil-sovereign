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


# The security-critical fail-closed guarantee is that the ALWAYS-ON set (watched unconditionally) and the
# OPTIONAL set (watched only when early-armed or run-proven) are each pinned BY NAME here — independently of the
# `optional` flag the code reads. Without this pin the fail-closed tests derive their expectation from the same
# flag, so a regression flipping an always-on unit (e.g. the spine-integrity verifier) to optional would pass CI
# while that unit goes silently unwatched. Changing either set is therefore a DELIBERATE edit to this pin.
_PINNED_OPTIONAL = {"vigil-finding-drain.service", "vigil-settle-drain.service",
                    "vigil-upgrade-drill.service",   # DEP-3: opt-in drill (deliberate pin edit)
                    "vigil-billing-drain.service",   # Front B: opt-in money-IN drain (deliberate pin edit)
                    "vigil-billing-drain-stripe.service"}   # Stripe lane of the money-IN drain (deliberate pin edit)
_PINNED_ALWAYS_ON = {
    "vigil-backup.service", "vigil-backup-push.service", "vigil-backup-drill.service",
    "vigil-ha-mirror.service", "vigil-integrity.service", "vigil-posture.service",
    "vigil-reprove.service", "vigil-twin.service", "vigil-checkpoint.service",
}


def test_optional_set_is_exactly_the_saas_drains_and_the_upgrade_drill():
    assert {s.unit for s in ua.registry() if s.optional} == _PINNED_OPTIONAL


def test_always_on_set_is_pinned_by_name_not_by_flag():
    """Flip an always-on unit to optional and THIS fails — independently of any flag-derived count."""
    assert {s.unit for s in ua.registry() if not s.optional} == _PINNED_ALWAYS_ON
    # the two partitions exactly cover the registry (no unit in neither / both)
    assert _PINNED_ALWAYS_ON | _PINNED_OPTIONAL == {s.unit for s in ua.registry()}
    assert not (_PINNED_ALWAYS_ON & _PINNED_OPTIONAL)


def test_registry_rejects_an_optional_unit_with_empty_enable_env():
    """Import-time invariant: an optional unit with no enable_env (unwatchable before its first heartbeat, with
    no knob to early-arm it) is refused — so a flip-to-optional cannot silently darken a fail-closed guard."""
    bad = ua.UnitSpec("vigil-integrity.service", "vigil-integrity.timer", 900, 60, "x",
                      optional=True, enable_env="")
    with pytest.raises(AssertionError):
        ua._validate_registry((bad,))
    ua._validate_registry(ua.registry())   # the shipped registry satisfies it


def test_every_always_on_unit_absent_alarms_with_all_enable_flags_cleared(tmp_path, monkeypatch):
    """Flag-INDEPENDENT fail-closed proof: with EVERY drain enable flag cleared and an empty state dir, the
    monitor alarms ABSENT for each PINNED always-on unit (by name), while the opted-out drains stay unwatched."""
    monkeypatch.delenv("VIGIL_FINDING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_DRAIN_ENABLED", raising=False)
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=_RecordingSink())
    states = {s["unit"]: s["state"] for s in summary["statuses"]}
    for unit in _PINNED_ALWAYS_ON:
        assert states.get(unit) == ua.ABSENT, f"{unit} is not ABSENT-alarmed fail-closed"
    assert _PINNED_OPTIONAL.isdisjoint(states)   # opted-out drains not watched


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
def _always_on() -> list:
    """The units watched fail-closed on EVERY host (optional=False). Opted-out OPTIONAL drains are not here."""
    return [s for s in ua.registry() if not s.optional]


def test_clean_fleet_raises_no_alarm(tmp_path, monkeypatch):
    """NEGATIVE CONTROL that the gate is not a no-op: a fresh, successful heartbeat for every unit fires
    ZERO alarms. The optional drains have fresh heartbeats here (they have run on this host), so they are
    watched healthy too — heartbeat presence arms the dead-man even with the monitor flags unset."""
    monkeypatch.delenv("VIGIL_FINDING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_DRAIN_ENABLED", raising=False)
    _write_all_healthy(tmp_path, now=T0)   # writes a beat for EVERY unit, drains included
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0 + 60, sink=sink)
    assert summary["alarms"] == 0
    assert summary["healthy"] == len(ua.registry())  # drains with a fresh beat are watched (run-state coupling)
    assert sink.alarms == []


def test_absent_heartbeat_is_a_staleness_alarm_fail_closed(tmp_path, monkeypatch):
    """FAIL-CLOSED: an empty state dir (no unit has ever run) alarms for EVERY ALWAYS-ON unit, never
    silent-healthy. An opted-out OPTIONAL drain is not watched (no false ABSENT alarm for a drain the host
    does not run) — proven separately by test_optional_drain_is_fail_closed_watched_once_enabled."""
    monkeypatch.delenv("VIGIL_FINDING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_DRAIN_ENABLED", raising=False)
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink)
    always_on = {s.unit for s in _always_on()}
    assert summary["alarms"] == len(always_on)
    assert summary["stale"] == len(always_on)  # ABSENT counts under the staleness dead-man
    assert all(a.kind == "unit-heartbeat-stale" for a in sink.alarms)
    states = {s["unit"]: s["state"] for s in summary["statuses"]}
    assert set(states.keys()) == always_on             # EVERY always-on unit watched; opted-out drains absent
    assert set(states.values()) == {ua.ABSENT}


def test_optional_drain_not_watched_when_disabled(tmp_path, monkeypatch):
    """The enablement gate: with its flag UNSET, an optional SaaS drain is NOT in the default watched set, so
    an empty state dir raises NO alarm for it — a host that never enabled the pipeline is not false-alarmed."""
    monkeypatch.delenv("VIGIL_FINDING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_DRAIN_ENABLED", raising=False)
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=_RecordingSink())
    watched = {s["unit"] for s in summary["statuses"]}
    assert "vigil-finding-drain.service" not in watched
    assert "vigil-settle-drain.service" not in watched


def test_optional_drain_is_fail_closed_watched_once_enabled(tmp_path, monkeypatch):
    """Once its flag is set, an optional drain IS watched fail-closed exactly like an always-on unit: an
    absent heartbeat is an ABSENT staleness alarm. So an ENABLED drain that stops firing is caught."""
    monkeypatch.setenv("VIGIL_FINDING_DRAIN_ENABLED", "1")
    monkeypatch.delenv("VIGIL_SETTLE_DRAIN_ENABLED", raising=False)
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=_RecordingSink())
    states = {s["unit"]: s["state"] for s in summary["statuses"]}
    assert states.get("vigil-finding-drain.service") == ua.ABSENT   # enabled ⇒ fail-closed watched
    assert "vigil-settle-drain.service" not in states               # still opted out


def test_optional_drain_with_a_heartbeat_is_watched_even_with_the_flag_unset(tmp_path, monkeypatch):
    """RUN-STATE COUPLING: a drain that has RUN (a heartbeat on disk) is watched even though the monitor's
    enable flag was never set — so a fresh beat counts the drain HEALTHY, and (crucially) a later stall will
    be caught. Without this, an enabled-but-monitor-unflagged drain was invisible to the dead-man."""
    monkeypatch.delenv("VIGIL_FINDING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_DRAIN_ENABLED", raising=False)
    ua.write_unit_heartbeat(tmp_path, "vigil-settle-drain.service", now=T0, ok=True, result="success")
    summary = ua.run_alert_monitor(tmp_path, now=T0 + 60, sink=_RecordingSink())
    states = {s["unit"]: s["state"] for s in summary["statuses"]}
    assert states.get("vigil-settle-drain.service") == ua.HEALTHY     # heartbeat present ⇒ watched (flag unset)
    assert "vigil-finding-drain.service" not in states                # no beat, no flag ⇒ still opted out


def test_enabled_money_drain_that_stops_is_caught_even_with_the_monitor_flag_unset(tmp_path, monkeypatch):
    """THE CLOSED HOLE (money safety): the settle drain fired (wrote a heartbeat) but its monitor enable flag
    was never set; it then STOPS and its beat goes stale. The dead-man MUST still raise exactly one staleness
    alarm — a stuck settle drain is money owed either way. Before the run-state coupling this was SILENT."""
    monkeypatch.delenv("VIGIL_FINDING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_DRAIN_ENABLED", raising=False)
    _write_all_healthy(tmp_path, now=T0)   # every other unit fresh-healthy, so the stale settle drain is isolated
    spec = ua._spec_for("vigil-settle-drain.service")
    old = T0 - spec.staleness_bound_s() - 1
    ua.write_unit_heartbeat(tmp_path, "vigil-settle-drain.service", now=old, ok=True, result="success")
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink)
    assert summary["alarms"] == 1
    assert len(sink.alarms) == 1
    a = sink.alarms[0]
    assert a.kind == "unit-heartbeat-stale"
    assert "vigil-settle-drain.service" in a.detail


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


def test_future_dated_heartbeat_is_failclosed_stale_and_alarms(tmp_path):
    """RED-PEN REGRESSION (#467): a heartbeat dated meaningfully in the FUTURE (clock skew, a backward-set
    clock, or a forged timestamp) must be fail-closed STALE and raise a staleness alarm — NOT silently
    HEALTHY. Before the fix, ``age = now - epoch`` went negative, slipped under the ``age > bound`` test, and
    the unit reported HEALTHY: a silent staleness fail-OPEN that contradicts the never-silently-healthy
    guarantee. Reverting the guard turns this red (state == HEALTHY, no alarm)."""
    _write_all_healthy(tmp_path, now=T0)
    spec = ua._spec_for("vigil-ha-mirror.service")
    # A beat dated well beyond both the skew tolerance and the unit's own randomized smear, into the future.
    future = T0 + max(spec.randomized_delay_s, ua.SKEW_TOLERANCE_S) + 3600
    ua.write_unit_heartbeat(tmp_path, "vigil-ha-mirror.service", now=future, ok=True, result="success")

    st = ua.unit_status(tmp_path, spec, now=T0)
    assert st.state == ua.STALE and st.is_alarm
    assert st.age_s is not None and st.age_s < 0  # negative age == future-dated
    assert "future" in st.detail.lower()

    # ...and it drives EXACTLY one alarm through the monitor while every other, fresh unit stays silent.
    sink = _RecordingSink()
    summary = ua.run_alert_monitor(tmp_path, now=T0, sink=sink)
    assert summary["alarms"] == 1
    assert len(sink.alarms) == 1
    a = sink.alarms[0]
    assert a.kind == "unit-heartbeat-stale"
    assert "vigil-ha-mirror.service" in a.detail


def test_future_dated_heartbeat_within_skew_tolerance_stays_healthy(tmp_path):
    """The guard tolerates benign NTP jitter: a heartbeat only slightly ahead of ``now`` (inside the skew
    tolerance) is still HEALTHY, so the fix does not flap on ordinary clock drift."""
    _write_all_healthy(tmp_path, now=T0)
    spec = ua._spec_for("vigil-ha-mirror.service")
    ua.write_unit_heartbeat(tmp_path, "vigil-ha-mirror.service",
                            now=T0 + ua.SKEW_TOLERANCE_S - 1, ok=True, result="success")
    st = ua.unit_status(tmp_path, spec, now=T0)
    assert st.state == ua.HEALTHY and not st.is_alarm


def test_future_dated_delivery_heartbeat_is_failclosed_stale(tmp_path):
    """RED-PEN REGRESSION (#467), delivery path: a delivery heartbeat dated in the FUTURE must be treated as
    stale (fail-closed), not silently reported as a healthy alerting path. Reverting the delivery-path guard
    turns this red (stale is False)."""
    transport = _FakeTransport(status=204)
    notifier = _notifier(tmp_path, [ua.WebhookNotifyTarget("https://hook.example/a", transport=transport)])
    # Deliver at a future timestamp so the recorded delivery heartbeat is dated ahead of the check's ``now``.
    future = T0 + ua.SKEW_TOLERANCE_S + 3600
    notifier.deliver(Alarm(ts="t", severity="critical", kind="unit-failed", home="h", detail="d"), now=future)
    stale, detail = ua.delivery_is_stale(tmp_path, now=T0)
    assert stale is True
    assert "future" in detail.lower()


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
    # The two planes the sovereign-side monitor must never pull in: the sovereign app (sigil) and the whole
    # offense engine (framework / strix / crucible). The guard matches any of them so a future refactor that
    # routes through an offense module at import scope reds here, not silently at runtime.
    assert not re.search(r"^\s*(import|from)\s+(sigil|framework|strix|crucible)\b", src, re.M), \
        "FATAL-2: unit_alerts must import no sigil / framework / strix / crucible module at module scope"
