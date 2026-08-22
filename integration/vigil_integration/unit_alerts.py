"""unit_alerts — heartbeat staleness alarms for every HA/scheduled systemd unit (W8-1 #467).

The defect this closes: nothing monitored the HA pair or any timer unit. A backup, an off-host push, a
recovery drill or the HA mirror-sync could fail — or its timer could stop firing — for MONTHS, and the only
way to discover it was for a human to run ``journalctl`` by hand. A silent HA gap is the worst kind: you
learn the standby was never synced at the moment you need to fail over to it.

This module gives every scheduled unit a **heartbeat** and a **staleness monitor**:

  * Each unit writes a heartbeat when it runs (:func:`write_unit_heartbeat`, called from the unit's systemd
    ``ExecStopPost=`` hook via ``vigil unit-heartbeat``). The heartbeat records the run's ``SERVICE_RESULT``,
    so a unit that RAN and FAILED is distinguishable from one that has not run at all.
  * :func:`run_alert_monitor` enumerates the whole unit registry and, for each watched unit, alarms when the
    heartbeat is **absent** (never ran / removed — fail-CLOSED), **stale** (older than the unit's cadence-
    derived bound — the timer stopped firing), or records a **failed** last run. A clean, fresh heartbeat
    for every unit raises nothing (the monitor is not a no-op that always alarms).
  * Alerting is **push-based**: alarms are forwarded to a configured destination (a webhook, or an exec sink
    such as ``sendmail`` / a pager CLI) built from the environment (:func:`build_notifier_from_env`).
  * **Alert delivery is itself dead-man'd.** Every alarm is ALSO appended to a durable LOCAL log (so a total
    push outage is still discoverable on the box), a failed push writes a distinct ``alert-delivery-failed``
    marker, and a successful push advances a **delivery heartbeat** whose own staleness
    (:func:`delivery_is_stale`) means "we have stopped being able to deliver alerts" — the failure of the
    alerting path is observable, not silent.

FATAL-2 (the two-env boundary): this is the OFFENSE/integration plane. It NEVER imports ``sigil`` or the
``framework``. It reads/writes only inert on-disk JSON heartbeats and reuses the :class:`Alarm` /
:class:`AlarmSink` primitives from :mod:`integrity_verifier` (W6-7), which themselves import only
``vigil_core``. It holds no owner key and reaches no target.

HONEST SCOPE (do not overclaim): the *logic* here — enumeration, staleness bounds, fail-closed absent-is-an-
alarm, exactly-one-alert-per-failed-unit, the delivery dead-man — is fully exercised by the tests with an
injected clock and an in-process fake transport. What is **live-only** (and cannot be exercised in CI):
whether real systemd actually invokes the ``ExecStopPost`` hook on every unit, and whether a real webhook /
sendmail endpoint accepts the push. Those are wired (``infra/systemd/*`` + ``vigil-alerts.{service,timer}``)
but their firing is asserted only against fakes here.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

# Reuse the W6-7 alarm primitives (the hint's "reuse AlarmSink/heartbeat"). integrity_verifier imports ONLY
# vigil_core — importing it here keeps this module boundary-clean (no sigil, no framework). FATAL-2 intact.
from .integrity_verifier import Alarm, AlarmSink

# ── unit status vocabulary ──────────────────────────────────────────────────────────────────────────────
HEALTHY = "healthy"     # a fresh heartbeat whose last run succeeded
FAILED = "failed"       # a fresh heartbeat whose last run FAILED (ran, but the unit reported failure)
STALE = "stale"         # a heartbeat older than the unit's staleness bound (the timer stopped firing)
ABSENT = "absent"       # no heartbeat at all (never ran / removed) — fail-CLOSED: treated as an alarm

# States that raise an alarm. ABSENT and STALE are BOTH staleness alarms (dead-man); FAILED is a run-failed
# alarm. Only HEALTHY is silent — so a monitor that fired for a clean fleet would be a proven no-op bug.
_ALARM_STATES = {FAILED, STALE, ABSENT}

# ── staleness-bound tuning (env-overridable, fail-closed defaults) ──────────────────────────────────────
# A unit is STALE when its heartbeat is older than its cadence-derived bound. The bound must exceed one full
# scheduling period plus the timer's randomized smear (else a legitimately-delayed run flaps), but stay well
# under two periods (else a wholly-missed cycle hides). We use cadence*1.5 + randomized_delay, which fires
# after ~one-and-a-half missed periods: a single skipped run is caught without false positives from jitter.
_STALENESS_CADENCE_FACTOR = 1.5
# A heartbeat dated meaningfully in the FUTURE is not fresh — it means the writer's clock is skewed, was set
# backward, or the timestamp was forged. Left unguarded, a future ``epoch`` yields a negative age that slips
# under the ``age > bound`` staleness test and is reported HEALTHY — a silent fail-OPEN that contradicts the
# never-silently-healthy guarantee. We tolerate a small skew (NTP jitter, brief drift) and treat anything
# more future-dated than that (or, per unit, than its own randomized timer smear, whichever is larger) as
# fail-closed STALE. This is symmetric with the past-dated ``age > bound`` staleness bound.
SKEW_TOLERANCE_S = 300
# A unit not in the registry (e.g. a brand-new timer whose author forgot to register it) gets this
# conservative bound so it is monitored fail-closed rather than silently unwatched. 25h > a daily cadence.
_DEFAULT_UNKNOWN_STALENESS_S = 25 * 3600
# The delivery dead-man: if no alert has been successfully pushed in this long, the alerting path itself is
# considered down (a watchdog — doctor / another host — reads the delivery heartbeat and alarms).
_DELIVERY_STALENESS_S_ENV = "VIGIL_ALERT_DELIVERY_MAX_STALENESS_S"
_DEFAULT_DELIVERY_STALENESS_S = 26 * 3600


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


# ── the unit registry ───────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class UnitSpec:
    """One scheduled unit we monitor. ``cadence_s`` and ``randomized_delay_s`` mirror the unit's timer (see
    ``infra/systemd/<name>.timer``); ``staleness_s`` is the derived alarm bound (env-overridable per unit via
    ``VIGIL_ALERT_MAX_STALENESS_<UNIT>`` where <UNIT> is the unit name upper-cased with non-alnum → ``_``)."""
    unit: str                 # the full systemd unit id, e.g. "vigil-backup.service" (matches %n)
    timer: str                # the paired timer, e.g. "vigil-backup.timer"
    cadence_s: int            # nominal seconds between fires (from the timer's OnCalendar/OnUnitActiveSec)
    randomized_delay_s: int   # the timer's RandomizedDelaySec smear
    description: str

    @property
    def _env_key(self) -> str:
        safe = "".join(c if c.isalnum() else "_" for c in self.unit).upper()
        return f"VIGIL_ALERT_MAX_STALENESS_{safe}"

    def staleness_bound_s(self) -> int:
        derived = int(self.cadence_s * _STALENESS_CADENCE_FACTOR) + self.randomized_delay_s
        return _env_int(self._env_key, derived)


# Curated to match the committed timer files under infra/systemd/. The cadence values are the OnCalendar /
# OnUnitActiveSec of each timer; a guard test (test_unit_alerts.py) asserts EVERY infra/systemd/*.timer has an
# entry here, so a new timer added without registration fails CI rather than going silently unmonitored.
HA_UNITS: tuple[UnitSpec, ...] = (
    UnitSpec("vigil-backup.service", "vigil-backup.timer", 24 * 3600, 1800,
             "two-plane portable local backup (daily)"),
    UnitSpec("vigil-backup-push.service", "vigil-backup-push.timer", 24 * 3600, 1800,
             "off-host push of the encrypted backup (daily)"),
    UnitSpec("vigil-backup-drill.service", "vigil-backup-drill.timer", 7 * 24 * 3600, 1800,
             "backup recovery drill — proves a backup actually restores (weekly)"),
    UnitSpec("vigil-ha-mirror.service", "vigil-ha-mirror.timer", 15 * 60, 60,
             "HA passive mirror sync of the active's spine (every 15m)"),
    UnitSpec("vigil-integrity.service", "vigil-integrity.timer", 15 * 60, 60,
             "continuous spine integrity verifier (every 15m)"),
    UnitSpec("vigil-posture.service", "vigil-posture.timer", 30 * 60, 0,
             "signed posture re-proof series (every 30m)"),
    UnitSpec("vigil-reprove.service", "vigil-reprove.timer", 6 * 3600, 300,
             "continuous re-proof of confirmed findings (every 6h)"),
    UnitSpec("vigil-checkpoint.service", "vigil-checkpoint.timer", 15 * 60, 60,
             "scheduled off-box witnessed-checkpoint emitter — anti-rollback anchor (every 15m)"),
)

_BY_NAME = {u.unit: u for u in HA_UNITS}


def registry() -> tuple[UnitSpec, ...]:
    return HA_UNITS


def _spec_for(unit: str) -> Optional[UnitSpec]:
    return _BY_NAME.get(unit)


# ── state-dir resolution ────────────────────────────────────────────────────────────────────────────────
def default_state_dir() -> Path:
    """Where per-unit heartbeats live. ``VIGIL_ALERT_STATE_DIR`` overrides; otherwise ``$XDG_STATE_HOME`` (or
    ``~/.local/state``) ``/vigil/unit-heartbeats``. The systemd units get this writable via ``StateDirectory=
    vigil`` even under ``ProtectSystem=strict`` (no bespoke ReadWritePaths needed)."""
    env = os.environ.get("VIGIL_ALERT_STATE_DIR")
    if env:
        return Path(env).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else Path("~/.local/state").expanduser()
    return base / "vigil" / "unit-heartbeats"


def _heartbeat_path(state_dir: Path, unit: str) -> Path:
    # One file per unit. The unit id is used verbatim as the stem; systemd unit ids are filesystem-safe.
    return state_dir / f"{unit}.hb.json"


def _now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


# ── heartbeat write / read ──────────────────────────────────────────────────────────────────────────────
def write_unit_heartbeat(state_dir: str | os.PathLike, unit: str, *, now: Optional[float] = None,
                         ok: bool, result: str = "", detail: str = "") -> Path:
    """Persist that ``unit`` RAN at ``now`` with success=``ok``. Atomic (temp + os.replace) so a reader never
    sees a half-written beat. Returns the heartbeat path. Called from the unit's ``ExecStopPost`` hook."""
    now = time.time() if now is None else now
    sd = Path(state_dir).expanduser()
    p = _heartbeat_path(sd, unit)
    beat = {"unit": unit, "ts": _now_iso(now), "epoch": float(now), "ok": bool(ok),
            "result": result or ("success" if ok else "failed"), "detail": detail}
    sd.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(beat, sort_keys=True), encoding="utf-8")
    os.replace(str(tmp), str(p))
    return p


def read_unit_heartbeat(state_dir: str | os.PathLike, unit: str) -> Optional[dict]:
    p = _heartbeat_path(Path(state_dir).expanduser(), unit)
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


@dataclass(frozen=True)
class UnitStatus:
    unit: str
    state: str                # HEALTHY | FAILED | STALE | ABSENT
    detail: str
    age_s: Optional[float] = None
    staleness_bound_s: Optional[int] = None

    @property
    def is_alarm(self) -> bool:
        return self.state in _ALARM_STATES

    @property
    def severity(self) -> str:
        # A run that FAILED and a mirror/timer that stopped are both operationally critical for HA.
        return "critical"

    @property
    def alarm_kind(self) -> str:
        return "unit-failed" if self.state == FAILED else "unit-heartbeat-stale"

    def to_dict(self) -> dict:
        return {"unit": self.unit, "state": self.state, "detail": self.detail,
                "age_s": self.age_s, "staleness_bound_s": self.staleness_bound_s}


def unit_status(state_dir: str | os.PathLike, spec: UnitSpec, *, now: Optional[float] = None) -> UnitStatus:
    """Classify one unit's current heartbeat. Fail-CLOSED: an ABSENT or undated/unreadable heartbeat is a
    staleness alarm, never silently healthy."""
    now = time.time() if now is None else now
    bound = spec.staleness_bound_s()
    beat = read_unit_heartbeat(state_dir, spec.unit)
    if beat is None:
        return UnitStatus(spec.unit, ABSENT,
                          f"no heartbeat for {spec.unit} — it has never run (or its heartbeat was removed); "
                          f"expected every ~{spec.cadence_s}s (dead-man, fail-closed)",
                          age_s=None, staleness_bound_s=bound)
    epoch = beat.get("epoch")
    if not isinstance(epoch, (int, float)):
        return UnitStatus(spec.unit, STALE,
                          f"{spec.unit} heartbeat has no valid timestamp — treating as stale (fail-closed)",
                          age_s=None, staleness_bound_s=bound)
    age = now - float(epoch)
    if age < -max(spec.randomized_delay_s, SKEW_TOLERANCE_S):
        return UnitStatus(spec.unit, STALE,
                          f"{spec.unit} heartbeat is dated {-age:.0f}s in the FUTURE — clock skew, a "
                          f"backward-set clock, or a forged timestamp; fail-closed (never silently healthy)",
                          age_s=age, staleness_bound_s=bound)
    if age > bound:
        return UnitStatus(spec.unit, STALE,
                          f"{spec.unit} heartbeat is {age:.0f}s old (> {bound}s) — the unit/timer has stopped "
                          f"running (dead-man)", age_s=age, staleness_bound_s=bound)
    if not bool(beat.get("ok", False)):
        return UnitStatus(spec.unit, FAILED,
                          f"{spec.unit} last run FAILED ({beat.get('result', '?')}) {beat.get('detail', '')}"
                          .strip(), age_s=age, staleness_bound_s=bound)
    return UnitStatus(spec.unit, HEALTHY, f"{spec.unit} healthy ({age:.0f}s old)", age_s=age,
                      staleness_bound_s=bound)


def collect_statuses(state_dir: str | os.PathLike, *, watched: Optional[list[str]] = None,
                     now: Optional[float] = None) -> list[UnitStatus]:
    """The current status of every watched unit (default: the whole registry). Read-only — fires no alarms."""
    now = time.time() if now is None else now
    specs = _watched_specs(watched)
    return [unit_status(state_dir, s, now=now) for s in specs]


def _watched_specs(watched: Optional[list[str]]) -> list[UnitSpec]:
    if watched is None:
        return list(HA_UNITS)
    out: list[UnitSpec] = []
    for name in watched:
        spec = _spec_for(name)
        # An unknown unit name is still watched, fail-closed, with a conservative bound — never dropped.
        out.append(spec or UnitSpec(name, "", _DEFAULT_UNKNOWN_STALENESS_S, 0, "unregistered unit"))
    return out


# ── push notifier + delivery dead-man ───────────────────────────────────────────────────────────────────
class NotifyError(Exception):
    """A push target failed to deliver (non-2xx, non-zero exit, transport error)."""


@dataclass
class DeliveryResult:
    delivered: bool           # at least one PUSH target accepted the alarm
    attempted: int            # push targets tried
    succeeded: int            # push targets that accepted
    failures: list[str] = field(default_factory=list)
    push_configured: bool = False

    def to_dict(self) -> dict:
        return {"delivered": self.delivered, "attempted": self.attempted, "succeeded": self.succeeded,
                "failures": self.failures, "push_configured": self.push_configured}


class ExecNotifyTarget:
    """Push by running a command with the alarm JSON on stdin (e.g. ``sendmail``, a pager CLI, a curl wrapper).
    A non-zero exit is a delivery FAILURE. ``runner`` is injectable so tests use a fake instead of a real
    subprocess."""

    def __init__(self, argv: list[str], *, timeout: float = 20.0,
                 runner: Optional[Callable[[list[str], bytes, float], int]] = None) -> None:
        self.argv = list(argv)
        self.timeout = timeout
        self._runner = runner or self._subprocess_runner

    @staticmethod
    def _subprocess_runner(argv: list[str], payload: bytes, timeout: float) -> int:
        proc = subprocess.run(argv, input=payload, timeout=timeout,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode

    def send(self, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        rc = self._runner(self.argv, body, self.timeout)
        if rc != 0:
            raise NotifyError(f"exec notify target {self.argv[0]!r} exited {rc}")

    def describe(self) -> str:
        return f"exec:{self.argv[0]}"


class WebhookNotifyTarget:
    """Push by HTTP POST of the alarm JSON to a URL. ``transport`` is injectable (default: urllib) so the
    delivery LOGIC is tested with a fake and the real network stays live-only. A non-2xx (or transport
    error) is a delivery FAILURE."""

    def __init__(self, url: str, *, timeout: float = 20.0,
                 transport: Optional[Callable[[str, bytes, float], int]] = None) -> None:
        self.url = url
        self.timeout = timeout
        self._transport = transport or self._urllib_transport

    @staticmethod
    def _urllib_transport(url: str, payload: bytes, timeout: float) -> int:
        import urllib.request
        req = urllib.request.Request(url, data=payload, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator-configured URL
            return int(getattr(resp, "status", 0) or resp.getcode())

    def send(self, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        try:
            status = self._transport(self.url, body, self.timeout)
        except Exception as exc:  # noqa: BLE001 — any transport error is a delivery failure
            raise NotifyError(f"webhook POST failed: {type(exc).__name__}: {exc}") from exc
        if not (200 <= int(status) < 300):
            raise NotifyError(f"webhook POST returned HTTP {status}")

    def describe(self) -> str:
        return f"webhook:{self.url}"


class Notifier:
    """Push alarms to configured destinations, with a LOCAL durable fallback and a delivery dead-man.

    Contract per :meth:`deliver`:
      * append the alarm to the durable local log (always — a total push outage stays discoverable on-box);
      * try every push target; count successes;
      * on any push success, advance the delivery heartbeat (last-successful-delivery time);
      * if push is configured but NOTHING succeeded, write a distinct ``alert-delivery-failed`` marker to the
        local log — the alerting path's own failure is recorded, not swallowed.
    """

    def __init__(self, push_targets: list[Any], *, local_log: str | os.PathLike,
                 delivery_heartbeat_path: str | os.PathLike, echo: bool = True) -> None:
        self.push_targets = list(push_targets)
        self.local_log = Path(local_log).expanduser()
        self.delivery_heartbeat_path = Path(delivery_heartbeat_path).expanduser()
        self.echo = echo

    @property
    def push_configured(self) -> bool:
        return len(self.push_targets) > 0

    def _append_local(self, record: dict) -> None:
        try:
            self.local_log.parent.mkdir(parents=True, exist_ok=True)
            with open(self.local_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError:
            pass  # a local-log write failure must not swallow the push path

    def _advance_delivery_heartbeat(self, now: float) -> None:
        p = self.delivery_heartbeat_path
        beat = {"ts": _now_iso(now), "epoch": float(now)}
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(json.dumps(beat, sort_keys=True), encoding="utf-8")
            os.replace(str(tmp), str(p))
        except OSError:
            pass

    def deliver(self, alarm: Alarm, *, now: Optional[float] = None) -> DeliveryResult:
        now = time.time() if now is None else now
        payload = alarm.to_dict()
        self._append_local({"kind": "alert", "delivered_at": _now_iso(now), **payload})
        failures: list[str] = []
        succeeded = 0
        for t in self.push_targets:
            describe = getattr(t, "describe", None)
            name = describe() if callable(describe) else type(t).__name__
            try:
                t.send(payload)
                succeeded += 1
            except Exception as exc:  # noqa: BLE001 — one bad target must not stop the others
                failures.append(f"{name}: {exc}")
        if self.echo:
            import sys
            print(f"ALERT [{alarm.severity}] {alarm.kind}: {alarm.detail} "
                  f"(pushed {succeeded}/{len(self.push_targets)})", file=sys.stderr)
        if succeeded > 0:
            self._advance_delivery_heartbeat(now)
        elif self.push_configured:
            # Push was configured but EVERY target failed: record the alerting path's own failure locally so a
            # watchdog / the delivery dead-man surfaces it even though the remote never heard about it.
            self._append_local({"kind": "alert-delivery-failed", "at": _now_iso(now),
                                "failures": failures, "alarm": payload})
        return DeliveryResult(delivered=succeeded > 0, attempted=len(self.push_targets),
                              succeeded=succeeded, failures=failures, push_configured=self.push_configured)


def build_notifier_from_env(state_dir: str | os.PathLike, *, echo: bool = True) -> Notifier:
    """Construct a :class:`Notifier` from the environment. Push destinations (any subset):
      * ``VIGIL_ALERT_WEBHOOK_URL`` — HTTP POST each alarm as JSON.
      * ``VIGIL_ALERT_EXEC`` — a command (shell-split) fed the alarm JSON on stdin (e.g. ``sendmail -t``).
    The durable local log and delivery heartbeat live under ``state_dir`` and are ALWAYS present."""
    import shlex
    sd = Path(state_dir).expanduser()
    targets: list[Any] = []
    url = os.environ.get("VIGIL_ALERT_WEBHOOK_URL", "").strip()
    if url:
        targets.append(WebhookNotifyTarget(url))
    exec_cmd = os.environ.get("VIGIL_ALERT_EXEC", "").strip()
    if exec_cmd:
        targets.append(ExecNotifyTarget(shlex.split(exec_cmd)))
    return Notifier(targets, local_log=sd / "alert-delivery.jsonl",
                    delivery_heartbeat_path=sd / "alert-delivery-heartbeat.json", echo=echo)


def read_delivery_heartbeat(state_dir: str | os.PathLike) -> Optional[dict]:
    p = Path(state_dir).expanduser() / "alert-delivery-heartbeat.json"
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def delivery_is_stale(state_dir: str | os.PathLike, *, now: Optional[float] = None,
                      max_staleness_s: Optional[int] = None) -> tuple[bool, str]:
    """The delivery dead-man: have we STOPPED being able to push alerts? STALE (True) when no alert has been
    successfully delivered within ``max_staleness_s``. Fail-CLOSED with a caveat: an ABSENT delivery
    heartbeat means either "no alert has ever needed delivering" (benign) or "we have never been able to
    deliver" (bad) — indistinguishable from the heartbeat alone, so it is reported as ``unknown`` (True,
    flagged) rather than silently OK. A watchdog treats unknown as worth surfacing, not as an outage."""
    now = time.time() if now is None else now
    max_staleness_s = (_env_int(_DELIVERY_STALENESS_S_ENV, _DEFAULT_DELIVERY_STALENESS_S)
                       if max_staleness_s is None else max_staleness_s)
    beat = read_delivery_heartbeat(state_dir)
    if beat is None:
        return True, ("no successful alert delivery on record — either nothing has needed alerting yet, or the "
                      "push path has never worked (unknown; surfaced fail-closed)")
    epoch = beat.get("epoch")
    if not isinstance(epoch, (int, float)):
        return True, "alert delivery heartbeat has no valid timestamp — treating as stale (fail-closed)"
    age = now - float(epoch)
    if age < -SKEW_TOLERANCE_S:
        return True, (f"alert delivery heartbeat is dated {-age:.0f}s in the FUTURE — clock skew, a "
                      f"backward-set clock, or a forged timestamp; treating as stale (fail-closed)")
    if age > max_staleness_s:
        return True, (f"last successful alert delivery was {age:.0f}s ago (> {max_staleness_s}s) — the alerting "
                      f"path has stopped delivering (dead-man)")
    return False, f"alert delivery path healthy (last success {age:.0f}s ago)"


# ── the monitor ─────────────────────────────────────────────────────────────────────────────────────────
def _default_alarm_log(state_dir: Path) -> Path:
    return state_dir / "unit-alarms.jsonl"


def run_alert_monitor(
    state_dir: str | os.PathLike,
    *,
    watched: Optional[list[str]] = None,
    now: Optional[float] = None,
    sink: Optional[AlarmSink] = None,
    notifier: Optional[Notifier] = None,
    require_push: bool = False,
) -> dict:
    """One monitor cycle: classify every watched unit; for each non-HEALTHY unit emit EXACTLY ONE alarm
    (durable local sink + push notifier); return a summary. Fail-CLOSED: an absent heartbeat is an alarm.

    ``require_push`` makes a missing push configuration itself an alarm (a monitor with nowhere to send is
    not "push-based alerting"). Returns ``{checked, healthy, failed, stale, alarms, delivered, push_configured,
    delivery_ok, delivery_detail, statuses}``."""
    now = time.time() if now is None else now
    sd = Path(state_dir).expanduser()
    sink = sink or AlarmSink(log_path=_default_alarm_log(sd))
    statuses = collect_statuses(sd, watched=watched, now=now)

    alarms = 0
    delivered = 0
    push_configured = bool(notifier and notifier.push_configured)

    # Fail-closed config check: alerting with no push destination is a gap the operator must see.
    if require_push and not push_configured:
        alarms += 1
        cfg = Alarm(ts=_now_iso(now), severity="error", kind="alert-config",
                    home=str(sd),
                    detail="alert monitor has NO push destination configured (set VIGIL_ALERT_WEBHOOK_URL "
                           "and/or VIGIL_ALERT_EXEC) — alarms would not reach anyone")
        sink.emit(cfg)
        if notifier is not None:
            res = notifier.deliver(cfg, now=now)
            delivered += 1 if res.delivered else 0

    for st in statuses:
        if not st.is_alarm:
            continue
        alarms += 1
        alarm = Alarm(ts=_now_iso(now), severity=st.severity, kind=st.alarm_kind, home=str(sd),
                      detail=st.detail, checks=[st.to_dict()])
        sink.emit(alarm)                       # exactly one durable local record per non-healthy unit
        if notifier is not None:
            res = notifier.deliver(alarm, now=now)  # exactly one push attempt per non-healthy unit
            delivered += 1 if res.delivered else 0

    delivery_stale, delivery_detail = delivery_is_stale(sd, now=now)
    return {
        "checked": len(statuses),
        "healthy": sum(1 for s in statuses if s.state == HEALTHY),
        "failed": sum(1 for s in statuses if s.state == FAILED),
        "stale": sum(1 for s in statuses if s.state in (STALE, ABSENT)),
        "alarms": alarms,
        "delivered": delivered,
        "push_configured": push_configured,
        # The delivery dead-man is only a hard "not ok" once something has needed delivering and could not be:
        # an unknown/absent delivery heartbeat with no alarms this cycle is benign.
        "delivery_ok": not (push_configured and alarms > 0 and delivered == 0),
        "delivery_stale": delivery_stale,
        "delivery_detail": delivery_detail,
        "statuses": [s.to_dict() for s in statuses],
        "state_dir": str(sd),
    }


def run_alert_monitor_loop(
    state_dir: str | os.PathLike,
    *,
    cycles: int = 1,
    interval: float = 0.0,
    sleep: Callable[[float], Any] = time.sleep,
    now_fn: Callable[[], float] = time.time,
    watched: Optional[list[str]] = None,
    sink: Optional[AlarmSink] = None,
    notifier: Optional[Notifier] = None,
    require_push: bool = False,
) -> dict:
    """Run ``cycles`` monitor cycles (``cycles<=0`` ⇒ forever) with an INJECTABLE cadence + clock. Returns the
    LAST cycle's summary plus ``cycles_run`` and cumulative ``total_alarms``."""
    sd = Path(state_dir).expanduser()
    sink = sink or AlarmSink(log_path=_default_alarm_log(sd))
    last: dict = {}
    total_alarms = 0
    i = 0
    forever = cycles <= 0
    while forever or i < cycles:
        now = now_fn()
        last = run_alert_monitor(sd, watched=watched, now=now, sink=sink, notifier=notifier,
                                 require_push=require_push)
        total_alarms += int(last.get("alarms", 0))
        i += 1
        if forever or i < cycles:
            sleep(interval)
    last = dict(last)
    last["cycles_run"] = i
    last["total_alarms"] = total_alarms
    return last


# ── CLI entry points (wired from vigil_integration.cli) ─────────────────────────────────────────────────
def cmd_unit_heartbeat(unit: str, *, result: str = "", ok: Optional[bool] = None,
                       state_dir: Optional[str] = None, detail: str = "") -> int:
    """`vigil unit-heartbeat <unit>` — the ExecStopPost hook each unit runs. systemd exports ``SERVICE_RESULT``
    into the ExecStopPost environment (it is NOT expandable on the unit's command line), so when neither
    ``--result`` nor ``--ok/--failed`` is given we read it from ``$SERVICE_RESULT`` (``success`` ⇒ ok). This
    lets the unit file carry a bare ``ExecStopPost=… vigil unit-heartbeat %n``."""
    sd = Path(state_dir).expanduser() if state_dir else default_state_dir()
    if not result:
        result = os.environ.get("SERVICE_RESULT", "")
    if ok is None:
        ok = result.strip().lower() == "success"
    write_unit_heartbeat(sd, unit, ok=ok, result=result, detail=detail)
    return 0


def cmd_alerts(*, state_dir: Optional[str], watch: bool, cycles: int, interval: float,
               status_only: bool, require_push: bool, as_json: bool) -> int:
    """`vigil alerts` — the staleness monitor. Reads the environment for push destinations
    (build_notifier_from_env). ``--status`` is read-only; otherwise one cycle (or ``--watch`` for a loop).
    Exits non-zero when any unit is in an alarm state (so systemd OnFailure / a required check catches it)."""
    import sys
    sd = Path(state_dir).expanduser() if state_dir else default_state_dir()

    if status_only:
        statuses = collect_statuses(sd)
        stale, detail = delivery_is_stale(sd)
        if as_json:
            print(json.dumps({"statuses": [s.to_dict() for s in statuses],
                              "delivery_stale": stale, "delivery_detail": detail}, indent=2, sort_keys=True))
        else:
            print(f"VIGIL unit alerts — status of {len(statuses)} scheduled units")
            for s in statuses:
                mark = {HEALTHY: "OK ", FAILED: "!! ", STALE: ".. ", ABSENT: "-- "}.get(s.state, "?? ")
                print(f"  {mark}{s.unit}: {s.state} — {s.detail}")
            print(f"  delivery: {'STALE' if stale else 'ok'} — {detail}")
        return 0 if all(not s.is_alarm for s in statuses) else 1

    notifier = build_notifier_from_env(sd)
    if not notifier.push_configured:
        print("vigil alerts: WARNING — no push destination configured (VIGIL_ALERT_WEBHOOK_URL / "
              "VIGIL_ALERT_EXEC). Alarms go to the durable local log only.", file=sys.stderr)
    if watch:
        summary = run_alert_monitor_loop(sd, cycles=cycles, interval=interval, notifier=notifier,
                                         require_push=require_push)
    else:
        summary = run_alert_monitor(sd, notifier=notifier, require_push=require_push)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary.get("alarms", 0) == 0 else 1


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="vigil alerts",
                                 description="heartbeat staleness alarms for every HA/scheduled unit")
    ap.add_argument("--state-dir", default=None)
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--cycles", type=int, default=0)
    ap.add_argument("--interval", type=float, default=300.0)
    ap.add_argument("--status", action="store_true", dest="status_only")
    ap.add_argument("--require-push", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args(argv)
    return cmd_alerts(state_dir=args.state_dir, watch=args.watch, cycles=args.cycles, interval=args.interval,
                      status_only=args.status_only, require_push=args.require_push, as_json=args.as_json)


if __name__ == "__main__":
    raise SystemExit(main())
