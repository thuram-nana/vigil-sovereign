"""DEP-2 (#73) — the READINESS GATE for bring-up: "is this box actually ready?", answered honestly.

Before this, bring-up had no single readiness verdict. ``vigil-bringup.service`` is deliberately best-effort
(its ``-`` prefix means a failed docker/image bring-up never fails boot), ``vigil-command.service`` only
proves the proxy PROCESS started, and ``vigil doctor`` / the proxy's ``/readyz`` each answer half the
question. Nothing combined them into one bounded wait an operator (or a downstream unit) can act on.

:func:`wait_ready` is that gate. ``ready`` iff BOTH hold, polled until a hard deadline:

  * the proxy's ``/readyz`` answers 200 — its REAL dependency (the sovereign backend) is listening; and
  * ``vigil doctor`` reports ``ok`` — no hard prerequisite gap (binaries, venvs, writable dirs, a tampered
    signed release, an unhealthy watched money drain, ...).

INVARIANTS:
  * READ-ONLY and NOT AN ENABLER. Readiness gating is not execution enabling: this module writes nothing,
    sets no flag, starts no service, and never touches ``VIGIL_CUSTOMER_PROD_EXECUTION`` (or any other hold).
    A READY verdict authorizes nothing; it only reports.
  * BOUNDED. Every wait has a hard deadline (and every probe a short timeout); it can never hang bring-up.
  * LOOPBACK-ONLY. The ``/readyz`` URL must be a loopback ``http(s)`` URL (the same hardened pin the OTLP
    sink uses), so the probe can never be pointed off-box.
  * FAIL-CLOSED. Any probe fault is "not ready"; an unreadable doctor is "not ready".
  * Stdlib-only, framework-free (FATAL-2): ``doctor`` is imported lazily and is itself boundary-clean.
"""
from __future__ import annotations

import http.client
import time
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

__all__ = ["DEFAULT_READYZ_URL", "probe_readyz", "doctor_ok", "wait_ready"]

DEFAULT_READYZ_URL = "http://127.0.0.1:8770/readyz"     # `vigil up --port 8770` (vigil-command.service)
_PROBE_TIMEOUT_S = 2.0
_MAX_WAIT_S = 6 * 3600.0                                # a sane ceiling on any single wait


def readyz_url_is_loopback(url: Any) -> bool:
    """The same hardened loopback pin the OTLP sink uses (DNS-free, parser-differential-safe)."""
    try:
        from .live.otel_export import endpoint_is_loopback
        return bool(endpoint_is_loopback(url))
    except Exception:  # noqa: BLE001 — cannot prove loopback ⇒ refuse
        return False


def probe_readyz(url: str = DEFAULT_READYZ_URL, *, timeout: float = _PROBE_TIMEOUT_S) -> "tuple[bool, str]":
    """GET ``url`` once. ``(True, "")`` iff it answers HTTP 200; else ``(False, reason)``. Never raises; a
    non-loopback URL is refused without any connection."""
    if not readyz_url_is_loopback(url):
        return False, "readyz URL is not loopback — refused (probe never leaves the box)"
    try:
        p = urlparse(url)
        is_https = p.scheme.lower() == "https"
        port = p.port or (443 if is_https else 80)
        conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
        conn = conn_cls(p.hostname, port, timeout=timeout)
        try:
            conn.request("GET", p.path or "/readyz")
            resp = conn.getresponse()
            resp.read(4096)
            status = resp.status
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 — refused / timeout / protocol error ⇒ not ready
        return False, f"/readyz not answering: {type(exc).__name__}"
    if status == 200:
        return True, ""
    return False, f"/readyz answered HTTP {status} (a real dependency is down)"


def doctor_ok(repo_root: Path) -> "tuple[bool, list]":
    """``vigil doctor``'s verdict: ``(ok, issues)``. An unreadable doctor is NOT ok (fail-closed)."""
    try:
        from . import doctor as _doctor
        report = _doctor.collect(repo_root)
        return bool(report.get("ok")), [str(i) for i in report.get("issues", [])]
    except Exception as exc:  # noqa: BLE001
        return False, [f"vigil doctor could not run: {type(exc).__name__}: {exc}"]


def wait_ready(repo_root: Path, *, url: str = DEFAULT_READYZ_URL, wait_s: float = 0.0, interval_s: float = 2.0,
               probe: Optional[Callable[[str], "tuple[bool, str]"]] = None,
               doctor: Optional[Callable[[Path], "tuple[bool, list]"]] = None,
               clock: Optional[Callable[[], float]] = None,
               sleep: Optional[Callable[[float], None]] = None) -> dict:
    """Poll until READY or the deadline (``wait_s`` seconds; 0 = check once). Returns a JSON-safe verdict:
    ``{ready, readyz_ok, readyz_detail, doctor_ok, doctor_issues, attempts, waited_s, url}``.

    Each attempt probes ``/readyz`` first (cheap) and only runs the heavier ``vigil doctor`` once ``/readyz``
    is up. Bounded: at most ``wait_s`` (clamped to ``[0, 6h]``) plus one final attempt's probe time."""
    _probe = probe or (lambda u: probe_readyz(u))
    _doctor = doctor or doctor_ok
    _clock = clock or time.monotonic
    _sleep = sleep or time.sleep
    try:
        budget = min(max(float(wait_s), 0.0), _MAX_WAIT_S)
    except (TypeError, ValueError):
        budget = 0.0
    if budget != budget:                                 # NaN ⇒ check once
        budget = 0.0
    try:
        step = max(float(interval_s), 0.05)
    except (TypeError, ValueError):
        step = 2.0
    verdict: dict = {"ready": False, "readyz_ok": False, "readyz_detail": "", "doctor_ok": None,
                     "doctor_issues": [], "attempts": 0, "waited_s": 0.0, "url": url}
    if not readyz_url_is_loopback(url):
        verdict["readyz_detail"] = "readyz URL is not loopback — refused (probe never leaves the box)"
        return verdict
    # Bounded even if the clock stalls: never more attempts than the budget allows at the polling interval.
    max_attempts = int(budget // step) + 2
    t0 = _clock()
    while True:
        verdict["attempts"] += 1
        try:
            r_ok, r_detail = _probe(url)
        except Exception as exc:  # noqa: BLE001 — a probe fault is "not ready"
            r_ok, r_detail = False, f"probe error: {type(exc).__name__}"
        verdict["readyz_ok"], verdict["readyz_detail"] = bool(r_ok), str(r_detail or "")
        if r_ok:
            try:
                d_ok, issues = _doctor(repo_root)
            except Exception as exc:  # noqa: BLE001 — an unreadable doctor is NOT ready (fail-closed)
                d_ok, issues = False, [f"vigil doctor could not run: {type(exc).__name__}"]
            verdict["doctor_ok"], verdict["doctor_issues"] = bool(d_ok), list(issues)
            if d_ok:
                verdict["ready"] = True
        elapsed = _clock() - t0
        verdict["waited_s"] = round(max(elapsed, 0.0), 3)
        if verdict["ready"] or elapsed >= budget or verdict["attempts"] >= max_attempts:
            return verdict
        _sleep(min(step, max(budget - elapsed, 0.0)))
