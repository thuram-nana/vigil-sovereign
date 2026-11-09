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
  * BOUNDED. Every wait has a hard deadline, and EACH probe and EACH doctor run has its own OVERALL deadline
    (enforced on a daemon thread — http.client's timeout is per socket op, so a slow-dripping listener could
    otherwise hold one probe forever). Worst case ≈ ``--wait`` + one probe deadline + one doctor deadline.
  * LOOPBACK-ONLY. The ``/readyz`` URL must be a loopback ``http(s)`` URL whose host is a loopback IP LITERAL
    (the hardened OTLP pin, minus the ``localhost`` name — no name resolution), so the probe never leaves the box.
  * HONEST LIMIT. Any process answering 200 on the port reads as a ready proxy; the doctor half still has to
    pass, and anything squatting the UI port has already displaced the UI. It is a POINT-IN-TIME verdict.
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
_PROBE_DEADLINE_S = 5.0                                 # OVERALL bound on one /readyz probe
DOCTOR_DEADLINE_S = 180.0                               # OVERALL bound on one `vigil doctor` run
_MAX_WAIT_S = 6 * 3600.0                                # a sane ceiling on any single wait


def readyz_url_is_loopback(url: Any) -> bool:
    """The hardened OTLP loopback pin (parser-differential-safe), AND the host must be a loopback IP LITERAL —
    the ``localhost`` NAME is refused so nothing is ever resolved (a broken hosts file cannot redirect it)."""
    try:
        from .live.otel_export import endpoint_is_loopback
        if not endpoint_is_loopback(url):
            return False
        host = (urlparse(url).hostname or "").strip().lower()
        return host != "localhost"
    except Exception:  # noqa: BLE001 — cannot prove loopback ⇒ refuse
        return False


def _bounded(fn: Callable[..., Any], arg: Any, deadline_s: float) -> "tuple[bool, Any, Optional[BaseException]]":
    """Run ``fn(arg)`` on a daemon thread; ``(done, result, exc)`` within ``deadline_s``. An overrunning call is
    abandoned (daemon — never blocks process exit), so no single probe / doctor run can hang the gate."""
    import threading

    box: dict = {}

    def run() -> None:
        try:
            box["r"] = fn(arg)
        except BaseException as exc:  # noqa: BLE001 — reported to the caller, never propagated off-thread
            box["e"] = exc
    t = threading.Thread(target=run, name="vigil-ready-bounded", daemon=True)
    t.start()
    t.join(deadline_s)
    if t.is_alive():
        return False, None, None
    return True, box.get("r"), box.get("e")


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
               sleep: Optional[Callable[[float], None]] = None,
               probe_deadline_s: float = _PROBE_DEADLINE_S, doctor_deadline_s: float = DOCTOR_DEADLINE_S) -> dict:
    """Poll until READY or the deadline (``wait_s`` seconds; 0 = check once). Returns a JSON-safe verdict:
    ``{ready, readyz_ok, readyz_detail, doctor_ok, doctor_issues, attempts, waited_s, url}``.

    Each attempt probes ``/readyz`` first (cheap) and only runs the heavier ``vigil doctor`` once ``/readyz``
    is up. Bounded: at most ``wait_s`` (clamped to ``[0, 6h]``) + one probe deadline + one doctor deadline.
    Never raises."""
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
    if step != step or step == float("inf"):              # NaN / inf interval ⇒ the default
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
        done, res, err = _bounded(_probe, url, probe_deadline_s)
        if not done:
            r_ok, r_detail = False, f"/readyz did not answer within {probe_deadline_s:g} s"
        elif err is not None or not isinstance(res, tuple) or len(res) != 2:
            r_ok, r_detail = False, f"probe error: {type(err).__name__ if err else 'bad result'}"
        else:
            r_ok, r_detail = res
        verdict["readyz_ok"], verdict["readyz_detail"] = bool(r_ok), str(r_detail or "")
        if r_ok:
            ddone, dres, derr = _bounded(_doctor, repo_root, doctor_deadline_s)
            if not ddone:
                d_ok, issues = False, [f"vigil doctor did not finish within {doctor_deadline_s:g} s"]
            elif derr is not None or not isinstance(dres, tuple) or len(dres) != 2:
                # an unreadable doctor is NOT ready (fail-closed)
                d_ok, issues = False, [f"vigil doctor could not run: {type(derr).__name__ if derr else 'bad result'}"]
            else:
                d_ok, issues = dres
            verdict["doctor_ok"], verdict["doctor_issues"] = bool(d_ok), list(issues)
            if d_ok:
                verdict["ready"] = True
        elapsed = _clock() - t0
        verdict["waited_s"] = round(max(elapsed, 0.0), 3)
        if verdict["ready"] or elapsed >= budget or verdict["attempts"] >= max_attempts:
            return verdict
        _sleep(min(step, max(budget - elapsed, 0.0)))
