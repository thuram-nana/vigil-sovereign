"""eval.soak — the load + soak harness (W11-6, #487).

CRUCIBLE's accuracy gate (``benchmark``) proves detection quality on a small labelled app; it does NOT
exercise SCALE or ENDURANCE. This module is the load/soak harness: a self-contained loopback app that
serves N in-scope endpoints (a deterministic subset reflectively-XSS-vulnerable), driven by a real
``WebScanCampaign``. It has three parts, split by cost so the falsifiable core rides per-PR CI while the
long-running endurance run rides a schedule:

  1. SINGLE-SHOT SCALE measurement (:func:`run_soak`) — wall-clock, requests issued, peak RSS, pages
     crawled — over a configurable endpoint count, so an operator can characterise where the
     single-host design caps.
  2. A DETERMINISM-UNDER-LOAD fingerprint (:func:`scan_fingerprint`) — the load-bearing invariant the
     discoverer + the byte-identical gate rest on: the ``ScanReport`` is a PURE FUNCTION of its inputs.
     Running the same N-endpoint scan twice yields the SAME fingerprint (findings + surface counts,
     wall-clock excluded), proving replay-determinism holds at scale.
  3. A REAL SUSTAINED SOAK (:func:`run_soak_sustained`) — drive the scan iteration after iteration
     against ONE long-lived fixture (sustained load), tracking (a) THROUGHPUT against a DOCUMENTED floor
     (:data:`SUSTAINED_THROUGHPUT_FLOOR_RPS`; a run below it fails) and (b) process RSS across the whole
     run via :func:`detect_leak` (a rising memory trend fails). :class:`LeakingWorkload` is the
     artificially-leaking negative control the leak check must catch; :func:`clean_workload` is its
     healthy twin the check must leave alone.

Honest split (V2 government bar). The FAST, scaled half — the leak detector with its leaking-fixture
negative control and a SCALED sustained run against a deliberately conservative floor
(:data:`CI_THROUGHPUT_FLOOR_RPS`) — runs in the required ``CRUCIBLE eval + benchmark corpus`` job (see
``tests/test_soak_leak.py``). The FULL multi-minute sustained soak at the SLA floor is the scheduled
``.github/workflows/soak.yml`` job (``python3 -m framework.v2.eval.soak --sustained``); it is NOT a
per-PR gate and is honestly labelled as such. See ``docs/decisions/W11-6-load-soak-throughput-leak.md``.

Loopback-only (binds 127.0.0.1); additive; imported by tests + runnable as a script. No runtime code
path changes, so ``make gate`` is untouched.
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import resource
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict

from ..scanner.campaign import ScanReport, WebScanCampaign
from ..scanner.cli import loopback_send

# ---- Documented throughput floors (audit-requests / second; the scan is CPU-bound SERIAL work) --------
# The FULL sustained soak (the scheduled `soak.yml` job) enforces this SLA floor over a long run. A
# sustained run whose measured throughput falls below it FAILS. It is deliberately below the ~90 rps
# measured locally on the loopback fixture, leaving headroom for a shared runner while still catching a
# real (order-of-magnitude) regression.
SUSTAINED_THROUGHPUT_FLOOR_RPS = 30.0
# The fast per-PR check (crucible-eval) runs a SCALED-DOWN soak and enforces a deliberately CONSERVATIVE
# fraction of the SLA, so the gate is falsifiable (a genuine regression trips it) without going flaky on
# a shared 2-core PR runner. See docs/decisions/W11-6-load-soak-throughput-leak.md for the rationale.
CI_THROUGHPUT_FLOOR_RPS = 15.0

# ---- Leak-detector defaults (a memory series is in MiB) ----------------------------------------------
# A leak is flagged only when BOTH a sustained positive slope AND a meaningful net growth hold, so noise
# or a one-off warmup allocation cannot masquerade as a leak.
_LEAK_WARMUP = 1
_LEAK_SLOPE_THRESHOLD_MB = 0.5   # MiB gained per iteration (least-squares slope)
_LEAK_GROWTH_THRESHOLD_MB = 4.0  # MiB, last-third mean minus first-third mean


class SoakHandler(BaseHTTPRequestHandler):
    """A many-endpoint app: ``/`` links to ``/e/0..n-1?q=seed``; each ``/e/{i}`` reflects ``q``. An
    EVEN-indexed endpoint reflects it verbatim into executable HTML (reflected-XSS-vulnerable); an ODD
    one echoes it inertly (JSON) — a deterministic, half-vulnerable surface. ``n_endpoints`` is set on a
    subclass by :func:`serve_soak`."""

    n_endpoints = 20
    server_version = "soak/1.0"
    sys_version = ""

    def log_message(self, *args: object) -> None:  # keep the target quiet
        return

    def _q(self) -> str:
        return parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("q", [""])[0]

    def _send(self, body: bytes, ctype: str = "text/html; charset=utf-8", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        path = urlsplit(self.path).path
        if path == "/":
            links = "".join(f'<a href="/e/{i}?q=seed">e{i}</a> ' for i in range(self.n_endpoints))
            self._send(f"<!doctype html><html><body><h1>soak</h1>{links}</body></html>".encode())
            return
        if path.startswith("/e/"):
            try:
                idx = int(path[3:])
            except ValueError:
                self._send(b"not found", status=404)
                return
            q = self._q()
            if idx % 2 == 0:  # EVEN: reflect verbatim into HTML -> reflected-XSS-vulnerable
                self._send(f"<!doctype html><html><body>results for {q}</body></html>".encode())
            else:             # ODD: echo inertly as JSON -> not executable, no finding
                self._send(('{"results": "' + q + '"}').encode(), ctype="application/json")
            return
        self._send(b"not found", status=404)


@contextmanager
def serve_soak(n_endpoints: int) -> Iterator[str]:
    """Run an N-endpoint soak app on ``127.0.0.1:<ephemeral>`` for the block; yield its base URL."""
    handler = type("SoakHandlerN", (SoakHandler,), {"n_endpoints": max(1, int(n_endpoints))})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="soak-app", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class SoakResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoints: int
    pages_crawled: int
    requests_discovered: int
    audit_requests_sent: int
    active_findings: int
    elapsed_s: float
    throughput_rps: float          # audit requests / second (a scale datum, not a scoring input)
    peak_rss_mb: float
    fingerprint: str


def _norm_endpoint(ep: object) -> str:
    """Endpoint as path+query, DROPPING the scheme://host:port — the loopback server binds an EPHEMERAL
    port that changes each run, so the raw URL is not a determinism signal (only the path+query is)."""
    sp = urlsplit(str(ep))
    if sp.scheme:
        return sp.path + ("?" + sp.query if sp.query else "")
    return str(ep)


def scan_fingerprint(report: ScanReport) -> str:
    """A DETERMINISTIC digest of a scan's RESULT — the oracle-confirmed findings (by identity) plus the
    surface counts — with wall-clock AND the ephemeral host:port EXCLUDED. Two replays of the same scan
    produce the same fingerprint iff the report is a pure function of its inputs (the replay-determinism
    invariant, at scale)."""
    findings = sorted(
        (str(getattr(f, "bug_class", "")), _norm_endpoint(getattr(f, "endpoint", "")),
         str(getattr(f, "insertion_point", "")), str(getattr(f, "confirmed_by", "")))
        for f in report.active_findings)
    passive = sorted(
        (str(getattr(f, "check_id", getattr(f, "title", ""))), str(getattr(f, "severity", "")),
         _norm_endpoint(getattr(f, "url", "")))
        for f in report.passive_findings)
    payload = json.dumps({
        "active": findings, "passive": passive,
        "pages_crawled": report.pages_crawled,
        "requests_discovered": report.requests_discovered,
    }, sort_keys=True)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def run_soak(n_endpoints: int = 200, *, max_pages: int | None = None,
             max_audit_requests: int = 0) -> SoakResult:
    """Drive a real ``WebScanCampaign`` against an N-endpoint loopback fixture and return the scale
    metrics + the deterministic fingerprint. ``max_pages`` defaults to ``n_endpoints + 4`` (crawl the
    whole surface); ``max_audit_requests`` 0 = unbounded. Pure w.r.t. ``n_endpoints`` (deterministic
    fixture + deterministic scan)."""
    n = max(1, int(n_endpoints))
    pages = max_pages if max_pages is not None else n + 4
    with serve_soak(n) as base:
        started = time.monotonic()
        report = WebScanCampaign(
            loopback_send, max_pages=pages, max_audit_requests=max_audit_requests,
            enable_oob=False).run(base + "/")
        elapsed = time.monotonic() - started
    reqs = report.audit_requests_sent
    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss   # Linux: KiB
    return SoakResult(
        endpoints=n, pages_crawled=report.pages_crawled,
        requests_discovered=report.requests_discovered, audit_requests_sent=reqs,
        active_findings=len(report.active_findings), elapsed_s=round(elapsed, 3),
        throughput_rps=round(reqs / elapsed, 1) if elapsed > 0 else 0.0,
        peak_rss_mb=round(peak_kb / 1024, 1), fingerprint=scan_fingerprint(report))


# ==================================================================================================
# W11-6 (#487): the REAL soak — sustained load with a documented throughput floor and leak detection.
# ==================================================================================================
def current_rss_mb() -> float | None:
    """Current (resident) process RSS in MiB via ``/proc/self/statm`` on Linux, or ``None`` where
    ``/proc`` is absent. Unlike ``resource.getrusage().ru_maxrss`` — a HIGH-WATER mark that never
    decreases and so cannot reveal a leak's SHAPE — this is the LIVE resident set, which rises AND falls
    as memory is freed. That is the signal a leak detector needs: a genuine leak keeps climbing while
    healthy churn returns to a plateau."""
    try:
        with open("/proc/self/statm", "r", encoding="ascii") as fh:
            resident_pages = int(fh.read().split()[1])
    except (OSError, IndexError, ValueError):
        return None
    return resident_pages * (os.sysconf("SC_PAGE_SIZE") / (1024 * 1024))


class LeakVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    leaked: bool
    slope_mb_per_iter: float   # least-squares slope over the post-warmup series
    growth_mb: float           # last-third mean minus first-third mean
    n_samples: int
    warmup_dropped: int
    slope_threshold_mb: float
    growth_threshold_mb: float
    reason: str


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def detect_leak(samples: Sequence[float], *, warmup: int = _LEAK_WARMUP,
                slope_threshold_mb: float = _LEAK_SLOPE_THRESHOLD_MB,
                growth_threshold_mb: float = _LEAK_GROWTH_THRESHOLD_MB) -> LeakVerdict:
    """Decide whether a per-iteration MEMORY series (MiB) reveals a leak. PURE and deterministic: the
    decision is a function of the numbers alone, so it is testable without a live process — feed it a
    rising series and it flags a leak; feed it a flat one and it does not.

    Drops ``warmup`` leading samples (the first iteration warms imports/caches), then requires BOTH a
    least-squares slope above ``slope_threshold_mb`` per iteration AND a net growth (last-third mean −
    first-third mean) above ``growth_threshold_mb``. Demanding both means transient noise or a single
    warmup step cannot masquerade as a leak, while a steady climb is caught."""
    warmup = max(0, int(warmup))
    xs = list(samples)[warmup:]
    m = len(xs)
    if m < 3:
        return LeakVerdict(
            leaked=False, slope_mb_per_iter=0.0, growth_mb=0.0, n_samples=len(samples),
            warmup_dropped=warmup, slope_threshold_mb=slope_threshold_mb,
            growth_threshold_mb=growth_threshold_mb,
            reason=f"insufficient samples for a trend (need >=3 post-warmup, have {m}); leak not evaluated")
    mean_x = (m - 1) / 2.0
    mean_y = _mean(xs)
    den = sum((i - mean_x) ** 2 for i in range(m))
    num = sum((i - mean_x) * (y - mean_y) for i, y in enumerate(xs))
    slope = num / den if den else 0.0
    k = max(1, m // 3)
    growth = _mean(xs[-k:]) - _mean(xs[:k])
    leaked = slope > slope_threshold_mb and growth > growth_threshold_mb
    reason = (f"slope {slope:.2f} MiB/iter (>{slope_threshold_mb}) and growth {growth:.2f} MiB "
              f"(>{growth_threshold_mb}) over {m} post-warmup samples") if leaked else (
              f"stable: slope {slope:.2f} MiB/iter, growth {growth:.2f} MiB over {m} post-warmup samples")
    return LeakVerdict(
        leaked=leaked, slope_mb_per_iter=round(slope, 3), growth_mb=round(growth, 3),
        n_samples=len(samples), warmup_dropped=warmup, slope_threshold_mb=slope_threshold_mb,
        growth_threshold_mb=growth_threshold_mb, reason=reason)


def throughput_holds(measured_rps: float, floor_rps: float) -> bool:
    """True iff measured throughput meets the documented floor. A pure predicate, so the floor gate is
    falsifiable without a live run: a below-floor number returns ``False`` (the gate is not a no-op)."""
    return measured_rps >= floor_rps


def _touch_pages(buf: bytearray) -> None:
    """Write one byte per page so the whole buffer becomes RESIDENT. A fresh anonymous mmap is not
    counted in RSS until it is written to, so an untouched allocation would be invisible to the sampler;
    touching every page makes the allocation real to :func:`current_rss_mb`."""
    step = 4096
    buf[::step] = b"\x5a" * len(buf[::step])


def memory_series(work: Callable[[int], object], iterations: int, *,
                  sampler: Callable[[], float | None] = current_rss_mb,
                  collect_between: bool = True) -> list[float]:
    """Run ``work(i)`` for ``iterations`` and sample process memory after each (a leak shows as a rising
    series). ``collect_between`` forces a ``gc.collect()`` before each sample so a correctly-freed
    transient allocation cannot masquerade as growth. Raises ``RuntimeError`` if no sampler is available
    on this platform (callers in CI guard with ``current_rss_mb() is None``)."""
    out: list[float] = []
    for i in range(int(iterations)):
        work(i)
        if collect_between:
            gc.collect()
        s = sampler()
        if s is None:
            raise RuntimeError("no process-RSS sampler on this platform (/proc/self/statm absent)")
        out.append(float(s))
    return out


class LeakingWorkload:
    """A DELIBERATELY-leaking workload: each call allocates ``mib`` MiB, touches every page, and RETAINS
    it, so process RSS grows without bound. It is the negative control the leak check must DETECT — an
    artificial leak that, were the detector a no-op, would slip through and prove it worthless."""

    def __init__(self, mib: float = 8.0) -> None:
        self._n = int(mib * 1024 * 1024)
        self.held: list[bytearray] = []

    def __call__(self, _i: int) -> None:
        b = bytearray(self._n)
        _touch_pages(b)
        self.held.append(b)


def clean_workload(mib: float = 8.0) -> Callable[[int], None]:
    """A well-behaved twin of :class:`LeakingWorkload`: it allocates and TOUCHES ``mib`` MiB each call
    but does NOT retain it, so RSS plateaus. It proves the detector does not fire on healthy churn (no
    false positive)."""
    n = int(mib * 1024 * 1024)

    def work(_i: int) -> None:
        b = bytearray(n)
        _touch_pages(b)
        del b

    return work


class SustainedSoakResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoints: int
    iterations: int
    audit_requests_sent: int
    elapsed_s: float
    throughput_rps: float
    throughput_floor_rps: float
    throughput_ok: bool
    rss_samples_mb: list[float]
    peak_rss_mb: float
    leak: LeakVerdict
    fingerprint: str
    determinism_stable: bool
    passed: bool


def run_soak_sustained(n_endpoints: int = 4, iterations: int = 200, *,
                       max_audit_requests: int = 60,
                       floor_rps: float = SUSTAINED_THROUGHPUT_FLOOR_RPS,
                       min_duration_s: float = 0.0,
                       sampler: Callable[[], float | None] = current_rss_mb,
                       leak_warmup: int = _LEAK_WARMUP) -> SustainedSoakResult:
    """Drive a real ``WebScanCampaign`` against ONE long-lived N-endpoint loopback fixture, iteration
    after iteration (SUSTAINED load), tracking throughput and process RSS across the whole run.

    Runs at least ``iterations`` iterations AND at least ``min_duration_s`` seconds (whichever is
    greater), so the scheduled job can express a real multi-minute soak by duration. Returns the scale
    metrics, the memory-trend :class:`LeakVerdict`, and whether the run held the documented throughput
    floor. ``passed`` is the AND of: throughput at/above ``floor_rps``; NO detected leak; and the scan
    fingerprint stayed identical across every iteration (determinism under load). A caller (the CLI /
    the scheduled workflow) turns ``passed is False`` into a non-zero exit so a regression is RED."""
    n = max(1, int(n_endpoints))
    pages = n + 4
    samples: list[float] = []
    fps: set[str] = set()
    total_reqs = 0
    ran = 0
    with serve_soak(n) as base:
        started = time.monotonic()
        while True:
            report = WebScanCampaign(
                loopback_send, max_pages=pages, max_audit_requests=max_audit_requests,
                enable_oob=False).run(base + "/")
            total_reqs += report.audit_requests_sent
            fps.add(scan_fingerprint(report))
            gc.collect()
            s = sampler()
            if s is not None:
                samples.append(round(float(s), 2))
            ran += 1
            elapsed = time.monotonic() - started
            if ran >= max(1, int(iterations)) and elapsed >= min_duration_s:
                break
        elapsed = time.monotonic() - started
    throughput = round(total_reqs / elapsed, 1) if elapsed > 0 else 0.0
    leak = detect_leak(samples, warmup=leak_warmup)
    determinism_stable = len(fps) <= 1
    throughput_ok = throughput_holds(throughput, floor_rps)
    passed = throughput_ok and not leak.leaked and determinism_stable
    return SustainedSoakResult(
        endpoints=n, iterations=ran, audit_requests_sent=total_reqs, elapsed_s=round(elapsed, 3),
        throughput_rps=throughput, throughput_floor_rps=floor_rps, throughput_ok=throughput_ok,
        rss_samples_mb=samples, peak_rss_mb=round(max(samples), 2) if samples else 0.0,
        leak=leak, fingerprint=(sorted(fps)[0] if fps else ""),
        determinism_stable=determinism_stable, passed=passed)


def main(argv: list[str] | None = None) -> int:
    """``python3 -m framework.v2.eval.soak [--endpoints N] [--max-requests M]`` — a single-shot scale
    snapshot; or ``--sustained`` for the full endurance soak (throughput floor + leak detection), which
    returns a non-zero exit — turning the run RED — if the floor is breached, a leak is detected, or the
    fingerprint diverges across iterations."""
    import argparse
    ap = argparse.ArgumentParser(prog="soak", description="CRUCIBLE load + soak harness (loopback).")
    ap.add_argument("--endpoints", type=int, default=200, help="How many endpoints to serve (default 200).")
    ap.add_argument("--max-requests", type=int, default=0, help="Audit-request cap (0 = unbounded).")
    ap.add_argument("--sustained", action="store_true",
                    help="Run the full sustained-load soak (throughput floor + leak detection) instead "
                         "of a single-shot scale snapshot; exits non-zero on a regression.")
    ap.add_argument("--iterations", type=int, default=400, help="Sustained soak: minimum iterations (default 400).")
    ap.add_argument("--min-duration-s", type=float, default=0.0,
                    help="Sustained soak: minimum wall-clock seconds to keep driving load (default 0).")
    ap.add_argument("--floor-rps", type=float, default=SUSTAINED_THROUGHPUT_FLOOR_RPS,
                    help=f"Sustained soak: documented throughput floor (default {SUSTAINED_THROUGHPUT_FLOOR_RPS}).")
    args = ap.parse_args(argv)
    if args.sustained:
        endpoints = args.endpoints if args.endpoints != 200 else 8   # a soak drives DURATION, not breadth
        cap = args.max_requests if args.max_requests else 60
        res = run_soak_sustained(endpoints, iterations=args.iterations, max_audit_requests=cap,
                                 floor_rps=args.floor_rps, min_duration_s=args.min_duration_s)
        print(json.dumps(res.model_dump(), indent=2))
        if not res.passed:
            reasons = []
            if not res.throughput_ok:
                reasons.append(f"throughput {res.throughput_rps} rps < documented floor {res.throughput_floor_rps} rps")
            if res.leak.leaked:
                reasons.append(f"memory leak DETECTED ({res.leak.reason})")
            if not res.determinism_stable:
                reasons.append("scan fingerprint diverged across iterations")
            print("::error::SOAK FAILED: " + "; ".join(reasons), file=sys.stderr)
            return 1
        return 0
    res_single = run_soak(args.endpoints, max_audit_requests=args.max_requests)
    print(json.dumps(res_single.model_dump(), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
