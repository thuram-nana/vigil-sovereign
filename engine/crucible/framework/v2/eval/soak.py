"""eval.soak — the scale/soak harness (Phase 4).

CRUCIBLE's accuracy gate (``benchmark``) proves detection quality on a small labelled app; it does NOT
exercise SCALE. This is the missing load harness: a self-contained loopback app that serves N in-scope
endpoints (a deterministic subset reflectively-XSS-vulnerable), driven by a real ``WebScanCampaign``,
with the two things "barely tested at scale" needs:

  1. THROUGHPUT/MEMORY measurement — wall-clock, requests issued, peak RSS, pages crawled — over a
     configurable endpoint count, so an operator can characterise where the single-host design caps.
  2. A DETERMINISM-UNDER-LOAD fingerprint (:func:`scan_fingerprint`) — the load-bearing invariant the
     discoverer + the byte-identical gate rest on: the ``ScanReport`` is a PURE FUNCTION of its inputs.
     Running the same N-endpoint scan twice yields the SAME fingerprint (findings + surface counts,
     wall-clock excluded), proving replay-determinism holds at scale.

Loopback-only (binds 127.0.0.1); additive; imported by tests + runnable as a script. No runtime code
path changes, so ``make gate`` is untouched.
"""

from __future__ import annotations

import json
import resource
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict

from ..scanner.campaign import ScanReport, WebScanCampaign
from ..scanner.cli import loopback_send


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
    import hashlib
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


def main(argv: list[str] | None = None) -> int:
    """``python3 -m framework.v2.eval.soak [--endpoints N] [--max-requests M]`` — run the soak + print
    the scale metrics as JSON."""
    import argparse
    ap = argparse.ArgumentParser(prog="soak", description="CRUCIBLE scale/soak harness (loopback).")
    ap.add_argument("--endpoints", type=int, default=200, help="How many endpoints to serve (default 200).")
    ap.add_argument("--max-requests", type=int, default=0, help="Audit-request cap (0 = unbounded).")
    args = ap.parse_args(argv)
    res = run_soak(args.endpoints, max_audit_requests=args.max_requests)
    print(json.dumps(res.model_dump(), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
