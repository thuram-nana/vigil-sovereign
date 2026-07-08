"""
scanner.cli — ``python3 -m framework.v2 scan <url>``.

A one-command autonomous web scan over the full arsenal: crawl -> passive ->
active audit (per-point checks + the request-level CORS/host-header/JWT/GraphQL
checks) -> oracle-confirmed report, with self-learning check ordering.

**Loopback-only, by design.** This Wave-1 entrypoint issues traffic through a
plain local HTTP client and therefore refuses any non-loopback host. Scanning an
authorized *remote* target must go through the ``engage`` runner (Wave 2), whose
``send`` is the charter/scope/kill-switch/egress-gated executor — the safety
stack this thin client deliberately does not reimplement. Pointing ``scan`` at a
remote host is refused with that guidance rather than sending ungated traffic.
"""

from __future__ import annotations

import argparse
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .campaign import WebScanCampaign
from .insertion import HttpRequest

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects — the CORS/host-header/open-redirect checks need
    the raw 30x ``Location`` header, which a redirect-following client hides."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401,ANN001
        return None


def loopback_send(req: HttpRequest, *, timeout: float = 10.0) -> dict:
    """Issue one request against a loopback target and return
    ``{status, body, headers, latency_ms}`` — the response shape the checks and
    oracles consume. Never follows redirects; never raises (a transport error is
    a status-0 empty response so a scan degrades rather than crashes)."""
    data = req.body.encode("utf-8") if req.body else None
    r = urllib.request.Request(req.url, data=data, method=req.method)
    for k, v in req.headers:
        r.add_header(k, v)
    opener = urllib.request.build_opener(_NoRedirect)
    t0 = time.monotonic()
    try:
        with opener.open(r, timeout=timeout) as resp:
            status, raw, headers = resp.status, resp.read(), list(resp.headers.items())
    except urllib.error.HTTPError as e:  # a 4xx/5xx is a real, useful response
        status, raw, headers = e.code, e.read(), list(e.headers.items())
    except Exception:
        return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0}
    return {
        "status": status,
        "body": raw.decode("utf-8", "replace"),
        "headers": [(str(k), str(v)) for k, v in headers],
        "latency_ms": (time.monotonic() - t0) * 1000.0,
    }


def _is_loopback(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower() in _LOOPBACK_HOSTS


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 scan",
        description="Autonomous loopback web scan (crawl + passive + active arsenal).",
    )
    parser.add_argument("target", help="Seed URL on a loopback host (127.0.0.1/localhost/::1).")
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--max-audit-requests", type=int, default=0,
                        help="Cap total active requests (0 = unbounded).")
    parser.add_argument("--targeted", action="store_true",
                        help="Prioritise checks per point by parameter fingerprint.")
    parser.add_argument("--no-oob", action="store_true", help="Disable the loopback OOB receiver.")
    parser.add_argument("--domxss", action="store_true",
                        help="Also emit static DOM-XSS source->sink leads (candidates, not confirmed).")
    parser.add_argument("--browser-xss", action="store_true",
                        help="Confirm DOM-XSS by real execution in a headless browser (needs Chromium).")
    parser.add_argument("--spa", action="store_true",
                        help="Run the SPA crawler to capture fetch/XHR endpoints (needs Chromium).")
    parser.add_argument("--bandit-file", default=None,
                        help="Persist/warm-start the self-learning check-ordering bandit here.")
    parser.add_argument("--bandit-context", default="default",
                        help="Archetype key the bandit keys its posteriors on.")
    parser.add_argument("--format", choices=("text", "json", "sarif", "html"), default="text",
                        help="Report format (json/sarif/html emit a machine/CI/human report to stdout).")
    parser.add_argument("--strict-evidence", action="store_true",
                        help="Withhold any confirmed finding that does NOT re-ground as a fact "
                             "at render time from the rendered report (json/sarif/html). The "
                             "finding stays in --reverifiable-out (nothing is lost internally); "
                             "off by default (default = label every finding with its grounding).")
    parser.add_argument("--progress-log", default=None,
                        help="Append live phase/finding events as JSONL here (for the Ops Console "
                             "live view). Off by default; adds no cost when unset.")
    parser.add_argument("--reverifiable-out", default=None,
                        help="Also write the raw ScanReport JSON (findings WITH oracle_context "
                             "certificates) here — the artifact `verify` re-runs.")
    args = parser.parse_args(argv)

    if not _is_loopback(args.target):
        print(
            "refused: `scan` is loopback-only (127.0.0.1/localhost/::1). Scanning an\n"
            "authorized remote target goes through the gated executor — use `engage`.",
        )
        return 2

    progress = None
    if args.progress_log:
        from .progress import JsonlSink
        progress = JsonlSink(args.progress_log)

    report = WebScanCampaign(
        loopback_send,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        max_audit_requests=args.max_audit_requests,
        targeted=args.targeted,
        enable_oob=not args.no_oob,
        enable_domxss=args.domxss,
        enable_browser_xss=args.browser_xss,
        enable_spa_crawl=args.spa,
        bandit_path=args.bandit_file,
        bandit_context=args.bandit_context,
        progress=progress,
    ).run(args.target)

    if args.reverifiable_out:
        # The raw ScanReport (findings WITH their oracle_context certificates) — the
        # document `python3 -m framework.v2 verify` re-runs. The rendered report
        # formats intentionally omit the certificate, so this is the re-verifiable
        # artifact a CI/console re-check consumes.
        from pathlib import Path as _P
        _P(args.reverifiable_out).write_text(report.model_dump_json(indent=2), encoding="utf-8")

    if args.format != "text":
        from .report import render
        print(render(report, args.format, strict_evidence=args.strict_evidence))
        return 0

    print(f"scan {report.target}")
    print(f"  pages crawled     : {report.pages_crawled}")
    print(f"  requests audited  : {report.requests_audited} ({report.audit_requests_sent} sent)")
    print(f"  confirmed findings: {len(report.active_findings)}")
    for f in report.active_findings:
        print(f"    [{f.confirmed_by}] {f.bug_class} @ {f.insertion_point} (conf {f.confidence:.2f})")
    if report.passive_findings:
        print(f"  passive findings  : {len(report.passive_findings)}")
    if report.dom_xss_candidates:
        print(f"  dom-xss leads     : {len(report.dom_xss_candidates)} (candidates, not confirmed)")
    if report.discovered_endpoints:
        print(f"  spa endpoints     : {len(report.discovered_endpoints)} discovered")
        for ep in report.discovered_endpoints[:20]:
            print(f"    {ep}")
    return 0
