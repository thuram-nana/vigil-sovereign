"""eval.soak — the scale/soak harness (Phase 4).

Pins the load-bearing invariant the discoverer + the byte-identical gate rest on — a scan is a PURE
FUNCTION of its inputs, at scale — and that the harness measures sane scale metrics. Loopback only.
"""

from __future__ import annotations

from framework.v2.eval.soak import run_soak, scan_fingerprint, serve_soak
from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.cli import loopback_send

# Kept small + request-bounded so the test is fast; bounding is a DETERMINISTIC truncation (the audit
# budget is consumed in a fixed serial order), so the determinism assertion is unaffected.
_N = 8
_CAP = 160


def _scan(n: int, cap: int):
    with serve_soak(n) as base:
        return WebScanCampaign(loopback_send, max_pages=n + 4, max_audit_requests=cap,
                               enable_oob=False).run(base + "/")


def test_scan_is_replay_deterministic_at_scale():
    # THE invariant: two full scans of the same N-endpoint surface produce the byte-identical result
    # fingerprint (findings + surface, wall-clock and the ephemeral port excluded).
    a = scan_fingerprint(_scan(_N, _CAP))
    b = scan_fingerprint(_scan(_N, _CAP))
    assert a == b, "the ScanReport is NOT replay-deterministic at scale"


def test_soak_finds_the_vulnerable_subset():
    # the even-indexed endpoints reflect into HTML → the reflection oracle confirms XSS on them.
    r = _scan(_N, _CAP)
    assert len(r.active_findings) > 0
    assert all(f.bug_class == "xss" for f in r.active_findings)


def test_soak_harness_reports_sane_scale_metrics():
    res = run_soak(_N, max_audit_requests=_CAP)
    assert res.endpoints == _N
    assert res.pages_crawled > 0 and res.requests_discovered > 0
    assert res.audit_requests_sent > 0 and res.elapsed_s >= 0.0
    assert res.throughput_rps >= 0.0 and res.peak_rss_mb > 0.0
    assert res.fingerprint.startswith("sha256:")


def test_soak_surface_grows_with_endpoint_count():
    # a larger fixture crawls more pages + discovers more surface (a scaling sanity, not a scoring input).
    small = run_soak(4, max_audit_requests=_CAP)
    large = run_soak(12, max_audit_requests=_CAP)
    assert large.pages_crawled > small.pages_crawled
    assert large.requests_discovered >= small.requests_discovered
