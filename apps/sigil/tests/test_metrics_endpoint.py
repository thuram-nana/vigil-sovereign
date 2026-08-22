"""W6-3 #454 — the SOVEREIGN plane (glass-cockpit UI) exposes OpenMetrics on /metrics.

The route is UNAUTHENTICATED and Host-ungated — the SAME probe posture as /healthz+/readyz (this cockpit
binds loopback / a private WG address only). The exposition carries the RED series (the server's own
requests), the process metrics, and the four domain counters. A scrape after some traffic reflects the
request in the RED counter (the negative-control that the RED wiring is not a no-op).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=packages/core/vigil_core:apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_metrics_endpoint.py
"""
from __future__ import annotations

import re
import tempfile
import threading
import time
import urllib.request

from sigil.spine.store import SpineStore
from sigil.ui.server import build_server as build_ui

TOKEN = "owner-shared-token-metrics-1"


def _spine() -> str:
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve():
    srv = build_ui(token=TOKEN, port=0, spine_path=_spine())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _get(port: int, path: str, *, host: str | None = None):
    h = {"Host": host} if host is not None else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, r.headers.get("Content-Type", ""), r.read().decode()


def _series_present(text: str, name: str) -> bool:
    return any(re.match(rf"^{re.escape(name)}(\{{[^}}]*\}})?\s+\S+$", ln) for ln in text.splitlines())


def test_metrics_is_unauthenticated_openmetrics_with_red_process_and_domain():
    srv, port = _serve()
    try:
        # a probe presents no token and a probe Host (not the anti-rebind allowlist) — still served.
        _get(port, "/healthz", host="kube-probe/1.0")  # warm up the RED counter with one completed request
        status, ctype, body = _get(port, "/metrics", host="kube-probe/1.0")
        assert status == 200
        assert ctype.startswith("application/openmetrics-text")
        assert body.rstrip().endswith("# EOF")
        assert 'plane="sovereign"' in body
        # the four domain counters
        for fam in ("vigil_facts_total", "vigil_leads_total", "vigil_refusals_total",
                    "vigil_gate_denials_total"):
            assert fam in body, f"missing domain series {fam}"
        # RED
        assert _series_present(body, "vigil_requests_total"), "no RED request sample after traffic"
        assert "# TYPE vigil_request_duration_seconds histogram" in body
        # process
        assert "vigil_process_resident_memory_bytes" in body
        assert "vigil_process_uptime_seconds" in body
    finally:
        srv.shutdown()


def test_metrics_body_carries_no_token():
    srv, port = _serve()
    try:
        _, _, body = _get(port, "/metrics")
        assert TOKEN not in body
    finally:
        srv.shutdown()
