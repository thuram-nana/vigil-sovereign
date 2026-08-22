"""W6-3 #454 — the OFFENSE plane exposes OpenMetrics on /metrics, and a real gate DENY is reflected.

Two properties, both against the real reverse-proxy server:

  * `/metrics` (UNAUTHENTICATED, Host-ungated — the same probe posture as /healthz+/readyz) returns valid
    OpenMetrics text with the RED series, the process metrics, and the four domain counters; the domain
    counters (facts/leads/refusals) are folded from the business-counter JSON snapshot the server points at.
  * NEGATIVE CONTROL — a forced gate DENY through the REAL offense gate
    (`build_offense_gate(...)`, whose wrapper calls `record_gate_verdict`) increments the process gate-denial
    counter, and a subsequent /metrics scrape reflects the higher value AND crosses the shipped alert rule's
    threshold. A build with no fix would not increment (there is no counter) — the assertion is observed.

Run: PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core \
     .venv-offense/bin/python -m pytest -q integration/tests/test_metrics_endpoint.py
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from pathlib import Path

from vigil_core.metrics import default_registry
from vigil_integration.conjunctive_gate import build_offense_gate
from vigil_integration.uiproxy import make_proxy_server

REPO = Path(__file__).resolve().parents[2]
ALERTS = REPO / "infra" / "observability" / "vigil-alerts.yml"


def _serve(tmp_path: Path):
    serve_dir = tmp_path / "ui"
    serve_dir.mkdir(parents=True, exist_ok=True)
    # the business snapshot the /metrics route folds into the domain counters
    snap = tmp_path / "live-ui" / "telemetry.json"
    snap.parent.mkdir(parents=True, exist_ok=True)
    snap.write_text(json.dumps({"totals": {"facts": 6, "leads": 11, "refusals": 3}}), encoding="utf-8")
    srv = make_proxy_server("127.0.0.1", 0, serve_dir)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _get(port: int, path: str):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")  # no token, no proxy Host
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, r.headers.get("Content-Type", ""), r.read().decode()


def _series_value(text: str, name: str) -> float:
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = re.match(rf"^{re.escape(name)}(\{{[^}}]*\}})?\s+(\S+)$", line)
        if m:
            return float(m.group(2))
    raise AssertionError(f"series {name} not found in exposition")


def test_metrics_endpoint_serves_openmetrics_with_red_process_and_domain(tmp_path):
    srv, port = _serve(tmp_path)
    try:
        _get(port, "/healthz")   # warm up so the RED request counter has at least one completed sample
        status, ctype, body = _get(port, "/metrics")
        assert status == 200
        assert ctype.startswith("application/openmetrics-text")
        assert body.rstrip().endswith("# EOF")
        # domain counters, folded from the JSON snapshot the server points at
        assert _series_value(body, "vigil_facts_total") == 6.0
        assert _series_value(body, "vigil_leads_total") == 11.0
        assert _series_value(body, "vigil_refusals_total") == 3.0
        assert "vigil_gate_denials_total" in body
        # RED + process
        assert "vigil_requests_total" in body
        assert "# TYPE vigil_request_duration_seconds histogram" in body
        assert "vigil_process_resident_memory_bytes" in body
        assert 'plane="offense"' in body
    finally:
        srv.shutdown()


def _spike_threshold() -> float:
    text = ALERTS.read_text(encoding="utf-8")
    block = re.split(r"(?m)^\s*- alert:\s*VigilGateDenialSpike\s*$", text)[1]
    m = re.search(r"vigil_gate_denials_total\b.*?>\s*([0-9.]+)", block)
    assert m, "could not parse the VigilGateDenialSpike threshold"
    return float(m.group(1))


def test_forced_offense_gate_denial_is_reflected_on_metrics_and_fires_alert(tmp_path):
    srv, port = _serve(tmp_path)
    try:
        _, _, before_body = _get(port, "/metrics")
        before = _series_value(before_body, "vigil_gate_denials_total")

        # A REAL offense gate. With no live engagement authority the CRUCIBLE leg fails closed → the
        # conjunctive verdict is a DENY, and build_offense_gate's wrapper records it. trust_root is a
        # non-None sentinel (the None-refusal is a separate concern); the CRUCIBLE load fails inside.
        gate = build_offense_gate(slug="no-such-engagement", trust_root=object(),
                                  classify=lambda name: "A0")
        verdict = gate("curl", "http://127.0.0.1/")
        assert verdict.allowed is False and verdict.outcome == "deny"

        _, _, after_body = _get(port, "/metrics")
        after = _series_value(after_body, "vigil_gate_denials_total")
        assert after == before + 1.0, "the offense gate DENY must increment vigil_gate_denials_total"

        # the shipped alert rule fires on the observed increase; it did not before the denial.
        thr = _spike_threshold()
        assert (before - before) <= thr        # no denial yet → not firing
        assert (after - before) > thr          # after the denial → firing
    finally:
        srv.shutdown()


def test_default_registry_is_the_one_the_proxy_renders(tmp_path):
    """The proxy renders the process-global registry, so a denial counted anywhere in the process shows up
    on /metrics (the property the negative control relies on)."""
    srv, _ = _serve(tmp_path)
    try:
        assert srv.metrics is default_registry()
        assert srv.metrics.plane == "offense"
    finally:
        srv.shutdown()
