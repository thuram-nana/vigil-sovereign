"""
W6-4 (#455) — a REAL OTLP collector profile + a VISIBLE failure when the backend is unreachable.

Before this slice VIGIL's spans reached ``OTLPSink`` (dep #539) but the shipped collector config only
terminated them in the collector's own stdout (the ``debug`` exporter), and an unreachable telemetry
backend was a SILENT drip of the sink's ``dropped`` counter — nothing an operator could see. This slice
adds (a) a collector profile that forwards to a real backend and (b) ``live.otel_export.probe_collector``,
the reachability preflight that makes a down backend VISIBLE.

Everything here is FRAMEWORK-FREE and OTEL-FREE by construction: the reachability path rides stdlib
``http.client`` against a minimal in-test OTLP receiver (a real loopback HTTP server), and the config
check rides PyYAML — so this whole file executes in the REQUIRED sovereign CI leg (``pytest
integration/tests``) whether or not ``opentelemetry`` is installed. The stronger, protobuf-level "a real
span's bytes arrive at the endpoint" proof is separately covered, otel-gated, in ``test_live_otel_export.py``.

The load-bearing assertion (acceptance (c)): with the backend UNREACHABLE, the failure is VISIBLE (a
returned error + a logged WARNING), NOT a silent drop — and the reachable case is its own negative control
(it neither warns nor reports failure), so the probe is proven not to be a constant.
"""
from __future__ import annotations

import http.server
import logging
import socket
import threading
from pathlib import Path

import pytest

from vigil_integration.live.otel_export import CollectorProbe, probe_collector

_REPO = Path(__file__).resolve().parents[2]
_DEFAULT_CFG = _REPO / "infra" / "sidecars" / "otel-config.yaml"
_BACKEND_CFG = _REPO / "infra" / "sidecars" / "otel-config-backend.yaml"


# --- a minimal in-test OTLP/HTTP receiver (a real loopback backend stand-in) ------------------------

class _OTLPReceiver:
    """A real HTTP server on loopback that speaks just enough OTLP/HTTP to stand in for a backend: it
    accepts ``POST /v1/traces``, captures each request (path + body length), and answers 200. Binds an
    EPHEMERAL port (127.0.0.1:0) so tests never collide. No opentelemetry, no network beyond loopback."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, int]] = []
        receiver = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 — BaseHTTPRequestHandler's contract
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length) if length else b""
                receiver.requests.append((self.path, len(body)))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_a):  # silence the default stderr access log
                return

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "_OTLPReceiver":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _free_but_dead_port() -> int:
    """A loopback port that is bound-then-released, so nothing listens on it — a connect is REFUSED. This
    gives the negative control a deterministically-unreachable endpoint (no waiting on a timeout)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- POSITIVE: a live loopback endpoint is reachable, and the probe REACHES it ----------------------

def test_probe_reports_reachable_against_a_live_loopback_endpoint(caplog):
    with _OTLPReceiver() as rx:
        with caplog.at_level(logging.WARNING, logger="vigil_integration.live.otel_export"):
            probe = probe_collector(rx.url, timeout=2.0)
    assert isinstance(probe, CollectorProbe)
    assert probe.reachable is True and bool(probe) is True
    assert probe.detail == ""                      # reachable ⇒ no error text to display
    # the probe made a REAL round-trip to the endpoint's /v1/traces route (the export destination is live).
    assert rx.requests and rx.requests[0][0] == "/v1/traces"
    # NEGATIVE CONTROL half: a reachable collector logs NO warning — so the warning in the unreachable
    # test below is caused by unreachability, not emitted unconditionally (the probe is not a constant).
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


# --- THE LOAD-BEARING NEGATIVE CONTROL: an UNREACHABLE backend is VISIBLE, not silently dropped ------

def test_unreachable_backend_surfaces_a_visible_error_not_a_silent_drop(caplog):
    dead = f"http://127.0.0.1:{_free_but_dead_port()}"
    with caplog.at_level(logging.WARNING, logger="vigil_integration.live.otel_export"):
        probe = probe_collector(dead, timeout=2.0)
    # (1) the failure is RETURNED, visibly, with a human-readable reason a diagnostic can print.
    assert probe.reachable is False and bool(probe) is False
    assert "UNREACHABLE" in probe.detail and dead in probe.detail
    # (2) and it is LOGGED at WARNING — the opposite of a silent ``dropped++``. THIS is acceptance (c).
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings, "an unreachable OTLP backend must be VISIBLE (a WARNING), not a silent drop"
    assert any("UNREACHABLE" in r.getMessage() for r in warnings)


def test_probe_is_total_never_raises_on_hostile_input():
    # totality: the preflight degrades every bad input to a visible reachable=False, never a crash.
    for bad in (None, "", "not a url", 12345, "ftp://127.0.0.1:4318", object()):
        probe = probe_collector(bad, timeout=0.5)
        assert probe.reachable is False


def test_probe_refuses_a_non_loopback_endpoint_visibly(caplog):
    # the egress pin: a non-loopback endpoint is refused WITHOUT a connection (never DNS-resolved), and the
    # refusal is visible (returned + logged) rather than a silent no-op.
    with caplog.at_level(logging.WARNING, logger="vigil_integration.live.otel_export"):
        probe = probe_collector("http://169.254.169.254:4318")     # cloud metadata — must never be probed
    assert probe.reachable is False and "not loopback" in probe.detail
    assert [r for r in caplog.records if r.levelno >= logging.WARNING]


# --- the collector PROFILE actually exports to a REAL backend (acceptance (a), config half) ----------

def test_backend_collector_profile_exports_to_a_real_backend_not_only_stdout():
    yaml = pytest.importorskip("yaml")   # PyYAML is in the framework runtime lock ⇒ runs in the P5 leg
    assert _BACKEND_CFG.is_file(), f"the real-backend collector profile {_BACKEND_CFG} is missing"
    cfg = yaml.safe_load(_BACKEND_CFG.read_text(encoding="utf-8"))

    exporters = cfg.get("exporters", {})
    # a REAL backend export exporter (otlp/*) must exist AND declare an endpoint — not just `debug` (stdout).
    otlp_exporters = [k for k in exporters if str(k).split("/")[0] == "otlp"]
    assert otlp_exporters, "the backend profile must define an OTLP exporter to a real backend"
    for name in otlp_exporters:
        assert exporters[name].get("endpoint"), f"exporter {name} must point at a backend endpoint"

    # the traces pipeline must actually ROUTE to that real backend (a defined-but-unwired exporter is a lie).
    traces = cfg["service"]["pipelines"]["traces"]["exporters"]
    assert any(str(e).split("/")[0] == "otlp" for e in traces), \
        "the traces pipeline must export to the real OTLP backend, not only to debug/stdout"


def test_default_profile_is_stdout_only_so_the_backend_profile_is_the_real_delta():
    # NEGATIVE CONTROL for the config check: the DEFAULT profile's traces pipeline exports ONLY to debug
    # (stdout) — proving the assertion above detects a genuine difference, not something both files share.
    yaml = pytest.importorskip("yaml")
    cfg = yaml.safe_load(_DEFAULT_CFG.read_text(encoding="utf-8"))
    traces = cfg["service"]["pipelines"]["traces"]["exporters"]
    assert traces == ["debug"], "the default profile is expected to terminate traces in stdout only"
