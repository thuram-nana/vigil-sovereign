"""NET-2b red-pen folds on the OTLP egress pin (``live.otel_export``), which `vigil engage --otlp-endpoint`
made reachable from operator input for the first time:

  * HIGH — a urllib.parse-vs-urllib3 authority differential (``http://evil.com\\@127.0.0.1:4318`` passed the
    pin as 127.0.0.1 while requests/urllib3 — what the real exporter uses — would POST to evil.com). The pin
    now refuses backslash / whitespace / control / non-ASCII / userinfo / percent-in-authority up front, and
    every string it accepts must resolve to the SAME loopback host under urllib3.
  * MED — the requests-based exporter is built on a pinned Session: no ambient HTTP(S)_PROXY, no redirects.
  * MED — a sink that cannot export (no exporter installed) reports ``armed=False`` and ``_build_emit``
    refuses to wire it (and never logs "armed") instead of silently skipping every record.
  * LOW — diagnostics never echo userinfo credentials.

Runs without opentelemetry: the exporter module is faked where needed.
"""
from __future__ import annotations

import logging
import sys
import types

import pytest

from vigil_integration.live import otel_export as oe
from vigil_integration.live.otel_export import OTLPSink, endpoint_is_loopback, probe_collector, redact_endpoint

LOOPBACK = "http://127.0.0.1:4318"


@pytest.mark.parametrize("ep", [
    "http://evil.com\\@127.0.0.1:4318",
    "https://evil.com\\@127.0.0.1:4318/v1/traces",
    "http://evil.com:80\\@127.0.0.1:4318",
    "http://127.0.0.1:4318\\evil.com",
    "http://u:p@127.0.0.1:4318",
    "http://evil.com@127.0.0.1:4318",
    "http://127.0.0.1:4318\t",
    "http://127.0.0.1\n:4318",
    "http://127.0.0.1:4318/ ",
    "http://[::1%25eth0]:4318",
    "http://[::1%eth0]:4318",
    "http://127.0.0.1:4318/é",
    "http://１２７.0.0.1:4318",
])
def test_authority_confusion_is_refused_by_the_pin(ep):
    assert endpoint_is_loopback(ep) is False


@pytest.mark.parametrize("ep", [
    "http://127.0.0.1:4318", "https://127.0.0.1:4318/v1/traces", "http://localhost:4318",
    "http://[::1]:4318", "http://127.5.6.7:4318/v1/traces?x=1#frag",
])
def test_every_accepted_endpoint_is_loopback_under_urllib3_too(ep):
    urllib3 = pytest.importorskip("urllib3")
    assert endpoint_is_loopback(ep) is True
    host = urllib3.util.parse_url(oe._traces_url(ep)).host
    assert host in ("127.0.0.1", "localhost", "[::1]", "::1", "127.5.6.7"), host


@pytest.mark.parametrize("raw,shown", [
    ("https://admin:s3cr3t@host:4318/x", "https://***@host:4318/…"),
    ("http://127.0.0.1:4318/v1/traces?api_key=SECRET", "http://127.0.0.1:4318/…"),   # query ⇒ never shown
    ("http://127.0.0.1:4318#token=T", "http://127.0.0.1:4318/…"),                    # fragment ⇒ never shown
    ("http://u:p/w?x@127.0.0.1:4318", "http://***@127.0.0.1:4318"),                   # `/` inside the password
    ("http://127.0.0.1:4318", "http://127.0.0.1:4318"),
    ("http://127.0.0.1:4318/", "http://127.0.0.1:4318"),
    ("not a url", "<endpoint>"),
    (None, ""),
])
def test_redaction_keeps_only_scheme_host_port(raw, shown):
    assert redact_endpoint(raw) == shown


def test_redaction_neutralises_line_forging():
    shown = redact_endpoint("http://a\n  OK vault: ACTIVE\x1b[0m")
    assert "\n" not in shown and "\x1b" not in shown


def test_probe_refusal_detail_never_echoes_credentials():
    probe = probe_collector("https://admin:s3cr3t@collector.corp:4318")
    assert probe.reachable is False and "s3cr3t" not in probe.detail


def _fake_exporter_module(monkeypatch, captured):
    class FakeOTLPSpanExporter:
        def __init__(self, **kw):
            captured.update(kw)

    names = ["opentelemetry", "opentelemetry.exporter", "opentelemetry.exporter.otlp",
             "opentelemetry.exporter.otlp.proto", "opentelemetry.exporter.otlp.proto.http"]
    for n in names:
        if n not in sys.modules:
            monkeypatch.setitem(sys.modules, n, types.ModuleType(n))
    mod = types.ModuleType("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    mod.OTLPSpanExporter = FakeOTLPSpanExporter
    monkeypatch.setitem(sys.modules, mod.__name__, mod)


def test_the_real_exporter_gets_a_pinned_session(monkeypatch):
    pytest.importorskip("requests")
    captured: dict = {}
    _fake_exporter_module(monkeypatch, captured)
    sink = OTLPSink(LOOPBACK)
    assert sink.armed is True
    session = captured["session"]
    assert session.trust_env is False          # no ambient HTTP(S)_PROXY relays loopback telemetry off-box
    assert session.max_redirects == 0          # a redirect from the collector is never followed
    assert captured["endpoint"] == "http://127.0.0.1:4318/v1/traces"


def test_no_pinned_session_means_no_exporter(monkeypatch):
    captured: dict = {}
    _fake_exporter_module(monkeypatch, captured)
    monkeypatch.setitem(sys.modules, "requests", None)      # `import requests` raises ImportError
    sink = OTLPSink(LOOPBACK)
    assert sink.armed is False and captured == {}            # fail closed: inert, never an unpinned exporter


def test_armed_reflects_loopback_and_exporter():
    assert OTLPSink(LOOPBACK, exporter=object()).armed is True
    assert OTLPSink("http://10.0.0.5:4318", exporter=object()).armed is False


def test_build_emit_refuses_an_unarmed_sink_and_never_claims_armed(monkeypatch, caplog):
    from vigil_integration.live import wiring

    monkeypatch.setattr(OTLPSink, "_build_default_exporter", lambda self, ep: None)   # exporter not installed
    monkeypatch.setattr(oe, "probe_collector", lambda ep: oe.CollectorProbe(endpoint=ep, reachable=True, detail=""))
    with caplog.at_level(logging.INFO):
        emit = wiring._build_emit("slug", LOOPBACK)
    assert emit is None                                      # nothing wired: byte-identical to telemetry-off
    msgs = [r.getMessage() for r in caplog.records]
    assert any("NOT armed" in m for m in msgs)
    assert not any("export armed" in m for m in msgs)


def test_sink_log_lines_never_echo_query_secrets(caplog):
    class Down:
        def export(self, spans):
            raise ConnectionError("down")
    ep = "http://127.0.0.1:4318/v1/traces?api_key=SECRET"
    assert endpoint_is_loopback(ep) is True          # a query string is a legal loopback endpoint...
    sink = OTLPSink(ep, exporter=Down(), max_consecutive_failures=1)
    sink._to_readable_span = lambda record: ("readable", record)
    from vigil_integration.observability import new_span
    with caplog.at_level(logging.WARNING):
        sink(new_span("op", spine_hash="h", seq=1))  # latches → logs the endpoint
    assert caplog.records and not any("SECRET" in r.getMessage() for r in caplog.records)   # ...but never logged
