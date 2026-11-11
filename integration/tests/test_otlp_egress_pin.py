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

Audit folds (the "no endpoint secret on any surface" invariant):

  * LOW — ``redact_endpoint`` split everything after ``://`` at the LAST ``@`` and treated the tail as host:port,
    so an ``@`` in the path / query / fragment printed what followed it (``?user=ops@corp.example&token=SECRET``
    was shown as ``***@corp.example&token=SECRET``). The authority is now isolated first; an ``@`` after it is
    ambiguous and shows no part of the authority at all; only host:port-shaped text is ever echoed.
  * LOW — ``_build_emit`` logged the RAW endpoint (query string included) on the "export armed" INFO line.

Runs without opentelemetry: the exporter module is faked where needed.
"""
from __future__ import annotations

import http.server
import itertools
import logging
import re
import sys
import threading
import types
from urllib.parse import urlsplit

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
    ("http://127.0.0.1:4318", "http://127.0.0.1:4318"),
    ("http://127.0.0.1:4318/", "http://127.0.0.1:4318"),
    ("http://[::1]:4318/v1/traces?api_key=SECRET", "http://[::1]:4318/…"),
    ("https://admin:p@ss@host:4318/x?k=v", "https://***@host:4318/…"),               # `@` inside the password
    ("not a url", "<endpoint>"),
    (None, ""),
    # An `@` AFTER the authority (path / query / fragment / after a backslash). Splitting the whole remainder at
    # its LAST `@` printed everything after it as "host:port" — `***@corp.example&token=SECRET`, `***@SECRET`.
    ("http://127.0.0.1:4318/v1/traces?user=ops@corp.example&token=SECRET", "http://***/…"),
    ("http://127.0.0.1:4318/v1/traces?api_key=abc@SECRET", "http://***/…"),
    ("http://127.0.0.1:4318/v1/traces#a@SECRET", "http://***/…"),
    ("http://127.0.0.1:4318/a@SECRET", "http://***/…"),
    ("http://127.0.0.1:4318?k=abc@SECRET", "http://***/…"),
    ("http://127.0.0.1:4318#abc@SECRET", "http://***/…"),
    ("http://evil.com\\@127.0.0.1:4318?token=SECRET", "http://***/…"),
    # ...and the same string read the OTHER way — a password with an unencoded `/ ? #` — must not print the
    # user / password head that sits before the first delimiter either. Ambiguous ⇒ neither side is shown.
    ("http://u:p/w?x@127.0.0.1:4318", "http://***/…"),
    ("https://admin:pa/ss@collector.corp:4318", "https://***/…"),
    ("https://admin:pa#ss@collector.corp:4318/v1/traces", "https://***/…"),
    ("https://admin:12345/678@collector.corp:4318", "https://***/…"),               # a digits-only password head
    ("http://admin/pw@127.0.0.1:4318", "http://***/…"),                              # would pass for host:port
    # A "host:port" that is not host:port-shaped is never echoed (a secret separated by something other than
    # `/ ? #`, a non-numeric "port").
    ("http://127.0.0.1:4318 token=SECRET", "http://***"),
    ("http://127.0.0.1:4318&token=SECRET", "http://***"),
    ("http://127.0.0.1:4318;token=SECRET/v1/traces", "http://***/…"),
    ("http://127.0.0.1:SECRET", "http://***"),
])
def test_redaction_keeps_only_scheme_host_port(raw, shown):
    assert redact_endpoint(raw) == shown


# The differential: every SENSITIVE part below is spelled in UPPERCASE letters, every scheme / host / port in
# lowercase + digits, so "an uppercase letter in the output" is a leak whatever the parser.
_D_SCHEMES = ["http", "https"]
_D_USERINFO = ["", "USER@", "USER:PASSWORD@", "USER:PASS@WORD@", "USER:PA/SSWORD@", "USER:PA?SSWORD@",
               "USER:PA#SSWORD@", "USER:PA\\SSWORD@",
               "USER/NAME@", "USER:98765/SSWORD@"]      # heads that are host:port-SHAPED on their own
_D_HOSTS = ["127.0.0.1:4318", "127.0.0.1", "localhost:4318", "[::1]:4318", "collector.corp:4318"]
_D_PATHS = ["", "/", "/V1/TRACES", "/V1/OPS@CORP", "\\EVIL@CORP"]
_D_QUERIES = ["", "?API_KEY=SECRET", "?USER=OPS@CORP.EXAMPLE&TOKEN=SECRET", "?API_KEY=ABC@SECRET"]
_D_FRAGMENTS = ["", "#TOKEN=SECRET", "#ABC@SECRET"]
_D_SHAPE = re.compile(r"https?://(?:\*\*\*|(?:\*\*\*@)?(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::[0-9]+)?)(?:/…)?")


def _runs(text, n=3):
    return {text[i:i + n] for i in range(len(text) - n + 1)}


def test_redaction_never_echoes_any_run_of_the_path_query_fragment_or_userinfo():
    """Differential against TWO independent readings of each endpoint — RFC 3986 (``urllib.parse.urlsplit``: the
    authority ends at the first ``/ ? #``) and the operator's (everything before the LAST ``@`` is the
    credential, even when the password contains ``/ ? #``). The redacted form must contain no character run of
    the path, query, fragment or userinfo under EITHER reading, and must still show the host whenever the two
    readings agree on where it is."""
    checked = shown_host = 0
    for scheme, ui, host, path, query, frag in itertools.product(
            _D_SCHEMES, _D_USERINFO, _D_HOSTS, _D_PATHS, _D_QUERIES, _D_FRAGMENTS):
        raw = f"{scheme}://{ui}{host}{path}{query}{frag}"
        shown = redact_endpoint(raw)
        assert not any(ch.isupper() for ch in shown), (raw, shown)          # nothing sensitive, by alphabet
        assert _D_SHAPE.fullmatch(shown), (raw, shown)                      # only scheme://[***@]host:port[/…]
        rest = raw.split("://", 1)[1]
        parts = [rest.rpartition("@")[0]]                                   # the operator's reading of userinfo
        try:
            sp = urlsplit(raw)                                              # the RFC reading
            parts += [sp.path, sp.query, sp.fragment, sp.netloc.rpartition("@")[0]]
        except ValueError:
            pass
        for part in parts:
            leaked = sorted(run for run in _runs(part) if run in shown)
            assert not leaked, (raw, shown, leaked)
        ambiguous = "@" in path + query + frag or any(c in ui for c in "/?#\\")
        if ambiguous:
            assert shown.startswith(f"{scheme}://***") and host not in shown, (raw, shown)
        else:
            assert shown.startswith(f"{scheme}://{'***@' if ui else ''}{host}"), (raw, shown)
            shown_host += 1
        checked += 1
    assert checked == 2 * 10 * 5 * 5 * 4 * 3 and shown_host > 300            # the corpus really ran, both ways


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


@pytest.fixture()
def loopback_collector():
    """A REAL loopback HTTP listener that answers the collector preflight (any status proves reachability)."""
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(5)


def _logged(caplog):
    """Every way a log record can reach an operator: the formatted message and the raw args (a JSON / structured
    handler serialises ``record.args`` itself)."""
    return [r.getMessage() + " | " + repr(r.args) for r in caplog.records]


def test_build_emit_never_logs_the_raw_endpoint_when_it_arms(monkeypatch, caplog, loopback_collector):
    """The reachable + armed path, end to end through the real preflight: ``_build_emit`` announced the collector
    with the RAW endpoint — ``…/v1/traces?api_key=SECRET`` — at INFO. It must log the redacted form only."""
    from vigil_integration.live import wiring

    ep = f"http://127.0.0.1:{loopback_collector}/v1/traces?api_key=SECRET"
    assert endpoint_is_loopback(ep) is True                                  # a legal endpoint, really wired
    monkeypatch.setattr(OTLPSink, "_build_default_exporter", lambda self, e: object())   # exporter "installed"
    with caplog.at_level(logging.DEBUG):
        emit = wiring._build_emit("slug", ep)
    assert emit is not None                                                  # the sink IS armed and wired
    armed = [r.getMessage() for r in caplog.records if "export armed" in r.getMessage()]
    assert armed == [f"OTLP collector reachable at http://127.0.0.1:{loopback_collector}/… — engine telemetry "
                     f"export armed"]
    assert not any("SECRET" in line or "api_key" in line for line in _logged(caplog))


@pytest.mark.parametrize("state", ["unreachable", "unarmed"])
def test_build_emit_never_logs_the_raw_endpoint_on_its_other_paths(monkeypatch, caplog, state, loopback_collector):
    from vigil_integration.live import wiring

    port = loopback_collector if state == "unarmed" else 1                   # port 1: nothing listens there
    if state == "unarmed":
        monkeypatch.setattr(OTLPSink, "_build_default_exporter", lambda self, e: None)
    else:
        monkeypatch.setattr(OTLPSink, "_build_default_exporter", lambda self, e: object())
    with caplog.at_level(logging.DEBUG):
        wiring._build_emit("slug", f"http://127.0.0.1:{port}/v1/traces?api_key=SECRET")
    assert caplog.records                                                    # each path says something...
    assert not any("SECRET" in line or "api_key" in line for line in _logged(caplog))   # ...never the secret


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
