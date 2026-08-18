"""
W17-5 (#539) — the OTLP sink is WIRED into the observability recorder.

Before this slice ``live.otel_export.OTLPSink`` had ZERO callers: the ``otel-collector`` service shipped in
``docker-compose.yml`` and the AS-BUILT docs claimed the "OTLP exporter [was] wired into the engine", yet
no code path ever handed a span to the sink. These tests defend the wiring that closes that gap:

  * ``observability.make_sink`` — register the live, loopback-pinned ``OTLPSink`` behind the endpoint
    config, OFF by default (no endpoint ⇒ no sink ⇒ the recorder emits to nothing, byte-identical); and
  * ``live.wiring._build_emit`` — the engine's F11 emit seam that maps each signed ``ExecRecord`` the OODA
    loop emits into a spine-bound span exported to the collector, also OFF by default.

The invariant they guard: the wiring authorizes NOTHING (emit-only), it stays OFF by default, and it
PRESERVES the OTLPSink loopback egress pin (registration can never widen the destination).

Framework-free and otel-free by construction: the assertions ride the sink's health COUNTERS and an
injected capturing sink, so they run in the sovereign CI leg whether or not ``opentelemetry`` is installed
(the collector/wire-level export is separately covered, otel-gated, in ``test_live_otel_export.py``).
"""
from __future__ import annotations

from vigil_integration.live.executor import ExecRecord
from vigil_integration.live.wiring import _build_emit
from vigil_integration.observability import (
    Span,
    SpanKind,
    SpanStatus,
    SpineTracer,
    make_sink,
)

LOOPBACK = "http://127.0.0.1:4318"


class _SpyExporter:
    """The injected OTLP exporter contract (``export(spans) -> result``). Captures spans; no network."""

    def __init__(self) -> None:
        self.calls: list = []

    def export(self, spans):
        self.calls.extend(spans)
        return None


# --- make_sink: register OTLPSink behind the endpoint config, OFF by default ------------------------

def test_make_sink_is_off_by_default():
    # OFF by default: no endpoint ⇒ no sink registered ⇒ the recorder emits to nothing (byte-identical to
    # before this seam existed). A ``None`` sink is the recorder's own "emit nowhere" default.
    assert make_sink() is None
    assert make_sink(otlp_endpoint=None) is None
    assert make_sink(otlp_endpoint="") is None


def test_make_sink_registers_the_live_otlp_sink_when_an_endpoint_is_configured():
    sink = make_sink(otlp_endpoint=LOOPBACK, exporter=_SpyExporter())
    assert sink is not None, "a configured OTLP endpoint must register a live sink (OTLPSink), not nothing"
    assert type(sink).__name__ == "OTLPSink"


def test_a_recorded_span_reaches_the_registered_otlp_sink():
    # THE core wiring. A span recorded through the SpineTracer whose sink is the registered OTLPSink
    # actually REACHES the sink — proven by exactly one health counter ticking per record (``exported`` when
    # a collector/otel is present, else ``skipped``); either way the record reached ``OTLPSink.__call__``.
    #
    # FAIL-BEFORE: without make_sink's OTLP branch, ``make_sink(otlp_endpoint=...)`` returns None, the first
    # assert fires, and — as it was before this slice — no span can EVER reach OTLPSink (it had 0 callers).
    sink = make_sink(otlp_endpoint=LOOPBACK, exporter=_SpyExporter())
    assert sink is not None
    before = sum(sink.stats().values())
    tr = SpineTracer(sink=sink, root_hash="engagement-1")
    span = tr.start_span("recon.scan", spine_hash="h", seq=1)
    assert isinstance(span, Span)
    assert sum(sink.stats().values()) - before == 1, "the recorded span never reached the OTLP sink"


def test_registration_preserves_the_loopback_egress_pin():
    # NEGATIVE CONTROL: registering a sink can never widen the destination past loopback. A non-loopback
    # endpoint yields a sink that REFUSES every record (never egresses) — the counter that ticks is
    # ``refused``, never ``exported``, and the injected exporter is never even called. This also proves the
    # positive test above is not vacuous (the counter does not simply always tick ``exported``).
    spy = _SpyExporter()
    sink = make_sink(otlp_endpoint="http://8.8.8.8:4318", exporter=spy)
    assert sink is not None and type(sink).__name__ == "OTLPSink"
    tr = SpineTracer(sink=sink, root_hash="engagement-1")
    tr.start_span("op", spine_hash="h", seq=1)
    stats = sink.stats()
    assert stats["refused"] == 1 and stats["exported"] == 0
    assert spy.calls == []


# --- _build_emit: the engine's F11 emit seam, OFF by default ----------------------------------------

def test_build_emit_is_off_by_default():
    # OFF by default: no otlp_endpoint ⇒ no emit seam ⇒ the engine emits no telemetry span (byte-identical).
    assert _build_emit("slug", None) is None
    assert _build_emit("slug", "") is None


def test_build_emit_maps_an_exec_record_to_a_span_that_reaches_the_sink():
    # With an OTLP endpoint configured the seam maps each signed ExecRecord into a spine-bound span and
    # hands it to the sink. FAIL-BEFORE: with the seam un-wired (``_build_emit`` returning None), there is
    # no callable to map records — the ExecRecord never becomes a span and nothing reaches the sink.
    captured: list = []
    emit = _build_emit("slug", LOOPBACK, sink=lambda r: captured.append(r))
    assert callable(emit)
    rec = ExecRecord(seq=3, now=1000, tool="nmap", phase="informational", tier="A1",
                     target="127.0.0.1", exit_code=0)
    assert emit(rec) is None                              # emit-only: returns no verdict an actor can branch on
    assert len(captured) == 1 and isinstance(captured[0], Span)
    span = captured[0]
    assert span.name == "live.exec:nmap" and span.kind == SpanKind.CLIENT
    assert span.seq == 3 and span.status == SpanStatus.OK
    assert span.attributes["vigil.tool"] == "nmap"
    assert span.attributes["vigil.target"] == "127.0.0.1"
    # DETERMINISTIC identity: the span's spine hash is the signed record's own id (no wallclock/RNG).
    assert span.spine_hash == rec.record_id


def test_build_emit_maps_a_failed_exec_to_an_error_span():
    captured: list = []
    emit = _build_emit("slug", LOOPBACK, sink=lambda r: captured.append(r))
    emit(ExecRecord(seq=4, now=2, tool="sqlmap", exit_code=1))
    assert captured[0].status == SpanStatus.ERROR


def test_build_emit_is_total_and_emit_only():
    # NEGATIVE CONTROL + totality: a non-ExecRecord is no signal (no span is produced), and a raising sink
    # (a down collector) is swallowed — telemetry never raises into, nor denies, cognition.
    captured: list = []
    emit = _build_emit("slug", LOOPBACK, sink=lambda r: captured.append(r))
    for garbage in (None, 123, "x", {"not": "a record"}, object()):
        assert emit(garbage) is None
    assert captured == [], "a non-record must produce no span"

    def boom(_record):
        raise ConnectionError("collector down")

    emit_boom = _build_emit("slug", LOOPBACK, sink=boom)
    # a live record through a failing sink: swallowed, never raises out of the emit seam.
    assert emit_boom(ExecRecord(seq=1, now=1, tool="nmap", exit_code=0)) is None
