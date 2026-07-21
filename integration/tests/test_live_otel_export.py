"""
WS1d-otel — the LIVE OTLP exporter binding (``live.otel_export.OTLPSink``) for the F11 observability
plane. The through-line every test defends is the sovereign invariant the red-pen attacks: the sink is
EMIT-ONLY (it returns no allow/deny/tier/verdict — only a health counter), egress is PINNED TO LOOPBACK
(a non-loopback endpoint never egresses — the injected exporter is never even called), every exported
attribute is SECRET-FREE (F3-redacted key AND value, all the way to the OTLP wire form), identity is
DETERMINISTIC (trace/span ids derive from the injected spine hash/seq — no wallclock/RNG), a DOWN/failing
collector never breaks the recorder or the engine (errors swallowed + a count-based circuit breaker), and
the sink is TOTAL on a malformed record (never raises into the recorder).
"""

from __future__ import annotations

import pathlib

import pytest

from vigil_integration.live.otel_export import (
    OTLPSink,
    _hex_to_int,
    _is_export_success,
    _otlp_scalar,
    endpoint_is_loopback,
)
from vigil_integration.observability import (
    Span,
    SpanKind,
    SpanStatus,
    SpineTracer,
    derive_span_id,
    derive_trace_id,
    new_observation,
    new_span,
)

# opentelemetry is required to actually build the ReadableSpan a real collector would receive.
otel_sdk = pytest.importorskip("opentelemetry.sdk.trace")
otel_encoder = pytest.importorskip("opentelemetry.exporter.otlp.proto.common.trace_encoder")
encode_spans = otel_encoder.encode_spans

# Any of these on the sink would mean the exporter can authorize — NONE may be present (EMIT-ONLY).
_AUTHORITY_SURFACE = ("allowed", "allow", "deny", "denied", "authorize", "authorized",
                      "tier", "outcome", "verdict", "grant", "permit")

LOOPBACK = "http://127.0.0.1:4318"


class SpyExporter:
    """A fake in-memory OTLP exporter (the injected-exporter contract, ``export(spans) -> result``). It
    captures the ReadableSpans it is handed so a test can inspect the exact wire-bound records — and it
    never touches the network, so the suite never requires a live collector."""

    def __init__(self, result: object = None) -> None:
        self.calls: list = []
        self.batches: int = 0
        self._result = result

    def export(self, spans):
        self.batches += 1
        self.calls.extend(spans)
        return self._result


class BoomExporter:
    """A fake standing in for a DOWN collector — every export raises (a ConnectionError analogue)."""

    def __init__(self) -> None:
        self.attempts = 0

    def export(self, spans):
        self.attempts += 1
        raise ConnectionError("collector down")


def _wire(spy: SpyExporter) -> bytes:
    """Serialise the captured spans to the exact OTLP protobuf that would hit the collector."""
    return encode_spans(spy.calls).SerializePartialToString()


# --- egress PIN: loopback-only destination gate -----------------------------------------------------

@pytest.mark.parametrize("endpoint,expected", [
    ("http://127.0.0.1:4318", True),
    ("https://127.0.0.1:4318/v1/traces", True),
    ("http://127.5.6.7:4318", True),            # anywhere in 127.0.0.0/8
    ("http://[::1]:4318", True),                # IPv6 loopback
    ("http://localhost:4318", True),            # the reserved loopback name
    ("http://169.254.169.254:4318", False),     # cloud metadata (link-local) — NEVER
    ("http://8.8.8.8:4318", False),             # public
    ("http://10.0.0.5:4318", False),            # private, still not loopback
    ("http://127.0.0.1.evil.com:4318", False),  # look-alike hostname, not an IP literal
    ("http://2130706433:4318", False),          # decimal 127.0.0.1 form — refused (fail-closed)
    ("ftp://127.0.0.1:4318", False),            # non-http scheme refused
    ("127.0.0.1:4318", False),                  # no scheme → hostname unparsed → refused
    ("not a url", False),
    ("", False),
    (None, False),
    (12345, False),
])
def test_endpoint_loopback_gate_is_fail_closed(endpoint, expected):
    assert endpoint_is_loopback(endpoint) is expected


# --- basic export to the injected exporter ----------------------------------------------------------

def test_records_export_to_the_injected_exporter_as_readable_spans():
    spy = SpyExporter()
    sink = OTLPSink(LOOPBACK, exporter=spy)
    s = new_span("http.get", kind=SpanKind.CLIENT, spine_hash="rec:abc", seq=12, ts=1000,
                 attributes={"http.method": "GET"})
    o = new_observation("tool", "nmap", spine_hash="h2", seq=2, ts=50, attributes={"port": 80})
    sink(s)
    sink(o)
    assert sink.stats() == {"exported": 2, "dropped": 0, "refused": 0, "skipped": 0}
    assert len(spy.calls) == 2
    rs = spy.calls[0]
    assert rs.name == "http.get"
    assert rs.attributes["http.method"] == "GET"
    assert rs.attributes["vigil.record"] == "span"
    assert rs.attributes["vigil.spine_hash"] == "rec:abc"
    # the OTLP wire encoding must succeed (a real collector would accept these).
    assert len(_wire(spy)) > 0


def test_call_returns_none_and_records_are_valid_otel_spans():
    spy = SpyExporter()
    sink = OTLPSink(LOOPBACK, exporter=spy)
    assert sink(new_span("op", spine_hash="h", seq=1)) is None      # EMIT-ONLY: no verdict returned
    assert isinstance(spy.calls[0], otel_sdk.ReadableSpan)


# --- DETERMINISTIC identity: ids derive from the injected spine hash/seq (no wallclock/RNG) ----------

def test_span_ids_are_deterministic_and_spine_derived():
    spy1, spy2 = SpyExporter(), SpyExporter()
    make = lambda: new_span("op", spine_hash="rec:xyz", seq=7, ts=9,      # noqa: E731
                            attributes={"a": "1"})
    OTLPSink(LOOPBACK, exporter=spy1)(make())
    OTLPSink(LOOPBACK, exporter=spy2)(make())
    rs1, rs2 = spy1.calls[0], spy2.calls[0]
    # byte-identical ids across two independent exporters — pure function of spine identity.
    assert rs1.context.trace_id == rs2.context.trace_id
    assert rs1.context.span_id == rs2.context.span_id
    # and they equal the deterministic spine derivation the record itself used.
    assert format(rs1.context.trace_id, "032x") == derive_trace_id("rec:xyz")
    assert format(rs1.context.span_id, "016x") == derive_span_id("rec:xyz", 7)


def test_ids_are_never_zero_even_for_an_empty_record():
    # an all-zero trace/span id is rejected by OTel; a bare record must still get a non-zero, deterministic id.
    spy = SpyExporter()
    OTLPSink(LOOPBACK, exporter=spy)(new_span("", spine_hash="", seq=0))
    rs = spy.calls[0]
    assert rs.context.trace_id != 0 and rs.context.span_id != 0


# --- SECRET-FREE: every exported attribute (key AND value) is scrubbed all the way to the wire -------

def test_secrets_never_reach_the_exported_span_or_the_wire():
    spy = SpyExporter()
    sink = OTLPSink(LOOPBACK, exporter=spy)
    sink(new_span("llm.call", spine_hash="h", seq=1, attributes={
        "authorization": "Bearer sk-SUPERSECRET-TOKEN-1234567890",
        "api_key": "AKIA-DEADBEEF-SECRET",
        "note": "curl -H 'Authorization: Bearer sk-LEAK-98765' https://t",
        "url": "https://user:hunter2@target.example/path",
        "safe": "kept",
    }))
    rs = spy.calls[0]
    blob = _wire(spy)
    for secret in (b"SUPERSECRET", b"DEADBEEF", b"sk-LEAK-98765", b"hunter2"):
        assert secret not in blob, f"secret {secret!r} leaked into the OTLP wire form"
    assert rs.attributes["safe"] == "kept"      # non-secret structure preserved


def test_secret_smuggled_into_an_attribute_KEY_is_scrubbed_before_export():
    # a JSON object can carry ANY string key — a secret smuggled into a KEY is attacker-reachable and must
    # be scrubbed by the SAME F3 vocabulary the values use, even if OTLPSink is handed a raw record.
    spy = SpyExporter()
    OTLPSink(LOOPBACK, exporter=spy)(new_observation("generation", "llm", spine_hash="h", seq=1,
        attributes={"aws_secret_access_key=AKIA-KEYLEAK-9999": "x", "safe": "kept"}))
    blob = _wire(spy)
    assert b"AKIA-KEYLEAK-9999" not in blob
    assert spy.calls[0].attributes["safe"] == "kept"


def test_a_hand_built_unredacted_record_is_still_scrubbed_at_the_export_boundary():
    # defense in depth: even a Span constructed DIRECTLY (bypassing the recorder's redaction) must not
    # carry a secret to the collector — the sink re-runs the F3 redaction at the export boundary.
    raw = Span(name="op", trace_id="a" * 32, span_id="b" * 16, spine_hash="h", seq=1,
               attributes={"token": "sk-RAW-RECORD-LEAK-7777"})
    spy = SpyExporter()
    OTLPSink(LOOPBACK, exporter=spy)(raw)
    assert b"sk-RAW-RECORD-LEAK-7777" not in _wire(spy)


def test_secret_in_span_name_status_message_or_obs_name_never_reaches_the_wire():
    # FINDING-1 regression: ReadableSpan.name and Status.description are the two OTLP free-string fields
    # derived from record content (record.name / observation.name / record.status_message). A secret
    # smuggled into any of them on a HAND-BUILT (un-redacted) record must be F3-scrubbed at the export
    # boundary exactly like the attributes are — or it reaches the collector wire.
    spy = SpyExporter()
    sink = OTLPSink(LOOPBACK, exporter=spy)
    sink(Span(name="Authorization: Bearer sk-NAMELEAK-ABCDEF123456", span_id="b" * 16,
              spine_hash="h", seq=1))                                            # secret in Span.name
    sink(Span(name="op", span_id="c" * 16, spine_hash="h", seq=2, status=SpanStatus.ERROR,
              status_message="boom Authorization: Bearer sk-STATUSLEAK-99887766"))  # secret in status_message
    sink(new_observation("tool", "Authorization: Bearer sk-OBSNAMELEAK-5555",
                         spine_hash="h", seq=3))                                 # secret in Observation.name
    blob = _wire(spy)
    for secret in (b"sk-NAMELEAK-ABCDEF123456", b"sk-STATUSLEAK-99887766", b"sk-OBSNAMELEAK-5555"):
        assert secret not in blob, f"secret {secret!r} leaked through an OTLP name/status free-string field"


def test_otlp_scalar_flattens_non_scalars_secret_free_and_deterministic():
    # values must become OTLP-native scalars; a non-scalar is reduced to a STABLE type token that is
    # re-scrubbed, so a secret reachable only through a value's repr cannot leak AND (FINDING-2) no
    # non-deterministic memory address is ever embedded.
    class Leaky:
        def __repr__(self) -> str:
            return "authorization=Bearer sk-REPR-LEAK-5555"

    assert _otlp_scalar(True) is True
    assert _otlp_scalar(5) == 5
    assert _otlp_scalar(1.5) == 1.5
    assert "sk-REPR-LEAK-5555" not in _otlp_scalar(Leaky())          # foreign object → scrubbed type token
    assert "sk-REPR-LEAK-5555" not in _otlp_scalar({"authorization": "Bearer sk-REPR-LEAK-5555"})
    assert isinstance(_otlp_scalar(2 ** 70), str)                    # out-of-int64 → stringified (valid OTLP)
    # DETERMINISM: two distinct plain objects (whose default repr embeds a per-instance memory address)
    # must flatten to the SAME bytes — no address leaks into the exported attribute.
    a, b = _otlp_scalar(object()), _otlp_scalar(object())
    assert a == b == "<object>"
    assert "0x" not in a                                             # never a memory address


def test_foreign_object_attribute_exports_deterministically_no_memory_address():
    # FINDING-2 regression at the export boundary: a record carrying a foreign object attribute must
    # export byte-identically across two runs — a raw str(obj) would embed a per-instance memory address
    # and make two byte-identical records diverge on the wire (breaking spine determinism).
    def export(val):
        spy = SpyExporter()
        OTLPSink(LOOPBACK, exporter=spy)(Span(name="op", span_id="a" * 16, spine_hash="h", seq=1,
                                              attributes={"weird": val}))
        return spy.calls[0].attributes["weird"], _wire(spy)

    v1, blob1 = export(object())
    v2, blob2 = export(object())
    assert v1 == v2 == "<object>"                 # stable type token, not str(obj)
    assert "0x" not in v1                          # no memory address embedded
    assert blob1 == blob2                          # byte-identical OTLP wire form across runs


# --- EGRESS PIN: a non-loopback endpoint NEVER egresses (the exporter is never called) ---------------

def test_non_loopback_endpoint_never_calls_the_injected_exporter():
    for bad in ("http://169.254.169.254:4318", "http://8.8.8.8:9", "http://evil.example.com:4318",
                "http://127.0.0.1.evil.com:4318", "not a url"):
        spy = SpyExporter()
        sink = OTLPSink(bad, exporter=spy)      # even WITH an exporter injected...
        sink(new_span("exfil", spine_hash="h", seq=1))
        assert spy.calls == [], f"{bad} egressed to the exporter"     # ...it is NEVER reached
        assert sink.refused == 1 and sink.exported == 0


def test_non_loopback_endpoint_builds_no_real_exporter():
    sink = OTLPSink("http://8.8.8.8:4318")      # no injected exporter, non-loopback
    assert sink._exporter is None               # a live exporter is never built off-loopback
    sink(new_span("op", spine_hash="h", seq=1))
    assert sink.refused == 1


# --- a DOWN/failing collector never breaks the recorder or the engine -------------------------------

def test_a_failing_exporter_is_swallowed_and_never_raises():
    boom = BoomExporter()
    sink = OTLPSink(LOOPBACK, exporter=boom)
    assert sink(new_span("op", spine_hash="h", seq=1)) is None      # export raised internally...
    assert sink.dropped == 1 and sink.exported == 0                 # ...tracked as dropped, not raised


def test_export_failure_result_counts_as_dropped_not_delivered():
    from opentelemetry.sdk.trace.export import SpanExportResult
    spy = SpyExporter(result=SpanExportResult.FAILURE)
    sink = OTLPSink(LOOPBACK, exporter=spy)
    sink(new_span("op", spine_hash="h", seq=1))
    assert sink.dropped == 1 and sink.exported == 0


def test_circuit_breaker_latches_silent_after_repeated_failures():
    # a persistently down collector must not be hammered forever on the hot path — after N consecutive
    # failures the sink latches silent (count-based, no clock) and stops calling the exporter entirely.
    boom = BoomExporter()
    sink = OTLPSink(LOOPBACK, exporter=boom, max_consecutive_failures=3)
    for i in range(3):
        sink(new_span("op", spine_hash="h", seq=i))
    assert boom.attempts == 3 and sink.dropped == 3
    # further records are skipped WITHOUT touching the exporter — the down collector can't stall the engine.
    sink(new_span("op", spine_hash="h", seq=99))
    assert boom.attempts == 3 and sink.skipped == 1


def test_a_success_resets_the_failure_streak():
    class Flaky:
        def __init__(self):
            self.n = 0

        def export(self, spans):
            self.n += 1
            if self.n in (1, 3):
                raise ConnectionError("blip")
            return None

    sink = OTLPSink(LOOPBACK, exporter=Flaky(), max_consecutive_failures=2)
    sink(new_span("op", spine_hash="h", seq=1))     # fail (streak 1)
    sink(new_span("op", spine_hash="h", seq=2))     # success → streak reset to 0
    sink(new_span("op", spine_hash="h", seq=3))     # fail (streak 1, not 2) → NOT latched
    assert sink._disabled is False and sink.exported == 1 and sink.dropped == 2


def test_recorder_is_never_broken_by_a_down_collector_end_to_end():
    # wire OTLPSink (down collector) as the SpineTracer's injected sink — the recorder must still return
    # its records and must NOT increment ITS OWN dropped counter (the sink swallows internally).
    boom = BoomExporter()
    sink = OTLPSink(LOOPBACK, exporter=boom)
    tr = SpineTracer(sink=sink, root_hash="engagement-1")
    s = tr.start_span("recon.scan", spine_hash="h", seq=1)
    o = tr.on_oracle_verdict(True, evidence_ref="cert:1", spine_hash="h", seq=2)
    assert isinstance(s, Span) and o is not None        # cognition proceeds despite the dead collector
    assert tr.dropped == 0                               # the recorder saw no failure (sink swallowed it)
    assert sink.dropped == 2                             # the sink tracked the drops for telemetry health


# --- TOTAL on malformed input -----------------------------------------------------------------------

@pytest.mark.parametrize("garbage", [None, 123, "a string", {"not": "a record"}, [1, 2], object()])
def test_total_on_a_malformed_record(garbage):
    spy = SpyExporter()
    sink = OTLPSink(LOOPBACK, exporter=spy)
    assert sink(garbage) is None                # never raises
    assert spy.calls == [] and sink.skipped == 1    # a non-record is no signal, never exported


def test_no_exporter_wired_still_never_raises():
    sink = OTLPSink(LOOPBACK, exporter=None)
    # force the "no live exporter available" path deterministically (don't depend on collector presence).
    sink._exporter = None
    assert sink(new_span("op", spine_hash="h", seq=1)) is None
    assert sink.skipped == 1


def test_otel_unavailable_makes_the_sink_inert():
    from vigil_integration.live.otel_export import _OTEL_UNAVAILABLE
    spy = SpyExporter()
    sink = OTLPSink(LOOPBACK, exporter=spy)
    sink._otel_cache = _OTEL_UNAVAILABLE        # simulate opentelemetry absent
    sink(new_span("op", spine_hash="h", seq=1))
    assert spy.calls == [] and sink.skipped == 1    # no otel → no conversion → no export, no crash


# --- helper units -----------------------------------------------------------------------------------

def test_hex_to_int_is_total_and_bounded():
    assert _hex_to_int("ff", 8, "aa") == 0xFF
    assert _hex_to_int("not-hex", 8, "ab") == 0xAB        # invalid → deterministic fallback
    assert _hex_to_int("", 8, "") == 1                    # all-zero → forced non-zero
    assert _hex_to_int(None, 16, None) == 1
    assert _hex_to_int("f" * 40, 8, "") == (1 << 64) - 1  # masked to width


def test_is_export_success_maps_the_real_and_fake_results():
    from opentelemetry.sdk.trace.export import SpanExportResult
    assert _is_export_success(SpanExportResult.SUCCESS) is True
    assert _is_export_success(SpanExportResult.FAILURE) is False
    assert _is_export_success(None) is True               # a spy returning None counts as delivered
    assert _is_export_success(True) is True
    assert _is_export_success(0) is True and _is_export_success(1) is False


def test_default_exporter_is_built_only_for_a_loopback_endpoint():
    # a loopback endpoint with no injected exporter lazily builds a REAL OTLP exporter (construction only —
    # no network). It is never built off-loopback.
    live = OTLPSink(LOOPBACK)
    assert live._exporter is not None
    assert type(live._exporter).__name__ == "OTLPSpanExporter"
    off = OTLPSink("http://8.8.8.8:4318")
    assert off._exporter is None


# ====================================================================================================
# THE SOVEREIGN INVARIANT — the OTLP sink is EMIT-ONLY, loopback-pinned, secret-free, deterministic,
# and can never break the engine. This is the adversarial test the red-pen attacks; it asserts every
# clause of the invariant at once.
# ====================================================================================================

def test_sovereign_invariant_otlp_sink_emit_only_loopback_secret_free_deterministic_total():
    # (1) EMIT-ONLY: the sink exposes NO authorization surface, and __call__ yields a verdict-free None.
    spy = SpyExporter()
    sink = OTLPSink(LOOPBACK, exporter=spy)
    for attr in _AUTHORITY_SURFACE:
        assert not hasattr(sink, attr), f"OTLPSink exposes an authorization surface .{attr}"
    ret = sink(new_span("exploit", kind=SpanKind.CLIENT, spine_hash="s3", seq=3, ts=102,
                        attributes={"prompt": "auth: Bearer sk-INVARIANT-LEAK-1", "safe": "ok"}))
    assert ret is None                                   # never a verdict an actor could branch on

    # (2) SECRET-FREE all the way to the wire — the attribute KEY and VALUE, AND the two OTLP free-string
    #     fields derived from record content (the span/observation NAME and the STATUS message). A secret
    #     smuggled into ANY of these on a hand-built record must never reach the wire.
    sink(Span(name="Authorization: Bearer sk-NAMELEAK-INV", span_id="b" * 16, spine_hash="s3", seq=8))
    sink(Span(name="op", span_id="c" * 16, spine_hash="s3", seq=9, status=SpanStatus.ERROR,
              status_message="Authorization: Bearer sk-STATUSLEAK-INV"))
    sink(new_observation("tool", "Authorization: Bearer sk-OBSNAMELEAK-INV", spine_hash="s3", seq=10))
    blob = _wire(spy)
    for secret in (b"sk-INVARIANT-LEAK-1", b"sk-NAMELEAK-INV", b"sk-STATUSLEAK-INV", b"sk-OBSNAMELEAK-INV"):
        assert secret not in blob, f"secret {secret!r} reached the OTLP collector wire"
    assert spy.calls[0].attributes["safe"] == "ok"

    # (3) DETERMINISTIC identity: the exported ids are a pure function of injected spine identity — a
    #     byte-identical replay through a fresh sink reproduces them; no wallclock, no RNG.
    spy2 = SpyExporter()
    OTLPSink(LOOPBACK, exporter=spy2)(new_span("exploit", kind=SpanKind.CLIENT, spine_hash="s3", seq=3,
                                              ts=102,
                                              attributes={"prompt": "auth: Bearer sk-INVARIANT-LEAK-1",
                                                          "safe": "ok"}))
    assert spy2.calls[0].context.span_id == spy.calls[0].context.span_id
    assert format(spy.calls[0].context.span_id, "016x") == derive_span_id("s3", 3)

    # (4) EGRESS PINNED TO LOOPBACK: the same records aimed at cloud-metadata NEVER reach the exporter.
    evil_spy = SpyExporter()
    evil = OTLPSink("http://169.254.169.254:4318", exporter=evil_spy)
    evil(new_span("exfil", spine_hash="s3", seq=3, attributes={"data": "secret"}))
    evil(new_observation("tool", "curl", spine_hash="s4", seq=4))
    assert evil_spy.calls == [] and evil.refused == 2 and evil.exported == 0

    # (5) A DOWN COLLECTOR NEVER BREAKS THE ENGINE: wired to a live recorder, cognition still proceeds
    #     and the recorder never sees a failure (the sink swallows it).
    boom = BoomExporter()
    tr = SpineTracer(sink=OTLPSink(LOOPBACK, exporter=boom), root_hash="X")
    assert isinstance(tr.start_span("op", spine_hash="h", seq=1), Span)
    assert tr.dropped == 0

    # (6) TOTAL: fully hostile input to the emit path returns None and never raises.
    assert sink(object()) is None and sink(None) is None


def test_no_wallclock_or_rng_in_the_exporter_source():
    """Structural guard: the identity-bearing exporter must contain NO wallclock/RNG so an OTLP span id
    can never become non-deterministic. (The lazily-imported opentelemetry SDK uses time/random for the
    HTTP retry BACKOFF — that is the transport layer, not our span-identity layer, and is not imported at
    module scope here.)"""
    src = pathlib.Path(__file__).resolve().parents[1] / "vigil_integration" / "live" / "otel_export.py"
    text = src.read_text(encoding="utf-8")
    for token in ("import time", "import random", "import datetime", "import uuid", "import secrets",
                  "time.time", "datetime.now", "utcnow", "random.", "uuid.", "secrets."):
        assert token not in text, f"otel_export.py contains forbidden non-determinism source {token!r}"
