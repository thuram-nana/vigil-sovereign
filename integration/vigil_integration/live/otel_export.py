"""
live.otel_export — the LIVE OTLP exporter binding for the observability plane (VIGIL-LIVE, §12 WS1d).

This is the drop-in for the observability recorder's INJECTED SINK seam. The F11 recorder
(``observability.recorder.SpineTracer``) builds spine-bound, redacted ``Span`` / ``Observation``
records and pushes each to a ``Sink = Callable[[record], Any]`` best-effort; the local
``CollectingExporter`` is the in-memory stand-in and the live OTel collector was deferred. ``OTLPSink``
is that live sink: it converts each record to an OTel ``ReadableSpan`` and hands it to an OTLP/HTTP
exporter (``opentelemetry-exporter-otlp-proto-http``) pointed at the collector.

Going live changes NOTHING about the sovereign contract. This module is EMIT-ONLY and the red-pen
attacks exactly that:

  * **EMIT-ONLY / authorizes nothing.** ``__call__`` returns ``None``; no method returns an
    allow/deny/tier/verdict/authority. The sink echoes telemetry out of the box; it never gates an
    action, mints a fact, or grants a tier. The only observable state is best-effort health COUNTERS
    (``exported``/``dropped``/``refused``/``skipped``) — integers an actor cannot branch on to proceed.
  * **EGRESS PINNED TO LOOPBACK.** For this validation the only permitted OTLP destination is loopback
    (127.0.0.0/8 or ``::1``). A non-loopback ``endpoint`` → the sink NEVER egresses: every ``__call__``
    is refused BEFORE the exporter is touched (even an injected exporter is never called), fail-closed.
    This is a loopback PIN, the inverse of the gateway SSRF denylist (which hard-denies loopback for the
    offense sandbox); the collector is trusted host infrastructure, not an offense target.
  * **SECRET-FREE.** Every exported attribute KEY and VALUE is scrubbed through the SAME F3 spine
    redactor the records were built with (``observability.model.redact_attributes`` → the one
    ``_redact_str`` / ``redact_tool_args`` vocabulary) again at the export boundary, and every value is
    then flattened to an OTLP-native scalar with any stringified form re-scrubbed. The two OTLP
    free-string fields derived from record content — the span/observation NAME (``ReadableSpan.name``)
    and the STATUS message (``Status.description``) — are routed through the SAME ``_redact_str``
    scrubber at that boundary too, so NO free-form string leaves unscrubbed — a secret can never reach
    the collector even if ``OTLPSink`` is handed a hand-built (un-redacted) record.
  * **DETERMINISTIC IDENTITY.** The OTel trace/span ids are derived from the record's already-derived
    spine identity (``spine_hash``/``seq`` via ``observability.identity``) — NO wallclock, NO RNG. Re-
    exporting a byte-identical record yields byte-identical ids.
  * **A DOWN/FAILING COLLECTOR NEVER BREAKS THE ENGINE.** Any exporter error/timeout/failure is
    swallowed (a telemetry outage must never deny cognition), tracked only as ``dropped``. A short
    export timeout plus a deterministic consecutive-failure circuit breaker (``max_consecutive_failures``,
    count-based — no clock) latches the sink silent so a down collector can never stall the hot path.
  * **TOTAL on a malformed record.** Any garbage handed to ``__call__`` degrades to ``skipped`` (no
    signal); the sink never raises into the recorder.

The exporter is INJECTED (``exporter=`` argument) so unit tests use a fake in-memory spy and never
require a live collector; only when it is left ``None`` (and the endpoint is loopback) is a real
``OTLPSpanExporter`` lazily built. ``opentelemetry`` is imported lazily so this module stays import-clean
and inert (never exports) where the package is absent.

Import-clean: stdlib + the F11 observability seam + the F3 redactor; ``opentelemetry`` lazily/optionally.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from ..observability.identity import derive_span_id, derive_trace_id
from ..observability.model import (
    Observation,
    Span,
    SpanStatus,
    coerce_int,
    coerce_str,
    redact_attributes,
)
from ..tools.mcp_registry import _redact_str  # the F3 free-string scrubber (ONE secret vocabulary)

# OTLP HTTP signal path appended to a bare collector base url (per the OTLP/HTTP spec).
_TRACES_PATH = "/v1/traces"
# int64 bounds — an OTLP int attribute must fit a signed 64-bit; anything else is stringified.
_INT64_MIN = -(2 ** 63)
_INT64_MAX = 2 ** 63 - 1
# sentinel: opentelemetry probed and found unavailable (distinct from "not yet probed" == None).
_OTEL_UNAVAILABLE = object()


# ---------------------------------------------------------------------------------------------------
# egress pin — loopback-only destination gate (fail-closed)
# ---------------------------------------------------------------------------------------------------


def endpoint_is_loopback(endpoint: Any) -> bool:
    """Whether an OTLP ``endpoint`` points at LOOPBACK only — the sole destination this validation
    permits. Fail-closed and DNS-free: accepts an ``http(s)://`` url whose host is a loopback IP literal
    (127.0.0.0/8 or ``::1``) or the reserved name ``localhost``; anything else (a public/link-local IP,
    a hostname, a missing scheme, a ``127.0.0.1.evil.com`` look-alike, garbage) → ``False``. Never
    resolves DNS — an unrecognised host is refused rather than looked up. Total: never raises."""
    if not isinstance(endpoint, str) or not endpoint.strip():
        return False
    try:
        parsed = urlparse(endpoint.strip())
    except Exception:  # noqa: BLE001 — a malformed url degrades to "not loopback", never raises
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    host = host.strip()
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _traces_url(endpoint: str) -> str:
    """Normalise a collector base url to its traces signal path. A bare ``http://127.0.0.1:4318`` gets
    ``/v1/traces`` appended; an endpoint that already names a path is used verbatim. Total."""
    try:
        parsed = urlparse(endpoint)
        if not parsed.path or parsed.path == "/":
            return urlunparse(parsed._replace(path=_TRACES_PATH))
    except Exception:  # noqa: BLE001
        return endpoint
    return endpoint


# ---------------------------------------------------------------------------------------------------
# the live OTLP sink
# ---------------------------------------------------------------------------------------------------


class OTLPSink:
    """An EMIT-ONLY OTLP/HTTP sink implementing the observability recorder's injected-sink contract
    (``__call__(record) -> None``). Converts a spine-bound ``Span`` / ``Observation`` to an OTel
    ``ReadableSpan`` and exports it to a loopback OTLP collector, best-effort. It authorizes nothing,
    egresses only to loopback, scrubs every attribute secret-free, derives ids deterministically from
    spine identity, and never lets a down collector break the recorder. Never raises into the caller."""

    def __init__(self, endpoint: Any = "http://127.0.0.1:4318", exporter: Any = None, *,
                 timeout: float = 2.0, max_consecutive_failures: int = 3) -> None:
        self.endpoint: str = coerce_str(endpoint)
        # EGRESS PIN: a non-loopback endpoint disarms the sink entirely — it will never egress.
        self._loopback: bool = endpoint_is_loopback(self.endpoint)
        try:
            self._timeout: float = float(timeout)
        except (TypeError, ValueError):
            self._timeout = 2.0
        self._max_consecutive_failures: int = max(1, coerce_int(max_consecutive_failures, 3))

        # best-effort HEALTH counters — telemetry health only, NOT an authorization surface.
        self.exported: int = 0   # records handed to the collector successfully
        self.dropped: int = 0    # export failures/exceptions (a down collector) — swallowed
        self.refused: int = 0    # non-loopback endpoint → egress refused (never reached the exporter)
        self.skipped: int = 0    # no exporter / unavailable otel / malformed record → no signal

        self._consecutive_failures: int = 0
        self._disabled: bool = False          # circuit breaker: latched silent after repeated failures
        self._otel_cache: Any = None          # None=unprobed, tuple=loaded, _OTEL_UNAVAILABLE=absent

        # Injected exporter wins (tests pass a fake). Only build a REAL exporter when it was not injected
        # AND the endpoint is loopback — a non-loopback endpoint never gets a live exporter.
        if exporter is not None:
            self._exporter: Any = exporter
        elif self._loopback:
            self._exporter = self._build_default_exporter(self.endpoint)
        else:
            self._exporter = None

    # -- public contract -----------------------------------------------------------------------------

    def __call__(self, record: Any) -> None:
        """The injected-sink entry point. Export ``record`` best-effort; return ``None`` always. Any
        failure is swallowed (a telemetry crash must never deny cognition) — the sink NEVER raises."""
        try:
            self._export_one(record)
        except Exception:  # noqa: BLE001 — belt-and-suspenders: the sink must never raise into the recorder
            self.dropped += 1
        return None

    def stats(self) -> dict[str, int]:
        """A snapshot of the best-effort health counters (all integers). Telemetry health only — nothing
        here is an allow/deny an actor could branch on."""
        return {"exported": self.exported, "dropped": self.dropped,
                "refused": self.refused, "skipped": self.skipped}

    # -- export path ---------------------------------------------------------------------------------

    def _export_one(self, record: Any) -> None:
        if not isinstance(record, (Span, Observation)):
            self.skipped += 1                       # None / garbage record → no signal
            return
        if not self._loopback:
            self.refused += 1                       # EGRESS PIN: non-loopback → never egress
            return
        if self._disabled:
            self.skipped += 1                       # circuit breaker latched open (collector proven down)
            return
        if self._exporter is None:
            self.skipped += 1                       # nothing wired to export to
            return
        readable = self._to_readable_span(record)
        if readable is None:
            self.skipped += 1                       # otel absent or record unconvertible → no signal
            return
        if self._do_export(readable):
            self.exported += 1
            self._consecutive_failures = 0
        else:
            self.dropped += 1
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._max_consecutive_failures:
                # Stop hammering a down collector — a deterministic, count-based (no-clock) latch so a
                # dead collector can never stall the engine's hot path indefinitely.
                self._disabled = True

    def _do_export(self, readable: Any) -> bool:
        """Hand one ReadableSpan to the injected exporter; report success. Every exporter error is
        swallowed here (returns ``False``) so a down collector never propagates into the recorder."""
        try:
            result = self._exporter.export([readable])
        except Exception:  # noqa: BLE001 — a failing/down collector is a dropped record, never a crash
            return False
        return _is_export_success(result)

    def _build_default_exporter(self, endpoint: str) -> Any:
        """Lazily build a real OTLP/HTTP span exporter for a loopback collector. Import + construction are
        both guarded: a missing ``opentelemetry`` or a construction error degrades to ``None`` (the sink
        stays inert, never egresses), never a crash. A short timeout keeps a down collector from stalling
        the hot path."""
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except Exception:  # noqa: BLE001 — no otlp exporter installed → inert sink
            return None
        try:
            return OTLPSpanExporter(endpoint=_traces_url(endpoint), timeout=self._timeout)
        except Exception:  # noqa: BLE001
            return None

    # -- record → OTLP ReadableSpan (deterministic identity, secret-free attributes) -----------------

    def _otel(self) -> Optional[tuple]:
        """Lazily import + cache the OTel span types. Returns the tuple, or ``None`` if unavailable."""
        if self._otel_cache is _OTEL_UNAVAILABLE:
            return None
        if self._otel_cache is not None:
            return self._otel_cache
        try:
            from opentelemetry.sdk.trace import ReadableSpan
            from opentelemetry.trace import SpanContext
            from opentelemetry.trace import SpanKind as OTelSpanKind
            from opentelemetry.trace import TraceFlags
            from opentelemetry.trace.status import Status, StatusCode
            self._otel_cache = (ReadableSpan, SpanContext, TraceFlags, OTelSpanKind, Status, StatusCode)
            return self._otel_cache
        except Exception:  # noqa: BLE001 — otel absent → inert (records skipped, never exported)
            self._otel_cache = _OTEL_UNAVAILABLE
            return None

    def _to_readable_span(self, record: Any) -> Any:
        """Convert one spine-bound record to an OTel ``ReadableSpan``. Ids derive from the record's
        spine identity (deterministic, no wallclock/RNG); every attribute is re-scrubbed secret-free and
        flattened to an OTLP-native scalar. Total — returns ``None`` on any conversion failure."""
        types = self._otel()
        if types is None:
            return None
        ReadableSpan, SpanContext, TraceFlags, OTelSpanKind, Status, StatusCode = types
        try:
            if isinstance(record, Span):
                trace_hex, span_hex, parent_hex = record.trace_id, record.span_id, record.parent_span_id
                name = record.name
                kind = getattr(OTelSpanKind, record.kind.name, OTelSpanKind.INTERNAL)
                status = _map_status(record.status, record.status_message, Status, StatusCode)
                start = coerce_int(record.start_ts)
                end = record.end_ts if (isinstance(record.end_ts, int)
                                        and not isinstance(record.end_ts, bool)) else start
                base = {"vigil.record": "span", "vigil.spine_hash": record.spine_hash,
                        "vigil.seq": record.seq}
            else:  # Observation
                trace_hex = record.trace_id
                span_hex = record.id[:16] if isinstance(record.id, str) and record.id else ""
                parent_hex = record.span_id                    # the span the observation hangs off, if any
                name = record.name or record.type.value
                kind = OTelSpanKind.INTERNAL
                status = Status(StatusCode.UNSET)
                start = coerce_int(record.ts)
                end = start                                    # an observation is a point in time
                base = {"vigil.record": "observation", "vigil.observation.type": record.type.value,
                        "vigil.observation.level": record.level.value,
                        "vigil.spine_hash": record.spine_hash, "vigil.seq": record.seq}

            merged = dict(record.attributes)
            merged.update(base)
            # SECRET-FREE: re-run the ONE F3 vocabulary over key+value, then flatten every value to an
            # OTLP-native scalar (re-scrubbing any stringified form) — safe even for a hand-built record.
            attributes = {k: _otlp_scalar(v) for k, v in redact_attributes(merged).items()}

            trace_id = _hex_to_int(trace_hex, 16, derive_trace_id(record.spine_hash))
            span_id = _hex_to_int(span_hex, 8, derive_span_id(record.spine_hash, record.seq))
            ctx = SpanContext(trace_id=trace_id, span_id=span_id, is_remote=False,
                              trace_flags=TraceFlags(TraceFlags.SAMPLED))
            parent = None
            if isinstance(parent_hex, str) and parent_hex:
                parent_id = _hex_to_int(parent_hex, 8, "")
                parent = SpanContext(trace_id=trace_id, span_id=parent_id, is_remote=False,
                                     trace_flags=TraceFlags(TraceFlags.SAMPLED))
            return ReadableSpan(
                # SECRET-FREE: the OTLP span NAME is a record-derived free string — scrub it through the
                # SAME F3 vocabulary as the attributes so a secret in record.name / observation.name can
                # never reach the collector, even on a hand-built (un-redacted) record.
                name=_redact_str(coerce_str(name)),
                context=ctx,
                parent=parent,
                attributes=attributes,
                kind=kind,
                status=status,
                start_time=start,
                end_time=end,
            )
        except Exception:  # noqa: BLE001 — an unconvertible record is skipped, never a crash
            return None


# ---------------------------------------------------------------------------------------------------
# helpers — total + deterministic, no clock/RNG
# ---------------------------------------------------------------------------------------------------


def _is_export_success(result: Any) -> bool:
    """Whether an exporter's return value means "delivered". Handles the real
    ``SpanExportResult.SUCCESS`` (``.name == 'SUCCESS'``), a fake spy returning ``None``/``True``, and an
    int result (``SUCCESS == 0``). A malformed/unknown result is treated as delivered (best-effort — this
    only affects a health counter and the circuit breaker, never an authorization)."""
    if result is None:
        return True
    name = getattr(result, "name", None)
    if isinstance(name, str):
        return name.upper() == "SUCCESS"
    if isinstance(result, bool):
        return result
    if isinstance(result, int):
        return result == 0
    return True


def _otlp_scalar(value: Any) -> Any:
    """Flatten one attribute value to an OTLP-native scalar (``str``/``bool``/``int``/``float``), keeping
    it SECRET-FREE and DETERMINISTIC. A ``str`` is re-scrubbed through the F3 free-string vocabulary; an
    int outside int64 is stringified (its decimal digits — deterministic) and scrubbed. Any non-scalar
    (``None``/dict/list/foreign object) is reduced to a STABLE type token (``<type-name>``, still scrubbed)
    rather than ``str(obj)``: a raw ``str(obj)`` can embed the default object repr's memory ADDRESS (or a
    nested foreign object's), which would make two byte-identical records export different attribute bytes
    and break spine determinism (model.py leaves such objects un-stringified for exactly this reason).
    Total."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if _INT64_MIN <= value <= _INT64_MAX else _redact_str(coerce_str(value))
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        return _redact_str(value)
    return _redact_str("<" + type(value).__name__ + ">")


def _hex_to_int(hex_str: Any, width_bytes: int, fallback_hex: Any) -> int:
    """Parse a hex id to a width-bounded, non-zero int (OTel rejects an all-zero trace/span id). An
    invalid/empty id falls back to the deterministic spine-derived id — identity stays a pure function of
    the injected spine hash/seq, never a clock or RNG. Total."""
    value: Optional[int] = None
    if isinstance(hex_str, str) and hex_str:
        try:
            value = int(hex_str, 16)
        except ValueError:
            value = None
    if value is None:
        try:
            value = int(fallback_hex, 16)
        except (ValueError, TypeError):
            value = 0
    value &= (1 << (width_bytes * 8)) - 1
    return value if value != 0 else 1


def _map_status(status: Any, message: Any, Status: Any, StatusCode: Any) -> Any:
    """Map the record's telemetry ``SpanStatus`` to an OTel ``Status``. A severity, never an
    authorization. Total."""
    if status == SpanStatus.OK:
        code = StatusCode.OK
    elif status == SpanStatus.ERROR:
        code = StatusCode.ERROR
    else:
        code = StatusCode.UNSET
    # SECRET-FREE: the OTLP Status.description is a record-derived free string — scrub it through the
    # SAME F3 vocabulary as the attributes so a secret in status_message can never reach the collector.
    desc = _redact_str(coerce_str(message))
    return Status(code, description=desc or None)
