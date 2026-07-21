"""
observability.model — the typed OTel span + Langfuse observation records (VIGIL-FUSION F11, C11).

pentagi runs a two-plane telemetry stack: ONE OpenTelemetry pipeline of generic ``Span``s (kind
Internal/Server/Client/Producer/Consumer) for infra signals, and a SEPARATE Langfuse plane with an
LLM-native observation taxonomy (Generation/Agent/Tool/Chain/Retriever/Evaluator/Embedding/Guardrail).
This module reimplements the SHAPE of both as passive, serialisable, **EMIT-ONLY** records — bound to
spine identity and, critically, carrying NO authorization surface.

The sovereign invariant is baked into the TYPES here (the red-pen attacks exactly this):

  * A ``Span`` / ``Observation`` is a passive RECORD. It has no ``allowed`` / ``allow`` / ``deny`` /
    ``authorize`` / ``tier`` field and no method that returns an authorization. Anything a WARDEN gate
    or an oracle *decided* is recorded — if at all — only as an INERT, REDACTED descriptive string
    inside ``attributes`` (an echo of a decision made elsewhere); nothing in the sovereign core ever
    reads it back to gate or to mint a fact. Observability describes; it never decides.
  * Records are ``frozen``: a consumer cannot mutate a recorded span into a different verdict, and an
    "end" is an append-only ``model_copy`` to a NEW span, never an in-place edit of a signed record.
  * Every ``attributes`` KEY and VALUE is run through the F3 redaction — the SAME scrubber and secret
    vocabulary the immutable spine uses (``_redact_str`` on each key string, ``redact_tool_args`` on the
    values) — at construction time, so a str-typed attribute (the only shape JSON-native tool/LLM output
    parses to) can never carry a credential to a log/collector. Two documented best-effort residuals,
    inherited from the F3 scrubber and NOT silently claimed away: a purely POSITIONAL secret, and a
    secret reachable only through a NON-str value's ``__repr__`` (a foreign object — unreachable from
    JSON-native untrusted input, and deliberately not stringified because ``str(obj)`` would inject a
    non-deterministic address and break spine determinism). See ``redact_attributes``.

``status`` (OTel span status) and ``level`` (Langfuse observation level) are telemetry SEVERITIES —
they say "this span errored" / "this observation is a warning", never "this action is authorized".

Import-clean: pydantic + stdlib + the F3 redactor only.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..tools import redact_tool_args
from ..tools.mcp_registry import _redact_str  # the F3 free-string scrubber (ONE secret vocabulary)


class SpanKind(str, Enum):
    """OTel span kind. Purely descriptive (where a span sits in a call graph) — NOT an authority."""

    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class SpanStatus(str, Enum):
    """OTel span status — a telemetry outcome of the traced operation, never an authorization."""

    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


class ObservationType(str, Enum):
    """The Langfuse LLM-native observation taxonomy. GUARDRAIL (gate blocks) and EVALUATOR (oracle
    verdicts) are the two VIGIL leans on hardest — an off-the-shelf telemetry shape for exactly the
    events a provable engine produces."""

    GENERATION = "generation"
    AGENT = "agent"
    TOOL = "tool"
    CHAIN = "chain"
    RETRIEVER = "retriever"
    EVALUATOR = "evaluator"
    EMBEDDING = "embedding"
    GUARDRAIL = "guardrail"


class ObservationLevel(str, Enum):
    """Langfuse observation level — a telemetry SEVERITY (debug/default/warning/error). It grades how
    noteworthy a record is; it is NOT an allow/deny."""

    DEBUG = "debug"
    DEFAULT = "default"
    WARNING = "warning"
    ERROR = "error"


# ---------------------------------------------------------------------------------------------------
# coercion helpers — everything here is total (attacker-influenceable input degrades, never crashes)
# ---------------------------------------------------------------------------------------------------


def coerce_str(v: Any, default: str = "") -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return default
    try:
        return str(v)
    except Exception:  # noqa: BLE001 — a hostile __str__ must not crash record construction
        return default


def coerce_int(v: Any, default: int = 0) -> int:
    """Timestamps/sequences are injected monotone integers. A ``bool`` is an ``int`` subclass but is
    never a valid time coordinate, so it degrades to the default (deny-the-ambiguous)."""
    if isinstance(v, bool) or not isinstance(v, int):
        return default
    return v


def coerce_enum(enum_cls: type, v: Any, default: Any) -> Any:
    """Coerce ``v`` to a member of ``enum_cls`` by value then by NAME; unknown → ``default`` (which may
    be ``None`` so a caller can degrade an unknown observation type to 'no signal')."""
    if isinstance(v, enum_cls):
        return v
    if isinstance(v, str):
        try:
            return enum_cls(v)
        except ValueError:
            try:
                return enum_cls[v.upper()]
            except KeyError:
                return default
    return default


def redact_attributes(attributes: Any) -> dict[str, Any]:
    """Scrub every attribute — KEY and VALUE — before it is recorded, reusing the F3 spine redactor (ONE
    secret vocabulary, ONE scrubber path). Each KEY string is run through the SAME free-string scrubber
    the values use (``_redact_str`` — masks an inline ``secret=…`` / ``Bearer …`` / ``--secret …`` /
    ``user:pass@`` credential smuggled INTO a key), then the VALUES are scrubbed by ``redact_tool_args``
    (a value under a secret key is masked whole; inline ``Bearer``/``api_key=``/``--secret``/``user:pass@``
    secrets in free strings are scrubbed; nested dicts/lists are descended). Key- and value-scrubbing
    share ``_is_secret_key``/``_redact_str`` so they can never disagree. Non-dict input → ``{}`` (no
    signal). Total: any redactor error also degrades to ``{}`` rather than leaking or crashing.

    This is the load-bearing SECRET-FREE guarantee for the str-typed attributes JSON-native tool/LLM
    output parses to (str/int/float/bool/None/dict/list): a span/observation is built ONLY from the
    output of this function. Documented best-effort residuals (NOT silently claimed, inherited from the
    F3 scrubber): a purely POSITIONAL secret with no key/flag/structure, and a secret reachable only
    through a NON-str value's ``__repr__`` (a foreign object — unreachable from JSON-native untrusted
    input, and deliberately left un-stringified so a non-deterministic ``repr`` address can never break
    spine determinism). Declare secrets via a named key/flag rather than positionally, and record
    str/JSON-native attribute values."""
    if not isinstance(attributes, dict):
        return {}
    try:
        # Scrub BOTH sides of every pair through the ONE F3 vocabulary: the KEY string via _redact_str
        # (the same free-string scrubber the values use), then the values via redact_tool_args.
        normalized = {_redact_str(coerce_str(k)): val for k, val in attributes.items()}
        return redact_tool_args(normalized)
    except Exception:  # noqa: BLE001 — fail secret-free-and-empty, never leak the raw attribute
        return {}


class Span(BaseModel):
    """One OTel-style span, bound to spine identity. ``spine_hash`` is the shared identity linking the
    span to the signed spine record it describes (offline-verifiable); ``span_id`` is its OTel-shaped,
    deterministically-derived id. ``start_ts`` / ``end_ts`` are INJECTED integer timestamps (the spine
    sequence or a caller clock) — never read from the wallclock here. FROZEN and authorization-free."""

    model_config = ConfigDict(frozen=True)

    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    name: str = ""
    kind: SpanKind = SpanKind.INTERNAL
    spine_hash: str = ""                       # shared identity → the signed spine record
    seq: int = 0                               # injected spine sequence (deterministic coordinate)
    start_ts: int = 0                          # injected timestamp (NOT wallclock)
    end_ts: Optional[int] = None               # None while open; set (append-only) on completion
    status: SpanStatus = SpanStatus.UNSET
    status_message: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)   # ALWAYS pre-redacted


class Observation(BaseModel):
    """One Langfuse-style observation, bound to spine identity. Shares the ``trace_id`` of the span/run
    that produced it and carries the ``spine_hash`` of the record it describes, so telemetry and the
    signed corpus share one identity. FROZEN and authorization-free — the WARDEN outcome / oracle
    verdict it may record lives only as an inert redacted string in ``attributes``."""

    model_config = ConfigDict(frozen=True)

    id: str = ""
    trace_id: str = ""
    span_id: str = ""                          # the span this observation hangs off (if any)
    type: ObservationType
    name: str = ""
    spine_hash: str = ""                       # shared identity → the signed spine record
    seq: int = 0
    ts: int = 0                                # injected timestamp (NOT wallclock)
    level: ObservationLevel = ObservationLevel.DEFAULT
    attributes: dict[str, Any] = Field(default_factory=dict)   # ALWAYS pre-redacted
