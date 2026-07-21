"""
vigil_integration.observability — spine-bound, EMIT-ONLY telemetry (VIGIL-FUSION F11, C11).

An OTel-style span/trace model + a Langfuse-style observation taxonomy (Generation/Agent/Tool/Chain/
Retriever/Evaluator/Embedding/Guardrail), reimplemented from pentagi's design (design-only; Go source
never vendored) and bound to VIGIL's signed spine identity. One identity is threaded through: a span/
observation carries the spine record hash and a deterministically-derived id, so traces and spine
records share an id — the corpus is offline-verifiable AND debuggable.

Two provable-engine observations are first-class: a **Guardrail** on every WARDEN gate block and an
**Evaluator** on every oracle confirm/refute.

The sovereign invariant this package upholds (and its tests attack):

  * **EMIT-ONLY.** Observability describes; it never gates or authorizes. No record and no function
    exposes an allow/deny/tier verdict — a WARDEN outcome or oracle verdict is recorded only as an
    inert, redacted descriptive string, and nothing in the sovereign core reads it back to decide.
  * **SECRET-FREE.** Every attribute is scrubbed through the F3 spine redactor at construction.
  * **DETERMINISTIC.** Ids derive from the injected spine hash/seq via ``sha256`` — no wallclock, no
    RNG; timestamps are injected. A trace rebuilds byte-identically from the same spine records.
  * **TOTAL.** Every public function degrades malformed input to a stable record or ``None``; a failing
    sink is swallowed. A telemetry crash is a denial-of-cognition, and this package refuses to cause one.

The exporter is modelled as an INJECTED sink; the live OTel collector / Langfuse stack is deferred.
Import-clean: pydantic + stdlib + the F3 redactor only.
"""

from .identity import (
    derive_observation_id,
    derive_span_id,
    derive_trace_id,
    span_id_matches,
)
from .model import (
    Observation,
    ObservationLevel,
    ObservationType,
    Span,
    SpanKind,
    SpanStatus,
    coerce_enum,
    coerce_int,
    coerce_str,
    redact_attributes,
)
from .recorder import (
    CollectingExporter,
    Sink,
    SpineTracer,
    complete_span,
    evaluator_observation,
    guardrail_observation,
    is_warden_block,
    new_observation,
    new_span,
    warden_outcome,
)

__all__ = [
    # identity
    "derive_trace_id", "derive_span_id", "derive_observation_id", "span_id_matches",
    # model
    "Span", "Observation", "SpanKind", "SpanStatus", "ObservationType", "ObservationLevel",
    "coerce_str", "coerce_int", "coerce_enum", "redact_attributes",
    # recorder
    "Sink", "SpineTracer", "CollectingExporter",
    "new_span", "complete_span", "new_observation",
    "guardrail_observation", "evaluator_observation", "warden_outcome", "is_warden_block",
]
