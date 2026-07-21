"""
observability.recorder — the EMIT-ONLY passive recorder + spine-bound builders (VIGIL-FUSION F11, C11).

This is the operating surface of the observability plane. It offers:

  * pure builders — ``new_span`` / ``complete_span`` / ``new_observation`` — that turn injected spine
    identity + (already-redacted) attributes into a typed record. They derive the id deterministically
    (``identity.derive_*``, no wallclock/RNG) and redact every attribute (``model.redact_attributes``).
  * two first-class provable-engine observations — ``guardrail_observation`` on a WARDEN gate block and
    ``evaluator_observation`` on an oracle confirm/refute — matching pentagi's Langfuse taxonomy.
  * ``SpineTracer`` — a thin recorder that holds an INJECTED sink (the exporter; the live OTel collector
    is deferred) and a trace identity. Its methods build a record, push it to the sink, and return the
    record. That is the whole contract.

The sovereign invariant, enforced structurally here (the red-pen attacks exactly this):

  * **EMIT-ONLY / never authorizes.** No function returns an allow/deny/tier verdict — only a ``Span`` /
    ``Observation`` record or ``None``. A WARDEN outcome or an oracle verdict is recorded as an inert,
    redacted descriptive string; recording it changes no gate, mints no fact, grants no tier. The
    guardrail/evaluator helpers OBSERVE a decision made elsewhere — they never make one.
  * **Total on malformed input.** Tool/LLM/attacker-influenced arguments degrade to a stable record or
    to ``None`` (no signal); a builder never raises. A sink that raises is swallowed (a telemetry
    failure must never deny cognition), tracked only as a ``dropped`` counter.
  * **Deterministic + secret-free** (see ``identity`` and ``model``).

Import-clean: stdlib + pydantic + the local model/identity (which reuse the F3 redactor); no framework.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .identity import derive_observation_id, derive_span_id, derive_trace_id
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

# The exporter is an injected sink: a callable given the built record. Its return value is IGNORED and
# any exception it raises is swallowed — telemetry is strictly best-effort and can never gate the loop.
Sink = Callable[[Any], Any]


# ---------------------------------------------------------------------------------------------------
# pure builders
# ---------------------------------------------------------------------------------------------------


def new_span(name: Any, *, trace_id: Any = "", kind: Any = SpanKind.INTERNAL, spine_hash: Any = "",
             seq: Any = 0, ts: Any = 0, parent_span_id: Any = "", span_id: Any = "",
             salt: str = "", attributes: Any = None) -> Optional[Span]:
    """Build a started span bound to the injected spine identity. ``span_id`` derives deterministically
    from ``spine_hash``/``seq`` unless supplied. Total — returns ``None`` on any unexpected error."""
    try:
        sid = coerce_str(span_id) or derive_span_id(spine_hash, seq, salt=salt)
        return Span(
            trace_id=coerce_str(trace_id),
            span_id=sid,
            parent_span_id=coerce_str(parent_span_id),
            name=coerce_str(name),
            kind=coerce_enum(SpanKind, kind, SpanKind.INTERNAL),
            spine_hash=coerce_str(spine_hash),
            seq=coerce_int(seq),
            start_ts=coerce_int(ts),
            end_ts=None,
            status=SpanStatus.UNSET,
            attributes=redact_attributes(attributes),
        )
    except Exception:  # noqa: BLE001 — a telemetry record must never crash the caller
        return None


def complete_span(span: Any, *, ts: Any = 0, status: Any = SpanStatus.OK, status_message: Any = "",
                  attributes: Any = None) -> Optional[Span]:
    """Close a span APPEND-ONLY: returns a NEW span (``model_copy``) with ``end_ts``/``status`` set and
    any extra attributes merged (redacted); the original frozen record is never mutated. A non-``Span``
    input degrades to ``None``. Total."""
    if not isinstance(span, Span):
        return None
    try:
        merged = dict(span.attributes)
        merged.update(redact_attributes(attributes))
        return span.model_copy(update={
            "end_ts": coerce_int(ts),
            "status": coerce_enum(SpanStatus, status, SpanStatus.OK),
            "status_message": coerce_str(status_message),
            "attributes": merged,
        })
    except Exception:  # noqa: BLE001
        return None


def new_observation(obs_type: Any, name: Any, *, trace_id: Any = "", spine_hash: Any = "", seq: Any = 0,
                    ts: Any = 0, span_id: Any = "", level: Any = ObservationLevel.DEFAULT,
                    salt: str = "", obs_id: Any = "", attributes: Any = None) -> Optional[Observation]:
    """Build a Langfuse-style observation bound to spine identity. An UNKNOWN observation type degrades
    to ``None`` (no signal) rather than mislabelling. ``id`` derives deterministically unless supplied.
    Total — never raises."""
    otype = coerce_enum(ObservationType, obs_type, None)
    if otype is None:
        return None
    try:
        name_s = coerce_str(name)
        oid = coerce_str(obs_id) or derive_observation_id(spine_hash, seq, kind=otype.value,
                                                          name=name_s, salt=salt)
        return Observation(
            id=oid,
            trace_id=coerce_str(trace_id),
            span_id=coerce_str(span_id),
            type=otype,
            name=name_s,
            spine_hash=coerce_str(spine_hash),
            seq=coerce_int(seq),
            ts=coerce_int(ts),
            level=coerce_enum(ObservationLevel, level, ObservationLevel.DEFAULT),
            attributes=redact_attributes(attributes),
        )
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------------------------------
# WARDEN Guardrail + oracle Evaluator — the two provable-engine observations
# ---------------------------------------------------------------------------------------------------


def warden_outcome(decision: Any) -> str:
    """Read a WARDEN/gate decision's outcome as a descriptive string, duck-typed across the codebase's
    verdict shapes (``ToolDecision.outcome`` / ``EdgeVerdict.outcome``+``allowed`` /
    ``ToolCallVerdict``). Pure description; this does not decide anything. Unknown → ``"unknown"``."""
    o = getattr(decision, "outcome", None)
    if isinstance(o, str) and o:
        return o
    allowed = getattr(decision, "allowed", None)
    auto = getattr(decision, "auto", None)
    if allowed is True or auto is True:
        return "allow"
    if allowed is False or auto is False:
        return "deny"
    return "unknown"


def is_warden_block(decision: Any) -> bool:
    """Whether a WARDEN decision is a BLOCK (anything that did not auto-allow: deny / queue / unknown).
    Fail-closed for telemetry: an undecipherable decision counts as a block so the Guardrail still
    fires. This is a *description* of a decision made elsewhere, never an authorization."""
    return warden_outcome(decision) not in ("allow", "auto")


def guardrail_observation(tool_name: Any, decision: Any = None, *, trace_id: Any = "", spine_hash: Any = "",
                          seq: Any = 0, ts: Any = 0, span_id: Any = "", salt: str = "",
                          attributes: Any = None) -> Optional[Observation]:
    """A Langfuse **Guardrail** observation for a WARDEN gate block. Records — as INERT, REDACTED
    descriptive strings — the tool, the outcome, the tier and the reason WARDEN reported. These are an
    echo of a decision the gate already made; nothing here gates, and no sovereign-core code reads these
    attributes to authorize. Total — a ``None``/garbage ``decision`` still yields a well-formed record."""
    attrs: dict[str, Any] = {
        "warden.tool": coerce_str(tool_name),
        "warden.outcome": warden_outcome(decision),
        "warden.tier": coerce_str(getattr(decision, "tier", "")),
        "warden.reason": coerce_str(getattr(decision, "reason", "")),
    }
    if isinstance(attributes, dict):
        attrs.update({coerce_str(k): v for k, v in attributes.items()})
    return new_observation(ObservationType.GUARDRAIL, coerce_str(tool_name) or "warden.block",
                           trace_id=trace_id, spine_hash=spine_hash, seq=seq, ts=ts, span_id=span_id,
                           level=ObservationLevel.WARNING, salt=salt, attributes=attrs)


def evaluator_observation(*, confirmed: Any, evidence_ref: Any = "", detail: Any = "", trace_id: Any = "",
                          spine_hash: Any = "", seq: Any = 0, ts: Any = 0, span_id: Any = "",
                          salt: str = "", attributes: Any = None) -> Optional[Observation]:
    """A Langfuse **Evaluator** observation for an oracle confirm/refute. Fires on BOTH a confirm and a
    refute. Records the verdict and the signed ``evidence_ref`` (a spine hash / SCITT cert id — not a
    secret, and the thing that makes the confirm offline-verifiable) as inert descriptive attributes.

    Sovereign posture: only ``confirmed is True`` records ``"confirm"`` (any ambiguous/non-bool value
    fails closed to ``"refute"`` — telemetry never over-claims a confirm). Recording a confirm does NOT
    mint a FACT: this is a passive echo of the oracle's verdict; the signed FACT is minted solely by the
    oracle path in ``agent.react`` / the graph projector, never here. Total — never raises."""
    verdict = "confirm" if confirmed is True else "refute"
    ref = coerce_str(evidence_ref)
    attrs: dict[str, Any] = {
        "oracle.verdict": verdict,
        "oracle.evidence_ref": ref,
        "oracle.evidence_present": bool(ref.strip()),
        "oracle.detail": coerce_str(detail),
    }
    if isinstance(attributes, dict):
        attrs.update({coerce_str(k): v for k, v in attributes.items()})
    level = ObservationLevel.DEFAULT if confirmed is True else ObservationLevel.WARNING
    return new_observation(ObservationType.EVALUATOR, "oracle.verdict", trace_id=trace_id,
                           spine_hash=spine_hash, seq=seq, ts=ts, span_id=span_id, level=level,
                           salt=salt, attributes=attrs)


# ---------------------------------------------------------------------------------------------------
# the emit-only recorder
# ---------------------------------------------------------------------------------------------------


class SpineTracer:
    """A passive, EMIT-ONLY recorder. Holds an INJECTED sink (the exporter) and a stable trace identity
    derived from the engagement's root spine hash. Every method builds a spine-bound, redacted record,
    pushes it to the sink best-effort, and returns the record. It gates nothing and returns no
    authorization; a sink error is swallowed (tracked in ``dropped``), so telemetry never denies
    cognition. It never raises."""

    def __init__(self, *, sink: Optional[Sink] = None, trace_id: Any = "", root_hash: Any = "") -> None:
        self._sink: Optional[Sink] = sink if callable(sink) else None
        self.trace_id: str = coerce_str(trace_id) or derive_trace_id(root_hash)
        self.dropped: int = 0   # count of sink failures — telemetry health, NOT an authorization signal

    def _emit(self, record: Any) -> Any:
        if record is not None and self._sink is not None:
            try:
                self._sink(record)
            except Exception:  # noqa: BLE001 — a failing exporter must never break the engagement
                self.dropped += 1
        return record

    def start_span(self, name: Any, *, kind: Any = SpanKind.INTERNAL, spine_hash: Any = "", seq: Any = 0,
                   ts: Any = 0, parent_span_id: Any = "", span_id: Any = "", salt: str = "",
                   attributes: Any = None) -> Optional[Span]:
        return self._emit(new_span(name, trace_id=self.trace_id, kind=kind, spine_hash=spine_hash,
                                   seq=seq, ts=ts, parent_span_id=parent_span_id, span_id=span_id,
                                   salt=salt, attributes=attributes))

    def end_span(self, span: Any, *, ts: Any = 0, status: Any = SpanStatus.OK, status_message: Any = "",
                 attributes: Any = None) -> Optional[Span]:
        return self._emit(complete_span(span, ts=ts, status=status, status_message=status_message,
                                        attributes=attributes))

    def observe(self, obs_type: Any, name: Any, *, spine_hash: Any = "", seq: Any = 0, ts: Any = 0,
                span_id: Any = "", level: Any = ObservationLevel.DEFAULT, salt: str = "",
                attributes: Any = None) -> Optional[Observation]:
        return self._emit(new_observation(obs_type, name, trace_id=self.trace_id, spine_hash=spine_hash,
                                          seq=seq, ts=ts, span_id=span_id, level=level, salt=salt,
                                          attributes=attributes))

    def on_warden_decision(self, tool_name: Any, decision: Any, *, spine_hash: Any = "", seq: Any = 0,
                           ts: Any = 0, span_id: Any = "", salt: str = "", attributes: Any = None,
                           always: bool = False) -> Optional[Observation]:
        """Emit a Guardrail observation ON A BLOCK. By default it fires only when the WARDEN decision is
        a block (deny/queue/unknown) and returns ``None`` for an auto-allow (no block → no guardrail);
        ``always=True`` records every decision. Emit-only — this never affects the decision itself."""
        if not always and not is_warden_block(decision):
            return None
        return self._emit(guardrail_observation(tool_name, decision, trace_id=self.trace_id,
                                                spine_hash=spine_hash, seq=seq, ts=ts, span_id=span_id,
                                                salt=salt, attributes=attributes))

    def on_oracle_verdict(self, confirmed: Any, *, evidence_ref: Any = "", detail: Any = "",
                          spine_hash: Any = "", seq: Any = 0, ts: Any = 0, span_id: Any = "",
                          salt: str = "", attributes: Any = None) -> Optional[Observation]:
        """Emit an Evaluator observation for an oracle confirm/refute. Emit-only — recording a confirm
        does not mint a fact."""
        return self._emit(evaluator_observation(confirmed=confirmed, evidence_ref=evidence_ref,
                                                detail=detail, trace_id=self.trace_id, spine_hash=spine_hash,
                                                seq=seq, ts=ts, span_id=span_id, salt=salt,
                                                attributes=attributes))


class CollectingExporter:
    """A trivial in-memory sink (the injected exporter contract, for tests and local debugging). The
    live OTel collector / Langfuse stack is the deferred production sink. Passive: it stores the records
    it is handed; it authorizes nothing and is never consulted by the sovereign core."""

    def __init__(self) -> None:
        self.records: list[Any] = []

    def __call__(self, record: Any) -> None:
        self.records.append(record)

    def spans(self) -> list[Span]:
        return [r for r in self.records if isinstance(r, Span)]

    def observations(self) -> list[Observation]:
        return [r for r in self.records if isinstance(r, Observation)]
