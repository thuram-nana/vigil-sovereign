"""
verify.poc_translate — turn EXECUTOR-captured exchanges into a ``FindingContext`` (Proof Studio B1).

The oracle only ever judges a ``FindingContext``. :mod:`verify.adapter` already knows how to build one
from observations a probe collected (``from_http_responses``, ``from_process_output``, ``from_evaluation``,
``from_error_signature``, ``from_request_payload``). This module is the single, typed bridge between
:class:`evidence.poc.CapturedExchange` records — the raw request/response bytes an executor captured while
driving the target — and those builders.

Hard boundary (mirrors ``adapter``): this is a TRANSLATOR, not a generator or a judge.

  * It never sends traffic, mints a payload, or contacts a target.
  * It reads bytes the caller already captured (via an injected ``resolve`` that maps a byte-ref to its
    bytes) and reshapes them into a ``FindingContext``.
  * It returns ``None`` — never a fabricated context — when the capture does not carry the STRUCTURE an
    oracle needs (an unmapped channel, a missing half of a paired oracle, a byte-ref that will not
    resolve). A ``None`` here is the honest "nothing to adjudicate": the mint then yields a LEAD. It does
    NOT itself decide whether the oracle FIRES — a present-but-benign capture (baseline == mutated) still
    translates to a context; the oracle declines to fire over it. That separation keeps the translator
    dumb and the oracle the sole authority.

Everything it emits is JSON-serialisable, so the resulting context re-verifies offline.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from .adapter import FindingContext

# Channel families this translator understands. A capture whose channel is not one of these yields None
# (an honest "no reproducible context") rather than a guessed oracle input.
HTTP_DIFFERENTIAL = "http_differential"   # baseline vs mutated HTTP response bodies (boolean/differential blind)
PROCESS = "process"                       # captured stdout/stderr (sanitizer/crash markers)
EVALUATION = "evaluation"                 # an injected expression the server evaluated (SSTI/EL)
ERROR_SIGNATURE = "error_signature"       # a datastore/parser error a payload provoked
REQUEST_PAYLOAD = "request_payload"       # a single decoded request-parameter value (request-side parse-proof)

_KNOWN_CHANNELS = frozenset(
    {HTTP_DIFFERENTIAL, PROCESS, EVALUATION, ERROR_SIGNATURE, REQUEST_PAYLOAD}
)

ResolveFn = Callable[[str], "bytes | None"]


def _decode(raw: "bytes | None") -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _by_role(exchanges: Sequence[Any], role: str) -> Any | None:
    for ex in exchanges:
        if getattr(ex, "role", "") == role:
            return ex
    return None


def _resp_body(ex: Any, resolve: ResolveFn) -> str | None:
    """Resolve one exchange's response bytes to text, or None if it cannot be resolved. The captured
    'response bytes' are the RESPONSE BODY the oracle adjudicates (status is carried structurally on the
    exchange), so the comparison stays deterministic — volatile headers (Date/Server) are not captured."""
    ref = getattr(ex, "response_bytes_ref", "") or ""
    if not ref:
        return None
    return _decode(resolve(ref))


def context_from_exchanges(
    exchanges: Sequence[Any],
    *,
    bug_class: str,
    resolve: ResolveFn,
    discriminator: Mapping[str, Any] | None = None,
) -> FindingContext | None:
    """Build the ``FindingContext`` a set of captured exchanges proves, or ``None`` if the capture lacks
    the structure any supported oracle needs.

    ``exchanges`` are :class:`evidence.poc.CapturedExchange` (duck-typed: ``.channel``, ``.role``,
    ``.status``, ``.response_bytes_ref``). All exchanges must share one ``channel`` — a single translation
    is one oracle family. ``resolve`` maps a byte-ref to its raw bytes (the executor-captured, non-LLM
    channel); a ref that resolves to ``None`` collapses the whole translation to ``None`` (fail-closed —
    a context is never built from bytes the translator could not read)."""
    exs = list(exchanges or [])
    if not exs or not str(bug_class or "").strip():
        return None
    channel = getattr(exs[0], "channel", "")
    if channel not in _KNOWN_CHANNELS:
        return None
    if any(getattr(e, "channel", "") != channel for e in exs):
        return None                       # a single translator handles exactly one channel family

    if channel == HTTP_DIFFERENTIAL:
        baseline = _by_role(exs, "baseline")
        mutated = _by_role(exs, "mutated")
        if baseline is None or mutated is None:
            return None
        b_body = _resp_body(baseline, resolve)
        m_body = _resp_body(mutated, resolve)
        if b_body is None or m_body is None:
            return None
        return FindingContext.from_http_responses(
            {"status": getattr(baseline, "status", None), "body": b_body},
            {"status": getattr(mutated, "status", None), "body": m_body},
            bug_class=bug_class,
            discriminator=dict(discriminator) if discriminator is not None
            else {"dimensions": ["status", "length", "lexical"]},
        )

    if channel == PROCESS:
        ex = exs[0]
        body = _resp_body(ex, resolve)
        if body is None:
            return None
        return FindingContext.from_process_output(body, bug_class=bug_class)

    if channel == ERROR_SIGNATURE:
        observed = _by_role(exs, "mutated") or exs[0]
        control = _by_role(exs, "control")
        obs_body = _resp_body(observed, resolve)
        if obs_body is None:
            return None
        ctrl_body = _resp_body(control, resolve) if control is not None else None
        return FindingContext.from_error_signature(obs_body, control_body=ctrl_body, bug_class=bug_class)

    if channel == EVALUATION:
        # The injected expression + its expected value ride on the request ref (decoded), the evaluated
        # result on the response ref; a benign control is the optional control-role exchange.
        treatment = _by_role(exs, "treatment") or _by_role(exs, "mutated") or exs[0]
        raw_expr = _decode(resolve(getattr(treatment, "request_bytes_ref", "") or "")) or ""
        observed = _resp_body(treatment, resolve)
        if not raw_expr or observed is None:
            return None
        expected = getattr(treatment, "bug_class", "") and ""   # placeholder; caller supplies via request
        # The expected value is carried as the FIRST line of the request ref ("<expected>\n<raw_expr>"),
        # so the translator needs no extra field. If the format is not present, we cannot translate.
        parts = raw_expr.split("\n", 1)
        if len(parts) != 2 or not parts[0].strip():
            return None
        expected, raw_expr = parts[0].strip(), parts[1]
        control = _by_role(exs, "control")
        ctrl_body = _resp_body(control, resolve) if control is not None else None
        return FindingContext.from_evaluation(
            raw_expr, expected, observed, control_body=ctrl_body, bug_class=bug_class
        )

    if channel == REQUEST_PAYLOAD:
        ex = exs[0]
        payload = _decode(resolve(getattr(ex, "request_bytes_ref", "") or ""))
        if payload is None:
            return None
        return FindingContext.from_request_payload(
            payload, bug_class=bug_class, param=getattr(ex, "role", "") or ""
        )

    return None  # pragma: no cover - defensive; _KNOWN_CHANNELS is exhaustive above
