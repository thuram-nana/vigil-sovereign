"""
verify.adapter — translate already-collected observations into oracle inputs.

`OracleVerifier.confirm` consumes a plain `finding_context` mapping (see
verifier.confirm's docstring). Producing that mapping by hand at every call
site is error-prone and couples the caller to the exact key names. This module
is the single, typed translation layer between *observations a probe already
collected* and *the context the oracle layer judges*.

Hard boundary — this is a TRANSLATOR, not a generator:

  * It never sends traffic, mints payloads, or contacts a target.
  * It takes data the caller already has (two HTTP responses, a list of OOB
    hits, an expected/observed state pair, captured process output, a sink)
    and reshapes it into the keys `confirm` recognises.
  * Everything it emits is JSON-serialisable, so a `FindingContext` can be
    stored alongside the finding it confirms and replayed deterministically.

`FindingContext.to_verifier_context()` yields exactly the dict `confirm`
reads — and only the keys whose inputs are actually present, so an oracle
with no observed data is *skipped*, never fed empty values it might
misjudge.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Coercion helpers — kept local so the adapter depends on nothing but stdlib
# ---------------------------------------------------------------------------


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


def _response_to_dict(value: Any, latency_ms: float | None = None) -> dict[str, Any]:
    """Normalise one observed HTTP response into `{status?, body, latency_ms?}`.

    Accepts (all already-collected, nothing is fetched here):
      * a mapping with any of {status|status_code, body|text|content,
        latency_ms|elapsed_ms};
      * a response-like object exposing `.status_code`/`.status` and
        `.text`/`.content` (httpx.Response, urllib's http.client response, …);
      * a raw `str`/`bytes` body.
    """
    if value is None:
        raise ValueError("response is None; nothing to translate")

    if isinstance(value, Mapping):
        status = value.get("status", value.get("status_code"))
        body = value.get("body", value.get("text", value.get("content")))
        lat = value.get("latency_ms", value.get("elapsed_ms", latency_ms))
        out: dict[str, Any] = {"body": _coerce_text(body if body is not None else "")}
        if status is not None:
            out["status"] = int(status)
        if lat is not None:
            out["latency_ms"] = float(lat)
        return out

    # Duck-typed response object (avoid importing httpx just to isinstance it).
    if hasattr(value, "status_code") or hasattr(value, "status"):
        status = getattr(value, "status_code", None)
        if status is None:
            status = getattr(value, "status", None)
        body = getattr(value, "text", None)
        if body is None:
            body = getattr(value, "content", None)
        out = {"body": _coerce_text(body if body is not None else "")}
        if status is not None:
            out["status"] = int(status)
        if latency_ms is not None:
            out["latency_ms"] = float(latency_ms)
        return out

    # Raw body.
    out = {"body": _coerce_text(value)}
    if latency_ms is not None:
        out["latency_ms"] = float(latency_ms)
    return out


def _hit_to_dict(hit: Any) -> dict[str, Any]:
    """Reduce one OOB interaction (OOBHit model, mapping, or duck-typed object)
    to a JSON-safe dict the oob oracle can read."""
    if hasattr(hit, "model_dump"):
        return dict(hit.model_dump())
    if isinstance(hit, Mapping):
        return dict(hit)
    return {
        "method": getattr(hit, "method", "?"),
        "path": getattr(hit, "path", "?"),
        "client_ip": getattr(hit, "client_ip", "?"),
    }


def _sink_to_serialisable(sink: Any) -> Any:
    """Keep mappings/lists as-is (JSON-safe, and the side-effect oracle searches
    them structurally); coerce anything else to text."""
    if isinstance(sink, Mapping):
        return {str(k): _coerce_text(v) for k, v in sink.items()}
    if isinstance(sink, (list, tuple)):
        return [_coerce_text(x) for x in sink]
    return _coerce_text(sink)


# ---------------------------------------------------------------------------
# FindingContext — the typed carrier of oracle inputs
# ---------------------------------------------------------------------------


class FindingContext(BaseModel):
    """Typed, replayable bundle of the observations one finding is judged on.

    A field left `None` means "this oracle has no observed data" — its key is
    omitted from `to_verifier_context()` and the oracle is skipped. Build one
    with the classmethod that matches the signal you collected; combine several
    by passing more than one builder's output through `merge` if a finding is
    corroborated by multiple oracles."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str = Field(
        default="",
        description="Canonical or aliased bug class; selects the oracle set.",
    )

    # differential_response_oracle
    baseline: dict[str, Any] | None = None
    mutated: dict[str, Any] | None = None
    discriminator: dict[str, Any] | None = None

    # boolean_inference_oracle (SPRT over repeated true/false probes)
    probe_rounds: list[dict[str, Any]] | None = None

    # timing_oracle (statistical time-based blind)
    baseline_latencies: list[float] | None = None
    treatment_latencies: list[float] | None = None
    timing_injected_ms: float | None = None
    timing_alpha: float | None = None
    timing_dose: dict[str, Any] | None = None

    # achieved_state_oracle
    expected_state: dict[str, Any] | None = None
    observed_state: dict[str, Any] | None = None

    # predicate_oracle (evidence-carrying achieved-state; Wave 7)
    observed_evidence: dict[str, Any] | None = None
    predicate: dict[str, Any] | None = None

    # side_effect_oracle
    marker: str | None = None
    observed_sink: Any | None = None

    # evaluation_oracle (SSTI/EL — the server evaluated an injected expression)
    eval_raw: str | None = None
    eval_expected: str | None = None
    eval_observed: str | None = None
    eval_control: str | None = None

    # error_signature_oracle (error-based injection — a datastore/parser error)
    error_observed: str | None = None
    error_control: str | None = None

    # dom_execution_oracle (DOM-XSS — injected JS executed in a real DOM)
    dom_binding_calls: list[str] | None = None
    dom_canary: str | None = None

    # sanitizer_signal_oracle
    process_output: str | None = None

    # oob_callback_oracle
    oob_hits: list[Any] | None = None

    # service_reachability_oracle (a real transport handshake reproduced a scanner's "open port")
    handshake: dict[str, Any] | None = None

    # tls_weakness_oracle (a real TLS handshake negotiated a deprecated protocol / weak cipher)
    tls: dict[str, Any] | None = None

    # version_range_oracle (a package version provably falls in an advisory's affected range)
    version_advisory: dict[str, Any] | None = None

    # -- builders ----------------------------------------------------------

    @classmethod
    def from_http_responses(
        cls,
        baseline: Any,
        mutated: Any,
        *,
        bug_class: str = "boolean_sqli",
        discriminator: Mapping[str, Any] | None = None,
        baseline_latency_ms: float | None = None,
        mutated_latency_ms: float | None = None,
    ) -> "FindingContext":
        """A baseline vs. mutated response pair, for the differential oracle
        (boolean- and time-based blind signals). Latencies are optional and
        only needed for a time-based comparison; omit them for a purely
        boolean (status/length/lexical) differential to stay deterministic."""
        return cls(
            bug_class=bug_class,
            baseline=_response_to_dict(baseline, baseline_latency_ms),
            mutated=_response_to_dict(mutated, mutated_latency_ms),
            discriminator=dict(discriminator) if discriminator is not None else None,
        )

    @classmethod
    def from_boolean_probes(
        cls,
        true_responses: Sequence[Any],
        false_a_responses: Sequence[Any],
        false_b_responses: Sequence[Any],
        *,
        bug_class: str = "boolean_sqli",
        discriminator: Mapping[str, Any] | None = None,
    ) -> "FindingContext":
        """Aligned per-round responses for the SPRT boolean-inference oracle:
        for each round, the TRUE-clause response and two FALSE-clause responses
        (the second is the dynamic-page control). Rounds are zipped to the
        shortest of the three lists; nothing is fetched here."""
        rounds = [
            {"true": _response_to_dict(t), "false_a": _response_to_dict(a), "false_b": _response_to_dict(b)}
            for t, a, b in zip(true_responses, false_a_responses, false_b_responses)
        ]
        return cls(
            bug_class=bug_class,
            probe_rounds=rounds,
            discriminator=dict(discriminator) if discriminator is not None else None,
        )

    @classmethod
    def from_timing_samples(
        cls,
        baseline_latencies: Sequence[float],
        treatment_latencies: Sequence[float],
        *,
        bug_class: str = "time_based_sqli",
        injected_ms: float | None = None,
        alpha: float | None = None,
        dose: Mapping[str, Any] | None = None,
    ) -> "FindingContext":
        """Paired latency samples (a benign baseline vs a delay-injected probe)
        for the statistical timing oracle. ``injected_ms`` is the delay the
        probe tried to induce (enables the effect-size floor); ``dose`` optionally
        carries a second delay's samples for a dose-response check. Samples are
        already-measured milliseconds — nothing is fetched here."""
        return cls(
            bug_class=bug_class,
            baseline_latencies=[float(x) for x in baseline_latencies],
            treatment_latencies=[float(x) for x in treatment_latencies],
            timing_injected_ms=float(injected_ms) if injected_ms is not None else None,
            timing_alpha=float(alpha) if alpha is not None else None,
            timing_dose=dict(dose) if dose is not None else None,
        )

    @classmethod
    def from_oob(
        cls, hits: Any, *, bug_class: str = "ssrf"
    ) -> "FindingContext":
        """A list of out-of-band interactions (whatever `OOBReceiver.poll`
        returned) for the oob-callback oracle. An empty list is a valid,
        non-firing negative control."""
        return cls(
            bug_class=bug_class,
            oob_hits=[_hit_to_dict(h) for h in (hits or [])],
        )

    @classmethod
    def from_state(
        cls,
        expected: Mapping[str, Any],
        observed: Mapping[str, Any],
        *,
        bug_class: str = "idor",
    ) -> "FindingContext":
        """An expected (attacker-predicted) vs. observed state pair for the
        achieved-state oracle (IDOR/BOLA/mass-assignment/privesc)."""
        return cls(
            bug_class=bug_class,
            expected_state=dict(expected or {}),
            observed_state=dict(observed or {}),
        )

    @classmethod
    def from_predicate(
        cls,
        observed_evidence: Mapping[str, Any],
        predicate: Mapping[str, Any],
        *,
        bug_class: str = "cors",
    ) -> "FindingContext":
        """Raw observed values plus a declarative dangerous-condition predicate
        for the predicate oracle (CORS/host-header/redirect/JWT/IDOR/race). The
        oracle — not the check — evaluates the condition, so the verdict is no
        longer a rubber-stamp. Both are JSON so the certificate re-verifies."""
        return cls(
            bug_class=bug_class,
            observed_evidence={str(k): v for k, v in dict(observed_evidence or {}).items()},
            predicate=dict(predicate),
        )

    @classmethod
    def from_handshake(
        cls, handshake: Mapping[str, Any], *, bug_class: str = "service_reachable"
    ) -> "FindingContext":
        """A captured transport handshake (verify.reachability), for the service-reachability
        oracle — the retained connect evidence that turns a scanner's "open port" into a FACT.

        The ``handshake`` MUST come from a real gated connect (``reachability.capture_handshake``),
        NEVER a scanner's parsed "open" row: the oracle re-verifies reachability by an INDEPENDENT
        handshake, so laundering a sensor's ``open`` observation straight into this context would
        defeat prove-don't-guess (the observation stays GROUNDING_INTEL until a live connect
        reproduces it)."""
        return cls(bug_class=bug_class, handshake=dict(handshake or {}))

    @classmethod
    def from_tls_handshake(
        cls, tls: Mapping[str, Any], *, bug_class: str = "weak_tls"
    ) -> "FindingContext":
        """A captured TLS handshake (verify.tls), for the TLS-weakness oracle — the retained negotiated
        protocol/cipher that turns a "weak TLS" observation into a FACT. Like ``from_handshake``, the
        ``tls`` evidence MUST come from a real gated capture (``tls.capture_tls_handshake``), never a
        scanner's parsed row — the oracle re-verifies by an INDEPENDENT handshake."""
        return cls(bug_class=bug_class, tls=dict(tls or {}))

    @classmethod
    def from_version_advisory(
        cls, advisory: Mapping[str, Any], *, bug_class: str = "vulnerable_dependency"
    ) -> "FindingContext":
        """A scanner's advisory match ({package, version, affected range}) for the version-range
        oracle — the retained evidence that proves a package version falls in an advisory's affected
        range. The oracle re-derives membership deterministically, so a scanner's CVE match is
        confirmed a FACT only by the actual version comparison, never the scanner's say-so."""
        return cls(bug_class=bug_class, version_advisory=dict(advisory or {}))

    @classmethod
    def from_process_output(
        cls, captured: Any, *, bug_class: str = "crash"
    ) -> "FindingContext":
        """Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/
        abort/traceback markers)."""
        return cls(bug_class=bug_class, process_output=_coerce_text(captured))

    @classmethod
    def from_side_effect(
        cls,
        marker: str,
        observed_sink: Any,
        *,
        bug_class: str = "xss",
    ) -> "FindingContext":
        """A unique canary marker plus the sink it was observed in, for the
        side-effect oracle (XSS/SSTI/path-traversal/error-based)."""
        return cls(
            bug_class=bug_class,
            marker=_coerce_text(marker),
            observed_sink=_sink_to_serialisable(observed_sink),
        )

    @classmethod
    def from_evaluation(
        cls,
        raw_expr: str,
        expected_result: str,
        observed_body: Any,
        *,
        control_body: Any = None,
        bug_class: str = "ssti",
    ) -> "FindingContext":
        """An injected expression, the value it computes to, and the response it
        was observed in (plus an optional benign control), for the evaluation
        oracle. Confirms SSTI/EL only when the server EVALUATED the expression —
        the result present, the raw template text absent."""
        return cls(
            bug_class=bug_class,
            eval_raw=_coerce_text(raw_expr),
            eval_expected=_coerce_text(expected_result),
            eval_observed=_coerce_text(observed_body),
            eval_control=_coerce_text(control_body) if control_body is not None else None,
        )

    @classmethod
    def from_error_signature(
        cls,
        observed_body: Any,
        *,
        control_body: Any = None,
        bug_class: str = "error_based_sqli",
    ) -> "FindingContext":
        """A response (and an optional benign control) for the error-signature
        oracle. Confirms error-based injection when a distinctive datastore/parser
        error the payload provoked is present in the response but not the control."""
        return cls(
            bug_class=bug_class,
            error_observed=_coerce_text(observed_body),
            error_control=_coerce_text(control_body) if control_body is not None else None,
        )

    @classmethod
    def from_dom_execution(
        cls,
        binding_calls: Sequence[Any],
        canary: str,
        *,
        bug_class: str = "dom_xss",
    ) -> "FindingContext":
        """The arguments a page passed to the CDP execution binding, plus the
        unique canary, for the DOM-execution oracle. Confirms DOM-XSS only when
        the injected script actually ran and called back with the canary."""
        return cls(
            bug_class=bug_class,
            dom_binding_calls=[_coerce_text(c) for c in (binding_calls or [])],
            dom_canary=_coerce_text(canary),
        )

    # -- combination -------------------------------------------------------

    def merge(self, other: "FindingContext") -> "FindingContext":
        """Fold another context's populated inputs into this one, so a single
        finding can be judged by multiple oracles. `self` wins on conflicts;
        `other.bug_class` is only adopted when `self` has none."""
        data = self.model_dump()
        for key, value in other.model_dump().items():
            if key == "bug_class":
                if not data.get("bug_class"):
                    data["bug_class"] = value
                continue
            if data.get(key) is None and value is not None:
                data[key] = value
        return FindingContext(**data)

    # -- emit --------------------------------------------------------------

    def to_verifier_context(self) -> dict[str, Any]:
        """The exact mapping `OracleVerifier.confirm` consumes. Only keys whose
        inputs are present are emitted; a paired oracle (differential,
        achieved-state, side-effect) is only wired when *both* halves exist."""
        ctx: dict[str, Any] = {"bug_class": self.bug_class}
        if self.baseline is not None and self.mutated is not None:
            ctx["baseline"] = self.baseline
            ctx["mutated"] = self.mutated
            if self.discriminator is not None:
                ctx["discriminator"] = self.discriminator
        if self.probe_rounds is not None:
            ctx["probe_rounds"] = self.probe_rounds
            if self.discriminator is not None and "discriminator" not in ctx:
                ctx["discriminator"] = self.discriminator
        if self.baseline_latencies is not None and self.treatment_latencies is not None:
            ctx["baseline_latencies"] = self.baseline_latencies
            ctx["treatment_latencies"] = self.treatment_latencies
            if self.timing_injected_ms is not None:
                ctx["timing_injected_ms"] = self.timing_injected_ms
            if self.timing_alpha is not None:
                ctx["timing_alpha"] = self.timing_alpha
            if self.timing_dose is not None:
                ctx["timing_dose"] = self.timing_dose
        if self.expected_state is not None and self.observed_state is not None:
            ctx["expected_state"] = self.expected_state
            ctx["observed_state"] = self.observed_state
        if self.observed_evidence is not None and self.predicate is not None:
            ctx["observed_evidence"] = self.observed_evidence
            ctx["predicate"] = self.predicate
        if self.marker is not None and self.observed_sink is not None:
            ctx["marker"] = self.marker
            ctx["observed_sink"] = self.observed_sink
        if self.eval_expected is not None and self.eval_observed is not None:
            ctx["eval_raw"] = self.eval_raw or ""
            ctx["eval_expected"] = self.eval_expected
            ctx["eval_observed"] = self.eval_observed
            if self.eval_control is not None:
                ctx["eval_control"] = self.eval_control
        if self.error_observed is not None:
            ctx["error_observed"] = self.error_observed
            if self.error_control is not None:
                ctx["error_control"] = self.error_control
        if self.dom_binding_calls is not None and self.dom_canary is not None:
            ctx["dom_binding_calls"] = self.dom_binding_calls
            ctx["dom_canary"] = self.dom_canary
        if self.process_output is not None:
            ctx["process_output"] = self.process_output
        if self.oob_hits is not None:
            ctx["oob_hits"] = self.oob_hits
        if self.handshake is not None:
            ctx["handshake"] = self.handshake
        if self.tls is not None:
            ctx["tls"] = self.tls
        if self.version_advisory is not None:
            ctx["version_advisory"] = self.version_advisory
        return ctx
