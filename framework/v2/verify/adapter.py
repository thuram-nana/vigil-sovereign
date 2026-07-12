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


# The bounded window AEGIS retains around a disclosed canary (PR1 privacy contract): the
# sentinel is kept VERBATIM (so the oracle re-fires offline) plus a small context margin,
# and the rest of the model transcript is dropped — never the whole output.
_DISCLOSURE_MARGIN = 32


def _bounded_disclosure_span(canary: str, output: Any, *, margin: int = _DISCLOSURE_MARGIN) -> str:
    """Retain ONLY a bounded window around the canary's occurrence — the sentinel kept
    verbatim (the reverify contract needs it) plus ``margin`` chars of context each side. If
    the canary is absent (the oracle would not fire) retain NOTHING, so a non-disclosing
    transcript is never over-retained into a certificate. PR1: the class-1 certificate holds
    the sentinel + a bounded redacted span, never the raw transcript / PII."""
    c = _coerce_text(canary)
    o = _coerce_text(output)
    if not c:
        return ""
    idx = o.find(c)
    if idx < 0:
        return ""
    start = max(0, idx - margin)
    end = min(len(o), idx + len(c) + margin)
    span = o[start:end]
    if start > 0:
        span = "..." + span
    if end < len(o):
        span = span + "..."
    return span


# The ONLY structural behavior fields the prompt-injection oracle reads; anything else a
# caller puts in a behavior dict (e.g. a raw transcript) is dropped, never retained.
_PI_BEHAVIOR_KEYS = ("tool", "refused", "boundary_token_echoed")


def _pi_retained(obs: Any) -> dict[str, Any]:
    """Keep ONLY the three structurally-detectable fields the prompt-injection oracle compares
    — so a behavior dict that also carries raw prompt/response text is not laundered into the
    retained certificate. JSON-safe + deterministic."""
    src = dict(obs) if isinstance(obs, Mapping) else {}
    return {k: src[k] for k in _PI_BEHAVIOR_KEYS if k in src}


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

    # AEGIS system_prompt_disclosure_oracle (a planted high-entropy canary appeared VERBATIM
    # in the app's own LLM output). PR1: these carry PLAINTEXT — the reverify contract re-fires
    # on verbatim substrings, so the certificate honestly retains the random sentinel + a
    # bounded, boundary-redacted output span (never proprietary prompt text, never raw PII).
    canary: str | None = None
    llm_output: str | None = None

    # AEGIS prompt_injection_oracle (control-vs-treatment behavior delta — the ONLY path that
    # earns the adversarial `prompt_injection` class). Each is a small JSON-safe behavior obs.
    pi_control: dict[str, Any] | None = None
    pi_treatment: dict[str, Any] | None = None

    # AEGIS honeypot_hit_oracle (deterministic set-membership over seeded honeypot paths).
    requested_path: str | None = None
    honeypot_paths: list[str] | None = None
    crawler_allowlisted: bool | None = None

    # AEGIS credential_stuffing_oracle (SPRT over unseen-(account, source) auth SUCCESS outcomes,
    # Holm-controlled across identities). The retained events carry ONLY {account, source, success}
    # where account/source are keyed-HMAC pseudonyms — no raw username/IP enters the certificate.
    auth_events: list[dict[str, Any]] | None = None
    benign_sources: list[str] | None = None
    credstuff_alpha: float | None = None
    credstuff_beta: float | None = None
    credstuff_p1: float | None = None
    credstuff_p0: float | None = None
    credstuff_fwer: float | None = None

    # AEGIS request-side PARSE-PROOF oracles (the inline "provable firewall" gateway) — a single
    # DECODED request-parameter value, judged on the REQUEST ALONE. request_payload is the value;
    # payload_param names the insertion point (rides on the certificate). Proves a STRUCTURED
    # INJECTION ATTEMPT (SQL string-literal break-out / shell command construct), never exploitation.
    request_payload: str | None = None
    payload_param: str | None = None

    # version_range_oracle (a package version provably falls in an advisory's affected range)
    version_advisory: dict[str, Any] | None = None
    # policy_path_oracle (a real IAM grant path lets a principal reach a resource) — the retained raw
    # policy graph + the reachability query it is judged on
    policy: dict[str, Any] | None = None
    # k8s_posture_oracle (a kube-bench CIS control FAILED with a concrete observed insecure setting) —
    # the RETAINED control evidence (sensors.k8s_runtime) the parse-proof judges
    k8s_control: dict[str, Any] | None = None
    # cloud_posture_oracle (Wave-F1: a retained cloud/CSPM posture control whose ACHIEVED STATE literally
    # carries an insecure fact — encryption-at-rest disabled / public exposure / a wildcard principal) —
    # the RETAINED control evidence (sensors.cloud) the membership/parse-proof judges over its
    # achieved-state ALONE, offline. No benchmark/scan/engage finding carries cloud_control, so appending
    # this leaves the gate byte-identical.
    cloud_control: dict[str, Any] | None = None
    # mesh_posture_oracle (Wave-G3: a retained service-mesh posture control whose ACHIEVED STATE literally
    # carries an insecure fact — permissive/disabled mTLS, an allow-all AuthorizationPolicy, or an
    # unauthenticated Linkerd inbound policy) — the RETAINED mesh-config evidence the membership/parse-proof
    # judges over its achieved-state ALONE, offline, ZERO mesh/kubectl calls. No benchmark/scan/engage
    # finding carries mesh_control, so appending this leaves the gate byte-identical.
    mesh_control: dict[str, Any] | None = None
    # jwt_forgery_oracle (Workstream-B: a captured JWT is STRUCTURALLY FORGEABLE — judged on the token
    # ALONE, offline, zero traffic). jwt_token is the captured token string; jwt_candidate_keys are the
    # supplied secrets / RSA public keys the HMAC-reproduction proof is tried against (a weak-secret
    # baseline is always tried too). No benchmark/scan/engage finding carries jwt_token, so appending
    # this leaves the gate byte-identical.
    jwt_token: str | None = None
    jwt_candidate_keys: list[str] | None = None
    # saml_forgery_oracle (Workstream NW-1: a captured SAML Response is STRUCTURALLY FORGEABLE — judged
    # on the decoded XML ALONE, offline, zero traffic, on the XXE-safe parse). saml_xml is the decoded
    # SAML Response XML string. No benchmark/scan/engage finding carries saml_xml, so appending this
    # leaves the gate byte-identical.
    saml_xml: str | None = None

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
    def from_policy_graph(
        cls, policy: Mapping[str, Any], *, bug_class: str = "privilege_path"
    ) -> "FindingContext":
        """A retained IAM policy graph + reachability query (verify.policy_path), for the policy-path
        oracle — the retained evidence that turns a cloud sensor's "over-privileged / can reach R"
        LEAD into a FACT. Like ``from_handshake``, the ``policy`` graph MUST be re-derived from the raw
        operator export (``policy_path.build_policy_graph``), never laundered from the sensor's minted
        world-model beliefs: the oracle re-derives the grant path over the retained raw policy, so the
        certificate re-verifies offline. ``policy`` carries {principal, resource, access?, grants,
        assume, member_of}."""
        return cls(bug_class=bug_class, policy=dict(policy or {}))

    @classmethod
    def from_k8s_posture(
        cls, control: Mapping[str, Any], *, bug_class: str = "k8s_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED kube-bench CIS control (``sensors.k8s_runtime``), for the k8s-posture oracle — the
        retained evidence that turns a CIS-control-failure LEAD into a FACT. The oracle re-derives the
        weakness (a hard FAIL whose observed value literally carries a dangerous flag) over the retained
        control, so a kube-bench FAIL is confirmed a FACT only by the actual insecure setting, never the
        scanner's say-so. ``control`` carries {check_id, status, actual_value?, description?, section?}.

        Only the structural fields the oracle judges are retained — a caller-supplied control that also
        carries verbose scanner prose is reduced to the fields the parse-proof reads, so nothing else is
        laundered into the certificate. JSON-safe + deterministic (re-verifies offline)."""
        src = dict(control or {})
        retained = {k: _coerce_text(src.get(k)) for k in (
            "check_id", "status", "actual_value", "description", "section", "benchmark") if src.get(k)}
        return cls(bug_class=bug_class, k8s_control=retained)

    @classmethod
    def from_cloud_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "cloud_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED cloud/CSPM posture control (``sensors.cloud``), for the cloud-posture oracle (Wave-F1
        — the achieved-state SIBLING of ``from_k8s_posture``). The retained evidence that turns a
        cloud-posture LEAD into a FACT: the oracle re-derives the weakness (encryption-at-rest disabled on
        a sensitive datastore, an explicit public-exposure flag, or a wildcard/anonymous principal named
        in the retained policy) over the control's ACHIEVED STATE alone — offline, ZERO cloud calls — so a
        CSPM tool's "public / mis-configured" is confirmed a FACT only by the actual insecure state, never
        the scanner's say-so.

        Accepts either a nested ``achieved_state`` sub-dict or a flat ``sensors.cloud`` resource record
        (``{id, public?, sensitive?, encrypted?, grants?}``). Only the structural fields the oracle judges
        are retained into a canonical shape — a caller-supplied control that also carries verbose scanner
        prose or full grant objects is reduced to {resource_id, control_id, status, provider,
        achieved_state:{encrypted, public, sensitive, principals}}, so nothing else is laundered into the
        certificate. JSON-safe + deterministic (re-verifies offline)."""
        src = dict(control or {})
        inner = src.get("achieved_state") if isinstance(src.get("achieved_state"), Mapping) else src
        state: dict[str, Any] = {}
        for flag in ("encrypted", "public", "sensitive"):
            if inner.get(flag) is not None:
                state[flag] = inner.get(flag)          # bool/str kept as-is; the oracle tri-bools it
        principals: list[str] = []
        raw = inner.get("principals")
        if isinstance(raw, (list, tuple)):
            principals.extend(_coerce_text(p) for p in raw if p is not None)
        grants = inner.get("grants")
        if isinstance(grants, (list, tuple)):
            principals.extend(
                _coerce_text(g.get("principal")) for g in grants
                if isinstance(g, Mapping) and g.get("principal") is not None)
        if principals:
            state["principals"] = principals
        retained: dict[str, Any] = {"achieved_state": state}
        rid = src.get("resource_id") or src.get("id")
        cid = src.get("control_id") or src.get("check_id")
        if rid not in (None, ""):
            retained["resource_id"] = _coerce_text(rid)
        if cid not in (None, ""):
            retained["control_id"] = _coerce_text(cid)
        for k in ("status", "provider"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        return cls(bug_class=bug_class, cloud_control=retained)

    @classmethod
    def from_mesh_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "mesh_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED service-mesh posture control (``verify.mesh_posture.ingest_mesh_config``), for the
        mesh-posture oracle (Wave-G3 — the MESH twin of ``from_cloud_control``). The retained evidence that
        turns a mesh-config LEAD into a FACT: the oracle re-derives the weakness (permissive/disabled mTLS,
        an allow-all AuthorizationPolicy, or an unauthenticated Linkerd inbound policy) over the control's
        ACHIEVED STATE alone — offline, ZERO mesh/kubectl calls, NO attack — so a mesh linter's
        "permissive / allows everyone" is confirmed a FACT only by the actual insecure state, never the
        scanner's say-so.

        Only the structural fields the oracle judges are retained into a canonical shape (``resource_kind``,
        ``name``, ``namespace``, ``scope``, ``status``, and — per resource kind — ``mtls_mode`` /
        ``action`` + a canonicalized ``rules`` list / ``default_inbound_policy``). AuthorizationPolicy rules
        are reduced to the from-source principals plus a presence marker for ``to`` / ``when`` (so the
        empty-catch-all vs. scoped distinction is preserved but verbose scanner prose is never laundered
        into the certificate). JSON-safe + deterministic (re-verifies offline)."""
        src = dict(control or {})
        retained: dict[str, Any] = {}
        rk = src.get("resource_kind") or src.get("kind")
        if rk not in (None, ""):
            retained["resource_kind"] = _coerce_text(rk)
        for k in ("name", "namespace", "scope", "status", "mtls_mode", "action"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        inbound = src.get("default_inbound_policy") or src.get("inbound_policy")
        if inbound not in (None, ""):
            retained["default_inbound_policy"] = _coerce_text(inbound)
        rules = src.get("rules")
        if isinstance(rules, (list, tuple)):
            canon: list[dict[str, Any]] = []
            for rule in rules:
                if not isinstance(rule, Mapping):
                    continue
                out: dict[str, Any] = {}
                froms = rule.get("from")
                if isinstance(froms, (list, tuple)) and froms:
                    canon_from: list[dict[str, Any]] = []
                    for f in froms:
                        if isinstance(f, Mapping) and isinstance(f.get("source"), Mapping):
                            fsrc = f["source"]
                            s: dict[str, Any] = {}
                            for key in ("principals", "requestPrincipals", "request_principals"):
                                vals = fsrc.get(key)
                                if isinstance(vals, (list, tuple)):
                                    s[key] = [_coerce_text(v) for v in vals]
                            canon_from.append({"source": s} if s else {})
                        else:
                            canon_from.append({})
                    out["from"] = canon_from
                if rule.get("to"):
                    out["to"] = [{}]      # presence marker: a path/method restriction exists (not catch-all)
                if rule.get("when"):
                    out["when"] = [{}]    # presence marker: a condition exists (not catch-all)
                canon.append(out)
            retained["rules"] = canon
        return cls(bug_class=bug_class, mesh_control=retained)

    @classmethod
    def from_jwt_token(
        cls,
        token: str,
        *,
        candidate_keys: Sequence[str | bytes] = (),
        bug_class: str = "jwt_forgeable",
    ) -> "FindingContext":
        """A captured JWT plus the candidate secrets / RSA public keys to test it against, for the
        jwt-forgery oracle (Workstream-B). Confirms STRUCTURAL FORGEABILITY — judged on the token
        ALONE, offline, ZERO forged traffic — ONLY on a re-runnable proof: ``alg=none``/``None``, an HS*
        signature recomputable from a candidate/weak key, or an RS256->HS256 confusion (the HS* signature
        verifies with a supplied RSA public key as the HMAC secret). A normal RS256 token with an unknown
        key, or an HS* token whose secret is not recoverable, does NOT confirm (near-zero-FP).

        The token + candidate keys are JSON-safe, so a confirmed forgery re-verifies OFFLINE from its
        certificate (``verify.reverify``) — re-run the pure oracle over the retained token, get the same
        verdict. Candidate keys are coerced to text (a PEM public key is a string); an empty list is
        valid (the oracle still tries its weak-secret baseline and the ``alg=none`` proof)."""
        keys = [k.decode("utf-8", "replace") if isinstance(k, bytes) else _coerce_text(k)
                for k in (candidate_keys or ())]
        return cls(
            bug_class=bug_class,
            jwt_token=_coerce_text(token),
            jwt_candidate_keys=keys or None,
        )

    @classmethod
    def from_saml_structure(
        cls,
        xml: str,
        *,
        bug_class: str = "saml_structural_forgery",
    ) -> "FindingContext":
        """A captured SAML Response's decoded XML, for the saml-forgery oracle (Workstream NW-1 — the
        SAML SIBLING of ``from_jwt_token``). Confirms STRUCTURAL FORGEABILITY — judged on the XML ALONE,
        offline, ZERO forged traffic, on the XXE-safe parse — ONLY on a coarse, c14n-free STRUCTURAL
        invariant a validly signed assertion cannot exhibit: an unsigned consumed assertion, a
        ds:Reference/@URI that does not cover the consumed element, or the signature-wrapping shape (the
        dual of ``scanner.sso.wrap_assertion_xsw``). A properly signed single assertion, a doc with no
        consumed NameID, malformed/empty XML, and a DOCTYPE/ENTITY doc (XXE-refused) do NOT confirm
        (near-zero-FP).

        The XML is JSON-safe, so a confirmed forgery re-verifies OFFLINE from its certificate
        (``verify.reverify``) — re-run the pure oracle over the retained XML, get the same verdict. Full
        XML-DSig C14N/transform processing is deliberately NOT attempted (needs lxml/signxml, out of
        scope); this is the offline structural complement to the LIVE response-differential SAML checks."""
        return cls(bug_class=bug_class, saml_xml=_coerce_text(xml))

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

    # -- AEGIS builders (the defensive dual) -------------------------------

    @classmethod
    def from_llm_disclosure(
        cls, canary: str, llm_output: Any, *, bug_class: str = "system_prompt_disclosure"
    ) -> "FindingContext":
        """A planted canary sentinel plus the app's own LLM output, for the system-prompt-
        disclosure oracle. Confirms the SECRET LEAKED (the sentinel appeared verbatim) — not
        that an injection caused it. PR1: we retain ONLY a bounded window around the canary
        (sentinel kept verbatim so the certificate re-fires offline), NOT the whole model
        output — so a transcript that also contains PII/credentials is not over-retained."""
        return cls(
            bug_class=bug_class,
            canary=_coerce_text(canary),
            llm_output=_bounded_disclosure_span(canary, llm_output),
        )

    @classmethod
    def from_prompt_injection(
        cls,
        control: Mapping[str, Any],
        treatment: Mapping[str, Any],
        *,
        bug_class: str = "prompt_injection",
    ) -> "FindingContext":
        """A clean control-turn behavior obs vs the attacker treatment-turn behavior obs, for
        the prompt-injection oracle. Each is a JSON-safe mapping over the structurally-
        detectable fields {tool, refused, boundary_token_echoed}. Confirms injection ONLY on a
        provable behavior delta (never on markers alone).

        Retains ONLY those three structural fields — a caller-supplied behavior dict that also
        carries a raw prompt/response transcript is NOT retained into the certificate (privacy:
        the oracle reads only these keys, so nothing else is evidence)."""
        return cls(
            bug_class=bug_class,
            pi_control=_pi_retained(control),
            pi_treatment=_pi_retained(treatment),
        )

    @classmethod
    def from_honeypot(
        cls,
        requested_path: str,
        honeypot_paths: Sequence[str],
        *,
        crawler_allowlisted: bool = False,
        bug_class: str = "automated_access",
    ) -> "FindingContext":
        """A requested path plus the seeded honeypot path set (and whether the requester is an
        allowlisted known-good crawler), for the honeypot oracle. Confirms AUTOMATED ACCESS
        (P1), never "scraping": a fetch of a resource no human UI links."""
        return cls(
            bug_class=bug_class,
            requested_path=_coerce_text(requested_path),
            honeypot_paths=[_coerce_text(p) for p in (honeypot_paths or [])],
            crawler_allowlisted=bool(crawler_allowlisted),
        )

    @classmethod
    def from_request_payload(
        cls,
        payload: str,
        *,
        bug_class: str,
        param: str = "",
    ) -> "FindingContext":
        """A single DECODED request-parameter value (and its ``param`` NAME), for the AEGIS request-side
        parse-proof oracles (``sqli_attempt`` -> SQL string-literal break-out; ``command_injection_attempt``
        -> shell command-execution construct; ``nosql_injection_attempt`` -> a MongoDB query operator
        injected as a KEY — from the param name ``user[$ne]`` or a JSON value ``{"$ne":null}``). Judged on
        the REQUEST ALONE — proves a STRUCTURED INJECTION ATTEMPT, never exploitation. The value must
        already be percent-/entity-decoded by the caller (the gateway decodes at the insertion point)."""
        return cls(
            bug_class=bug_class,
            request_payload=_coerce_text(payload),
            payload_param=_coerce_text(param),
        )

    @classmethod
    def from_auth_activity(
        cls,
        auth_events: Sequence[Mapping[str, Any]],
        *,
        benign_sources: Sequence[str] | None = None,
        bug_class: str = "credential_stuffing",
    ) -> "FindingContext":
        """An ORDERED auth-outcome window (each ``{account, source, success}``, identifiers already
        keyed-HMAC pseudonymised at the ingest boundary) for the credential-stuffing oracle.
        Confirms ATO only when a source's UNSEEN-(account, source) SUCCESSES cross the SPRT AND
        survive the Holm family-wise control across identities; a failed-only burst confirms
        nothing (it yields no SPRT round).

        Only the three structural fields are retained — a caller-supplied event that also carries a
        raw username / IP / user-agent is NOT laundered into the certificate (the oracle reads only
        these keys, so nothing else is evidence). ``benign_sources`` is the operator's known-good
        egress allowlist (a documented NAT/CGNAT) whose successes REFUTE."""
        retained = [
            {"account": _coerce_text(e.get("account")),
             "source": _coerce_text(e.get("source")),
             "success": bool(e.get("success", False))}
            for e in (auth_events or []) if isinstance(e, Mapping)
        ]
        return cls(
            bug_class=bug_class,
            auth_events=retained,
            benign_sources=(
                [_coerce_text(s) for s in benign_sources] if benign_sources is not None else None
            ),
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
        if self.policy is not None:
            ctx["policy"] = self.policy
        if self.k8s_control is not None:
            ctx["k8s_control"] = self.k8s_control
        if self.cloud_control is not None:
            ctx["cloud_control"] = self.cloud_control
        if self.mesh_control is not None:
            ctx["mesh_control"] = self.mesh_control
        if self.jwt_token is not None:
            ctx["jwt_token"] = self.jwt_token
            if self.jwt_candidate_keys is not None:
                ctx["jwt_candidate_keys"] = self.jwt_candidate_keys
        if self.saml_xml is not None:
            ctx["saml_xml"] = self.saml_xml
        # AEGIS (defensive dual) — only wired when both halves of a paired oracle are present.
        if self.canary is not None and self.llm_output is not None:
            ctx["canary"] = self.canary
            ctx["llm_output"] = self.llm_output
        if self.pi_control is not None and self.pi_treatment is not None:
            ctx["pi_control"] = self.pi_control
            ctx["pi_treatment"] = self.pi_treatment
        if self.requested_path is not None and self.honeypot_paths is not None:
            ctx["requested_path"] = self.requested_path
            ctx["honeypot_paths"] = self.honeypot_paths
            if self.crawler_allowlisted is not None:
                ctx["crawler_allowlisted"] = self.crawler_allowlisted
        if self.request_payload is not None:
            ctx["request_payload"] = self.request_payload
            if self.payload_param is not None:
                ctx["payload_param"] = self.payload_param
        if self.auth_events is not None:
            ctx["auth_events"] = self.auth_events
            if self.benign_sources is not None:
                ctx["benign_sources"] = self.benign_sources
            for k in ("alpha", "beta", "p1", "p0", "fwer"):
                v = getattr(self, f"credstuff_{k}")
                if v is not None:
                    ctx[f"credstuff_{k}"] = v
        return ctx
