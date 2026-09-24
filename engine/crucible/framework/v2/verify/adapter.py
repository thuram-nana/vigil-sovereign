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
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

# The IMDS capture builder (from_imds_capture) caps every retained string so a hostile/oversized capture
# cannot bloat the certificate (audit B5).
_IMDS_CAPTURE_STR_CAP = 2048


def _imds_json_scalar(v: Any) -> Any:
    """Keep JSON-native scalars; coerce anything else (a ``datetime``, an arbitrary object) to a capped
    string so the retained IMDS context is ALWAYS JSON-serializable (audit B5)."""
    if v is None or isinstance(v, bool) or isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        return v[:_IMDS_CAPTURE_STR_CAP]
    return _coerce_text(v)[:_IMDS_CAPTURE_STR_CAP]


_IMDS_ADAPTER_ERROR_KEYS = frozenset({
    "error", "errors", "errormessage", "error_message", "errorcode", "error_code",
    "message", "code", "__type", "fault", "error_description",
})


def _imds_body_has_error(obj: Any, depth: int = 0) -> bool:
    """Mirror of the oracle's recursive failure-marker scan: True iff an ``_IMDS_ADAPTER_ERROR_KEYS`` key
    with a truthy value appears at ANY bounded depth (round-2). The adapter flattens the confirming body, so
    without this a NESTED error would be dropped and the scrubbed context would re-verify as FIRING even
    though the raw capture is a failed call — breaking the mint↔re-execution mirror."""
    if depth > 4 or not isinstance(obj, Mapping):
        return False
    for k, val in obj.items():
        if not val:
            continue
        if _coerce_text(k).strip().lower() in _IMDS_ADAPTER_ERROR_KEYS:
            return True
        if isinstance(val, Mapping) and _imds_body_has_error(val, depth + 1):
            return True
        if isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, Mapping) and _imds_body_has_error(item, depth + 1):
                    return True
    return False


def _imds_scrub_source(value: Any) -> str:
    """Retain ``scheme://host[:port]/path`` ONLY for an http(s) URL — DROP userinfo, query, and fragment so
    a secret carried in the URL query (``?token=…``) or userinfo (``user:pass@``) is never laundered into
    the certificate (audit B5). A non-URL source (``env:…``, a file path) is kept verbatim. IPv6 hosts are
    re-bracketed. Everything is length-capped."""
    raw = _coerce_text(value)
    try:
        p = urlsplit(raw)
        if p.scheme in ("http", "https") and p.hostname:
            host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
            netloc = f"{host}:{p.port}" if p.port else host
            return urlunsplit((p.scheme, netloc, p.path, "", ""))[:_IMDS_CAPTURE_STR_CAP]
    except ValueError:
        pass
    return raw[:_IMDS_CAPTURE_STR_CAP]


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
        "token": getattr(hit, "token", ""),   # VF-2a: preserve the token so the oracle can verify it
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

    # ssi_evaluation_oracle (Wave-4.1 Server-Side Includes, CWE-97 — the server EVALUATED an injected SSI
    # directive). REUSES the frozen EVALUATION kind but routes through a DISTINCT ctx key (`ssi_expected`/
    # `ssi_observed`) so no benchmark/scan/engage finding carries it and the gate stays byte-identical; the
    # verifier's EVALUATION arm dispatches these keys to oracles.ssi_evaluation_oracle (computed-product proof).
    ssi_raw: str | None = None
    ssi_expected: str | None = None
    ssi_observed: str | None = None
    ssi_control: str | None = None

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
    oob_token: str | None = None   # VF-2a: the REGISTERED per-finding secret the callback must carry to fire
    # TTL / replay window (additive; both None ⇒ no check ⇒ byte-identical). Retained at mint time so offline
    # re-verify applies the SAME deterministic check over the receipt's target-observed received_at.
    oob_issued_at: float | None = None
    oob_expires_at: float | None = None
    oob_skew: float | None = None

    # service_reachability_oracle (a real transport handshake reproduced a scanner's "open port")
    handshake: dict[str, Any] | None = None

    # anonymous_reachable_oracle (Slice-C3: a bounded, UNAUTHENTICATED HTTP GET reached a resource a
    # cloud posture already re-derived as PUBLIC — an unauthenticated 2xx with a present body). No
    # benchmark/scan/engage finding carries this, so appending it leaves the gate byte-identical; routes
    # to the ACTIVE_EXPOSURE kind via its distinct `anon_get` ctx key.
    anon_get: dict[str, Any] | None = None

    # tls_weakness_oracle (a real TLS handshake negotiated a deprecated protocol / weak cipher)
    tls: dict[str, Any] | None = None

    # weak_crypto_artifact_oracle (a parsed crypto artifact — e.g. an X.509 cert — is signed with a
    # BROKEN hash: MD5/SHA1). No benchmark/scan/engage finding carries this, so it leaves the gate
    # byte-identical; routes to the TLS_WEAKNESS kind (a weak-crypto FACT) via a distinct ctx key.
    crypto_artifact: dict[str, Any] | None = None

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
    # k8s_workload_posture_oracle (a LIVE cluster RBAC binding — sensors.k8s_live — that provably grants a
    # dangerous built-in ClusterRole to an anonymous subject) — the RETAINED binding evidence (raw subjects +
    # role) the membership/parse-proof judges over its achieved-state ALONE, offline, ZERO cluster calls. The
    # RBAC/achieved-state sibling of k8s_control; no benchmark/scan/engage finding carries k8s_workload_control,
    # so appending this leaves the gate byte-identical.
    k8s_workload_control: dict[str, Any] | None = None
    # k8s_rbac_verb_grant_oracle (E4 TIER-2: a retained RBAC binding + its SEPARATELY-retained role_object
    # whose PARSED rules provably grant a dangerous verb on a resource to an attacker-occupiable subject —
    # an anonymous subject, the namespace-default ServiceAccount, or system:authenticated). The STRONGER
    # rule-parsing sibling of k8s_workload_control (which only name-matches a built-in role). The RETAINED
    # binding + role_object (subjects + roleRef; role rules + rules_source) the membership/parse-proof judges
    # ALONE, offline, ZERO cluster calls. No benchmark/scan/engage finding carries k8s_rbac_grant_control, so
    # appending this leaves the gate byte-identical.
    k8s_rbac_grant_control: dict[str, Any] | None = None
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
    # cicd_posture_oracle (Phase-2: a parsed GitHub-Actions control provably carries a dangerous construct
    # — an unpinned third-party action / pwn-request / script-injection sink — judged over the RETAINED
    # workflow control ALONE, offline, ZERO repo clone / pipeline run). No benchmark/scan/engage finding
    # carries cicd_control, so appending this leaves the gate byte-identical.
    cicd_control: dict[str, Any] | None = None
    # A RETAINED MobSF mobile-posture control for the mobile-posture oracle. No benchmark finding carries
    # mobile_control, so appending this leaves the gate byte-identical.
    mobile_control: dict[str, Any] | None = None
    # A RETAINED DNS email-auth policy record (FORGE Domain 10) for the email-auth-posture oracle. No
    # benchmark finding carries email_auth_control, so appending this leaves the gate byte-identical.
    email_auth_control: dict[str, Any] | None = None
    # A RETAINED IdP-export control (FORGE Domain 7) for the identity-posture oracle. No benchmark finding
    # carries identity_control, so appending this leaves the gate byte-identical.
    identity_control: dict[str, Any] | None = None
    # W16-STD-5 client-side POSTURE-WEAKNESS controls (constitution §V client-side classes). Each routes to
    # its posture oracle (clickjacking = missing framing headers; csrf = token-not-enforced control-
    # differential; postmessage = wildcard target-origin static check). No benchmark/scan/engage finding
    # carries any of these keys, so appending them leaves the gate byte-identical.
    clickjacking_control: dict[str, Any] | None = None
    csrf_control: dict[str, Any] | None = None
    postmessage_control: dict[str, Any] | None = None
    # prototype_pollution_oracle (Wave-2.2 client-side ACHIEVED-STATE FACT — CWE-1321). The binding-reported
    # readback a driver captured after rendering the target page: {polluted_key, polluted_val, expected_val,
    # benign_key, benign_key_undefined}. The oracle fires ONLY when Object.prototype[uniqKey] === uniqVal AND
    # the benign-key control stayed undefined — the achieved polluted state, never "the payload appeared". No
    # benchmark/scan/engage finding carries proto_pollution, so appending it leaves the gate byte-identical;
    # routes to the PROTOTYPE_POLLUTION kind via its distinct `proto_pollution` ctx key.
    proto_pollution: dict[str, Any] | None = None
    # csp_posture_oracle (Wave-2.4 CSP permissive-policy POSTURE-FACT — CWE-693/CWE-1021). The RETAINED
    # enforced CSP response header + report-only flag: {header, report_only, url, rule}. The oracle re-parses
    # the effective script-src (script-src else default-src) offline — no browser — and fires ONLY on a real
    # permissive weakness ('unsafe-inline' with no neutralizing nonce/hash, a wildcard '*', an http:/data:
    # scheme source, or 'unsafe-eval'). No benchmark/scan/engage finding carries csp_control, so appending it
    # leaves the gate byte-identical; routes to the CSP_POSTURE kind via its distinct `csp_control` ctx key.
    csp_control: dict[str, Any] | None = None
    # the achieved CSP-bypass guard (Wave-2.4). Alongside the DOM_EXECUTION fields (dom_binding_calls/
    # dom_canary) the `csp_bypass` class also retains {header, report_only} of the ENFORCED CSP the execution
    # DEFIED, so the DOM_EXECUTION dispatch arm can re-derive OFFLINE that the policy purported to block the
    # execution (a genuine bypass) — a no-CSP / permissive-CSP / report-only execution is plain DOM-XSS, not a
    # bypass. No benchmark/scan/default finding carries csp_block_control, so appending it is inert on the gate.
    csp_block_control: dict[str, Any] | None = None
    # csrf_achieved_oracle (Wave-3.3 gated-workflow ACHIEVED-STATE FACT — CWE-352). The retained
    # browser-OBSERVED evidence a gated headless-browser cross-site re-drive captured: {rule, method,
    # endpoint, target_origin, initiator_origin, ambient_cookie_name, associated_cookies, observed_cookie_
    # header, observed_request_fields, observed_request_header_names, marker, with_cookie_state,
    # no_cookie_state}. The oracle (kind ACHIEVED_STATE, reached via the fresh `csrf_achieved` ctx key)
    # DERIVES cross_origin (from the observed origins) and ambient_only (from the observed request) — it
    # never trusts a bare bool — and fires ONLY when a SameSite-honoring browser ACTUALLY attached the
    # ambient cookie cross-site (observed associated_cookies, no SameSite block) AND the VIGIL-chosen unique
    # marker reached the authoritative post-state but is ABSENT from the no-cookie control. No
    # benchmark/scan/engage finding carries `csrf_achieved`, so appending it leaves the gate byte-identical.
    csrf_achieved: dict[str, Any] | None = None
    # session_fixation_oracle (Wave-3.2 ACHIEVED-STATE FACT — CWE-384, its OWN OracleKind.SESSION_FIXATION).
    # The retained record scanner.session.SessionFixationCheck captured through the gated send carries the RAW
    # bytes the oracle re-runs its PRIVATE-READ DIFFERENTIAL over — {sentinel_id, post_auth_id, cookie_name,
    # private_discriminator (D, the victim-PRIVATE datum), success_marker (LEGACY, not a minting path),
    # logged_out_markers, logged_out_statuses, authorized_view (status/body of S0's fixed-session read),
    # owner_view (the owner's authoritative POSITIVE reference), unauth_ref (a SAME-SHAPE substantive-2xx read
    # by an OTHER unauthorized identity — the DECISIVE negative reference), logged_out_ref (a same-URL
    # NO-COOKIE gating baseline)} — never a pre-computed authenticated bool. The oracle fires ONLY when the
    # VIGIL-fixed pre-auth sentinel id SURVIVED login unrotated (post_auth_id == sentinel_id) AND D is PRESENT
    # in S0's read AND in the owner's authoritative read yet PROVABLY ABSENT from the SUBSTANTIVE SAME-SHAPE
    # other-identity reference and a valid no-session baseline (the private-read reduction that proves S0
    # reached the victim's gated content — a bare success-marker / credential-presence differential proves
    # nothing and cannot mint). No/invalid/reflected D, a missing positive or same-shape negative reference, D
    # present in a negative reference, a rotated id, or a server-set-only id (no sentinel shape) do not fire.
    # No benchmark/scan/engage finding carries session_fixation, so appending it leaves the gate byte-identical;
    # routes to the dedicated ACHIEVED_STATE-sibling kind via its distinct `session_fixation` ctx key so
    # oracle_version(ACHIEVED_STATE) is untouched.
    session_fixation: dict[str, Any] | None = None
    # workflow_abuse_oracle (Wave-4.4 gated-workflow ACHIEVED-STATE FACT — race limit-overrun CWE-362 /
    # business-logic price-manipulation CWE-840, reusing the FROZEN ACHIEVED_STATE kind). The retained
    # record the RUNNER (scanner.race / scanner.bizlogic, or live.race_bizlogic_redrive) captured, carrying
    # the RAW bytes the oracle re-runs its verdict over — {mode ("race"|"tamper"), owner_signed_spec (the
    # runner-attested owner-signature-verified fact — the FATAL-2-safe gated-workflow attestation the
    # certificate binds), and for race: max_allowed + responses (raw {status, body} burst outcomes) +
    # success_predicate (the operator's SEMANTIC per-response commit predicate the oracle RE-EVALUATES to
    # re-derive the count — never a trusted integer); for tamper: observed_state + danger (the operator's
    # danger predicate over the post-state)}. Race is COUNT-based, NEVER timing; a bare any-2xx count is a
    # LEAD; no owner-signed spec is INCONCLUSIVE. No benchmark/scan/engage finding carries workflow_abuse,
    # so appending it leaves the gate byte-identical; routes to ACHIEVED_STATE via its distinct ctx key.
    workflow_abuse: dict[str, Any] | None = None
    # mfa_bypass_oracle (Wave-4.5 ACHIEVED-STATE FACT — CWE-287/CWE-308, its OWN OracleKind.MFA_BYPASS). The
    # retained record scanner.mfa.MfaBypassCheck captured through the gated send carries the RAW bytes the
    # oracle re-runs its FAIL-CLOSED + PRIVATE-READ adjudication over — {operator_attestation (the three-part
    # HARD certification gate: mfa_enrolled_account + factor1_only_presented + post_mfa_resource_certified),
    # private_discriminator (D, the victim-PRIVATE post-MFA-gated datum), factor1_view (status/body of the
    # factor-1-only session's read of the post-MFA resource), owner_view (the fully post-MFA owner's
    # authoritative POSITIVE reference), pre_mfa_ref (a SAME-SHAPE substantive-2xx read by an OTHER not-post-MFA
    # identity — the DECISIVE negative reference), logged_out_ref (a same-URL no-session gating baseline),
    # logged_out_markers, logged_out_statuses} — never a pre-computed authenticated bool. The oracle fires ONLY
    # under the complete attestation (LOCK 1) AND when D is PRESENT in the factor-1-only read AND in the
    # post-MFA owner's read yet PROVABLY ABSENT from the SUBSTANTIVE SAME-SHAPE other-identity reference and a
    # valid no-session baseline (LOCK 2 — the private-read reduction). WITHOUT the attestation NO fire for ANY
    # input (a LEAD); a benign app that enforces factor-2 (D absent from the factor-1-only read) is a
    # channel-confirmed CLEAN. No benchmark/scan/engage finding carries mfa_bypass, so appending it leaves the
    # gate byte-identical; routes to the dedicated kind via its distinct `mfa_bypass` ctx key so
    # oracle_version(ACHIEVED_STATE) is untouched.
    mfa_bypass: dict[str, Any] | None = None
    # smuggling_desync_oracle (Wave-4.2 HTTP request smuggling — CWE-444, retires the A12 timing LEAD). The
    # retained record the gated raw-socket re-drive (live/smuggling_redrive.py) captured: {canary (a unique
    # high-entropy per-probe token VIGIL embedded in the smuggled prefix), technique (CL.TE/TE.CL/obfuscated
    # TE), conflict ({channel,status,reason,body} of VIGIL's OWN second request on the CONFLICT connection),
    # control ({...} of the SAME second request on an identical NO-CONFLICT connection)}. The oracle (kind
    # DIFFERENTIAL_RESPONSE, reached via the fresh `smuggling_desync` ctx key) fires ONLY when the unique
    # canary is ECHOED in the conflict leg's second response AND ABSENT from the no-conflict control's second
    # response (the back-end treated the smuggled prefix as the start of VIGIL's OWN next request — an
    # achieved desync), never on timing and never on a bare mangled-method status. NO victim is poisoned: both
    # requests are VIGIL's own on its own socket. No benchmark/scan/engage finding carries `smuggling_desync`,
    # so appending it leaves the gate byte-identical and reuses the frozen kind (oracle_version untouched).
    smuggling_desync: dict[str, Any] | None = None
    # password_reset_invariant_oracle (Wave-4.3 — CWE-640/613/330, its OWN OracleKind.PASSWORD_RESET_INVARIANT).
    # The retained record scanner.reset captured through the gated send carries the RAW bytes the oracle re-runs
    # over. Discriminated by `mode`:
    #   * mode="token_reuse" — {reset_token, private_discriminator (D), authorized_view (the read after
    #     AUTHENTICATING with the replay-set secret), owner_view (the owner's authoritative POSITIVE reference),
    #     unauth_ref (a SUBSTANTIVE SAME-SHAPE unauthorized read — the DECISIVE negative reference), logged_out_ref
    #     (a no-session baseline), logged_out_markers, logged_out_statuses}. The oracle fires ONLY when the
    #     PRIVATE-READ REDUCTION proves the replay-set secret reached D (present in the owner's read, absent from
    #     the same-shape unauthorized read and the no-session baseline) — never a bare 200; a single-use token that
    #     correctly expires does not fire.
    #   * mode="token_collision" — {samples/tokens: [...]} captured from INDEPENDENT reset requests (in order).
    #     Fires ONLY on a genuinely-EXPLOITABLE PREDICTABLE COUNTER (>=3 tokens forming an EXACT arithmetic
    #     progression — observe one, predict the next). A BYTE-IDENTICAL token — same account LABEL or across
    #     DIFFERENT account LABELS — is DELIBERATELY NOT a FACT: labels are never proven distinct PRINCIPALS (a
    #     benign identifier-NORMALIZING generator maps 'alice'/'Alice' to ONE principal) ⇒ LEAD; genuine
    #     cross-principal exploitation is minted only by password_reset_cross_user (the private-read differential).
    #     Distinct tokens do not fire; ENTROPY is never scored (a low-entropy-but-distinct token stays a LEAD).
    # No benchmark/scan/engage finding carries `password_reset_invariant`, so appending it leaves the gate
    # byte-identical; routes to the dedicated kind via its distinct `password_reset_invariant` ctx key so
    # oracle_version(ACHIEVED_STATE) is untouched. (The CROSS-USER reset sub-property reuses the ACHIEVED_STATE
    # predicate/observed_evidence path via an IdorCheck; the HOST-POISONING sub-property reuses host_header_injection.)
    password_reset_invariant: dict[str, Any] | None = None
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
    # saml_candidate_certs (the OPT-IN cryptographic escalation, mirroring jwt_candidate_keys): the
    # OPERATOR-PROVIDED TRUSTED IdP signing cert(s) (PEM), the trust anchor the XML-DSig signature is
    # cryptographically verified against when `signxml` is importable. The signature's OWN embedded
    # ds:X509Certificate is NEVER a trust anchor (an attacker controls it — that self-signed FP is
    # exactly what got the JWT x5c/embedded-key oracle rejected). When empty (or signxml absent) the
    # crypto branch is DORMANT and the oracle degrades to structural-only, byte-identical. No
    # benchmark/scan/engage finding carries saml_candidate_certs.
    saml_candidate_certs: list[str] | None = None
    # imds_credential_capture_oracle (BUILD-PLAN §E1: a RETAINED capture proving role/SA credentials were
    # retrieved from the instance metadata endpoint AND authenticated — the achieved-effect FACT of an
    # SSRF/foothold -> IMDS chain, judged over the JSON-safe capture ALONE, offline, ZERO network, NO
    # exploitation). The credential's SECRET material (SecretAccessKey / Token / access_token) is redacted
    # to a presence marker by ``from_imds_capture`` — the oracle never validates a secret's content, only
    # its presence, so the certificate carries NO live secret yet re-verifies offline. No benchmark/scan/
    # engage finding carries imds_capture, so appending this leaves the gate byte-identical.
    imds_capture: dict[str, Any] | None = None
    # E5 exposed-secret validity (BUILD-PLAN §E5): a RETAINED, secret-safe capture proving an EXPOSED secret
    # is VALID — a structurally-recognized leaked credential that AUTHENTICATED via a confirming call bound
    # to it over a trusted, per-TYPE-allow-listed transport. The secret VALUE is redacted to a presence
    # marker by ``from_secret_capture`` (the oracle judges validity via the confirming call, never the
    # secret's content), so the certificate carries NO live secret yet re-verifies offline. No benchmark/
    # scan/engage finding carries secret_capture, so appending this leaves the gate byte-identical.
    secret_capture: dict[str, Any] | None = None
    # E2 IAM privilege-escalation PRIMITIVE (BUILD-PLAN §E2): a RETAINED IAM-policy capture — the base
    # principal, the target resource, the base policy GRAPH, and the escalation statements — the
    # iam_escalation_oracle re-derives an UNCONDITIONAL escalation primitive that STRICTLY increases what the
    # base principal reaches (a differential of the base vs escalation-closed closures). Carries NO secret —
    # only IAM ids/actions/resources (identifiers), so a confirmed FACT re-verifies offline. No benchmark/
    # scan/engage finding carries iam_escalation_capture, so appending this leaves the gate byte-identical.
    iam_escalation_capture: dict[str, Any] | None = None

    # E3 (BUILD-PLAN §E3) GCP service-account IMPERSONATION — a RETAINED, secret-safe capture proving a
    # principal minted a short-lived token AS a named target SA B, confirmed by a tokeninfo/userinfo identity
    # echo of B at a TRUSTED, allow-listed Google endpoint bound to the mint by a shared token fingerprint. The
    # minted TOKEN is redacted to a presence marker by ``from_gcp_impersonation_capture`` (the oracle proves
    # impersonation via the confirming echo + binding, never the token's content). Like E1/E5 it is reachable
    # ONLY via its bug_class row keyed on this ctx field, which no benchmark/scan/engage finding carries, so
    # appending this leaves the gate byte-identical.
    gcp_impersonation_capture: dict[str, Any] | None = None

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
        cls, hits: Any, *, bug_class: str = "ssrf", expected_token: "str | None" = None,
        issued_at: "float | None" = None, expires_at: "float | None" = None,
        skew: "float | None" = None,
    ) -> "FindingContext":
        """A list of out-of-band interactions (whatever `OOBReceiver.poll` / `DNSCollector.poll`
        returned) for the oob-callback oracle. An empty list is a valid,
        non-firing negative control. VF-2a: pass ``expected_token`` — the REGISTERED per-finding secret
        (`oob.register_token`) — so the oracle (live AND on offline re-verify) fires only for a hit that
        carried it. Omitting it yields a context the oracle refuses to confirm (fail-closed).

        TTL / replay (additive): pass ``issued_at`` / ``expires_at`` — the mint window retained here — to
        additionally require a token-matched hit's target-observed ``received_at`` to fall within
        ``[issued_at - skew, expires_at + skew]``. Omitting both keeps the exact prior (windowless) behaviour."""
        return cls(
            bug_class=bug_class,
            oob_hits=[_hit_to_dict(h) for h in (hits or [])],
            oob_token=expected_token,
            oob_issued_at=issued_at,
            oob_expires_at=expires_at,
            oob_skew=skew,
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
    def from_race_burst(
        cls,
        responses: "Sequence[Mapping[str, Any]]",
        *,
        max_allowed: int,
        owner_signed_spec: bool,
        success_predicate: Mapping[str, Any] | None = None,
        bug_class: str = "request_race",
    ) -> "FindingContext":
        """A single-packet burst's RAW ``{status, body}`` responses plus the operator's SEMANTIC success
        predicate and ``max_allowed``, for the gated ``workflow_abuse_oracle`` (COUNT-based, never timing).
        ``owner_signed_spec`` is the runner-attested fact that the owner's Ed25519 signature over the
        WorkflowSpec AST was verified before the burst; without it the oracle is INCONCLUSIVE. Without a
        ``success_predicate`` the over-count is a LEAD (an any-2xx count is not proof of over-consumption).
        The oracle RE-EVALUATES ``success_predicate`` over each retained response, so the count re-derives
        offline from the raw bytes — never a trusted integer."""
        return cls(
            bug_class=bug_class,
            workflow_abuse={
                "mode": "race",
                "owner_signed_spec": bool(owner_signed_spec),
                "max_allowed": int(max_allowed),
                # Bodies are coerced to text so the RETAINED context is JSON-safe (the certificate must
                # serialize) and re-verifies offline byte-for-byte; the semantic predicate reads text.
                "responses": [
                    {"status": (r.get("status") if isinstance(r, Mapping) else None),
                     "body": _coerce_text(r.get("body") if isinstance(r, Mapping) else r)}
                    for r in (responses or [])
                ],
                **({"success_predicate": dict(success_predicate)} if success_predicate else {}),
            },
        )

    @classmethod
    def from_workflow_tamper(
        cls,
        observed_state: Mapping[str, Any],
        danger: Mapping[str, Any],
        *,
        owner_signed_spec: bool,
        bug_class: str = "business_logic",
    ) -> "FindingContext":
        """The observed post-state a tampering probe landed in plus the operator's ``danger`` predicate,
        for the gated ``workflow_abuse_oracle``. ``owner_signed_spec`` is the runner-attested owner-
        signature-verified fact (INCONCLUSIVE without it). The oracle fires iff ``danger`` holds over the
        post-state — a validating / correctly-priced flow (the benign twin) fails it (channel-confirmed
        clean). Both are JSON so the certificate re-verifies offline."""
        return cls(
            bug_class=bug_class,
            workflow_abuse={
                "mode": "tamper",
                "owner_signed_spec": bool(owner_signed_spec),
                "observed_state": {str(k): v for k, v in dict(observed_state or {}).items()},
                "danger": dict(danger),
            },
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
    def from_anonymous_capture(
        cls, capture: Mapping[str, Any], *, bug_class: str = "anonymous_reachable"
    ) -> "FindingContext":
        """A captured UNAUTHENTICATED HTTP GET (verify.reachability_cloud), for the active-exposure
        oracle — the retained response that turns a cloud POSTURE fact ("this bucket is public") into a
        PROVEN anonymously-reachable FACT.

        Like ``from_handshake``, the ``capture`` MUST come from a real gated, credential-free GET
        (``reachability_cloud.capture_anonymous_get``: kill-switch -> single-host -> ACTIVE_RECON ->
        charter scope), NEVER a posture tool's "public=true" row: the oracle re-verifies *reachability*
        by an INDEPENDENT anonymous request, so laundering a "public" configuration straight into this
        context would defeat prove-don't-guess. Both this and the retained capture are JSON-safe, so the
        certificate re-verifies offline with no network."""
        return cls(bug_class=bug_class, anon_get=dict(capture or {}))

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
    def from_crypto_artifact(
        cls, artifact: Mapping[str, Any], *, bug_class: str = "weak_crypto_artifact"
    ) -> "FindingContext":
        """A parsed crypto-artifact descriptor (e.g. ``{"signature_algorithm": "sha1WithRSAEncryption",
        "oid": "1.2.840.113549.1.1.5", "subject": ...}``) for the weak-crypto-artifact oracle. The
        retained OID name is what the oracle classifies — a pure, re-verifiable string check (a broken
        signature hash MD5/SHA1 is unconditionally weak), like the TLS oracle re-verifies a cipher name."""
        return cls(bug_class=bug_class, crypto_artifact=dict(artifact or {}))

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
    def from_k8s_workload_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "k8s_workload_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED live-cluster RBAC-binding control (``sensors.k8s_live``), for the k8s-workload-posture
        oracle — the RBAC achieved-state SIBLING of ``from_k8s_posture`` / ``from_cloud_control``. The
        retained evidence that turns a live RBAC-binding LEAD into a FACT: the oracle re-derives the weakness
        (an ANONYMOUS subject — system:anonymous / system:unauthenticated — bound to a dangerous built-in
        ClusterRole: cluster-admin / admin / edit) over the binding's RETAINED raw ``subjects`` + ``role``
        ALONE — offline, ZERO cluster calls — so a live RBAC read is confirmed a FACT only by the actual
        anonymous-privileged binding, never the collector's say-so.

        Only the structural fields the oracle judges are retained into a canonical shape — a caller-supplied
        control that also carries verbose evidence is reduced to {check_id, resource_kind, name,
        achieved_state:{subjects, role, role_kind, role_apigroup}}, so nothing else is laundered into the
        certificate. JSON-safe + deterministic (re-verifies offline)."""
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        inner = src.get("achieved_state") if isinstance(src.get("achieved_state"), Mapping) else src
        state: dict[str, Any] = {}
        raw_subjects = inner.get("subjects")
        if isinstance(raw_subjects, (list, tuple)):
            canon_subjects: list[Any] = []
            for s in raw_subjects:
                if s is None:
                    continue
                if isinstance(s, Mapping):
                    # RETAIN the TYPED subject {kind, name, api_group} — the oracle decides anon-ness from the
                    # k8s TYPE, not a flattened string (reviewer BLOCK #3). Coercing a typed subject to text
                    # here would launder the triple into a stringified dict the oracle can never match (a silent
                    # false negative — the same canonicalizer-drops-semantics class as the mesh `from` bug).
                    canon_subjects.append({
                        "kind": _coerce_text(s.get("kind")),
                        "name": _coerce_text(s.get("name")),
                        "api_group": _coerce_text(s.get("api_group") or s.get("apiGroup")),
                    })
                else:
                    canon_subjects.append(_coerce_text(s))   # legacy live-read: a bare reserved-name string
            state["subjects"] = canon_subjects
        for k in ("role", "role_kind", "role_apigroup"):
            if inner.get(k) not in (None, ""):
                state[k] = _coerce_text(inner.get(k))
        retained: dict[str, Any] = {"achieved_state": state}
        for k in ("check_id", "resource_kind", "name", "namespace"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        return cls(bug_class=bug_class, k8s_workload_control=retained)

    @classmethod
    def from_k8s_rbac_grant_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "k8s_rbac_privilege_grant"
    ) -> "FindingContext":
        """A RETAINED RBAC ``binding`` + its SEPARATELY-retained ``role_object``, for the E4 TIER-2
        k8s_rbac_verb_grant oracle — the STRONGER, rule-PARSING sibling of ``from_k8s_workload_control``
        (which only name-matches a built-in role). The oracle re-derives the weakness (an attacker-occupiable
        subject bound to a dangerous (verb,resource) grant, under the subject-gated near-zero-FP rule) over
        the RETAINED binding + role_object ALONE — offline, ZERO cluster calls — so a live RBAC read is
        confirmed a FACT only by the actual dangerous grant, never the collector's say-so.

        Only the structural fields the oracle judges are retained into a canonical shape (subjects keep their
        TYPED {kind,name,namespace,api_group} — the namespace is LOAD-BEARING for the default-SA check, unlike
        the workload reducer which drops it; the roleRef and the role's rules + rules_source + aggregationRule
        presence). Nothing else is laundered into the certificate. The RBAC metadata carries no secret (the
        kubeconfig bearer token is fingerprinted-and-discarded by the runner and never reaches the capture).
        JSON-safe + deterministic (re-verifies offline)."""
        cap = _IMDS_CAPTURE_STR_CAP
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        b_src = src.get("binding") if isinstance(src.get("binding"), Mapping) else {}
        r_src = src.get("role_object") if isinstance(src.get("role_object"), Mapping) else {}

        # -- binding: kind, namespace, name, subjects (typed/string), roleRef ------------------------------
        binding: dict[str, Any] = {}
        for out_k, keys in (("kind", ("kind",)), ("namespace", ("namespace", "ns")), ("name", ("name",))):
            for kk in keys:
                if b_src.get(kk) not in (None, ""):
                    binding[out_k] = _coerce_text(b_src.get(kk))[:cap]
                    break
        raw_subjects = b_src.get("subjects")
        if isinstance(raw_subjects, (list, tuple)):
            canon_subjects: list[Any] = []
            for s in raw_subjects:
                if s is None:
                    continue
                if isinstance(s, Mapping):
                    canon_subjects.append({
                        "kind": _coerce_text(s.get("kind"))[:cap],
                        "name": _coerce_text(s.get("name"))[:cap],
                        # RETAIN namespace — load-bearing for the default-SA (default:default) discrimination.
                        "namespace": _coerce_text(s.get("namespace")
                                                  if s.get("namespace") is not None else s.get("ns"))[:cap],
                        "api_group": _coerce_text(s.get("api_group") or s.get("apiGroup"))[:cap],
                    })
                else:
                    canon_subjects.append(_coerce_text(s)[:cap])   # legacy live-read reserved-name string
            binding["subjects"] = canon_subjects
        ref_src = b_src.get("role_ref")
        if not isinstance(ref_src, Mapping):
            ref_src = b_src.get("roleRef") if isinstance(b_src.get("roleRef"), Mapping) else {}
        ref: dict[str, Any] = {}
        for out_k, keys in (("name", ("name",)), ("kind", ("kind",)),
                            ("api_group", ("api_group", "apiGroup"))):
            for kk in keys:
                if ref_src.get(kk) not in (None, ""):
                    ref[out_k] = _coerce_text(ref_src.get(kk))[:cap]
                    break
        if ref:
            binding["role_ref"] = ref

        # -- role_object: identity + PARSED rules + provenance ---------------------------------------------
        role_object: dict[str, Any] = {}
        for out_k, keys in (("name", ("name",)), ("kind", ("kind",)),
                            ("api_group", ("api_group", "apiGroup")),
                            ("namespace", ("namespace", "ns")),
                            ("rules_source", ("rules_source", "rulesSource"))):
            for kk in keys:
                if r_src.get(kk) not in (None, ""):
                    role_object[out_k] = _coerce_text(r_src.get(kk))[:cap]
                    break
        # aggregationRule PRESENCE is retained as a boolean marker (its selectors are not judged) — a truthy
        # aggregationRule makes a static_manifest source non-authoritative.
        if bool(r_src.get("aggregationRule")) or bool(r_src.get("aggregation_rule")):
            role_object["aggregation_rule"] = True
        raw_rules = r_src.get("rules")
        if isinstance(raw_rules, (list, tuple)):
            canon_rules: list[dict[str, Any]] = []
            for rule in raw_rules:
                if not isinstance(rule, Mapping):
                    continue
                cr: dict[str, Any] = {}
                for out_k, keys in (("verbs", ("verbs",)),
                                    ("resources", ("resources", "resource")),
                                    ("apiGroups", ("apiGroups", "api_groups")),
                                    ("resourceNames", ("resourceNames", "resource_names"))):
                    for kk in keys:
                        v = rule.get(kk)
                        if isinstance(v, (list, tuple)):
                            cr[out_k] = [_coerce_text(x)[:cap] for x in v]
                            break
                if cr:
                    canon_rules.append(cr)
            role_object["rules"] = canon_rules

        retained: dict[str, Any] = {"binding": binding, "role_object": role_object}
        for k in ("check_id", "name"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))[:cap]
                break
        return cls(bug_class=bug_class, k8s_rbac_grant_control=retained)

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
        owner_accounts, achieved_state:{encrypted, public, sensitive, principals}}, so nothing else is
        laundered into the certificate. The optional ``owner_account`` / ``owner_accounts`` (the charter's
        authorized own-account id(s), threaded in by the capture) is retained so the cross-account rule (P4)
        can re-derive a NAMED cross-account grant offline; when absent the rule stays a LEAD (never guessed).
        JSON-safe + deterministic (re-verifies offline)."""
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
        # The OWNER's own-account set (P4) — the charter's authorized own-account id(s) the capture threads
        # in. Gathered from ``owner_account`` (scalar) + ``owner_accounts`` (list), at the control top-level
        # AND inside a nested achieved_state, de-duped (order-preserving). Retained top-level so the
        # cross-account rule re-derives the same verdict offline; absent -> not retained -> the rule stays a
        # LEAD (the owner is never guessed).
        owner: list[str] = []
        for scope in (src, inner):
            if not isinstance(scope, Mapping):
                continue
            one = scope.get("owner_account")
            if one not in (None, ""):
                owner.append(_coerce_text(one))
            many = scope.get("owner_accounts")
            if isinstance(many, (list, tuple)):
                owner.extend(_coerce_text(a) for a in many if a not in (None, ""))
        if owner:
            seen: set[str] = set()
            retained["owner_accounts"] = [a for a in owner if not (a in seen or seen.add(a))]
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
                elif froms:
                    # A `from` that is present-and-TRUTHY but NOT a canonicalizable non-empty list (a mapping, a
                    # string, a mis-authored shape) still expresses SOURCE-RESTRICTION intent. The oracle's
                    # _mesh_authz_allows_all treats a truthy `from` as PRESENT via `not froms` — the rule is NOT
                    # a catch-all and does not fire. Dropping it here collapsed a source-restricted rule to {}
                    # which the oracle then re-read as an empty_catch_all_rule and minted a signed "admits EVERY
                    # caller" FACT (red-pen HIGH — a restrictive AuthorizationPolicy inverted to most-permissive,
                    # signed + offline-re-verifiable). Mirror the to/when presence-marker exactly. (A FALSY `from`
                    # — [] / None — is absent to the oracle's truthiness, so it stays a genuine catch-all here
                    # too; the two sides agree.)
                    out["from"] = [{}]      # presence marker: a source restriction exists (not catch-all)
                if rule.get("to"):
                    out["to"] = [{}]      # presence marker: a path/method restriction exists (not catch-all)
                if rule.get("when"):
                    out["when"] = [{}]    # presence marker: a condition exists (not catch-all)
                canon.append(out)
            retained["rules"] = canon
        return cls(bug_class=bug_class, mesh_control=retained)

    @classmethod
    def from_cicd_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "cicd_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED GitHub-Actions workflow control (``verify.cicd_posture.ingest_workflow`` /
        ``sensors.cicd``), for the CI/CD-posture oracle. The oracle re-derives the danger (an unpinned
        third-party action, a pwn-request, a script-injection sink) over the control's literal evidence
        alone — offline, ZERO repo clone / pipeline run — so a workflow linter's say-so is confirmed a
        FACT only by the actual dangerous construct. Only the fields the oracle judges are retained
        (verbose YAML is never laundered into the certificate). JSON-safe + deterministic."""
        src = dict(control or {})
        retained: dict[str, Any] = {}
        for k in ("rule", "workflow", "job", "uses", "trigger", "checkout_ref", "run"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        return cls(bug_class=bug_class, cicd_control=retained)

    @classmethod
    def from_mobile_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "mobile_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED MobSF mobile-posture control (``sensors.mobile`` / ``verify.mobile_posture``), for
        the mobile-posture oracle. The oracle re-derives the weakness over the control's literal evidence
        alone — offline, by actually LOADING the embedded key material — so a scanner's say-so is confirmed
        a FACT only by the reconstructed key. Only the fields the oracle judges are retained (the ``pem``
        block verbatim so it re-parses); a lead-only control retains nothing extra. JSON-safe + deterministic."""
        src = dict(control or {})
        retained: dict[str, Any] = {}
        for k in ("rule", "check_id", "category", "pem",
                  # exported-content-provider evidence (parsed from the raw AndroidManifest)
                  "name", "exported", "permission", "read_permission", "write_permission",
                  "has_path_permission"):
            v = src.get(k)
            if v not in (None, ""):
                retained[k] = v if isinstance(v, bool) else _coerce_text(v)
        return cls(bug_class=bug_class, mobile_control=retained)

    @classmethod
    def from_email_auth_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "email_auth_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED DNS email-authentication policy record (``sensors.email_auth`` /
        ``verify.email_auth``), for the email-auth-posture oracle (FORGE Domain 10). The oracle re-derives
        a spoofing-permitting policy (no DMARC / p=none / SPF +all) from the record's literal text alone —
        offline, ZERO DNS calls — so a scanner's say-so is confirmed a FACT only by the published policy
        itself. Only the fields the oracle judges are retained. JSON-safe + deterministic."""
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        retained: dict[str, Any] = {}
        for k in ("rule", "domain", "dmarc_record", "spf_record", "org_domain", "org_dmarc_record"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        # The attestation flags are retained STRICTLY: only a literal True survives. NEVER bool()-coerce —
        # that would widen the oracle's `is not True` guard back open (a truthy "false"/"no"/1 would become
        # True) and, because retention happens BEFORE the certificate is minted, would LAUNDER a fabricated
        # attestation permanently into a signed, forever-re-firing certificate.
        for flag in ("dmarc_observed", "org_dmarc_observed", "is_org_domain"):
            if src.get(flag) is True:
                retained[flag] = True
        return cls(bug_class=bug_class, email_auth_control=retained)

    @classmethod
    def from_identity_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "identity_misconfiguration"
    ) -> "FindingContext":
        """A RETAINED identity-provider export control (``sensors.identity`` / ``verify.identity_posture``),
        for the identity-posture oracle (FORGE Domain 7). The oracle re-derives an identity-posture weakness
        (a privileged identity with MFA provably off; a credential past its rotation policy; a universal
        wildcard grant; or a dormant privileged identity) from the control's STRICT-TYPED literal fields alone
        — offline, ZERO IdP calls — so a scanner's say-so is a FACT only by the export itself. Only the fields
        the oracle judges are retained. JSON-safe + deterministic."""
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        retained: dict[str, Any] = {}
        for k in ("rule", "subject", "grant"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        # Integer fields are retained ONLY as genuine ints (a bool is not an int; a numeric string is not
        # coerced) — the oracle compares them; a laundered non-integer would be refused there, but keeping
        # retention strict means the certificate never carries a value the oracle would not itself accept.
        for k in ("age_days", "max_age_days", "days_since_login", "dormancy_threshold_days"):
            v = src.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                retained[k] = v
        # The attestation flags are retained STRICTLY: only a literal True/False survives (never coerced) —
        # a truthy "false"/1 would widen the oracle's strict `is True`/`is False` guards and, because
        # retention precedes minting, LAUNDER a fabricated attestation permanently into a signed certificate.
        for flag in ("privileged", "never_rotated", "admin_all"):
            if src.get(flag) is True:
                retained[flag] = True
        # mfa_enrolled is the one flag whose FALSE is load-bearing (it is the fired condition), so BOTH a
        # literal True (compliant, silent) and a literal False (the weakness) are retained; anything else is
        # dropped so the oracle sees "unknown" and REFUSES rather than reading absence as False.
        if src.get("mfa_enrolled") is True:
            retained["mfa_enrolled"] = True
        elif src.get("mfa_enrolled") is False:
            retained["mfa_enrolled"] = False
        return cls(bug_class=bug_class, identity_control=retained)

    @classmethod
    def from_clickjacking_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "clickjacking"
    ) -> "FindingContext":
        """A RETAINED response's header set for the clickjacking posture oracle (W16-STD-5). The oracle
        re-derives the weakness (NO framing X-Frame-Options AND no CSP frame-ancestors) over the OBSERVED
        headers alone — offline, ZERO traffic — so a scanner's say-so is a FACT only by the actual absent
        defense. The full captured header collection is retained (the oracle must see EVERY header to prove
        neither defense is present); ``url``/``rule`` are retained verbatim. JSON-safe + deterministic."""
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        retained: dict[str, Any] = {}
        for k in ("rule", "url"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        headers = src.get("headers")
        if isinstance(headers, Mapping):
            # lowercase-key the retained headers so the certificate is canonical and the oracle's
            # complete-header-set requirement is met from the certificate alone.
            retained["headers"] = {_coerce_text(k).lower(): _coerce_text(v) for k, v in headers.items()}
        elif isinstance(headers, (list, tuple)):
            retained["headers"] = [[_coerce_text(p[0]), _coerce_text(p[1])]
                                   for p in headers if isinstance(p, (list, tuple)) and len(p) == 2]
        return cls(bug_class=bug_class, clickjacking_control=retained)

    @classmethod
    def from_csrf_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "csrf"
    ) -> "FindingContext":
        """A RETAINED control-vs-treatment status pair for the CSRF posture oracle (W16-STD-5). The oracle
        re-derives the weakness (a state-changing request accepted 2xx with a valid token AND accepted 2xx
        with the token removed/forged) over the retained statuses alone — offline — so a scanner's say-so is
        a FACT only by the actual acceptance-differential. Only the fields the oracle judges are retained;
        the two statuses are retained STRICTLY as ints (never coerced). JSON-safe + deterministic."""
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        retained: dict[str, Any] = {}
        for k in ("rule", "method", "endpoint"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        for k in ("token_present_status", "token_absent_status"):
            v = src.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                retained[k] = v
        return cls(bug_class=bug_class, csrf_control=retained)

    @classmethod
    def from_csrf_achieved(
        cls,
        *,
        method: str,
        endpoint: str,
        marker: str,
        with_cookie_state: Any,
        no_cookie_state: Any,
        target_origin: str,
        initiator_origin: str,
        ambient_cookie_name: str,
        associated_cookies: "Sequence[Mapping[str, Any]] | None" = None,
        observed_cookie_header: str = "",
        observed_request_fields: "Sequence[str] | None" = None,
        observed_request_header_names: "Sequence[str] | None" = None,
        bug_class: str = "csrf_achieved",
    ) -> "FindingContext":
        """The RETAINED browser-OBSERVED evidence for the CSRF-achieved oracle (Wave-3.3). The gated
        headless-browser cross-site re-drive issues the state-changing request FIRST without the ambient
        cookie (the control) then WITH it (the treatment) from a GENUINELY different-site attacker page,
        each followed by an authoritative post-state readback; ``marker`` is the VIGIL-chosen unique token
        the write carried.

        The oracle (kind ACHIEVED_STATE, via the ``csrf_achieved`` ctx key) DERIVES cross_origin and
        ambient_only FROM this evidence — it never trusts a bare bool:
          * ``initiator_origin`` (the browser-attested ``Origin`` of the attacker page) and
            ``target_origin`` must be genuinely cross-site;
          * ``associated_cookies`` (the CDP ``Network.requestWillBeSentExtraInfo`` observation, each
            ``{name, blocked_reasons}``) + ``observed_cookie_header`` must show the browser ACTUALLY
            attached the ``ambient_cookie_name`` cookie cross-site with NO SameSite block — the
            SameSite-dissolution proof; a Strict/Lax cookie carries a ``SameSite*`` blocked reason;
          * ``observed_request_fields`` / ``observed_request_header_names`` must carry NO anti-CSRF token;
          * the ``marker`` appears in ``with_cookie_state`` AND is ABSENT from ``no_cookie_state``.
        All evidence is retained verbatim so the pure oracle re-derives the same facts offline and a
        tampered origin / associated-cookie / readback no longer confirms. JSON-safe + deterministic."""
        return cls(
            bug_class=bug_class,
            csrf_achieved={
                "rule": "cross_site_state_change",
                "method": _coerce_text(method),
                "endpoint": _coerce_text(endpoint),
                "target_origin": _coerce_text(target_origin),
                "initiator_origin": _coerce_text(initiator_origin),
                "ambient_cookie_name": _coerce_text(ambient_cookie_name),
                "associated_cookies": [
                    {"name": _coerce_text(c.get("name")),
                     "blocked_reasons": [_coerce_text(r) for r in (c.get("blocked_reasons") or [])]}
                    for c in (associated_cookies or []) if isinstance(c, Mapping)
                ],
                "observed_cookie_header": _coerce_text(observed_cookie_header),
                "observed_request_fields": [_coerce_text(f) for f in (observed_request_fields or [])],
                "observed_request_header_names": [
                    _coerce_text(h).lower() for h in (observed_request_header_names or [])
                ],
                "marker": _coerce_text(marker),
                "with_cookie_state": _coerce_text(with_cookie_state),
                "no_cookie_state": _coerce_text(no_cookie_state),
            },
        )

    @classmethod
    def from_postmessage_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "postmessage"
    ) -> "FindingContext":
        """A RETAINED postMessage handler source (and/or a captured target-origin literal) for the
        postMessage posture oracle (W16-STD-5). The oracle re-derives the weakness (a ``*`` targetOrigin
        send, or a handler that consumes ``event.data`` with NO origin check) over the retained source
        alone — offline, a sound static check — so a scanner's say-so is a FACT only by the actual source.
        The handler source is retained verbatim (the oracle re-parses it). JSON-safe + deterministic."""
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        retained: dict[str, Any] = {}
        for k in ("rule", "target_origin"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        source = src.get("handler_source") or src.get("source")
        if source not in (None, ""):
            retained["handler_source"] = _coerce_text(source)
        return cls(bug_class=bug_class, postmessage_control=retained)

    @classmethod
    def from_csp_control(
        cls, control: Mapping[str, Any], *, bug_class: str = "csp_posture"
    ) -> "FindingContext":
        """A RETAINED CSP response header (+ report-only flag) for the CSP posture oracle (Wave-2.4). The
        oracle re-parses the effective script-src (script-src else default-src) over the retained header
        ALONE — offline, no browser — and fires only on the actual permissive weakness, so a scanner's
        say-so is a FACT only by the actual parsed policy. The header is retained verbatim (the oracle
        re-parses it); ``report_only`` is retained STRICTLY as a bool. JSON-safe + deterministic."""
        src = dict(control or {}) if isinstance(control, Mapping) else {}
        retained: dict[str, Any] = {}
        for k in ("rule", "url", "header"):
            if src.get(k) not in (None, ""):
                retained[k] = _coerce_text(src.get(k))
        if "report_only" in src:
            retained["report_only"] = bool(src.get("report_only"))
        return cls(bug_class=bug_class, csp_control=retained)

    @classmethod
    def from_csp_bypass(
        cls,
        binding_calls: Sequence[Any],
        canary: str,
        csp_header: str,
        *,
        report_only: bool = False,
        bug_class: str = "csp_bypass",
    ) -> "FindingContext":
        """The DOM-execution readback PLUS the retained enforced CSP the execution DEFIED, for the achieved
        CSP-bypass class (Wave-2.4). Reuses the DOM_EXECUTION oracle (``binding_calls``/``canary`` — the
        same unforgeable execution signal ``from_dom_execution`` carries) and additionally retains the
        ENFORCED CSP header so the guarded dispatch can re-derive OFFLINE that the policy's script-src
        purported to block the execution — a genuine bypass, never a no-CSP/permissive DOM-XSS relabelled.
        ``report_only`` is retained as a bool (a report-only header enforces nothing, so it can never mint a
        bypass). JSON-safe + deterministic."""
        return cls(
            bug_class=bug_class,
            dom_binding_calls=[_coerce_text(c) for c in (binding_calls or [])],
            dom_canary=_coerce_text(canary),
            csp_block_control={"header": _coerce_text(csp_header), "report_only": bool(report_only)},
        )

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
        candidate_certs: Sequence[str | bytes] = (),
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

        ``candidate_certs`` (OPT-IN, mirroring ``from_jwt_token``'s ``candidate_keys``) are the
        OPERATOR-PROVIDED TRUSTED IdP signing cert(s) (PEM). When supplied AND ``signxml`` is importable,
        the oracle ADDITIONALLY runs a real XML-DSig cryptographic verification against those trusted
        anchors and fires when the signature is DEFINITIVELY invalid (wrong signer / tampered digest).
        The signature's OWN embedded ds:X509Certificate is NEVER trusted (an attacker controls it). When
        no trusted cert is supplied (or signxml is absent) the crypto branch is DORMANT and this degrades
        to the structural-only oracle, byte-identical.

        The XML (and PEM certs) are JSON-safe, so a confirmed forgery re-verifies OFFLINE from its
        certificate (``verify.reverify``) — re-run the pure oracle over the retained XML + trusted certs,
        get the same verdict. This is the offline structural complement to the LIVE response-differential
        SAML checks, with an opt-in cryptographic escalation."""
        certs = [c.decode("utf-8", "replace") if isinstance(c, bytes) else _coerce_text(c)
                 for c in (candidate_certs or ())]
        return cls(bug_class=bug_class, saml_xml=_coerce_text(xml),
                   saml_candidate_certs=certs or None)

    @classmethod
    def from_imds_capture(
        cls, capture: Mapping[str, Any], *, bug_class: str = "imds_credential_capture"
    ) -> "FindingContext":
        """A RETAINED IMDS/metadata credential-capture, for the E1 exploitation-chain oracle (BUILD-PLAN
        §E1). The retained evidence that turns an SSRF/foothold-reaches-IMDS LEAD into an achieved-effect
        FACT: the oracle re-derives, over this capture ALONE — offline, ZERO network, NO exploitation —
        that role/SA credentials were retrieved from the instance metadata endpoint AND authenticated (a
        confirming sts:GetCallerIdentity / tokeninfo echoed the identity). This builder is NOT a runner; it
        reduces whatever the WARDEN-gated runner captured into the canonical shape the oracle judges.

        SECRET-SAFE by construction: the credential's secret material (``SecretAccessKey`` / ``Token`` /
        ``access_token``) is REDACTED to a fixed presence marker — the oracle never validates a secret's
        content, only that a secret was PRESENT at capture time, so the certificate carries NO live secret
        yet the same verdict re-verifies offline. The AWS ``AccessKeyId`` and the confirming call's
        identity echo (``Arn`` / 12-digit ``Account`` / ``UserId`` / ``email`` / ``sub``) are IDENTIFIERS,
        not secrets (they appear in CloudTrail), so they are retained verbatim — they are load-bearing for
        the structural + authentication proof. The ``source`` url is retained verbatim (the oracle parses it
        with ``urllib.parse.urlsplit`` and requires its HOST — not a substring of the raw string — to be the
        metadata endpoint, so a userinfo-@/query-param/rebind host or a creds-file path is NOT an IMDS
        reach). A failure marker in the confirming call's body (error/errors/message/code/__type/Fault) is
        also retained so a FAILED call re-verifies as NON-firing (the mint-side failure gate is mirrored at
        re-execution). Verbose scanner prose is never laundered in. JSON-safe + deterministic (re-verifies
        offline)."""
        src = dict(capture or {})
        cred_src: Mapping[str, Any] = src
        for k in ("credential", "creds", "credentials"):
            if isinstance(src.get(k), Mapping):
                cred_src = src[k]
                break

        def _redact_present(value: Any) -> str | None:
            # A non-empty secret becomes a fixed marker (its PRESENCE is the structural fact the oracle
            # judges — it never validates a secret's content); an absent/empty secret stays absent.
            return "[REDACTED]" if _coerce_text(value).strip() else None

        cred: dict[str, Any] = {}
        akid = cred_src.get("AccessKeyId") or cred_src.get("access_key_id")
        if akid not in (None, ""):
            cred["AccessKeyId"] = _coerce_text(akid)[:_IMDS_CAPTURE_STR_CAP]   # identifier, not a secret
        sec = _redact_present(cred_src.get("SecretAccessKey") or cred_src.get("secret_access_key"))
        if sec is not None:
            cred["SecretAccessKey"] = sec                          # redacted presence marker
        tok = _redact_present(cred_src.get("Token") or cred_src.get("SessionToken")
                              or cred_src.get("session_token"))
        if tok is not None:
            cred["Token"] = tok                                    # redacted presence marker
        at = _redact_present(cred_src.get("access_token") or cred_src.get("accessToken"))
        if at is not None:
            cred["access_token"] = at                              # redacted presence marker (GCP)
        tt = cred_src.get("token_type") or cred_src.get("tokenType")
        if tt not in (None, ""):
            cred["token_type"] = _coerce_text(tt)
        source = ""
        for obj in (cred_src, src):
            if not isinstance(obj, Mapping):
                continue
            for k in ("source", "url", "metadata_url", "endpoint", "uri"):
                if obj.get(k) not in (None, ""):
                    source = _imds_scrub_source(obj.get(k))    # drop userinfo/query/fragment secrets (B5)
                    break
            if source:
                break
        if source:
            cred["source"] = source
        # E1-complete: retain the runner-produced binding fingerprint + IMDS-GET transport provenance (all
        # non-secret: a hash, an IP, booleans) so the oracle's FACT-capability check re-verifies offline.
        for k in ("credential_fingerprint", "resolved_peer"):
            if cred_src.get(k) not in (None, ""):
                cred[k] = _coerce_text(cred_src.get(k))[:_IMDS_CAPTURE_STR_CAP]
        for k in ("no_proxy", "no_redirect"):
            if cred_src.get(k) is not None:
                cred[k] = _imds_json_scalar(cred_src.get(k))

        retained: dict[str, Any] = {"credential": cred}
        if src.get("provider") not in (None, ""):
            retained["provider"] = _coerce_text(src.get("provider"))

        call_src: Mapping[str, Any] | None = None
        for k in ("confirming_call", "confirmation", "confirm_call", "verify_call", "caller_identity"):
            if isinstance(src.get(k), Mapping):
                call_src = src[k]
                break
        if call_src is not None:
            call: dict[str, Any] = {}
            st = call_src.get("status", call_src.get("status_code"))
            if st is not None:
                call["status"] = _imds_json_scalar(st)              # JSON-safe (a datetime/object won't break) (B5)
            for k in ("action", "method"):
                if call_src.get(k) not in (None, ""):
                    call[k] = _coerce_text(call_src.get(k))[:_IMDS_CAPTURE_STR_CAP]
            if call_src.get("endpoint") not in (None, ""):
                call["endpoint"] = _imds_scrub_source(call_src.get("endpoint"))   # drop query secrets (B5)
            # E1-complete: retain the confirming-call binding fingerprint + trusted-transport provenance.
            for k in ("credential_fingerprint", "resolved_peer", "response_digest"):
                if call_src.get(k) not in (None, ""):
                    call[k] = _coerce_text(call_src.get(k))[:_IMDS_CAPTURE_STR_CAP]
            for k in ("tls_verified", "no_proxy", "no_redirect"):
                if call_src.get(k) is not None:
                    call[k] = _imds_json_scalar(call_src.get(k))
            body_src: Mapping[str, Any] = call_src
            for k in ("response", "body", "identity", "result", "json"):
                if isinstance(call_src.get(k), Mapping):
                    body_src = call_src[k]
                    break
            resp: dict[str, Any] = {}
            for out_k, keys in (("Arn", ("Arn", "arn")), ("Account", ("Account", "account")),
                                ("UserId", ("UserId", "user_id", "userId")),
                                ("email", ("email", "email_address")), ("sub", ("sub", "subject"))):
                for kk in keys:
                    if body_src.get(kk) not in (None, ""):
                        resp[out_k] = _coerce_text(body_src.get(kk))[:_IMDS_CAPTURE_STR_CAP]
                        break
            for kk in ("exp", "expires_in", "expires_at", "expiry", "expireTime", "expire_time"):
                if body_src.get(kk) not in (None, ""):
                    resp[kk] = _imds_json_scalar(body_src.get(kk))    # JSON-safe expiry (B5)
                    break
            # Retain a truthy error marker so a FAILED confirming call stays non-firing on re-verify — the
            # full failure allowlist MUST match the oracle's `_IMDS_ERROR_KEYS` so the mint-side gate is
            # mirrored at re-execution.
            for kk in list(body_src.keys()):
                if (str(kk).strip().lower() in _IMDS_ADAPTER_ERROR_KEYS and body_src.get(kk)):
                    resp[_coerce_text(kk)[:_IMDS_CAPTURE_STR_CAP]] = \
                        _coerce_text(body_src.get(kk))[:_IMDS_CAPTURE_STR_CAP]
            # round-2 (seam mirror): the adapter FLATTENS the body, so a NESTED failure marker would be
            # dropped and the scrubbed context would wrongly re-verify as firing. If the raw body carries an
            # error at ANY depth but none was retained above, add a top-level marker so re-execution sees the
            # failure (the mint-side recursive gate is now mirrored at re-execution).
            if _imds_body_has_error(body_src) and not any(
                    _coerce_text(k).strip().lower() in _IMDS_ADAPTER_ERROR_KEYS for k in resp):
                resp["error"] = "[failure marker retained from nested confirming-call metadata]"
            if resp:
                call["response"] = resp
            retained["confirming_call"] = call
        return cls(bug_class=bug_class, imds_capture=retained)

    @classmethod
    def from_secret_capture(
        cls, capture: Mapping[str, Any], *, bug_class: str = "secret_credential_validity"
    ) -> "FindingContext":
        """A RETAINED, SECRET-SAFE exposed-secret capture, for the E5 validity oracle (BUILD-PLAN §E5). Reduces
        whatever the WARDEN-gated secret-validation runner captured into the canonical shape the oracle judges.

        SECRET-SAFE by construction: the secret VALUE is REDACTED to a fixed presence marker — the oracle
        proves VALIDITY via the confirming call, never the secret's content, so the certificate carries NO
        live secret yet the same verdict re-verifies offline. The non-secret IDENTIFIER (an AWS AccessKeyId, a
        token prefix), the exposure ``source``, the fingerprints, and the confirming call's identity echo are
        IDENTIFIERS, not secrets, retained verbatim (load-bearing for the structural + authentication proof).
        A failure marker in the confirming call's body is retained so a FAILED call re-verifies as NON-firing.
        JSON-safe + deterministic (re-verifies offline)."""
        src = dict(capture or {})
        cred_src: Mapping[str, Any] = src.get("credential") if isinstance(src.get("credential"), Mapping) else {}
        call_src: Mapping[str, Any] = (src.get("confirming_call")
                                       if isinstance(src.get("confirming_call"), Mapping) else {})
        cap = _IMDS_CAPTURE_STR_CAP

        cred: dict[str, Any] = {}
        ident = cred_src.get("identifier") or cred_src.get("id") or cred_src.get("prefix")
        if ident not in (None, ""):
            cred["identifier"] = _coerce_text(ident)[:cap]                 # non-secret id / prefix
        if _coerce_text(cred_src.get("secret")).strip():
            cred["secret"] = "[REDACTED]"                                  # PRESENCE marker only
        for k in ("credential_fingerprint", "source"):
            if cred_src.get(k) not in (None, ""):
                cred[k] = _coerce_text(cred_src.get(k))[:cap]

        call: dict[str, Any] = {}
        if call_src:
            for k in ("action", "endpoint", "credential_fingerprint", "resolved_peer", "response_digest"):
                if call_src.get(k) not in (None, ""):
                    call[k] = _coerce_text(call_src.get(k))[:cap]
            if call_src.get("status") not in (None, ""):
                call["status"] = call_src.get("status")
            for k in ("tls_verified", "no_proxy", "no_redirect"):
                if k in call_src:
                    call[k] = bool(call_src.get(k))
            resp_src = call_src.get("response")
            if isinstance(resp_src, Mapping):
                # identity echo (Arn/Account/UserId/login/id/…) + any failure marker — numbers/bools kept
                # verbatim (a GitHub numeric id is load-bearing), everything else capped text.
                resp = {_coerce_text(rk)[:cap]: (rv if isinstance(rv, (int, float, bool))
                                                 else _coerce_text(rv)[:cap])
                        for rk, rv in list(resp_src.items())[:32]}
                if _imds_body_has_error(resp_src) and not any(
                        _coerce_text(k).strip().lower() in _IMDS_ADAPTER_ERROR_KEYS for k in resp):
                    resp["error"] = "[failure marker retained from nested confirming-call metadata]"
                if resp:
                    call["response"] = resp

        retained: dict[str, Any] = {"secret_type": _coerce_text(src.get("secret_type"))[:cap].lower()}
        if cred:
            retained["credential"] = cred
        if call:
            retained["confirming_call"] = call
        return cls(bug_class=bug_class, secret_capture=retained)

    @classmethod
    def from_gcp_impersonation_capture(
        cls, capture: Mapping[str, Any], *, bug_class: str = "gcp_sa_impersonation"
    ) -> "FindingContext":
        """A RETAINED, SECRET-SAFE GCP service-account impersonation capture, for the E3 oracle (BUILD-PLAN
        §E3). Reduces whatever the WARDEN-gated impersonation runner captured into the canonical shape the
        oracle judges.

        SECRET-SAFE by construction: the minted impersonation TOKEN (``token`` / ``access_token`` /
        ``id_token`` / ``signed_jwt`` …) is REDACTED to a fixed presence marker — the oracle proves
        impersonation via the confirming identity echo + the fingerprint binding, never the token's content,
        so the certificate carries NO live token yet the same verdict re-verifies offline. The named target SA
        (``mint.target``), the mint method, the fingerprints, and the confirming call's identity echo (email /
        numeric sub) are IDENTIFIERS, not secrets, retained verbatim (load-bearing for the impersonation
        proof). A failure marker in the confirming call's body is retained so a FAILED call re-verifies as
        NON-firing. JSON-safe + deterministic (re-verifies offline)."""
        src = dict(capture or {})
        cap = _IMDS_CAPTURE_STR_CAP
        mint_src: Mapping[str, Any] = src
        for k in ("mint", "impersonation", "token_mint", "mint_call"):
            if isinstance(src.get(k), Mapping):
                mint_src = src[k]
                break
        call_src: Mapping[str, Any] = (src.get("confirming_call")
                                       if isinstance(src.get("confirming_call"), Mapping) else {})

        mint: dict[str, Any] = {}
        for out_k, keys in (("method", ("method", "action")),
                            ("target", ("target_service_account", "target", "target_sa", "target_email",
                                        "target_principal", "service_account", "sa"))):
            for kk in keys:
                if mint_src.get(kk) not in (None, ""):
                    mint[out_k] = _coerce_text(mint_src.get(kk))[:cap]   # identifier, not a secret
                    break
        if any(_coerce_text(mint_src.get(k)).strip() for k in
               ("token", "access_token", "accessToken", "id_token", "idToken",
                "signed_jwt", "signedJwt", "signed_blob", "signedBlob")):
            mint["token"] = "[REDACTED]"                                  # PRESENCE marker only
        if mint_src.get("credential_fingerprint") not in (None, ""):
            mint["credential_fingerprint"] = _coerce_text(mint_src.get("credential_fingerprint"))[:cap]
        if mint_src.get("endpoint") not in (None, ""):
            mint["endpoint"] = _imds_scrub_source(mint_src.get("endpoint"))   # drop query secrets (B5)
        if mint_src.get("status") not in (None, ""):
            mint["status"] = _imds_json_scalar(mint_src.get("status"))

        call: dict[str, Any] = {}
        if call_src:
            for k in ("action", "endpoint", "credential_fingerprint", "resolved_peer", "response_digest"):
                if call_src.get(k) not in (None, ""):
                    call[k] = (_imds_scrub_source(call_src.get(k)) if k == "endpoint"
                               else _coerce_text(call_src.get(k))[:cap])
            if call_src.get("status") not in (None, ""):
                call["status"] = _imds_json_scalar(call_src.get("status"))
            for k in ("tls_verified", "no_proxy", "no_redirect"):
                if k in call_src:
                    call[k] = bool(call_src.get(k))
            resp_src = call_src.get("response")
            if isinstance(resp_src, Mapping):
                resp: dict[str, Any] = {}
                for out_k, keys in (("email", ("email", "email_address")), ("sub", ("sub", "subject"))):
                    for kk in keys:
                        if resp_src.get(kk) not in (None, ""):
                            resp[out_k] = _coerce_text(resp_src.get(kk))[:cap]
                            break
                for kk in ("exp", "expires_in", "expires_at", "expiry", "expireTime", "expire_time"):
                    if resp_src.get(kk) not in (None, ""):
                        resp[kk] = _imds_json_scalar(resp_src.get(kk))
                        break
                for kk in list(resp_src.keys()):
                    if str(kk).strip().lower() in _IMDS_ADAPTER_ERROR_KEYS and resp_src.get(kk):
                        resp[_coerce_text(kk)[:cap]] = _coerce_text(resp_src.get(kk))[:cap]
                # a NESTED failure marker the flat scan above would miss (mirrors from_imds_capture round-2).
                if _imds_body_has_error(resp_src) and not any(
                        _coerce_text(k).strip().lower() in _IMDS_ADAPTER_ERROR_KEYS for k in resp):
                    resp["error"] = "[failure marker retained from nested confirming-call metadata]"
                if resp:
                    call["response"] = resp

        retained: dict[str, Any] = {}
        for k in ("target_service_account", "target"):
            if src.get(k) not in (None, ""):
                retained["target_service_account"] = _coerce_text(src.get(k))[:cap]
                break
        if mint:
            retained["mint"] = mint
        if call:
            retained["confirming_call"] = call
        return cls(bug_class=bug_class, gcp_impersonation_capture=retained)

    @classmethod
    def from_iam_escalation_capture(
        cls, capture: Mapping[str, Any], *, bug_class: str = "iam_escalation_primitive"
    ) -> "FindingContext":
        """A RETAINED IAM-policy capture for the E2 escalation-primitive oracle (BUILD-PLAN §E2). Reduces the
        capture into the canonical shape ``iam_escalation_oracle`` judges — {base_principal, target_resource,
        target_access, graph:{grants,assume,member_of}, escalation:{primitive, via, statements[], boundary?,
        scp?}} — retaining ONLY the structural fields the differential re-derivation reads, so verbose export
        prose is not laundered into the certificate. Carries NO secret — only IAM ids / actions / resources
        (identifiers), retained verbatim (capped) because they are load-bearing. A Condition is reduced to a
        presence marker (the oracle only checks its PRESENCE, never its content). JSON-safe + deterministic
        (re-verifies offline)."""
        cap = _IMDS_CAPTURE_STR_CAP
        src = dict(capture or {})

        def _t(v: Any) -> str:
            return _coerce_text(v)[:cap]

        def _lst(v: Any) -> list[str]:
            items = [v] if isinstance(v, str) else (list(v) if isinstance(v, Sequence) else [])
            return [_t(x) for x in items[:256] if isinstance(x, str)]

        def _graph(g: Any) -> dict[str, Any]:
            g = g if isinstance(g, Mapping) else {}
            grants = [{"principal": _t(x.get("principal")), "resource": _t(x.get("resource")),
                       "access": _t(x.get("access"))}
                      for x in (g.get("grants") or [])[:1024] if isinstance(x, Mapping)]
            edges = {rel: [{"src": _t(x.get("src")), "dst": _t(x.get("dst"))}
                           for x in (g.get(rel) or [])[:1024] if isinstance(x, Mapping)]
                     for rel in ("assume", "member_of")}
            return {"grants": grants, **edges}

        def _stmt(s: Any) -> dict[str, Any]:
            s = s if isinstance(s, Mapping) else {}
            out: dict[str, Any] = {}
            eff = _t(s.get("effect") or s.get("Effect"))
            if eff:
                out["effect"] = eff
            actions = _lst(s.get("action") or s.get("Action"))
            if actions:
                out["action"] = actions
            not_action = _lst(s.get("not_action") or s.get("NotAction"))
            if not_action:
                out["not_action"] = not_action
            resources = _lst(s.get("resource") or s.get("Resource"))
            if resources:
                out["resource"] = resources
            if s.get("condition") or s.get("Condition"):
                out["condition"] = {"present": True}   # presence marker only (the oracle checks presence)
            return out

        esc_src = src.get("escalation") if isinstance(src.get("escalation"), Mapping) else {}
        esc: dict[str, Any] = {
            "primitive": _t(esc_src.get("primitive")), "via": _t(esc_src.get("via")),
            "statements": [_stmt(x) for x in (esc_src.get("statements") or [])[:256] if isinstance(x, Mapping)],
        }
        for layer in ("boundary", "scp"):
            lv = esc_src.get(layer)
            if isinstance(lv, Mapping):
                esc[layer] = {"statements": [_stmt(x) for x in (lv.get("statements") or [])[:256]
                                             if isinstance(x, Mapping)]}

        retained: dict[str, Any] = {
            "base_principal": _t(src.get("base_principal")),
            "target_resource": _t(src.get("target_resource")),
            "target_access": _t(src.get("target_access")),
            "graph": _graph(src.get("graph")),
            "escalation": esc,
        }
        return cls(bug_class=bug_class, iam_escalation_capture=retained)

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
    def from_ssi(
        cls,
        raw_directive: str,
        expected_result: str,
        observed_body: Any,
        *,
        control_body: Any = None,
        bug_class: str = "ssi",
    ) -> "FindingContext":
        """An injected Server-Side Include DIRECTIVE (``<!--#…-->``), the PER-PROBE random product it
        computes to, and the response it was observed in (plus an optional benign control), for the
        SSI evaluation oracle (Wave-4.1, CWE-97). Confirms SSI only when the server EVALUATED the
        directive — the product present, the raw directive absent — never on an inert-comment echo."""
        return cls(
            bug_class=bug_class,
            ssi_raw=_coerce_text(raw_directive),
            ssi_expected=_coerce_text(expected_result),
            ssi_observed=_coerce_text(observed_body),
            ssi_control=_coerce_text(control_body) if control_body is not None else None,
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

    @classmethod
    def from_prototype_pollution(
        cls,
        *,
        polluted_key: str,
        expected_val: str,
        benign_key: str,
        polluted_val: Any,
        benign_key_undefined: Any,
        bug_class: str = "prototype_pollution",
    ) -> "FindingContext":
        """The binding-reported achieved-state readback for the prototype-pollution oracle.

        ``polluted_key``/``expected_val`` are the UNIQUE per-probe key/value the
        ``__proto__[uniqKey]=uniqVal`` gadget drove in; ``polluted_val`` is what
        ``Object.prototype[polluted_key]`` actually held after the page rendered; ``benign_key`` is a
        different key that was NEVER injected and ``benign_key_undefined`` whether it stayed undefined.
        The oracle confirms client-side prototype pollution ONLY when ``polluted_val == expected_val``
        AND ``benign_key_undefined is True`` — the ACHIEVED polluted state, never that the payload merely
        appeared in the DOM."""
        return cls(
            bug_class=bug_class,
            proto_pollution={
                "polluted_key": _coerce_text(polluted_key),
                "expected_val": _coerce_text(expected_val),
                "polluted_val": None if polluted_val is None else _coerce_text(polluted_val),
                "benign_key": _coerce_text(benign_key),
                "benign_key_undefined": bool(benign_key_undefined) if benign_key_undefined is not None else None,
            },
        )

    @classmethod
    def from_session_fixation(
        cls,
        *,
        sentinel_id: str,
        post_auth_id: str | None,
        cookie_name: str = "",
        private_discriminator: str | None = None,
        success_marker: str | None = None,
        logged_out_markers: Any = (),
        logged_out_statuses: Any = (),
        authorized_view: Any = None,
        owner_view: Any = None,
        unauth_ref: Any = None,
        logged_out_ref: Any = None,
        bug_class: str = "session_fixation",
    ) -> "FindingContext":
        """The retained session-fixation record for the session-fixation oracle (OracleKind.SESSION_FIXATION,
        CWE-384). It carries the RAW bytes the oracle re-runs its PRIVATE-READ DIFFERENTIAL over — never a
        pre-computed authenticated bool, never a bare success-marker differential.

        ``sentinel_id`` (S0) is the UNIQUE high-entropy id VIGIL chose and set as the session cookie BEFORE the
        operator login sequence; ``post_auth_id`` (S1) is the session-cookie value in effect AFTER login;
        ``private_discriminator`` (D) is the operator's genuine victim-PRIVATE datum — the achieved-state
        proof. ``authorized_view`` is ``{status, body}`` of the protected URL fetched carrying the VIGIL-fixed
        id S0 AFTER login (S0's read); ``owner_view`` is the SAME URL read authoritatively as the owner/victim
        (the POSITIVE reference — D must be PRESENT); ``unauth_ref`` is the SAME URL read by an OTHER
        unauthorized identity (the DECISIVE SAME-SHAPE negative reference — a substantive 2xx from which D must
        be ABSENT); ``logged_out_ref`` is the SAME URL with NO session cookie (the no-session gating baseline);
        ``logged_out_markers`` / ``logged_out_statuses`` are the operator's decisive not-authenticated signals;
        ``success_marker`` is LEGACY and is NOT a minting path (a bare marker differential proves only that a
        credential changed the response, not that S0 authenticated). The oracle fires ONLY when S1 == S0 (the
        fixed id survived unrotated) AND D is PRESENT in S0's read AND in the owner's authoritative read yet
        PROVABLY ABSENT from a SUBSTANTIVE SAME-SHAPE other-identity reference and a valid no-session baseline
        — the achieved fixation state, never that a cookie was merely set. No/invalid/reflected D, a missing
        positive or same-shape negative reference, D present in a negative reference, a rotated value with a
        dead S0, a missing S1, or an undecidable differential are LEAD / clean / inconclusive — never a FACT."""
        def _view(v: Any) -> "dict | None":
            if not isinstance(v, Mapping):
                return None
            return {"status": v.get("status"), "body": _coerce_text(v.get("body"))}

        def _strs(seq: Any) -> "list[str]":
            if isinstance(seq, (list, tuple, set, frozenset)):
                return [_coerce_text(x) for x in seq]
            return []

        def _ints(seq: Any) -> "list[int]":
            out: list[int] = []
            if isinstance(seq, (list, tuple, set, frozenset)):
                for x in seq:
                    try:
                        out.append(int(x))
                    except (TypeError, ValueError):
                        continue
            return out

        return cls(
            bug_class=bug_class,
            session_fixation={
                "sentinel_id": _coerce_text(sentinel_id),
                "post_auth_id": None if post_auth_id is None else _coerce_text(post_auth_id),
                "cookie_name": _coerce_text(cookie_name),
                "private_discriminator": None if private_discriminator is None else _coerce_text(private_discriminator),
                "success_marker": None if success_marker is None else _coerce_text(success_marker),
                "logged_out_markers": _strs(logged_out_markers),
                "logged_out_statuses": _ints(logged_out_statuses),
                "authorized_view": _view(authorized_view),
                "owner_view": _view(owner_view),
                "unauth_ref": _view(unauth_ref),
                "logged_out_ref": _view(logged_out_ref),
            },
        )

    @classmethod
    def from_mfa_bypass(
        cls,
        *,
        mfa_enrolled_account: bool = False,
        factor1_only_presented: bool = False,
        post_mfa_resource_certified: bool = False,
        private_discriminator: str | None = None,
        factor1_view: Any = None,
        owner_view: Any = None,
        pre_mfa_ref: Any = None,
        logged_out_ref: Any = None,
        logged_out_markers: Any = (),
        logged_out_statuses: Any = (),
        bug_class: str = "mfa_bypass",
    ) -> "FindingContext":
        """The retained MFA-bypass record for the MFA-bypass oracle (OracleKind.MFA_BYPASS, CWE-287/CWE-308). It
        carries the RAW bytes the oracle re-runs its FAIL-CLOSED + PRIVATE-READ adjudication over — never a
        pre-computed authenticated bool.

        The three operator attestation booleans form the HARD certification gate (each must be strict ``True``):
        ``mfa_enrolled_account`` (the account has a second factor ENROLLED), ``factor1_only_presented`` (VIGIL's
        session completed ONLY factor-1 — no OTP/WebAuthn/push), and ``post_mfa_resource_certified`` (the read
        resource/datum is genuinely gated BEHIND factor-2 — the lock that closes the killer FP of an
        intentionally factor-1 page). ``private_discriminator`` (D) is the operator's genuine victim-PRIVATE
        post-MFA-gated datum — the achieved-state proof. ``factor1_view`` is ``{status, body}`` of the post-MFA
        resource read carrying ONLY the factor-1 session; ``owner_view`` is the SAME resource read by the fully
        post-MFA-authenticated owner (the POSITIVE reference — D must be PRESENT); ``pre_mfa_ref`` is the SAME
        resource read by an OTHER not-post-MFA identity (the DECISIVE SAME-SHAPE negative reference — a
        substantive 2xx from which D must be ABSENT); ``logged_out_ref`` is the SAME resource with NO session
        (the no-session gating baseline); ``logged_out_markers`` / ``logged_out_statuses`` are the operator's
        decisive not-authenticated signals. The oracle fires ONLY under the complete attestation AND when D is
        PRESENT in the factor-1-only read AND in the post-MFA owner's read yet PROVABLY ABSENT from the
        SUBSTANTIVE SAME-SHAPE other-identity reference and a valid no-session baseline. An incomplete
        attestation, no/invalid/reflected D, a missing positive or same-shape negative reference, D present in a
        negative reference, or an undecidable differential are LEAD / clean / inconclusive — never a FACT."""
        def _view(v: Any) -> "dict | None":
            if not isinstance(v, Mapping):
                return None
            return {"status": v.get("status"), "body": _coerce_text(v.get("body"))}

        def _strs(seq: Any) -> "list[str]":
            if isinstance(seq, (list, tuple, set, frozenset)):
                return [_coerce_text(x) for x in seq]
            return []

        def _ints(seq: Any) -> "list[int]":
            out: list[int] = []
            if isinstance(seq, (list, tuple, set, frozenset)):
                for x in seq:
                    try:
                        out.append(int(x))
                    except (TypeError, ValueError):
                        continue
            return out

        return cls(
            bug_class=bug_class,
            mfa_bypass={
                "operator_attestation": {
                    "mfa_enrolled_account": mfa_enrolled_account is True,
                    "factor1_only_presented": factor1_only_presented is True,
                    "post_mfa_resource_certified": post_mfa_resource_certified is True,
                },
                "private_discriminator": None if private_discriminator is None else _coerce_text(private_discriminator),
                "factor1_view": _view(factor1_view),
                "owner_view": _view(owner_view),
                "pre_mfa_ref": _view(pre_mfa_ref),
                "logged_out_ref": _view(logged_out_ref),
                "logged_out_markers": _strs(logged_out_markers),
                "logged_out_statuses": _ints(logged_out_statuses),
            },
        )

    @classmethod
    def from_smuggling_desync(
        cls,
        *,
        canary: str,
        technique: str,
        conflict_second: Any,
        control_second: Any,
        bug_class: str = "request_smuggling",
    ) -> "FindingContext":
        """The retained record for the smuggling-desync oracle (kind DIFFERENTIAL_RESPONSE, via the fresh
        ``smuggling_desync`` ctx key; Wave-4.2, CWE-444). It carries the RAW second-request responses the
        oracle re-runs its UNIQUE-CANARY DIFFERENTIAL over — never a bool, never a latency.

        ``canary`` is the UNIQUE high-entropy per-probe token VIGIL minted and embedded in the smuggled prefix
        of the FIRST (conflict) request; ``technique`` names the framing conflict (CL.TE / TE.CL / an
        obfuscated TE). ``conflict_second`` is ``{channel, status, reason, body}`` of VIGIL's OWN SECOND
        request read on the connection whose first request carried the conflict; ``control_second`` is the
        SAME second request read on a SECOND VIGIL-owned connection whose first request was the same bytes but
        WELL-FORMED (no conflict). The oracle fires ONLY when the canary is echoed in the conflict second
        response and absent from the control second response — the achieved desync, never timing, never a
        bare mangled-method status. NO victim is poisoned (both requests are VIGIL's own on its own socket)."""
        def _leg(v: Any) -> "dict":
            if not isinstance(v, Mapping):
                return {"channel": False, "status": None, "reason": "", "body": ""}
            status = v.get("status")
            try:
                status = int(status) if status is not None else None
            except (TypeError, ValueError):
                status = None
            return {"channel": bool(v.get("channel", False)), "status": status,
                    "reason": _coerce_text(v.get("reason")), "body": _coerce_text(v.get("body"))}

        return cls(
            bug_class=bug_class,
            smuggling_desync={
                "canary": _coerce_text(canary),
                "technique": _coerce_text(technique),
                "conflict": _leg(conflict_second),
                "control": _leg(control_second),
            },
        )

    @classmethod
    def from_password_reset_reuse(
        cls,
        *,
        reset_token: str,
        private_discriminator: str | None = None,
        authorized_view: Any = None,
        owner_view: Any = None,
        unauth_ref: Any = None,
        logged_out_ref: Any = None,
        logged_out_markers: Any = (),
        logged_out_statuses: Any = (),
        consumed_secret: str | None = None,
        replay_secret: str | None = None,
        authorized_secret: str | None = None,
        bug_class: str = "password_reset_reuse",
    ) -> "FindingContext":
        """The retained token-REUSE / NON-EXPIRY record for the password-reset oracle
        (OracleKind.PASSWORD_RESET_INVARIANT, CWE-640/613). It carries the RAW bytes the oracle re-runs its
        PRIVATE-READ REDUCTION over — never a pre-computed success bool, never a bare 200.

        The runner CONSUMES a reset token (setting the account password to a first unique VIGIL secret P1
        =``consumed_secret``), then REPLAYS the same token to set a SECOND, unique VIGIL secret P2
        =``replay_secret``, then AUTHENTICATES with P2 (=``authorized_secret``, the credential the
        ``authorized_view`` read was reached with) and reads the account. ``authorized_view`` is ``{status,
        body}`` of that replay-authenticated read; ``owner_view`` is the SAME URL read authoritatively as the
        owner (the POSITIVE reference — D must be PRESENT); ``unauth_ref`` is the SAME URL read by an OTHER
        unauthorized identity (the DECISIVE SAME-SHAPE negative reference — a substantive 2xx from which D must be
        ABSENT); ``logged_out_ref`` is the SAME URL with NO session (the no-session baseline).
        ``private_discriminator`` (D) is the operator's genuine victim-PRIVATE datum. The oracle first BINDS the
        achieved read to P2 (P2 present + non-trivial + DISTINCT from P1, and ``authorized_secret`` == P2, D not
        an echo of P2), then fires ONLY when D is PRESENT in the replay-authenticated read AND the owner's read
        yet PROVABLY ABSENT from the same-shape unauthorized reference and the no-session baseline (the REPLAY
        GENUINELY changed the credential). A single-use token that correctly expires leaves P2 unset — the
        replay-authenticated read never reaches D ⇒ channel-confirmed CLEAN. A failed P2-binding (wrong-secret
        read, P2==P1, P2 absent), no/invalid/reflected D or a missing/failing reference ⇒ LEAD (never a FACT)."""
        def _view(v: Any) -> "dict | None":
            if not isinstance(v, Mapping):
                return None
            return {"status": v.get("status"), "body": _coerce_text(v.get("body"))}

        def _strs(seq: Any) -> "list[str]":
            if isinstance(seq, (list, tuple, set, frozenset)):
                return [_coerce_text(x) for x in seq]
            return []

        def _ints(seq: Any) -> "list[int]":
            out: list[int] = []
            if isinstance(seq, (list, tuple, set, frozenset)):
                for x in seq:
                    try:
                        out.append(int(x))
                    except (TypeError, ValueError):
                        continue
            return out

        return cls(
            bug_class=bug_class,
            password_reset_invariant={
                "mode": "token_reuse",
                "reset_token": _coerce_text(reset_token),
                "private_discriminator": None if private_discriminator is None else _coerce_text(private_discriminator),
                "authorized_view": _view(authorized_view),
                "owner_view": _view(owner_view),
                "unauth_ref": _view(unauth_ref),
                "logged_out_ref": _view(logged_out_ref),
                "logged_out_markers": _strs(logged_out_markers),
                "logged_out_statuses": _ints(logged_out_statuses),
                # P2-binding fields (mirror session fixation's sentinel-binding): the consumed P1, the replay-set
                # P2, and the credential the authorized read was actually reached with — so the oracle can prove
                # the achieved state is attributable to the REPLAY, never the first consume / a leftover session.
                "consumed_secret": None if consumed_secret is None else _coerce_text(consumed_secret),
                "replay_secret": None if replay_secret is None else _coerce_text(replay_secret),
                "authorized_secret": None if authorized_secret is None else _coerce_text(authorized_secret),
            },
        )

    @classmethod
    def from_password_reset_collision(
        cls,
        *,
        samples: Any = None,
        tokens: Any = None,
        bug_class: str = "password_reset_collision",
    ) -> "FindingContext":
        """The retained deterministic-COLLISION record for the password-reset oracle
        (OracleKind.PASSWORD_RESET_INVARIANT, CWE-640/330). ``samples`` are the runner's captures from INDEPENDENT
        reset requests, in request order, each a ``{token, account}`` mapping (the account LABEL the token was
        issued for — carried so a byte-identical repeat across labels can be surfaced as a stronger LEAD). A flat
        ``tokens`` list is also accepted (labels UNKNOWN). The oracle fires ONLY on a genuinely-EXPLOITABLE
        PREDICTABLE COUNTER: >=3 tokens forming an EXACT arithmetic progression. A BYTE-IDENTICAL token — same
        account LABEL or across DIFFERENT account LABELS — is DELIBERATELY NOT a FACT: account labels are never
        proven to be distinct PRINCIPALS (a benign identifier-NORMALIZING generator maps 'alice'/'Alice' to ONE
        principal; a deterministic-but-secure generator repeats for one user) ⇒ LEAD; genuine cross-principal
        exploitation is minted only by ``password_reset_cross_user`` (the private-read differential). A set of
        distinct tokens ⇒ channel-confirmed CLEAN; too few / too-short samples ⇒ LEAD. ENTROPY is never scored —
        a distinct-but-low-entropy token stays a probabilistic LEAD, never a FACT here."""
        norm: list[dict[str, str]] = []
        if isinstance(samples, (list, tuple)):
            for item in samples:
                if isinstance(item, Mapping):
                    tok = _coerce_text(item.get("token"))
                    acct = _coerce_text(item.get("account"))
                else:
                    tok, acct = _coerce_text(item), ""
                norm.append({"token": tok, "account": acct})
        elif isinstance(tokens, (list, tuple)):
            norm = [{"token": _coerce_text(x), "account": ""} for x in tokens]
        return cls(
            bug_class=bug_class,
            password_reset_invariant={"mode": "token_collision", "samples": norm},
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
        if self.ssi_expected is not None and self.ssi_observed is not None:
            # Wave-4.1 SSI: DISTINCT ctx keys route the frozen EVALUATION kind to ssi_evaluation_oracle.
            ctx["ssi_raw"] = self.ssi_raw or ""
            ctx["ssi_expected"] = self.ssi_expected
            ctx["ssi_observed"] = self.ssi_observed
            if self.ssi_control is not None:
                ctx["ssi_control"] = self.ssi_control
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
        if self.oob_token is not None:
            ctx["oob_token"] = self.oob_token   # VF-2a: retained so offline re-verify can check the token
        if self.oob_issued_at is not None:
            ctx["oob_issued_at"] = self.oob_issued_at   # retained TTL window (deterministic offline re-verify)
        if self.oob_expires_at is not None:
            ctx["oob_expires_at"] = self.oob_expires_at
        if self.oob_skew is not None:
            ctx["oob_skew"] = self.oob_skew
        if self.handshake is not None:
            ctx["handshake"] = self.handshake
        if self.anon_get is not None:
            ctx["anon_get"] = self.anon_get
        if self.tls is not None:
            ctx["tls"] = self.tls
        if self.crypto_artifact is not None:
            ctx["crypto_artifact"] = self.crypto_artifact
        if self.version_advisory is not None:
            ctx["version_advisory"] = self.version_advisory
        if self.policy is not None:
            ctx["policy"] = self.policy
        if self.k8s_control is not None:
            ctx["k8s_control"] = self.k8s_control
        if self.k8s_workload_control is not None:
            ctx["k8s_workload_control"] = self.k8s_workload_control
        if self.k8s_rbac_grant_control is not None:
            ctx["k8s_rbac_grant_control"] = self.k8s_rbac_grant_control
        if self.cloud_control is not None:
            ctx["cloud_control"] = self.cloud_control
        if self.mesh_control is not None:
            ctx["mesh_control"] = self.mesh_control
        if self.cicd_control is not None:
            ctx["cicd_control"] = self.cicd_control
        if self.mobile_control is not None:
            ctx["mobile_control"] = self.mobile_control
        if self.email_auth_control is not None:
            ctx["email_auth_control"] = self.email_auth_control
        if self.identity_control is not None:
            ctx["identity_control"] = self.identity_control
        if self.clickjacking_control is not None:
            ctx["clickjacking_control"] = self.clickjacking_control
        if self.csrf_control is not None:
            ctx["csrf_control"] = self.csrf_control
        if self.postmessage_control is not None:
            ctx["postmessage_control"] = self.postmessage_control
        if self.proto_pollution is not None:
            ctx["proto_pollution"] = self.proto_pollution
        if self.csp_control is not None:
            ctx["csp_control"] = self.csp_control
        if self.csp_block_control is not None:
            ctx["csp_block_control"] = self.csp_block_control
        if self.csrf_achieved is not None:
            ctx["csrf_achieved"] = self.csrf_achieved
        if self.session_fixation is not None:
            ctx["session_fixation"] = self.session_fixation
        if self.workflow_abuse is not None:
            ctx["workflow_abuse"] = self.workflow_abuse
        if self.mfa_bypass is not None:
            ctx["mfa_bypass"] = self.mfa_bypass
        if self.smuggling_desync is not None:
            ctx["smuggling_desync"] = self.smuggling_desync
        if self.password_reset_invariant is not None:
            ctx["password_reset_invariant"] = self.password_reset_invariant
        if self.jwt_token is not None:
            ctx["jwt_token"] = self.jwt_token
            if self.jwt_candidate_keys is not None:
                ctx["jwt_candidate_keys"] = self.jwt_candidate_keys
        if self.saml_xml is not None:
            ctx["saml_xml"] = self.saml_xml
            if self.saml_candidate_certs is not None:
                ctx["saml_candidate_certs"] = self.saml_candidate_certs
        if self.imds_capture is not None:
            ctx["imds_capture"] = self.imds_capture
        if self.secret_capture is not None:
            ctx["secret_capture"] = self.secret_capture
        if self.gcp_impersonation_capture is not None:
            ctx["gcp_impersonation_capture"] = self.gcp_impersonation_capture
        if self.iam_escalation_capture is not None:
            ctx["iam_escalation_capture"] = self.iam_escalation_capture
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
