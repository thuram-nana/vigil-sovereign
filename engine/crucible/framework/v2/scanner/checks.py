"""
scanner.checks — the active-check library.

A check is the unit Burp's scanner is built from: for a bug class, it knows how
to *probe* one insertion point (what payloads to place, how many requests to
send) and how to shape the observed responses into a :class:`verify.FindingContext`
that the deterministic oracle layer adjudicates. The oracle — never the LLM,
never a heuristic — decides confirmation, so every finding this library produces
is signal-anchored (the precision property Burp's Tentative/Firm heuristics
lack).

Checks are pure w.r.t. the graph and deterministic given a `send`: the marker a
reflection check plants is derived from the insertion point's id, so a run is
replayable. A check emits a FindingContext or None (insufficient evidence); it
makes NO confirmation decision itself.

Boundary: checks place payloads only into the insertion point the engine hands
them, and only issue requests through the engine's injected `send` — which in
production is the scope/charter/kill-switch/egress-gated executor. Payloads here
are verification probes (differential terms, unique canary markers, traversal
tokens), not weaponized exploits.
"""

from __future__ import annotations

import math
import re
import time
from html.parser import HTMLParser
from dataclasses import dataclass
from typing import Callable, ClassVar, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

from ..verify.adapter import FindingContext
from ..verify.oob import OOBReceiver
from . import js_lex as _js_lex
from .insertion import HttpRequest, InsertionPoint, RequestTemplate

# A `send` turns a rendered request into an observed response dict
# {status, body, latency_ms?}. Injected by the engine so checks never touch the
# network directly (and tests drive a localhost target).
Send = Callable[[HttpRequest], dict]


@runtime_checkable
class Check(Protocol):
    """Probes one insertion point and returns oracle-ready evidence, or None."""

    id: str
    bug_class: str

    def probe(
        self, template: RequestTemplate, point: InsertionPoint, send: Send
    ) -> FindingContext | None: ...


@dataclass(frozen=True)
class DifferentialCheck:
    """Boolean/logic differential: send a benign value and a probe value into the
    same point and let the differential oracle judge whether the responses
    diverge (boolean-blind SQLi/NoSQLi, auth-logic, filter bypass).

    The point's own base value is NOT used as the baseline — a fresh benign value
    is, so the comparison is payload-vs-payload and the base is left untouched as
    a control the engine can re-check."""

    id: str
    bug_class: str
    benign: str
    probe_payload: str

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        baseline = send(template.render(point, self.benign))
        mutated = send(template.render(point, self.probe_payload))
        return FindingContext.from_http_responses(
            baseline, mutated, bug_class=self.bug_class,
            discriminator={"dimensions": ["status", "length", "lexical"]},
        )


@dataclass(frozen=True)
class BooleanInferenceCheck:
    """Boolean-blind via a sequential probability ratio test (SPRT).

    Each round sends a TRUE-condition clause and the FALSE-condition clause
    twice (the second FALSE is a dynamic-page control). It runs the SPRT online
    to stop as soon as the evidence is decisive — few rounds for a clear signal,
    a bounded ``n_max`` otherwise — then hands every collected round to the
    boolean-inference oracle, which recomputes the same decision deterministically.
    Robust to flaky/dynamic backends that make a single true/false comparison
    false-positive."""

    id: str
    bug_class: str
    true_clause: str
    false_clause: str
    n_max: int = 24
    alpha: float = 0.05
    beta: float = 0.05
    p1: float = 0.9
    p0: float = 0.1

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        from ..verify.oracles import differential_response_oracle  # local: avoid import cycle at module load

        upper = math.log((1.0 - self.beta) / self.alpha)
        lower = math.log(self.beta / (1.0 - self.alpha))
        llr = 0.0
        trues: list[dict] = []
        false_as: list[dict] = []
        false_bs: list[dict] = []
        for _ in range(self.n_max):
            t = _as_dict(send(template.render(point, self.true_clause)))
            a = _as_dict(send(template.render(point, self.false_clause)))
            b = _as_dict(send(template.render(point, self.false_clause)))
            trues.append(t)
            false_as.append(a)
            false_bs.append(b)
            across = differential_response_oracle(a, t).fired
            within_same = not differential_response_oracle(a, b).fired
            signal = across and within_same
            llr += math.log(self.p1 / self.p0) if signal else math.log((1.0 - self.p1) / (1.0 - self.p0))
            if llr >= upper or llr <= lower:
                break  # SPRT reached a decision — stop early

        return FindingContext.from_boolean_probes(
            trues, false_as, false_bs, bug_class=self.bug_class,
        )


def _as_dict(resp: object) -> dict:
    if isinstance(resp, dict):
        return resp
    return {"body": str(resp)}


@dataclass(frozen=True)
class TimingCheck:
    """Statistical time-based blind (SQLi / command injection).

    Measures ``samples`` paired latencies — a benign value vs a delay-injecting
    payload — and hands them to the timing oracle, which decides via a rank-sum
    test + effect-size floor + optional dose-response (never a fixed threshold).
    Benign and probe requests are interleaved so latency drift biases both
    equally. Expensive (``2*samples`` requests per point), so it is opt-in and
    best spent on bandit-prioritised candidates."""

    id: str
    bug_class: str
    benign: str
    sleep_payload: str
    injected_ms: float
    samples: int = 15
    # optional second, larger delay for a dose-response corroboration
    dose_payload: str | None = None
    dose_ms: float | None = None

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        base: list[float] = []
        treat: list[float] = []
        dose_samples: list[float] = []
        for _ in range(self.samples):
            base.append(self._time(send, template, point, self.benign))
            treat.append(self._time(send, template, point, self.sleep_payload))
            if self.dose_payload is not None:
                dose_samples.append(self._time(send, template, point, self.dose_payload))

        dose = None
        if self.dose_payload is not None and self.dose_ms:
            dose = {
                "low_ms": self.injected_ms, "low_samples": treat,
                "high_ms": self.dose_ms, "high_samples": dose_samples,
            }
        return FindingContext.from_timing_samples(
            base, treat, bug_class=self.bug_class,
            injected_ms=self.injected_ms, dose=dose,
        )

    @staticmethod
    def _time(send: Send, template: RequestTemplate, point: InsertionPoint, value: str) -> float:
        """Wall-time one request in milliseconds. Times the ``send`` itself (the
        I/O), so it works whether or not the send reports its own latency; a
        blind payload that makes the target error is still timed."""
        t0 = time.monotonic()
        try:
            send(template.render(point, value))
        except Exception:
            pass
        return (time.monotonic() - t0) * 1000.0


@dataclass(frozen=True)
class MarkerReflectionCheck:
    """Side-effect reflection: place a unique canary (wrapped by `payload_template`)
    and confirm via the side-effect oracle iff the *raw* canary reaches the
    response sink (reflected/stored XSS, error-based/echoed injection,
    template/EL reflection, path-traversal content markers).

    The canary is derived from the point id so it is unique per position and the
    run is deterministic. `payload_template` must contain `{marker}`."""

    id: str
    bug_class: str
    payload_template: str = "{marker}"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        marker = f"crucible{_slugify(point.id)}mark"
        payload = self.payload_template.format(marker=marker)
        resp = send(template.render(point, payload))
        body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
        return FindingContext.from_side_effect(marker, body, bug_class=self.bug_class)

    def adapt(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        """WAF-adaptive fallback (opt-in, engine-driven): when the canonical payload
        is filtered/blocked, synthesize a form that both gets past the filter AND
        reflects the canary into an EXECUTABLE context, then hand that response to the
        same side-effect oracle. The sink proxy is the executable-reflection oracle
        itself, so a bypass that only reflects inertly is not treated as success — the
        precision anchor is unchanged."""
        from .fitness import reflection_proximity
        from .waf_evasion import adaptive_bypass
        from ..verify.oracles import reflection_context_oracle

        marker = f"crucible{_slugify(point.id)}mark"
        payload = self.payload_template.format(marker=marker)

        def send_form(form: str) -> dict:
            return send(template.render(point, form))

        def sink_present(resp: dict) -> bool:
            body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
            return reflection_context_oracle(marker, body).fired

        def proximity(resp: dict) -> float:
            body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
            return reflection_proximity(marker, body)

        res = adaptive_bypass(payload, send_form, sink_present, proximity=proximity)
        if res is None:
            return None
        body = res.response.get("body", "") if isinstance(res.response, dict) else str(res.response)
        return FindingContext.from_side_effect(marker, body, bug_class=self.bug_class)


@dataclass(frozen=True)
class OOBCheck:
    """Out-of-band (blind) check: mint a unique correlation token, embed its
    loopback callback URL into a payload, inject it, and poll the receiver for
    an inbound interaction. The proof is the *callback the target makes*, not
    anything in the response — so this reaches the blind classes (SSRF, blind
    XXE, OOB SQLi, deserialization/JNDI gadgets) that leave no visible signal.

    ``payload_template`` must contain ``{callback}``. Polling is deadline-bounded
    with a small interval so a DEFERRED interaction (a callback that lands after
    the injecting request returns) is still caught — the case a single one-shot
    poll misses. Distinguished from response-based checks by ``wants_oob``; the
    engine hands it the receiver."""

    id: str
    bug_class: str
    payload_template: str = "{callback}"
    poll_deadline: float = 2.0
    poll_interval: float = 0.05

    wants_oob: ClassVar[bool] = True

    ttl: float = 300.0

    def probe(
        self, template: RequestTemplate, point: InsertionPoint, send: Send, oob: OOBReceiver
    ) -> FindingContext | None:
        token, callback_url = oob.register_token()
        # VF-2b: when the receiver signs receipts (a collector keypair is configured), a receipt-bearing hit
        # REQUIRES an authority-bound TTL window, so record the mint anchor. When there is NO collector key
        # (VF-2a token-only), omit it so the windowless path stays byte-identical.
        issued_at = time.time() if getattr(oob, "collector_pubkey", None) else None
        payload = self.payload_template.format(callback=callback_url)
        try:
            send(template.render(point, payload))
        except Exception:
            # A blind payload may make the target error its own response; the
            # callback — not the response — is the signal, so keep waiting for it.
            pass
        deadline = time.monotonic() + self.poll_deadline
        hits = oob.poll(token)
        while not hits and time.monotonic() < deadline:
            time.sleep(self.poll_interval)
            hits = oob.poll(token)
        # VF-2a: retain the REGISTERED per-finding token so the oracle fires only for a callback that carried
        # it (live AND on offline re-verify) — a fabricated/unrelated hit no longer confirms. On the VF-2b
        # path, also retain the mint anchor (the TTL DURATION is taken out-of-band from the signed authority).
        return FindingContext.from_oob(
            hits, bug_class=self.bug_class, expected_token=token,
            issued_at=issued_at,
            expires_at=(issued_at + float(self.ttl)) if issued_at is not None else None,
        )


@dataclass(frozen=True)
class DNSOOBCheck:
    """DNS out-of-band (blind) check: the sibling of :class:`OOBCheck` for a target whose outbound HTTP is
    blocked but whose resolver still forwards DNS. Mint a unique token whose callback HOST is
    ``<token>.<base-domain>``, embed it in a payload that triggers a DNS LOOKUP even when HTTP egress is
    filtered, inject it, and poll the AUTHORITATIVE DNS collector (``verify.dns_collector.DNSCollector``)
    for the query the target's resolver forwarded. The proof is the DNS lookup — a strictly weaker but still
    sound claim than a completed HTTP fetch (resolution reached us; a connection need not have completed).

    ``payload_template`` must contain ``{callback}`` (the bare DNS host — NOT a URL with a scheme, though a
    payload may wrap it, e.g. ``http://{callback}/``). ``ttl`` (seconds) mints a TTL window retained on the
    finding context; a lookup observed outside it is refused as EXPIRED/REPLAY on live AND offline re-verify.
    ``oob`` is a ``DNSCollector`` (its ``register_dns_token`` / ``poll`` surface); an ``OOBReceiver`` also
    fits (``register_token`` alias), so the same check runs against either collector."""

    id: str
    bug_class: str
    payload_template: str = "{callback}"
    poll_deadline: float = 2.0
    poll_interval: float = 0.05
    ttl: float = 300.0

    wants_oob: ClassVar[bool] = True

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send, oob) -> "FindingContext | None":
        register = getattr(oob, "register_dns_token", None) or oob.register_token
        token, host = register()
        issued_at = time.time()
        payload = self.payload_template.format(callback=host)
        try:
            send(template.render(point, payload))
        except Exception:
            # A blind payload may make the target error its own response; the DNS lookup — not the
            # response — is the signal, so keep waiting for it.
            pass
        deadline = time.monotonic() + self.poll_deadline
        hits = oob.poll(token)
        while not hits and time.monotonic() < deadline:
            time.sleep(self.poll_interval)
            hits = oob.poll(token)
        # Retain the registered token AND the mint TTL window so the oracle fires only for a token-matched
        # lookup observed inside the window (live AND on deterministic offline re-verify).
        return FindingContext.from_oob(
            hits, bug_class=self.bug_class, expected_token=token,
            issued_at=issued_at, expires_at=issued_at + float(self.ttl),
        )


@runtime_checkable
class RequestCheck(Protocol):
    """A check that operates on the WHOLE request/response — adding a header,
    reading a response header — rather than fuzzing one insertion point. The
    engine runs it once per request. Returns oracle-ready evidence, or None."""

    id: str
    bug_class: str

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None: ...


@dataclass(frozen=True)
class CorsActiveCheck:
    """Active CORS misconfiguration: send a hostile ``Origin`` and check whether
    the server REFLECTS it back with credentials — the exact combination that lets
    an attacker page read authenticated responses. Confirmed via achieved-state
    only on the dangerous reflection, so a properly-scoped CORS policy does not
    fire. Note: ``Access-Control-Allow-Origin: *`` WITH credentials is deliberately
    NOT confirmed here — browsers refuse ``*``+credentials, so it is not
    credential-readable and would be an over-claim as an exploitable FACT (a passive
    check may still surface it as a lower-severity misconfiguration lead)."""

    id: str = "cors-active"
    bug_class: str = "cors"
    evil_origin: str = "https://crucible-evil-origin.test"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        headers = [(k, v) for k, v in req.headers if k.lower() != "origin"]
        headers.append(("Origin", self.evil_origin))
        resp = send(req.model_copy(update={"headers": headers}))
        if not isinstance(resp, dict):
            return None
        rh = resp.get("headers", []) or []
        acao = next((str(v) for k, v in rh if str(k).lower() == "access-control-allow-origin"), "")
        acac = next((str(v) for k, v in rh if str(k).lower() == "access-control-allow-credentials"), "")
        # The ORACLE decides the exploitable condition over the raw header values:
        # ACAO REFLECTS the hostile origin AND credentials are allowed. A wildcard
        # (`*`) is excluded — browsers do not honour `*`+credentials, so it cannot
        # read authenticated responses. A properly-scoped policy fails the predicate.
        return FindingContext.from_predicate(
            {"acao": acao, "acac": acac, "evil_origin": self.evil_origin},
            {"all": [
                {"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
                {"ieq": [{"var": "acac"}, "true"]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class HostHeaderCheck:
    """Host-header injection: send a hostile ``Host`` and check whether the app
    reflects it into an absolute URL — a redirect ``Location`` or an absolute link
    in the body — which is what poisons password-reset links and web-cache. A
    plain-text echo of the host does not fire; only its use as a URL authority."""

    id: str = "host-header"
    bug_class: str = "host_header_injection"
    evil_host: str = "crucible-evil-host.test"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        headers = [(k, v) for k, v in req.headers if k.lower() != "host"]
        headers.append(("Host", self.evil_host))
        resp = send(req.model_copy(update={"headers": headers}))
        if not isinstance(resp, dict):
            return None
        body = str(resp.get("body", ""))
        rh = resp.get("headers", []) or []
        location = next((str(v) for k, v in rh if str(k).lower() == "location"), "")
        # The oracle checks whether the hostile Host became the AUTHORITY of a URL the
        # app EMITS (a redirect Location, an href/src/action link/resource/form, or a
        # meta/JS redirect) — the only forms a victim's browser would actually use. A
        # plain-text ECHO of the reconstructed URL back to the requester does NOT fire
        # (not exploitable), and matching is on the WHOLE authority, so a subdomain
        # reflection like `//evil-host.cdn.example.com` does not collide with the evil
        # host either.
        # As above: on a followed 3xx the body is never rendered, so a Host-derived link inside it is not
        # something a victim can use. The Location disjunct still stands on its own.
        followed = bool(location) and int(resp.get("status", 0) or 0) in (301, 302, 303, 307, 308)
        body_available = bool(resp.get("body_semantically_available", True))
        return FindingContext.from_predicate(
            {"location_host": _host(location), "evil_host": self.evil_host,
             "body": body, "followed_redirect": followed, "body_available": body_available,
             "emitted_url_hosts": _emitted_url_hosts(body)},
            {"any": [
                {"eq": [{"var": "location_host"}, {"var": "evil_host"}]},
                {"all": [
                    {"eq": [{"var": "body_available"}, True]},
                    {"not": {"eq": [{"var": "followed_redirect"}, True]}},
                    {"in": [{"var": "evil_host"}, {"var": "emitted_url_hosts"}]},
                ]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class OpenRedirectCheck:
    """Open redirection: inject a canary absolute URL into a redirect parameter
    and confirm via achieved-state ONLY when the response actually redirects to
    the canary's host — a 30x Location to the canary host, or a meta-refresh /
    JS-location redirect that resolves to it. A redirect that stays on the app's
    own host (the app merely echoing the param inside its own URL) does NOT fire,
    so this does not false-positive on reflected-but-safe redirect params.

    Runs on any point (the caller scopes it via targeting to redirect-ish params).
    Needs response headers from ``send``; a follow-redirects=False client (the
    production executor) exposes the Location header."""

    id: str = "open-redirect"
    bug_class: str = "open_redirect"
    canary: str = "https://crucible-redirect-canary.test/pwned"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        resp = send(template.render(point, self.canary))
        if not isinstance(resp, dict):
            return None
        status = int(resp.get("status", 0))
        headers = resp.get("headers", []) or []
        location = next((str(v) for k, v in headers if str(k).lower() == "location"), "")
        body = str(resp.get("body", ""))

        # The oracle decides redirection to the canary host over the raw status,
        # Location, and the body's ACTUAL navigation targets: a 30x Location to the
        # canary host, OR a meta-refresh / JS-location sink whose target host IS the
        # canary host. Reflection on the app's own host — or the canary merely echoed
        # somewhere in the body next to an unrelated <meta http-equiv=...> — fails the
        # predicate (no false positive on echoed-but-safe params).
        # A 3xx that carries a Location is FOLLOWED by the browser, so its body is never rendered: any
        # navigation the body describes cannot happen, and counting it would be a false FACT.
        followed = bool(location) and status in (301, 302, 303, 307, 308)
        # A body VIGIL could not decode (unsupported Content-Encoding, undeclared non-UTF-8 charset, a
        # truncated response) is NOT evidence: the body disjunct must not fire over it, and a non-firing
        # over it is INCONCLUSIVE for the runner, never CLEAN. Captures without the flag are treated as
        # available so the engine's own plain-text sends behave exactly as before.
        body_available = bool(resp.get("body_semantically_available", True))
        return FindingContext.from_predicate(
            {"status": status, "location_host": _host(location),
             "canary_host": _host(self.canary), "body": body,
             "followed_redirect": followed, "body_available": body_available,
             "markup_redirect_hosts": _markup_redirect_hosts(body)},
            {"any": [
                {"all": [
                    {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                    {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},
                ]},
                {"all": [
                    {"eq": [{"var": "body_available"}, True]},
                    {"not": {"eq": [{"var": "followed_redirect"}, True]}},
                    {"min_len": [{"var": "canary_host"}, 1]},
                    {"in": [{"var": "canary_host"}, {"var": "markup_redirect_hosts"}]},
                ]},
            ]},
            bug_class=self.bug_class)


def _graphql_schema_type_count(body: str) -> int:
    """Number of types in a GraphQL introspection RESPONSE (``data.__schema.types``), or 0 when the body is
    not a well-formed introspection response. VIGIL sends its OWN introspection query; this counts what came
    back. Total on untrusted input — a non-JSON body, a GraphQL ``errors`` response ("introspection is
    disabled"), or a non-GraphQL page all count 0, so the predicate fires ONLY on a real returned schema."""
    import json
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return 0
    if not isinstance(obj, dict):
        return 0
    data = obj.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    types = schema.get("types") if isinstance(schema, dict) else None
    return len(types) if isinstance(types, list) else 0


@dataclass(frozen=True)
class GraphqlIntrospectionCheck:
    """GraphQL introspection exposure: send VIGIL's OWN minimal introspection query and confirm via
    achieved-state ONLY when the endpoint returns a WELL-FORMED introspection schema
    (``data.__schema.types`` is a non-empty array). A 400/403, a GraphQL ``errors`` response
    ("introspection is disabled"), or any non-GraphQL page fails the predicate — so this does NOT fire on the
    mere presence of a ``/graphql`` path, and never on a tool's say-so: the schema is read from VIGIL's own
    live capture. A body VIGIL could not decode is NOT evidence (the predicate is suppressed), so a
    non-firing over an unreadable body is INCONCLUSIVE for the runner, never CLEAN.

    Request-level (no insertion point): it POSTs the query to the endpoint URL as ``application/json``."""

    id: str = "graphql-introspection"
    bug_class: str = "graphql_introspection"
    query: str = '{"query":"query IntrospectionQuery { __schema { types { name } } }"}'

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        headers = [(k, v) for k, v in req.headers if k.lower() != "content-type"]
        headers.append(("Content-Type", "application/json"))
        resp = send(req.model_copy(update={"method": "POST", "headers": headers, "body": self.query}))
        if not isinstance(resp, dict):
            return None
        body = str(resp.get("body", ""))
        # A body VIGIL could not decode (unsupported encoding / undeclared charset / truncated) is not
        # evidence: the count disjunct must not fire over it, and a non-firing is INCONCLUSIVE not CLEAN.
        body_available = bool(resp.get("body_semantically_available", True))
        return FindingContext.from_predicate(
            {"introspection_type_count": _graphql_schema_type_count(body), "body_available": body_available},
            {"all": [
                {"eq": [{"var": "body_available"}, True]},
                {"gt": [{"var": "introspection_type_count"}, 0]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class IdorCheck:
    """Broken-object-level authorization (IDOR / BOLA / BFLA) via a two-identity read.

    Confirmation is achieved-state, not reflection: acting as the attacker, it
    requests an object owned by a DIFFERENT identity (``victim_ref``) and checks
    whether the response actually reveals that identity's PRIVATE content — the
    ground truth being what the victim's own session (``victim_send``) sees for
    the same reference.

    SOUNDNESS (this is why bola/idor were once reverted as UNSOUND): a naive
    ``contains(attacker_body, victim_body)`` over the WHOLE body FALSE-POSITIVES on
    shared boilerplate — two identities render the same shell/nav/footer, so the
    victim's page is trivially a substring of the attacker's. Even a victim-UNIQUE
    discriminator (``victim_discriminator``) is not enough ON ITS OWN: the operator
    can HONESTLY BUT WRONGLY believe a footer/banner/tenant string is victim-unique
    when it is really global boilerplate present in EVERY record — including the
    attacker's own. That mistake reconstructs the exact reverted false positive.
    So a FACT here requires BOTH the discriminator AND a MANDATORY negative control
    (``control_ref``, an attacker-OWNED reference): the marker must be ABSENT from
    the attacker's own legitimate object, which is what actually PROVES the marker
    is victim-specific rather than a global string. The oracle fires ONLY when:

      * the attacker got 200, AND
      * the discriminator genuinely IS in the victim's AUTHORITATIVE body (proving
        the operator handed a real per-identity marker, not a typo), AND
      * the attacker's cross-read REACHED that same discriminator (the achieved
        unauthorized read), AND
      * the discriminator is ABSENT from the attacker's OWN object (``control_ref``)
        — the differential that proves the marker is victim-SPECIFIC, not global
        boilerplate the operator mistook for unique.

    Without a discriminator OR without ``control_ref`` the check CANNOT fire
    soundly, so it returns None (the class stays a rigorous LEAD, never a false
    CLEAN and never a false FACT). 'Victim-unique' is thus ENFORCED by the control
    differential, never accepted as a bare operator assertion. Runs only on the
    object-reference point (``ref_param``); other points return None. ``victim_send``
    is a send authenticated as the victim (a second AuthSession / the ceremony's
    second identity riding the same gated executor)."""

    id: str
    ref_param: str
    victim_ref: str
    victim_send: Send
    bug_class: str = "idor"
    # The per-identity marker that ONLY the victim's authoritative record contains. Empty ⇒ the sound
    # check cannot fire (fail-closed to a non-firing LEAD, never the boilerplate false positive).
    victim_discriminator: str = ""
    # MANDATORY attacker-owned reference for the near-zero-FP negative control: the discriminator MUST be
    # absent when the attacker reads their OWN object, proving the marker is victim-specific not global.
    # Empty ⇒ the FACT cannot be minted (probe returns None ⇒ a rigorous LEAD), because 'victim-unique'
    # is only PROVEN by the control differential, never by the operator's assertion.
    control_ref: str = ""

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        if point.name != self.ref_param:
            return None
        disc = (self.victim_discriminator or "").strip()
        if not disc:
            # No victim-unique discriminator ⇒ the only sound predicate is unavailable. Do NOT fall back to
            # the whole-body containment (the reverted false positive). Emit nothing: a rigorous LEAD.
            return None
        control_ref = (self.control_ref or "").strip()
        if not control_ref:
            # The negative control is MANDATORY: without an attacker-owned reference we cannot PROVE the
            # discriminator is victim-unique rather than global boilerplate (the exact shared-boilerplate FP
            # that caused the prior IDOR/BOLA revert). Fail closed to a non-firing LEAD — never mint here.
            return None
        victim = self.victim_send(template.render(point, self.victim_ref))
        attacker = send(template.render(point, self.victim_ref))
        control = send(template.render(point, control_ref))
        victim_body = str(victim.get("body", "")) if isinstance(victim, dict) else str(victim)
        attacker_body = str(attacker.get("body", "")) if isinstance(attacker, dict) else str(attacker)
        control_body = str(control.get("body", "")) if isinstance(control, dict) else str(control)
        attacker_status = int(attacker.get("status", 0)) if isinstance(attacker, dict) else 0

        evidence: dict[str, object] = {
            "attacker_status": attacker_status, "victim_body": victim_body,
            "attacker_body": attacker_body, "attacker_own_body": control_body, "discriminator": disc,
        }
        # The control differential is retained in the oracle_context as three EXPLICIT clauses (not a bare
        # bool), so offline ``verify`` re-checks presence-in-victim AND presence-in-attacker-cross-read AND
        # absence-in-control over the retained bodies — the pure achieved-state predicate re-fires exactly.
        clauses: list[dict] = [
            {"eq": [{"var": "attacker_status"}, 200]},
            {"min_len": [{"var": "discriminator"}, 6]},
            # the discriminator genuinely identifies the victim's AUTHORITATIVE record (operator input is real)
            {"contains": [{"var": "victim_body"}, {"var": "discriminator"}]},
            # the attacker's cross-read REACHED the victim-unique marker (the achieved unauthorized read)
            {"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]},
            # MANDATORY negative control: the marker must NOT appear when the attacker reads their OWN object —
            # this refutes a globally-present string the operator wrongly believed was victim-unique.
            {"not": {"contains": [{"var": "attacker_own_body"}, {"var": "discriminator"}]}},
        ]
        return FindingContext.from_predicate(evidence, {"all": clauses}, bug_class=self.bug_class)


@dataclass(frozen=True)
class EvaluationCheck:
    """Server-side template / expression-language injection via EVALUATION.

    Sends a benign control and an arithmetic probe expression (e.g. Jinja2
    ``{{31337*31337}}``), captures both responses, and hands them to the
    evaluation oracle — which confirms SSTI/EL only when the server COMPUTED the
    expression (the result present, the raw template text absent), never on mere
    reflection. ``probe_expr`` and ``expected_result`` are paired per template
    engine; use a distinctive product so the result cannot coincidentally appear."""

    id: str
    bug_class: str
    probe_expr: str
    expected_result: str
    benign: str = "crucible-benign-eval"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        control = send(template.render(point, self.benign))
        probe = send(template.render(point, self.probe_expr))
        control_body = control.get("body", "") if isinstance(control, dict) else str(control)
        probe_body = probe.get("body", "") if isinstance(probe, dict) else str(probe)
        return FindingContext.from_evaluation(
            self.probe_expr, self.expected_result, probe_body,
            control_body=control_body, bug_class=self.bug_class,
        )


@dataclass(frozen=True)
class ErrorSignatureCheck:
    """Error-based injection (SQL/NoSQL/LDAP/XPath) via a provoked backend error.

    Sends a benign control and a syntax-breaking payload (e.g. a lone quote), and
    hands both responses to the error-signature oracle — which confirms only when
    a distinctive datastore/parser error appears in the probe response but NOT in
    the benign control, so a page that always shows a stack trace cannot be
    mistaken for injection."""

    id: str
    bug_class: str
    probe_payload: str = "'\"`)"
    benign: str = "crucible-benign-term"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        control = send(template.render(point, self.benign))
        probe = send(template.render(point, self.probe_payload))
        control_body = control.get("body", "") if isinstance(control, dict) else str(control)
        probe_body = probe.get("body", "") if isinstance(probe, dict) else str(probe)
        return FindingContext.from_error_signature(
            probe_body, control_body=control_body, bug_class=self.bug_class,
        )


@dataclass(frozen=True)
class ContentSignatureCheck:
    """File read / local file inclusion by KNOWN-CONTENT signature.

    Injects a payload (e.g. a traversal ``../../../../etc/passwd``) into the
    insertion point and confirms via the side-effect oracle ONLY when a
    distinctive signature of the *target file's content* (``root:x:0:0:``, a
    ``[extensions]`` INI section, ``<web-app``) appears in the response — proof the
    file was actually READ, not merely that the path was reflected. The signature
    is specific enough that its presence is the proof; a reflected-but-not-read
    payload does not fire (the current marker-reflection path-traversal check only
    proved reflection, which is not a file read)."""

    id: str
    bug_class: str
    payload: str
    signature: str

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        resp = send(template.render(point, self.payload))
        body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
        return FindingContext.from_side_effect(self.signature, body, bug_class=self.bug_class)

    def adapt(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        """WAF-adaptive fallback (opt-in): when a traversal payload is filtered,
        synthesize a form that gets past the filter AND still returns the target
        file's content signature. The sink proxy is the signature's presence — proof
        the file was read, not merely that the path reflected — so the confirmation
        bar is identical to the normal path."""
        from .waf_evasion import adaptive_bypass

        def send_form(form: str) -> dict:
            return send(template.render(point, form))

        def sink_present(resp: dict) -> bool:
            body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
            return self.signature in body

        res = adaptive_bypass(self.payload, send_form, sink_present)
        if res is None:
            return None
        body = res.response.get("body", "") if isinstance(res.response, dict) else str(res.response)
        return FindingContext.from_side_effect(self.signature, body, bug_class=self.bug_class)


@dataclass(frozen=True)
class PathProbeCheck:
    """Framework/CMS exposure via a known-path signature (a request-level check).

    Fetches a fixed path relative to the target (e.g. ``/actuator/env``,
    ``/wp-json``, ``/.git/config``) and confirms exposure ONLY when a distinctive
    signature the framework leaks (``propertySources``, ``DB_PASSWORD``, a WP REST
    JSON) appears in the response — adjudicated by the predicate oracle, not a mere
    2xx. The signature must be specific enough that its presence is proof; a 404 or
    a signature-less response does not fire. Runs once per host."""

    id: str
    bug_class: str
    probe_path: str
    signature: str
    http_method: str = "GET"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        parts = urlsplit(req.url)
        base = f"{parts.scheme}://{parts.netloc}/"
        url = urljoin(base, self.probe_path.lstrip("/"))
        resp = send(req.model_copy(update={"method": self.http_method, "url": url, "body": ""}))
        if not isinstance(resp, dict):
            return None
        status = int(resp.get("status", 0))
        body = str(resp.get("body", ""))
        if status in (0, 404):
            return None  # not present -> nothing to adjudicate
        return FindingContext.from_predicate(
            {"status": status, "body": body},
            {"all": [{"icontains": [{"var": "body"}, self.signature]}]},
            bug_class=self.bug_class,
        )


def _slugify(s: str) -> str:
    return "".join(c for c in s if c.isalnum())


def _host(url: str) -> str:
    """The netloc of a URL, lowercased, or '' if it has none (relative URL)."""
    return urlsplit(url).netloc.lower()


# Scan windows are BOUNDED so a hostile, unterminated body cannot cause quadratic backtracking: a real
# <meta> tag or redirect URL never approaches these limits, but an attacker-controlled response could
# otherwise pack many "<meta " starts with no ">" (each greedy [^>]* rescanning to end → O(n^2)).
_MARKUP_SCAN_CAP = 512_000        # only the head of a response carries navigation markup; cap the parse
# Only two regexes remain: the URL inside a meta-refresh `content` value, and the JS navigation sinks inside
# script text. Everything structural — which bytes are markup at all, where a tag ends, which quote closes an
# attribute, what a raw-text element swallows — is delegated to the stdlib tokenizer below.
_META_REFRESH_VALUE_CAP = 4096    # a real refresh target never approaches this


_HTML_WHITESPACE = " \t\n\x0c\r"     # the HTML Standard's ASCII-whitespace set, not str.isspace()


def _meta_refresh_url(content: str) -> str:
    """The URL a browser would navigate to from a ``<meta http-equiv=refresh>`` ``content`` value, or "".

    This follows the HTML Standard's *shared declarative refresh steps* rather than approximating them —
    twice now an approximation was wrong in BOTH directions at once. Searching the value for any ``url=``
    minted a false FACT on ``content="url=http://evil/"`` (no time component, so a browser refreshes
    NOTHING) and on ``content="0; please wait;url=http://evil/"`` (the URL is the whole remainder after the
    separator, so it is the relative string ``please wait;url=…`` and stays same-origin). Requiring a
    literal ``url=`` simultaneously MISSED ``content="0;http://evil/"`` — the keyword is optional and every
    major browser navigates it — reporting a real open redirect as CLEAN.

    The steps, in order: skip whitespace; require a time (digits, or a leading ``.``); skip the fractional
    part; skip whitespace; consume ONE ``;`` or ``,``; skip whitespace; if the rest starts with ``url``,
    consume it plus an optional ``=`` (each with surrounding whitespace); the URL is then the remainder,
    optionally delimited by a quote. Bounded input, single forward pass, no backtracking."""
    value = (content or "")[:_META_REFRESH_VALUE_CAP]
    i, n = 0, len(value)

    def skip_ws(k: int) -> int:
        while k < n and value[k] in _HTML_WHITESPACE:
            k += 1
        return k

    i = skip_ws(i)
    start = i
    while i < n and value[i].isascii() and value[i].isdigit():
        i += 1
    if i == start and not (i < n and value[i] == "."):
        return ""                       # no time component: the browser refreshes nothing at all
    while i < n and ((value[i].isascii() and value[i].isdigit()) or value[i] == "."):
        i += 1                          # fractional part is parsed and ignored
    if i >= n:
        return ""                       # a bare time reloads the SAME page — not a navigation elsewhere
    if value[i] not in ";," and value[i] not in _HTML_WHITESPACE:
        return ""                       # the code point right after the time MUST be `;`, `,` or ASCII
                                        # whitespace; anything else ends parsing, so `0url=http://evil/`
                                        # and `0http://evil/` navigate NOWHERE (they reload same-origin)
    i = skip_ws(i)
    if i < n and value[i] in ";,":
        i = skip_ws(i + 1)
    if i >= n:
        return ""
    if value[i:i + 3].lower() == "url":
        i = skip_ws(i + 3)              # the keyword is consumed whether or not an `=` follows it
        if i < n and value[i] == "=":
            i = skip_ws(i + 1)
    if i < n and value[i] in "\"'":     # a quote delimits the URL; anything after the match is dropped
        quote, i = value[i], i + 1
        end = value.find(quote, i)
        return value[i:end if end >= 0 else n].strip(_HTML_WHITESPACE)
    # strip only ASCII whitespace: urlsplit (and a browser) KEEP other Unicode spaces such as U+00A0
    return value[i:].strip(_HTML_WHITESPACE)
# JS navigation sinks: location.href/.assign/.replace, window/document.location[.href], with = or (
#
# Sinks are filtered by lexical region (see js_lex): a match only counts when it BEGINS in executable code,
# so a commented-out or quoted sink is excluded structurally rather than by hoping the regex misses it. The
# one ambiguity JavaScript's grammar cannot settle without parsing — `/` as regex-start vs division — is
# resolved AWAY from minting, so an ambiguous span can never produce a FACT.
_JS_REDIRECT = re.compile(
    r"(?<![-\w])(?:(?:window|document|top|parent|self)\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=|\()\s*"
    r"[\"']([^\"']{1,4096})[\"']",
    re.IGNORECASE)
# The property name must match the WHOLE value against an allow-list of genuinely URL-valued properties
# (`fullmatch`). A substring test would fire on `not-og:url`, on a value that merely CONTAINS `og:url`, and
# — worst — on `twitter:image:alt` / `og:image:alt`, which are ALT TEXT, not URLs.
_URL_VALUED_META = re.compile(
    r"og:(?:url|(?:image|audio|video)(?::(?:url|secure_url))?)|twitter:(?:url|image(?::src)?)",
    re.IGNORECASE)


class _MarkupScan(HTMLParser):
    """Tokenize a response body with the STDLIB HTML tokenizer and record only what the app actually EMITS.

    This deliberately replaces a hand-written masker. Deciding "is this URL live markup or inert text?" is a
    tokenizer problem — comments, raw-text and escapable-raw-text elements, attribute quoting (including
    unquoted values), malformed and unterminated tags — and every hand-rolled approximation of it leaked in
    BOTH directions: inert text counted as an emission (a benign page minting a signed FALSE FACT) and live
    markup masked away (a real vulnerability silently DROPPED), plus repeated super-linear blowups on
    attacker-controlled bodies. ``html.parser`` gets those cases right, is linear, and ships with Python.

    Two things are layered on top, because the tokenizer does not model them and both change a verdict:

    * ``<template>`` content is an inert document fragment — it is not rendered and its resources are not
      fetched — but the tokenizer reports its children as ordinary tags, so emissions are suppressed while
      inside one. Depth is tracked on real tokenizer events, so a ``</template>`` appearing inside a script
      string or an attribute value cannot close it.
    * The WHATWG script-data DOUBLE-ESCAPE state: after ``<!--<script`` the next ``</script>`` returns to the
      escaped state instead of closing the element, so the markup after it is still script text. The
      tokenizer closes at the first ``</script>``, so emissions are suppressed until the following one —
      unless a ``-->`` ends the escape first.

    Everything the tokenizer already gets right (comments, ``script``/``style``/``textarea``/``title``/
    ``xmp``/``plaintext``/``noembed``/``noframes``/``iframe`` content, and live ``noscript``/``pre``/``code``
    content) is simply trusted.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.url_attrs: list[str] = []          # href/src/action values of LIVE tags
        self.metas: list[dict[str, str]] = []   # attributes of LIVE <meta> tags
        self.script_text: list[str] = []        # raw text of LIVE <script> elements (JS sink source)
        self._template_depth = 0
        self._in_script = False                 # the tokenizer is inside a <script> element
        self._script_open = False               # a script element is LOGICALLY still open (WHATWG state)
        self._escaped = False                   # script-data-escaped   (entered by `<!--`)
        self._double = False                    # script-data-double-escaped (entered by `<script` there)

    @property
    def _live(self) -> bool:
        # `_script_open` while the tokenizer is NOT in a script element means WHATWG considers us still
        # inside script data — what the tokenizer is now reporting as markup is really script text.
        return self._template_depth == 0 and not (self._script_open and not self._in_script)

    def _record(self, tag: str, attrs: "list[tuple[str, str | None]]") -> None:
        if not self._live:
            return
        # FIRST duplicate wins, as WHATWG specifies ("if there is already an attribute with that name, drop
        # the new one"). A plain dict comprehension keeps the LAST, which both mints a false FACT (a benign
        # first href with a hostile second) and drops a real one (hostile first, benign second).
        d: dict[str, str] = {}
        for key, value in attrs:
            d.setdefault(key.lower(), value or "")
        if tag == "meta":
            self.metas.append(d)
        for key in ("href", "src", "action"):
            if d.get(key):
                self.url_attrs.append(d[key])

    @property
    def _in_script_data(self) -> bool:
        """WHATWG still considers us inside script TEXT even though the tokenizer thinks it left the
        element. Tags it reports here are not tags at all, so they must not move any state."""
        return self._script_open and not self._in_script

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if tag == "template":
            self._template_depth += 1
            return
        if tag == "script":
            # A `<script>` seen while a script element is still logically OPEN (the tokenizer closed it at a
            # `</script>` that WHATWG treats as double-escape-exit) re-enters the double-escaped state.
            if self._script_open:
                self._double = True
            else:
                self._script_open, self._double, self._escaped = True, False, False
            self._in_script = True
        self._record(tag, attrs)

    def handle_startendtag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if self._in_script_data:
            return
        # The solidus is IGNORED on a non-void element, so `<template/>` OPENS a template: its content is an
        # inert fragment until the matching end tag. Treating it as open-and-closed left that content live.
        if tag == "template":
            self._template_depth += 1
            return
        self._record(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if self._in_script_data and tag != "script":
            return                          # a `</template>` inside script text closes nothing
        if tag == "template":
            self._template_depth = max(0, self._template_depth - 1)
            return
        if tag == "script":
            self._in_script = False
            if self._double:
                self._double = False        # double-escaped: this end tag returns to escaped, not a close
            else:
                # A real close ends the element AND its escape state: `_escaped` leaking into the next
                # script element made a later `<script ` look like a double-escape entry and suppressed a
                # live sink after it (a real vulnerability reported CLEAN).
                self._script_open, self._escaped = False, False

    def handle_data(self, data: str) -> None:
        # The escape state must also advance while the tokenizer is OUTSIDE the element but WHATWG still
        # considers us in script data: that text is script text, so a `-->` in it really does end the
        # escape. Ignoring it left `_escaped` stale, and a later `<script ` then looked like a fresh
        # double-escape entry and suppressed a live page (a real vulnerability reported CLEAN).
        if not (self._in_script or self._in_script_data):
            return
        if self._live and self._in_script:
            self.script_text.append(data)
        self._escaped, self._double = _script_data_state(data, self._escaped, self._double)


def _script_data_state(text: str, escaped: bool, double: bool) -> tuple[bool, bool]:
    """Advance the WHATWG script-data escape state across one chunk of script text.

    Models the actual state machine rather than guessing from substrings, because both guesses were wrong:
    a bare ``rfind("<!--<script")`` missed a NON-ADJACENT entry (``<!-- x <script>``, which really does
    double-escape) and fired on ``<!--<script<`` / ``<!--<scripting`` (which really do NOT, because
    ``<script`` must be followed by whitespace, ``/`` or ``>``) — minting a false FACT in the first case and
    certifying a genuinely vulnerable page CLEAN in the second. ``find``-based, so it stays linear."""
    i, n = 0, len(text)
    while i < n:
        if not escaped:
            start = text.find("<!--", i)
            if start < 0:
                break
            escaped, i = True, start + 4
            continue
        close = text.find("-->", i)
        entry = -1
        if not double:
            k = i
            while True:
                k = text.find("<script", k)
                if k < 0:
                    break
                after = k + 7
                if after >= n or text[after].isspace() or text[after] in "/>":
                    entry = k
                    break
                k += 7
        if close >= 0 and (entry < 0 or close < entry):
            escaped, double, i = False, False, close + 3      # `-->` leaves both escaped states
        elif entry >= 0:
            double, i = True, entry + 7                       # `<script` + terminator enters double-escape
        else:
            break
    return escaped, double


def _scan_markup(body: str) -> _MarkupScan:
    """Tokenize (a capped prefix of) ``body``. Malformed input never raises: whatever was tokenized before
    the error is what a browser would have parsed up to that point, and is what we judge."""
    text = (body or "")[:_MARKUP_SCAN_CAP]
    scan = _MarkupScan()
    if ">" not in text:
        return scan          # no complete tag can exist, so nothing is emitted — skip the tokenizer
    try:
        scan.feed(text)
        scan.close()
    except Exception:                             # noqa: BLE001 — keep what parsed; never fail the probe
        pass
    return scan


def _meta_refresh_hosts(scan: _MarkupScan) -> list[str]:
    """Hosts a declarative ``<meta http-equiv=refresh>`` would navigate to."""
    hosts: list[str] = []
    for meta in scan.metas:
        if (meta.get("http-equiv") or "").strip().lower() == "refresh":
            target = _meta_refresh_url(meta.get("content") or "")
            if target:
                hosts.append(_host(target))
    return [h for h in hosts if h]


def _js_sink_hosts(scan: _MarkupScan) -> list[str]:
    """Hosts a JS location sink would navigate to — counting ONLY sinks that begin in executable code."""
    hosts: list[str] = []
    for text in scan.script_text:
        for match in _JS_REDIRECT.finditer(text):
            # A sink inside a comment, a string, a template literal, or an ambiguous `/`-span never runs (or
            # cannot be shown to run without parsing); counting it was the false-FACT surface that kept this
            # branch quarantined LEAD-only.
            if _js_lex.sink_is_executable(text, match.start()):
                hosts.append(_host(match.group(1).strip()))
    return [h for h in hosts if h]


def _redirect_hosts(scan: _MarkupScan) -> list[str]:
    """Every host parsed markup would navigate to. Kept as the union for the predicate, while the two
    sources stay separately available: they are DIFFERENT evidence branches with different capabilities
    (a declarative refresh is statically decidable; a JS sink is only lexically decidable), so a verdict
    must be attributable to one of them rather than to their merger."""
    return _meta_refresh_hosts(scan) + _js_sink_hosts(scan)


def meta_refresh_hosts(body: str) -> list[str]:
    """Public: declarative-refresh navigation targets in ``body`` (branch ``*.body_markup``)."""
    return _meta_refresh_hosts(_scan_markup(body))


def js_sink_hosts(body: str) -> list[str]:
    """Public: executable JS-sink navigation targets in ``body`` (branch ``open_redirect.js_sink``)."""
    return _js_sink_hosts(_scan_markup(body))


def _markup_redirect_hosts(body: str) -> list[str]:
    """The hosts a browser would actually NAVIGATE to from the response markup — the target of a
    meta-refresh or a JS location sink. Returns lowercased netlocs; a relative / same-origin target
    contributes nothing. This is the co-location test that makes open-redirect confirmation sound: the
    canary host must be an ACTUAL navigation target, not merely a substring reflected somewhere in the body
    next to an unrelated ``<meta http-equiv=Content-Type>``.

    HONEST RESIDUAL: the extracted host list is a DERIVED observation stored in ``observed_evidence``
    alongside the raw ``body``, so re-verification re-fires the predicate over the derived list rather than
    re-parsing the body. The certificate signature makes the stored evidence tamper-evident, but the
    veracity firewall cannot demote a MINT-TIME derivation bug here — which is why this path is pinned by
    explicit true-positive AND negative-control tests plus a differential test against the stdlib tokenizer.
    This is the same property every shipped predicate has (e.g. ``location_host = _host(location)``)."""
    return _redirect_hosts(_scan_markup(body))


def _emitted_url_hosts(body: str) -> list[str]:
    """The hosts that appear as the AUTHORITY of a URL the app EMITS — an href/src/action attribute value, a
    URL-valued canonical/social meta (og:url, …), or a meta-refresh / JS-location redirect target. These are
    URLs a VICTIM's browser or a cache/crawler actually uses, which is what makes a reflected ``Host``
    exploitable (cache poisoning, poisoned reset link, canonical hijack).

    Crucially this is EMISSION, not mere presence: a URL that only appears as inert text — a 404 message
    echoing the reconstructed ``http://<Host>/path`` back to the requester, a ``<pre>`` sample, an HTML
    comment, a JSON error string — is NOT counted. Such an echo is shown only to the requester (who set
    their own Host) and is not exploitable. Authorities come from stdlib ``urlsplit`` (via ``_host``), so a
    relative URL whose QUERY contains ``//evil`` is correctly NOT an emission of ``evil``."""
    scan = _scan_markup(body)
    hosts = _redirect_hosts(scan)
    for value in scan.url_attrs:
        host = _host(value.strip())
        if host:
            hosts.append(host)
    for meta in scan.metas:
        prop = (meta.get("property") or meta.get("name") or "").strip()
        if _URL_VALUED_META.fullmatch(prop):
            host = _host((meta.get("content") or "").strip())
            if host:
                hosts.append(host)
    return [h for h in hosts if h]


# ---------------------------------------------------------------------------
# A seed library covering oracle-observable classes the verify layer confirms.
# Each check reuses an EXISTING oracle (differential / side_effect), so adding a
# class is a payload+shape declaration, not new confirmation machinery.
# ---------------------------------------------------------------------------

BOOLEAN_SQLI = DifferentialCheck(
    id="boolean-sqli", bug_class="boolean_sqli",
    benign="crucible-benign-term",
    probe_payload="x' OR '1'='1",
)

REFLECTED_XSS = MarkerReflectionCheck(
    id="reflected-xss", bug_class="xss",
    payload_template="\"'><x{marker}>",
)

# SSTI / path-traversal / error-based used to be MarkerReflectionCheck probes that
# confirmed on bare canary REFLECTION — but reflecting a canary only proves input
# is echoed (an XSS signal, already covered by REFLECTED_XSS), NOT that a template
# was evaluated, a file was read, or a datastore errored. On any endpoint that
# reflects input verbatim (a search box, an echo, an error page) all three fired as
# FALSE POSITIVES — the benchmark app only dodged this by reflecting solely
# markup-shaped input. These now use the evidence-carrying oracles: SSTI confirms
# only when the server COMPUTED the arithmetic (result present, raw absent),
# path-traversal only when the target file's CONTENT appears, error-based only when
# a datastore error appears in the probe but not the benign control. Prove, don't
# guess — a reflecting endpoint no longer trips any of the three.
SSTI_EVAL_BRACES = EvaluationCheck(
    id="ssti-eval-braces", bug_class="ssti",
    probe_expr="{{7331*7331}}", expected_result="53743561",
)

SSTI_EVAL_DOLLAR = EvaluationCheck(
    id="ssti-eval-dollar", bug_class="ssti",
    probe_expr="${7331*7331}", expected_result="53743561",
)

PATH_TRAVERSAL = ContentSignatureCheck(
    id="path-traversal", bug_class="path_traversal",
    payload="../../../../etc/passwd", signature="root:x:0:0:",
)

ERROR_BASED = ErrorSignatureCheck(
    id="error-based-injection", bug_class="error_based_sqli",
)


# --- out-of-band (blind) checks: confirmed by a callback, not a response ----

SSRF_OOB = OOBCheck(
    id="ssrf-oob", bug_class="ssrf",
    # a bare callback URL: a server-side fetch of it is the interaction
    payload_template="{callback}",
)

XXE_OOB = OOBCheck(
    id="xxe-oob", bug_class="blind_xxe",
    # external general entity that dereferences the callback on parse
    payload_template=(
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE r [<!ENTITY x SYSTEM \"{callback}\">]><r>&x;</r>"
    ),
)

RCE_OOB = OOBCheck(
    id="rce-oob", bug_class="command_injection",
    # a command-injection break-out that curls the callback (blind OS cmdi)
    payload_template=";curl {callback};",
)

DESERIALIZATION_OOB = OOBCheck(
    id="deserialization-oob", bug_class="deserialization",
    # JNDI/log4shell-style lookup: dereferenced during unsafe deserialization
    payload_template="${{jndi:ldap://{callback}}}",
)


# --- DNS out-of-band (blind) checks: confirmed by the DNS lookup the target's resolver forwards, even
#     when outbound HTTP is blocked. Each payload triggers a resolution of <token>.<base-domain>.
DNS_SSRF_OOB = DNSOOBCheck(
    id="ssrf-dns-oob", bug_class="ssrf",
    # a server-side fetch resolves the callback host before any (blocked) HTTP connect
    payload_template="http://{callback}/",
)

DNS_XXE_OOB = DNSOOBCheck(
    id="xxe-dns-oob", bug_class="blind_xxe",
    # external general entity: the parser resolves the SYSTEM host on parse
    payload_template=(
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE r [<!ENTITY x SYSTEM \"http://{callback}/x\">]><r>&x;</r>"
    ),
)

DNS_RCE_OOB = DNSOOBCheck(
    id="rce-dns-oob", bug_class="command_injection",
    # a command-injection break-out that forces a DNS lookup (no HTTP needed)
    payload_template=";nslookup {callback};",
)


# Open redirect: an evidence-carrying point check (fires only on a real redirect
# to the canary host), safe to run everywhere — the targeting selector still
# prioritises redirect-ish params.
OPEN_REDIRECT = OpenRedirectCheck()

DEFAULT_CHECKS: tuple[Check, ...] = (
    BOOLEAN_SQLI,
    REFLECTED_XSS,
    SSTI_EVAL_BRACES,
    SSTI_EVAL_DOLLAR,
    PATH_TRAVERSAL,
    ERROR_BASED,
    OPEN_REDIRECT,
    SSRF_OOB,
    XXE_OOB,
    RCE_OOB,
    DESERIALIZATION_OOB,
)
"""A ready-to-run seed set. Every check maps to a bug_class the verifier already
routes to an oracle, so it confirms end-to-end. The OOB checks (`wants_oob`) run
only when the engine has an OOBReceiver — without one they are skipped, never
guessed. Extend by declaring more DifferentialCheck / MarkerReflectionCheck /
OOBCheck entries — no new oracle needed."""
