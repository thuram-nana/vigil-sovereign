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
import time
from dataclasses import dataclass
from typing import Callable, ClassVar, Protocol, runtime_checkable
from urllib.parse import urlsplit

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
        return FindingContext.from_oob(hits, bug_class=self.bug_class)


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
    the server reflects it (or wildcards) with credentials — the combination that
    lets an attacker page read authenticated responses. Confirmed via
    achieved-state only on the dangerous reflection, so a properly-scoped CORS
    policy does not fire."""

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
        # The ORACLE decides the dangerous condition over the raw header values:
        # (ACAO reflects the hostile origin OR is a wildcard) AND credentials are
        # allowed. A properly-scoped policy fails the predicate and does not fire.
        return FindingContext.from_predicate(
            {"acao": acao, "acac": acac, "evil_origin": self.evil_origin},
            {"all": [
                {"any": [{"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
                         {"eq": [{"var": "acao"}, "*"]}]},
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
        # The oracle checks whether the hostile Host became a URL authority: a
        # redirect Location to it, or an absolute //evil-host URL in the body. A
        # plain-text echo of the host does NOT satisfy the predicate.
        return FindingContext.from_predicate(
            {"location_host": _host(location), "evil_host": self.evil_host,
             "body": body, "evil_url": f"//{self.evil_host}"},
            {"any": [
                {"eq": [{"var": "location_host"}, {"var": "evil_host"}]},
                {"contains": [{"var": "body"}, {"var": "evil_url"}]},
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
        # Location, and body: a 30x Location to the canary host, OR a meta/JS
        # redirect in the body that resolves to it. Reflection on the app's own
        # host fails the predicate (no false positive on echoed-but-safe params).
        return FindingContext.from_predicate(
            {"status": status, "location_host": _host(location),
             "canary_host": _host(self.canary), "body": body},
            {"any": [
                {"all": [
                    {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                    {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},
                ]},
                {"all": [
                    {"min_len": [{"var": "canary_host"}, 1]},
                    {"contains": [{"var": "body"}, {"var": "canary_host"}]},
                    {"any": [
                        {"icontains": [{"var": "body"}, "http-equiv"]},
                        {"icontains": [{"var": "body"}, "location.href"]},
                        {"icontains": [{"var": "body"}, "location.replace"]},
                    ]},
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


def _slugify(s: str) -> str:
    return "".join(c for c in s if c.isalnum())


def _host(url: str) -> str:
    """The netloc of a URL, lowercased, or '' if it has none (relative URL)."""
    return urlsplit(url).netloc.lower()


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

SSTI_REFLECTION = MarkerReflectionCheck(
    id="ssti-reflection", bug_class="ssti",
    # a canary the engine looks for reflected verbatim; the SSTI arithmetic
    # variant is added by the engine's context step, this is the reflection gate.
    payload_template="{marker}",
)

PATH_TRAVERSAL = MarkerReflectionCheck(
    id="path-traversal", bug_class="path_traversal",
    payload_template="../../{marker}",
)

ERROR_BASED = MarkerReflectionCheck(
    id="error-based-injection", bug_class="error_based_sqli",
    payload_template="{marker}'\"\\",
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


DEFAULT_CHECKS: tuple[Check, ...] = (
    BOOLEAN_SQLI,
    REFLECTED_XSS,
    SSTI_REFLECTION,
    PATH_TRAVERSAL,
    ERROR_BASED,
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
