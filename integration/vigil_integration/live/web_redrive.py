"""web_redrive — a runner-owned, gated HTTP re-drive → ACHIEVED_STATE FACT (Wave #3, the web column).

A web tool (httpx / katana / nuclei) PROPOSES a URL; this re-drives it — the RUNNER (never the tool) crafts
the probe, sends it through a GATED HTTP client, and the existing deterministic ``predicate_oracle`` judges
the captured response. It mints a signed, offline-re-verifiable FACT for the web classes whose predicate is
a DEFINITE, EXPLOITABLE proposition over observed values (scoped to the co-located condition, not a loose
substring match — a benign reflecting page does not false-FACT):

  * open_redirect   — a 30x whose Location host == the injected canary host (or a meta/JS redirect to it);
  * cors            — Access-Control-Allow-Origin reflects the evil origin (or ``*``) AND ...-Credentials=true;
  * host_header_injection — a hostile Host header became a redirect Location authority (or a ``//evil`` in body).

It REUSES the shipped ``scanner.checks`` probes verbatim (same crafting + the exact predicate the oracle
already trusts) driven by a gated ``send`` — so nothing about the oracle or the predicate is reinvented; only
the transport is made charter-gated. A grype/nuclei match never mints a FACT; only this re-drive + the oracle
do (criterion-6). ``provenance="live_redrive"`` — the evidence is the runner's own live, gated capture.

FATAL-2: framework + urllib imports are FUNCTION-LOCAL; importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# the web classes this wave mints as FACTs (each has a definite, exploitable-condition ACHIEVED_STATE predicate).
WEB_FACT_CLASSES = ("open_redirect", "cors", "host_header_injection")


@dataclass
class WebRedriveResult:
    url: str
    facts: list = field(default_factory=list)     # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)     # AdapterResult (status=="lead") — CHANNEL-CONFIRMED
    inconclusive: list = field(default_factory=list)  # (bug_class, item) — a probe with NO channel; never CLEAN
    admissions: list = field(default_factory=list)    # (branch, verdict, reason) — the audit trail
    contexts: dict = field(default_factory=dict)  # finding_ref -> oracle_context (offline re-verify)
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)


def _gated_web_send(slug: str, *, timeout: float = 8.0):
    """Return ``(send, state)``. ``send`` is a ``scanner.checks.Send`` —
    ``send(HttpRequest) -> {status, body, headers, latency_ms}`` — that AUTHORIZES each request's URL
    through the URL-shaped active-recon gate (kill-switch → single-host → ACTIVE_RECON → charter scope →
    http(s), no embedded creds) BEFORE issuing it, follows NO redirects (so the raw Location is captured),
    and is bounded.

    ``state`` is a mutable ``{"channels": int, "no_channel": int}`` counter the runner uses to tell a
    GENUINE observation from a NON-observation. A refusal (per-request gate deny / kill-switch tripped
    mid-run) or any transport error (connection refused, timeout, DNS failure) increments ``no_channel``
    and returns a status-0 empty response — the check sees nothing and mints no FACT (never an un-gated
    send). The runner MUST NOT treat a no-channel probe as a "channel-confirmed CLEAN": no channel means
    INCONCLUSIVE, not clean (the "found nothing != CLEAN" invariant). Only a real HTTP response — any
    status, including 4xx/5xx — increments ``channels``."""
    import time
    import urllib.error
    import urllib.request

    from framework.v2.verify.reachability_cloud import _authorize  # the URL-shaped gate (offense-side)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D401
            return None

    from urllib.parse import urlsplit

    from .body_decode import MAX_RAW_BYTES, decode_body
    from .dns_pin import pinned_handlers, resolve_and_validate

    def _address_authorized(address: str) -> bool:
        """Re-ask the SAME gate about the resolved address. Reusing the charter decision (rather than a
        second, looser rule) is what keeps the pin honest: an address the gate would refuse as a target is
        refused as a destination."""
        scheme = "https" if str(address).count(":") > 1 else "http"   # bracket IPv6 for the URL form
        literal = f"[{address}]" if str(address).count(":") > 1 else address
        return _authorize(f"http://{literal}/", slug) is None

    _EMPTY = {"status": 0, "body": "", "headers": [], "latency_ms": 0.0,
              "body_semantically_available": False, "body_unavailable_reason": "no channel"}
    state = {"channels": 0, "no_channel": 0, "body_unavailable": 0}

    def send(req: Any) -> dict:
        if _authorize(req.url, slug) is not None:
            state["no_channel"] += 1
            return dict(_EMPTY)   # refused (gate deny / kill-switch mid-run) — NO channel, not a CLEAN
        data = req.body.encode("utf-8") if getattr(req, "body", None) else None
        r = urllib.request.Request(req.url, data=data, method=getattr(req, "method", "GET"))
        for k, v in getattr(req, "headers", []) or []:
            r.add_header(k, v)
        if not r.has_header("Accept-encoding"):
            # Ask only for encodings we can reverse. A target may still answer with something else (some
            # CDNs compress unconditionally) — that path is handled by decode_body, which refuses rather
            # than guessing, so the body is INCONCLUSIVE rather than silently mangled.
            r.add_header("Accept-Encoding", "gzip, deflate, identity")
        # An EMPTY ProxyHandler is MANDATORY (mirrors the shipped gated connector): without it urllib honours
        # http_proxy/https_proxy/ALL_PROXY, so the real TCP peer would be a proxy the gate never authorized —
        # the charter/single-host scope check would pass while traffic went elsewhere, and the proxy's bytes
        # would be labelled provenance="live_redrive". No auth handler either: the probe stays anonymous.
        # DNS time-of-check/time-of-use: the gate authorized a NAME, but urllib would resolve that name
        # again at connect time, so nothing binds the authorization to the endpoint actually reached
        # (rebinding, a short TTL, a poisoned resolver, or a multi-A record with one address out of scope).
        # Resolve once, require EVERY address to satisfy the same charter scope the gate used, then PIN the
        # connection to the validated address while still presenting the original hostname for TLS/Host.
        parts = urlsplit(req.url)
        target_host = parts.hostname or ""
        target_port = parts.port or (443 if parts.scheme == "https" else 80)
        resolution = resolve_and_validate(target_host, target_port, _address_authorized)
        if not resolution.allowed:
            state["no_channel"] += 1
            refused = dict(_EMPTY)
            refused["body_unavailable_reason"] = resolution.refused_reason
            return refused
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                             *pinned_handlers(resolution.pinned))
        t0 = time.monotonic()
        try:
            # Read ONE BYTE PAST the bound: reading exactly the cap cannot distinguish "the response was
            # this long" from "the response was longer and we hold a prefix", and a body-dependent NEGATIVE
            # over a prefix cannot prove the absence of markup.
            with opener.open(r, timeout=timeout) as resp:
                status, raw, headers = resp.status, resp.read(MAX_RAW_BYTES + 1), list(resp.headers.items())
        except urllib.error.HTTPError as e:      # a 4xx/5xx is a real, useful response — a genuine channel
            status, raw, headers = e.code, e.read(MAX_RAW_BYTES + 1), list(e.headers.items())
        except Exception:                        # noqa: BLE001 — transport error (no channel) → INCONCLUSIVE
            state["no_channel"] += 1
            return dict(_EMPTY)
        state["channels"] += 1
        headers = [(str(k), str(v)) for k, v in headers]
        truncated = len(raw) > MAX_RAW_BYTES
        body = decode_body(raw[:MAX_RAW_BYTES], headers, truncated=truncated)
        # The capture carries its own decoding provenance so an adjudicator can tell "the document said
        # nothing" from "we never read the document".
        if not body.body_semantically_available:
            # A real channel, but NOT a readable document. Header-derived evidence in this same response
            # stays adjudicable; body-derived evidence must not be scored as CLEAN over bytes we never
            # decoded, so the runner is told.
            state["body_unavailable"] += 1
        return {"status": status, "body": body.text, "headers": headers,
                "latency_ms": (time.monotonic() - t0) * 1000.0,
                "pinned_ip": resolution.pinned, "resolved_addresses": list(resolution.addresses),
                "raw_sha256": body.raw_sha256, "raw_len": body.raw_len,
                "content_encoding": body.content_encoding, "charset": body.charset,
                "decoded": body.decoded, "truncated": body.truncated,
                "body_semantically_available": body.body_semantically_available,
                "body_unavailable_reason": body.reason}

    return send, state


# The insertion points a redirect parameter realistically occupies. QUERY_NAME / BODY_FORM_NAME / JSON_KEY
# are deliberately excluded: injecting a canary URL as a parameter NAME does not model any real redirect
# flow, and probing them would add requests without adding evidence.
# Named by VALUE, not by enum member: the framework import is function-local (FATAL-2), so this module must
# not reference InsertionKind at import time. _redrive_kinds() resolves them where the enum is available.
_REDRIVE_INSERTION_KIND_NAMES = (
    "QUERY_VALUE", "URL_PATH_SEG", "COOKIE_VALUE", "BODY_FORM_VALUE", "JSON_VALUE",
)


def _redrive_kinds(insertion_kind):
    """The InsertionKind members this re-drive probes, resolved against the caller's enum."""
    return tuple(getattr(insertion_kind, name) for name in _REDRIVE_INSERTION_KIND_NAMES
                 if hasattr(insertion_kind, name))


def _oracle_signal(context: "dict"):
    """Run the deterministic oracle over the retained context and return its (fired, conclusive) signal.

    Kept separate from minting so admission can see the oracle's answer BEFORE any certificate exists."""
    from framework.v2.verify.oracles import predicate_oracle  # noqa: PLC0415 (FATAL-2: function-local)

    evidence = context.get("observed_evidence") or {}
    predicate = context.get("predicate") or {}
    return predicate_oracle(evidence, predicate)


def _attribute_branch(bug_class: str, context: "dict", fired: bool) -> str:
    """Map an outcome to exactly ONE registered evidence branch.

    A verdict that cannot be attributed to a single branch cannot be checked against any branch's declared
    capability, so attribution is part of admission rather than a reporting detail. Header-derived evidence
    is preferred when it is what actually fired, because it carries the stronger capability (it is
    CLEAN-capable, and independent of whether the body could be decoded)."""
    evidence = context.get("observed_evidence") or {}
    if bug_class == "cors":
        return "cors.reflected_origin_with_credentials"
    if bug_class == "host_header_injection":
        if evidence.get("location_host") and evidence.get("location_host") == evidence.get("evil_host"):
            return "host_header.location_header"
        return "host_header.body_emission"
    if bug_class == "oidc_redirect_uri":
        if evidence.get("location_host") and evidence.get("location_host") == evidence.get("canary_host"):
            return "oidc_redirect_uri.location_header"
        return "oidc_redirect_uri.body_markup"
    # open_redirect: header first, then the two body sources, which are DIFFERENT branches with different
    # capabilities (a declarative refresh is statically decidable; a JS sink is only lexically decidable).
    if evidence.get("location_host") and evidence.get("location_host") == evidence.get("canary_host"):
        return "open_redirect.location_header"
    canary = evidence.get("canary_host")
    body = evidence.get("body") or ""
    if canary and body:
        from framework.v2.scanner.checks import js_sink_hosts, meta_refresh_hosts  # noqa: PLC0415
        if canary in meta_refresh_hosts(body):
            return "open_redirect.body_markup"
        if canary in js_sink_hosts(body):
            return "open_redirect.js_sink"
    return "open_redirect.body_markup"      # nothing fired: attribute to the body branch, whose declared
                                            # capability correctly refuses to call that a CLEAN


def web_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                timeout: float = 8.0) -> WebRedriveResult:
    """Re-drive ``url`` through the shipped web checks via a gated send and mint a signed FACT for every
    ACHIEVED_STATE predicate the oracle confirms over VIGIL's OWN live capture. The predicates are scoped to
    the exploitable, co-located condition (a real navigation target / reflected-origin+creds), and a probe
    that established no channel is INCONCLUSIVE (never CLEAN). Returns a :class:`WebRedriveResult`."""
    from framework.v2.scanner.checks import CorsActiveCheck, HostHeaderCheck, OpenRedirectCheck  # noqa: PLC0415
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit  # noqa: PLC0415

    res = WebRedriveResult(url=url)
    # PRE-FLIGHT the gate ONCE: a refused engagement (kill-switch / out-of-scope / no-slug / bad URL) means
    # VIGIL never observed the target, so there is NO channel — we must NOT run the checks and let their
    # empty captures be mislabelled a "channel-confirmed CLEAN" (the "found nothing ≠ CLEAN" invariant). We
    # return refused with zero adjudications. The per-request gate in `send` remains as defence-in-depth.
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    send, state = _gated_web_send(slug, timeout=timeout)
    template = RequestTemplate(HttpRequest(method="GET", url=url))

    def _run(probe_fn, bug_class: str, item: str) -> None:
        """Run one check, but adjudicate ONLY if the probe established a real channel. A probe whose every
        send was gate-refused (kill-switch tripped mid-run) or errored (connection refused / timeout)
        observed NOTHING — it is INCONCLUSIVE, never a 'channel-confirmed CLEAN' (the 'found nothing !=
        CLEAN' invariant). We snapshot the channel counter around the probe to decide."""
        before, before_bodies = state["channels"], state["body_unavailable"]
        ctx = probe_fn()
        had_channel = state["channels"] > before
        if not had_channel:
            res.inconclusive.append((bug_class, item))   # no observation → do NOT let it become CLEAN
            return
        body_unreadable = state["body_unavailable"] > before_bodies
        if ctx is None:
            return
        context = ctx.to_verifier_context()
        finding = {"check_id": f"web:{bug_class}:{item}", "bug_class": bug_class,
                   "insertion_point": item, "oracle_context": context}

        # ADMISSION DECIDES, MINTING EXECUTES. Run the deterministic oracle, attribute the outcome to ONE
        # registered evidence branch, and let admit() apply that branch's declared capabilities against what
        # this observation actually supports. Calling confirm_and_certify directly would let a verdict reach
        # a certificate without any capability check ever running.
        signal = _oracle_signal(context)
        branch = _attribute_branch(bug_class, context, signal.fired)
        observed = {
            "channel_established": True,
            "body_semantically_available": not body_unreadable,
            "not_followed_redirect": not bool(context.get("observed_evidence", {}).get("followed_redirect")),
            "gate_authorized": True,
        }
        admitted = admit(branch, fired=signal.fired, conclusive=signal.conclusive, observed=observed)
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="live_redrive")
        res.contexts[r.finding_ref] = context
        res.admissions.append((branch, admitted.verdict.value, admitted.reason))
        if r.is_fact:
            res.facts.append(r)
        elif admitted.verdict is Verdict.INCONCLUSIVE:
            res.inconclusive.append((bug_class, item))
            res.notes.append(f"{bug_class} [{branch}]: {admitted.reason}")
        else:
            res.leads.append(r)

    try:
        # request-level checks (add an evil Origin / Host to the whole request)
        _run(lambda: CorsActiveCheck().probe(template, send), "cors", url)
        _run(lambda: HostHeaderCheck().probe(template, send), "host_header_injection", url)
        # per-insertion-point: open-redirect injects the canary into each query-value point
        orc = OpenRedirectCheck()
        # A redirect parameter is not only a query value: apps take `next`/`returnTo` from a path segment,
        # a cookie, or a urlencoded/JSON body just as often. Restricting the re-drive to QUERY_VALUE meant
        # those insertion points were ABSENT from adjudication — not reported as unexamined, simply missing,
        # which reads to a consumer as "nothing there". Every point below is covered by the same admission
        # path, so each one's outcome is attributed and capability-checked like any other.
        for point in template.insertion_points(kinds=_redrive_kinds(InsertionKind)):
            _run(lambda p=point: orc.probe(template, p, send), "open_redirect", f"{url}#{point.id}")
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"probe error: {type(e).__name__}: {e}")
    return res
