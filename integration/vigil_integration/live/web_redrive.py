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
    branch_verdicts: dict = field(default_factory=dict)  # bug_class -> {branch: verdict}
    contexts: dict = field(default_factory=dict)  # finding_ref -> oracle_context (offline re-verify)
    insertion_surfaces: dict = field(default_factory=dict)  # bug_class -> set(surface) actually EXAMINED
    probed_redirect_param_names: list = field(default_factory=list)  # candidate names on the synth carriers
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def surfaces_probed(self, bug_class: str) -> list:
        """The insertion surfaces on which ``bug_class`` was ACTUALLY examined (a channel was established),
        in a stable order. A surface only appears here if a real HTTP response came back on it — a
        gate-refused or transport-errored probe examined nothing and is deliberately excluded."""
        return sorted(self.insertion_surfaces.get(bug_class, set()))

    def coverage_statement(self, bug_class: str) -> str:
        """Name the insertion surfaces a CLEAN for ``bug_class`` is BOUNDED to.

        The product thesis is a SOUND negative: a CLEAN must mean "examined here and found nothing", never
        "did not look". So a family CLEAN is only honest when it also names WHERE it looked. An empty
        coverage set is not a clean bill of health — it is INCONCLUSIVE (nothing was examined)."""
        surfaces = self.surfaces_probed(bug_class)
        if not surfaces:
            return (f"{bug_class}: no insertion surface established a channel — INCONCLUSIVE, not CLEAN "
                    f"(nothing was examined)")
        return (f"{bug_class}: examined across insertion surfaces [{', '.join(surfaces)}]; any CLEAN is "
                f"bounded to these surfaces and the probed redirect-parameter names, never a claim of "
                f"absence on a surface or parameter name not examined")

    def family_coverage(self) -> dict:
        """Every examined family -> the insertion surfaces it was examined on (for persisted reporting)."""
        return {bug: self.surfaces_probed(bug) for bug in self.insertion_surfaces}

    def family_verdict(self, bug_class: str) -> str:
        """The conservative composition over every branch of ``bug_class`` (see verdict.compose).

        Reporting must use this rather than any single branch: a CLEAN header branch sitting beside a FACT
        body branch would otherwise be summarised as a clean family, asserting safety no branch established."""
        from .verdict import compose  # noqa: PLC0415
        return compose(list(self.branch_verdicts.get(bug_class, {}).values())).value

    def family_verdicts(self) -> dict:
        """Every examined family, conservatively composed."""
        return {bug: self.family_verdict(bug) for bug in self.branch_verdicts}


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


def benign_control_fetch(url: str, *, slug: str, timeout: float = 8.0) -> "bytes | None":
    """One VIGIL-owned, GATED, benign GET of ``url`` (no payload, no canary) — the CONTROL an error-signature
    proof is compared against (S6). Its response BODY bytes are what ``verify.oracles.error_signature_oracle``
    checks the exploit response against: the same datastore/parser error present in BOTH the exploit and this
    benign control means the page always errors ⇒ NOT attributable ⇒ the mint stays a LEAD.

    It reuses the SAME charter-gated, DNS-pinned, proxy-free send as the web re-drive (kill-switch →
    single-host → ACTIVE_RECON → charter scope), so a control is only ever fetched from an in-scope target.
    Returns the decoded body bytes when a real channel was established AND the whole document was read and
    soundly decoded, else ``None`` — a refusal (out of scope / kill-switch), a transport error, an
    un-decodable body, OR a body the send could only capture as a PREFIX (``truncated``: the document was
    longer than ``MAX_RAW_BYTES``) all yield ``None``. The truncated-but-decodable case is the load-bearing
    one: the send caps the control at ``MAX_RAW_BYTES`` while the observed side is the (uncapped) retained
    blob, so returning a decoded PREFIX would let the oracle compare an error present in the full observed
    response against a control from which that error was merely truncated away — an always-erroring page
    whose datastore error sits past the cap would then mint a FALSE FACT. A control we cannot soundly
    adjudicate over (``not body_semantically_available``) is therefore refused: the caller degrades the FACT
    to a LEAD (fail-closed), never adjudicates over bytes it never read. NEVER raises."""
    if not str(url or "").strip():
        return None
    try:
        from framework.v2.scanner.insertion import HttpRequest  # noqa: PLC0415 — FATAL-2 (offense plane)
        from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

        # PRE-FLIGHT the gate ONCE (mirrors ``web_redrive``): a refused engagement means VIGIL never observed
        # the target, so there is no control to compare against — refuse rather than send.
        if _authorize(url, slug) is not None:
            return None
        send, state = _gated_web_send(slug, timeout=timeout)
        resp = send(HttpRequest(method="GET", url=url))
        if state["channels"] <= 0:
            return None   # no channel established (gate deny mid-run / transport error) ⇒ no control
        # Refuse a control the module cannot soundly adjudicate OVER THE WHOLE DOCUMENT. ``send`` reads only
        # ``MAX_RAW_BYTES`` and sets ``body_semantically_available = decoded and not truncated``; the observed
        # side (proof/run.py::_resolve) is the UNCAPPED retained blob. A truncated (or un-decodable) control
        # would be captured ASYMMETRICALLY against the observed bytes — an error past the cap absent from the
        # prefix would fail to suppress a fire — so mirror the web_redrive runner's INCONCLUSIVE handling
        # (``state["body_unavailable"]``) and refuse. A None control ⇒ the caller keeps the mint fail-closed.
        if not resp.get("body_semantically_available"):
            return None
        body = resp.get("body")
        if isinstance(body, (bytes, bytearray)):
            return bytes(body) or None
        if isinstance(body, str):
            return body.encode("utf-8", errors="replace") or None
        return None
    except Exception:  # noqa: BLE001 — a control fetch must never raise into the mint; no channel ⇒ None
        return None


# The insertion surfaces this re-drive probes for open-redirect. A redirect parameter is NOT only a query
# value: apps read next/returnTo from a URL PATH segment, a COOKIE, a urlencoded BODY, or a JSON BODY just as
# often. A bare GET template exposes only the URL, so restricting the re-drive to QUERY_VALUE / URL_PATH_SEG
# meant those other surfaces were ABSENT from adjudication — not reported unexamined, simply missing, which
# reads to a consumer as "nothing there" and let a redirect reachable ONLY via a cookie/body param be
# reported CLEAN (a latent false-CLEAN). The runner therefore SYNTHESISES the cookie / urlencoded / JSON
# carriers (each with the correct method + Content-Type) so those insertion points EXIST to be rendered into
# and adjudicated by the SAME admission path. No benign-twin baseline is needed for soundness: the
# OpenRedirectCheck predicate fires ONLY on a real navigation to the UNIQUE canary HOST — which the app can
# only reach by using the injected value as a redirect target — so a benign reflection never false-FACTs.
# QUERY_NAME / BODY_FORM_NAME / JSON_KEY stay OUT as an ORACLE BOUNDARY: a canary injected as a parameter
# NAME does not model the redirect-VALUE property under test.
#
# Named by VALUE, not by enum member: the framework import is function-local (FATAL-2), so this module must
# not reference InsertionKind at import time. _redirect_templates() resolves them where the enum is available.

# Well-known redirect-parameter names tried on the synthesised cookie/body/JSON carriers, in addition to any
# name the proposed URL itself carries. A CLEAN over the synthesised surfaces is BOUNDED to this candidate
# set — stated honestly in the coverage statement — never a claim that no body/cookie redirect exists under
# some other name. Kept small so the re-drive's request footprint stays bounded.
_REDIRECT_PARAM_NAMES = (
    "next", "url", "redirect", "redirect_uri", "redirect_url", "returnto", "return_url",
    "returnurl", "return", "dest", "destination", "continue",
)
_MAX_CANDIDATE_REDIRECT_NAMES = 12


def _candidate_redirect_names(url: str) -> "list[str]":
    """Redirect-parameter names to try on the synthesised cookie/body/JSON carriers.

    GROUNDED first in the names the proposed URL actually carries (so an endpoint's real redirect parameter
    is exercised on EVERY surface, not only the query), then a small fixed set of well-known names for
    breadth, de-duplicated case-insensitively and capped. Purely lexical over the URL — no network."""
    from urllib.parse import parse_qsl, urlsplit  # noqa: PLC0415 — stdlib, function-local (style parity)
    names: "list[str]" = []
    seen: "set[str]" = set()
    try:
        for k, _v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            low = k.lower()
            if k and low not in seen:
                names.append(k)
                seen.add(low)
    except Exception:  # noqa: BLE001 — a malformed URL simply contributes no grounded names
        pass
    for n in _REDIRECT_PARAM_NAMES:
        if n not in seen:
            names.append(n)
            seen.add(n)
    return names[:_MAX_CANDIDATE_REDIRECT_NAMES]


def _redirect_templates(url, names, http_request, insertion_kind, request_template):
    """The ``(RequestTemplate, insertion-kinds)`` carriers the open-redirect re-drive probes.

    Four carriers, each restricted to the surface it introduces so the URL query/path is not re-probed by the
    body carriers: the bare GET (URL query + path), a GET with a synthesised Cookie header, a POST with a
    urlencoded body, and a POST with a JSON body. ``names`` (from :func:`_candidate_redirect_names`) are the
    redirect-parameter names placed on the synthesised carriers — the caller passes them so it can also record
    the CLEAN's parameter-name bound. Every carrier feeds the identical admission path, so each surface's
    outcome is attributed and capability-checked like any other. Returns a list; never raises."""
    import json  # noqa: PLC0415 — stdlib, function-local
    templates = [
        (request_template(http_request(method="GET", url=url)),
         (insertion_kind.QUERY_VALUE, insertion_kind.URL_PATH_SEG)),
    ]
    if names:
        cookie = "; ".join(f"{n}=redir" for n in names)
        templates.append((
            request_template(http_request(method="GET", url=url, headers=[("Cookie", cookie)])),
            (insertion_kind.COOKIE_VALUE,)))
        form = "&".join(f"{n}=redir" for n in names)
        templates.append((
            request_template(http_request(
                method="POST", url=url,
                headers=[("Content-Type", "application/x-www-form-urlencoded")], body=form)),
            (insertion_kind.BODY_FORM_VALUE,)))
        js = json.dumps({n: "redir" for n in names}, separators=(",", ":"))
        templates.append((
            request_template(http_request(
                method="POST", url=url, headers=[("Content-Type", "application/json")], body=js)),
            (insertion_kind.JSON_VALUE,)))
    return templates


def _oracle_signal(context: "dict"):
    """Run the deterministic oracle over the retained context and return its (fired, conclusive) signal.

    Kept separate from minting so admission can see the oracle's answer BEFORE any certificate exists."""
    from framework.v2.verify.oracles import predicate_oracle  # noqa: PLC0415 (FATAL-2: function-local)

    evidence = context.get("observed_evidence") or {}
    predicate = context.get("predicate") or {}
    return predicate_oracle(evidence, predicate)


def _branch_outcomes(bug_class: str, context: "dict", overall_fired: bool) -> "list[tuple[str, bool]]":
    """Every ATOMIC branch outcome present in this response, as ``(branch_id, fired)``.

    Deliberately NOT "one branch per response". A single response can carry a 302 ``Location``, a body
    meta-refresh AND a JavaScript sink at once; collapsing that to a single branch by precedence would
    discard real evidence and, worse, hide the LIMITATIONS of the branches it dropped — the body branches
    are not CLEAN-capable, so silently reporting only the header branch would let a response look more
    conclusively examined than it was.

    Each outcome is admitted separately, so each is judged against ITS OWN declared capability and appears
    in the audit trail with its own verdict."""
    evidence = context.get("observed_evidence") or {}
    followed = bool(evidence.get("followed_redirect"))
    body = evidence.get("body") or ""
    # A Location host equals the target only when the response ACTUALLY REDIRECTED. Without this, a status
    # 200 that merely reflects the canary into a Location header (or a render-dependent body/JS redirect on
    # a page that also sets Location) was attributed to the `location_header` branch — laundering
    # body/JS-derived, render-dependent evidence into a 3xx-header FACT whose DECLARED evidence surface was
    # never observed. The status gate MUST match the oracle's own Location disjunct (checks.py: a 3xx status
    # AND a matching Location host), so the branch fires exactly when its declared evidence is present.
    is_redirect = int(evidence.get("status", 0) or 0) in (301, 302, 303, 307, 308)
    location_host = evidence.get("location_host")

    if bug_class == "cors":
        return [("cors.reflected_origin_with_credentials", overall_fired)]

    if bug_class == "host_header_injection":
        # The host-header Location disjunct is itself status-free (checks.py:HostHeaderCheck), so branch and
        # oracle already agree here — do not add a gate the oracle does not have.
        evil = evidence.get("evil_host")
        emitted = evidence.get("emitted_url_hosts") or []
        return [
            ("host_header.location_header", bool(evil) and location_host == evil),
            ("host_header.body_emission", bool(evil) and evil in emitted and not followed),
        ]

    prefix = "oidc_redirect_uri" if bug_class == "oidc_redirect_uri" else "open_redirect"
    canary = evidence.get("canary_host")
    outcomes = [(f"{prefix}.location_header",
                 bool(canary) and is_redirect and location_host == canary)]
    meta_fired = js_fired = False
    if canary and body:
        from framework.v2.scanner.checks import js_sink_hosts, meta_refresh_hosts  # noqa: PLC0415
        meta_fired = canary in meta_refresh_hosts(body) and not followed
        js_fired = canary in js_sink_hosts(body) and not followed
    outcomes.append((f"{prefix}.body_markup", meta_fired))
    if prefix == "open_redirect":       # the SSO check has no registered JS-sink branch
        outcomes.append(("open_redirect.js_sink", js_fired))
    return outcomes


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
    from .verdict import Verdict, admit, compose as _compose  # noqa: PLC0415

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

    def _run(probe_fn, bug_class: str, item: str, *, surface: str = "") -> None:
        """Run one check, but adjudicate ONLY if the probe established a real channel. A probe whose every
        send was gate-refused (kill-switch tripped mid-run) or errored (connection refused / timeout)
        observed NOTHING — it is INCONCLUSIVE, never a 'channel-confirmed CLEAN' (the 'found nothing !=
        CLEAN' invariant). We snapshot the channel counter around the probe to decide.

        ``surface`` names the insertion surface this probe examined (e.g. ``json_value``); it is recorded as
        EXAMINED only when a channel was established, so the coverage statement can bound a CLEAN to the
        surfaces actually reached and never count a no-channel probe as coverage."""
        before, before_bodies = state["channels"], state["body_unavailable"]
        ctx = probe_fn()
        had_channel = state["channels"] > before
        if not had_channel:
            res.inconclusive.append((bug_class, item))   # no observation → do NOT let it become CLEAN
            return
        if surface:
            res.insertion_surfaces.setdefault(bug_class, set()).add(surface)
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
        observed = {
            "channel_established": True,
            "body_semantically_available": not body_unreadable,
            "not_followed_redirect": not bool(context.get("observed_evidence", {}).get("followed_redirect")),
            "gate_authorized": True,
        }
        # One admission PER ATOMIC BRANCH OUTCOME. A response carrying several kinds of evidence yields
        # several admissions, each judged against its own declared capability, so nothing is hidden by the
        # precedence of a stronger sibling.
        for branch, fired in _branch_outcomes(bug_class, context, signal.fired):
            admitted = admit(branch, fired=fired, conclusive=signal.conclusive, observed=observed)
            res.admissions.append((branch, admitted.verdict.value, admitted.reason))
            # STRONGEST-wins across insertion points, not last-wins. `_run` fires once PER insertion point,
            # all with the same branch names, so a benign point processed AFTER the firing one used to
            # overwrite its verdict — reporting a family as INCONCLUSIVE while it held a live signed FACT
            # (?next=<redirect>&utm_source=x is an everyday URL). A branch is FACT for the family if ANY
            # point produced a FACT; compose() over {prior, new} takes the stronger under the same lattice.
            branch_map = res.branch_verdicts.setdefault(bug_class, {})
            prior = branch_map.get(branch)
            branch_map[branch] = _compose([prior, admitted.verdict.value]).value if prior else admitted.verdict.value
            per_branch = dict(finding, check_id=f"{finding['check_id']}#{branch}")
            r = certify_admitted(per_branch, admitted, engagement_slug=engagement_slug, signers=signers,
                                 provenance="live_redrive")
            res.contexts[r.finding_ref] = context
            if r.is_fact:
                res.facts.append(r)
            elif admitted.verdict is Verdict.INCONCLUSIVE:
                res.inconclusive.append((bug_class, f"{item}#{branch}"))
                res.notes.append(f"{bug_class} [{branch}]: {admitted.reason}")
            else:
                res.leads.append(r)

    try:
        # request-level checks (add an evil Origin / Host to the whole request)
        _run(lambda: CorsActiveCheck().probe(template, send), "cors", url, surface="origin_header")
        _run(lambda: HostHeaderCheck().probe(template, send), "host_header_injection", url,
             surface="host_header")
        # per-insertion-point: open-redirect injects the canary into each redirect insertion point, across
        # EVERY surface a redirect parameter is really taken from — the URL query/path, a Cookie, a
        # urlencoded body, and a JSON body. The runner synthesises the cookie/body/JSON carriers (see
        # _redirect_templates) so those insertion points EXIST to be rendered into; each carrier is restricted
        # to the surface it introduces so the URL is not re-probed. Every outcome flows through the SAME
        # admission path, so each surface is attributed and capability-checked like any other.
        orc = OpenRedirectCheck()
        # the candidate redirect-parameter names placed on the synthesised cookie/body/JSON carriers — recorded
        # so the location_header CLEAN's parameter-name bound is machine-readable, not prose-only.
        names = _candidate_redirect_names(url)
        res.probed_redirect_param_names = list(names)
        for tmpl, kinds in _redirect_templates(url, names, HttpRequest, InsertionKind, RequestTemplate):
            for point in tmpl.insertion_points(kinds=kinds):
                _run(lambda t=tmpl, p=point: orc.probe(t, p, send), "open_redirect",
                     f"{url}#{point.id}", surface=point.kind.value)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"probe error: {type(e).__name__}: {e}")
    return res
