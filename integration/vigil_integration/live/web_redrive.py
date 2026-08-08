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

    _EMPTY = {"status": 0, "body": "", "headers": [], "latency_ms": 0.0}
    state = {"channels": 0, "no_channel": 0}

    def send(req: Any) -> dict:
        if _authorize(req.url, slug) is not None:
            state["no_channel"] += 1
            return dict(_EMPTY)   # refused (gate deny / kill-switch mid-run) — NO channel, not a CLEAN
        data = req.body.encode("utf-8") if getattr(req, "body", None) else None
        r = urllib.request.Request(req.url, data=data, method=getattr(req, "method", "GET"))
        for k, v in getattr(req, "headers", []) or []:
            r.add_header(k, v)
        opener = urllib.request.build_opener(_NoRedirect)
        t0 = time.monotonic()
        try:
            with opener.open(r, timeout=timeout) as resp:
                status, raw, headers = resp.status, resp.read(), list(resp.headers.items())
        except urllib.error.HTTPError as e:      # a 4xx/5xx is a real, useful response — a genuine channel
            status, raw, headers = e.code, e.read(), list(e.headers.items())
        except Exception:                        # noqa: BLE001 — transport error (no channel) → INCONCLUSIVE
            state["no_channel"] += 1
            return dict(_EMPTY)
        state["channels"] += 1
        return {"status": status, "body": raw.decode("utf-8", "replace"),
                "headers": [(str(k), str(v)) for k, v in headers], "latency_ms": (time.monotonic() - t0) * 1000.0}

    return send, state


def web_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                timeout: float = 8.0) -> WebRedriveResult:
    """Re-drive ``url`` through the shipped web checks via a gated send and mint a signed FACT for every
    ACHIEVED_STATE predicate the oracle confirms over VIGIL's OWN live capture. The predicates are scoped to
    the exploitable, co-located condition (a real navigation target / reflected-origin+creds), and a probe
    that established no channel is INCONCLUSIVE (never CLEAN). Returns a :class:`WebRedriveResult`."""
    from framework.v2.scanner.checks import CorsActiveCheck, HostHeaderCheck, OpenRedirectCheck  # noqa: PLC0415
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

    from ..oracle_adapter import confirm_and_certify  # noqa: PLC0415 (FATAL-2: function-local)

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
        before = state["channels"]
        ctx = probe_fn()
        had_channel = state["channels"] > before
        if not had_channel:
            res.inconclusive.append((bug_class, item))   # no observation → do NOT let it become CLEAN
            return
        if ctx is None:
            return
        finding = {"check_id": f"web:{bug_class}:{item}", "bug_class": bug_class,
                   "insertion_point": item, "oracle_context": ctx.to_verifier_context()}
        r = confirm_and_certify(finding, engagement_slug=engagement_slug, signers=signers,
                                provenance="live_redrive")
        res.contexts[r.finding_ref] = finding["oracle_context"]
        (res.facts if r.is_fact else res.leads).append(r)

    try:
        # request-level checks (add an evil Origin / Host to the whole request)
        _run(lambda: CorsActiveCheck().probe(template, send), "cors", url)
        _run(lambda: HostHeaderCheck().probe(template, send), "host_header_injection", url)
        # per-insertion-point: open-redirect injects the canary into each query-value point
        orc = OpenRedirectCheck()
        for point in template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)):
            _run(lambda p=point: orc.probe(template, p, send), "open_redirect", f"{url}#{point.id}")
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"probe error: {type(e).__name__}: {e}")
    return res
