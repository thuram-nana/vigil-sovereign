"""dom_redrive — runner-owned gated headless-browser re-drive → signed FACT for the two DOM ACHIEVED-STATE
classes reached from the Strix proof-sink dispatch rail (``proof/run.py``): DOM-XSS and client-side
prototype pollution.

It extends the exact ``runtime_redrive`` discipline (the RUNNER — never a tool — crafts the probe → the
existing deterministic oracle judges VIGIL's OWN fresh capture → one atomic evidence branch is admitted
against its declared capability → ``certify_admitted(provenance="live_redrive")`` mints a signed,
offline-re-verifiable FACT) to two BROWSER-BACKED classes whose oracle observes the ACHIEVED runtime state of
a real DOM rather than an HTTP response body:

  * ``dom_xss`` — the ``dom_execution`` oracle (``OracleKind.DOM_EXECUTION``): VIGIL drives an execution
    payload into the proposed URL/param (query) and the fragment (``location.hash`` sinks) in its OWN
    egress-gated headless-Chromium/CDP harness (``scanner.browser_xss.confirm_dom_xss``), which registers the
    ``__crucible_xss`` binding — a callback ONLY the driver installs — and mints a FACT ONLY when the injected
    script actually EXECUTED and called back with VIGIL's unique per-probe canary. A reflected-but-inert /
    encoded payload produces no binding call and does not fire (→ LEAD).

  * ``prototype_pollution`` — the ``prototype_pollution`` oracle (``OracleKind.PROTOTYPE_POLLUTION``): VIGIL
    drives a ``__proto__[uniqKey]=uniqVal`` gadget across the client sources
    (``scanner.proto_pollution.confirm_proto_pollution``) and reads the achieved ``Object.prototype`` state
    back THROUGH a planted ``__crucible_pp`` binding, minting a FACT ONLY when
    ``Object.prototype[uniqKey] === uniqVal`` AND a benign-key control stayed ``undefined``. The oracle's
    ``cpp_<hex>`` / ``ppv_<hex>`` canary-SHAPE guard means only VIGIL's OWN secrets-derived probe can satisfy
    it — a Strix-supplied readback (an arbitrary/pre-existing key) can NEVER mint.

Soundness is inherited unchanged. The Strix report is NEVER proof: VIGIL drives its OWN gadget/probe in its
OWN gated browser and the unforgeable canary is VIGIL-generated. A mint happens ONLY when the deterministic
oracle FIRES over VIGIL's own capture; a non-fire is a LEAD. The browser harness is EGRESS-GATED
(``CdpBrowser(allowed_hosts=...)`` — resolver-rules + Fetch allowlist confine it to the charter-authorised
host + loopback), and the URL-shaped charter gate (``reachability_cloud._authorize``) refuses out-of-scope
traffic BEFORE any browser is launched. Neither branch is CLEAN-capable: a non-fire (or a browserless env) is
INCONCLUSIVE, never CLEAN — "found nothing ≠ CLEAN". A browserless runner (no usable Chromium / CDP harness,
grounded in ``scanner.cdp.cdp_available`` — the ``scanner.browser.browser_usable`` analogue for the CDP path)
yields a LEAD, never a false negative and never a CLEAN.

FATAL-2: every framework-touching import is FUNCTION-LOCAL — importing this module co-loads no offense engine.
It reuses ``runtime_redrive``'s ``RuntimeRedriveResult`` + ``_admit_one`` + ``_candidate_names_hint`` (all
FATAL-2-safe: their framework imports are themselves function-local).
"""

from __future__ import annotations

from typing import Any, Optional

from .runtime_redrive import RuntimeRedriveResult, _admit_one, _candidate_names_hint

# The registered evidence branches each arm admits through. No new OracleKind: dom_xss reuses DOM_EXECUTION,
# prototype_pollution reuses PROTOTYPE_POLLUTION (both already frozen in verify._ALL_ORACLES). Kept in
# lock-step with docs/capability-matrix/evidence-branches.json.
_DOM_XSS_BRANCH = "dom_xss.dom_execution"
_PROTO_POLLUTION_BRANCH = "prototype_pollution.achieved_state"

# Candidate query-parameter names a DOM-XSS sink tends to read from when the proposed URL carries no usable
# parameter (mirrors runtime_redrive._XSS_PARAMS). A CLEAN would be bounded to these + the fragment — but this
# branch is not clean-capable, so the set only bounds where a FACT is SOUGHT, never a claim of absence.
_DOM_XSS_PARAMS = ("q", "query", "search", "s", "ref", "name", "keyword", "term", "message", "comment",
                   "title", "redirect", "url", "next", "hash", "fragment", "data")
# Browser launches + navigations are EXPENSIVE; probe at most this many query surfaces (plus the fragment).
_DOM_MAX_PARAMS = 3


def _host_of(url: str) -> str:
    """The hostname of ``url`` (for the browser's own egress allowlist). Lexical only, no network."""
    from urllib.parse import urlsplit  # noqa: PLC0415 — stdlib
    try:
        return (urlsplit(url if "://" in url else "http://" + url).hostname or "")
    except Exception:  # noqa: BLE001 — a malformed URL simply yields no host (the gate then refuses anyway)
        return ""


def _browser_preamble(url: str, slug: str, bug_class: str, branch: str):
    """Shared preamble for the two browser-backed arms: build the result, verify the branch is REGISTERED
    (fail-closed), and run the URL-shaped charter gate BEFORE any browser is launched. Returns
    ``(res, ok)`` — ``ok=False`` when the arm must return early (unregistered branch / gate refusal).
    Deliberately does NOT touch the browser: the ``cdp_available`` usability check happens only when the arm
    is about to construct its OWN harness, so a test may inject a stub browser without a real Chromium."""
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from .verdict import branch_ids  # noqa: PLC0415

    res = RuntimeRedriveResult(url=url, bug_class=bug_class)
    if branch not in branch_ids():
        res.notes.append(f"branch {branch!r} is not registered — cannot admit (fail-closed)")
        return res, False
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res, False
    return res, True


def _mark_browserless(res: "RuntimeRedriveResult", bug_class: str, url: str, why: str) -> None:
    """A browserless env is INCONCLUSIVE (a LEAD), never CLEAN. Record it as such — grounded in
    ``scanner.cdp.cdp_available`` (the CDP-path analogue of ``scanner.browser.browser_usable``)."""
    res.inconclusive.append((bug_class, f"{url}#browserless"))
    res.notes.append(f"{why} — DOM re-drive is INCONCLUSIVE (a LEAD, never CLEAN)")


def dom_xss_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                    param: "str | None" = None, timeout: float = 25.0,
                    browser: Any = None) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for DOM-based XSS in VIGIL's OWN egress-gated headless-browser harness and mint a
    signed FACT ONLY when the deterministic ``dom_execution`` oracle observes VIGIL's unique per-probe canary
    ACTUALLY EXECUTE in a real DOM (a ``__crucible_xss`` binding call) — never on a reflected-but-inert
    payload.

    Drives the fragment (``location.hash`` sinks) and the declared / candidate query parameters. A missing
    endpoint / gate refusal / browserless env / oracle non-fire ⇒ LEAD. ``browser`` (a started ``CdpBrowser``
    or a stub) may be injected to amortise launch cost / for tests; otherwise an egress-gated one is
    constructed here and torn down. Never raises."""
    from framework.v2.verify.oracles import dom_execution_oracle  # noqa: PLC0415 — FATAL-2 (offense plane)

    res, ok = _browser_preamble(url, slug, "dom_xss", _DOM_XSS_BRANCH)
    if not ok:
        return res

    from framework.v2.scanner.browser_xss import confirm_dom_xss  # noqa: PLC0415 — FATAL-2
    from framework.v2.scanner.cdp import CdpBrowser, CdpError, cdp_available  # noqa: PLC0415 — FATAL-2

    # A caller/test-supplied browser is reused for every target; otherwise VIGIL builds its OWN egress-gated
    # harness — a FRESH one PER injection target, because confirm_dom_xss opens a CDP session it does not
    # close, so reusing a single browser across calls breaks execution on the 2nd+ call (verified).
    external = browser is not None
    if not external and not cdp_available():
        _mark_browserless(res, "dom_xss", url,
                          "no usable headless browser / CDP harness (cdp_available() is False)")
        return res
    host = _host_of(url)

    # (param, in_fragment) injection targets: the fragment (location.hash sinks) ALWAYS, then the declared
    # param first + a few candidate query names (bounded — browser navigations are expensive).
    targets: "list[tuple[str | None, bool]]" = [(None, True)]
    max_params = 1 if (param and param.strip()) else _DOM_MAX_PARAMS
    for name in _candidate_names_hint(url, _DOM_XSS_PARAMS, param, max_params):
        targets.append((name, False))

    fired_here = False
    try:
        for pm, in_fragment in targets:
            br = browser
            if not external:
                try:
                    br = CdpBrowser(allowed_hosts={host} if host else None).start()
                except CdpError as exc:
                    _mark_browserless(res, "dom_xss", url,
                                      f"the egress-gated CDP harness could not launch ({type(exc).__name__})")
                    return res
            try:
                results = confirm_dom_xss(url, param=pm, in_fragment=in_fragment, browser=br)
            except CdpError as exc:
                res.notes.append(f"dom_xss probe error [{'fragment' if in_fragment else pm}]: {type(exc).__name__}")
                results = []
            finally:
                if not external and br is not None:
                    try:
                        br.stop()
                    except Exception:  # noqa: BLE001 — teardown must never raise into the re-drive path
                        pass
            surface = "fragment" if in_fragment else f"query:{pm}"
            for r in results:
                context = r.context.to_verifier_context()
                signal = dom_execution_oracle(context.get("dom_binding_calls"), context.get("dom_canary", ""))
                out = _admit_one(res, branch=_DOM_XSS_BRANCH, bug_class="dom_xss",
                                 engagement_slug=engagement_slug, signers=signers, context=context,
                                 item=f"{r.injection}:{r.canary}", surface=surface,
                                 fired=signal.fired, conclusive=signal.conclusive, body_unreadable=False)
                if out.is_fact:
                    fired_here = True
                    break
            if fired_here:
                break     # one FACT is decisive for a re-drive — stop (bounded browser work)
    except Exception as exc:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"dom_xss_redrive error: {type(exc).__name__}: {exc}")
    return res


def proto_pollution_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                            param: "str | None" = None, timeout: float = 25.0,
                            browser: Any = None) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for CLIENT-SIDE PROTOTYPE POLLUTION in VIGIL's OWN egress-gated headless-browser
    harness and mint a signed FACT ONLY when the deterministic ``prototype_pollution`` oracle proves the
    ACHIEVED state: ``Object.prototype[uniqKey] === uniqVal`` for VIGIL's unique per-probe ``cpp_<hex>`` /
    ``ppv_<hex>`` canary driven across a client source, AND a benign-key control stayed ``undefined``.

    The oracle's canary-SHAPE guard means only VIGIL's OWN secrets-derived probe can satisfy it — a
    Strix-supplied readback (an arbitrary or pre-existing prototype property) can NEVER mint. A page that
    merely reflects the gadget without polluting the prototype, an ambient-pollution page (benign key not
    undefined), a value mismatch, a gate refusal, or a browserless env all ⇒ LEAD. ``param`` is accepted for a
    uniform arm signature but the readback is over ``Object.prototype`` — not a single insertion point — so it
    does not narrow the client sources driven. ``browser`` may be injected for tests. Never raises."""
    from framework.v2.verify.oracles import prototype_pollution_oracle  # noqa: PLC0415 — FATAL-2

    res, ok = _browser_preamble(url, slug, "prototype_pollution", _PROTO_POLLUTION_BRANCH)
    if not ok:
        return res

    own = browser is None
    br = browser
    if br is None:
        from framework.v2.scanner.cdp import CdpBrowser, CdpError, cdp_available  # noqa: PLC0415 — FATAL-2
        if not cdp_available():
            _mark_browserless(res, "prototype_pollution", url,
                              "no usable headless browser / CDP harness (cdp_available() is False)")
            return res
        host = _host_of(url)
        try:
            br = CdpBrowser(allowed_hosts={host} if host else None).start()
        except CdpError as exc:
            _mark_browserless(res, "prototype_pollution", url,
                              f"the egress-gated CDP harness could not launch ({type(exc).__name__})")
            return res

    try:
        from framework.v2.scanner.proto_pollution import confirm_proto_pollution  # noqa: PLC0415 — FATAL-2
        from framework.v2.scanner.cdp import CdpError  # noqa: PLC0415

        try:
            results = confirm_proto_pollution(url, browser=br)
        except CdpError as exc:
            _mark_browserless(res, "prototype_pollution", url,
                              f"the CDP harness failed during the readback ({type(exc).__name__})")
            return res

        for r in results:
            context = r.context.to_verifier_context()
            signal = prototype_pollution_oracle(context.get("proto_pollution"))
            out = _admit_one(res, branch=_PROTO_POLLUTION_BRANCH, bug_class="prototype_pollution",
                             engagement_slug=engagement_slug, signers=signers, context=context,
                             item=f"{r.source}:{r.syntax}:{r.key}", surface=f"source:{r.source}",
                             fired=signal.fired, conclusive=signal.conclusive, body_unreadable=False)
            if out.is_fact:
                break     # one FACT is decisive for a re-drive — stop
    except Exception as exc:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"proto_pollution_redrive error: {type(exc).__name__}: {exc}")
    finally:
        if own and br is not None:
            try:
                br.stop()
            except Exception:  # noqa: BLE001 — teardown must never raise into the re-drive path
                pass
    return res
