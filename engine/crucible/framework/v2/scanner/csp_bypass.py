"""
scanner.csp_bypass — two DISTINCT sound Content-Security-Policy claims (Wave 2.4).

CSP is a *defense-in-depth* control, so the two things worth saying about it are of very
different strength, and this module keeps them separate rather than collapsing them into one
soft "CSP looks weak" lead:

  (a) **Achieved CSP bypass** (``confirm_csp_bypass`` → bug_class ``csp_bypass``) — a unique
      per-probe canary that ACTUALLY EXECUTED in a real headless DOM (the ``__crucible_xss``
      binding call, the SAME unforgeable signal ``browser_xss`` / ``stored_xss`` /
      ``postmessage_exploited`` use) DESPITE the target response carrying a RETAINED, ENFORCED
      (non-report-only) CSP whose effective ``script-src`` PURPORTED TO BLOCK an arbitrary
      injected script. That is a *genuine bypass*: the policy was restrictive, yet the script
      ran. It reuses ``OracleKind.DOM_EXECUTION`` — NO new kind — but the DOM_EXECUTION
      dispatch arm applies the ``csp_purports_to_block`` guard (``verify.oracles``), so an
      execution under an ABSENT / REPORT-ONLY / PERMISSIVE policy is plain DOM-XSS (the
      ``dom_xss`` class), NEVER relabelled a bypass. A gadget bypass of a well-formed policy
      that VIGIL cannot make EXECUTE stays a LEAD.

  (b) **Permissive-policy posture-FACT** (``capture_csp_posture`` → bug_class ``csp_posture``)
      — a pure parse over the RETAINED enforced CSP response HEADER (NO browser,
      offline-re-derivable): it fires (``OracleKind.CSP_POSTURE``) when the effective
      ``script-src`` (``script-src`` else the ``default-src`` fallback) carries a real
      permissive weakness a browser honors — ``'unsafe-inline'`` with NO neutralizing
      nonce-/hash- companion (a nonce/hash makes the browser IGNORE ``'unsafe-inline'`` per
      CSP3 — honored, so a hardened nonce policy is NOT flagged), a wildcard ``*`` source, an
      ``http:`` / ``data:`` scheme source, or ``'unsafe-eval'``. It is a posture-FACT of the
      PARSED weakness, strictly WEAKER than the achieved bypass, and distinct from the
      LEAD-level ``passive.py`` csp-unsafe-inline check (which is not FACT-capable).

The achieved-bypass primitive this module drives is **nonce reuse**: it reads the ``script-src``
nonce from the target's own CSP response and injects a ``<script nonce=…>`` carrying that value.
Against a properly-hardened app (a fresh per-response nonce) the reused nonce does not match the
injection response's nonce, so the browser blocks the script and nothing fires — exactly the
soundness boundary. Against a STATIC / reflected nonce (the real bug) the nonce matches and the
script executes under a restrictive policy: a confirmed bypass. It also drives the standard
execution payloads (``img``/``onerror`` …) so a strict no-nonce policy that BLOCKS them yields no
fire, and an ABSENT policy that lets them run is correctly adjudicated plain DOM-XSS (not a
bypass) by the guard.

Requires a browser for the achieved bypass (``scanner.cdp.cdp_available``); with none the caller
skips the dynamic path (a browserless run yields a LEAD, never a CLEAN). The posture capture
needs no browser.
"""

from __future__ import annotations

import re
import secrets
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..verify.adapter import FindingContext
from ..verify.oracles import csp_posture_oracle, csp_purports_to_block
from .cdp import CdpBrowser, CdpError

# The binding a payload calls on execution — the SAME one browser_xss / stored_xss /
# postmessage_exploited register (Runtime.addBinding). Only the driver registers it, so a call
# carrying the canary is unforgeable proof the injected script ran in the target's realm.
_BINDING = "__crucible_xss"

# a script-src nonce token: ``'nonce-<base64>'`` (the value reused verbatim in a <script nonce=…>
# attribute is the <base64> part, without the ``nonce-`` prefix or the surrounding quotes).
_NONCE_TOKEN_RE = re.compile(r"(?i)^'nonce-([^']+)'$")

# Standard execution payloads (event-handler + inline-script shapes). Under a RESTRICTIVE policy
# these are BLOCKED (no fire); under an ABSENT policy they EXECUTE but the guard adjudicates plain
# DOM-XSS, never a bypass. ``{b}`` = binding, ``{c}`` = canary, ``{n}`` = a reused nonce value.
_EXEC_PAYLOADS: tuple[str, ...] = (
    "<img src onerror=window.{b}('{c}')>",
    "<svg onload=window.{b}('{c}')>",
    "\"><img src onerror=window.{b}('{c}')>",
    "<script>window.{b}('{c}')</script>",
)
# The nonce-reuse bypass payload — a <script> carrying a nonce READ FROM the target's own CSP.
_NONCE_PAYLOAD = "<script nonce={n}>window.{b}('{c}')</script>"


def _header_message(headers: Any) -> Message:
    """Coerce a response's headers into a case-insensitive ``email.message.Message`` (what
    ``urllib`` returns) so ``Content-Security-Policy`` lookups are case-insensitive whether the
    caller passed the raw headers object, a plain dict, or a list of pairs."""
    if isinstance(headers, Message):
        return headers
    msg = Message()
    items: Sequence[tuple[str, Any]]
    if isinstance(headers, Mapping):
        items = list(headers.items())
    elif isinstance(headers, Sequence) and not isinstance(headers, (str, bytes)):
        items = [(k, v) for k, v in headers]  # type: ignore[misc]
    else:
        items = []
    for k, v in items:
        try:
            msg[str(k)] = str(v)
        except Exception:
            continue
    return msg


def _extract_csp(headers: Any) -> "tuple[str, bool]":
    """Return ``(csp_header_value, report_only)``. The ENFORCED ``Content-Security-Policy`` wins;
    when only ``Content-Security-Policy-Report-Only`` is present it is returned with
    ``report_only=True`` (it enforces nothing, so downstream never mints from it). ``("", False)``
    when neither header is present."""
    msg = _header_message(headers)
    enforced = msg.get("Content-Security-Policy")
    if enforced:
        return str(enforced), False
    report_only = msg.get("Content-Security-Policy-Report-Only")
    if report_only:
        return str(report_only), True
    return "", False


def _effective_script_tokens(csp_header: str) -> list[str]:
    """The effective ``script-src`` tokens a browser applies (``script-src`` else ``default-src``),
    parsed the SAME way ``verify.oracles._parse_csp`` does — first-occurrence-wins per directive."""
    directives: dict[str, list[str]] = {}
    for part in (csp_header or "")[:8000].split(";"):
        toks = part.split()
        if not toks:
            continue
        name = toks[0].lower()
        if name not in directives:
            directives[name] = toks[1:]
    if "script-src" in directives:
        return directives["script-src"]
    return directives.get("default-src", [])


def _nonces_of(csp_header: str) -> list[str]:
    """Every ``'nonce-<v>'`` value declared in the effective script-src — the values a nonce-reuse
    bypass reflects back into ``<script nonce=<v>>`` (works only if the nonce is static/reusable)."""
    out: list[str] = []
    for tok in _effective_script_tokens(csp_header):
        m = _NONCE_TOKEN_RE.match(tok.strip())
        if m:
            out.append(m.group(1))
    return out


def _gated_fetch_headers(url: str, *, timeout: float = 8.0) -> Any:
    """Fetch ``url`` with a MANDATORY empty ProxyHandler (no ambient proxy) and return its response
    headers. Loopback / authorized-target use only; the live product supplies retained headers from
    the gated ``web_redrive`` channel instead. Returns an empty header set on any error (a fetch
    that established nothing is INCONCLUSIVE, never a CLEAN)."""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=timeout) as resp:  # noqa: S310 (loopback/authorized only)
            return resp.headers
    except Exception:
        return Message()


# ---------------------------------------------------------------------------
# (b) Permissive-policy POSTURE-FACT — a pure parse over the retained header (no browser).
# ---------------------------------------------------------------------------


@dataclass
class CspPostureResult:
    """One CSP posture judgement over a retained enforced header: the URL, the retained header
    value, whether it was report-only, the parsed permissive weaknesses (empty ⇒ no fire), and the
    re-verifiable oracle context."""

    url: str
    header: str
    report_only: bool
    weaknesses: list[str]
    context: FindingContext
    bug_class: str = "csp_posture"

    @property
    def is_weak(self) -> bool:
        return bool(self.weaknesses) and not self.report_only


def capture_csp_posture(
    url: str, *, response_headers: Any = None, timeout: float = 8.0
) -> CspPostureResult:
    """Judge the CSP posture of the response at ``url`` from its RETAINED enforced CSP header alone
    — no browser, offline-re-derivable. Pass ``response_headers`` (the retained headers from a gated
    fetch); when omitted, a loopback/authorized fetch is performed. Fires the ``csp_posture`` FACT
    only on a real permissive weakness in the effective script-src ('unsafe-inline' with no
    neutralizing nonce/hash, a wildcard '*', an http:/data: scheme source, or 'unsafe-eval'); a
    well-formed nonce policy, a report-only header, or a header with no effective script-src does
    NOT fire."""
    headers = response_headers if response_headers is not None else _gated_fetch_headers(url, timeout=timeout)
    header, report_only = _extract_csp(headers)
    control = {"rule": "permissive_script_src", "url": url, "header": header, "report_only": report_only}
    ctx = FindingContext.from_csp_control(control)
    sig = csp_posture_oracle(control)
    weaknesses = list(sig.observed.get("weaknesses", [])) if sig.fired else []
    return CspPostureResult(
        url=url, header=header, report_only=report_only, weaknesses=weaknesses, context=ctx)


def csp_posture_finding(result: CspPostureResult, *, check_id: str = "") -> dict:
    """Build the finding dict (carrying the retained ``oracle_context``) for a permissive-CSP posture
    result, ready for the STD-WIRING admission choke (``verdict.admit("csp_posture.header_weakness",
    …)`` → ``oracle_adapter.certify_admitted(provenance="live_redrive")``)."""
    return {
        "check_id": check_id or "csp_posture:permissive_script_src",
        "bug_class": "csp_posture",
        "title": "Permissive Content-Security-Policy (script-src does not effectively restrict execution)",
        "severity": "Medium",
        "surface": f"CSP header:{result.url}",
        "summary": (
            "the enforced CSP's effective script-src carries a permissive weakness a browser honors: "
            + "; ".join(result.weaknesses)
        ),
        "oracle_context": result.context.to_verifier_context(),
    }


# ---------------------------------------------------------------------------
# (a) Achieved CSP BYPASS — execution in a real DOM despite a restrictive enforced policy.
# ---------------------------------------------------------------------------


@dataclass
class CspBypassResult:
    """One achieved-bypass attempt: the payload, where it was injected, the unique canary, the
    retained enforced CSP header the execution DEFIED (+ its report-only flag), whether the browser
    ran it, whether that CSP purported to block it (the guard), and the re-verifiable oracle
    context. ``bypassed`` is True only when BOTH executed AND the retained CSP purported to block."""

    payload: str
    canary: str
    injection: str
    csp_header: str
    report_only: bool
    executed: bool
    context: FindingContext
    bug_class: str = "csp_bypass"
    nonces_reused: list[str] = field(default_factory=list)

    @property
    def csp_purported_to_block(self) -> bool:
        return csp_purports_to_block({"header": self.csp_header, "report_only": self.report_only})

    @property
    def bypassed(self) -> bool:
        return self.executed and self.csp_purported_to_block


def _inject(url: str, payload: str, *, param: str) -> str:
    """Render ``payload`` into query parameter ``param`` of ``url`` (the app reflects it)."""
    parts = urlsplit(url)
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    kept.append((param, payload))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))


def confirm_csp_bypass(
    url: str,
    *,
    params: Sequence[str] = ("q", "x", "input", "search", "name"),
    browser: CdpBrowser | None = None,
    settle: float = 0.8,
    timeout: float = 8.0,
) -> list[CspBypassResult]:
    """Prove an achieved CSP bypass against ``url`` in a real headless DOM.

    Reads the target's enforced CSP header (extracting any static/reusable ``script-src`` nonce),
    then for each injection ``param`` drives (1) the NONCE-REUSE payload — a ``<script>`` carrying a
    nonce read from the target's own CSP — and (2) the standard execution payloads, injecting each
    into ``url`` via that query param and observing whether the browser EXECUTED it (called the
    ``__crucible_xss`` binding with the unique per-probe canary). The retained enforced CSP header
    is captured and bound into the oracle context.

    ``result.bypassed`` (and the guarded ``dom_execution`` oracle over ``result.context``) is True
    ONLY when the browser actually ran the injected script AND the retained enforced CSP's
    script-src purported to block it. Execution under an absent / report-only / permissive policy is
    plain DOM-XSS and does NOT fire. Raises :class:`CdpError` only if no browser is available (the
    caller then skips — a browserless run yields a LEAD, never a CLEAN)."""
    own = browser is None
    br = browser or CdpBrowser().start()
    results: list[CspBypassResult] = []
    try:
        sess = br.session()
        sess.add_binding(_BINDING)
        for param in params:
            base_header, base_report_only = _extract_csp(_gated_fetch_headers(url, timeout=timeout))
            nonces = _nonces_of(base_header)
            # nonce-reuse payloads (one per discovered reusable nonce) + standard exec payloads.
            payloads: list[tuple[str, list[str]]] = []
            for n in nonces:
                payloads.append((_NONCE_PAYLOAD.replace("{n}", n), [n]))
            payloads.extend((tmpl, []) for tmpl in _EXEC_PAYLOADS)
            for i, (template, reused) in enumerate(payloads):
                canary = f"cspb{i:02d}{secrets.token_hex(4)}"
                payload = template.format(b=_BINDING, c=canary)
                target = _inject(url, payload, param=param)
                # capture the enforced CSP header of the exact injection response (deterministic;
                # this is the policy the browser enforced) and retain it in the oracle context.
                header, report_only = _extract_csp(_gated_fetch_headers(target, timeout=timeout))
                try:
                    sess.navigate(target, settle=settle)
                    calls = sess.binding_calls(_BINDING)
                except CdpError:
                    calls = []
                executed = any(canary in c for c in calls)
                ctx = FindingContext.from_csp_bypass(
                    calls, canary, header, report_only=report_only, bug_class="csp_bypass")
                results.append(CspBypassResult(
                    payload=payload,
                    canary=canary,
                    injection=f"query:{param}",
                    csp_header=header,
                    report_only=report_only,
                    executed=executed,
                    context=ctx,
                    nonces_reused=reused,
                ))
    finally:
        if own:
            br.stop()
    return results


def csp_bypass_finding(result: CspBypassResult, *, check_id: str = "") -> dict:
    """Build the finding dict (carrying the retained ``oracle_context``) for an achieved CSP-bypass
    result, ready for the STD-WIRING admission choke (``verdict.admit("csp_bypass.dom_execution",
    …)`` → ``oracle_adapter.certify_admitted(provenance="live_redrive")``). The context re-fires the
    guarded ``dom_execution`` oracle offline; a mutated canary no longer matches the binding call and
    a tampered (permissive) CSP header no longer purports to block, so neither can mint the FACT."""
    reuse = f" via nonce reuse ({', '.join(result.nonces_reused)})" if result.nonces_reused else ""
    return {
        "check_id": check_id or f"csp_bypass:{result.injection}",
        "bug_class": "csp_bypass",
        "title": "Content-Security-Policy bypass (script executed despite a restrictive script-src)",
        "severity": "High",
        "surface": f"CSP-protected page:{result.injection}",
        "summary": (
            "an injected canary executed in the target's DOM DESPITE a retained enforced CSP whose "
            "script-src purported to block it" + reuse + " — a genuine CSP bypass, not DOM-XSS on a "
            "permissive/absent policy"
        ),
        "oracle_context": result.context.to_verifier_context(),
    }
