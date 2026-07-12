"""
aegis.inspect — inline request/response inspection for the AEGIS Gateway.

Turns a live HTTP request (and, in G4, its proxied response) into an AEGIS ``Verdict`` by running the
SAME deterministic ``verify/`` oracles the offensive engine uses, pointed inward at the operator's own
app. A CONFIRMED verdict carries a re-runnable ``CertRef`` (prove-don't-guess); everything unproven is
a lead/clear the gateway logs but NEVER blocks (fail-open). This module is PURE DETECTION — no
enforcement, no network, no wallclock/rng — so a verdict is a deterministic function of the request.

Request-side coverage (fires on the request ALONE, no app response needed):
  * honeypot tripwire     -> automated_access                (a fetch of a seeded path no UI links)
  * parse-proof SQLi       -> sqli_attempt                    (string-literal break-out into structure)
  * parse-proof cmd-inject -> command_injection_attempt       (shell command-execution construct)

Honest scope: a request-side confirmation proves a STRUCTURED INJECTION ATTEMPT, never that the app is
exploited — the response-side oracles (G4) prove exploitation. Everything below a fired oracle stays a
lead the caller may log; it is never a block.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit

from ..verify.adapter import FindingContext
from ..verify.confirmation import confirm_finding
from ..verify.verifier import OracleVerifier
from .models import CertRef, Verdict

# The request-side parse-proof classes checked over each request-parameter value.
_REQUEST_PAYLOAD_CLASSES = ("sqli_attempt", "command_injection_attempt")

# DoS-safe bounds: cap how many insertion points we inspect and how long each value can be before any
# oracle work (the oracle regexes are non-backtracking, but bounding the input is defence in depth).
_MAX_VALUES = 256
_MAX_VALUE_CHARS = 8192
_MAX_BODY_BYTES = 2_000_000


def _json_leaves(obj: Any, prefix: str, add: Callable[[str, str], None], depth: int = 0) -> None:
    """Recurse a parsed-JSON body, feeding each leaf STRING value (with its key path) to ``add``.
    Depth-bounded so a hostile deeply-nested body cannot exhaust the stack."""
    if depth > 32:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _json_leaves(v, f"{prefix}.{k}" if prefix else str(k), add, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _json_leaves(v, f"{prefix}[{i}]", add, depth + 1)
    elif isinstance(obj, str):
        add(prefix or "body", obj)


def candidate_values(path: str, headers: list[tuple[str, str]], body: str | None) -> list[tuple[str, str]]:
    """``(param_name, DECODED value)`` pairs from the request's injection surfaces — query params and
    urlencoded / JSON body values. Bounded and total (a malformed body is skipped, never raised).
    Header/cookie surfaces are a documented roadmap; the classic injection surface is query+body."""
    out: list[tuple[str, str]] = []

    def add(name: str, val: Any) -> None:
        if isinstance(val, str) and val and len(out) < _MAX_VALUES:
            out.append((str(name)[:128], val[:_MAX_VALUE_CHARS]))

    try:
        for k, v in parse_qsl(urlsplit(path).query, keep_blank_values=False):
            add(k, v)
    except Exception:
        pass

    ctype = ""
    for hk, hv in (headers or []):
        if str(hk).lower() == "content-type":
            ctype = str(hv).lower()
            break
    if body and len(body) <= _MAX_BODY_BYTES:
        try:
            if "application/json" in ctype:
                _json_leaves(json.loads(body), "", add)
            elif "x-www-form-urlencoded" in ctype or not ctype:
                for k, v in parse_qsl(body, keep_blank_values=False):
                    add(k, v)
        except Exception:
            pass
    return out[:_MAX_VALUES]


def _payload_verdict(bug_class: str, param: str, confirmed: Any, fc: FindingContext,
                     *, enforce: bool) -> Verdict:
    cert = CertRef.mint(fc.to_verifier_context(), bug_class=bug_class,
                        confirmed_by=confirmed.confirmed_by.value, confidence=confirmed.confidence)
    return Verdict(
        decision="confirmed",
        attack_class=bug_class,
        confidence=float(confirmed.confidence),
        certificate=cert,
        provenance=f"grounded:aegis:{bug_class}",
        # D1: an enforce action rides ONLY on a confirmed certificate; else observe (read-only).
        action="block" if enforce else "observe",
        contributing=[param] if param else [],
    )


def inspect_request(
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: str | None,
    *,
    honeypot_paths: list[str] | None = None,
    crawler_allowlisted: bool = False,
    enforce: bool = False,
    verifier: OracleVerifier | None = None,
) -> Verdict | None:
    """Run the REQUEST-SIDE oracles over one incoming request. Returns a CONFIRMED ``Verdict`` (with a
    re-runnable ``CertRef``) for the FIRST proven attack — a honeypot tripwire or a structured
    injection attempt — or ``None`` when nothing is proven (the gateway then forwards + inspects the
    response). Pure/deterministic; total (never raises). ``enforce`` sets the confirmed verdict's
    ``action`` to ``block`` (D1); otherwise it is ``observe`` (read-only)."""
    verifier = verifier or OracleVerifier()

    # (1) honeypot tripwire — a fetch of a seeded path no human UI links proves AUTOMATED access.
    hp = [p for p in (honeypot_paths or []) if p]
    if hp:
        req_path = urlsplit(path).path or path
        fc = FindingContext.from_honeypot(req_path, hp, crawler_allowlisted=crawler_allowlisted)
        confirmed = confirm_finding({"bug_class": "automated_access"}, context=fc, verifier=verifier)
        if confirmed is not None:
            return _payload_verdict("automated_access", req_path, confirmed, fc, enforce=enforce)

    # (2) request-payload parse-proof — each decoded value vs the SQLi / command-injection oracles.
    for param, value in candidate_values(path, headers, body):
        for bug_class in _REQUEST_PAYLOAD_CLASSES:
            fc = FindingContext.from_request_payload(value, bug_class=bug_class, param=param)
            confirmed = confirm_finding({"bug_class": bug_class}, context=fc, verifier=verifier)
            if confirmed is not None:
                return _payload_verdict(bug_class, param, confirmed, fc, enforce=enforce)

    return None


# response-side effect oracles are run over the app's own answer, so they prove EXPLOITATION (not
# merely an attempt): a request value that reached an executable HTML context, or a datastore error a
# quote-bearing value provoked. Reused verbatim from the offensive engine.
_MAX_RESPONSE_CHARS = 2_000_000

# The reflection oracle is canary-oriented: it proves a MARKER landed in an executable context. A
# whole `<script>...</script>` payload as the marker never lands in a tag name, so we extract the
# executable TOKEN the payload would place in script/attribute context (the script content, an
# event-handler value, a javascript: URL). If the payload reflected verbatim, that token lands in an
# executable position and the oracle fires; an HTML-encoded reflection leaves it inert (no fire).
_XSS_SCRIPT_RE = re.compile(r"(?is)<script[^>]*>(.*?)</script>")
_XSS_ONATTR_RE = re.compile(r"""(?is)\bon\w+\s*=\s*["']?([^"'>][^"'>]*)""")
_XSS_JSURL_RE = re.compile(r"(?is)javascript:([^\s\"'>]+)")
_MIN_XSS_MARKER = 4


def _xss_markers(value: str) -> list[str]:
    """Executable tokens a reflected-XSS payload would place in an executable context — the content
    of a ``<script>``, an ``on*`` handler value, or a ``javascript:`` URL. Bounded, deduped."""
    seen: list[str] = []
    for rx in (_XSS_SCRIPT_RE, _XSS_ONATTR_RE, _XSS_JSURL_RE):
        for tok in rx.findall(value):
            t = str(tok).strip()
            if len(t) >= _MIN_XSS_MARKER and t not in seen:
                seen.append(t)
            if len(seen) >= 8:
                return seen
    return seen


def inspect_response(
    path: str,
    headers: list[tuple[str, str]],
    body: str | None,
    response_body: str | None,
    *,
    enforce: bool = False,
    verifier: OracleVerifier | None = None,
) -> Verdict | None:
    """Run the RESPONSE-SIDE effect oracles over the (request, PROXIED-response) pair. Returns a
    CONFIRMED ``Verdict`` (with a re-runnable ``CertRef``) when the app's own answer PROVES
    exploitation — a request value reflected into an executable HTML context (reflected XSS), or a
    datastore error a quote-bearing value provoked (error-based SQLi) — else ``None`` (the gateway
    then relays the response untouched). Pure/deterministic; total. ``enforce`` sets the confirmed
    action to ``block``."""
    if not response_body:
        return None
    sink = response_body[:_MAX_RESPONSE_CHARS]
    verifier = verifier or OracleVerifier()
    values = candidate_values(path, headers, body)

    # (1) reflected XSS — a request value's executable token reached an EXECUTABLE HTML context in the
    # response. An HTML-encoded reflection leaves the token inert (the oracle PARSES; encoded = safe).
    for param, value in values:
        for marker in _xss_markers(value):
            fc = FindingContext.from_side_effect(marker, sink, bug_class="xss")
            confirmed = confirm_finding({"bug_class": "xss"}, context=fc, verifier=verifier)
            if confirmed is not None:
                return _payload_verdict("xss", param, confirmed, fc, enforce=enforce)

    # (2) error-based SQLi — a datastore error signature in the response, LINKED to a quote-bearing
    # request value (so an unrelated error page cannot manufacture a block).
    quote_param = next((p for p, v in values if "'" in v or '"' in v), None)
    if quote_param is not None:
        fc = FindingContext.from_error_signature(sink, bug_class="error_based_sqli")
        confirmed = confirm_finding({"bug_class": "error_based_sqli"}, context=fc, verifier=verifier)
        if confirmed is not None:
            return _payload_verdict("error_based_sqli", quote_param, confirmed, fc, enforce=enforce)

    return None
