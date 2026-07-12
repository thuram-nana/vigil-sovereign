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


# --- SSTI (server-side template / expression-language injection) — response-side proof ------------
#
# The confirmable signature is EVALUATION, not reflection: the request value carries a template
# wrapper around a PURE ARITHMETIC expression (`{{7*7}}`, `${7*7}`), and the app's OWN response shows
# the COMPUTED result (`49`) while the raw expression is GONE. ``evaluation_oracle`` proves exactly
# that (result present AND raw absent), so a reflected-but-unevaluated payload — the app echoed
# `{{7*7}}` verbatim, or HTML-encoded it — never fires (near-zero FP). We only recognise a wrapper
# around a PURE arithmetic body, so `{{ user.name }}` / `${price}` (no arithmetic) are not even
# candidates. The regexes are fixed-structure with bounded `\d{1,6}` operands — non-backtracking
# (ReDoS-safe). A 1-digit result (`{{1*1}}`) is skipped: too coincidental a token to confirm on.
_SSTI_ARITH = r"(\d{1,6})\s*([*+])\s*(\d{1,6})"
_SSTI_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\{\{\s*" + _SSTI_ARITH + r"\s*\}\}"),   # Jinja2/Twig/Nunjucks/Angular  {{7*7}}
    re.compile(r"\$\{\s*" + _SSTI_ARITH + r"\s*\}"),      # JSP-EL/Freemarker/Thymeleaf/JS ${7*7}
    re.compile(r"#\{\s*" + _SSTI_ARITH + r"\s*\}"),       # Ruby / JSF-EL                  #{7*7}
    re.compile(r"<%=\s*" + _SSTI_ARITH + r"\s*%>"),       # ERB / JSP                      <%= 7*7 %>
    re.compile(r"\*\{\s*" + _SSTI_ARITH + r"\s*\}"),       # Thymeleaf selection            *{7*7}
    re.compile(r"@\(\s*" + _SSTI_ARITH + r"\s*\)"),       # Razor                          @(7*7)
)
_SSTI_MIN_RESULT = 10   # require a >= 2-digit result so a coincidental single digit cannot confirm


def _ssti_candidates(value: str) -> list[tuple[str, str]]:
    """``(inner_expr, expected_result)`` pairs for each template-wrapped PURE-arithmetic payload in
    ``value`` — e.g. ``("7*7", "49")``. ``inner_expr`` is passed as the oracle's ``raw`` so BOTH a
    full-payload reflection (`{{7*7}}` contains `7*7`) and a bare-inner reflection are caught as
    'reflected, not evaluated'. Bounded + deduped; deterministic."""
    out: list[tuple[str, str]] = []
    for rx in _SSTI_PATTERNS:
        for m in rx.finditer(value):
            a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
            result = a * b if op == "*" else a + b
            if result < _SSTI_MIN_RESULT:
                continue
            inner = f"{m.group(1)}{op}{m.group(3)}"
            pair = (inner, str(result))
            if pair not in out:
                out.append(pair)
            if len(out) >= 8:
                return out
    return out


# --- Path traversal / local file read — response-side proof ---------------------------------------
#
# The confirmable signature is a distinctive FILESYSTEM artifact surfacing in the response after a
# request value walked the path toward a sensitive absolute file. The near-zero-FP anchor is a strict
# `/etc/passwd` root-line signature — the canonical 7-colon-field shape with root at uid/gid 0, which
# a benign HTML page essentially never carries. ``side_effect_oracle`` then confirms the exact matched
# line reached the response. A benign request never even enters this path (the request value must
# carry a `../`-style traversal indicator toward a sensitive file), so a benign input cannot trigger it.
_TRAVERSAL_REQ_RE = re.compile(
    r"(?i)(?:\.\.[\\/]|%2e%2e(?:[\\/]|%2f|%5c)|/etc/(?:passwd|shadow)\b|\\windows\\win\.ini\b"
    r"|%2fetc%2fpasswd)")
# A leaked /etc/passwd root line: `root:x:0:0:root:/root:/bin/bash`. Per-line, strictly shaped, with
# bounded negated char-classes (non-backtracking → ReDoS-safe). Requires root at uid 0 gid 0.
_PASSWD_ROOT_RE = re.compile(
    r"(?m)^root:[^:\r\n]{0,64}:0:0:[^:\r\n]{0,120}:[^:\r\n]{0,120}:[^\s:]{0,64}$")
_TRAVERSAL_MARGIN = 48   # bounded window retained around the matched signature (small certificate)


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
    exploitation — a request value reflected into an executable HTML context (reflected XSS), a
    template expression the server EVALUATED (SSTI), or a `/etc/passwd` signature a traversal payload
    surfaced (path traversal) — else ``None`` (the gateway then relays the response untouched).
    Pure/deterministic; total. ``enforce`` sets the confirmed action to ``block``."""
    if not response_body:
        return None
    sink = response_body[:_MAX_RESPONSE_CHARS]
    verifier = verifier or OracleVerifier()
    values = candidate_values(path, headers, body)

    # reflected XSS — a request value's executable token reached an EXECUTABLE HTML context in the
    # response. REQUIRE the value to be reflected VERBATIM first: an HTML-encoded reflection does not
    # appear verbatim (so it is inert and must not fire), and a marker that only coincides with the
    # site's OWN script is not a reflection of user input. Both were false positives without this gate.
    for param, value in values:
        if value not in sink:
            continue
        for marker in _xss_markers(value):
            fc = FindingContext.from_side_effect(marker, sink, bug_class="xss")
            confirmed = confirm_finding({"bug_class": "xss"}, context=fc, verifier=verifier)
            if confirmed is not None:
                return _payload_verdict("xss", param, confirmed, fc, enforce=enforce)

    # SSTI — a request value carried a template-wrapped arithmetic expression the server EVALUATED:
    # the response shows the computed result while the raw expression is GONE. ``evaluation_oracle``
    # (control-vs-treatment discipline: result present, raw absent) is what separates evaluation from
    # reflection — a `{{7*7}}` echoed verbatim or HTML-encoded still carries the raw `7*7`, so it does
    # NOT fire. Only a genuine server-side evaluation blocks (near-zero FP).
    for param, value in values:
        for inner, expected in _ssti_candidates(value):
            fc = FindingContext.from_evaluation(inner, expected, sink, bug_class="ssti")
            confirmed = confirm_finding({"bug_class": "ssti"}, context=fc, verifier=verifier)
            if confirmed is not None:
                return _payload_verdict("ssti", param, confirmed, fc, enforce=enforce)

    # Path traversal / LFI — a request value walked the path toward a sensitive file AND a strict
    # `/etc/passwd` root-line signature surfaced in the response. ``side_effect_oracle`` confirms the
    # exact matched line reached the response; the request-side traversal gate + the strict, anchored
    # signature keep it near-zero FP (a benign request never enters this path, and a benign page
    # essentially never carries a uid/gid-0 root passwd line). The retained sink is a bounded window
    # around the match, so the certificate stays small.
    if _PASSWD_ROOT_RE.search(sink):
        for param, value in values:
            if not _TRAVERSAL_REQ_RE.search(value):
                continue
            m = _PASSWD_ROOT_RE.search(sink)
            marker = m.group(0).strip()
            start = max(0, m.start() - _TRAVERSAL_MARGIN)
            snippet = sink[start:m.end() + _TRAVERSAL_MARGIN]
            fc = FindingContext.from_side_effect(marker, snippet, bug_class="path_traversal")
            confirmed = confirm_finding({"bug_class": "path_traversal"}, context=fc, verifier=verifier)
            if confirmed is not None:
                return _payload_verdict("path_traversal", param, confirmed, fc, enforce=enforce)

    # NOTE — error-based SQLi is DELIBERATELY not confirmed inline. Without a control/baseline response
    # (a differential the offensive engine has but a live proxy does not), a datastore-error signature
    # in the response cannot be PROVEN to have been caused by the request value rather than merely
    # displayed near it (a Q&A/paste/log-viewer page that reflects a searched error string, a name like
    # O'Brien rendered next to a tracked error). The adversarial review proved every proximity heuristic
    # still false-positives, so it stays OFF the block path (roadmap: a differential/OOB confirmation).
    return None
