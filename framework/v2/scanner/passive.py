"""
scanner.passive — the passive check library.

Passive checks derive findings from a response the crawler already collected: no
extra requests, no payloads, no target mutation. They are ~half of Burp's ~140
issue types and the highest-precision, lowest-risk part of a scan — a missing
`HttpOnly` flag or a reflected stack trace is a *fact about the observed bytes*,
not a probabilistic probe, so there is no oracle to consult and no false-positive
class from guessing.

Each :class:`PassiveCheck` reads one :class:`Response` (status, headers, body,
url) and yields zero or more :class:`PassiveFinding`s with a fixed severity,
confidence (`Certain` for structural facts, `Firm`/`Tentative` for pattern
matches), and the concrete evidence. The library is deterministic and pure.

This is the defensive-by-construction half of the scanner: it observes and
reports, it never sends. It runs over every response the crawler/audit engine
sees, at zero marginal request cost.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field


class Response(BaseModel):
    """One observed HTTP response — the unit a passive check reads. ``headers``
    is an ordered list of (name, value) pairs, faithful to the wire."""

    model_config = ConfigDict(extra="forbid")

    url: str = ""
    status: int = 0
    headers: list[tuple[str, str]] = Field(default_factory=list)
    body: str = ""

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def headers_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    @property
    def is_https(self) -> bool:
        return urlsplit(self.url).scheme == "https"


class PassiveFinding(BaseModel):
    """A deterministic observation about one response."""

    model_config = ConfigDict(extra="forbid")

    check_id: str
    title: str
    severity: str = Field(description="Critical | High | Medium | Low | Info")
    confidence: str = Field(description="Certain | Firm | Tentative")
    url: str = ""
    evidence: str = ""


# ---------------------------------------------------------------------------
# security-header hygiene
# ---------------------------------------------------------------------------


def check_security_headers(resp: Response) -> list[PassiveFinding]:
    """Missing standard hardening headers on an HTML response. Absence is a
    structural fact -> Certain."""
    out: list[PassiveFinding] = []
    ctype = (resp.header("content-type") or "").lower()
    is_html = "text/html" in ctype or ctype == ""
    checks = [
        ("content-security-policy", "Missing Content-Security-Policy", "Medium"),
        ("x-content-type-options", "Missing X-Content-Type-Options (MIME sniffing)", "Low"),
        ("x-frame-options", "Missing X-Frame-Options (clickjacking)", "Medium"),
        ("referrer-policy", "Missing Referrer-Policy", "Low"),
    ]
    for header, title, sev in checks:
        # clickjacking is also mitigated by CSP frame-ancestors
        if header == "x-frame-options":
            csp = (resp.header("content-security-policy") or "").lower()
            if "frame-ancestors" in csp:
                continue
        if is_html and resp.header(header) is None:
            out.append(PassiveFinding(
                check_id=f"missing-{header}", title=title, severity=sev,
                confidence="Certain", url=resp.url, evidence=f"{header} header absent",
            ))
    # HSTS only meaningful over HTTPS
    if resp.is_https and resp.header("strict-transport-security") is None:
        out.append(PassiveFinding(
            check_id="missing-hsts", title="Missing Strict-Transport-Security (HSTS)",
            severity="Low", confidence="Certain", url=resp.url,
            evidence="strict-transport-security header absent on an HTTPS response",
        ))
    return out


# ---------------------------------------------------------------------------
# cookie security
# ---------------------------------------------------------------------------

_COOKIE_NAME = re.compile(r"^\s*([^=;]+)=")


def check_cookie_flags(resp: Response) -> list[PassiveFinding]:
    """Set-Cookie missing HttpOnly / Secure / SameSite. Each is a structural
    fact about the header -> Certain."""
    out: list[PassiveFinding] = []
    for raw in resp.headers_all("set-cookie"):
        m = _COOKIE_NAME.match(raw)
        name = m.group(1).strip() if m else "?"
        attrs = raw.lower()
        if "httponly" not in attrs:
            out.append(_cookie_finding("cookie-missing-httponly", name, "HttpOnly", "Low", resp.url, raw))
        if resp.is_https and "secure" not in attrs:
            out.append(_cookie_finding("cookie-missing-secure", name, "Secure", "Medium", resp.url, raw))
        if "samesite" not in attrs:
            out.append(_cookie_finding("cookie-missing-samesite", name, "SameSite", "Low", resp.url, raw))
    return out


def _cookie_finding(cid: str, name: str, flag: str, sev: str, url: str, raw: str) -> PassiveFinding:
    return PassiveFinding(
        check_id=cid, title=f"Cookie '{name}' missing {flag} flag", severity=sev,
        confidence="Certain", url=url, evidence=f"Set-Cookie: {raw[:120]}",
    )


# ---------------------------------------------------------------------------
# cleartext transport
# ---------------------------------------------------------------------------


def check_cleartext(resp: Response) -> list[PassiveFinding]:
    out: list[PassiveFinding] = []
    if resp.is_https:
        return out
    # a password field served over HTTP
    if re.search(r"<input[^>]+type\s*=\s*['\"]?password", resp.body, re.I):
        out.append(PassiveFinding(
            check_id="cleartext-password-form", title="Password field served over cleartext HTTP",
            severity="Medium", confidence="Certain", url=resp.url,
            evidence="a type=password input is delivered without TLS",
        ))
    return out


# ---------------------------------------------------------------------------
# information disclosure
# ---------------------------------------------------------------------------

_DISCLOSURE = [
    ("info-stack-trace", "Stack trace / framework error disclosed", "Medium", "Firm",
     re.compile(r"(Traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+\.java:\d+\)|"
                r"Warning: \w+\(\)|Fatal error:|System\.\w+Exception|ORA-\d{5}|"
                r"SQLSTATE\[|You have an error in your SQL syntax)", re.I)),
    ("info-private-ip", "Private IP address disclosed", "Low", "Firm",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
    ("info-private-key", "Private key material disclosed", "High", "Certain",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("info-email", "Email address disclosed", "Info", "Firm",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]


def check_info_disclosure(resp: Response) -> list[PassiveFinding]:
    out: list[PassiveFinding] = []
    body = resp.body
    for cid, title, sev, conf, rx in _DISCLOSURE:
        m = rx.search(body)
        if m:
            out.append(PassiveFinding(
                check_id=cid, title=title, severity=sev, confidence=conf, url=resp.url,
                evidence=_snippet(body, m.start(), m.end()),
            ))
    # server/version banners
    server = resp.header("server")
    if server and re.search(r"\d", server):
        out.append(PassiveFinding(
            check_id="info-server-banner", title="Server version banner disclosed",
            severity="Info", confidence="Certain", url=resp.url, evidence=f"Server: {server}",
        ))
    powered = resp.header("x-powered-by")
    if powered:
        out.append(PassiveFinding(
            check_id="info-x-powered-by", title="X-Powered-By technology banner disclosed",
            severity="Info", confidence="Certain", url=resp.url, evidence=f"X-Powered-By: {powered}",
        ))
    return out


def _snippet(body: str, start: int, end: int, pad: int = 24) -> str:
    lo = max(0, start - pad)
    hi = min(len(body), end + pad)
    return ("…" if lo else "") + body[lo:hi].replace("\n", " ") + ("…" if hi < len(body) else "")


# ---------------------------------------------------------------------------
# CORS misconfiguration
# ---------------------------------------------------------------------------


def check_cors(resp: Response) -> list[PassiveFinding]:
    out: list[PassiveFinding] = []
    acao = resp.header("access-control-allow-origin")
    if acao is None:
        return out
    acac = (resp.header("access-control-allow-credentials") or "").lower() == "true"
    if acao == "*" and acac:
        out.append(PassiveFinding(
            check_id="cors-wildcard-with-credentials",
            title="CORS: wildcard origin with credentials", severity="High", confidence="Certain",
            url=resp.url, evidence="Access-Control-Allow-Origin: * with Allow-Credentials: true",
        ))
    elif acao == "null":
        out.append(PassiveFinding(
            check_id="cors-null-origin", title="CORS: 'null' origin allowed",
            severity="Medium", confidence="Firm", url=resp.url,
            evidence="Access-Control-Allow-Origin: null",
        ))
    return out


# ---------------------------------------------------------------------------
# dangerous HTTP methods (from an OPTIONS/Allow response)
# ---------------------------------------------------------------------------

_DANGEROUS_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")


def check_dangerous_methods(resp: Response) -> list[PassiveFinding]:
    allow = resp.header("allow")
    if not allow:
        return out_empty()
    present = {m.strip().upper() for m in allow.split(",")}
    flagged = [m for m in _DANGEROUS_METHODS if m in present]
    if not flagged:
        return out_empty()
    return [PassiveFinding(
        check_id="dangerous-http-methods", title=f"Dangerous HTTP methods enabled: {', '.join(flagged)}",
        severity="Low", confidence="Certain", url=resp.url, evidence=f"Allow: {allow}",
    )]


def out_empty() -> list[PassiveFinding]:
    return []


# ===========================================================================
# M5 module B — broadened passive coverage
#
# Same doctrine as above: every finding below is a fact about the observed
# bytes (a header present/absent, a token literally in the body). Structural
# facts are ``Certain``; regex/pattern matches are ``Firm``; the handful of
# genuine heuristics (autocomplete intent, a generic ``secret=`` assignment)
# are honestly marked ``Tentative``. Header-hygiene checks that only matter for
# a browser-rendered document are gated on an HTML-ish content type so an API
# (JSON/binary) response is never dinged for a page-only header.
# ===========================================================================


def _f(check_id: str, title: str, severity: str, confidence: str,
       url: str, evidence: str) -> PassiveFinding:
    return PassiveFinding(check_id=check_id, title=title, severity=severity,
                          confidence=confidence, url=url, evidence=evidence)


def _is_htmlish(resp: Response) -> bool:
    """True when the response is (or is indistinguishable from) an HTML
    document — the only context where page-hardening headers are demanded.
    Mirrors :func:`check_security_headers`: a missing Content-Type is treated
    as HTML because a browser would sniff it as such."""
    ctype = (resp.header("content-type") or "").lower()
    return "text/html" in ctype or ctype == ""


def _cookie_name(raw: str) -> str:
    m = _COOKIE_NAME.match(raw)
    return m.group(1).strip() if m else "?"


def _cookie_attrs(raw: str) -> list[str]:
    """The cookie's attributes (everything after ``name=value``), normalised to
    lower-case with interior spaces removed. Parsing attributes — rather than
    substring-searching the whole header — avoids matching a flag word that only
    appears inside the cookie's *name* (e.g. the literal 'secure' in
    ``__Secure-...``) or value."""
    return [seg.strip().lower().replace(" ", "") for seg in raw.split(";")[1:]]


# ---------------------------------------------------------------------------
# Content-Security-Policy — present but weak
# ---------------------------------------------------------------------------


def check_csp_weaknesses(resp: Response) -> list[PassiveFinding]:
    """A delivered CSP that keeps a hole open: ``'unsafe-inline'`` /
    ``'unsafe-eval'`` re-enable the very sinks CSP exists to close, and a bare
    ``*`` source in a fetch directive trusts every host. The token is literally
    in the policy -> Certain."""
    csp = resp.header("content-security-policy")
    if not csp:
        return []
    out: list[PassiveFinding] = []
    low = csp.lower()
    if "'unsafe-inline'" in low:
        out.append(_f("csp-unsafe-inline", "CSP allows 'unsafe-inline'",
                      "Medium", "Certain", resp.url, f"Content-Security-Policy: {csp[:160]}"))
    if "'unsafe-eval'" in low:
        out.append(_f("csp-unsafe-eval", "CSP allows 'unsafe-eval'",
                      "Medium", "Certain", resp.url, f"Content-Security-Policy: {csp[:160]}"))
    for directive in low.split(";"):
        parts = directive.split()
        if parts and parts[0] in ("default-src", "script-src", "script-src-elem",
                                  "object-src", "base-uri") and "*" in parts[1:]:
            out.append(_f("csp-wildcard-source", f"CSP {parts[0]} allows wildcard '*' source",
                          "Medium", "Certain", resp.url, f"{parts[0]} * in policy"))
            break
    return out


def check_csp_report_only_only(resp: Response) -> list[PassiveFinding]:
    """CSP shipped only as ``...-Report-Only``: it reports violations but blocks
    nothing. Enforcement is off -> Firm."""
    if not _is_htmlish(resp) or resp.header("content-security-policy"):
        return []
    ro = resp.header("content-security-policy-report-only")
    if ro:
        return [_f("csp-report-only-not-enforced",
                   "Content-Security-Policy present only in Report-Only mode (not enforced)",
                   "Low", "Firm", resp.url, f"Content-Security-Policy-Report-Only: {ro[:120]}")]
    return []


# ---------------------------------------------------------------------------
# Strict-Transport-Security — present but weak (missing HSTS is check_security_headers)
# ---------------------------------------------------------------------------


def check_hsts_weaknesses(resp: Response) -> list[PassiveFinding]:
    """HSTS delivered but under-configured: a short ``max-age`` shrinks the
    protection window and no ``includeSubDomains`` leaves siblings unprotected.
    Scoped to HTML documents over HTTPS."""
    if not resp.is_https or not _is_htmlish(resp):
        return []
    hsts = resp.header("strict-transport-security")
    if not hsts:
        return []
    out: list[PassiveFinding] = []
    low = hsts.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    if m and int(m.group(1)) < 15552000:  # < 180 days
        out.append(_f("hsts-short-max-age", f"HSTS max-age is short ({m.group(1)}s, < 180 days)",
                      "Low", "Firm", resp.url, f"Strict-Transport-Security: {hsts}"))
    if "includesubdomains" not in low:
        out.append(_f("hsts-no-include-subdomains", "HSTS missing includeSubDomains",
                      "Low", "Firm", resp.url, f"Strict-Transport-Security: {hsts}"))
    return out


# ---------------------------------------------------------------------------
# missing modern isolation / policy headers (HTML documents)
# ---------------------------------------------------------------------------


def check_missing_permissions_policy(resp: Response) -> list[PassiveFinding]:
    if _is_htmlish(resp) and resp.header("permissions-policy") is None \
            and resp.header("feature-policy") is None:
        return [_f("missing-permissions-policy", "Missing Permissions-Policy",
                   "Low", "Certain", resp.url, "permissions-policy header absent")]
    return []


def check_missing_coop(resp: Response) -> list[PassiveFinding]:
    if _is_htmlish(resp) and resp.header("cross-origin-opener-policy") is None:
        return [_f("missing-coop", "Missing Cross-Origin-Opener-Policy (COOP)",
                   "Low", "Certain", resp.url, "cross-origin-opener-policy header absent")]
    return []


def check_missing_coep(resp: Response) -> list[PassiveFinding]:
    if _is_htmlish(resp) and resp.header("cross-origin-embedder-policy") is None:
        return [_f("missing-coep", "Missing Cross-Origin-Embedder-Policy (COEP)",
                   "Info", "Certain", resp.url, "cross-origin-embedder-policy header absent")]
    return []


def check_missing_corp(resp: Response) -> list[PassiveFinding]:
    if _is_htmlish(resp) and resp.header("cross-origin-resource-policy") is None:
        return [_f("missing-corp", "Missing Cross-Origin-Resource-Policy (CORP)",
                   "Info", "Certain", resp.url, "cross-origin-resource-policy header absent")]
    return []


def check_missing_x_permitted_cross_domain_policies(resp: Response) -> list[PassiveFinding]:
    if _is_htmlish(resp) and resp.header("x-permitted-cross-domain-policies") is None:
        return [_f("missing-x-permitted-cross-domain-policies",
                   "Missing X-Permitted-Cross-Domain-Policies",
                   "Info", "Certain", resp.url, "x-permitted-cross-domain-policies header absent")]
    return []


# ---------------------------------------------------------------------------
# security headers present but set to a weak/wrong value
# ---------------------------------------------------------------------------


def check_x_content_type_options_weak(resp: Response) -> list[PassiveFinding]:
    v = resp.header("x-content-type-options")
    if v is not None and v.strip().lower() != "nosniff":
        return [_f("x-content-type-options-invalid",
                   "X-Content-Type-Options set to a non-'nosniff' value (MIME sniffing still possible)",
                   "Low", "Certain", resp.url, f"X-Content-Type-Options: {v}")]
    return []


def check_x_frame_options_weak(resp: Response) -> list[PassiveFinding]:
    v = resp.header("x-frame-options")
    if v is not None and v.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return [_f("x-frame-options-invalid",
                   "X-Frame-Options has a deprecated/invalid value (e.g. ALLOW-FROM); framing may not be blocked",
                   "Low", "Certain", resp.url, f"X-Frame-Options: {v}")]
    return []


def check_referrer_policy_unsafe(resp: Response) -> list[PassiveFinding]:
    v = resp.header("referrer-policy")
    if v is None:
        return []
    tokens = {t.strip().lower() for t in v.split(",")}
    if "unsafe-url" in tokens:
        return [_f("referrer-policy-unsafe-url",
                   "Referrer-Policy is 'unsafe-url' (full URL leaked cross-origin, even on downgrade)",
                   "Low", "Certain", resp.url, f"Referrer-Policy: {v}")]
    return []


def check_xss_protection_legacy(resp: Response) -> list[PassiveFinding]:
    """A non-zero ``X-XSS-Protection`` re-enables the legacy auditor, itself a
    source of XS-Leaks; the modern recommendation is ``0``. Present-and-not-0
    is a structural fact -> Certain."""
    v = resp.header("x-xss-protection")
    if v is not None and v.strip().split(";")[0].strip() != "0":
        return [_f("x-xss-protection-legacy",
                   "Legacy X-XSS-Protection filter enabled (recommended value is '0')",
                   "Low", "Certain", resp.url, f"X-XSS-Protection: {v}")]
    return []


def check_cache_control_sensitive(resp: Response) -> list[PassiveFinding]:
    """A response that sets a cookie (a sensitive, per-user artifact) yet is
    cacheable by shared caches can leak one user's session to the next. Heuristic
    on 'sets a cookie == sensitive' -> Firm."""
    if not resp.headers_all("set-cookie"):
        return []
    cc = (resp.header("cache-control") or "").lower()
    if "no-store" in cc or "private" in cc:
        return []
    return [_f("sensitive-response-cacheable",
               "Response sets a cookie but is cacheable (no Cache-Control: no-store/private)",
               "Low", "Firm", resp.url, f"Cache-Control: {resp.header('cache-control') or '(absent)'}")]


# ---------------------------------------------------------------------------
# cookies — modern flag hygiene beyond the base HttpOnly/Secure/SameSite check
# ---------------------------------------------------------------------------


def check_cookie_samesite_none_insecure(resp: Response) -> list[PassiveFinding]:
    """``SameSite=None`` without ``Secure`` is rejected by modern browsers — a
    self-defeating misconfiguration. Structural -> Certain."""
    out: list[PassiveFinding] = []
    for raw in resp.headers_all("set-cookie"):
        attrs = _cookie_attrs(raw)
        if "samesite=none" in attrs and "secure" not in attrs:
            out.append(_f("cookie-samesite-none-insecure",
                          f"Cookie '{_cookie_name(raw)}' is SameSite=None without Secure",
                          "Medium", "Certain", resp.url, f"Set-Cookie: {raw[:120]}"))
    return out


def check_cookie_prefix_violation(resp: Response) -> list[PassiveFinding]:
    """``__Host-`` / ``__Secure-`` prefixes carry browser-enforced requirements;
    a cookie that claims a prefix but breaks its rule is silently dropped by the
    UA. Structural -> Certain."""
    out: list[PassiveFinding] = []
    for raw in resp.headers_all("set-cookie"):
        name = _cookie_name(raw)
        attrs = _cookie_attrs(raw)
        if name.startswith("__Host-"):
            ok = ("secure" in attrs
                  and "path=/" in attrs
                  and not any(a.startswith("domain=") for a in attrs))
            if not ok:
                out.append(_f("cookie-host-prefix-invalid",
                              f"Cookie '{name}' violates __Host- rules (requires Secure, Path=/, no Domain)",
                              "Medium", "Certain", resp.url, f"Set-Cookie: {raw[:120]}"))
        elif name.startswith("__Secure-") and "secure" not in attrs:
            out.append(_f("cookie-secure-prefix-invalid",
                          f"Cookie '{name}' has __Secure- prefix but no Secure flag",
                          "Medium", "Certain", resp.url, f"Set-Cookie: {raw[:120]}"))
    return out


def check_cookie_broad_domain(resp: Response) -> list[PassiveFinding]:
    """A leading-dot ``Domain=.example.com`` deliberately widens a cookie to
    every subdomain — proven scope broadening -> Firm."""
    out: list[PassiveFinding] = []
    for raw in resp.headers_all("set-cookie"):
        if re.search(r";\s*domain\s*=\s*\.", raw, re.I):
            out.append(_f("cookie-broad-domain",
                          f"Cookie '{_cookie_name(raw)}' scoped to a parent domain (leading-dot Domain)",
                          "Low", "Firm", resp.url, f"Set-Cookie: {raw[:120]}"))
    return out


_SESSION_HINT = ("sess", "sid", "phpsessid", "jsessionid", "auth")


def check_cookie_persistent_session(resp: Response) -> list[PassiveFinding]:
    """A session-looking cookie given an Expires/Max-Age survives browser close —
    a persistent auth token. Name is a heuristic -> Firm."""
    out: list[PassiveFinding] = []
    for raw in resp.headers_all("set-cookie"):
        name = _cookie_name(raw)
        attrs = raw.lower()
        if not any(h in name.lower() for h in _SESSION_HINT):
            continue
        ma = re.search(r"max-age\s*=\s*(\d+)", attrs)
        persistent = bool(re.search(r"expires\s*=", attrs)) or (ma is not None and int(ma.group(1)) > 0)
        if persistent:
            out.append(_f("cookie-persistent-session",
                          f"Session cookie '{name}' is persistent (Expires/Max-Age set)",
                          "Low", "Firm", resp.url, f"Set-Cookie: {raw[:120]}"))
    return out


# ---------------------------------------------------------------------------
# information disclosure — more banners, source maps, comments, paths, secrets
# ---------------------------------------------------------------------------

_VERSION_HEADERS = [
    ("x-aspnet-version", "info-x-aspnet-version", "X-AspNet-Version version banner disclosed"),
    ("x-aspnetmvc-version", "info-x-aspnetmvc-version", "X-AspNetMvc-Version version banner disclosed"),
    ("x-generator", "info-x-generator", "X-Generator technology banner disclosed"),
    ("x-runtime", "info-x-runtime", "X-Runtime (Rails) header disclosed"),
    ("via", "info-via", "Via proxy header disclosed"),
]


def check_tech_version_headers(resp: Response) -> list[PassiveFinding]:
    """Extra technology/version banners beyond Server / X-Powered-By. Each is a
    verbatim header value -> Certain, Info."""
    out: list[PassiveFinding] = []
    for hdr, cid, title in _VERSION_HEADERS:
        v = resp.header(hdr)
        if v:
            out.append(_f(cid, title, "Info", "Certain", resp.url, f"{hdr}: {v}"))
    return out


def check_source_map_reference(resp: Response) -> list[PassiveFinding]:
    """A ``sourceMappingURL`` comment points at the un-minified source (and often
    original file paths). Match on the body -> Firm."""
    m = re.search(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", resp.body)
    if m:
        return [_f("source-map-reference", "Source map reference disclosed",
                   "Low", "Firm", resp.url, _snippet(resp.body, m.start(), m.end()))]
    return []


_COMMENT_KW = re.compile(
    r"\b(TODO|FIXME|HACK|XXX|BUG|password|passwd|pwd|secret|api[_-]?key|apikey|backdoor|credential)\b",
    re.I,
)


def check_html_comment_keywords(resp: Response) -> list[PassiveFinding]:
    """A developer note left in an HTML comment referencing a secret/TODO. Match
    inside ``<!-- ... -->`` only -> Firm."""
    for m in re.finditer(r"<!--(.*?)-->", resp.body, re.S):
        km = _COMMENT_KW.search(m.group(1))
        if km:
            return [_f("html-comment-keyword",
                       f"HTML comment contains a sensitive keyword ('{km.group(0)}')",
                       "Low", "Firm", resp.url, m.group(1).strip()[:140])]
    return []


_FS_PATH = re.compile(
    r"(?:[A-Za-z]:\\(?:Users|inetpub|Windows|Program Files(?: \(x86\))?|xampp|wwwroot)\\[\\\w .()\-]+"
    r"|/(?:var/www|usr/local|srv/www|opt/[\w.\-]+|home/[A-Za-z][\w.\-]*|var/lib/[\w.\-]+|"
    r"etc/(?:passwd|shadow|nginx|apache2|httpd|php))(?:/[\w.\-]+)*)"
)


def check_filesystem_path_disclosure(resp: Response) -> list[PassiveFinding]:
    """An absolute server path (Unix webroot/home or a Windows drive path) in the
    body — usually a leaked error or debug artifact -> Firm."""
    m = _FS_PATH.search(resp.body)
    if m:
        return [_f("filesystem-path-disclosure", "Absolute filesystem path disclosed",
                   "Low", "Firm", resp.url, _snippet(resp.body, m.start(), m.end()))]
    return []


_SECRETS = [
    ("secret-aws-access-key", "AWS access key ID disclosed", "High", "Firm",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret-google-api-key", "Google API key disclosed", "High", "Firm",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("secret-slack-token", "Slack token disclosed", "High", "Firm",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("secret-github-token", "GitHub token disclosed", "High", "Firm",
     re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("secret-jwt", "JSON Web Token disclosed in body", "Low", "Firm",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
]

_GENERIC_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|access[_-]?token|client[_-]?secret)\b[\"']?\s*[=:]\s*[\"']?"
    r"([A-Za-z0-9/_\-+.]{12,})")
_PLACEHOLDER = re.compile(r"(?i)your|example|placeholder|changeme|xxxx|dummy|redacted|\.\.\.")


def check_secrets_in_body(resp: Response) -> list[PassiveFinding]:
    """High-entropy provider credentials (AWS/Google/Slack/GitHub), a JWT, or a
    generic ``key = <value>`` assignment. Vendor formats are unmistakable ->
    Firm/High; the generic assignment is a guess -> Tentative."""
    out: list[PassiveFinding] = []
    body = resp.body
    for cid, title, sev, conf, rx in _SECRETS:
        m = rx.search(body)
        if m:
            out.append(_f(cid, title, sev, conf, resp.url, _snippet(body, m.start(), m.end())))
    gm = _GENERIC_SECRET.search(body)
    if gm and not _PLACEHOLDER.search(gm.group(2)):
        out.append(_f("secret-generic-assignment",
                      f"Possible secret assigned in body ('{gm.group(1)}')",
                      "Medium", "Tentative", resp.url, _snippet(body, gm.start(), gm.end())))
    return out


def check_git_metadata_exposed(resp: Response) -> list[PassiveFinding]:
    """Contents of a served ``.git`` object — a HEAD ref or a git config — which
    lets an attacker reconstruct source. Distinctive markers -> Firm, High."""
    b = resp.body
    m = re.search(r"ref:\s*refs/heads/\S+|\[core\][\s\S]{0,60}repositoryformatversion", b)
    if m:
        return [_f("git-metadata-exposed", "Git repository metadata exposed (.git contents)",
                   "High", "Firm", resp.url, _snippet(b, m.start(), m.end()))]
    return []


def check_debug_mode(resp: Response) -> list[PassiveFinding]:
    """A debug/profiler header left on: the Symfony profiler (X-Debug-Token) is a
    notable surface; any other ``X-Debug*`` header is at least an information
    leak. Header presence -> Certain."""
    if resp.header("x-debug-token") is not None or resp.header("x-debug-token-link") is not None:
        val = resp.header("x-debug-token") or resp.header("x-debug-token-link")
        return [_f("debug-profiler-exposed", "Symfony debug profiler exposed (X-Debug-Token)",
                   "Medium", "Certain", resp.url, f"X-Debug-Token: {val}")]
    for k, v in resp.headers:
        if k.lower().startswith("x-debug"):
            return [_f("debug-header", "Debug header present", "Low", "Certain",
                       resp.url, f"{k}: {v}")]
    return []


# ---------------------------------------------------------------------------
# content & transport — mixed content, insecure forms, SRI, listings, types
# ---------------------------------------------------------------------------


def check_mixed_content(resp: Response) -> list[PassiveFinding]:
    """An HTTPS document that loads sub-resources over ``http://``. Active
    content (script/frame/stylesheet) is executable -> Medium; passive media is
    Low. Namespace URLs (xmlns) and anchor hrefs are excluded — they are not
    fetched, so they are not mixed content."""
    if not resp.is_https:
        return []
    active: list[str] = []
    passive: list[str] = []
    for tm in re.finditer(r"<(script|iframe|img|audio|video|source|link)\b[^>]*>", resp.body, re.I):
        tag = tm.group(0)
        name = tm.group(1).lower()
        if name == "link" and "stylesheet" not in tag.lower():
            continue
        am = re.search(r"\b(?:src|href)\s*=\s*[\"']?(http://[^\"'\s>]+)", tag, re.I)
        if not am:
            continue
        (active if name in ("script", "iframe", "link") else passive).append(am.group(1))
    out: list[PassiveFinding] = []
    if active:
        out.append(_f("mixed-content-active",
                      "Active mixed content: HTTPS page loads a http:// script/frame/stylesheet",
                      "Medium", "Firm", resp.url, active[0][:120]))
    if passive:
        out.append(_f("mixed-content-passive",
                      "Passive mixed content: HTTPS page loads a http:// media resource",
                      "Low", "Firm", resp.url, passive[0][:120]))
    return out


def check_form_insecure_action(resp: Response) -> list[PassiveFinding]:
    """A form on an HTTPS page whose ``action`` posts over cleartext http:// —
    the submitted credentials leave TLS. Match on the tag -> Firm."""
    if not resp.is_https:
        return []
    m = re.search(r"<form\b[^>]*\baction\s*=\s*[\"']?(http://[^\"'\s>]+)", resp.body, re.I)
    if m:
        return [_f("form-insecure-action",
                   "Form on an HTTPS page submits to a cleartext http:// action",
                   "Medium", "Firm", resp.url, m.group(1)[:120])]
    return []


def check_password_autocomplete(resp: Response) -> list[PassiveFinding]:
    """A password field with no ``autocomplete=off/new-password``. Whether that
    is a defect is genuinely context-dependent (browsers ignore it, password
    managers prefer it on) -> Tentative."""
    pw = re.findall(r"<input\b[^>]*type\s*=\s*[\"']?password[^>]*>", resp.body, re.I)
    if not pw:
        return []
    for tag in pw:
        if re.search(r"autocomplete\s*=\s*[\"']?(off|new-password|current-password)", tag, re.I):
            return []
    return [_f("password-input-autocomplete",
               "Password field without autocomplete=off/new-password",
               "Low", "Tentative", resp.url, pw[0][:120])]


def check_missing_sri(resp: Response) -> list[PassiveFinding]:
    """A script pulled from a different host without a Subresource-Integrity
    hash: a compromise of that host runs in this origin. Cross-origin + no
    ``integrity`` -> Firm."""
    page_host = urlsplit(resp.url).netloc.lower()
    if not page_host:
        return []
    for tm in re.finditer(r"<script\b[^>]*\bsrc\s*=\s*[\"']?([^\"'\s>]+)[^>]*>", resp.body, re.I):
        tag, src = tm.group(0), tm.group(1)
        if src.startswith("//"):
            host = src[2:].split("/")[0].lower()
        elif re.match(r"https?://", src, re.I):
            host = urlsplit(src).netloc.lower()
        else:
            continue  # relative -> same origin, SRI not required
        if not host or host == page_host or re.search(r"\bintegrity\s*=", tag, re.I):
            continue
        return [_f("missing-sri", f"External script without Subresource Integrity ({host})",
                   "Low", "Firm", resp.url, src[:120])]
    return []


def check_content_type_mismatch(resp: Response) -> list[PassiveFinding]:
    """An HTML document served with no Content-Type (browser will sniff) or a
    non-HTML one (e.g. text/plain). Detected from the body markup -> Firm."""
    if not re.search(r"<!doctype\s+html|<html[\s>]", resp.body[:2000], re.I):
        return []
    ctype = resp.header("content-type") or ""
    if ctype == "":
        return [_f("content-type-missing-html", "HTML body served without a Content-Type header",
                   "Low", "Firm", resp.url, "Content-Type header absent for an HTML body")]
    low = ctype.lower()
    if "text/html" not in low and "application/xhtml" not in low:
        return [_f("content-type-mismatch-html",
                   "HTML body served with a non-HTML Content-Type",
                   "Low", "Firm", resp.url, f"Content-Type: {ctype}")]
    return []


def check_directory_listing(resp: Response) -> list[PassiveFinding]:
    """A web-server auto-index page ('Index of /' / 'Directory listing for /')."""
    if re.search(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /", resp.body, re.I):
        return [_f("directory-listing", "Directory listing exposed", "Medium", "Firm",
                   resp.url, "auto-index / directory-listing signature in body")]
    return []


def check_charset_missing(resp: Response) -> list[PassiveFinding]:
    """An HTML response that declares neither a charset in Content-Type nor a
    ``<meta charset>`` — a UTF-7/sniffing XSS foothold on old UAs."""
    ctype = (resp.header("content-type") or "").lower()
    if "text/html" not in ctype or "charset=" in ctype:
        return []
    if re.search(r"<meta[^>]+charset", resp.body[:2000], re.I):
        return []
    return [_f("html-charset-missing", "HTML response does not specify a character set",
               "Info", "Firm", resp.url, f"Content-Type: {resp.header('content-type')}")]


def check_wsdl_disclosure(resp: Response) -> list[PassiveFinding]:
    """A SOAP service description (WSDL) served in full — a complete map of the
    service's operations."""
    if re.search(r"<(?:wsdl:)?definitions\b[^>]*schemas\.xmlsoap\.org/wsdl", resp.body, re.I):
        return [_f("wsdl-disclosure", "WSDL service definition disclosed", "Low", "Firm",
                   resp.url, "WSDL <definitions> with the xmlsoap.org/wsdl namespace")]
    return []


def check_insecure_redirect(resp: Response) -> list[PassiveFinding]:
    """An HTTPS response redirecting (Location) to a cleartext http:// URL — a
    protocol downgrade an active attacker can exploit."""
    if not resp.is_https:
        return []
    loc = resp.header("location")
    if loc and re.match(r"http://", loc, re.I):
        return [_f("insecure-redirect", "HTTPS response redirects to a cleartext http:// URL",
                   "Low", "Firm", resp.url, f"Location: {loc[:160]}")]
    return []


# ---------------------------------------------------------------------------
# registry + runner
# ---------------------------------------------------------------------------

PASSIVE_CHECKS = (
    check_security_headers,
    check_cookie_flags,
    check_cleartext,
    check_info_disclosure,
    check_cors,
    check_dangerous_methods,
    # --- M5 module B: broadened passive coverage ---
    check_csp_weaknesses,
    check_csp_report_only_only,
    check_hsts_weaknesses,
    check_missing_permissions_policy,
    check_missing_coop,
    check_missing_coep,
    check_missing_corp,
    check_missing_x_permitted_cross_domain_policies,
    check_x_content_type_options_weak,
    check_x_frame_options_weak,
    check_referrer_policy_unsafe,
    check_xss_protection_legacy,
    check_cache_control_sensitive,
    check_cookie_samesite_none_insecure,
    check_cookie_prefix_violation,
    check_cookie_broad_domain,
    check_cookie_persistent_session,
    check_tech_version_headers,
    check_source_map_reference,
    check_html_comment_keywords,
    check_filesystem_path_disclosure,
    check_secrets_in_body,
    check_git_metadata_exposed,
    check_debug_mode,
    check_mixed_content,
    check_form_insecure_action,
    check_password_autocomplete,
    check_missing_sri,
    check_content_type_mismatch,
    check_directory_listing,
    check_charset_missing,
    check_wsdl_disclosure,
    check_insecure_redirect,
)


def scan_passive(resp: Response) -> list[PassiveFinding]:
    """Run every passive check over one response and return all findings, in
    check-registry order. Deterministic; sends nothing."""
    findings: list[PassiveFinding] = []
    for check in PASSIVE_CHECKS:
        findings.extend(check(resp))
    return findings
