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
)


def scan_passive(resp: Response) -> list[PassiveFinding]:
    """Run every passive check over one response and return all findings, in
    check-registry order. Deterministic; sends nothing."""
    findings: list[PassiveFinding] = []
    for check in PASSIVE_CHECKS:
        findings.extend(check(resp))
    return findings
