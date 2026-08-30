"""The catalogue of every vulnerability MERIDIAN plants.

Each entry names the sink, the VIGIL oracle that CONFIRMS it, the exact signal it needs, and what the
hardened twin does instead. Range Control renders this as the capability catalogue; the tests assert every
entry both fires in vuln mode and goes quiet (as a sound negative) in hardened mode. Kept in sync with the
handlers as the slices land.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Vuln:
    id: str
    title: str
    cwe: str
    vuln_class: str            # the engine bug_class this maps to
    method: str
    path: str
    param: str
    oracle: str                # the VIGIL OracleKind that confirms it
    severity: str              # critical | high | medium | low
    signal: str                # what the oracle needs to see (the plant)
    hardened: str              # what the hardened twin does instead
    slice: str                 # which build slice introduced it


VULNS: list[Vuln] = [
    Vuln("sqli-records", "SQL injection in the public-records search", "CWE-89", "sqli",
         "GET", "/records/search", "q", "ERROR_SIGNATURE + DIFFERENTIAL_RESPONSE", "critical",
         "the query is string-concatenated into SQLite: a broken quote surfaces a real sqlite3 error, and "
         "`' OR '1'='1` returns materially more rows than `' AND '1'='2`",
         "the query is parameterized and the DB error is never echoed", "S1"),
    Vuln("xss-reflected-records", "Reflected XSS in the records search", "CWE-79", "xss",
         "GET", "/records/search", "q", "REFLECTION_CONTEXT", "high",
         "the `q` value is echoed into the HTML response unescaped, in an executable position",
         "the reflection is HTML-escaped", "S1"),
    Vuln("xss-stored-notes", "Stored XSS in an application's notes", "CWE-79", "xss",
         "GET", "/track", "ref", "REFLECTION_CONTEXT", "high",
         "the application `notes` field is stored verbatim and rendered unescaped on the tracking page",
         "the stored note is HTML-escaped on render", "S1"),
    Vuln("path-traversal-docs", "Path traversal in the document download", "CWE-22", "path_traversal",
         "GET", "/documents/download", "file", "SIDE_EFFECT", "high",
         "a `../`/`%2e`/`/etc/`/`passwd` path returns a DECOY passwd signature (no real file is read)",
         "the escape is refused with a 404", "S1"),
    Vuln("open-redirect-continue", "Open redirect on the auth continue endpoint", "CWE-601", "open_redirect",
         "GET", "/auth/continue", "next", "ACHIEVED_STATE", "medium",
         "a 302 Location is issued to the attacker-controlled `next` host verbatim",
         "only same-origin/relative `next` is honoured; anything else is refused", "S1"),
    Vuln("exposure-dotenv", "Environment file exposure", "CWE-200", "exposure",
         "GET", "/.env", "", "ACHIEVED_STATE", "high",
         "`/.env` and `/actuator/env` serve a (fake) secret-bearing body with a known signature",
         "both paths return 404", "S1"),
    Vuln("bola-applications", "BOLA / IDOR on the applications API", "CWE-639", "bola",
         "GET", "/api/applications/<id>", "id", "ACHIEVED_STATE", "critical",
         "any caller (even unauthenticated) reads any application's owner PII (name, national id, phone) — "
         "no ownership check. Confirmed two-identity via `scan --access-control --ac-ref idor:id:<victim>`",
         "the caller's session must own the application (or be staff); otherwise 401/403", "S2"),
    Vuln("cors-api", "CORS misconfiguration on the API", "CWE-942", "cors",
         "GET", "/api/applications", "Origin", "ACHIEVED_STATE", "medium",
         "the response reflects a hostile Origin AND sets Access-Control-Allow-Credentials: true",
         "no ACAO is emitted for a cross-origin request", "S2"),
    Vuln("host-header-share", "Host-header injection in the share link", "CWE-644", "host_header_injection",
         "GET", "/api/applications/<ref>/share", "Host", "ACHIEVED_STATE", "medium",
         "the share URL's authority is built from the attacker-controlled Host header",
         "the share URL uses the server's canonical host", "S2"),
    Vuln("bac-review-queue", "Broken access control on the review queue", "CWE-284", "broken_access_control",
         "GET", "/staff", "", "ACHIEVED_STATE", "high",
         "the staff review queue (applicant PII + notes) is reachable with no session at all",
         "the queue requires a clerk+ session", "S2"),
    Vuln("bfla-approve", "BFLA on the approve action", "CWE-285", "bfla",
         "POST", "/staff/applications/<id>/approve", "", "ACHIEVED_STATE", "high",
         "any caller can approve an application (no function-level authorization)",
         "approval requires a registrar+ session", "S2"),
    Vuln("privesc-role", "Privilege escalation via the admin role-change", "CWE-269", "privilege_escalation",
         "POST", "/admin/users/<id>/role", "role", "ACHIEVED_STATE", "critical",
         "any caller can set any account's role (including elevating themselves to admin)",
         "role changes require an admin session", "S2"),
    Vuln("bizlogic-pay", "Business-logic flaw in fee payment", "CWE-840", "business_logic",
         "POST", "/api/applications/<id>/pay", "amount", "ACHIEVED_STATE", "high",
         "the client-supplied `amount` is trusted, so a 0 or negative payment marks the fee PAID",
         "the server charges the real fee and rejects an underpayment", "S2"),
    Vuln("weak-authn-login", "Weak authentication (no rate limit)", "CWE-307", "authentication",
         "POST", "/login", "password", "n/a (drives detect brute-force/spray)", "medium",
         "plaintext credential check with NO rate limit; every attempt is written to auth.log",
         "a per-IP rate limit returns 429 after repeated failures", "S2"),
    Vuln("ssrf-fetch", "SSRF in the document fetch", "CWE-918", "ssrf",
         "GET", "/documents/fetch", "url", "OOB_CALLBACK", "high",
         "the server fetches an arbitrary user-supplied http(s) URL — the engine's loopback OOB callback "
         "URL lands on its receiver and the OOB oracle fires (file:// is refused, so this is SSRF not LFI)",
         "only the allowlisted document host may be fetched (private/loopback refused)", "S3"),
    Vuln("xxe-import", "XXE in the XML document import", "CWE-611", "blind_xxe",
         "POST", "/documents/import", "(body)", "OOB_CALLBACK", "high",
         "an imported XML document's external SYSTEM entity is resolved (fetched) → an outbound request to "
         "the entity URL (the OOB signal)",
         "external entities are never resolved", "S3"),
    Vuln("llm-injection-permitbot", "Prompt injection in the PermitBot assistant", "CWE-1427", "llm_injection",
         "GET", "/assistant", "q", "catalog/manual (web scan does not auto-fire an LLM oracle)", "medium",
         "an injection message makes the mock model leak its system prompt + the internal secret token",
         "a guardrail refuses the injection and the secret never appears in output", "S3"),
]


def by_id(vid: str) -> Vuln | None:
    return next((v for v in VULNS if v.id == vid), None)
