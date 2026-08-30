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
]


def by_id(vid: str) -> Vuln | None:
    return next((v for v in VULNS if v.id == vid), None)
