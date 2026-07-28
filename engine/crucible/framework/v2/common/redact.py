"""
common.redact — deterministic masking of secrets before they touch disk (Speed X2).

Two at-rest sinks archive operator/target data in the clear: the human-readable
``.http`` evidence dumps (request/response header lines) and the JSONL engagement
logs. Neither needs the literal secret to stay useful, and on a shared host a
world-readable ``Authorization`` / ``Cookie`` header — or a token logged in a
structured field — is a credential leak that outlives the engagement.

These maskers replace the sensitive VALUE with a stable placeholder while
preserving the surrounding shape (the header name, the log key), so evidence and
logs stay legible. They are PURE + DETERMINISTIC — same input always yields the
same output, no wallclock/rng — so replay, the calibration audit, and the evidence
artifact manifest (which hashes the .http files AFTER this masking) all stay
self-consistent.

Scope is deliberately conservative: mask by credential HEADER NAME / log KEY, not
by scanning free text for "token-like" substrings. Over-masking a response body or
a reflected payload would destroy the very proof a finding rests on; the raw body
(``response.body``) is never touched here and is protected instead by owner-only
(0600) permissions. This masks the credential that authenticated the request, not
the vulnerability evidence it produced.
"""

from __future__ import annotations

import re
from typing import Any

# The placeholder left in place of a masked value. Stable + distinctive so an
# operator can see a secret WAS present (and grep for leaks) without seeing it.
MASK = "<redacted-X2>"

# Header names whose VALUE is a credential / session token and must never be
# archived in the clear. Compared case-insensitively against the trimmed name.
SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-relay-key",
})

# Structured-log field names whose VALUE is a secret — matched EXACTLY (with the
# credential headers folded in). Exact-first avoids the classic substring trap:
# masking must never eat non-secret telemetry that merely CONTAINS a secret word
# (token counts `tokens_in`/`tokens_out`/`token_max`, an id `cache_key`, ...).
_EXACT_SECRET_KEYS = frozenset({
    "token", "secret", "password", "passwd", "pwd", "bearer",
    "credential", "credentials",
    "api_key", "apikey", "access_token", "auth_token", "refresh_token",
    "session_token", "id_token", "csrf_token", "xsrf_token",
    "private_key", "secret_key", "signing_key", "session_key", "relay_key",
    "client_secret",
}) | SENSITIVE_HEADERS

# Whole delimited SEGMENTS that are unambiguously secret wherever they appear
# (no telemetry/identifier field uses these). Deliberately EXCLUDES 'token' and
# 'key', which collide with `tokens_in`/`token_max` telemetry and `cache_key`
# identifiers — those are handled by the exact set + secret suffixes below.
_STRONG_SECRET_SEGMENTS = frozenset({
    "password", "passwd", "secret", "authorization", "cookie",
    "credential", "credentials", "bearer",
})

# Suffixes that mark a secret without eating plurals/limits: `access_token` is a
# secret, but `tokens_in` / `token_max` are not (they do not END with `_token`).
_SECRET_SUFFIXES = (
    "_token", "-token", "_secret", "-secret",
    "_password", "-password", "_passwd", "-passwd",
    "_apikey", "-apikey", "_api_key", "-api-key",
)

_SEGMENT_SPLIT = re.compile(r"[_\-.]+")


def redact_header(name: str, value: str) -> str:
    """Return ``value`` unless ``name`` is a known credential header, in which case
    the placeholder. The name is preserved so the archive still records THAT the
    header was sent, just not its bytes."""
    return MASK if name.strip().lower() in SENSITIVE_HEADERS else value


def is_secret_key(key: str) -> bool:
    """True if a structured-log field name marks its value as a secret. Matches on
    exact names, unambiguous whole SEGMENTS, and secret SUFFIXES — never a bare
    substring, so credential fields (`authorization`, `access_token`, `api_key`,
    `session_cookie`, `client_secret`) mask while telemetry that merely contains a
    secret word (`tokens_in`, `tokens_out`, `token_max`, `token_count`) and plain
    identifiers (`cache_key`, `keyword`) are left intact."""
    k = key.strip().lower()
    if k in _EXACT_SECRET_KEYS:
        return True
    if any(seg in _STRONG_SECRET_SEGMENTS for seg in _SEGMENT_SPLIT.split(k)):
        return True
    return k.endswith(_SECRET_SUFFIXES)


def _scrub_value(v: Any) -> Any:
    """Recurse a value: a nested dict is scrubbed by key; a LIST is scrubbed element-wise (a credential
    under a secret key inside a list-of-dicts — a realistic structlog header capture — would otherwise slip
    through, since the old scrubber recursed into dicts but not lists). Any other value passes through."""
    if isinstance(v, dict):
        return scrub_log_event(v)
    if isinstance(v, list):
        return [_scrub_value(x) for x in v]
    return v


def scrub_log_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a structlog event dict with every secret-keyed field's value replaced by the
    placeholder, recursing into nested dicts AND lists. Deterministic and total: an unrecognised value is
    passed through unchanged."""
    out: dict[str, Any] = {}
    for k, v in event.items():
        if isinstance(k, str) and is_secret_key(k):
            out[k] = MASK
        else:
            out[k] = _scrub_value(v)
    return out
