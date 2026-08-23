"""
vigil_core.redact — deterministic masking of secrets before they touch a log or an at-rest sink.

This is the SINGLE, shared redaction helper for the whole monorepo (W6-5). It was historically
maintained only inside the offense engine (``framework/v2/common/redact.py``); that module now
re-exports THIS one, so the offensive side keeps byte-identical behaviour while the sovereign SIGIL
plane and the host gateway reuse the very same masker instead of forking their own. Because
``vigil_core`` is a member of BOTH isolated environments (env-sovereign and env-offense) and imports
NO ``framework.*``/``strix.*``/``sigil.*``, sharing it crosses no FATAL-2 boundary.

Two masking surfaces:

* ``scrub_log_event`` — masks the VALUE of any secret-keyed field in a structured (structlog / stdlib
  ``extra=``) event dict, recursing into nested dicts and lists. Matched by KEY name — never by scanning
  free text for "token-like" substrings — so telemetry that merely contains a secret word
  (``tokens_in``/``token_max``) and plain identifiers (``cache_key``) are left intact.
* ``redact_log_message`` — masks a secret VALUE embedded in a free-text log *message* (a ``Bearer``
  token, an ``Authorization`` / ``Cookie`` header line, or a ``secret_key=value`` assignment). The
  plain-text sovereign / gateway planes emit messages, not only structured fields, so a message-level
  masker is required for the negative control to hold in every plane.

Everything here is PURE + DETERMINISTIC — same input always yields the same output, no wallclock / rng —
so replay, calibration audits, and the evidence artifact manifest (which hashes ``.http`` files AFTER
masking) all stay self-consistent. Scope is deliberately conservative: it masks the credential that
authenticated a request or a secret-named field, not the vulnerability evidence a finding rests on.
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


# --------------------------------------------------------------------------------------------------
# Free-text message masking (W6-5). The plain-text planes emit a rendered MESSAGE string, so a secret
# can ride the message text itself (`log.warning("sent Authorization: Bearer %s", tok)`) where the
# key-name scrubber above never sees it. These three patterns mask the credential SHAPES that appear
# in a log line while leaving ordinary prose intact.
# --------------------------------------------------------------------------------------------------

# `Bearer <token>` anywhere (the token charset covers base64url / JWT / opaque tokens).
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=\-]+")

# A known credential HEADER name followed by `:` or `=` then its value, masked to end-of-line. These
# header names are unambiguously secret, so masking the whole value (cookies included, which use `;`
# internally) is correct and never eats non-secret prose.
_HEADER_VALUE_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(h) for h in sorted(SENSITIVE_HEADERS)) + r")(\s*[:=]\s*)([^\r\n]+)"
)

# A generic `name=value` / `name: value` assignment. The value is masked ONLY when the NAME is a secret
# key (reusing ``is_secret_key`` — the same vocabulary as the structured scrubber), so `password=hunter2`
# masks while `count=3` / `path=/tmp/x` do not.
_GENERIC_KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.\-]{0,63})(\s*[:=]\s*)(\"?[^\s\"';,&]+\"?)")


def redact_log_message(text: Any) -> Any:
    """Mask credential VALUES embedded in a free-text log message. Non-str input passes through
    unchanged. Deterministic; order-fixed so it is idempotent (masking twice yields the same string)."""
    if not isinstance(text, str) or not text:
        return text
    # 1) credential header values (mask the whole value, cookies included) — runs first so a later,
    #    broader pass never has to re-see a header value.
    s = _HEADER_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    # 2) `Bearer <token>` wherever it appears (e.g. an Authorization value already reduced, or a bare
    #    "Bearer ey..." in prose).
    s = _BEARER_RE.sub(lambda m: f"{m.group(1)} {MASK}", s)

    # 3) secret-named `key=value` assignments; the value is masked only when the name is a secret key.
    def _kv(m: "re.Match[str]") -> str:
        if is_secret_key(m.group(1)):
            return f"{m.group(1)}{m.group(2)}{MASK}"
        return m.group(0)

    return _GENERIC_KV_RE.sub(_kv, s)


__all__ = [
    "MASK",
    "SENSITIVE_HEADERS",
    "redact_header",
    "is_secret_key",
    "scrub_log_event",
    "redact_log_message",
]
