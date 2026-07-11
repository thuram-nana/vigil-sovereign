"""
api.authn — OPTIONAL bearer / relay-key hardening for the loopback API.

DEFAULT-SAFE: with no key configured (the default) this is a NO-OP — the API's
loopback bind and same-origin POST guard are unchanged and every existing caller
keeps working. It is ADDITIVE hardening for the ONE scenario the loopback bind does
not cover: an operator who deliberately FRONTS the API behind a reverse proxy /
tunnel. Then a shared secret gates EVERY request (read AND action), fail-closed, so
exposure past loopback still requires the key. The loopback + same-origin guards are
never relaxed by this — the key is stacked ON TOP of them, never in place of them.

The key mirrors the OOB relay's ``X-Relay-Key`` discipline: it travels in a request
HEADER (never the query string, so it never lands in a proxy access log), is compared
in CONSTANT TIME (``hmac.compare_digest``), and is accepted either as a standard bearer
token (``Authorization: Bearer <key>``) or the ``X-Relay-Key`` header.

Configuration is opt-in via the ``CRUCIBLE_API_KEY`` environment variable (or an
explicit ``serve(api_key=...)`` for tests / an embedder). A blank/whitespace value is
treated as UNSET (no enforcement) — the key must be a real secret to take effect, so a
misconfigured empty key never silently disables auth while looking configured.
"""

from __future__ import annotations

import hmac
import os

# opt-in configuration. Unset (or blank) → no enforcement (the default no-op).
ENV_VAR = "CRUCIBLE_API_KEY"

_BEARER_HEADER = "Authorization"
_RELAY_KEY_HEADER = "X-Relay-Key"
_BEARER_PREFIX = "bearer "


def load_api_key(explicit: str | None = None) -> str | None:
    """The configured API key, or ``None`` when unset (the default → no enforcement).

    ``explicit`` (tests / an embedder) overrides the environment. A blank/whitespace
    value is treated as UNSET so an empty key never silently disables enforcement while
    appearing configured."""
    raw = explicit if explicit is not None else os.environ.get(ENV_VAR)
    if raw is None:
        return None
    key = raw.strip()
    return key or None


def _presented_key(headers) -> str:
    """The key the request presents, from ``Authorization: Bearer <k>`` OR ``X-Relay-Key``.
    Fail-closed: anything malformed yields ``''`` (which cannot match a real key)."""
    auth = (headers.get(_BEARER_HEADER, "") or "").strip()
    if auth.lower().startswith(_BEARER_PREFIX):
        return auth[len(_BEARER_PREFIX):].strip()
    return (headers.get(_RELAY_KEY_HEADER, "") or "").strip()


def check_api_key(headers, configured: str | None) -> tuple[bool, str]:
    """Return ``(ok, reason)``.

    When no key is configured, always ``(True, "")`` — the default no-op. When a key IS
    configured, the request must present a matching key (constant-time compare); a
    missing or mismatched key is REFUSED (fail-closed). ``headers`` is a mapping with a
    case-insensitive ``.get`` (an ``http.client.HTTPMessage`` / dict)."""
    if not configured:
        return True, ""
    presented = _presented_key(headers)
    if not presented:
        return False, "missing API key (Authorization: Bearer <key> or X-Relay-Key)"
    if not hmac.compare_digest(presented, configured):
        return False, "invalid API key"
    return True, ""
