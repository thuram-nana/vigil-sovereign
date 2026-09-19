"""
common.redact — deterministic masking of secrets before they touch disk (Speed X2).

The redaction logic now lives in ONE shared home, ``vigil_core.redact`` (W6-5), so the offense engine,
the sovereign SIGIL plane and the host gateway all mask with the SAME helper instead of forking three
copies. This module is a thin re-export of that shared source: every symbol offense code and its tests
already import (``MASK``, ``scrub_log_event``, ``is_secret_key``, ``redact_header``,
``SENSITIVE_HEADERS``) resolves to the shared implementation, so offense behaviour is byte-identical
while the single source of truth is maintained once. ``vigil_core`` imports no ``framework.*`` /
``strix.*`` / ``sigil.*``, so re-exporting it crosses no FATAL-2 boundary.

Scope (unchanged): mask by credential HEADER NAME / structured-log KEY, and by credential SHAPE in a
free-text log message — never by scanning a response body for "token-like" substrings, which would
destroy the very proof a finding rests on. The raw evidence body is protected instead by owner-only
(0600) permissions.
"""

from __future__ import annotations

import re

from vigil_core.redact import (
    MASK,
    SENSITIVE_HEADERS,
    is_secret_key,
    redact_header,
    redact_log_message,
    scrub_log_event,
)

# JSON-aware VALUE masker — the FRAMEWORK-LOCAL complement to ``redact_log_message`` above, which masks
# form-encoded ``k=v`` / ``Bearer`` / credential-header shapes but NOT JSON (``"password":"hunter2"`` slips
# through: the quote after the key breaks its ``name[:=]value`` grammar). The offense engage executor can
# transmit a JSON request BODY whose redacted preview is shown to the owner for consent AND written to the
# owner-only engagement log, so a credential VALUE under a secret KEY must be masked while non-secret keys
# (role, amount, email, username, …) stay VISIBLE for informed consent.
# FATAL-2: defined here in ``framework`` with stdlib ``re`` only — it adds NO ``vigil_integration`` import
# (importing the broker's ``_redact_str`` would cross the two-env boundary), and mirrors the value-masker
# pattern already used by ``report.dossier._redact_value_secrets``.
_JSON_SECRET_KEY = (
    r"password|passwd|pwd|access_token|refresh_token|token|client_secret|secret|"
    r"api_key|apikey|authorization|auth|cookie|session|credential|private_key|key"
)
_JSON_SECRET_RE = re.compile(
    r'("(?:' + _JSON_SECRET_KEY + r')"\s*:\s*)'      # g1: the "secretkey" :   (case-insensitive, any spacing)
    r'("(?:[^"\\]|\\.)*"|[^\s,}\]]+)',               # g2: a JSON string value (escape-aware) OR a bare scalar
    re.IGNORECASE,
)


def redact_json_secrets(text):
    """Mask the VALUE of any JSON key whose NAME is a known credential (case-insensitive) — for both
    ``"k":"v"`` and ``"k": "v"`` spacing, and for string OR bare-scalar values — while leaving NON-secret
    keys (role, amount, price, qty, email, username, …) visible so a human reviewer still sees the
    security-relevant content. Best-effort pattern matching over a JSON-ish string; non-str passes through
    unchanged; deterministic + idempotent."""
    if not isinstance(text, str) or not text:
        return text
    return _JSON_SECRET_RE.sub(lambda m: m.group(1) + '"' + MASK + '"', text)


__all__ = [
    "MASK",
    "SENSITIVE_HEADERS",
    "is_secret_key",
    "redact_header",
    "redact_json_secrets",
    "redact_log_message",
    "scrub_log_event",
]
