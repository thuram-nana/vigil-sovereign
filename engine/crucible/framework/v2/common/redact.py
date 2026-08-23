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

from vigil_core.redact import (
    MASK,
    SENSITIVE_HEADERS,
    is_secret_key,
    redact_header,
    redact_log_message,
    scrub_log_event,
)

__all__ = [
    "MASK",
    "SENSITIVE_HEADERS",
    "is_secret_key",
    "redact_header",
    "redact_log_message",
    "scrub_log_event",
]
