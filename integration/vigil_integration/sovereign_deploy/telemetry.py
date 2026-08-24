"""
sovereign_deploy.telemetry — schema-ALLOWLISTED telemetry with an explicit NO-COLLECT list (W13-8).

Property 4 of the sovereign / air-gapped deployment slice (#501): any telemetry that could ever leave the
box passes through a SCHEMA ALLOWLIST — only field names on :data:`TELEMETRY_SCHEMA_ALLOWLIST` are emitted,
everything else is dropped (allowlist, not denylist: an unknown field is dropped by default, so a new field
cannot silently start leaking) — AND an explicit :data:`NO_COLLECT_FIELDS` list of names that must NEVER be
emitted (operator identity, target addresses, credentials/secrets, evidence bodies, PII). The two lists are
DISJOINT by construction (a field cannot be both collectable and no-collect), asserted at import and pinned
by a test.

This is the emission-time complement to the existing collector (``vigil_integration.telemetry``, a one-way
projection of the signed spine into a metrics snapshot) and the F3 redaction vocabulary
(``vigil_core.redact``). The collector decides WHAT is counted; this module decides what may LEAVE, and does
it by a positive allowlist plus a hard no-collect scrub applied at EVERY nesting level.

NEGATIVE CONTROL (the AC's own words): plant a no-collect-list field in the source data and assert it is
ABSENT from the emitted payload — proven by ``test_sovereign_deploy_telemetry.py``, which also asserts an
allowlisted field survives (so the scrubber is not simply emitting nothing) and that an unknown field is
dropped (allowlist semantics).

Import-clean (FATAL-2): stdlib only.
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = [
    "TELEMETRY_SCHEMA_ALLOWLIST",
    "NO_COLLECT_FIELDS",
    "schema_allowlist",
    "no_collect_fields",
    "build_telemetry_payload",
    "scrub_snapshot_for_export",
]

#: The ONLY field names permitted in emitted telemetry. Everything is aggregate metrics or non-identifying
#: build/state labels. Allowlist, not denylist: a field not named here is dropped, so adding data to an
#: upstream record cannot silently begin exporting it.
TELEMETRY_SCHEMA_ALLOWLIST: "frozenset[str]" = frozenset({
    # snapshot envelope
    "schema", "generated_at", "note",
    # aggregate counters (no content, just counts)
    "events", "facts", "leads", "refusals", "tool_calls", "messages", "findings",
    "by_kind", "last_event_id", "count",
    # structure
    "engagements", "totals",
    # a per-engagement OPAQUE LOCAL label (not a target address) — kept for per-engagement metrics
    "slug",
    # non-identifying build / deployment state labels
    "product_version", "build_id", "channel", "state", "installed", "operational",
})

#: Field names that must NEVER be emitted, at any nesting level — a hard scrub applied on top of the
#: allowlist (defense in depth). Identity, target addresses, credentials/secrets, raw evidence, PII.
NO_COLLECT_FIELDS: "frozenset[str]" = frozenset({
    # operator / machine identity
    "operator", "os_login", "git_name", "git_email", "hostname", "key_fingerprint", "username", "user",
    "fingerprint",
    # target / network locators
    "target", "target_url", "url", "host", "ip", "ip_address", "remote_addr", "source_ip", "address",
    # credentials / secrets / crypto material
    "credential", "credentials", "secret", "password", "passwd", "token", "api_key", "apikey",
    "authorization", "cookie", "session", "private_key", "signature", "signature_b64", "nonce", "mac",
    # raw payloads / evidence content
    "body", "body_excerpt", "raw", "raw_excerpt", "request", "response", "payload", "evidence",
    # personal data
    "pii", "email", "phone",
})


def _norm(key: object) -> str:
    return str(key).strip().lower()


# Normalised sets for O(1) case-insensitive membership tests.
_ALLOW = frozenset(_norm(k) for k in TELEMETRY_SCHEMA_ALLOWLIST)
_NOCOLLECT = frozenset(_norm(k) for k in NO_COLLECT_FIELDS)

# The DISJOINTNESS invariant: a field is either collectable or no-collect, never both. If this ever fires
# at import, a maintainer added a name to both lists — a real ambiguity that must be resolved, not shipped.
assert _ALLOW.isdisjoint(_NOCOLLECT), (
    "TELEMETRY_SCHEMA_ALLOWLIST and NO_COLLECT_FIELDS must be disjoint; overlap: "
    f"{sorted(_ALLOW & _NOCOLLECT)}"
)

# Allowlisted fields whose VALUE is an opaque count map (kind -> count). Their inner keys are a controlled
# event vocabulary (data labels, not schema fields), so they pass through — EXCEPT any inner label that
# matches a no-collect name, which is dropped, and only numeric counts are kept.
_OPAQUE_COUNT_MAPS = frozenset({"by_kind"})


def schema_allowlist() -> "frozenset[str]":
    """The emitted-telemetry field allowlist (a copy-safe frozenset)."""
    return TELEMETRY_SCHEMA_ALLOWLIST


def no_collect_fields() -> "frozenset[str]":
    """The explicit never-emit field list (a copy-safe frozenset)."""
    return NO_COLLECT_FIELDS


def _scrub_value(norm_key: str, value: Any) -> Any:
    if norm_key in _OPAQUE_COUNT_MAPS and isinstance(value, Mapping):
        return {
            str(ik): iv
            for ik, iv in value.items()
            if _norm(ik) not in _NOCOLLECT and isinstance(iv, (int, float)) and not isinstance(iv, bool)
        }
    if isinstance(value, Mapping):
        return _scrub_mapping(value)
    if isinstance(value, (list, tuple)):
        return [_scrub_mapping(e) if isinstance(e, Mapping) else e for e in value]
    return value


def _scrub_mapping(m: Mapping) -> dict:
    out: dict = {}
    for k, v in m.items():
        nk = _norm(k)
        if nk in _NOCOLLECT:      # hard no-collect scrub — wins even if a name were mistakenly allowlisted
            continue
        if nk not in _ALLOW:      # allowlist is primary: an unknown field is dropped by default
            continue
        out[str(k)] = _scrub_value(nk, v)
    return out


def build_telemetry_payload(source: Any) -> dict:
    """Return an emittable telemetry payload containing ONLY allowlisted, non-no-collect fields from
    ``source``, scrubbed recursively at every nesting level. A non-mapping source yields ``{}``.

    Guarantees, at every level: (1) a field whose name is not on :data:`TELEMETRY_SCHEMA_ALLOWLIST` is
    dropped; (2) a field whose name is on :data:`NO_COLLECT_FIELDS` is dropped even if it appears (defense in
    depth). So a planted no-collect field — anywhere in the structure, including inside an engagement row —
    is absent from the result. Total: never raises on odd input."""
    if not isinstance(source, Mapping):
        return {}
    return _scrub_mapping(source)


def scrub_snapshot_for_export(snapshot: Any) -> dict:
    """Convenience alias for :func:`build_telemetry_payload`, named for its call site: the last gate a
    ``vigil_integration.telemetry`` metrics snapshot passes through before it could leave the box."""
    return build_telemetry_payload(snapshot)
