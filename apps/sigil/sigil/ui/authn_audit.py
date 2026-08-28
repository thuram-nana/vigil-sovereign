"""Slice 1c — authentication / session audit events on the sovereign spine.

Login and logout transitions were previously UNRECORDED: a successful or failed owner/teammate login left
no trace on the spine. This appends an append-only, SECRET-FREE audit record for each transition, reusing
the same `store.append(kind="event", ...)` primitive the governor uses for account grants (so it is
chain-hashed and immutable like every other event).

SECRET DISCIPLINE (mirrors the accounts rule that only hashes/booleans reach the spine): a payload carries
ONLY the event name, the username (or "anonymous"), the login METHOD, the OUTCOME, and a coarse reason CODE
— NEVER a bearer, token, challenge, signature, password, or TOTP code.

BEST-EFFORT (fail-open on the AUDIT WRITE only): the auth DECISION has already been made and returned by the
caller; a spine hiccup while writing the side-record must NOT turn a valid login into a 500 or deny it. The
write is wrapped so it never raises out of the auth path. (The decision itself is never fail-open — that is
enforced in the login handlers, unchanged.)

Stdlib only — no framework/strix. Offense-free by construction.
"""
from __future__ import annotations

from typing import Optional

# Coarse, enumerated reason codes (no free-form / secret content ever).
REASON_INVALID_TOKEN = "invalid_token"
REASON_NO_IDENTITY = "no_identity"
REASON_CHALLENGE = "challenge"
REASON_SIGNATURE = "signature"
REASON_BAD_CREDENTIALS = "bad_credentials"
REASON_TOTP = "totp"

_AUTHN_SOURCE = "authn"


def record_authn(store, event: str, *, username: str = "", method: str = "", outcome: str = "",
                 reason: "Optional[str]" = None) -> None:
    """Append one secret-free authn audit event (`kind="event", source="authn"`). Never raises: an
    audit-write failure is swallowed so it cannot break the already-decided auth response."""
    try:
        # `username` is attacker-controllable (a failed-login submits an arbitrary username under the body
        # cap), so bound every field — a valid username is <=64 chars — so a hostile oversized value cannot
        # bloat the audit record. event/method/outcome/reason are server-chosen literals; capped defensively.
        payload = {
            "signal": "authn.audit",
            "event": str(event)[:64],
            "username": str(username or "anonymous")[:64],
            "method": str(method or "")[:32],
            "outcome": str(outcome or "")[:16],
        }
        if reason:
            payload["reason"] = str(reason)[:32]
        store.append(kind="event", source=_AUTHN_SOURCE, actor="cockpit", payload=payload)
    except Exception:  # noqa: BLE001 — a spine hiccup must not break the auth response (best-effort audit)
        pass
