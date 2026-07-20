"""
authority.canonical — deterministic signing bytes for an authority.

Governance authorisers sign an engagement authority so a tampered scope,
window, or destructive flag is detectable. The canonical form mirrors the
entitlement layer's: compact, sorted-key UTF-8 JSON with a
domain-separation prefix distinct from the entitlement, revocation, and
proposal domains — so an authority signature can never be replayed as any
other kind of signature.
"""

from __future__ import annotations

import json
from typing import Final

from .models import EngagementAuthority

_AUTHORITY_DOMAIN: Final[bytes] = b"crucible-authority-v1\x00"


def authority_signing_bytes(authority: EngagementAuthority) -> bytes:
    """The exact bytes an authoriser signs / a verifier checks."""
    body = json.dumps(
        authority.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _AUTHORITY_DOMAIN + body
