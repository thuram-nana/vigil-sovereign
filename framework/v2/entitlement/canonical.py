"""
entitlement.canonical — deterministic canonical bytes for signing.

A signature is over bytes, not over a Python object. Signer and
verifier must agree on the exact bytes. We define the canonical form
as UTF-8 JSON with:

  - keys sorted lexicographically, recursively;
  - no insignificant whitespace (compact separators);
  - datetimes serialised by Pydantic to RFC 3339 strings (mode="json");
  - enums serialised to their string values (mode="json");
  - a domain-separation prefix so an entitlement signature can never be
    replayed as a revocation signature (or vice versa).

The prefix is part of the signed bytes. It binds the signature to a
document *kind*, which is the cheap, standard defence against
cross-protocol signature reuse.

This module is intentionally tiny and dependency-light: the canonical
form must be auditable in one read and stable across versions.
"""

from __future__ import annotations

import json
from typing import Final

from .models import EntitlementDocument, RevocationDocument

# Domain-separation tags. Never change these without a schema_version
# bump and a migration: changing a tag invalidates every existing
# signature over that document kind.
_ENTITLEMENT_DOMAIN: Final[bytes] = b"crucible-entitlement-v1\x00"
_REVOCATION_DOMAIN: Final[bytes] = b"crucible-revocation-v1\x00"


def _canonical_json(payload: dict[str, object]) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, compact separators."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def entitlement_signing_bytes(document: EntitlementDocument) -> bytes:
    """The exact bytes an authoriser signs / a verifier checks for an
    entitlement document."""
    body = _canonical_json(document.model_dump(mode="json"))
    return _ENTITLEMENT_DOMAIN + body


def revocation_signing_bytes(document: RevocationDocument) -> bytes:
    """The exact bytes signed / checked for a revocation document."""
    body = _canonical_json(document.model_dump(mode="json"))
    return _REVOCATION_DOMAIN + body
