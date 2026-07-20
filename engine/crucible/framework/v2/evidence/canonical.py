"""
evidence.canonical — deterministic canonical bytes + digests for evidence integrity.

A signature is over BYTES, and a digest binds a certificate to the EXACT evidence it
was judged on. Both need one canonical form, identical for producer and verifier. We
reuse the same discipline the entitlement/authority layers use (sorted-key compact
UTF-8 JSON with a domain-separation prefix), so an evidence signature can never be
replayed as an entitlement/authority/revocation signature and vice versa.

Domain tag is versioned and load-bearing: changing it invalidates every existing
evidence signature, so it never changes without a schema bump + migration.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

# Never change without a schema_version bump + migration (invalidates all evidence sigs).
_EVIDENCE_DOMAIN: Final[bytes] = b"crucible-evidence-v1\x00"


def canonical_json(payload: Any) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys (recursive), compact separators. The one
    form producer and verifier agree on."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_payload(payload: Any) -> str:
    """sha256 of a JSON-serialisable payload in canonical form — binds a certificate to
    the exact bytes of (e.g.) an oracle_context."""
    return sha256_hex(canonical_json(payload))


def evidence_signing_bytes(certificate_payload: dict[str, Any]) -> bytes:
    """The exact bytes an authoriser signs / a verifier checks for an evidence
    certificate (the certificate's canonical JSON under the evidence domain tag)."""
    return _EVIDENCE_DOMAIN + canonical_json(certificate_payload)
