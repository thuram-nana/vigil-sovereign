"""Deterministic canonical bytes + digests for spine integrity.

VENDORED VERBATIM from CRUCIBLE `framework/v2/evidence/canonical.py` (owner's own work).
Copied — not imported — so SIGIL owns its integrity primitives, fully decoupled from the
offensive engine's environment (sovereignty doctrine). Behaviour is byte-identical.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Final

# Never change without a schema bump + migration (invalidates all existing signatures).
_EVIDENCE_DOMAIN: Final[bytes] = b"crucible-evidence-v1\x00"


def canonical_json(payload: Any) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys (recursive), compact separators."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_payload(payload: Any) -> str:
    """sha256 of a JSON-serialisable payload in canonical form."""
    return sha256_hex(canonical_json(payload))


def evidence_signing_bytes(certificate_payload: dict[str, Any]) -> bytes:
    """The exact bytes signed/verified (canonical JSON under the domain tag)."""
    return _EVIDENCE_DOMAIN + canonical_json(certificate_payload)
