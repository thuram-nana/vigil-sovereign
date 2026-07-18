"""SIGIL's vendored integrity substrate (owner's own CRUCIBLE work, copied verbatim).

The one seam that would ever couple to the engine — now fully self-contained. SIGIL
imports NO `framework.*` module at all, which is the strongest form of the sovereignty
doctrine (§1.3 / §12): the offensive engine cannot even be loaded into a SIGIL process.
`assert_no_offense()` proves it.
"""
from __future__ import annotations

import sys

from .canonical import canonical_json, digest_payload, evidence_signing_bytes, sha256_hex
from .chain import append_entry, build_chain, sign_head, verify_chain, verify_head
from .crypto import generate_keypair, sign, verify_one, verify_threshold, KeyPair
from .models import AuthorizerKey, ChainEntry, Signature, SignedChainHead, TrustRoot

__all__ = [
    "canonical_json", "digest_payload", "evidence_signing_bytes", "sha256_hex",
    "append_entry", "build_chain", "sign_head", "verify_chain", "verify_head",
    "generate_keypair", "sign", "verify_one", "verify_threshold", "KeyPair",
    "AuthorizerKey", "ChainEntry", "Signature", "SignedChainHead", "TrustRoot",
    "assert_no_offense",
]


def assert_no_offense() -> None:
    """Fail-closed: NO framework.* module may be loaded in a SIGIL process (doctrine §12)."""
    leaked = [m for m in sys.modules if m == "framework" or m.startswith("framework.")]
    if leaked:
        raise RuntimeError(f"SIGIL sovereignty violation: engine modules loaded: {leaked}")
