"""SIGIL's integrity substrate — now the shared `vigil_core` (VIGIL monorepo, source of truth).

SIGIL re-exports the primitives from `vigil_core` instead of carrying its own copy (the duplicate is gone).
On top of the shared core it keeps its sovereignty guard: `assert_no_offense()` — the offense-free-by-
construction guarantee — which forbids loading ANY offense-engine module into a SIGIL (env-sovereign)
process. In the VIGIL monorepo that now means BOTH the CRUCIBLE engine (`framework.*`) AND the Strix agent
body (`strix.*`). The guard lives HERE, not in `vigil_core`, precisely because CRUCIBLE (an offense engine)
depends on the same shared core.
"""
from __future__ import annotations

import sys

from vigil_core import (
    AuthorizerKey,
    ChainEntry,
    IntegrityError,
    KeyPair,
    Signature,
    SignedChainHead,
    TrustRoot,
    append_entry,
    build_chain,
    canonical_json,
    digest_payload,
    evidence_signing_bytes,
    generate_keypair,
    sha256_hex,
    sign,
    sign_head,
    verify_chain,
    verify_head,
    verify_one,
    verify_threshold,
)

__all__ = [
    "canonical_json", "digest_payload", "evidence_signing_bytes", "sha256_hex",
    "append_entry", "build_chain", "sign_head", "verify_chain", "verify_head",
    "generate_keypair", "sign", "verify_one", "verify_threshold", "KeyPair", "IntegrityError",
    "AuthorizerKey", "ChainEntry", "Signature", "SignedChainHead", "TrustRoot",
    "assert_no_offense",
]

# offense-engine namespaces barred from any SIGIL (env-sovereign) process.
_OFFENSE_NAMESPACES = ("framework", "strix")


def assert_no_offense() -> None:
    """Fail-closed: NO offense-engine module may be loaded in a SIGIL process (sovereignty doctrine §12) —
    neither the CRUCIBLE engine (`framework.*`) nor the Strix agent body (`strix.*`)."""
    leaked = [m for m in sys.modules
              if m in _OFFENSE_NAMESPACES or any(m.startswith(ns + ".") for ns in _OFFENSE_NAMESPACES)]
    if leaked:
        raise RuntimeError(f"SIGIL sovereignty violation: offense modules loaded: {leaked}")
