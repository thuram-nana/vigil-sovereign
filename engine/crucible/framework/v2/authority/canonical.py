"""
authority.canonical — deterministic signing bytes for an authority.

Governance authorisers sign an engagement authority so a tampered scope, window, or destructive flag is
detectable. The canonical form + the signer now live in the shared integrity core
(``vigil_core.authority``) so the SOVEREIGN plane can produce byte-identical signing input WITHOUT
importing ``framework`` (the two-env boundary, FATAL-2). This module re-exports them, so every framework
caller of ``authority_signing_bytes`` keeps resolving against the SINGLE source of truth — the sovereign
signer and this engine's verifier agree by construction, not by a drift-catching test.

Behaviour is byte-identical to the prior framework-local form: the same domain-separation prefix
(distinct from the entitlement, revocation, and proposal domains) followed by compact, sorted-key UTF-8
JSON — so authorities signed before this lift still verify.
"""

from __future__ import annotations

from vigil_core.authority import _AUTHORITY_DOMAIN, authority_signing_bytes

__all__ = ["authority_signing_bytes", "_AUTHORITY_DOMAIN"]
