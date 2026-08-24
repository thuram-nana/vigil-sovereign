"""VSCP authorization issuance — a facade over the RBAC-of-record and the findings boundary.

VSCP's control-plane actions (registering a deployment or a trust authority, issuing or
revoking an authorization) authorize through :func:`authorize_action`, a facade in the
``sovereign_bridge`` sense: it SEQUENCES existing deciders and returns the composed
verdict. The two gates are

  1. the findings boundary (:func:`vscp.findings_boundary.finding_boundary_gate`) — a
     control-plane action may never be a covert assessment-finding read; and
  2. the RBAC-of-record (:func:`vigil_core.rbac.role_can`) — the reviewer (read-only
     ``viewer``) is refused every write.

:func:`issue_authorization` is the full mint: it authorizes first (fail-closed — a refused
authorization signs NOTHING), then binds the decision into a signed, hash-chained
authorization record using VSCP's OWN Ed25519 signing key (from :mod:`vscp.config`, never
the product's) over VSCP's OWN chain — isolated signing, reusing the ``vigil_core`` crypto
primitives rather than reimplementing them.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from vigil_core.canonical import digest_payload
from vigil_core.chain import append_entry
from vigil_core.crypto import KeyPair, generate_keypair, sign, verify_one
from vigil_core.models import ChainEntry
from vigil_core.rbac import role_can

from .config import VscpConfig
from .findings_boundary import finding_boundary_gate
from .gate import Decision, Gate, GateOutcome, compose
from .rbac_routes import READ, WRITE

__all__ = [
    "PermissionRefused",
    "action_permission",
    "authorize_action",
    "load_or_create_signing_key",
    "AuthorizationRecord",
    "issue_authorization",
]

# The write actions of the control plane. Anything not listed is treated as a read
# (requiring only ``read``), so a NEW mutating action must be added here or it defaults to
# read-tier — but the route layer (rbac_routes) is the per-route enforcement of record;
# this map governs the programmatic issuance path.
_WRITE_ACTIONS = frozenset(
    {
        "register_deployment",
        "register_trust_authority",
        "issue_authorization",
        "revoke_authorization",
    }
)


class PermissionRefused(PermissionError):
    """Raised by the strict helpers when a role lacks the permission an action requires."""


def action_permission(action: str) -> str:
    """The permission an action requires: WRITE for a mutating action, else READ."""
    return WRITE if action in _WRITE_ACTIONS else READ


def _rbac_gate(role: str | None, action: str) -> Gate:
    perm = action_permission(action)

    def decide(_request: Any) -> GateOutcome:
        if role_can(role, perm):
            return GateOutcome(allow=True, reason=f"role {role!r} holds {perm!r}", code="RBAC_OK")
        return GateOutcome(
            allow=False,
            reason=f"role {role!r} lacks {perm!r} required for {action!r}",
            code="RBAC_DENY",
        )

    return Gate("rbac", decide)


def authorize_action(
    *, role: str | None, action: str, request: Mapping[str, Any] | None = None
) -> Decision:
    """Compose the VSCP authorization facade for ``action`` by ``role`` and return the
    verdict. Gate order: findings boundary first (an action referencing a finding is
    refused before anything else), then RBAC. Every DENY names the gate that produced it."""
    req = dict(request or {})
    gates = [Gate("findings_boundary", finding_boundary_gate), _rbac_gate(role, action)]
    return compose(req, gates)


# --------------------------------------------------------------------------------------
# Isolated signing material — VSCP's OWN key, at VSCP's OWN path (config, validated
# disjoint from every product data root). Reuses vigil_core Ed25519; never the product key.
# --------------------------------------------------------------------------------------
def load_or_create_signing_key(config: VscpConfig) -> KeyPair:
    """Load the VSCP signing keypair from ``config.signing_key_path``, creating it (0600)
    if absent. The path was validated at config construction to be outside every product
    data root, so this can never read or write the product's owner key."""
    path = Path(config.signing_key_path)
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        return KeyPair(public_key_b64=data["public_key_b64"], private_key_b64=data["private_key_b64"])
    config.ensure_data_dir()
    kp = generate_keypair()
    path.parent.mkdir(parents=True, exist_ok=True)
    # write 0600 via atomic replace
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps({"public_key_b64": kp.public_key_b64, "private_key_b64": kp.private_key_b64}),
        encoding="utf-8",
    )
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return kp


@dataclass(frozen=True)
class AuthorizationRecord:
    """A minted authorization: the decision + subject/action, digest, VSCP signature, and
    its position on VSCP's own hash-chain. Offline-verifiable with the public key alone."""

    seq: int
    subject: str
    action: str
    scope: str
    effect: str
    issued_at: int
    digest: str
    signature_b64: str
    signer_public_key_b64: str
    chain_entry: ChainEntry

    def core(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "subject": self.subject,
            "action": self.action,
            "scope": self.scope,
            "effect": self.effect,
            "issued_at": self.issued_at,
        }

    def verify(self) -> bool:
        """Re-derive the digest and check the signature — offline, key-only."""
        expected = digest_payload(self.core())
        if expected != self.digest:
            return False
        return verify_one(self.signer_public_key_b64, self.digest.encode("ascii"), self.signature_b64)


def issue_authorization(
    *,
    role: str | None,
    subject: str,
    scope: str,
    config: VscpConfig,
    prior_entries: list[ChainEntry] | None = None,
    request: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> AuthorizationRecord:
    """Mint a signed authorization for ``subject`` over ``scope``, issued by ``role``.

    FAIL-CLOSED: authorize first (``issue_authorization`` action). A reviewer, or any role
    lacking WRITE, is refused with :class:`PermissionRefused` and NOTHING is signed. A
    request that references an assessment finding is likewise refused by the boundary gate.
    On ALLOW, the record is signed with VSCP's own key and appended to VSCP's own chain.
    """
    decision = authorize_action(role=role, action="issue_authorization", request=request)
    if not decision.allowed:
        raise PermissionRefused(
            f"authorization issuance refused by gate {decision.denied_by!r}: {decision.reason}"
        )
    kp = load_or_create_signing_key(config)
    entries = list(prior_entries or [])
    seq = (entries[-1].seq + 1) if entries else 0
    issued_at = int(now if now is not None else time.time())
    core = {
        "seq": seq,
        "subject": subject,
        "action": "issue_authorization",
        "scope": scope,
        "effect": decision.effect,
        "issued_at": issued_at,
    }
    digest = digest_payload(core)
    signature_b64 = sign(kp.private_key_b64, digest.encode("ascii"))
    entry = append_entry(entries, digest)
    return AuthorizationRecord(
        seq=seq,
        subject=subject,
        action="issue_authorization",
        scope=scope,
        effect=decision.effect,
        issued_at=issued_at,
        digest=digest,
        signature_b64=signature_b64,
        signer_public_key_b64=kp.public_key_b64,
        chain_entry=entry,
    )
