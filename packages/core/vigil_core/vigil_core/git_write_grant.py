"""GitWriteGrant — an owner-signed, repo-EXACT, per-capability authorization for GitHub WRITES.

The repo-connect PR-bot (Slice 3) may, when enabled, post review comments and open fix PRs. Authorizing
that is NOT a scan-scope decision — a writable repo is a capability, not a target — so (like the sibling
``DestructionAuthority``, and the ``oob_relay_host`` precedent) it is a SEPARATE owner-signed grant, NOT a
field on ``EngagementAuthority``. Keeping it separate means adding this capability does NOT change the
canonical bytes of any existing authority, so every already-provisioned signed authority keeps verifying
(no migration, no weakening of existing controls).

A grant names ONE engagement + ONE exact repo and carries per-capability bits (``allow_comment`` /
``allow_pr``), BOTH default False — so a grant authorizes only what the owner explicitly signed, and the
default (no grant, or an all-False grant) authorizes NOTHING. The owner threshold-signs the canonical core
under a distinct domain tag; the offense plane verifies the identical bytes. Pure validated data + Ed25519
over a domain-separated core — it reuses ``vigil_core``'s signer/verifier and makes no new crypto decision.

FATAL-2: lives in ``vigil_core`` (framework-free) so the SOVEREIGN plane owner-signs it with ``vigil_core``
alone and the OFFENSE plane verifies the same bytes — one definition, agreeing by construction.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot

#: EXACT ``host/org/repo`` (lowercased) — three concrete segments, no wildcard / org-wide / host-only form.
#: Enforces "exact repository AND organization matching": a grant names one org AND one repo, never a pattern.
_REPO_RE: Final = re.compile(r"^[a-z0-9.-]+/[a-z0-9._-]+/[a-z0-9._-]+$")

# Domain-separation prefix — DISTINCT from the authority / destruction / evidence / … domains, so a
# git-write-grant signature can never be replayed as any other kind. Never change without a schema bump.
_GIT_WRITE_DOMAIN: Final[bytes] = b"vigil-git-write-grant-v1\x00"

#: The write capabilities a grant may authorize, each a separate owner-signed bit (both default OFF).
GIT_WRITE_CAPABILITIES: Final[frozenset[str]] = frozenset({"comment", "pr"})


class GitWriteGrant(BaseModel):
    """An owner-signed grant to WRITE to one exact repo under one engagement. Separate read/comment/patch
    permissions: ``allow_comment`` and ``allow_pr`` are independent, both default False (off)."""

    model_config = ConfigDict(extra="forbid")

    engagement_slug: str = Field(min_length=1)
    repo: str = Field(min_length=1, description="The EXACT host/org/repo this grant authorizes writes to, "
                      "e.g. 'github.com/org/repo'. No org-wide / host-broad / wildcard patterns.")
    grant_id: str = Field(min_length=1, description="Unique id for the signed audit trail + exact-replay detection.")
    epoch: int = Field(ge=0, description="Monotonic per engagement. A grant whose epoch is BELOW the recorded "
                       "high-water is a replayed/superseded grant and is refused (supersession-replay protection).")
    issued_at: datetime
    not_before: datetime
    not_after: datetime
    allow_comment: bool = Field(default=False, description="May post PR review comments (lower risk, reversible).")
    allow_pr: bool = Field(default=False, description="May open fix pull requests (higher risk; also m-of-n-gated).")
    revoked: bool = Field(default=False, description="An owner-signed REVOCATION: a grant signed with revoked=True "
                          "(at a higher epoch) withdraws ALL write capability for the repo, superseding the grant.")

    @field_validator("repo", mode="before")
    @classmethod
    def _canon_repo(cls, v: object) -> str:
        # Normalize to the canonical lowercased form BEFORE signing, so the SIGNED value is byte-identical to
        # the value the gate matches against — no signed-vs-matched drift (red-pen LOW).
        return str(v or "").strip().lower()

    @model_validator(mode="after")
    def _check(self) -> "GitWriteGrant":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        if not _REPO_RE.match(self.repo.strip().lower()):
            raise ValueError("repo must be an EXACT host/org/repo (e.g. 'github.com/org/repo'); "
                             "no wildcard / org-wide / host-only patterns")
        return self


class SignedGitWriteGrant(BaseModel):
    """A :class:`GitWriteGrant` plus governance signatures over its canonical form, verified against the
    same ``TrustRoot`` the authority layer uses."""

    model_config = ConfigDict(extra="forbid")

    document: GitWriteGrant
    signatures: list[Signature] = Field(min_length=1)


def git_write_grant_signing_bytes(grant: GitWriteGrant) -> bytes:
    """The exact bytes an owner signs / a verifier checks: the domain tag + the compact, sorted-key UTF-8
    JSON of the document (the same canonical form the authority primitive uses, under a distinct domain)."""
    return _GIT_WRITE_DOMAIN + canonical_json(grant.model_dump(mode="json"))


def sign_git_write_grant(document: GitWriteGrant, signers: dict[str, str]) -> SignedGitWriteGrant:
    """Owner-sign a grant with each ``key_id -> private_key_b64`` (sovereign-side; the private key is used
    only inside :func:`sign`, never persisted/returned). The caller supplies at least the trust root's
    threshold of authorised signers."""
    msg = git_write_grant_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedGitWriteGrant(document=document, signatures=signatures)


def verify_git_write_grant(signed: SignedGitWriteGrant, trust_root: TrustRoot) -> tuple[bool, str]:
    """Return ``(ok, reason)`` — True iff at least the threshold of DISTINCT trust-root authorisers validly
    signed the grant's canonical form. Verify-only (no private material; safe on either plane). Fail-CLOSED,
    never raises: a quorum-collapsing trust root (duplicate authorizer public keys), or malformed/weak
    signature material, is a ``(False, reason)`` refusal — mirrors :func:`verify_engagement_authority`."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(git_write_grant_signing_bytes(signed.document), signed.signatures, trust_root)
    except IntegrityError as e:
        return False, f"git-write-grant signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
