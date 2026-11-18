"""Shard-assignment schema, canonical signing bytes, and an owner-side signer (Front C S2a).

The FATAL-2-clean integrity core for a SHARD ASSIGNMENT — the SOVEREIGN record that one tenant
(``tenant_id``, which equals ``org_id`` equals the ``CRUCIBLE_TENANT`` id) is placed on ONE ``shard_id`` at a
monotonic ``epoch``. Defined ONCE here in the shared core so the sovereign plane (which holds the owner key and
mints the record in the Provisioner) and the keyless routing edge (which VERIFIES the identical bytes before it
directs a tenant's requests/jobs to a shard) agree BY CONSTRUCTION over the exact bytes, never by a drift-catching
test. Mirrors ``connected_repo_record.py`` / ``monitoring_authority.py`` exactly (same canonical form, same
fail-closed verify).

A shard assignment is a DISTINCT capability from every other signed purpose: the distinct domain tag
(``shard-assignment`` in :data:`spine_domains.DOMAIN_TAGS`) makes that separation CRYPTOGRAPHIC — a
shard-assignment signature can never satisfy an ownership-proof, monitoring, credit-lease, connected-repo or
engagement-authority check, or vice-versa.

The ``epoch`` lives INSIDE the owner-signed canonical bytes and is bumped on every live migration, so a consumer
holding a route minted at an older epoch can detect it is STALE and fail closed (the authoritative assignment has
moved on). ``issued_at`` is the per-tenant anti-replay high-water: a captured assignment can never resurrect a
tenant onto a shard it was migrated off, because its ``issued_at`` sits at or below the high-water. ``tenant_id``
and ``shard_id`` are each validated as a SAFE single path component (no separator / ``..`` traversal / absolute
path / NUL) so an assignment can never map a tenant to a shard-root path that escapes its parent.

Pure, validated data + Ed25519 over a domain-separated canonical core — the owner private key is used only inside
:func:`sign` and is never persisted or returned.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# Domain-separation prefix — distinct from authority / monitoring / connected-repo / credit-lease / every other
# signed purpose, so a shard-assignment signature can never be replayed as (or satisfied by) any other kind.
# Sourced from the ONE registry; never change without a schema bump + migration (it invalidates every signature).
_SHARD_ASSIGNMENT_DOMAIN = DOMAIN_TAGS["shard-assignment"]

# A SAFE single path component: an alphanumeric start then [A-Za-z0-9._-], max 64 chars. This is the SAME shape
# the engine's ``common/paths.py`` ``_TENANT_RE`` enforces for a ``CRUCIBLE_TENANT`` id (a tenant_id == org_id ==
# CRUCIBLE_TENANT), replicated here (the engine module is offense-side and MUST NOT be imported across FATAL-2) and
# kept byte-identical by ``tests/test_shard_assignment_record.py::test_tenant_re_in_lockstep_with_engine_paths``.
# Forbidding separators / ``.``/``..`` traversal / absolute paths / NUL by construction, so neither a tenant_id nor
# a shard_id can ever name a shard-root path that escapes its parent.
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def check_tenant_component(value: object, *, label: str) -> str:
    """Validate ``value`` as a safe single path component (fail-closed ``ValueError``). ``label`` names the field
    for the error. Used for both ``tenant_id`` and ``shard_id`` so neither can traverse a directory."""
    v = str(value or "").strip()
    if not _TENANT_RE.fullmatch(v):
        raise ValueError(
            f"{label} must be a safe single path component: an alphanumeric start then [A-Za-z0-9._-], "
            f"max 64 chars, no separators / '.'/'..' traversal / absolute path / NUL")
    return v


class ShardAssignmentRecord(BaseModel):
    """The per-tenant shard placement the routing edge verifies before it directs a tenant to a shard."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, description="The tenant this assignment places (tenant_id == org_id == "
                           "CRUCIBLE_TENANT); a safe single path component.")
    shard_id: str = Field(min_length=1, description="The shard that owns this tenant; a safe single path "
                          "component (the shard's base directory is named by it at deploy).")
    epoch: int = Field(ge=1, description="Monotonic placement generation, bumped on every live migration. Inside "
                       "the signed bytes so a route minted at an older epoch is detectably STALE and fails closed.")
    issued_at: float = Field(default=0.0, description="Mint anchor / per-tenant anti-replay high-water on the "
                             "minting spine (a captured assignment cannot resurrect a migrated-off placement).")
    state: str = Field(default="assigned", description="'assigned' (the active placement) — a tenant is removed "
                       "from the fleet by the SAFE unsigned 'unassigned' tombstone on the spine, not by this field.")
    note: str = Field(default="")

    @field_validator("tenant_id")
    @classmethod
    def _check_tenant(cls, v: str) -> str:
        return check_tenant_component(v, label="tenant_id")

    @field_validator("shard_id")
    @classmethod
    def _check_shard(cls, v: str) -> str:
        return check_tenant_component(v, label="shard_id")

    @field_validator("state")
    @classmethod
    def _check_state(cls, v: str) -> str:
        if v != "assigned":
            raise ValueError("a signed shard-assignment record's state must be 'assigned' (removal is the "
                             "unsigned 'unassigned' tombstone, the safe direction)")
        return v


class SignedShardAssignmentRecord(BaseModel):
    """A shard-assignment record plus governance signatures over its canonical form, verified against the owner
    ``TrustRoot``. A tampered tenant / shard / epoch / issued_at is detected (every field is in the signed bytes)."""

    model_config = ConfigDict(extra="forbid")

    document: ShardAssignmentRecord
    signatures: list[Signature] = Field(min_length=1)


def shard_assignment_signing_bytes(record: ShardAssignmentRecord) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the domain tag followed by the compact, sorted-key
    UTF-8 JSON of the document (byte-identical shape to ``connected_repo_signing_bytes`` / monitoring / lease)."""
    return _SHARD_ASSIGNMENT_DOMAIN + canonical_json(record.model_dump(mode="json"))


def sign_shard_assignment_record(document: ShardAssignmentRecord, signers: dict[str, str]) -> SignedShardAssignmentRecord:
    """Sign a shard-assignment record with each ``key_id -> private_key_b64``. Sovereign-side (the OWNER signs);
    the private key is used only inside :func:`sign` and never persisted or returned."""
    msg = shard_assignment_signing_bytes(document)
    signatures = [Signature(key_id=key_id, signature_b64=sign(priv_b64, msg)) for key_id, priv_b64 in signers.items()]
    return SignedShardAssignmentRecord(document=document, signatures=signatures)


def verify_shard_assignment_record(signed: SignedShardAssignmentRecord, trust_root: TrustRoot) -> "tuple[bool, str]":
    """Return ``(ok, reason)``. True iff at least the threshold of DISTINCT trust-root authorisers validly signed
    the record's canonical form. Verify-only (no private material; safe on the keyless routing edge). Fail-CLOSED
    and contract-honouring: never raises. Rejects a quorum-collapsing trust root (duplicate authorizer public keys
    under distinct key_ids) exactly as the authority / monitoring / connected-repo primitives do, and a malformed /
    weak-key signature is a refusal, never an uncaught crash in the fold."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(shard_assignment_signing_bytes(signed.document), signed.signatures, trust_root)
    except (IntegrityError, TypeError, ValueError) as e:   # ValueError: a document that cannot be UTF-8 encoded
        return False, f"shard-assignment signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
