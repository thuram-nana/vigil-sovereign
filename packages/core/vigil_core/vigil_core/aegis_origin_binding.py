"""AEGIS AS-2g — the owner-signed ORIGIN BINDING contract (the sovereign mints, the keyless plane verifies).

The "binding" half of AS-2g (binding + publish). AS-2f mints a v2 monitoring grant but leaves the tenant
origin OUT (``origin=None``, ``origin_binding_sha256=None`` — the explicit AS-2g seam in
:mod:`vigil_core.authority_v2`). AS-2g attaches the proven binding: a SEPARATE owner-signed document that binds
ONE subject to its declared HTTPS origin, its edge chain, and a sha256 COMMITMENT to the tenant's SEALED
origin-lock secret, and whose own sha256 is the ``origin_binding_sha256`` the grant carries. A grant is thereby
cryptographically bound to EXACTLY one published binding record; the per-tenant defence (the AS-2d broker's Z3
prover) reads the published binding and cross-checks it against the grant before it arms a forward target.

Defined ONCE here in the shared integrity core — exactly like :mod:`vigil_core.authority_v2` — so the SOVEREIGN
plane (which holds the owner key, provisions + seals the origin secret, and mints this record) and the keyless
AEGIS data plane (which verifies the identical published bytes before it forwards a tenant's traffic) agree BY
CONSTRUCTION, never by a drift-catching test. It REUSES the AS-2a :class:`AuthoritySubject` and
:class:`OriginTuple` so the authority and the binding never drift on what "the subject" or "the origin" is.

PUBLIC-REPO SAFE. The published binding carries NO plaintext secret: ``origin_secret_sha256`` is a DETERMINISTIC
domain-separated HMAC-SHA256 commitment (a keyed PRF — AS-2h ``vigil_core.aegis_sealing``'s ``secret_mac``) keyed
by the origin-lock secret, so the record reveals nothing a captor could use. It is NOT a sha256 of the sealed
ciphertext (the at-rest AEAD seal is nonce-randomised and non-reproducible); the data plane matches by recomputing
the SAME keyed PRF from the DELIVERED secret. (The field name keeps ``sha256`` for the HMAC-SHA256 primitive it is
built on, not to imply a bare hash of the secret or its ciphertext.)

Determinism: NO wallclock and NO global RNG anywhere on a signed or canonical path. Every time and epoch is a
caller-supplied field; the signing bytes and the binding digest are pure functions of the document. The digest
is taken over the SIGNING BYTES (domain tag + canonical document), independent of any particular signature — a
binding's identity is its CONTENT, so re-signing the same document yields the same ``origin_binding_sha256``.

Fail-closed: a grant with no origin, a binding that does not verify under the owner root, a subject / origin /
edge-chain mismatch, or a binding digest that is not the grant's ``origin_binding_sha256`` => the grant is
UNBOUND and :func:`grant_binds_origin` returns ``(False, reason)``; it never raises on hostile input.

FATAL-2: imports only ``vigil_core`` siblings + stdlib + pydantic. No ``framework``, no ``sigil`` — safe to
import on either plane.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Final, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .authority_v2 import AuthoritySubject, MonitoringAuthorityV2, OriginTuple, check_component
from .canonical import canonical_json
from .crypto import IntegrityError, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# The AS-2g origin-binding domain tag (NUL-terminated; distinct from the v2 grant / epoch / release / revocation
# tags). A binding signature can never replay as any of those, and vice-versa (domain separation).
_ORIGIN_BINDING_DOMAIN: Final[bytes] = DOMAIN_TAGS["aegis-origin-binding"]

_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


class AegisOriginBinding(BaseModel):
    """The per-subject owner-signed origin binding the keyless AEGIS plane cross-checks before it forwards.

    Binds the SAME ``subject`` and ``origin`` shapes the v2 grant declares (AS-2a reuse) to the ``edge_chain``
    and a keyed-PRF ``origin_secret_sha256`` commitment (HMAC-SHA256 over the origin-lock secret, no plaintext).
    The grant's ``origin_binding_sha256`` equals :func:`origin_binding_digest` of this document, so tampering
    with the origin, the edge chain or the commitment changes the digest and the grant is detectably unbound."""

    model_config = ConfigDict(extra="forbid")

    subject: AuthoritySubject
    origin: OriginTuple
    edge_chain: str = Field(default="shared_actor", description="The declared edge provider_id (a safe path "
                            "component), or the 'shared_actor' sentinel; MUST match the bound grant's edge_chain.")
    origin_secret_sha256: str = Field(min_length=64, max_length=64, description="A keyed-PRF commitment (64 "
                                      "lowercase hex) to the tenant's origin-lock secret: a DETERMINISTIC domain-"
                                      "separated HMAC-SHA256 (AS-2h secret_mac), NOT a sha256 of the sealed "
                                      "ciphertext and NOT the secret — the published record carries no plaintext "
                                      "(public-repo safe); the data plane recomputes it from the delivered secret.")
    epoch: int = Field(ge=1, description="Monotone binding generation; a higher epoch supersedes a lower.")
    issued_at: float = Field(default=0.0, description="Mint anchor / per-subject anti-replay high-water.")
    issued_by: str = Field(default="", description="Owner / provisioner that minted this binding.")
    note: str = Field(default="")

    @field_validator("edge_chain")
    @classmethod
    def _check_edge_chain(cls, v: str) -> str:
        return check_component(v, label="edge_chain")

    @field_validator("origin_secret_sha256")
    @classmethod
    def _check_commitment(cls, v: str) -> str:
        s = str(v or "").strip().lower()
        if not _SHA256_HEX_RE.match(s):
            raise ValueError("origin_secret_sha256 must be 64 lowercase hex characters")
        return s


class SignedAegisOriginBinding(BaseModel):
    """An origin binding plus governance signatures over its canonical form, verified against the OWNER
    ``TrustRoot``. A tampered subject / origin / edge_chain / commitment / epoch is detected (every field is in
    the signed bytes)."""

    model_config = ConfigDict(extra="forbid")

    document: AegisOriginBinding
    signatures: list[Signature] = Field(min_length=1)


def aegis_origin_binding_signing_bytes(binding: AegisOriginBinding) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the origin-binding domain tag followed by the
    compact, sorted-key UTF-8 JSON of the document (byte-identical SHAPE to the v2 grant signing bytes, DISTINCT
    tag)."""
    return _ORIGIN_BINDING_DOMAIN + canonical_json(binding.model_dump(mode="json"))


def _signatures(document_bytes: bytes, signers: dict[str, str]) -> list[Signature]:
    from .crypto import sign
    return [Signature(key_id=key_id, signature_b64=sign(priv_b64, document_bytes))
            for key_id, priv_b64 in signers.items()]


def sign_aegis_origin_binding(document: AegisOriginBinding, signers: dict[str, str]) -> SignedAegisOriginBinding:
    """Owner-sign an origin binding with each ``key_id -> private_key_b64``. Sovereign-side; the private key is
    used only inside :func:`vigil_core.crypto.sign` and never persisted or returned."""
    return SignedAegisOriginBinding(
        document=document, signatures=_signatures(aegis_origin_binding_signing_bytes(document), signers))


def verify_aegis_origin_binding(signed: SignedAegisOriginBinding, trust_root: TrustRoot) -> "tuple[bool, str]":
    """``(ok, reason)``: True iff the threshold of DISTINCT OWNER-root authorisers validly signed the binding's
    canonical form. Verify-only (no private material; safe on the keyless AEGIS plane). Fail-CLOSED: a
    quorum-collapsing trust root (duplicate authorizer public keys) is refused, and a malformed / weak-key
    signature is a refusal, never a crash."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(aegis_origin_binding_signing_bytes(signed.document), signed.signatures,
                                  trust_root)
    except (IntegrityError, TypeError, ValueError) as e:
        return False, f"aegis-origin-binding signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason


def origin_binding_digest(binding: Union[AegisOriginBinding, SignedAegisOriginBinding]) -> str:
    """The 64-hex ``origin_binding_sha256`` the v2 grant carries: sha256 of the binding's SIGNING BYTES (domain
    tag + canonical document), independent of any particular signature. Deterministic — the same document always
    maps to the same digest, so re-signing never changes what a grant is bound to."""
    doc = binding.document if isinstance(binding, SignedAegisOriginBinding) else binding
    return hashlib.sha256(aegis_origin_binding_signing_bytes(doc)).hexdigest()


def origin_binding_publish_path(subject: AuthoritySubject) -> str:
    """The ONE canonical place that computes where a subject's origin binding is published — a content-addressed
    file name (sha256 hex + ``.binding.json``) over the (subject) tuple, so NO org / host string can traverse the
    publish directory or collide across subjects, and the ``.binding.json`` suffix never collides with the grant
    (``.json``) or epoch-statement (``.epoch.json``) files. Deterministic; one binding per subject (the latest
    supersedes). Mirrors :func:`vigil_core.authority_v2.authority_publish_path`."""
    key = f"{subject.kind.value}\x00{subject.org_id}\x00{subject.host}\x00origin-binding"
    return hashlib.sha256(key.encode("utf-8")).hexdigest() + ".binding.json"


def grant_binds_origin(grant: MonitoringAuthorityV2, signed_binding: SignedAegisOriginBinding,
                       trust_root: TrustRoot) -> "tuple[bool, str]":
    """The AS-2g cross-check the data plane (the AS-2d broker's Z3 prover) composes from an ALREADY-READ grant
    and the published binding record. ``(True, "bound")`` iff EVERY conjunct holds; otherwise ``(False, reason)``
    — the grant is treated as UNBOUND and no forward target is armed (fail closed). Never raises on hostile input.

    Conjuncts (each fails closed):
      1. the grant declares an origin AND an ``origin_binding_sha256`` (else it is unbound by construction);
      2. the published binding VERIFIES under the owner root;
      3. the binding's subject == the grant's subject (a binding for one tenant can never bind another's grant);
      4. the binding's origin tuple == the grant's origin tuple (same scheme/host/port);
      5. the binding's edge_chain == the grant's edge_chain;
      6. ``origin_binding_digest(binding) == grant.origin_binding_sha256`` (constant-time) — the grant is bound
         to EXACTLY this binding's content.
    """
    if grant.origin is None or grant.origin_binding_sha256 is None:
        return False, "grant declares no origin / origin_binding_sha256 (unbound)"
    ok, why = verify_aegis_origin_binding(signed_binding, trust_root)
    if not ok:
        return False, f"published origin binding does not verify: {why}"
    b = signed_binding.document
    if b.subject != grant.subject:
        return False, "origin-binding subject does not match the grant's subject"
    if b.origin != grant.origin:
        return False, "origin-binding origin tuple does not match the grant's origin"
    if b.edge_chain != grant.edge_chain:
        return False, "origin-binding edge_chain does not match the grant's edge_chain"
    if not hmac.compare_digest(origin_binding_digest(b), str(grant.origin_binding_sha256)):
        return False, "origin-binding digest does not match the grant's origin_binding_sha256"
    return True, "bound"
