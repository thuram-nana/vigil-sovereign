"""Owner-root identity delegation (unification S4).

The two-anchor finding seam verifies an offense finding's anchor-1 (the CRUCIBLE m-of-n governance
signature) against a TrustRoot. That governance root, in the low-level primitive, is a FREE-FLOATING key
handed to the sovereign receiver with no cryptographic tie to the OWNER — anyone who provisioned a
governance authority could mint findings that path would accept. S4 does NOT remove that primitive; it
ADDS an owner-tied derivation on top: the OWNER (the sovereign 1-of-1 trust root) signs a
``DelegationCert`` authorizing a specific offense-governance TrustRoot, bounded by ROLE, SCOPE, and EXPIRY,
and ``FindingReceiver.from_delegation`` DERIVES the governance root it trusts from that owner-signed
delegation instead of trusting a handed-in root. Under ``from_delegation`` a finding is admitted only if
its governance signer was delegated by the owner AND (for a non-wildcard scope) the finding's own signed
``engagement_slug`` matches the delegated scope.

Honest boundary of enforcement: the owner tie is a property of the ``from_delegation`` path, not a global
invariant. The raw ``FindingReceiver(store, crucible_trust_root=...)`` / ``ingest_finding`` primitives
remain and do NOT check owner delegation — they are the low-level building blocks (and test surface).
Sovereign daemon/CLI wiring MUST construct via ``from_delegation``; there is no production caller of the
raw path today. See ``apps/sigil/sigil/inbound/finding_receiver.py``.

It is pure DATA verified with ``vigil_core`` alone (Ed25519 over a domain-separated canonical core), so it
crosses the offense↔sovereign boundary exactly like the inert finding: the owner private key stays
sovereign-side; the offense process holds only the delegated governance key, never the owner key. Additive
and version-conditional — a NEW domain tag (``vigil-delegation-v1``), so it cannot perturb the v1
evidence/head signing bytes. Fail-closed on every axis: wrong owner, wrong role, out-of-scope, expired,
unsigned, malformed, invalid threshold, or a quorum-inflating authorizer set → refuse (never a
partial-trust default). Bearer-cert caveat: a delegation has no pre-expiry revocation, so ``not_after``
is its only bound — the owner sizes that window to the shortest practical horizon."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .canonical import canonical_json
from .crypto import IntegrityError, load_public_key, sign, verify_one
from .models import AuthorizerKey, TrustRoot

# Domain tag so an owner delegation signature can never be replayed as a spine-head / evidence / floor /
# witness-roster / capability signature (each uses a distinct prefix).
_DELEGATION_DOMAIN = b"vigil-delegation-v1\x00"
_SCHEMA = 1

# The well-known role the owner delegates to the offense-side CRUCIBLE m-of-n governance authority (the
# key that signs an offense finding's anchor-1). One string shared by the owner signer and the sovereign
# verifier so a role typo can't silently accept an unintended delegation.
OFFENSE_GOVERNANCE_ROLE = "offense-governance"

# The well-known role the owner delegates to the STABLE offense engagement-spine identity (S5) — the one
# key that signs the offense checkpoint spine, the executor ExecRecords, and the detection certificates.
# Distinct from the governance role so the spine identity and the anchor-1 finding authority stay separate
# keys with separate, minimal signing surfaces (delegating one never widens the other).
OFFENSE_SPINE_ROLE = "offense-spine"


class DelegationError(Exception):
    """A delegation is absent, malformed, unsigned, by a non-owner key, out of role/scope, expired, or has
    an invalid threshold — fail-closed: the caller must trust NO governance root rather than a partial one."""


class DelegationCert(BaseModel):
    """An owner-signed authorization of an offense-governance TrustRoot, bounded by role/scope/expiry.
    Pure JSON-serialisable data (``model_dump_json``/``model_validate_json``) — crosses the boundary as
    inert signed data, verified with ``vigil_core`` alone."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = _SCHEMA
    owner_pubkey: str                       # the delegating owner (the sovereign 1-of-1 trust root)
    role: str                               # what is delegated, e.g. "offense-governance"
    scope: str                              # the engagement scope/slug it is valid for ("*" = any scope)
    not_after: int                          # expiry (unix seconds); the delegation is invalid at now > not_after
    authorizers: list[AuthorizerKey]        # the DELEGATED governance keys (the derived TrustRoot's members)
    threshold: int                          # m-of-n for the delegated root
    sig: str = ""                           # owner Ed25519 signature over the domain-tagged canonical core

    def _core(self) -> dict:
        """The exact fields the owner signature covers (everything but ``sig``), in a stable shape."""
        return {
            "schema_version": self.schema_version, "owner_pubkey": self.owner_pubkey,
            "role": self.role, "scope": self.scope, "not_after": self.not_after,
            "authorizers": [{"key_id": a.key_id, "name": a.name, "public_key_b64": a.public_key_b64}
                            for a in self.authorizers],
            "threshold": self.threshold,
        }


def _msg(core: dict) -> bytes:
    m = canonical_json(core)
    return _DELEGATION_DOMAIN + (m if isinstance(m, bytes) else m.encode("utf-8"))


def sign_delegation(owner_key, *, role: str, scope: str, authorizers, threshold: int,
                    not_after: int) -> DelegationCert:
    """Owner-sign a delegation of the offense-governance TrustRoot ``(authorizers, threshold)``. Only the
    owner (holder of the sovereign private key) can mint one. Raises DelegationError on an empty role/scope,
    an empty/invalid authorizer set or threshold, or a quorum-inflating (duplicate key_id or pubkey)
    authorizer set — the owner cannot mint even a footgun root. ``scope="*"`` and a far ``not_after`` are
    legitimate but deliberately broad owner choices; size them to the shortest practical horizon (there is
    no pre-expiry revocation)."""
    if not str(role).strip():
        raise DelegationError("a delegation needs a non-empty role")
    if not str(scope).strip():
        raise DelegationError("a delegation needs a non-empty scope ('*' for any)")
    auths = list(authorizers)
    if not auths:
        raise DelegationError("a delegation needs at least one authorizer")
    if not (1 <= int(threshold) <= len(auths)):
        raise DelegationError(f"threshold {threshold} out of range for {len(auths)} authorizers")
    if len({a.key_id for a in auths}) != len(auths):
        raise DelegationError("delegation has duplicate authorizer key_ids")
    if len({a.public_key_b64 for a in auths}) != len(auths):
        raise DelegationError("delegation has duplicate authorizer public keys (would collapse the quorum)")
    cert = DelegationCert(owner_pubkey=owner_key.public_key_b64, role=str(role), scope=str(scope),
                          not_after=int(not_after), authorizers=auths, threshold=int(threshold))
    return cert.model_copy(update={"sig": sign(owner_key.private_key_b64, _msg(cert._core()))})


def verify_delegation(cert: DelegationCert, *, trusted_owner_pubkey: str, now: int, role: str,
                      scope: str) -> TrustRoot:
    """Return the DELEGATED governance TrustRoot iff ``cert`` is a delegation the TRUSTED OWNER signed, for
    the required ``role``, covering ``scope``, and not expired at ``now``. Fail-closed: raises
    DelegationError on ANY failure (the caller must then trust no governance root).

    ``now`` MUST come from a trusted clock the caller controls (unix seconds) — the expiry check is only as
    sound as that clock; never pass an attacker-influenced timestamp."""
    if not isinstance(cert, DelegationCert):
        raise DelegationError("not a delegation certificate")
    if int(cert.schema_version) != _SCHEMA:
        raise DelegationError(f"unsupported delegation schema_version {cert.schema_version!r} (expected {_SCHEMA})")
    if not trusted_owner_pubkey or cert.owner_pubkey != trusted_owner_pubkey:
        raise DelegationError("delegation is not by the trusted owner key")
    if cert.role != role:
        raise DelegationError(f"delegation role {cert.role!r} does not match required {role!r}")
    if cert.scope not in ("*", scope):
        raise DelegationError(f"delegation scope {cert.scope!r} does not cover {scope!r}")
    if not cert.sig or not isinstance(cert.sig, str):
        raise DelegationError("delegation is unsigned")
    try:
        ok = verify_one(trusted_owner_pubkey, _msg(cert._core()), cert.sig)
    except (IntegrityError, TypeError) as e:   # malformed sig/key material → fail-closed
        raise DelegationError(f"delegation signature is malformed: {e}") from e
    if not ok:
        raise DelegationError("delegation signature does not verify against the owner key")
    if int(now) > int(cert.not_after):
        raise DelegationError(f"delegation expired (now {int(now)} > not_after {cert.not_after})")
    if not cert.authorizers or not (1 <= int(cert.threshold) <= len(cert.authorizers)):
        raise DelegationError("delegation has an invalid threshold/authorizer set")
    # Quorum-integrity guards, mirroring TrustRoot._check (the shared backstop) so a malformed delegated set
    # is rejected with a TYPED DelegationError here, before the TrustRoot is built. A repeated key_id OR a
    # repeated pubkey (under distinct ids) would let fewer real keyholders satisfy the m-of-n threshold.
    if len({a.key_id for a in cert.authorizers}) != len(cert.authorizers):
        raise DelegationError("delegation has duplicate authorizer key_ids")
    if len({a.public_key_b64 for a in cert.authorizers}) != len(cert.authorizers):
        raise DelegationError("delegation has duplicate authorizer public keys (would collapse the quorum)")
    # Eager key validation: reject a non-canonical / low-order authorizer pubkey now (fail-fast at derive
    # time) rather than deferring to anchor-1, so the returned root is guaranteed usable. load_public_key
    # applies the I2 weak-key rejection (y>=p, small-order).
    for a in cert.authorizers:
        try:
            load_public_key(a.public_key_b64)
        except (IntegrityError, TypeError) as e:
            raise DelegationError(f"delegated authorizer {a.key_id!r} has an invalid public key: {e}") from e
    return TrustRoot(threshold=int(cert.threshold), authorizers=list(cert.authorizers))
