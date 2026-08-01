"""Owner-attested target IDENTITY + an attenuable re-verification CAPABILITY (VF §4/§7).

This is the *identity design* and *authorization design* the Verifiable-Fact protocol
(`docs/proof-carrying-finding/PROTOCOL.md`) specifies as prose, turned into real signed objects that verify
offline with ``vigil_core`` alone. Two threats it exists to close:

1. **Transplant / target-swap.** A RemediationCertificate binds ``surface``/``slug`` as producer-chosen free
   strings — a proof is meaningfully transplantable, and "against S" is not enforced. The **IdentityAttestation**
   fixes this: the OWNER (the accountable party who controls target S) signs an *acceptable-identity policy* for
   an engagement — e.g. "the TLS SPKI for host H is one of {pin1, pin2}" (a set, because identity legitimately
   rotates). A live verification carries an observed *identity sample*; it is accepted only if the sample
   SATISFIES the policy (``identity_matches``). Policy-over-certs, checked per sample, time-varying (§4).

2. **Unauthorized / illegal re-verification.** A third-party (regulator/insurer/customer) Mode-L re-verification
   re-runs an exploit against a real target — that must itself be authorized. The **Capability** is the
   owner-minted, scoped, windowed, revocable grant that makes it legal (§7): a bug-class allowlist, a
   ``non_destructive`` constraint, a ``[not_before, not_after]`` window, a ``rate_limit``, a ``revocation_id``,
   and an ``audience`` (who may wield it). It is **attenuable** biscuit-style: a holder appends a signed,
   public-key-verifiable Attenuation that can only NARROW (never widen) the grant, so a capability can be
   delegated down a chain (owner → auditor → sub-auditor) without the owner re-signing, and offline verification
   still bounds exactly what the final holder may do.

Both are pure JSON-serialisable DATA verified with Ed25519 over a domain-separated canonical core — so they
cross the offense↔sovereign boundary exactly like ``inert_finding`` and ``DelegationCert``: the owner private
key stays sovereign-side; the offense executor and any third-party verifier hold only inert signed bytes.
Additive and version-conditional (NEW domain tags — see ``spine_domains.DOMAIN_TAGS`` ``identity`` /
``capability`` / ``attenuation`` — so nothing perturbs the v1 evidence/delegation/head signing bytes).

Fail-closed on EVERY axis: wrong owner, wrong engagement, expired/not-yet-valid, unsigned, malformed,
destructive, empty allowlist, a class not in the allowlist, a revoked id, a WIDENING attenuation, a broken /
reordered attenuation chain, a signer who is not the current audience, or a live sample that does not satisfy
the identity policy → refuse (never a partial-trust default).

Honest boundary. ``now`` MUST come from a trusted clock the caller controls (unix seconds); every window/expiry
check is only as sound as that clock. Revocation is a ``revoked_ids`` set the verifier supplies (short TTL +
list + kill-switch, per PROTOCOL §7) — a capability spent inside its window before revocation propagates is the
known, stated gap. The IdentityAttestation trusts the OWNER about the OWNER's own system: O could misattest its
own target, but that is self-defeating for the accountable party (§8). This layer does NOT provide
byte-authenticity against a *malicious producer* for arbitrary classes — that stays in the deferred frontier.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .canonical import canonical_json, digest_payload
from .crypto import IntegrityError, load_public_key, sign, verify_one
from .spine_domains import DOMAIN_TAGS

_SCHEMA = 1
_IDENTITY_DOMAIN = DOMAIN_TAGS["identity"]
_CAPABILITY_DOMAIN = DOMAIN_TAGS["capability"]
_ATTENUATION_DOMAIN = DOMAIN_TAGS["attenuation"]

_WILDCARD_AUDIENCE = "*"


class CapabilityError(Exception):
    """An identity attestation or capability is absent, malformed, unsigned, by a non-owner key, out of
    engagement/scope, expired, destructive, revoked, widened by an attenuation, chained wrong, or the live
    sample does not satisfy the identity policy — fail-closed: the caller must authorize NOTHING."""


def _msg(domain: bytes, core: dict) -> bytes:
    m = canonical_json(core)
    return domain + (m if isinstance(m, bytes) else m.encode("utf-8"))


# --------------------------------------------------------------------------------------------------------
# IdentityAttestation — the owner-attested acceptable-identity policy for an engagement (§4).
# --------------------------------------------------------------------------------------------------------
class IdentityAttestation(BaseModel):
    """Owner-signed: engagement E → an acceptable-identity policy. ``policy`` maps an identity *dimension*
    (``tls_spki_sha256`` / ``host`` / ``commit_sha256`` / ``resource_id`` / ...) to the set of acceptable
    values for it. Matching is **any-of within a dimension** (rotation) and **conjunctive across dimensions**
    (a sample must satisfy every dimension the owner constrained)."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = _SCHEMA
    owner_pubkey: str
    engagement: str
    policy: dict[str, list[str]]
    not_after: int
    sig: str = ""

    def _core(self) -> dict:
        # Sort each dimension's allowlist so the signed bytes are order-independent (set semantics).
        return {
            "schema_version": self.schema_version, "owner_pubkey": self.owner_pubkey,
            "engagement": self.engagement,
            "policy": {k: sorted(v) for k, v in sorted(self.policy.items())},
            "not_after": self.not_after,
        }


def _policy_is_wellformed(policy: dict[str, list[str]]) -> bool:
    # Fail-closed shape: at least one dimension, every dimension a non-empty list of non-empty strings.
    if not isinstance(policy, dict) or not policy:
        return False
    for dim, allowed in policy.items():
        if not isinstance(dim, str) or not dim.strip():
            return False
        if not isinstance(allowed, list) or not allowed:
            return False
        if any((not isinstance(v, str)) or (not v.strip()) for v in allowed):
            return False
    return True


def sign_identity_attestation(owner_key, *, engagement: str, policy: dict[str, list[str]],
                              not_after: int) -> IdentityAttestation:
    """Owner-sign an acceptable-identity policy for ``engagement``. Raises CapabilityError on an empty
    engagement or a malformed policy (an empty policy would match nothing OR — if mis-handled — everything;
    we reject it outright so the owner cannot mint a footgun attestation)."""
    if not str(engagement).strip():
        raise CapabilityError("an identity attestation needs a non-empty engagement")
    if not _policy_is_wellformed(policy):
        raise CapabilityError("identity policy must be a non-empty map of dimension -> non-empty value list")
    att = IdentityAttestation(owner_pubkey=owner_key.public_key_b64, engagement=str(engagement),
                              policy=dict(policy), not_after=int(not_after))
    return att.model_copy(update={"sig": sign(owner_key.private_key_b64, _msg(_IDENTITY_DOMAIN, att._core()))})


def identity_digest(att: IdentityAttestation) -> str:
    """The stable digest of the attestation's signed core — what a Capability binds to. Independent of the
    signature (Ed25519 is deterministic, but binding to the core keeps the tie semantic: 'this policy')."""
    return digest_payload(att._core())


def verify_identity_attestation(att: IdentityAttestation, *, trusted_owner_pubkey: str, now: int,
                                engagement: str) -> str:
    """Return ``identity_digest(att)`` iff the TRUSTED OWNER signed ``att`` for ``engagement`` and it is not
    expired at ``now``. Fail-closed: raises CapabilityError on any failure."""
    if not isinstance(att, IdentityAttestation):
        raise CapabilityError("not an identity attestation")
    if int(att.schema_version) != _SCHEMA:
        raise CapabilityError(f"unsupported identity schema_version {att.schema_version!r}")
    if not trusted_owner_pubkey or att.owner_pubkey != trusted_owner_pubkey:
        raise CapabilityError("identity attestation is not by the trusted owner key")
    if att.engagement != engagement:
        raise CapabilityError(f"identity attestation engagement {att.engagement!r} != required {engagement!r}")
    if not _policy_is_wellformed(att.policy):
        raise CapabilityError("identity attestation carries a malformed policy")
    if not att.sig or not isinstance(att.sig, str):
        raise CapabilityError("identity attestation is unsigned")
    try:
        ok = verify_one(trusted_owner_pubkey, _msg(_IDENTITY_DOMAIN, att._core()), att.sig)
    except (IntegrityError, TypeError) as e:
        raise CapabilityError(f"identity signature is malformed: {e}") from e
    if not ok:
        raise CapabilityError("identity signature does not verify against the owner key")
    if int(now) > int(att.not_after):
        raise CapabilityError(f"identity attestation expired (now {int(now)} > not_after {att.not_after})")
    return identity_digest(att)


def identity_matches(policy: dict[str, list[str]], sample: dict[str, str]) -> bool:
    """True iff the observed ``sample`` satisfies EVERY dimension the ``policy`` constrains (conjunctive),
    each by set membership (any-of). A dimension the policy names but the sample omits → False (a sample
    cannot 'downgrade' by withholding a constrained dimension). A malformed policy → False. Extra sample
    dimensions the policy does not name are ignored."""
    if not _policy_is_wellformed(policy):
        return False
    if not isinstance(sample, dict):
        return False
    for dim, allowed in policy.items():
        observed = sample.get(dim)
        if not isinstance(observed, str) or observed not in set(allowed):
            return False
    return True


# --------------------------------------------------------------------------------------------------------
# Capability — the owner-minted, scoped, windowed, revocable, attenuable re-verification grant (§7).
# --------------------------------------------------------------------------------------------------------
class Capability(BaseModel):
    """Owner-signed authorization to re-verify. Bound to an IdentityAttestation by ``identity_digest`` (so
    the grant cannot ride a different target's identity). ``audience`` is the pubkey of the first holder, or
    ``"*"`` (bearer)."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = _SCHEMA
    owner_pubkey: str
    engagement: str
    identity_digest: str                    # binds to verify_identity_attestation()'s return
    class_allowlist: list[str]              # exact bug-class strings this may re-drive (no wildcard)
    non_destructive: bool = True            # MUST be True — a re-verification grant is non-destructive
    not_before: int
    not_after: int
    rate_limit: int                         # max re-drives / window (informational; executor enforces)
    revocation_id: str                      # checked against the verifier-supplied revoked set
    audience: str = _WILDCARD_AUDIENCE      # who may wield/attenuate: a pubkey, or "*" (bearer)
    sig: str = ""

    def _core(self) -> dict:
        return {
            "schema_version": self.schema_version, "owner_pubkey": self.owner_pubkey,
            "engagement": self.engagement, "identity_digest": self.identity_digest,
            "class_allowlist": sorted(self.class_allowlist), "non_destructive": self.non_destructive,
            "not_before": self.not_before, "not_after": self.not_after, "rate_limit": self.rate_limit,
            "revocation_id": self.revocation_id, "audience": self.audience,
        }

    def _digest(self) -> str:
        return digest_payload(self._core())


class Attenuation(BaseModel):
    """A biscuit-style, public-key-verifiable narrowing appended by the CURRENT holder. It chains to the prior
    link by ``prev_digest`` and is signed by ``signer_pubkey``, which MUST equal the prior link's audience
    (or anyone, if that audience is ``"*"``/bearer). Every field it sets may only NARROW the effective grant;
    a widening attenuation is rejected. ``next_audience`` names who may wield/attenuate after this link."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = _SCHEMA
    prev_digest: str                        # digest of the prior link's signed core (base cap, or prior atten.)
    signer_pubkey: str                      # must == the prior link's audience (unless that is "*")
    next_audience: str | None = None        # None = inherit; a pubkey = (re)delegate; "*" only if already "*"
    class_subset: list[str] | None = None   # ⊆ current allowlist
    not_before: int | None = None           # ≥ current not_before (start later = narrower)
    not_after: int | None = None            # ≤ current not_after (end earlier = narrower)
    rate_limit: int | None = None           # ≤ current rate_limit
    sig: str = ""

    def _core(self) -> dict:
        return {
            "schema_version": self.schema_version, "prev_digest": self.prev_digest,
            "signer_pubkey": self.signer_pubkey, "next_audience": self.next_audience,
            "class_subset": (sorted(self.class_subset) if self.class_subset is not None else None),
            "not_before": self.not_before, "not_after": self.not_after, "rate_limit": self.rate_limit,
        }

    def _digest(self) -> str:
        return digest_payload(self._core())


class EffectiveCapability(BaseModel):
    """The grant that actually holds after the base capability and every attenuation are intersected."""
    model_config = ConfigDict(extra="forbid")

    engagement: str
    identity_digest: str
    class_allowlist: list[str]
    not_before: int
    not_after: int
    rate_limit: int
    revocation_id: str
    audience: str


def sign_capability(owner_key, *, engagement: str, identity_digest: str, class_allowlist: list[str],
                    not_before: int, not_after: int, rate_limit: int, revocation_id: str,
                    audience: str = _WILDCARD_AUDIENCE, non_destructive: bool = True) -> Capability:
    """Owner-mint a re-verification capability. Raises CapabilityError on a footgun grant: empty engagement /
    identity binding / class allowlist / revocation_id, a wildcard in the class allowlist (must be explicit),
    a non-positive rate limit, an inverted window, a ``non_destructive=False`` grant, or a non-``"*"``
    audience that is not a valid Ed25519 public key."""
    if not str(engagement).strip():
        raise CapabilityError("a capability needs a non-empty engagement")
    if not str(identity_digest).strip():
        raise CapabilityError("a capability needs a non-empty identity_digest binding")
    allow = list(class_allowlist)
    if not allow or any((not isinstance(c, str)) or (not c.strip()) for c in allow):
        raise CapabilityError("class_allowlist must be a non-empty list of non-empty class strings")
    if _WILDCARD_AUDIENCE in allow:
        raise CapabilityError("class_allowlist must be explicit — no '*' wildcard class")
    if not non_destructive:
        raise CapabilityError("a re-verification capability is non-destructive by construction")
    if int(rate_limit) < 1:
        raise CapabilityError("rate_limit must be >= 1")
    if int(not_before) > int(not_after):
        raise CapabilityError(f"inverted window (not_before {not_before} > not_after {not_after})")
    if not str(revocation_id).strip():
        raise CapabilityError("a capability needs a non-empty revocation_id")
    _validate_audience(audience)
    cap = Capability(owner_pubkey=owner_key.public_key_b64, engagement=str(engagement),
                     identity_digest=str(identity_digest), class_allowlist=allow,
                     non_destructive=True, not_before=int(not_before), not_after=int(not_after),
                     rate_limit=int(rate_limit), revocation_id=str(revocation_id), audience=str(audience))
    return cap.model_copy(update={"sig": sign(owner_key.private_key_b64, _msg(_CAPABILITY_DOMAIN, cap._core()))})


def attenuate(holder_key, *, prev: Capability | Attenuation, next_audience: str | None = None,
              class_subset: list[str] | None = None, not_before: int | None = None,
              not_after: int | None = None, rate_limit: int | None = None) -> Attenuation:
    """Append a narrowing attenuation signed by the current holder (``holder_key`` must be the prior link's
    audience unless that is ``"*"``). ``next_audience`` (re)delegates to a new holder — ``None`` keeps the
    current holder; a pubkey pins/redelegates; ``"*"`` (bearer) is only accepted when the grant is ALREADY
    bearer (a pinned audience cannot be widened back to bearer). Only the intersecting fields are set; every
    widening is caught at VERIFY time (this constructor does not know the running effective grant, so it does
    not police narrowing itself — verify_capability is the authority)."""
    if next_audience is not None:
        _validate_audience(next_audience)
    prev_digest = prev._digest()
    att = Attenuation(prev_digest=prev_digest, signer_pubkey=holder_key.public_key_b64,
                      next_audience=(str(next_audience) if next_audience is not None else None),
                      class_subset=(list(class_subset) if class_subset is not None else None),
                      not_before=(int(not_before) if not_before is not None else None),
                      not_after=(int(not_after) if not_after is not None else None),
                      rate_limit=(int(rate_limit) if rate_limit is not None else None))
    return att.model_copy(update={"sig": sign(holder_key.private_key_b64, _msg(_ATTENUATION_DOMAIN, att._core()))})


def _validate_audience(audience: str) -> None:
    if audience == _WILDCARD_AUDIENCE:
        return
    if not isinstance(audience, str) or not audience.strip():
        raise CapabilityError("audience must be a pubkey or '*'")
    try:
        load_public_key(audience)   # I2 weak-key rejection (y>=p / small-order) — fail-fast
    except (IntegrityError, TypeError) as e:
        raise CapabilityError(f"audience is not a valid Ed25519 public key: {e}") from e


def verify_capability(cap: Capability, *, trusted_owner_pubkey: str, now: int, engagement: str,
                      attenuations: list[Attenuation] | None = None, wielder_pubkey: str | None = None,
                      revoked_ids: frozenset[str] = frozenset()) -> EffectiveCapability:
    """Return the EffectiveCapability iff ``cap`` is owner-signed for ``engagement``, its attenuation chain is
    intact and NARROW-ONLY, it is within its (attenuated) window at ``now``, non-destructive, not revoked, and
    (if ``wielder_pubkey`` given) the final audience admits that wielder. Fail-closed: raises CapabilityError
    on any failure.

    This is the low-level INSPECTION primitive: ``wielder_pubkey`` is optional so a caller may examine a
    capability's effective grant without a wielder in mind (audit/display). **Omitting it does NOT bind the
    wielder** — a pinned capability is usable by anyone if you never pass the wielder. Any executor / authorizer
    that gates a real re-drive MUST bind the wielder; use :func:`authorize_reverification` (where it is
    required), or pass ``wielder_pubkey`` here explicitly."""
    if not isinstance(cap, Capability):
        raise CapabilityError("not a capability")
    if int(cap.schema_version) != _SCHEMA:
        raise CapabilityError(f"unsupported capability schema_version {cap.schema_version!r}")
    if not trusted_owner_pubkey or cap.owner_pubkey != trusted_owner_pubkey:
        raise CapabilityError("capability is not by the trusted owner key")
    if cap.engagement != engagement:
        raise CapabilityError(f"capability engagement {cap.engagement!r} != required {engagement!r}")
    if not cap.non_destructive:
        raise CapabilityError("capability is not marked non_destructive")
    if not cap.class_allowlist or _WILDCARD_AUDIENCE in cap.class_allowlist:
        raise CapabilityError("capability has an empty or wildcard class_allowlist")
    if int(cap.rate_limit) < 1:
        raise CapabilityError("capability has a non-positive rate_limit")
    if int(cap.not_before) > int(cap.not_after):
        raise CapabilityError("capability has an inverted window")
    if not str(cap.revocation_id).strip():
        raise CapabilityError("capability has an empty revocation_id")
    if not cap.sig or not isinstance(cap.sig, str):
        raise CapabilityError("capability is unsigned")
    try:
        ok = verify_one(trusted_owner_pubkey, _msg(_CAPABILITY_DOMAIN, cap._core()), cap.sig)
    except (IntegrityError, TypeError) as e:
        raise CapabilityError(f"capability signature is malformed: {e}") from e
    if not ok:
        raise CapabilityError("capability signature does not verify against the owner key")

    # Walk the attenuation chain, intersecting narrow-only. The running (digest, audience) is what the NEXT
    # link must chain to and be signed by; a stripped, reordered, or forged link breaks one of these.
    eff_allow = set(cap.class_allowlist)
    eff_not_before, eff_not_after, eff_rate = int(cap.not_before), int(cap.not_after), int(cap.rate_limit)
    cur_digest, cur_audience = cap._digest(), cap.audience

    for i, att in enumerate(attenuations or []):
        if not isinstance(att, Attenuation):
            raise CapabilityError(f"attenuation #{i} is not an Attenuation")
        if int(att.schema_version) != _SCHEMA:
            raise CapabilityError(f"attenuation #{i} unsupported schema_version {att.schema_version!r}")
        if att.prev_digest != cur_digest:
            raise CapabilityError(f"attenuation #{i} does not chain to the prior link (broken/reordered)")
        if cur_audience != _WILDCARD_AUDIENCE and att.signer_pubkey != cur_audience:
            raise CapabilityError(f"attenuation #{i} signer is not the current audience")
        if not att.sig or not isinstance(att.sig, str):
            raise CapabilityError(f"attenuation #{i} is unsigned")
        try:
            ok = verify_one(att.signer_pubkey, _msg(_ATTENUATION_DOMAIN, att._core()), att.sig)
        except (IntegrityError, TypeError) as e:
            raise CapabilityError(f"attenuation #{i} signature is malformed: {e}") from e
        if not ok:
            raise CapabilityError(f"attenuation #{i} signature does not verify")
        # Audience is the delegation pointer. `None` inherits the current holder; a pubkey (re)delegates to a
        # new holder (lateral delegation is the point of an attenuable capability); "*" (bearer) is refused
        # once the grant is pinned — a pinned audience can never be widened back to bearer.
        if att.next_audience is None:
            next_audience = cur_audience
        elif att.next_audience == _WILDCARD_AUDIENCE:
            if cur_audience != _WILDCARD_AUDIENCE:
                raise CapabilityError(f"attenuation #{i} may not widen a pinned audience back to bearer")
            next_audience = _WILDCARD_AUDIENCE
        else:
            _validate_audience(att.next_audience)
            next_audience = att.next_audience
        # Narrow-only field intersections — any WIDENING is a hard reject, not a silent clamp.
        if att.class_subset is not None:
            sub = set(att.class_subset)
            if not sub or not sub.issubset(eff_allow):
                raise CapabilityError(f"attenuation #{i} class_subset is empty or widens the allowlist")
            eff_allow = sub
        if att.not_before is not None:
            if int(att.not_before) < eff_not_before:
                raise CapabilityError(f"attenuation #{i} not_before widens the window (earlier start)")
            eff_not_before = int(att.not_before)
        if att.not_after is not None:
            if int(att.not_after) > eff_not_after:
                raise CapabilityError(f"attenuation #{i} not_after widens the window (later end)")
            eff_not_after = int(att.not_after)
        if att.rate_limit is not None:
            if int(att.rate_limit) > eff_rate or int(att.rate_limit) < 1:
                raise CapabilityError(f"attenuation #{i} rate_limit widens or is non-positive")
            eff_rate = int(att.rate_limit)
        cur_digest, cur_audience = att._digest(), next_audience

    if eff_not_before > eff_not_after:
        raise CapabilityError("attenuation chain produced an inverted window")
    if not (eff_not_before <= int(now) <= eff_not_after):
        raise CapabilityError(f"capability not valid at now {int(now)} (window [{eff_not_before}, {eff_not_after}])")
    if cap.revocation_id in revoked_ids:
        raise CapabilityError(f"capability revocation_id {cap.revocation_id!r} is revoked")
    if wielder_pubkey is not None and cur_audience != _WILDCARD_AUDIENCE and wielder_pubkey != cur_audience:
        raise CapabilityError("wielder is not the capability's audience")

    return EffectiveCapability(engagement=cap.engagement, identity_digest=cap.identity_digest,
                               class_allowlist=sorted(eff_allow), not_before=eff_not_before,
                               not_after=eff_not_after, rate_limit=eff_rate, revocation_id=cap.revocation_id,
                               audience=cur_audience)


def authorize_reverification(cap: Capability, identity: IdentityAttestation, *, trusted_owner_pubkey: str,
                             now: int, engagement: str, bug_class: str, identity_sample: dict[str, str],
                             wielder_pubkey: str, attenuations: list[Attenuation] | None = None,
                             revoked_ids: frozenset[str] = frozenset()) -> EffectiveCapability:
    """The one call the executor / a third-party verifier makes before a Mode-L re-drive: prove the whole
    chain at once. Returns the EffectiveCapability iff (a) the OWNER attested this target's identity for the
    engagement, (b) the capability is owner-minted, chained narrow-only, in-window, non-destructive, and not
    revoked, (c) the capability is BOUND to exactly that identity attestation, (d) ``bug_class`` is in the
    (attenuated) allowlist, (e) the live ``identity_sample`` SATISFIES the attested policy, and (f) the
    presenting ``wielder_pubkey`` is admitted by the (attenuated) audience. Fail-closed.

    ``wielder_pubkey`` is REQUIRED (no default): the authorization gate can never be invoked without declaring
    who is wielding, so a pinned capability can never be used by a non-audience holder through this path. For a
    bearer ("*") capability any wielder is admitted, but the caller still declares its identity for the audit
    trail."""
    if not isinstance(wielder_pubkey, str) or not wielder_pubkey.strip():
        raise CapabilityError("authorize_reverification requires a non-empty wielder_pubkey")
    id_digest = verify_identity_attestation(identity, trusted_owner_pubkey=trusted_owner_pubkey, now=now,
                                            engagement=engagement)
    eff = verify_capability(cap, trusted_owner_pubkey=trusted_owner_pubkey, now=now, engagement=engagement,
                            attenuations=attenuations, wielder_pubkey=wielder_pubkey, revoked_ids=revoked_ids)
    if eff.identity_digest != id_digest:
        raise CapabilityError("capability is not bound to this identity attestation")
    if bug_class not in set(eff.class_allowlist):
        raise CapabilityError(f"bug_class {bug_class!r} is not in the capability's allowlist")
    if not identity_matches(identity.policy, identity_sample):
        raise CapabilityError("the live target's identity sample does not satisfy the attested policy")
    return eff
