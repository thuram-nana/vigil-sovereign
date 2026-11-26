"""AEGIS AS-2a — the authority-V2 contracts (the sovereign mints, the keyless AEGIS plane verifies).

The FATAL-2 SEAM CONTRACTS for DEFENSIVE live monitoring + enforcement, V2. Defined ONCE here in the shared
integrity core so the SOVEREIGN plane (which holds the owner key / the release key and mints these records after
its ownership + binding + release checks) and the keyless AEGIS data plane (which verifies the identical bytes
before it inspects or enforces on a tenant's traffic) agree BY CONSTRUCTION, never by a drift-catching test.
Mirrors ``authority.py`` / ``credit_lease.py`` / ``monitoring_authority.py`` / ``shard_assignment_record.py``
exactly: a pydantic ``extra="forbid"`` document, a domain-separated canonical signing-bytes helper, a
``Signed…`` wrapper, an owner-side ``sign_…`` and a verify-only, fail-closed ``verify_…``.

This slice ships the CONTRACTS + their sign/verify/revoke/epoch/lease/release semantics ONLY. It does NOT wire
anything into the gateway or the sovereign ``monitoring_authority`` registry (slices 2f / 2c / 2g / 29 do that):
every function here either validates/signs/verifies a document, or composes ALREADY-VERIFIED documents into a
contract-level decision — it holds no key on the verify path and reads no global clock or RNG.

Five contracts + two unsigned fail-safe signals + two helpers:

* ``MonitoringAuthorityV2`` — the owner-signed grant. A ``subject`` discriminator; an explicit ``capabilities``
  set (observe | block | virtual_patch | respond); a declared HTTPS ``origin`` tuple + ``origin_binding_sha256``
  (IP literals refused; no binding => no signature); an ``edge_chain`` declaration; a monotone ``epoch``; a
  short-lived ``lease`` (lapse => uninspected PASS-THROUGH, R16); ``instance_id`` + ``replica_index``. Verified
  against the OWNER root. Capabilities are inside the signed bytes (an OBSERVE grant cannot be flipped to carry
  BLOCK without a fresh owner signature); an ENFORCING capability is NECESSARY-NOT-SUFFICIENT.
* ``EpochStatement`` — the owner-signed monotone epoch marker for one subject. floor = max(local, statement);
  a grant whose epoch sits below the floor is detectably STALE and fails closed. A higher epoch SUPERSEDES.
* ``EnforceRelease`` — signed on a SEPARATE RELEASE ROOT (D30), verified against the release root ALONE, so an
  owner-root (grant) signature can never satisfy an enforce check. The owner-held release production enforcement
  needs; absent or unverifiable => NO enforce (fail closed).
* ``MonitoringRevocationV2`` — the owner-signed revocation that supersedes a grant at or below its epoch.
* ``AuthorityWithdrawal`` / ``EnforcementOverride`` — UNSIGNED fail-safe signals that reach the unit via its
  control dir (§4.7). They only ever REDUCE authority (withdrawal => pass-through; override => a strict downgrade
  to observe or pass-through), so they are honoured without a signature: the SAFE direction. They can NEVER raise
  enforcement, by construction (the override's target is a closed downgrade-only enum).
* ``authority_publish_path`` — the ONE canonical place that computes where a per-instance authority is published.
* ``evaluate_authority`` — the contract-level decision the data plane (2c / 2f / 29) composes from the
  already-verified documents; everything fails CLOSED toward PASS-THROUGH / OBSERVE (never toward enforce).

Determinism: NO wallclock and NO global RNG anywhere on a signed or canonical path. Every time and nonce is a
field the caller supplies; ``capabilities`` are sorted + de-duplicated in a validator so the same logical grant
serializes to BYTE-IDENTICAL canonical bytes regardless of input order.

FATAL-2: imports only ``vigil_core`` siblings + stdlib + pydantic. No ``framework``, no ``sigil`` — safe to
import on either plane.
"""
from __future__ import annotations

import enum
import hashlib
import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Any, Final, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# --- domain-separation prefixes (sourced from the ONE registry) --------------------------------------------
# Distinct, NUL-terminated tags: a signature computed under one purpose can never verify under another, and the
# v2 grant tag is distinct from the v1 monitoring-authority tag (a v1 signature can never replay as a v2 grant).
_AUTHORITY_V2_DOMAIN: Final[bytes] = DOMAIN_TAGS["monitoring-authority-v2"]
_EPOCH_STATEMENT_DOMAIN: Final[bytes] = DOMAIN_TAGS["aegis-epoch-statement"]
_ENFORCE_RELEASE_DOMAIN: Final[bytes] = DOMAIN_TAGS["aegis-enforce-release"]

# A single DNS label / hostname (the SAME shape the sovereign ownership flow enforces; replicated here because
# the sovereign module is across the FATAL-2 boundary and must not be imported). Letters/digits/hyphen labels,
# dot-separated, each label 1..63, total <= 253; no leading/trailing hyphen on a label.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
# A SAFE single path component for instance_id (no separator / '.'/'..' traversal / absolute path / NUL):
# an alphanumeric start then [A-Za-z0-9._-], max 64 chars. Mirrors ``check_tenant_component``'s shape.
_COMPONENT_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


def _as_utc(dt: datetime) -> datetime:
    """Read a tz-NAIVE datetime as UTC so a window comparison never raises on a naive/aware mix (a data-plane
    caller using ``datetime.utcnow()`` must not crash the fail-closed decision). A tz-aware datetime is unchanged."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def check_dns_host(value: object, *, label: str) -> str:
    """Validate ``value`` as a single bare DNS hostname, fail-closed ``ValueError``. IP literals are REFUSED
    (§4.4: an origin is declared as a DNS HTTPS tuple, never a bare IP — a bare IP has no zone to bind and is
    an internal-egress hazard). ``label`` names the field for the error. Lower-cased, so the canonical bytes
    do not drift on case."""
    h = str(value or "").strip().lower()
    if not h:
        raise ValueError(f"{label} is required")
    if "://" in h or "/" in h or ":" in h or " " in h:
        raise ValueError(f"{label} must be a bare hostname (e.g. api.example.com), not a URL, path, or host:port")
    if not _HOSTNAME_RE.match(h):
        raise ValueError(f"{label} {h!r} is not a valid hostname")
    # Refuse EVERY IP-literal encoding, not just the canonical dotted-quad / RFC-5952 form. A signed host that
    # resolves to loopback / link-local / cloud-metadata is an internal-egress (SSRF) hazard, and the resolver
    # accepts decimal, hex (0x..), octal (0..) and short-dotted IPv4 forms (0x7f.1, 2130706433, 0177.0.0.1,
    # 127.1, 0xa9fea9fe -> 169.254.169.254) that ``ipaddress.ip_address`` rejects but ``inet_aton`` accepts.
    ip_literal = False
    try:
        ipaddress.ip_address(h)                          # canonical IPv4 / IPv6
        ip_literal = True
    except ValueError:
        pass
    try:
        socket.inet_aton(h)                              # any IPv4 numeric encoding (decimal / hex / octal / short)
        ip_literal = True
    except OSError:
        pass
    if h.rsplit(".", 1)[-1].isdigit():                   # a real hostname's final label (TLD) is never all-numeric
        ip_literal = True
    if ip_literal:
        raise ValueError(f"{label} {h!r} is an IP literal — an origin is declared over a DNS hostname, not a bare IP")
    return h


def check_component(value: object, *, label: str) -> str:
    """Validate ``value`` as a safe single path component (no separator / traversal / NUL), fail-closed."""
    v = str(value or "").strip()
    if not _COMPONENT_RE.fullmatch(v):
        raise ValueError(
            f"{label} must be a safe single path component: an alphanumeric start then [A-Za-z0-9._-], "
            f"max 64 chars, no separators / '.'/'..' traversal / absolute path / NUL")
    return v


# --- shared discriminated subject -------------------------------------------------------------------------
class SubjectKind(str, enum.Enum):
    """What a V2 authority is ABOUT. ``HOST`` is the AS-1 per-tenant-host case (one exact host, no wildcard).
    The discriminator is the forward-compatible seam: later slices (e.g. 2k asset groups) extend it without
    changing the signed shape of a HOST subject."""

    HOST = "host"


class AuthoritySubject(BaseModel):
    """The discriminated subject shared by every V2 authority record (grant, epoch statement, release,
    revocation, and the unsigned signals), so they all bind the SAME (kind, org_id, host) — a release for one
    subject can never be read as a release for another."""

    model_config = ConfigDict(extra="forbid")

    kind: SubjectKind = Field(default=SubjectKind.HOST, description="Subject discriminator (one 'host' today).")
    org_id: str = Field(min_length=1, description="The tenant this authority is scoped to (a safe path component).")
    host: str = Field(min_length=1, description="The single EXACT monitored host; no wildcard / subdomain "
                      "inheritance, no IP literal.")

    @field_validator("org_id")
    @classmethod
    def _check_org(cls, v: str) -> str:
        return check_component(v, label="org_id")

    @field_validator("host")
    @classmethod
    def _check_host(cls, v: str) -> str:
        return check_dns_host(v, label="host")


# --- capabilities ------------------------------------------------------------------------------------------
class MonitoringCapability(str, enum.Enum):
    """The closed set of capabilities a V2 grant may carry. OBSERVE = inspect + alert (never blocks). The three
    ENFORCING capabilities (BLOCK, VIRTUAL_PATCH, RESPOND) are NECESSARY-NOT-SUFFICIENT: carrying one authorizes
    nothing on its own — the data plane additionally requires a release-root ``EnforceRelease`` that covers it
    (release_valid) plus continuous per-request re-authorization."""

    OBSERVE = "observe"
    BLOCK = "block"
    VIRTUAL_PATCH = "virtual_patch"   # AS-21 edge virtual patching
    RESPOND = "respond"               # AS-13 active response


#: The ENFORCING capabilities — the ones that MUST be covered by a verified ``EnforceRelease`` before the data
#: plane may act on them. OBSERVE is never in this set (observing needs only a live grant).
ENFORCING_CAPABILITIES: Final[frozenset[MonitoringCapability]] = frozenset(
    {MonitoringCapability.BLOCK, MonitoringCapability.VIRTUAL_PATCH, MonitoringCapability.RESPOND}
)


def _normalize_capabilities(values: Any) -> list[MonitoringCapability]:
    """Coerce an iterable of capabilities to a SORTED, DE-DUPLICATED list of :class:`MonitoringCapability`,
    fail-closed. Sorting by the enum VALUE makes the canonical bytes independent of input order (determinism:
    the same logical grant signs byte-identically however the caller ordered its capabilities)."""
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise ValueError("capabilities must be a list of capability values")
    seen: set[str] = set()
    out: list[MonitoringCapability] = []
    for item in values:
        cap = item if isinstance(item, MonitoringCapability) else MonitoringCapability(str(item))
        if cap.value not in seen:
            seen.add(cap.value)
            out.append(cap)
    out.sort(key=lambda c: c.value)
    return out


# --- declared origin + edge chain --------------------------------------------------------------------------
class OriginTuple(BaseModel):
    """A declared HTTPS origin: scheme (https only) + a bare DNS host (IP literals refused) + a port. §4.4."""

    model_config = ConfigDict(extra="forbid")

    scheme: str = Field(default="https", description="https only; http is refused (viewer TLS is terminated "
                        "at the edge, the origin hop is HTTPS).")
    host: str = Field(min_length=1, description="The origin DNS hostname; no IP literal, no port, no path.")
    port: int = Field(default=443, ge=1, le=65535, description="The origin TCP port (1..65535).")

    @field_validator("scheme")
    @classmethod
    def _check_scheme(cls, v: str) -> str:
        s = str(v or "").strip().lower()
        if s != "https":
            raise ValueError("origin scheme must be 'https'")
        return s

    @field_validator("host")
    @classmethod
    def _check_host(cls, v: str) -> str:
        return check_dns_host(v, label="origin host")


class MonitoringLease(BaseModel):
    """The short-lived liveness window that bounds a V2 grant end-to-end (§4.7: proposed 1 h, renewed every
    10 min). The grant is ACTIVE only while the lease covers ``now``; once the lease LAPSES the data plane
    degrades to uninspected PASS-THROUGH (R16) — it never hard-fails the tenant's traffic for a lapsed lease.
    The lease window must sit INSIDE the grant's own ``[not_before, not_after)``."""

    model_config = ConfigDict(extra="forbid")

    not_before: datetime
    not_after: datetime

    @model_validator(mode="after")
    def _check_window(self) -> "MonitoringLease":
        if self.not_after <= self.not_before:
            raise ValueError("lease not_after must be strictly after not_before")
        return self

    def covers(self, now: datetime) -> bool:
        """True iff the lease is live at ``now`` (half-open ``[not_before, not_after)``)."""
        return _as_utc(self.not_before) <= _as_utc(now) < _as_utc(self.not_after)


# --- the V2 grant ------------------------------------------------------------------------------------------
class MonitoringAuthorityV2(BaseModel):
    """The per-tenant, per-instance DEFENSIVE-monitoring authorization V2 the keyless AEGIS plane verifies
    before it inspects or (release-gated) enforces on a tenant's traffic."""

    model_config = ConfigDict(extra="forbid")

    subject: AuthoritySubject
    capabilities: list[MonitoringCapability] = Field(min_length=1, description="The explicit capability set; "
                                                     "sorted + de-duplicated. Must include at least one capability; "
                                                     "OBSERVE is the always-safe base, the rest are release-gated.")
    epoch: int = Field(ge=1, description="Monotone grant generation. Inside the signed bytes so a grant below the "
                       "subject's epoch floor (max local / EpochStatement) is detectably STALE and fails closed.")
    not_before: datetime
    not_after: datetime
    lease: MonitoringLease
    instance_id: str = Field(min_length=1, description="The deployment instance this grant is published for (a "
                             "safe path component); the per-instance publish path is derived from it.")
    replica_index: int = Field(default=0, ge=0, description="Which replica of the instance (0-based).")
    edge_chain: str = Field(default="shared_actor", description="The declared edge provider_id, or the "
                            "'shared_actor' sentinel when the tenant declares no dedicated edge chain (V5).")
    origin: Optional[OriginTuple] = Field(default=None, description="The declared HTTPS origin tuple. Paired with "
                                          "origin_binding_sha256: both present or both absent (no binding => no "
                                          "signature; a grant cannot carry an origin without its binding proof).")
    origin_binding_sha256: Optional[str] = Field(default=None, description="sha256 (64 lowercase hex) of the "
                                                 "signed origin binding this grant is bound to; set iff origin is.")
    issued_at: float = Field(default=0.0, description="Mint anchor / per-subject anti-replay high-water on the "
                             "minting spine (a captured grant cannot resurrect a superseded one).")
    issued_by: str = Field(default="", description="Owner / provisioner that minted this grant.")
    note: str = Field(default="")

    @field_validator("capabilities")
    @classmethod
    def _normalize_caps(cls, v: Any) -> list[MonitoringCapability]:
        caps = _normalize_capabilities(v)
        if not caps:
            raise ValueError("a grant must carry at least one capability")
        return caps

    @field_validator("instance_id")
    @classmethod
    def _check_instance(cls, v: str) -> str:
        return check_component(v, label="instance_id")

    @model_validator(mode="after")
    def _check(self) -> "MonitoringAuthorityV2":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        # The lease is the TIGHT bound: it must sit inside the grant's own window, never extend it.
        if self.lease.not_before < self.not_before or self.lease.not_after > self.not_after:
            raise ValueError("the lease window must sit inside the grant's [not_before, not_after)")
        # Origin + binding are paired: no binding => no signature (§4.4). A grant that declares an origin without
        # its binding sha256 (or vice-versa) is refused at construction, so an unbound origin can never be signed.
        if (self.origin is None) != (self.origin_binding_sha256 is None):
            raise ValueError("origin and origin_binding_sha256 are declared together (no binding => no signature)")
        if self.origin_binding_sha256 is not None and not _SHA256_HEX_RE.match(self.origin_binding_sha256):
            raise ValueError("origin_binding_sha256 must be 64 lowercase hex characters")
        return self

    def covers(self, now: datetime) -> bool:
        """True iff ``now`` is inside the grant's OUTER window (not the lease — see :meth:`lease_active`)."""
        return _as_utc(self.not_before) <= _as_utc(now) < _as_utc(self.not_after)

    def lease_active(self, now: datetime) -> bool:
        """True iff the grant's LEASE covers ``now`` (the tight end-to-end liveness bound). A False here is the
        R16 pass-through trigger even while the outer window still covers ``now``."""
        return self.lease.covers(now)

    def has_capability(self, capability: MonitoringCapability) -> bool:
        return capability in self.capabilities


class SignedMonitoringAuthorityV2(BaseModel):
    """A V2 grant plus governance signatures over its canonical form, verified against the OWNER ``TrustRoot``.
    A tampered subject / capability / origin / epoch / window / lease / instance is detected (every field is in
    the signed bytes)."""

    model_config = ConfigDict(extra="forbid")

    document: MonitoringAuthorityV2
    signatures: list[Signature] = Field(min_length=1)


# --- EpochStatement ----------------------------------------------------------------------------------------
class EpochStatement(BaseModel):
    """The owner-signed monotone epoch marker for one subject. The unit sets floor = max(local, statement) on
    boot / replacement / move; a grant whose epoch is below the floor is STALE and fails closed. A higher epoch
    SUPERSEDES a lower (the authoritative placement/authority generation has moved on)."""

    model_config = ConfigDict(extra="forbid")

    subject: AuthoritySubject
    epoch: int = Field(ge=1, description="The monotone epoch floor this statement sets for the subject.")
    issued_at: float = Field(default=0.0, description="Mint anchor / per-subject anti-replay high-water.")
    note: str = Field(default="")


class SignedEpochStatement(BaseModel):
    """An epoch statement plus governance signatures over its canonical form, verified against the owner root."""

    model_config = ConfigDict(extra="forbid")

    document: EpochStatement
    signatures: list[Signature] = Field(min_length=1)


# --- EnforceRelease (SEPARATE release root) ----------------------------------------------------------------
class EnforceRelease(BaseModel):
    """The owner-held release production enforcement needs (D30), signed on the SEPARATE RELEASE ROOT and
    verified against the release root ALONE. It names the ENFORCING capabilities it covers, a bounded window and
    a monotone epoch. Absent or unverifiable => NO enforce (fail closed); OBSERVE never needs a release."""

    model_config = ConfigDict(extra="forbid")

    subject: AuthoritySubject
    released_capabilities: list[MonitoringCapability] = Field(min_length=1, description="The ENFORCING "
                                                             "capabilities this release covers (a subset of "
                                                             "block | virtual_patch | respond); sorted + de-duped.")
    epoch: int = Field(ge=1, description="Monotone release generation (a newer release supersedes a stale one).")
    not_before: datetime
    not_after: datetime
    issued_at: float = Field(default=0.0, description="Mint anchor / per-subject anti-replay high-water.")
    issued_by: str = Field(default="", description="The release signer(s) under the release root (D30).")
    note: str = Field(default="")

    @field_validator("released_capabilities")
    @classmethod
    def _normalize_released(cls, v: Any) -> list[MonitoringCapability]:
        caps = _normalize_capabilities(v)
        bad = [c for c in caps if c not in ENFORCING_CAPABILITIES]
        if bad:
            raise ValueError(f"a release covers only ENFORCING capabilities "
                             f"{sorted(c.value for c in ENFORCING_CAPABILITIES)}; got non-enforcing {bad}")
        if not caps:
            raise ValueError("a release must cover at least one enforcing capability")
        return caps

    @model_validator(mode="after")
    def _check_window(self) -> "EnforceRelease":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self

    def covers(self, now: datetime) -> bool:
        return _as_utc(self.not_before) <= _as_utc(now) < _as_utc(self.not_after)

    def releases(self, capability: MonitoringCapability) -> bool:
        return capability in self.released_capabilities


class SignedEnforceRelease(BaseModel):
    """An enforce release plus signatures over its canonical form, verified against the RELEASE ``TrustRoot``
    (NOT the owner root). The separate root is the wall: an owner-root signature can never satisfy this."""

    model_config = ConfigDict(extra="forbid")

    document: EnforceRelease
    signatures: list[Signature] = Field(min_length=1)


# --- signed revocation -------------------------------------------------------------------------------------
class MonitoringRevocationV2(BaseModel):
    """The owner-signed revocation that supersedes a grant: honoured when it verifies under the owner root and
    its epoch is at or above the grant's. (The UNSIGNED :class:`AuthorityWithdrawal` is the other, fail-safe way
    to stop — this one is the authoritative, replay-resistant owner act that advances the epoch.)"""

    model_config = ConfigDict(extra="forbid")

    subject: AuthoritySubject
    epoch: int = Field(ge=1, description="The revocation's epoch; it supersedes any grant at or below it.")
    issued_at: float = Field(default=0.0, description="Mint anchor / per-subject anti-replay high-water.")
    reason: str = Field(default="")


class SignedMonitoringRevocationV2(BaseModel):
    """A revocation plus signatures over its canonical form, verified against the owner root."""

    model_config = ConfigDict(extra="forbid")

    document: MonitoringRevocationV2
    signatures: list[Signature] = Field(min_length=1)


# --- unsigned fail-safe signals (the SAFE direction; honoured without a signature) -------------------------
class AuthorityWithdrawal(BaseModel):
    """An UNSIGNED local withdrawal that reaches the unit via its control dir (§4.7). It only ever REMOVES
    authority (=> pass-through), so it is honoured without a signature — the SAFE direction. It can NEVER enable
    monitoring or enforcement; a captured/forged withdrawal merely re-withdraws (a no-op toward MORE enforcement)."""

    model_config = ConfigDict(extra="forbid")

    subject: AuthoritySubject
    reason: str = Field(default="")


class OverrideTarget(str, enum.Enum):
    """The closed, DOWNGRADE-ONLY set an unsigned override may clamp to. Neither value is an enforcing mode, so
    an override can never RAISE authority — it can only degrade a live grant toward observe or pass-through."""

    PASS_THROUGH = "pass_through"
    OBSERVE = "observe"


class EnforcementOverride(BaseModel):
    """An UNSIGNED local override that reaches the unit via its control dir (§4.7). ``downgrade_to`` is a closed
    downgrade-only enum, so an override — honoured without a signature because it only ever REDUCES authority —
    can clamp a live grant down to observe or pass-through but can NEVER turn observe into an enforcing mode."""

    model_config = ConfigDict(extra="forbid")

    subject: AuthoritySubject
    downgrade_to: OverrideTarget = Field(description="The strictly-lower authority to clamp to (observe or "
                                         "pass_through); never an enforcing mode.")
    reason: str = Field(default="")


# ============================================================================================================
# Canonical signing bytes + sign/verify (one per signed contract; the exact reuse idiom)
# ============================================================================================================
def monitoring_authority_v2_signing_bytes(grant: MonitoringAuthorityV2) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the v2 domain tag followed by the compact, sorted-key
    UTF-8 JSON of the document (byte-identical SHAPE to the v1 / lease / shard signing bytes, DISTINCT tag)."""
    return _AUTHORITY_V2_DOMAIN + canonical_json(grant.model_dump(mode="json"))


def epoch_statement_signing_bytes(statement: EpochStatement) -> bytes:
    """The exact bytes signed/verified for an epoch statement (domain tag + canonical document JSON)."""
    return _EPOCH_STATEMENT_DOMAIN + canonical_json(statement.model_dump(mode="json"))


def enforce_release_signing_bytes(release: EnforceRelease) -> bytes:
    """The exact bytes signed/verified for an enforce release (domain tag + canonical document JSON)."""
    return _ENFORCE_RELEASE_DOMAIN + canonical_json(release.model_dump(mode="json"))


def monitoring_revocation_v2_signing_bytes(revocation: MonitoringRevocationV2) -> bytes:
    """The exact bytes signed/verified for a v2 revocation. It reuses the v2 grant domain tag (a revocation is
    part of the same authority lifecycle and verifies under the same owner root); the DOCUMENT shapes are
    disjoint (a revocation has no capabilities / lease / origin), so neither can be parsed as the other even
    before the signature check (``extra="forbid"`` on both)."""
    return _AUTHORITY_V2_DOMAIN + canonical_json(revocation.model_dump(mode="json"))


def _signatures(document_bytes: bytes, signers: dict[str, str]) -> list[Signature]:
    return [Signature(key_id=key_id, signature_b64=sign(priv_b64, document_bytes))
            for key_id, priv_b64 in signers.items()]


def sign_monitoring_authority_v2(document: MonitoringAuthorityV2, signers: dict[str, str]) -> SignedMonitoringAuthorityV2:
    """Owner-sign a V2 grant with each ``key_id -> private_key_b64``. Sovereign-side; the private key is used
    only inside :func:`sign` and never persisted or returned."""
    return SignedMonitoringAuthorityV2(document=document,
                                       signatures=_signatures(monitoring_authority_v2_signing_bytes(document), signers))


def sign_epoch_statement(document: EpochStatement, signers: dict[str, str]) -> SignedEpochStatement:
    """Owner-sign an epoch statement. Sovereign-side (the reconciler, §4.4)."""
    return SignedEpochStatement(document=document,
                                signatures=_signatures(epoch_statement_signing_bytes(document), signers))


def sign_enforce_release(document: EnforceRelease, signers: dict[str, str]) -> SignedEnforceRelease:
    """Sign an enforce release with the RELEASE-ROOT signer(s). An owner act under the release root (D30); the
    caller supplies at least the release root's threshold of release-key signers, NOT the owner key."""
    return SignedEnforceRelease(document=document,
                                signatures=_signatures(enforce_release_signing_bytes(document), signers))


def sign_monitoring_revocation_v2(document: MonitoringRevocationV2, signers: dict[str, str]) -> SignedMonitoringRevocationV2:
    """Owner-sign a v2 revocation. Sovereign-side."""
    return SignedMonitoringRevocationV2(document=document,
                                        signatures=_signatures(monitoring_revocation_v2_signing_bytes(document), signers))


def _verify(document_bytes: bytes, signatures: list[Signature], trust_root: TrustRoot, *, what: str) -> "tuple[bool, str]":
    """The shared verify-only, fail-CLOSED body: reject a quorum-collapsing trust root (duplicate authorizer
    public keys under distinct key_ids) exactly as the sibling primitives do, then count distinct valid
    signatures against the threshold. Never raises — a malformed/weak-key signature is a refusal, not a crash."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(document_bytes, signatures, trust_root)
    except (IntegrityError, TypeError, ValueError) as e:   # ValueError: a document that cannot be UTF-8 encoded
        return False, f"{what} signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason


def verify_monitoring_authority_v2(signed: SignedMonitoringAuthorityV2, trust_root: TrustRoot) -> "tuple[bool, str]":
    """``(ok, reason)``: True iff the threshold of DISTINCT OWNER-root authorisers validly signed the grant's
    canonical form. Verify-only (no private material; safe on the keyless AEGIS plane). Fail-CLOSED."""
    return _verify(monitoring_authority_v2_signing_bytes(signed.document), signed.signatures, trust_root,
                   what="monitoring-authority-v2")


def verify_epoch_statement(signed: SignedEpochStatement, trust_root: TrustRoot) -> "tuple[bool, str]":
    """``(ok, reason)``: True iff the threshold of DISTINCT OWNER-root authorisers signed the epoch statement.
    Verify-only, fail-CLOSED."""
    return _verify(epoch_statement_signing_bytes(signed.document), signed.signatures, trust_root,
                   what="epoch-statement")


def verify_enforce_release(signed: SignedEnforceRelease, release_root: TrustRoot) -> "tuple[bool, str]":
    """``(ok, reason)``: True iff the threshold of DISTINCT RELEASE-ROOT authorisers signed the release. Verified
    against the SEPARATE RELEASE ROOT — pass the release root here, NOT the owner root. An owner-root signature
    is refused because the owner key is not among the release root's authorisers (the separate-root wall).
    Verify-only, fail-CLOSED."""
    return _verify(enforce_release_signing_bytes(signed.document), signed.signatures, release_root,
                   what="enforce-release")


def verify_monitoring_revocation_v2(signed: SignedMonitoringRevocationV2, trust_root: TrustRoot) -> "tuple[bool, str]":
    """``(ok, reason)``: True iff the threshold of DISTINCT OWNER-root authorisers signed the revocation.
    Verify-only, fail-CLOSED."""
    return _verify(monitoring_revocation_v2_signing_bytes(signed.document), signed.signatures, trust_root,
                   what="monitoring-revocation-v2")


# ============================================================================================================
# The one publish-path helper
# ============================================================================================================
def authority_publish_path(subject: AuthoritySubject, *, instance_id: str, replica_index: int = 0) -> str:
    """The ONE canonical place that computes where a per-instance V2 authority is published (§4.7 per-instance
    publish). Returns a fixed-charset, hashed file name for the (subject, instance, replica) tuple: a sha256
    hex digest + ``.json``, so NO org / host / instance string — however hostile — can traverse the publish
    directory or collide across subjects. Deterministic: the same tuple always maps to the same path; distinct
    tuples (incl. distinct instance_id or replica_index) map to distinct paths with overwhelming probability.

    ``instance_id`` is re-validated as a safe component here too, so a bad id is refused at the publish seam and
    not only at grant construction."""
    iid = check_component(instance_id, label="instance_id")
    if not isinstance(replica_index, int) or isinstance(replica_index, bool) or replica_index < 0:
        raise ValueError("replica_index must be a non-negative integer")
    key = f"{subject.kind.value}\x00{subject.org_id}\x00{subject.host}\x00{iid}\x00{replica_index}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest() + ".json"


# ============================================================================================================
# The contract-level decision (what the data plane composes from ALREADY-VERIFIED documents)
# ============================================================================================================
class AuthorityOutcome(str, enum.Enum):
    """The three contract-level outcomes. PASS_THROUGH = no authority / lapsed lease / withdrawn / stale /
    superseded — uninspected, shown VISIBLY (R16). OBSERVE = a live grant permits inspection + alerting, never
    a block. ENFORCE = a live grant AND a verified release permit the enforcing capability (still per-request
    re-authorized downstream)."""

    PASS_THROUGH = "pass_through"
    OBSERVE = "observe"
    ENFORCE = "enforce"


class AuthorityDecision(BaseModel):
    """The contract-level decision: an outcome, the enforcing capability it is FOR (only when ENFORCE), and the
    machine-readable reasons that led there. Everything is fail-closed toward PASS_THROUGH / OBSERVE."""

    model_config = ConfigDict(extra="forbid")

    outcome: AuthorityOutcome
    capability: Optional[MonitoringCapability] = None
    reasons: tuple[str, ...] = ()


def evaluate_authority(
    *,
    grant: Optional[MonitoringAuthorityV2],
    now: datetime,
    epoch_floor: int = 0,
    requested_capability: Optional[MonitoringCapability] = None,
    release: Optional[EnforceRelease] = None,
    revocation: Optional[MonitoringRevocationV2] = None,
    withdrawal: Optional[AuthorityWithdrawal] = None,
    override: Optional[EnforcementOverride] = None,
) -> AuthorityDecision:
    """Compose ALREADY-VERIFIED authority documents into a contract-level decision. This holds NO key and does
    NO signature math: the data plane (2c / 2f / 29) verifies each document against the right root FIRST (grant
    + revocation under the owner root; release under the release root; epoch_floor = max over verified
    EpochStatements) and passes only what verified. The unsigned ``withdrawal`` / ``override`` are passed as-is
    (the SAFE direction needs no signature). Everything fails CLOSED toward PASS_THROUGH / OBSERVE.

    Precedence (each step can only move toward LESS authority):
      1. no grant => PASS_THROUGH (nothing authorizes anything).
      2. unsigned withdrawal present => PASS_THROUGH (fail-safe stop).
      3. signed revocation at or above the grant's epoch => PASS_THROUGH (the owner superseded it).
      4. grant epoch below the floor (a higher EpochStatement) => PASS_THROUGH (STALE).
      5. lease lapsed, or outer window lapsed, at ``now`` => PASS_THROUGH (R16).
      6. otherwise the grant is LIVE: base outcome OBSERVE.
      7. for a requested ENFORCING capability: ENFORCE only iff the grant carries it AND a verified release
         covers it AND is live at ``now`` AND the release epoch is at or above the floor; else degrade to
         OBSERVE (never block without a release).
      8. an unsigned override clamps the result down to its downgrade-only target; it can never raise it.
    """
    reasons: list[str] = []
    if grant is None:
        return AuthorityDecision(outcome=AuthorityOutcome.PASS_THROUGH, reasons=("no-grant",))

    if withdrawal is not None and withdrawal.subject == grant.subject:
        return AuthorityDecision(outcome=AuthorityOutcome.PASS_THROUGH, reasons=("withdrawn",))

    if (revocation is not None and revocation.subject == grant.subject
            and revocation.epoch >= grant.epoch):
        return AuthorityDecision(outcome=AuthorityOutcome.PASS_THROUGH, reasons=("revoked",))

    if grant.epoch < epoch_floor:
        return AuthorityDecision(outcome=AuthorityOutcome.PASS_THROUGH, reasons=("stale-epoch",))

    if not grant.lease_active(now):
        return AuthorityDecision(outcome=AuthorityOutcome.PASS_THROUGH, reasons=("lease-lapsed",))

    if not grant.covers(now):
        return AuthorityDecision(outcome=AuthorityOutcome.PASS_THROUGH, reasons=("window-lapsed",))

    # The grant is LIVE. OBSERVE is always permitted by a live grant.
    outcome = AuthorityOutcome.OBSERVE
    capability: Optional[MonitoringCapability] = None
    reasons.append("grant-live")

    if requested_capability is not None and requested_capability in ENFORCING_CAPABILITIES:
        if not grant.has_capability(requested_capability):
            reasons.append("capability-not-granted")
        elif release is None:
            reasons.append("no-release")                      # fail-closed: no enforce without a release
        elif release.subject != grant.subject:
            reasons.append("release-subject-mismatch")
        elif not release.releases(requested_capability):
            reasons.append("capability-not-released")
        elif not release.covers(now):
            reasons.append("release-window-lapsed")
        elif release.epoch < epoch_floor:
            reasons.append("stale-release-epoch")
        else:
            outcome = AuthorityOutcome.ENFORCE
            capability = requested_capability
            reasons.append("release-valid")

    # An unsigned override can only ever DOWNGRADE (observe / pass_through); it never raises the outcome.
    if override is not None and override.subject == grant.subject:
        if override.downgrade_to is OverrideTarget.PASS_THROUGH:
            return AuthorityDecision(outcome=AuthorityOutcome.PASS_THROUGH,
                                     reasons=tuple(reasons + ["override-pass-through"]))
        # downgrade_to == OBSERVE: clamp an ENFORCE down to OBSERVE, leave OBSERVE / nothing as-is.
        if outcome is AuthorityOutcome.ENFORCE:
            outcome = AuthorityOutcome.OBSERVE
            capability = None
            reasons.append("override-observe")

    return AuthorityDecision(outcome=outcome, capability=capability, reasons=tuple(reasons))
