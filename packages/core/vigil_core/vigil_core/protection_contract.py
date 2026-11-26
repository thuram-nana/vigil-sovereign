"""AEGIS AS-2b — the protection contract (§4.5) + the append-only PROVIDER REGISTRY.

The ``protection_contract`` is the single READ-ONLY projection of a tenant's whole protection posture
— asset, edge, origin + binding + lock, sensors, telemetry, detections, enforcement capabilities,
the authority / release / flag / kill-switch terms, the failure policy, the customer prerequisites,
the trust assumptions, the six posture dimensions and the one ``headline``. It is NEVER authority:
nothing here is signed and nothing here grants anything — the authority lives in the AS-2a
``authority_v2`` records, which this contract only REFERENCES (by digest + declared state). AS-2b
ships the FULL SCHEMA; AS-4b ships the evaluator that FILLS and GRADES it (validators V1–V7), and
later provider slices (AS-10a/b, AS-17b, AS-18b, …) extend it by APPENDING to the provider registry.

Doctrine (see :mod:`vigil_core.aegis_schemas` for the shared rules this module inherits):

  * READ-ONLY / NEVER AUTHORITY — no signing, no key, no mutation of a signed record. The contract is
    a snapshot a renderer reads; it cannot raise anyone's authority.
  * FAIL-CLOSED — ``headline`` defaults to ``unsupported`` (claim nothing) and EVERY dimension to
    ``unsupported``; every prerequisite / term / lease defaults to the UNMET / INVALID value; the
    failure policy defaults to fail-CLOSED (``protection_interrupted``, not fail-open). A half-built
    contract therefore reads as "no protection", never as "enforcing".
  * APPEND-ONLY REGISTRY — :class:`ProviderRegistry` grows only by :meth:`ProviderRegistry.register`,
    which refuses a duplicate id and returns a NEW registry with the provider appended; the existing
    prefix is preserved by construction, so a later slice adds a provider without editing this file
    and without being able to rewrite an earlier provider.
  * DETERMINISM — canonical JSON, no wallclock, no RNG; set-valued lists sorted + de-duplicated.

FATAL-2: imports only ``vigil_core`` siblings + stdlib + pydantic. No ``framework``, no ``sigil``.
"""
from __future__ import annotations

import enum
from typing import Any, Final

from pydantic import ConfigDict, Field, field_validator, model_validator

from .aegis_schemas import (
    AdapterCapability,
    AssetRef,
    CanonicalModel,
    EffectVerification,
    EngineHealthState,
    OutcomeClass,
    ResponseManifest,
    clean_token,
)
from .authority_v2 import MonitoringCapability, OriginTuple, check_component
from .monitoring_authority import MonitoringMode

PROTECTION_CONTRACT_SCHEMA: Final[str] = "vigil.aegis.protection-contract.v1"
PROVIDER_REGISTRY_SCHEMA: Final[str] = "vigil.aegis.provider-registry.v1"

_MAX_LIST = 256


def _sorted_capabilities(values: Any, *, label: str) -> list[MonitoringCapability]:
    """SORTED-BY-VALUE, DE-DUPLICATED list of :class:`MonitoringCapability` (determinism), fail-closed."""
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise ValueError(f"{label} must be a list of capabilities")
    seen: set[str] = set()
    out: list[MonitoringCapability] = []
    for item in values:
        cap = item if isinstance(item, MonitoringCapability) else MonitoringCapability(str(item))
        if cap.value not in seen:
            seen.add(cap.value)
            out.append(cap)
    out.sort(key=lambda c: c.value)
    return out


def _clean_list(values: Any, *, label: str, max_len: int = 128) -> list[str]:
    """SORTED, DE-DUPLICATED list of :func:`clean_token`-validated strings."""
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise ValueError(f"{label} must be a list of tokens")
    seen: set[str] = set()
    out: list[str] = []
    for item in values:
        tok = clean_token(item, label=label, max_len=max_len)
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
    if len(out) > _MAX_LIST:
        raise ValueError(f"{label} has more than {_MAX_LIST} entries")
    out.sort()
    return out


def _opt_sha256(value: str, *, label: str) -> str:
    """'' or a 64-char lowercase hex digest, fail-closed."""
    if not value:
        return value
    s = str(value).strip().lower()
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError(f"{label} must be '' or a 64-char lowercase hex digest")
    return s


# --- posture vocabulary --------------------------------------------------------------------------
class Headline(str, enum.Enum):
    """The ONE honest headline (§4.5), a strict ladder from the fail-closed floor upward. The six
    values are also the per-dimension level. A consumer (AS-4b) computes the headline as the floor of
    the dimensions + the V1–V7 caps; the SCHEMA only declares the vocabulary and defaults to
    ``unsupported`` (claim nothing)."""

    UNSUPPORTED = "unsupported"   # fail-closed floor — the surface is not covered
    INACTIVE = "inactive"         # supported but not turned on
    DEGRADED = "degraded"         # active but impaired (crash loop / expiring / pending revocation)
    UNVERIFIED = "unverified"     # active, but a tenant-side proof is missing (caps the headline, V2)
    OBSERVING = "observing"       # inspecting + alerting; never blocks
    ENFORCING = "enforcing"       # release + crypto lock + verified edge + applied receipts (V3)


class PostureDimension(str, enum.Enum):
    """The six axes (§4.5 "six dimensions") whose floor is the headline. Each maps to a structural
    group of the contract, so the dimension set is grounded in the schema, not invented."""

    ASSET_PLACEMENT = "asset_placement"
    EDGE = "edge"
    ORIGIN_LOCK = "origin_lock"
    TELEMETRY = "telemetry"
    DETECTION_ENFORCEMENT = "detection_enforcement"
    AUTHORITY_RELEASE = "authority_release"


class LicensingMode(str, enum.Enum):
    """The declared licensing posture (AS-7a gate projects this; the authoritative vocabulary is the
    engine-side ``UseMode``, carried here as a plain token). DEFAULT ``unknown`` (fail-closed)."""

    UNKNOWN = "unknown"
    NONCOMMERCIAL = "noncommercial"
    EVALUATION = "evaluation"
    COMMERCIAL = "commercial"


class BindingState(str, enum.Enum):
    """§4.4/§4.5 origin-binding state. DEFAULT ``unverified`` (no proof yet)."""

    UNVERIFIED = "unverified"
    PENDING_REPROOF = "pending_reproof"
    PROVEN = "proven"
    SUSPENDED = "suspended"       # ≥3 failed re-proofs → 502 "origin unverified" (V6 → degraded)


class LockState(str, enum.Enum):
    """§4.4 origin-lock state. An IP allowlist alone "does not isolate you from other SIGIL tenants",
    so only ``crypto_verified`` (optionally + ip) permits a release. DEFAULT ``none``."""

    NONE = "none"
    IP_ALLOWLIST_ONLY = "ip_allowlist_only"
    CRYPTO_VERIFIED = "crypto_verified"
    CRYPTO_VERIFIED_IP = "crypto_verified+ip"


class CertState(str, enum.Enum):
    """§4.5 edge viewer-TLS cert state. DEFAULT ``unknown``."""

    UNKNOWN = "unknown"
    PENDING = "pending"
    ISSUED = "issued"
    EXPIRING = "expiring"
    EXPIRED = "expired"


class RevocationState(str, enum.Enum):
    """§4.5 authority revocation state. DEFAULT ``none`` (no revocation in flight). ``pending`` →
    degraded headline + stops at lease expiry (V6)."""

    NONE = "none"
    PENDING = "pending"
    EFFECTIVE = "effective"


class ReleaseState(str, enum.Enum):
    """§4.5 enforce-release state (the SEPARATE release root, D30). DEFAULT ``none`` — NO enforce
    without a verified release (fail-closed)."""

    NONE = "none"
    RELEASED = "released"
    WITHHELD = "withheld"
    WITHDRAWN = "withdrawn"       # a withdrawal alerts and drops enforcement


class SignerRole(str, enum.Enum):
    """Who signed the referenced grant. DEFAULT ``none`` (unsigned / unknown)."""

    NONE = "none"
    OWNER = "owner"
    RELEASE = "release"
    PROVISIONER = "provisioner"


class FailureBasis(str, enum.Enum):
    """What the gateway does on its own failure / overload. DEFAULT ``fail_closed`` — availability is
    preserved by PASS-THROUGH only where the tenant OPTED IN; otherwise protection interrupts
    honestly rather than silently forwarding uninspected (§5)."""

    FAIL_CLOSED = "fail_closed"            # 503 "Protection interrupted" (the safe default)
    PROTECTION_INTERRUPTED = "protection_interrupted"
    FAIL_OPEN_OPT_IN = "fail_open_opt_in"  # pass-through, ONLY where the tenant opted in


# --- edge / origin blocks ------------------------------------------------------------------------
class ViewerTls(CanonicalModel):
    """§4.5 edge viewer-TLS custody. The trust statement: AWS CloudFront terminates viewer TLS and
    holds the keys — the SIGIL unit never sees the viewer handshake."""

    terminated_by: str = Field(default="aws_cloudfront")
    key_custody: str = Field(default="aws")
    cert_state: CertState = Field(default=CertState.UNKNOWN)

    @field_validator("terminated_by", "key_custody")
    @classmethod
    def _tok(cls, v: str, info: Any) -> str:
        return clean_token(v, label=f"viewer_tls.{info.field_name}", max_len=48)


class EdgeBlock(CanonicalModel):
    """§4.5 ``edge{provider, ddos, viewer_tls, edge_auth, chain, rate_limits}``."""

    provider: str = Field(default="", description="The edge provider (e.g. aws_cloudfront).")
    ddos: str = Field(default="", description="The DDoS posture (e.g. aws_shield).")
    viewer_tls: ViewerTls = Field(default_factory=ViewerTls)
    edge_auth: bool = Field(default=False, description="Whether the per-tenant edge secret is verified at the origin.")
    chain: str = Field(default="shared_actor", description="The edge chain id, or 'shared_actor' when unverified (V5).")
    rate_limits: bool = Field(default=False, description="Whether edge rate limits are configured.")

    @field_validator("provider", "ddos")
    @classmethod
    def _tok_opt(cls, v: str, info: Any) -> str:
        return clean_token(v, label=f"edge.{info.field_name}", max_len=48, allow_empty=True)

    @field_validator("chain")
    @classmethod
    def _tok_chain(cls, v: str) -> str:
        return clean_token(v, label="edge.chain", max_len=64)


class OriginBinding(CanonicalModel):
    """§4.4/§4.5 ``origin.binding{sha256, state, reprove_due}``."""

    sha256: str = Field(default="", description="The origin_binding_sha256 the v2 grant carries, or ''.")
    state: BindingState = Field(default=BindingState.UNVERIFIED)
    reprove_due: str = Field(default="", description="A caller-supplied re-proof-due marker (epoch/ISO token); no clock here.")

    @field_validator("sha256")
    @classmethod
    def _sha(cls, v: str) -> str:
        return _opt_sha256(v, label="origin.binding.sha256")

    @field_validator("reprove_due")
    @classmethod
    def _due(cls, v: str) -> str:
        return clean_token(v, label="origin.binding.reprove_due", max_len=48, allow_empty=True)


class OriginLock(CanonicalModel):
    """§4.4 ``origin.lock{state, method}``. A release REQUIRES ``crypto_verified`` (V3)."""

    state: LockState = Field(default=LockState.NONE)
    method: str = Field(default="", description="The lock method (mtls / hmac_header / secret_header), or ''.")

    @field_validator("method")
    @classmethod
    def _m(cls, v: str) -> str:
        return clean_token(v, label="origin.lock.method", max_len=32, allow_empty=True)


class OriginBlock(CanonicalModel):
    """§4.5 ``origin{tuple, binding, lock}``. ``tuple`` reuses the AS-2a :class:`OriginTuple` (https +
    bare DNS host, IP literals refused) — the SAME shape the signed grant declares, so the contract
    and the authority never drift on what "the origin" is."""

    tuple: OriginTuple
    binding: OriginBinding = Field(default_factory=OriginBinding)
    lock: OriginLock = Field(default_factory=OriginLock)


class RequiredSensor(CanonicalModel):
    """§4.5 ``required_sensors[]{kind, state incl. crash_looping}``. ``state`` reuses
    :class:`EngineHealthState` (which carries ``crash_loop``); default ``unknown`` (fail-closed)."""

    kind: str = Field(description="The sensor kind (a token).")
    state: EngineHealthState = Field(default=EngineHealthState.UNKNOWN)

    @field_validator("kind")
    @classmethod
    def _k(cls, v: str) -> str:
        return clean_token(v, label="required_sensor.kind", max_len=48)


# --- authority / enforcement projections (NEVER authority — a snapshot of already-verified state) -
class LeaseProjection(CanonicalModel):
    """A READ-ONLY projection of the grant's lease. ``valid`` defaults to ``False`` — a lapsed or
    absent lease reads as PASS-THROUGH (R16), never as live."""

    valid: bool = Field(default=False)
    not_after: str = Field(default="", description="A caller-supplied lease-expiry marker (token); no clock here.")

    @field_validator("not_after")
    @classmethod
    def _na(cls, v: str) -> str:
        return clean_token(v, label="lease.not_after", max_len=48, allow_empty=True)


class RevocationProjection(CanonicalModel):
    """§4.5 ``revocation{state, acked_epoch}``."""

    state: RevocationState = Field(default=RevocationState.NONE)
    acked_epoch: int = Field(default=0, ge=0, description="The epoch at which the unit acknowledged the revocation.")


class AuthorizedActions(CanonicalModel):
    """§4.5 ``authorized_actions{grant_sha256, signer_role, mode, epoch, capabilities, lease,
    revocation}`` — a projection of the VERIFIED authority, read-only. ``mode`` defaults to
    ``observe`` and ``capabilities`` to empty (fail-closed: nothing authorized until a grant says so)."""

    grant_sha256: str = Field(default="", description="sha256 of the referenced v2 grant, or ''.")
    signer_role: SignerRole = Field(default=SignerRole.NONE)
    mode: MonitoringMode = Field(default=MonitoringMode.OBSERVE)
    epoch: int = Field(default=0, ge=0)
    capabilities: list[MonitoringCapability] = Field(default_factory=list)
    lease: LeaseProjection = Field(default_factory=LeaseProjection)
    revocation: RevocationProjection = Field(default_factory=RevocationProjection)

    @field_validator("grant_sha256")
    @classmethod
    def _sha(cls, v: str) -> str:
        return _opt_sha256(v, label="authorized_actions.grant_sha256")

    @field_validator("capabilities")
    @classmethod
    def _caps(cls, v: Any) -> list[MonitoringCapability]:
        return _sorted_capabilities(v, label="authorized_actions.capabilities")


class EnforceReleaseProjection(CanonicalModel):
    """§4.5 ``enforce_release{state}`` — the separate-root release state. DEFAULT ``none`` (no enforce)."""

    state: ReleaseState = Field(default=ReleaseState.NONE)


class EnforcementTerms(CanonicalModel):
    """§4.5 ``enforcement_terms{grant_block, enforce_release, flag, mode, entitlement, kill_switch,
    override, effective, reasons}`` — the conjunction a consumer evaluates. EVERY boolean defaults to
    the NON-ENFORCING value and ``effective`` to ``False``: enforcement is the AND of many terms and
    the schema never pre-asserts it (AS-4b/AS-29 compute ``effective``; here it is a fail-closed
    projection)."""

    grant_block: bool = Field(default=False, description="The grant carries an enforcing capability.")
    enforce_release: EnforceReleaseProjection = Field(default_factory=EnforceReleaseProjection)
    flag: bool = Field(default=False, description="VIGIL_AEGIS_SAAS_ENFORCE is on (default OFF).")
    mode: MonitoringMode = Field(default=MonitoringMode.OBSERVE)
    entitlement: bool = Field(default=False, description="The AEGIS_RESPOND entitlement is present.")
    kill_switch_tripped: bool = Field(default=False, description="A tripped kill-switch drops enforcement.")
    override_active: bool = Field(default=False, description="A downgrade-only override is in force.")
    effective: bool = Field(default=False, description="COMPUTED effective-enforcing; fail-closed default False.")
    reasons: list[str] = Field(default_factory=list)

    @field_validator("reasons")
    @classmethod
    def _r(cls, v: Any) -> list[str]:
        return _clean_list(v, label="enforcement_terms.reason")


class FailurePolicy(CanonicalModel):
    """§4.5 ``failure_policy{gateway_down, overload, basis, tenant_opt_in}``. Defaults fail-CLOSED."""

    gateway_down: FailureBasis = Field(default=FailureBasis.FAIL_CLOSED)
    overload: FailureBasis = Field(default=FailureBasis.FAIL_CLOSED)
    basis: str = Field(default="", description="The documented basis for the failure behaviour.")
    tenant_opt_in: bool = Field(default=False, description="Whether the tenant opted into fail-open failover.")

    @field_validator("basis")
    @classmethod
    def _b(cls, v: str) -> str:
        return clean_token(v, label="failure_policy.basis", max_len=120, allow_empty=True)


class CustomerPrerequisites(CanonicalModel):
    """§4.5 ``customer_prerequisites`` — each defaults ``False`` (a prerequisite is UNMET until proven,
    fail-closed)."""

    cname: bool = Field(default=False)
    cert: bool = Field(default=False)
    origin_bound: bool = Field(default=False)
    crypto_lock: bool = Field(default=False)
    existing_edge_preserved_or_acknowledged: bool = Field(default=False)
    client_ip_header: bool = Field(default=False)


class TrustAssumptions(CanonicalModel):
    """§4.5 ``trust_assumptions`` — architectural limitations the tenant ACKNOWLEDGES. Each defaults
    ``True`` because the limitation HOLDS by default: the honest default is to surface it, never to
    hide it."""

    aws_edge_terminates_viewer_tls: bool = Field(default=True)
    sigil_unit_sees_plaintext: bool = Field(default=True)
    gateway_reported_not_independent: bool = Field(default=True)
    ip_allowlist_lock_does_not_isolate_tenants: bool = Field(default=True)


class Dimensions(CanonicalModel):
    """§4.5 "six dimensions" — one :class:`Headline` level per axis, each defaulting to ``unsupported``
    (fail-closed). The headline is their floor (computed by AS-4b)."""

    asset_placement: Headline = Field(default=Headline.UNSUPPORTED)
    edge: Headline = Field(default=Headline.UNSUPPORTED)
    origin_lock: Headline = Field(default=Headline.UNSUPPORTED)
    telemetry: Headline = Field(default=Headline.UNSUPPORTED)
    detection_enforcement: Headline = Field(default=Headline.UNSUPPORTED)
    authority_release: Headline = Field(default=Headline.UNSUPPORTED)


class Budgets(CanonicalModel):
    """§4.5 ``budgets`` — the declared resource budgets. Default 0 (no budget granted — fail-closed)."""

    issuance_per_min: int = Field(default=0, ge=0, description="New-host certificate issuance budget (L1).")
    append_rate_per_min: int = Field(default=0, ge=0, description="Event-spool append-rate budget (AS-3c).")


# --- the contract --------------------------------------------------------------------------------
class ProtectionContract(CanonicalModel):
    """§4.5 — the full, read-only protection posture of one tenant asset. NEVER authority: a renderer
    reads it; AS-4b fills + grades it (V1–V7); nothing here is signed. ``headline`` defaults to
    ``unsupported`` so a half-built contract reads "no protection", never "enforcing"."""

    schema_id: str = Field(default=PROTECTION_CONTRACT_SCHEMA, alias="schema")
    asset: AssetRef
    edge: EdgeBlock = Field(default_factory=EdgeBlock)
    origin: OriginBlock
    required_sensors: list[RequiredSensor] = Field(default_factory=list)
    available_telemetry: list[str] = Field(default_factory=list)
    not_observed: list[str] = Field(default_factory=list, description="What is NOT observed (direct-to-origin, cache hits, chunked, >2 MiB, multipart, websocket, non-HTTP).")
    active_detections: list[str] = Field(default_factory=list)
    enforcement_capabilities: list[AdapterCapability] = Field(default_factory=list)
    authorized_actions: AuthorizedActions = Field(default_factory=AuthorizedActions)
    enforcement_terms: EnforcementTerms = Field(default_factory=EnforcementTerms)
    failure_policy: FailurePolicy = Field(default_factory=FailurePolicy)
    verification_checks: list[str] = Field(default_factory=list)
    critical_workflows: list[str] = Field(default_factory=list)
    customer_prerequisites: CustomerPrerequisites = Field(default_factory=CustomerPrerequisites)
    coverage_limitations: list[str] = Field(default_factory=list)
    versions: dict[str, str] = Field(default_factory=dict)
    budgets: Budgets = Field(default_factory=Budgets)
    trust_assumptions: TrustAssumptions = Field(default_factory=TrustAssumptions)
    licensing_mode: LicensingMode = Field(default=LicensingMode.UNKNOWN)
    dimensions: Dimensions = Field(default_factory=Dimensions)
    headline: Headline = Field(default=Headline.UNSUPPORTED)
    response_manifest: ResponseManifest = Field(default_factory=ResponseManifest)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @field_validator("schema_id")
    @classmethod
    def _check_schema(cls, v: str) -> str:
        if v != PROTECTION_CONTRACT_SCHEMA:
            raise ValueError(f"protection contract schema must be {PROTECTION_CONTRACT_SCHEMA!r}, got {v!r}")
        return v

    @field_validator("available_telemetry", "not_observed", "active_detections",
                     "verification_checks", "critical_workflows", "coverage_limitations")
    @classmethod
    def _lists(cls, v: Any, info: Any) -> list[str]:
        return _clean_list(v, label=f"protection_contract.{info.field_name}")

    @field_validator("versions")
    @classmethod
    def _versions(cls, v: Any) -> dict[str, str]:
        if not isinstance(v, dict):
            raise ValueError("protection_contract.versions must be a mapping")
        out: dict[str, str] = {}
        for key, val in v.items():
            k = clean_token(key, label="versions key", max_len=48)
            out[k] = clean_token(val, label=f"versions[{k}]", max_len=48)
        return out


# --- the append-only provider registry -----------------------------------------------------------
class ProviderDescriptor(CanonicalModel):
    """One enforcement/detection provider in the registry. Declares its ``capabilities`` (each an
    :class:`AdapterCapability` naming the ONE outcome class it reaches + how its effect is verified).
    ``provider_id`` is a safe path component; ``capabilities`` carries at least one entry."""

    provider_id: str = Field(description="The stable provider id (a safe path component).")
    title: str = Field(default="", description="A human label for the provider.")
    capabilities: list[AdapterCapability] = Field(min_length=1)

    @field_validator("provider_id")
    @classmethod
    def _pid(cls, v: str) -> str:
        return check_component(v, label="provider.provider_id")

    @field_validator("title")
    @classmethod
    def _title(cls, v: str) -> str:
        return clean_token(v, label="provider.title", max_len=80, allow_empty=True)

    @property
    def outcome_classes(self) -> tuple[OutcomeClass, ...]:
        """The de-duplicated, value-sorted outcome classes this provider reaches (derived)."""
        seen = sorted({c.outcome_class.value for c in self.capabilities})
        return tuple(OutcomeClass(v) for v in seen)


class DuplicateProviderError(ValueError):
    """Raised when a provider id already present in the registry is registered again (append-only)."""


class ProviderRegistry(CanonicalModel):
    """The APPEND-ONLY registry AS-4b evaluates the contract through. It grows ONLY via
    :meth:`register`, which refuses a duplicate id and returns a NEW registry with the provider
    appended — the existing prefix is preserved by construction, so a later slice adds a provider
    without editing this module and without rewriting an earlier one. Insertion order is meaningful
    and part of the canonical bytes (two registries built by the same append sequence are
    byte-identical; a different order is a different registry)."""

    schema_id: str = Field(default=PROVIDER_REGISTRY_SCHEMA, alias="schema")
    providers: list[ProviderDescriptor] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    @field_validator("schema_id")
    @classmethod
    def _check_schema(cls, v: str) -> str:
        if v != PROVIDER_REGISTRY_SCHEMA:
            raise ValueError(f"provider registry schema must be {PROVIDER_REGISTRY_SCHEMA!r}, got {v!r}")
        return v

    @model_validator(mode="after")
    def _no_dupes(self) -> "ProviderRegistry":
        ids = [p.provider_id for p in self.providers]
        if len(ids) != len(set(ids)):
            raise ValueError("provider registry has duplicate provider ids")
        return self

    @property
    def provider_ids(self) -> tuple[str, ...]:
        return tuple(p.provider_id for p in self.providers)

    def get(self, provider_id: str) -> ProviderDescriptor | None:
        for p in self.providers:
            if p.provider_id == provider_id:
                return p
        return None

    def register(self, descriptor: ProviderDescriptor) -> "ProviderRegistry":
        """Return a NEW registry with ``descriptor`` APPENDED. Fail-closed: a duplicate
        ``provider_id`` raises :class:`DuplicateProviderError` (an existing provider can never be
        silently overwritten). The returned registry's provider prefix equals this one's, exactly."""
        if self.get(descriptor.provider_id) is not None:
            raise DuplicateProviderError(
                f"provider {descriptor.provider_id!r} is already registered (the registry is append-only)")
        return ProviderRegistry(providers=[*self.providers, descriptor])


#: The baseline SIGIL-native provider AS-1a ships: the in-request-path gateway. It reaches outcome
#: classes 1 (prevented) and 3 (withheld) with a RETAINED RECEIPT (its own 403 / response-withhold),
#: and class 5 (detected) as a REPORTED observation — exactly the classes contract V7 allows AS-1a,
#: never class 2 or 4. Later slices append GuardDuty / EDR / CloudTrail / edge-virtual-patch providers.
BASELINE_SIGIL_PROVIDER: Final[ProviderDescriptor] = ProviderDescriptor(
    provider_id="sigil_gateway",
    title="SIGIL in-request-path gateway",
    capabilities=[
        AdapterCapability(kind="inline_block", outcome_class=OutcomeClass.PREVENTED_BEFORE_EXECUTION,
                          effect_verification=EffectVerification.RECEIPT),
        AdapterCapability(kind="response_withhold", outcome_class=OutcomeClass.RESPONSE_WITHHELD_AFTER_EXECUTION,
                          effect_verification=EffectVerification.RECEIPT),
        AdapterCapability(kind="observe_alert", outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
                          effect_verification=EffectVerification.REPORTED),
    ],
)


def baseline_provider_registry() -> ProviderRegistry:
    """A registry seeded with exactly the baseline SIGIL provider. Later slices call
    :meth:`ProviderRegistry.register` to append their provider; this function is the shared starting
    point so every plane begins from the same, byte-identical baseline."""
    return ProviderRegistry(providers=[BASELINE_SIGIL_PROVIDER])


__all__ = [
    "PROTECTION_CONTRACT_SCHEMA", "PROVIDER_REGISTRY_SCHEMA",
    "Headline", "PostureDimension", "LicensingMode", "BindingState", "LockState", "CertState",
    "RevocationState", "ReleaseState", "SignerRole", "FailureBasis",
    "ViewerTls", "EdgeBlock", "OriginBinding", "OriginLock", "OriginBlock", "RequiredSensor",
    "LeaseProjection", "RevocationProjection", "AuthorizedActions", "EnforceReleaseProjection",
    "EnforcementTerms", "FailurePolicy", "CustomerPrerequisites", "TrustAssumptions",
    "Dimensions", "Budgets", "ProtectionContract",
    "ProviderDescriptor", "ProviderRegistry", "DuplicateProviderError",
    "BASELINE_SIGIL_PROVIDER", "baseline_provider_registry",
]
