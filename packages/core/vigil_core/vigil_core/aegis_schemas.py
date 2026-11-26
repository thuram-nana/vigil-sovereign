"""AEGIS AS-2b — the base data contracts (schemas) for the hosted defensive plane.

The FATAL-2 SEAM SCHEMAS the SOVEREIGN plane (``apps/sigil``) and the keyless AEGIS data plane
(``engine/crucible/framework/v2/aegis``) both read: a tenant's ``aegis_event`` v2, a per-engine
``health`` v1 record, an ``asset_ref``, an ``adapter_capability``, and the ``response_manifest``
(deadlines + the five outcome classes). Defined ONCE here in the shared integrity core so the two
planes agree BY CONSTRUCTION, never by a drift-catching test — exactly the discipline AS-2a used for
the authority contracts (``authority_v2.py``). The protection contract + provider registry (§4.5)
live in the sibling :mod:`vigil_core.protection_contract`, which composes these shapes.

This slice ships the CONTRACTS ONLY. It wires nothing into the gateway, the spool, or the fleet
(slices 2c / 3b / 3d / 4b / 6a do that). Every type here is an inert, versioned, canonical-
serialisable value object. There is NO new runtime behaviour on any request / signed path, so there
is no flag to gate: an unchanged deployment imports these names and behaves byte-identically (the
same stance AS-2a took — "ships the CONTRACTS ... does NOT wire anything").

Doctrine enforced by construction:

  * DETERMINISM — no wallclock and no RNG anywhere. Every time-like value is a caller-supplied
    MONOTONIC ``seq`` or an integer duration; every id is caller-supplied. Canonical bytes are
    :func:`vigil_core.canonical.canonical_json` (sorted keys, compact) so the same logical record
    serialises BYTE-IDENTICALLY however the caller ordered its fields, and semantically-unordered
    lists are sorted + de-duplicated in a validator.
  * FAIL-CLOSED — every state enum DEFAULTS to its SAFEST / least-capable member (``UNKNOWN`` health,
    ``NONE`` effect-verification, no reachable outcome class), never to a value that would let a
    consumer over-claim protection. ``extra="forbid"`` makes an unknown key a PARSE REJECTION.
  * FORWARD-COMPATIBLE — new optional fields carry defaults (an older payload that omits them still
    parses), and ``kind`` tokens (adapter / engine / attack class) are validated STRINGS, not closed
    enums, so a later slice adds a provider / sensor / detector by APPENDING, never by editing a
    central enum. The append-only provider registry lives next door.

FATAL-2: imports only ``vigil_core`` siblings + stdlib + pydantic. No ``framework``, no ``sigil`` —
safe to import on either plane.
"""
from __future__ import annotations

import enum
from typing import Any, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .authority_v2 import check_component, check_dns_host
from .canonical import canonical_json, sha256_hex

# --- schema version strings (the `vigil.aegis.<name>.v<N>` convention of monitoring_report.py) ---
EVENT_V2_SCHEMA: Final[str] = "vigil.aegis.event.v2"
HEALTH_V1_SCHEMA: Final[str] = "vigil.aegis.health.v1"
RESPONSE_MANIFEST_SCHEMA: Final[str] = "vigil.aegis.response-manifest.v1"

_MAX_TOKEN = 128
_MAX_LIST = 256


def clean_token(value: object, *, label: str, max_len: int = _MAX_TOKEN, allow_empty: bool = False) -> str:
    """Validate ``value`` as a bounded, control-char-free single-line token, fail-closed ``ValueError``.

    NOT a path component (that is :func:`check_component`) and NOT a hostname (that is
    :func:`check_dns_host`) — this is the permissive-but-safe validator for free-text-ish tokens
    (an attack-class label, a provenance tier, a rule ref, an adapter kind, a reason string). It
    refuses control characters (incl. newlines / NUL / DEL) so a token can never smuggle a line
    break into a rendered card or a log line, and bounds the length so a field cannot be used as a
    DoS amplifier. Deterministic: whitespace is NOT stripped (a token's bytes are its identity), so
    the canonical form never drifts on an invisible edit."""
    s = str(value if value is not None else "")
    if not s and not allow_empty:
        raise ValueError(f"{label} is required")
    if len(s) > max_len:
        raise ValueError(f"{label} exceeds {max_len} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        raise ValueError(f"{label} contains a control character")
    return s


def _clean_sorted_tokens(values: Any, *, label: str, max_len: int = _MAX_TOKEN) -> list[str]:
    """Coerce an iterable of tokens to a SORTED, DE-DUPLICATED list (determinism: a set-valued field
    serialises byte-identically however the caller ordered it), each validated by :func:`clean_token`."""
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


class CanonicalModel(BaseModel):
    """Base for every AEGIS schema value object: ``extra='forbid'`` (an unknown key is a parse
    rejection, fail-closed) plus the three canonical-serialisation members every consumer relies on.
    ``canonical_bytes`` is the ONE serialisation; a digest or a round-trip is computed from it, so a
    schema can never have two disagreeing wire forms."""

    model_config = ConfigDict(extra="forbid")

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical JSON of this record (sorted keys, compact, enums as their values).

        Dumped BY ALIAS so a field's wire key is its declared alias (e.g. ``schema``, not the internal
        ``schema_id`` chosen to avoid shadowing ``BaseModel.schema``). The paired :meth:`parse` accepts
        either the alias or the name (``populate_by_name``), so the round-trip is lossless."""
        return canonical_json(self.model_dump(mode="json", by_alias=True))

    def digest(self) -> str:
        """sha256 hex of :meth:`canonical_bytes` — the content id a consumer keys on."""
        return sha256_hex(self.canonical_bytes())

    @classmethod
    def parse(cls, data: Any) -> Self:
        """Validate ``data`` (a mapping or an instance) into this schema, fail-closed on any violation."""
        return cls.model_validate(data)


# --- the five response / outcome classes (§11.6) -------------------------------------------------
class OutcomeClass(str, enum.Enum):
    """The CLOSED five-value outcome vocabulary (§11.6) an enforcement capability / a confirmed event
    is honestly labelled with. The distinctions are load-bearing against the overclaim "Blocked"
    (§2 K-C13): a response WITHHELD after the origin already ran is NOT a prevention.

      1. ``prevented_before_execution``          — the request never reached the app.
      3. ``response_withheld_after_execution``    — the app processed it; only the RESPONSE was withheld.
      2. ``interrupted_after_partial_execution``  — partial execution, then interrupted.
      4. ``contained_after_compromise``           — compromise occurred; blast radius was contained.
      5. ``detected_without_enforcement``         — observed / alerted only; nothing was stopped.
    """

    PREVENTED_BEFORE_EXECUTION = "prevented_before_execution"
    INTERRUPTED_AFTER_PARTIAL_EXECUTION = "interrupted_after_partial_execution"
    RESPONSE_WITHHELD_AFTER_EXECUTION = "response_withheld_after_execution"
    CONTAINED_AFTER_COMPROMISE = "contained_after_compromise"
    DETECTED_WITHOUT_ENFORCEMENT = "detected_without_enforcement"


#: The five classes as an ordered tuple (declaration order == §11.6 numbering). A manifest's
#: ``reachable`` set is a SUBSET of this; AS-1a reaches 1, 3 and 5 only (contract V7).
ALL_OUTCOME_CLASSES: Final[tuple[OutcomeClass, ...]] = (
    OutcomeClass.PREVENTED_BEFORE_EXECUTION,
    OutcomeClass.INTERRUPTED_AFTER_PARTIAL_EXECUTION,
    OutcomeClass.RESPONSE_WITHHELD_AFTER_EXECUTION,
    OutcomeClass.CONTAINED_AFTER_COMPROMISE,
    OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
)

#: The outcome classes AS-1a actually reaches (contract V7: "1a reaches outcome classes 1, 3 and 5
#: only"). The baseline SIGIL provider declares exactly these — never 2 or 4, which need a slow-path
#: or a containment provider that 1a does not ship.
BASELINE_REACHABLE_OUTCOMES: Final[tuple[OutcomeClass, ...]] = (
    OutcomeClass.PREVENTED_BEFORE_EXECUTION,
    OutcomeClass.RESPONSE_WITHHELD_AFTER_EXECUTION,
    OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
)


def _normalize_outcomes(values: Any, *, label: str) -> list[OutcomeClass]:
    """Coerce an iterable of outcome classes to a SORTED-BY-VALUE, DE-DUPLICATED list (determinism)."""
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise ValueError(f"{label} must be a list of outcome classes")
    seen: set[str] = set()
    out: list[OutcomeClass] = []
    for item in values:
        oc = item if isinstance(item, OutcomeClass) else OutcomeClass(str(item))
        if oc.value not in seen:
            seen.add(oc.value)
            out.append(oc)
    out.sort(key=lambda c: c.value)
    return out


class EffectVerification(str, enum.Enum):
    """How an enforcement/detection effect is VERIFIED — the honesty axis that separates "the provider
    says it blocked" from "we independently confirmed it blocked" (§4.5 ``effect_verification``).
    DEFAULT ``none`` is the fail-closed floor: an effect is UNVERIFIED unless a stronger basis is
    declared."""

    NONE = "none"                 # no verification — the effect is asserted, not shown (fail-closed floor)
    REPORTED = "reported"         # the provider REPORTS the effect; not independent (K17: latency/trust)
    RECEIPT = "receipt"           # an applied-change receipt was retained (the gateway's own 403/withhold)
    PROBE_VERIFIED = "probe_verified"  # a keyless Z4 probe re-confirmed the effect out of band (§14)


class EngineHealthState(str, enum.Enum):
    """The health state of one AEGIS engine / sensor / worker (health v1, reused for sensor state in
    the protection contract). DEFAULT ``unknown`` is the fail-closed floor — "dead looks the same as
    quiet" (bug B15) is defeated by never letting absence read as ``healthy``. ``crash_loop``,
    ``expiring`` and ``revocation_pending`` are the AS-3d states that force a ``degraded`` headline."""

    UNKNOWN = "unknown"                       # no fresh signal — fail-closed floor, NEVER "healthy"
    HEALTHY = "healthy"
    STALE = "stale"                           # last heartbeat older than the staleness deadline
    EXPIRING = "expiring"                     # lease / cert within its renewal window
    REVOCATION_PENDING = "revocation_pending"  # a revocation is acknowledged but not yet effective
    CRASH_LOOP = "crash_loop"                 # repeated restarts — PROTECTION_INTERRUPTED
    DOWN = "down"


class PlacementState(str, enum.Enum):
    """Where an asset's protecting instance is in its placement lifecycle (§4.5 ``placement_state``;
    §5.7 placement). DEFAULT ``declared`` — a tenant has asked, but nothing is placed yet."""

    DECLARED = "declared"      # requested by the tenant; not yet placed (fail-closed floor)
    PENDING = "pending"        # placement in progress
    PLACED = "placed"          # an instance is serving this asset
    RETIRED = "retired"        # placement removed (offboarding / Off)


class Criticality(CanonicalModel):
    """A tenant-DECLARED criticality. The load-bearing honesty property: ``authority`` is pinned to
    ``"none"`` by a validator — a tenant's criticality is a REQUEST, never a fact the system acts on
    (§4.5 ``criticality(tenant_declared, authority:none)``; doctrine: no ``protected`` state, no
    tenant self-attestation carries authority)."""

    tenant_declared: str = Field(default="unspecified", description="The tenant's own criticality label (advisory only).")
    authority: Literal["none"] = Field(default="none", description="ALWAYS 'none' — tenant criticality carries no authority.")

    @field_validator("tenant_declared")
    @classmethod
    def _check_declared(cls, v: str) -> str:
        return clean_token(v, label="criticality.tenant_declared", max_len=64)


class AssetRef(CanonicalModel):
    """``asset_ref`` (§4.5 ``asset{...}``) — the canonical, path-safe reference to one protected asset
    and where its protecting instance sits. ``criticality`` is advisory (authority:none). Pure value
    object; no schema-version field (it is a nested shape, versioned by its container)."""

    ref: str = Field(description="The stable asset reference id (a safe path component).")
    connection_path: str = Field(default="", description="How traffic reaches the asset (advisory label).")
    instance_id: str = Field(description="The protecting instance id (a safe path component).")
    cell: str = Field(default="", description="The placement cell (a safe path component), empty if unplaced.")
    placement_state: PlacementState = Field(default=PlacementState.DECLARED)
    isolation_tier: str = Field(default="unknown", description="The D7 isolation tier (t1/t2/t3/unknown).")
    criticality: Criticality = Field(default_factory=Criticality)

    @field_validator("ref", "instance_id")
    @classmethod
    def _check_component_fields(cls, v: str, info: Any) -> str:
        return check_component(v, label=f"asset_ref.{info.field_name}")

    @field_validator("cell")
    @classmethod
    def _check_optional_component(cls, v: str) -> str:
        if not v:
            return v
        return check_component(v, label="asset_ref.cell")

    @field_validator("connection_path")
    @classmethod
    def _check_connection_path(cls, v: str) -> str:
        return clean_token(v, label="asset_ref.connection_path", allow_empty=True)

    @field_validator("isolation_tier")
    @classmethod
    def _check_tier(cls, v: str) -> str:
        return clean_token(v, label="asset_ref.isolation_tier", max_len=16)


class AdapterCapability(CanonicalModel):
    """``adapter_capability`` (§4.5 ``enforcement_capabilities{kind, outcome_class, effect_verification}``)
    — what one enforcement/detection adapter can do and HOW honestly its effect is known. ``kind`` is
    a validated STRING, not a closed enum, so a later provider slice (AS-10a/b, AS-17b, AS-18b, …)
    declares a new adapter kind by APPENDING to the provider registry — never by editing a central
    enum. ``effect_verification`` defaults to ``none`` (fail-closed: an adapter proves nothing until
    it declares a basis)."""

    kind: str = Field(description="The adapter kind (e.g. 'inline_block', 'edge_virtual_patch', 'guardduty').")
    outcome_class: OutcomeClass = Field(description="Which of the five outcome classes this capability reaches.")
    effect_verification: EffectVerification = Field(default=EffectVerification.NONE)

    @field_validator("kind")
    @classmethod
    def _check_kind(cls, v: str) -> str:
        return clean_token(v, label="adapter_capability.kind", max_len=64)


class EngineHealth(CanonicalModel):
    """``health`` v1 — the per-engine/sensor health record the fleet (AS-6a) and the health endpoint
    (AS-3d) read. ``state`` defaults to ``unknown`` (fail-closed: absence never reads as healthy).
    ``seq`` is a caller-supplied MONOTONIC counter (never wallclock); ``last_heartbeat_seq`` lets a
    consumer compute staleness against the manifest's ``staleness_heartbeats`` deadline WITHOUT a
    clock on this path. ``reasons`` explains any non-healthy state (sorted, for a stable digest)."""

    schema_id: str = Field(default=HEALTH_V1_SCHEMA, alias="schema", description="The health v1 schema tag.")
    engine: str = Field(description="The engine / worker kind (unit, broker, prover, receiver, judge, …).")
    instance_id: str = Field(description="The engine instance id (a safe path component).")
    state: EngineHealthState = Field(default=EngineHealthState.UNKNOWN)
    seq: int = Field(ge=0, description="Caller-supplied MONOTONIC sequence — never wallclock.")
    last_heartbeat_seq: int = Field(default=0, ge=0, description="The seq of the last accepted heartbeat (for staleness).")
    reasons: list[str] = Field(default_factory=list, description="Why the state is not healthy (sorted).")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @field_validator("schema_id")
    @classmethod
    def _check_schema(cls, v: str) -> str:
        if v != HEALTH_V1_SCHEMA:
            raise ValueError(f"health schema must be {HEALTH_V1_SCHEMA!r}, got {v!r}")
        return v

    @field_validator("engine")
    @classmethod
    def _check_engine(cls, v: str) -> str:
        return clean_token(v, label="health.engine", max_len=48)

    @field_validator("instance_id")
    @classmethod
    def _check_instance(cls, v: str) -> str:
        return check_component(v, label="health.instance_id")

    @field_validator("reasons")
    @classmethod
    def _check_reasons(cls, v: Any) -> list[str]:
        return _clean_sorted_tokens(v, label="health.reason")


class ResponseDeadlines(CanonicalModel):
    """The response-time / convergence DEADLINES (§11.4/11.5), as INTEGER durations — no clock, no
    wallclock comparison in the schema. Defaults are the PROPOSED SLOs (plan §9.6: visibility p95
    ≤120 s, staleness ≤3 heartbeats, revocation ≤5 min bounded by the lease, renewal ≥14 days before
    expiry, convergence ≤2 sweeps); a deployment overrides them. ``fast_path_inspect_bytes`` is the
    2 MiB inspection cap past which a body is forwarded uninspected (the fast-path budget)."""

    visibility_p95_seconds: int = Field(default=120, ge=0)
    staleness_heartbeats: int = Field(default=3, ge=1)
    revocation_seconds: int = Field(default=300, ge=0)
    renewal_lead_days: int = Field(default=14, ge=0)
    convergence_sweeps: int = Field(default=2, ge=1)
    fast_path_inspect_bytes: int = Field(default=2 * 1024 * 1024, ge=0)


class ResponseManifest(CanonicalModel):
    """``response_manifest`` — the deployment's declared RESPONSE contract: its ``deadlines`` (§11.4/
    11.5) and the subset of the five ``OutcomeClass`` values it can REACH. ``reachable`` DEFAULTS to
    empty (fail-closed: claim no outcome until a provider declares it); the baseline is classes 1, 3
    and 5 (contract V7) via :func:`baseline_response_manifest`. Sorted for a stable digest."""

    schema_id: str = Field(default=RESPONSE_MANIFEST_SCHEMA, alias="schema")
    deadlines: ResponseDeadlines = Field(default_factory=ResponseDeadlines)
    reachable: list[OutcomeClass] = Field(default_factory=list, description="The outcome classes reachable here (subset of the five).")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @field_validator("schema_id")
    @classmethod
    def _check_schema(cls, v: str) -> str:
        if v != RESPONSE_MANIFEST_SCHEMA:
            raise ValueError(f"response manifest schema must be {RESPONSE_MANIFEST_SCHEMA!r}, got {v!r}")
        return v

    @field_validator("reachable")
    @classmethod
    def _check_reachable(cls, v: Any) -> list[OutcomeClass]:
        return _normalize_outcomes(v, label="response_manifest.reachable")


def baseline_response_manifest() -> ResponseManifest:
    """The baseline manifest AS-1a ships: the proposed deadlines + outcome classes 1, 3 and 5 only
    (contract V7). Later slices that add a slow-path (class 2) or containment (class 4) provider widen
    ``reachable`` by constructing a manifest with the extra classes — never by relabelling."""
    return ResponseManifest(reachable=list(BASELINE_REACHABLE_OUTCOMES))


class AegisEventV2(CanonicalModel):
    """``aegis_event`` v2 — the metadata-only monitoring event the data plane emits and the sovereign
    drain records (the v2 successor to ``monitoring_report.py``'s ``vigil.aegis.monitoring.v1``).

    v2 adds, over v1: ``instance_id`` + ``epoch`` (which signed grant/placement produced it),
    ``outcome_class`` (the honest §11.6 label on an enforced event) and ``rule_refs`` (AS-3b: the
    detection rules that fired). ``event_id`` is CALLER-SUPPLIED (determinism — v1's random
    ``report_id`` is replaced by a value the emitter provides, so the same logical event has a stable
    id). PRIVACY BY CONSTRUCTION, exactly like v1: verdict METADATA only — never the path, query,
    headers, body, client address or actor identity."""

    schema_id: str = Field(default=EVENT_V2_SCHEMA, alias="schema")
    org_id: str = Field(description="The tenant org id (a safe path component).")
    host: str = Field(description="The protected origin host (a bare DNS hostname).")
    instance_id: str = Field(description="The emitting instance id (a safe path component).")
    epoch: int = Field(ge=0, description="The authority epoch in force when the event was emitted.")
    seq: int = Field(ge=0, description="Caller-supplied MONOTONIC sequence — never wallclock.")
    decision: Literal["confirmed", "lead", "clear"] = Field(description="Three-valued; 'clear' is NOT 'safe'.")
    attack_class: str = Field(default="", description="The attack-class label (metadata).")
    action: Literal["allow", "observe", "challenge", "throttle", "block"] = Field(default="observe")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    provenance_tier: str = Field(default="", description="The provenance tier (grounded/intel/…), metadata only.")
    certificate_sha256: str = Field(default="", description="sha256 of the certificate for a confirmed event, else ''.")
    outcome_class: OutcomeClass | None = Field(default=None, description="The §11.6 outcome class, when an action was taken.")
    rule_refs: list[str] = Field(default_factory=list, description="Detection rule refs that fired (AS-3b; sorted).")
    event_id: str = Field(description="Caller-supplied stable event id (a safe path component).")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @field_validator("schema_id")
    @classmethod
    def _check_schema(cls, v: str) -> str:
        if v != EVENT_V2_SCHEMA:
            raise ValueError(f"event schema must be {EVENT_V2_SCHEMA!r}, got {v!r}")
        return v

    @field_validator("org_id", "instance_id", "event_id")
    @classmethod
    def _check_components(cls, v: str, info: Any) -> str:
        return check_component(v, label=f"event.{info.field_name}")

    @field_validator("host")
    @classmethod
    def _check_host(cls, v: str) -> str:
        return check_dns_host(v, label="event.host")

    @field_validator("attack_class", "provenance_tier")
    @classmethod
    def _check_tokens(cls, v: str, info: Any) -> str:
        return clean_token(v, label=f"event.{info.field_name}", allow_empty=True)

    @field_validator("certificate_sha256")
    @classmethod
    def _check_cert(cls, v: str) -> str:
        if not v:
            return v
        s = str(v).strip().lower()
        if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
            raise ValueError("event.certificate_sha256 must be '' or a 64-char lowercase hex digest")
        return s

    @field_validator("rule_refs")
    @classmethod
    def _check_rule_refs(cls, v: Any) -> list[str]:
        return _clean_sorted_tokens(v, label="event.rule_ref")


__all__ = [
    "EVENT_V2_SCHEMA", "HEALTH_V1_SCHEMA", "RESPONSE_MANIFEST_SCHEMA",
    "ALL_OUTCOME_CLASSES", "BASELINE_REACHABLE_OUTCOMES",
    "clean_token",
    "CanonicalModel",
    "OutcomeClass", "EffectVerification", "EngineHealthState", "PlacementState",
    "Criticality", "AssetRef", "AdapterCapability", "EngineHealth",
    "ResponseDeadlines", "ResponseManifest", "baseline_response_manifest",
    "AegisEventV2",
]
