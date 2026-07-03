"""
entitlement.policy — the load-bearing capability gate.

`require_capability(cap)` is the single entry point gated subsystems
call. It evaluates the provisioned entitlement once (cached), emits an
audit decision on every call, and raises a typed `EntitlementViolation`
subclass on denial.

Activation model (mirrors the sovereignty layer's PERMISSIVE default):

  - No trust root provisioned and CRUCIBLE_ENTITLEMENT_ENFORCED unset
    -> enforcement INACTIVE. Baseline runs; gated capabilities are
    permitted but every grant is logged at WARNING and `explain()`
    reports the ungoverned state. This keeps development checkouts
    working without provisioning.
  - Trust root present, OR CRUCIBLE_ENTITLEMENT_ENFORCED truthy
    -> enforcement ACTIVE. Gated capabilities require a valid,
    current, host-bound, unrevoked entitlement that grants them.
    Everything fails closed.

Evaluation order for an active deployment (first failure wins):
  threshold signatures -> validity window -> host binding -> revocation
  -> capability-in-grant.

Baseline capabilities (registry.BASELINE_CAPABILITIES) are always
available — even unenforced, even when an entitlement is present but
invalid. The safe core never depends on an entitlement.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

from ..common import logging as clog
from ..common.errors import (
    EntitlementBindingMismatch,
    EntitlementError,
    EntitlementExpired,
    EntitlementInvalid,
    EntitlementMissing,
    EntitlementRevoked,
    EntitlementViolation,
    CapabilityNotGranted,
)
from . import binding, registry, store
from .canonical import entitlement_signing_bytes, revocation_signing_bytes
from .crypto import verify_threshold
from .models import (
    Capability,
    CapabilityTier,
    EntitlementDecision,
    SignedEntitlement,
    TrustRoot,
)

_log = clog.get_logger("entitlement")

_ENFORCE_ENV = "CRUCIBLE_ENTITLEMENT_ENFORCED"
_OPERATOR_ENV = "CRUCIBLE_OPERATOR_IDENTITY"
_TRUTHY = {"1", "true", "yes", "on"}


def _operator_identities() -> list[str]:
    """Operator identities the running process presents, from
    CRUCIBLE_OPERATOR_IDENTITY (comma-separated). Injected by the
    deployment (e.g. a SPIFFE SVID for the operator/workload). Distinct
    from the host attestation identity used for hardware binding."""
    raw = os.environ.get(_OPERATOR_ENV, "")
    return [t.strip() for t in raw.split(",") if t.strip()]


def _operator_constraint_satisfied(constraint: str) -> tuple[bool, str]:
    """Return (ok, reason). A subject.operator_constraint binds the grant
    to a specific operator identity (or identity prefix, per the model
    docstring — SPIFFE ids are hierarchical). Satisfied iff a presented
    operator identity equals the constraint or begins with it. No
    presented identity at all fails CLOSED."""
    ids = _operator_identities()
    if not ids:
        return False, (
            f"entitlement binds an operator_constraint but no operator identity "
            f"is present (set {_OPERATOR_ENV} on the attested host)"
        )
    for ident in ids:
        if ident == constraint or ident.startswith(constraint):
            return True, "operator constraint satisfied"
    return False, "presented operator identity does not satisfy operator_constraint"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Coerce a possibly-naive datetime to aware UTC. Naive values are
    interpreted as UTC (the canonical form always emits an offset, so
    naive only arises from hand-edited files)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class _Eval:
    decision: EntitlementDecision
    error: type[EntitlementViolation] | None


@dataclass(frozen=True)
class _State:
    """The result of verifying the provisioned material once."""

    enforced: bool
    granted_tier: CapabilityTier | None
    effective_caps: frozenset[Capability]
    entitlement_id: str | None
    institution: str | None
    denial_error: type[EntitlementViolation] | None
    denial_reason: str
    summary: str


class EntitlementPolicy:
    """An evaluated entitlement state plus the gate methods. Build via
    `from_provisioned()` (reads disk) or inject a `_State` in tests via
    the classmethods on this module's helpers."""

    def __init__(self, state: _State) -> None:
        self._state = state

    # ---- construction ------------------------------------------------

    @classmethod
    def from_provisioned(cls) -> "EntitlementPolicy":
        return cls(_build_state())

    # ---- queries -----------------------------------------------------

    @property
    def enforced(self) -> bool:
        return self._state.enforced

    @property
    def granted_tier(self) -> CapabilityTier | None:
        return self._state.granted_tier

    def explain(self) -> str:
        return self._state.summary

    # ---- the gate ----------------------------------------------------

    def _evaluate(self, capability: Capability) -> _Eval:
        s = self._state
        now = _utcnow()

        def decide(allowed: bool, reason: str) -> EntitlementDecision:
            return EntitlementDecision(
                allowed=allowed,
                capability=capability,
                reason=reason,
                enforced=s.enforced,
                entitlement_id=s.entitlement_id,
                institution=s.institution,
                evaluated_at=now,
            )

        # Baseline is unconditional.
        if registry.is_baseline(capability):
            return _Eval(decide(True, "baseline capability"), None)

        # Ungoverned deployment: permit, but flag.
        if not s.enforced:
            return _Eval(
                decide(True, "enforcement inactive (no trust root provisioned)"),
                None,
            )

        # Enforced but no valid entitlement: deny with the stored reason.
        if s.granted_tier is None:
            assert s.denial_error is not None
            return _Eval(decide(False, s.denial_reason), s.denial_error)

        # Valid entitlement: is this capability within the grant?
        if capability in s.effective_caps:
            return _Eval(decide(True, f"granted by tier {s.granted_tier.value}"), None)
        return _Eval(
            decide(
                False,
                f"capability {capability.value!r} not in grant "
                f"(tier {s.granted_tier.value})",
            ),
            CapabilityNotGranted,
        )

    def assert_capability(self, capability: Capability) -> EntitlementDecision:
        """Raise an EntitlementViolation if `capability` is not
        authorised; return the (allowed) decision otherwise. Always
        emits an audit record."""
        ev = self._evaluate(capability)
        d = ev.decision
        _log.info(
            "entitlement.decision",
            capability=d.capability.value,
            allowed=d.allowed,
            enforced=d.enforced,
            reason=d.reason,
            entitlement_id=d.entitlement_id,
            institution=d.institution,
        )
        if not d.allowed:
            assert ev.error is not None
            raise ev.error(
                f"capability {capability.value!r} denied: {d.reason}"
            )
        if d.enforced is False and not registry.is_baseline(capability):
            _log.warning(
                "entitlement.ungoverned_grant",
                capability=capability.value,
                note="gated capability permitted because no trust root is "
                "provisioned; provision a trust root to enforce",
            )
        return d

    def is_capability_available(self, capability: Capability) -> bool:
        """Non-raising variant for feature-availability branching."""
        return self._evaluate(capability).decision.allowed


# ---------------------------------------------------------------------------
# State construction — the verification pipeline
# ---------------------------------------------------------------------------


def _enforcement_active(trust_root: TrustRoot | None) -> bool:
    if os.environ.get(_ENFORCE_ENV, "").strip().lower() in _TRUTHY:
        return True
    return trust_root is not None


def _ungoverned_state() -> _State:
    return _State(
        enforced=False,
        granted_tier=None,
        effective_caps=frozenset(),
        entitlement_id=None,
        institution=None,
        denial_error=None,
        denial_reason="",
        summary="enforcement INACTIVE — no trust root provisioned; baseline "
        "core runs, gated capabilities permitted with a logged warning",
    )


def _denied_state(
    error: type[EntitlementViolation],
    reason: str,
    *,
    entitlement_id: str | None = None,
    institution: str | None = None,
) -> _State:
    return _State(
        enforced=True,
        granted_tier=None,
        effective_caps=frozenset(),
        entitlement_id=entitlement_id,
        institution=institution,
        denial_error=error,
        denial_reason=reason,
        summary=f"enforcement ACTIVE — gated capabilities denied: {reason}",
    )


@dataclass(frozen=True)
class _RevocationOutcome:
    """The result of evaluating the revocation list against one
    entitlement. `error` is None when the entitlement survives; otherwise
    it is the typed violation and `reason` explains it."""

    error: type[EntitlementViolation] | None
    reason: str


def _evaluate_revocation(
    trust_root: TrustRoot,
    entitlement_id: str,
    revocation_required: bool,
) -> _RevocationOutcome:
    """Post-issuance kill-switch evaluation. Order:

      1. Load the list. Unreadable -> fail closed (tamper).
      2. Absent list: deny iff the entitlement declared it expects one
         (revocation_required); otherwise pass. This closes the
         'rm revocation.json' fail-open bypass.
      3. Present list: must be validly threshold-signed (else tamper).
      4. Anti-rollback: a serial below the persisted high-water mark is a
         replayed stale list -> deny. Accepted serials advance the mark.
      5. Revoked-id membership -> deny.
    """
    try:
        revocation = store.load_revocation()
    except EntitlementError as e:
        return _RevocationOutcome(EntitlementInvalid, f"revocation list unreadable: {e}")

    if revocation is None:
        if revocation_required:
            return _RevocationOutcome(
                EntitlementRevoked,
                "entitlement requires a revocation source but no revocation list "
                "is present (fail closed — a deleted revocation list must not "
                "silently un-gate a revocable entitlement)",
            )
        return _RevocationOutcome(None, "no revocation list present (none required)")

    msg = revocation_signing_bytes(revocation.document)
    thr = verify_threshold(msg, revocation.signatures, trust_root)
    if not thr.satisfied:
        return _RevocationOutcome(
            EntitlementInvalid,
            f"revocation list present but not validly signed ({thr.reason})",
        )

    serial = revocation.document.serial
    try:
        highwater = store.load_revocation_highwater()
    except EntitlementError as e:
        return _RevocationOutcome(
            EntitlementInvalid, f"revocation high-water mark unreadable: {e}"
        )
    if highwater is not None and serial < highwater:
        return _RevocationOutcome(
            EntitlementInvalid,
            f"revocation rollback refused: list serial {serial} is below the "
            f"last accepted serial {highwater} (stale list replay)",
        )
    if highwater is None or serial > highwater:
        store.store_revocation_highwater(serial)

    if entitlement_id in revocation.document.revoked_entitlement_ids:
        return _RevocationOutcome(
            EntitlementRevoked,
            f"entitlement {entitlement_id!r} is on revocation serial {serial}",
        )
    return _RevocationOutcome(None, "not revoked")


def _build_state() -> _State:
    try:
        trust_root = store.load_trust_root()
    except EntitlementError as e:
        # A present-but-broken trust root means a governed deployment
        # whose root is corrupt: fail closed.
        return _denied_state(EntitlementInvalid, f"trust root unreadable: {e}")

    if not _enforcement_active(trust_root):
        return _ungoverned_state()

    if trust_root is None:
        # Enforcement forced by env but nothing to verify against.
        return _denied_state(
            EntitlementInvalid,
            f"{_ENFORCE_ENV} is set but no trust root is provisioned",
        )

    try:
        signed = store.load_entitlement()
    except EntitlementError as e:
        return _denied_state(EntitlementInvalid, f"entitlement unreadable: {e}")

    if signed is None:
        return _denied_state(
            EntitlementMissing,
            "no entitlement provisioned (trust root present, grant absent)",
        )

    return _verify_entitlement(signed, trust_root)


def _verify_entitlement(signed: SignedEntitlement, trust_root: TrustRoot) -> _State:
    doc = signed.document
    eid = doc.entitlement_id
    inst = doc.subject.institution_name

    # 1. threshold signatures over the canonical entitlement bytes
    thr = verify_threshold(entitlement_signing_bytes(doc), signed.signatures, trust_root)
    if not thr.satisfied:
        return _denied_state(
            EntitlementInvalid,
            f"signature threshold not met: {thr.reason}",
            entitlement_id=eid,
            institution=inst,
        )

    # 2. validity window
    now = _utcnow()
    if now < _as_utc(doc.not_before):
        return _denied_state(
            EntitlementExpired,
            f"entitlement not yet valid (not_before {doc.not_before.isoformat()})",
            entitlement_id=eid,
            institution=inst,
        )
    if now > _as_utc(doc.not_after):
        return _denied_state(
            EntitlementExpired,
            f"entitlement expired (not_after {doc.not_after.isoformat()})",
            entitlement_id=eid,
            institution=inst,
        )

    # 3. host binding
    ok, why = binding.binding_satisfied(doc.binding)
    if not ok:
        return _denied_state(
            EntitlementBindingMismatch,
            why,
            entitlement_id=eid,
            institution=inst,
        )

    # 4. operator constraint — bind the grant to a specific operator identity
    if doc.subject.operator_constraint is not None:
        op_ok, op_why = _operator_constraint_satisfied(doc.subject.operator_constraint)
        if not op_ok:
            return _denied_state(
                EntitlementBindingMismatch,
                op_why,
                entitlement_id=eid,
                institution=inst,
            )

    # 5. revocation (fail-closed on missing-when-required; anti-rollback)
    rev = _evaluate_revocation(trust_root, eid, doc.revocation_required)
    if rev.error is not None:
        return _denied_state(rev.error, rev.reason, entitlement_id=eid, institution=inst)

    # 6. valid — compute effective capabilities
    caps = registry.effective_capabilities(doc.capability_tier, doc.granted_capabilities)
    return _State(
        enforced=True,
        granted_tier=doc.capability_tier,
        effective_caps=caps,
        entitlement_id=eid,
        institution=inst,
        denial_error=None,
        denial_reason="",
        summary=(
            f"enforcement ACTIVE — entitlement {eid!r} for {inst!r}, "
            f"tier {doc.capability_tier.value}, "
            f"{len(thr.valid_signers)}/{trust_root.threshold} signatures, "
            f"{len(caps)} capability(ies) granted"
        ),
    )


# ---------------------------------------------------------------------------
# Module-level active policy
# ---------------------------------------------------------------------------

_active_policy: EntitlementPolicy | None = None


def current_policy() -> EntitlementPolicy:
    """Return the active policy, building (and caching) it from
    provisioned material on first use. Verification runs once; call
    `reset_policy()` after changing provisioned files."""
    global _active_policy
    if _active_policy is None:
        _active_policy = EntitlementPolicy.from_provisioned()
    return _active_policy


def set_policy(policy: EntitlementPolicy | None) -> None:
    """Inject a policy (tests / programmatic provisioning). None reverts
    to lazy rebuild from disk on next `current_policy()`."""
    global _active_policy
    _active_policy = policy


def reset_policy() -> None:
    """Drop the cached policy so the next `current_policy()` re-reads
    disk and re-verifies. Production calls this after rotating
    entitlement material; tests call it between cases."""
    global _active_policy
    _active_policy = None


def require_capability(capability: Capability) -> EntitlementDecision:
    """Top-level gate. Raise EntitlementViolation if unauthorised."""
    return current_policy().assert_capability(capability)


def is_capability_available(capability: Capability) -> bool:
    """Top-level non-raising availability check."""
    return current_policy().is_capability_available(capability)
