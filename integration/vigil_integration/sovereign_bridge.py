"""
sovereign_bridge — ONE unified authorization entry that is a FACADE over the EXISTING gates (W13-2).

The programme decision (issue #495): ``authorize()`` is a **facade**, never a second policy engine. It
does NOT re-decide authorization; it calls the ALREADY-EXISTING gate chain — kill-switch, scope, WARDEN
(the ``conjunctive_gate`` authority-of-record) then sovereignty (the LLM-egress gate) then entitlement
(``require_capability``) — **in order**, and returns the *composed* verdict, normalized to ALLOW / DENY /
QUEUE with a reason code, the deciding gate, and any capability the entitlement gate confirmed. Building a
parallel policy decision point (a second PDP) is the exact anti-pattern the red-pen caught in ``vigil patch``
this session, so the invariant this module is built to hold is:

    EVERY non-ALLOW verdict this facade returns traces to an underlying gate — ``denied_by`` is the name of a
    real gate in the chain, and the reason is that gate's own reason. There is no branch in the composition
    that invents an ALLOW or a DENY from the request's own content: the facade only *sequences* gates and
    *reads* what they return. ``compose_authorization`` never inspects the ``request`` to make a verdict.

Fail-closed on every axis (mirrors ``vigil_core.gate.conjunctive_decide``): a gate that RAISES is a DENY
attributed to that gate; a gate that returns a verdict the facade does not recognise is a DENY attributed to
that gate; the FIRST non-ALLOW wins (deny OR queue short-circuits the rest). A construction with an EMPTY
gate chain is refused (a facade with nothing to delegate to would BE a decision point of its own), and — the
negative control W13-2 pins — a **production** deployment profile refuses to be built in ``OBSERVE_ONLY``
mode: production MUST ``ENFORCE``. There is deliberately **no** ``skip_security_checks``-equivalent flag
anywhere in the facade (asserted repo-wide by ``tests/test_sovereign_bridge.py``): no parameter can turn the
gate chain off.

Two-env boundary (FATAL-2). The composition core imports nothing but stdlib, so it loads in BOTH processes
exactly like ``vigil_core.gate`` (the sovereign leg can compose sovereign-appropriate gates without dragging
the offense engine in). The OFFENSE wiring — :func:`build_offense_bridge`, which binds the real CRUCIBLE
authority + kernel sovereignty + framework entitlement — imports ``framework`` LAZILY, inside functions, so
this module stays import-clean for the sovereign side (which never calls it). This mirrors
``conjunctive_gate.build_offense_gate`` and is asserted by ``tests/test_two_env_boundary.py``.

OBSERVE_ONLY → ENFORCE. ``authorize()`` always computes the TRUE composed verdict; the enforcement *mode*
governs only whether the caller must act on a non-ALLOW. In ``OBSERVE_ONLY`` (rollout only, never
production) a non-ALLOW is recorded but :meth:`SovereignDecision.blocks` is False, so a deployment can
measure what the chain WOULD refuse before flipping to ``ENFORCE``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Sequence

from vigil_core.target_classification import (
    RegisteredAssetStore, TargetClass, classify_target,
)

__all__ = [
    "Effect",
    "EnforcementMode",
    "DeploymentProfile",
    "GateOutcome",
    "Gate",
    "GateTrace",
    "AuthorizeRequest",
    "SovereignDecision",
    "SovereignBridge",
    "authorize",
    "compose_authorization",
    "build_offense_bridge",
]


class Effect(str, Enum):
    """The normalized verdict of a gate and of the composed decision. Only these three are recognised;
    anything else a gate returns is treated as an error and fails closed."""

    ALLOW = "allow"
    DENY = "deny"
    QUEUE = "queue"


class EnforcementMode(str, Enum):
    """OBSERVE_ONLY records the composed verdict without blocking (rollout only); ENFORCE blocks a
    non-ALLOW. A production profile rejects OBSERVE_ONLY at construction (W13-2 negative control)."""

    OBSERVE_ONLY = "observe_only"
    ENFORCE = "enforce"


class DeploymentProfile(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"


# Profiles that are production-grade and therefore MUST enforce. A frozenset so the membership test is a
# single, auditable predicate rather than scattered conditionals.
_PRODUCTION_PROFILES: frozenset[DeploymentProfile] = frozenset({DeploymentProfile.PRODUCTION})

# Canonical reason codes. Every non-ALLOW carries one, DERIVED FROM which gate spoke and its verdict — a
# label of the deciding gate, never a re-interpretation of the request (so it adds no policy).
_ALLOW_CODE = "ALLOW"
_GATE_ERROR_CODE = "GATE_ERROR"


@dataclass(frozen=True)
class GateOutcome:
    """What ONE underlying gate returned for a request. ``verdict`` must be an :class:`Effect`. ``code`` is
    the gate's own reason code (the facade labels it if absent); ``capability`` is any capability the gate
    confirmed (the entitlement leg). The facade reads this — it never overrides ``verdict``."""

    verdict: Effect
    reason: str = ""
    code: Optional[str] = None
    capability: Optional[str] = None
    detail: Any = None


@dataclass(frozen=True)
class Gate:
    """A NAMED delegation to an EXISTING gate. ``decide(request) -> GateOutcome`` is the gate's own
    decision; the facade calls it and composes the result. The facade makes no decision of its own — it
    only sequences these and reads what they return, so every verdict traces to a named gate here."""

    name: str
    decide: Callable[[Any], GateOutcome]


@dataclass(frozen=True)
class GateTrace:
    """One row of the audit trail: which gate was consulted, what it said, and the normalized code."""

    gate: str
    verdict: str
    reason: str
    code: str


@dataclass(frozen=True)
class AuthorizeRequest:
    """The request the facade hands to each gate. The facade itself NEVER reads these fields to make a
    verdict — the gates do. ``backend`` feeds the sovereignty (LLM-egress) gate; ``capability`` feeds the
    entitlement gate; ``tool_name``/``target_url``/``destructive`` (+ the destruction pair) feed the
    authority gate. A gate wired into the chain but handed no field it needs fails CLOSED (a missing
    authority is a DENY, never a pass)."""

    tool_name: str
    target_url: str = ""
    destructive: bool = False
    backend: Optional[str] = None
    capability: Any = None
    destruction_action: Any = None
    destruction_signed: Any = None
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class SovereignDecision:
    """The normalized, composed decision. ``effect`` is the TRUE composed verdict regardless of mode.

    Invariant (pinned by the structural test): ``effect is Effect.ALLOW``  <=>  ``denied_by is None``.
    Every non-ALLOW names the gate that produced it, so no verdict is the facade's own policy."""

    effect: Effect
    reason_code: str
    reason: str
    denied_by: Optional[str]
    capability: Optional[str]
    mode: EnforcementMode
    profile: DeploymentProfile
    trace: tuple[GateTrace, ...]

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def enforced(self) -> bool:
        return self.mode is EnforcementMode.ENFORCE

    def blocks(self) -> bool:
        """Does this decision actually block the action? Only when ENFORCE and the composed verdict is not
        ALLOW. In OBSERVE_ONLY the verdict is recorded but the caller does not block (rollout measurement)."""
        return self.mode is EnforcementMode.ENFORCE and self.effect is not Effect.ALLOW


def _coerce_mode(mode: Any) -> EnforcementMode:
    if isinstance(mode, EnforcementMode):
        return mode
    try:
        return EnforcementMode(str(mode))
    except ValueError as exc:  # unknown mode → fail closed (never silently ENFORCE or OBSERVE)
        raise ValueError(f"unknown enforcement mode {mode!r} (fail-closed)") from exc


def _coerce_profile(profile: Any) -> DeploymentProfile:
    if isinstance(profile, DeploymentProfile):
        return profile
    try:
        return DeploymentProfile(str(profile))
    except ValueError as exc:  # unknown profile → fail closed (do NOT default to a permissive profile)
        raise ValueError(f"unknown deployment profile {profile!r} (fail-closed)") from exc


def _validate_config(gates: Sequence[Gate], mode: EnforcementMode, profile: DeploymentProfile) -> None:
    """Fail-closed construction guards. These RAISE (they are config errors) — they are never returned as a
    DENY decision, so they cannot become a non-gate verdict that the structural invariant would count."""
    if not gates:
        raise ValueError(
            "sovereign_bridge is a FACADE over existing gates: it needs at least one gate to delegate to. "
            "An empty chain would make the facade a decision point of its own — refused (fail-closed)."
        )
    names = [g.name for g in gates]
    if len(set(names)) != len(names):
        raise ValueError(f"gate names must be unique so a verdict is unambiguously attributable: {names}")
    if profile in _PRODUCTION_PROFILES and mode is EnforcementMode.OBSERVE_ONLY:
        raise ValueError(
            f"deployment profile {profile.value!r} rejects OBSERVE_ONLY: a production deployment MUST "
            "ENFORCE. OBSERVE_ONLY is a rollout-only measurement mode (fail-closed)."
        )


def compose_authorization(
    request: Any,
    gates: Sequence[Gate],
    *,
    mode: EnforcementMode,
    profile: DeploymentProfile,
) -> SovereignDecision:
    """The PURE composition core. Sequence the gates in order; the FIRST non-ALLOW wins; a raised or
    unrecognised gate result is a DENY attributed to that gate. Never inspects ``request`` itself — only
    calls ``gate.decide(request)`` and reads the returned :class:`GateOutcome`. Stdlib-only, so it loads in
    both trust domains.

    Returns a :class:`SovereignDecision` whose ``effect`` is the true composed verdict; ``mode``/``profile``
    are stamped for the caller's enforcement decision (see :meth:`SovereignDecision.blocks`)."""
    trace: list[GateTrace] = []
    capability: Optional[str] = None

    for gate in gates:
        try:
            outcome = gate.decide(request)
        except Exception as exc:  # noqa: BLE001 — a raised gate is a DENY attributed to it, never a pass
            reason = f"gate {gate.name!r} raised (fail-closed): {type(exc).__name__}: {exc}"
            trace.append(GateTrace(gate.name, Effect.DENY.value, reason, _GATE_ERROR_CODE))
            return SovereignDecision(
                Effect.DENY, _GATE_ERROR_CODE, reason, gate.name, None, mode, profile, tuple(trace),
            )

        verdict = getattr(outcome, "verdict", None)
        if not isinstance(verdict, Effect):
            # A gate that returns something the facade does not recognise cannot be trusted to have
            # allowed — fail closed, attributed to that gate (never a silent pass).
            reason = f"gate {gate.name!r} returned an unrecognised verdict {verdict!r} (fail-closed)"
            trace.append(GateTrace(gate.name, Effect.DENY.value, reason, _GATE_ERROR_CODE))
            return SovereignDecision(
                Effect.DENY, _GATE_ERROR_CODE, reason, gate.name, None, mode, profile, tuple(trace),
            )

        code = outcome.code or f"{gate.name.upper()}_{verdict.name}"
        trace.append(GateTrace(gate.name, verdict.value, outcome.reason, code))

        if verdict is Effect.ALLOW:
            if outcome.capability is not None:
                capability = outcome.capability
            continue

        # First non-ALLOW (DENY or QUEUE) wins — short-circuit the remaining gates.
        return SovereignDecision(
            verdict, code, outcome.reason or code, gate.name, outcome.capability, mode, profile, tuple(trace),
        )

    # Every gate allowed.
    return SovereignDecision(
        Effect.ALLOW, _ALLOW_CODE, "all gates allow", None, capability, mode, profile, tuple(trace),
    )


def authorize(
    request: Any,
    gates: Sequence[Gate],
    *,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    profile: DeploymentProfile | str = DeploymentProfile.PRODUCTION,
) -> SovereignDecision:
    """The unified authorization entry point. Validates the config fail-closed (empty chain refused;
    production rejects OBSERVE_ONLY), then delegates to :func:`compose_authorization`. This is a thin
    facade: it adds NO policy — every verdict comes from a gate."""
    gates = tuple(gates)
    mode = _coerce_mode(mode)
    profile = _coerce_profile(profile)
    _validate_config(gates, mode, profile)
    return compose_authorization(request, gates, mode=mode, profile=profile)


class SovereignBridge:
    """A configured facade: an ordered gate chain + an enforcement mode + a deployment profile. Construction
    is fail-closed (see :func:`_validate_config`). :meth:`authorize` delegates to the free :func:`authorize`,
    so the class holds no policy either."""

    def __init__(
        self,
        gates: Sequence[Gate],
        *,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        profile: DeploymentProfile | str = DeploymentProfile.PRODUCTION,
    ) -> None:
        self._gates = tuple(gates)
        self._mode = _coerce_mode(mode)
        self._profile = _coerce_profile(profile)
        _validate_config(self._gates, self._mode, self._profile)

    @property
    def gate_names(self) -> tuple[str, ...]:
        return tuple(g.name for g in self._gates)

    @property
    def mode(self) -> EnforcementMode:
        return self._mode

    @property
    def profile(self) -> DeploymentProfile:
        return self._profile

    def authorize(self, request: Any) -> SovereignDecision:
        return authorize(request, self._gates, mode=self._mode, profile=self._profile)


# ============================================================================================================
# OFFENSE wiring — bind the facade over the REAL existing gates. framework imports are LAZY (FATAL-2): this
# section is reachable ONLY in env-offense, and importing this module never co-loads framework/strix.
# ============================================================================================================


def _authority_outcome(base_gate: Callable[..., Any], request: Any) -> GateOutcome:
    """Delegate to the EXISTING conjunctive gate-of-record (kill-switch ∧ scope ∧ WARDEN ∧ m-of-n
    destruction). Reads its :class:`vigil_core.gate.GateVerdict` and NORMALIZES — it does not re-decide. The
    granular reason code is DERIVED from the verdict's own fields (``crucible_allowed`` / ``warden``)."""
    verdict = base_gate(
        request.tool_name,
        request.target_url,
        request.destructive,
        destruction_action=request.destruction_action,
        destruction_signed=request.destruction_signed,
    )
    outcome_str = getattr(verdict, "outcome", None)
    reason = getattr(verdict, "reason", "") or ""
    if outcome_str == "allow":
        return GateOutcome(Effect.ALLOW, reason, code="IN_ENVELOPE")
    if outcome_str == "queue":
        return GateOutcome(Effect.QUEUE, reason, code="WARDEN_QUEUE")
    if outcome_str == "deny":
        # Derive WHICH sub-gate denied by reading the verdict (no re-decision).
        if getattr(verdict, "crucible_allowed", None) is False:
            code = "OUT_OF_ENVELOPE"  # kill-switch / validity window / scope / budget
        else:
            warden = getattr(verdict, "warden", None)
            code = "WARDEN_DENY" if warden is not None else "AUTHORITY_DENY"
        return GateOutcome(Effect.DENY, reason, code=code)
    # An unrecognised outcome from the authority gate → fail closed (never treat as allow).
    return GateOutcome(
        Effect.DENY, f"authority gate returned an unrecognised outcome {outcome_str!r}", code="AUTHORITY_DENY",
    )


def _sovereignty_outcome(request: Any) -> GateOutcome:
    """Delegate to the EXISTING LLM-egress sovereignty gate (``live.think_claude.llm_egress_refusal``, which
    itself wraps ``framework.v2.kernel.sovereignty``). ``None`` refusal ⇒ permitted; any refusal text ⇒
    DENY carrying the policy's own message. That function is TOTAL (never raises), so this leg is too."""
    from .live.think_claude import llm_egress_refusal  # offense-side, framework lazy inside it

    refusal = llm_egress_refusal(request.backend)
    if refusal is None:
        return GateOutcome(Effect.ALLOW, "sovereignty tier permits this backend", code="SOVEREIGNTY_OK")
    return GateOutcome(Effect.DENY, refusal, code="SOVEREIGNTY_REFUSED")


def _entitlement_outcome(request: Any) -> GateOutcome:
    """Delegate to the EXISTING capability gate (``framework.v2.entitlement.require_capability``). The
    bridge wires this leg only for a capability-gated action; a request that reaches it with NO capability
    declared is ambiguous authority → DENY (fail-closed). A raised ``EntitlementViolation`` (missing /
    expired / host-mismatch / revoked / not-granted) is a DENY carrying the violation's message."""
    cap = request.capability
    if cap is None:
        return GateOutcome(
            Effect.DENY,
            "entitlement gate is in the chain but the request declared no capability (fail-closed)",
            code="ENTITLEMENT_MISSING",
        )
    # A Capability enum stringifies as "Capability.X"; prefer its stable ``.value`` for the decision record.
    cap_id = getattr(cap, "value", None) or str(cap)
    from framework.v2.entitlement import require_capability  # offense-side only

    try:
        decision = require_capability(cap)
    except Exception as exc:  # noqa: BLE001 — an EntitlementViolation (or any error) is a DENY, never a pass
        return GateOutcome(
            Effect.DENY, f"{type(exc).__name__}: {exc}", code="ENTITLEMENT_DENIED", capability=cap_id,
        )
    return GateOutcome(
        Effect.ALLOW, getattr(decision, "reason", "") or "capability granted", code="ENTITLEMENT_OK",
        capability=cap_id,
    )


def _classification_outcome(
    request: Any, *, store: Optional[RegisteredAssetStore], in_scope: Optional[Callable[[str], bool]],
) -> GateOutcome:
    """Delegate to the EXISTING target classifier (``vigil_core.target_classification``): resolve the
    request's target to a :class:`TargetClass` (registered-asset store first, then the signed charter scope
    ``in_scope`` predicate) and NORMALIZE to an outcome. This leg adds NO scope policy — ``in_scope`` is the
    charter scope (source of truth) the caller derived from the signed authority; the classifier only reads
    it + the asset store. An authorized class ⇒ ALLOW; an UNKNOWN / out-of-scope / critical class ⇒ DENY
    (UNKNOWN is never authorized). The classifier is TOTAL (a raising scope predicate → UNKNOWN), so this
    leg never raises a verdict of its own."""
    result = classify_target(request.target_url, store=store, in_scope=in_scope)
    tc = result.target_class
    if result.authorized:
        return GateOutcome(Effect.ALLOW, result.reason, code=f"CLASS_{tc.name}")
    code = "TARGET_UNKNOWN" if tc is TargetClass.UNKNOWN else f"TARGET_{tc.name}"
    return GateOutcome(Effect.DENY, result.reason, code=code)


def _scope_check_from_authority(slug: str, trust_root: Any) -> Callable[[str], bool]:
    """Build the classification ``in_scope`` predicate from the SIGNED charter scope — the EXISTING source
    of truth, not a re-implementation. It loads the verified authority (the same loader the authority leg
    uses) and asks the EXISTING ``host_matches_scope``; framework is imported LAZILY (FATAL-2)."""

    def in_scope(host: str) -> bool:
        from framework.v2.authority.gate import load_authority_for_gate
        from framework.v2.common.ethics import host_matches_scope

        authority = load_authority_for_gate(slug, trust_root=trust_root)
        return host_matches_scope(host, authority.scope)

    return in_scope


def build_offense_bridge(
    *,
    slug: str,
    trust_root: Any,
    classify: Callable[[str], str],
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    profile: DeploymentProfile | str = DeploymentProfile.PRODUCTION,
    include_classification: bool = True,
    include_sovereignty: bool = True,
    include_entitlement: bool = True,
    asset_store: Optional[RegisteredAssetStore] = None,
    scope_check: Optional[Callable[[str], bool]] = None,
    base_gate: Optional[Callable[..., Any]] = None,
    **offense_gate_kwargs: Any,
) -> SovereignBridge:
    """Wire the facade over the REAL existing offense gates, in order:

        classification→ the EXISTING target classifier (``vigil_core.target_classification``): resolve the
                     target to a class (registered-asset store, then the SIGNED charter scope) and refuse
                     an UNKNOWN / out-of-scope / critical target. On by default (``include_classification``)
                     so UNKNOWN is never authorized; it consults the charter scope, it does not re-decide it.
        authority  → the EXISTING ``conjunctive_gate.build_offense_gate`` (kill-switch ∧ scope ∧ WARDEN ∧
                     m-of-n destruction) — the offense authority-of-record; a ``None`` trust_root is refused
                     by that builder, so the fail-closed refusal is inherited, not re-implemented here.
        sovereignty→ the EXISTING ``live.think_claude.llm_egress_refusal`` (kernel sovereignty tier).
        entitlement→ the EXISTING ``framework.v2.entitlement.require_capability``.

    ``include_classification`` / ``include_sovereignty`` / ``include_entitlement`` let the CALLER choose
    which existing gates a given action's chain applies (a non-egress action needs no sovereignty leg; an
    action needing no capability needs no entitlement leg) — this is chain COMPOSITION, not a per-request
    policy decision inside the facade. Every leg wired in ALWAYS runs and delegates; nothing turns a wired
    gate off per call. ``asset_store`` (a :class:`vigil_core...RegisteredAssetStore`) and ``scope_check``
    (the charter scope predicate; default: derived from the signed authority) feed the classification leg.

    ``base_gate`` (an already-built conjunctive gate callable) may be injected in place of building one — the
    same dependency-injection seam ``conjunctive_gate`` exposes, so the wiring is testable without the full
    trust-root machinery. framework is imported lazily below and inside the leg adapters (FATAL-2)."""
    if base_gate is None:
        from .conjunctive_gate import build_offense_gate  # framework LAZY inside its own closure

        base_gate = build_offense_gate(slug=slug, trust_root=trust_root, classify=classify, **offense_gate_kwargs)

    gates: list[Gate] = []
    if include_classification:
        # UNKNOWN is never authorized: classify the target FIRST (registered-asset store, then the signed
        # charter scope) so an unknown/out-of-scope/critical target is refused before any other leg runs.
        # ``scope_check`` is the charter scope predicate; when not injected it is derived from the SIGNED
        # authority (the source of truth) — NOT a parallel scope engine.
        check = scope_check if scope_check is not None else _scope_check_from_authority(slug, trust_root)
        gates.append(
            Gate("classification", lambda req: _classification_outcome(req, store=asset_store, in_scope=check))
        )
    gates.append(Gate("authority", lambda req: _authority_outcome(base_gate, req)))
    if include_sovereignty:
        gates.append(Gate("sovereignty", _sovereignty_outcome))
    if include_entitlement:
        gates.append(Gate("entitlement", _entitlement_outcome))
    return SovereignBridge(gates, mode=mode, profile=profile)
