"""
conjunctive_gate — every target-touching offense action must pass BOTH gates (VIGIL P7 Slice 3).

Two orthogonal, conjunctive checks over one signed spine (plus a THIRD for destructive actions):

  * CRUCIBLE authority — "is THIS target/action inside the signed engagement envelope RIGHT NOW?"
    (killswitch → validity window → scope → destructive → live-destructive → budget; fail-closed).
    Its killswitch step has absolute precedence, so it is checked FIRST.
  * WARDEN tool gate — "what TIER is this tool-class, and must the owner approve it?"
    (raise-only A2 floor → auto / queue / deny; see warden_gate.decide_tool).
  * Threshold-destruction (I4) — for a DESTRUCTIVE/high-blast action ONLY: "is there an owner-inclusive
    m-of-n authorization for exactly this action?" (see destruction_gate). Orthogonal to WARDEN's tier
    approval — an irreversible action needs the quorum even if WARDEN would auto-allow the class.

First failure wins; ANY error in any half is a DENY (never caught-and-continued). The verdict
is the conjunction: ALLOW only if CRUCIBLE in-envelope AND WARDEN auto AND (if destructive) threshold-
authorized; QUEUE if in-envelope + destruction-satisfied but WARDEN needs owner approval; DENY otherwise.

The composition core (:func:`conjunctive_decide`) is pure — both halves are injected as thunks — so it is
fully testable without CRUCIBLE or the kernel. As of unification S6 that pure core (``conjunctive_decide`` +
``GateVerdict``/``CrucibleResult``/``DestructionOutcome``) lives in the neutral shared ``vigil_core.gate`` so
BOTH processes import the SAME gate-of-record primitive; this module RE-EXPORTS it (back-compat for every
existing importer of ``vigil_integration.conjunctive_gate``) and adds the OFFENSE wrapper.
:func:`build_offense_gate` wires the real CRUCIBLE ``authorize_action`` (loaded via the governance trust root
— the seam map flagged a ``None`` trust root as the biggest fail-open) and the real WARDEN classifier; its
``framework`` import is LAZY so this module stays import-clean for the sovereign side (which never calls it).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

# The pure gate-of-record composition now lives in the neutral shared core (S6). Re-exported here so every
# existing `from vigil_integration.conjunctive_gate import ...` keeps working, byte-identical semantics.
from vigil_core.gate import CrucibleResult, DestructionOutcome, GateVerdict, conjunctive_decide

from .warden_gate import DEFAULT_CEILING, DEFAULT_FLOOR, ToolDecision, decide_tool

__all__ = [
    "GateVerdict", "CrucibleResult", "DestructionOutcome", "conjunctive_decide", "build_offense_gate",
]


def _as_datetime(now: Any) -> "datetime | None":
    """The CRUCIBLE leg (authorize_action) wants a timezone-aware datetime (or None → it uses utcnow). A
    single ``now`` shared with the destruction leg (which wants an epoch float) must be adapted per-leg —
    this was the confirmed gate bug: one ``now`` broke whichever leg it wasn't typed for."""
    if now is None or isinstance(now, datetime):
        return now
    if isinstance(now, (int, float)) and not isinstance(now, bool):
        try:
            return datetime.fromtimestamp(float(now), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return None                                # unusable → authorize_action defaults to utcnow (safe)


def _as_epoch(now: Any) -> float:
    """The destruction leg (authorize_destruction) wants an epoch float (it rejects None/datetime/bool as
    'not numeric'). None/unusable → the real wall-clock, which is correct for the not_before/not_after
    dead-man's-switch window (this is not the deterministic learning path)."""
    if isinstance(now, datetime):
        return now.timestamp()
    if isinstance(now, (int, float)) and not isinstance(now, bool):
        return float(now)
    return time.time()


def build_offense_gate(
    *,
    slug: str,
    trust_root: Any,
    classify: Callable[[str], str],
    floor: str = DEFAULT_FLOOR,
    ceiling: str = DEFAULT_CEILING,
    killswitch: Any = None,
    actions_taken: int = 0,
    now: Any = None,
    destruction_authority: Any = None,
    is_consumed: Callable[[str], bool] | None = None,
) -> Callable[..., GateVerdict]:
    """Return ``gate(tool_name, target_url, destructive=False, *, destruction_action=None,
    destruction_signed=None) -> GateVerdict`` wired to the REAL gates — including the I4 threshold-
    destruction conjunct for destructive actions.

    Offense-side only: imports ``framework`` lazily (this module never runs in the sovereign env).
    ``trust_root`` MUST be the governance TrustRoot — the CRUCIBLE authority is loaded verified,
    so a tampered scope/window/destructive-flag is rejected at load (the map's biggest fail-open).
    A ``None`` trust_root is refused: it would load the authority UNSIGNED, so it fails closed here.

    ``now`` MUST be a TRUSTED-caller value (a datetime, an epoch float, or None → real clock) — NEVER
    request/agent/attacker-derived data. It is load-bearing for the CRUCIBLE validity-window and the
    destruction dead-man's-switch: an in-window value passed for an out-of-window authority would honor it.
    The live wiring passes no ``now`` (→ None → real clock), and the per-call ``gate(...)`` has no ``now``
    argument, so the only path that sets it is the trusted caller here.

    Destructive actions are threshold-gated: pass a ``destruction_authority`` (immutable
    :class:`destruction_gate.DestructionAuthority` from deployment config) and an ``is_consumed``
    single-use check at build time, and per-call the ``destruction_action`` +
    ``destruction_signed`` quorum authorization. A destructive call missing ANY of these engages no
    threshold gate → ``conjunctive_decide`` DENIES it (fail-closed — an irreversible action never
    slips through on the two base gates alone).
    """
    if trust_root is None:
        raise ValueError(
            "build_offense_gate requires the governance trust_root: a None trust_root loads the "
            "CRUCIBLE authority UNSIGNED/unverified, so a tampered scope/window/destructive flag "
            "would pass the gate. Fail-closed refusal."
        )

    def gate(
        tool_name: str,
        target_url: str,
        destructive: bool = False,
        *,
        destruction_action: Any = None,
        destruction_signed: Any = None,
    ) -> GateVerdict:
        def crucible_authorize() -> CrucibleResult:
            # Lazy import keeps the module import-clean; only reachable in env-offense.
            from framework.v2.authority.gate import authorize_action, load_authority_for_gate
            from framework.v2.authority.models import ActionRequest

            authority = load_authority_for_gate(slug, trust_root=trust_root)  # verified, fail-closed
            req = ActionRequest(target=target_url, action_kind="offense", destructive=destructive)
            decision = authorize_action(
                authority, req, killswitch=killswitch, actions_taken=actions_taken,
                now=_as_datetime(now),          # CRUCIBLE leg wants a datetime (or None)
            )
            return CrucibleResult(allowed=bool(decision.allowed), reason=decision.reason)

        def warden_decide() -> ToolDecision:
            return decide_tool(tool_name, classify=classify, floor=floor, ceiling=ceiling)

        # Wire the real threshold-destruction thunk ONLY when the full context is present; otherwise
        # a destructive action reaches conjunctive_decide with no gate → DENY (fail-closed).
        destruction_authorize = None
        if destructive and destruction_authority is not None and destruction_action is not None \
                and destruction_signed is not None and is_consumed is not None:
            from .destruction_gate import authorize_destruction

            # Cross-bind the two halves: the quorum-authorized action MUST be the SAME target and
            # engagement the CRUCIBLE half is scoping (and the executor will act on). Without this a
            # single ALLOW could pair an in-envelope scope check for target A with a quorum that only
            # authorized destruction of target B. Fail-closed on any divergence.
            if (getattr(destruction_action, "target", None) != target_url
                    or getattr(destruction_action, "engagement_slug", None) != slug):
                def destruction_authorize() -> Any:  # type: ignore[misc]
                    return DestructionOutcome(
                        authorized=False,
                        reason=(f"authorization target/engagement "
                                f"({getattr(destruction_action, 'engagement_slug', None)!r}/"
                                f"{getattr(destruction_action, 'target', None)!r}) does not match the "
                                f"gate ({slug!r}/{target_url!r})"),
                    )
            else:
                def destruction_authorize() -> Any:  # type: ignore[misc]
                    return authorize_destruction(
                        destruction_action, destruction_signed,
                        authority=destruction_authority,
                        now=_as_epoch(now),      # destruction leg wants an epoch float
                        is_consumed=is_consumed,
                    )

        return conjunctive_decide(
            crucible_authorize=crucible_authorize,
            warden_decide=warden_decide,
            destructive=destructive,
            destruction_authorize=destruction_authorize,
        )

    return gate
