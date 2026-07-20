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

The composition core (:func:`conjunctive_decide`) is pure — both halves are injected as thunks —
so it is fully testable without CRUCIBLE or the kernel. :func:`build_offense_gate` wires the real
CRUCIBLE ``authorize_action`` (loaded via the governance trust root — the seam map flagged a
``None`` trust root as the biggest fail-open) and the real WARDEN classifier; its ``framework``
import is LAZY so this module stays import-clean for the sovereign side (which never calls it).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .warden_gate import DEFAULT_CEILING, DEFAULT_FLOOR, ToolDecision, decide_tool


@dataclass(frozen=True)
class GateVerdict:
    allowed: bool          # may this action auto-run right now?
    outcome: str           # "allow" | "queue" | "deny"
    reason: str
    crucible_allowed: bool | None      # CRUCIBLE in-envelope? (None if it errored)
    warden: ToolDecision | None        # the WARDEN tool decision (None if not reached/errored)


@dataclass(frozen=True)
class CrucibleResult:
    """The minimal shape the composition needs from the CRUCIBLE authority half."""
    allowed: bool
    reason: str


@dataclass(frozen=True)
class DestructionOutcome:
    """The minimal shape the composition needs from the threshold-destruction half. The concrete
    ``destruction_gate.DestructionDecision`` (``.authorized`` + ``.reason``) satisfies this duck-type,
    so the composition stays decoupled from that module and is testable in isolation."""
    authorized: bool
    reason: str


def conjunctive_decide(
    *,
    crucible_authorize: Callable[[], CrucibleResult],
    warden_decide: Callable[[], ToolDecision],
    destructive: bool = False,
    destruction_authorize: Callable[[], Any] | None = None,
) -> GateVerdict:
    """Compose the gates, first-failure-wins, fail-closed. Both core halves are thunks. For a
    DESTRUCTIVE action a THIRD conjunct is required — the m-of-n threshold-destruction authorization
    (``destruction_authorize`` returns an object with ``.authorized`` + ``.reason``); a destructive
    action with no destruction gate wired, an errored gate, or an unauthorized result is a DENY."""
    # 1. CRUCIBLE first — its killswitch step is the absolute stop. Any deny OR error => DENY.
    try:
        cru = crucible_authorize()
    except Exception as exc:  # a raised EthicsViolation (halted/expired/out-of-scope/…) or any error
        return GateVerdict(False, "deny", f"CRUCIBLE gate error/refusal (fail-closed): {exc}", None, None)
    if not cru.allowed:
        return GateVerdict(False, "deny", f"CRUCIBLE denied: {cru.reason}", False, None)

    # 2. WARDEN tool gate.
    try:
        war = warden_decide()
    except Exception as exc:
        return GateVerdict(False, "deny", f"WARDEN gate error (fail-closed): {exc}", True, None)

    # 3. Threshold-destruction gate — a HARD extra conjunct for destructive/high-blast actions. It is
    #    orthogonal to WARDEN's tier approval: an autonomous worker must not perform an irreversible
    #    action without the owner-inclusive m-of-n quorum, even if WARDEN would auto-allow the class.
    if destructive:
        if destruction_authorize is None:
            return GateVerdict(
                False, "deny",
                "destructive action requires a threshold-destruction gate, but none was wired "
                "(fail-closed)", True, war,
            )
        try:
            dz = destruction_authorize()
        except Exception as exc:
            return GateVerdict(False, "deny", f"destruction gate error (fail-closed): {exc}", True, war)
        if getattr(dz, "authorized", False) is not True:
            # strict `is True` (not truthiness): a buggy/adversarial gate returning a truthy-but-not-
            # bool authorized (e.g. "no", 1, a non-empty list) must NOT open the irreversible-action gate.
            return GateVerdict(
                False, "deny",
                f"destructive action not threshold-authorized: {getattr(dz, 'reason', 'refused')}",
                True, war,
            )

    if war.outcome == "auto":
        note = "both gates allow: CRUCIBLE in-envelope AND WARDEN auto"
        if destructive:
            note += " AND destruction threshold-authorized"
        return GateVerdict(True, "allow", note, True, war)
    if war.outcome == "queue":
        return GateVerdict(False, "queue", f"in envelope, but WARDEN needs owner approval: {war.reason}", True, war)
    # "deny" OR any unrecognised WARDEN outcome → DENY. Only an explicit "auto" may ALLOW, so a
    # new/unexpected outcome string can never silently open the gate (fail-closed conjunction).
    return GateVerdict(False, "deny", f"WARDEN refused tool {war.tool!r} (outcome={war.outcome!r}): {war.reason}", True, war)


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
                authority, req, killswitch=killswitch, actions_taken=actions_taken, now=now,
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
                        authority=destruction_authority, now=now, is_consumed=is_consumed,
                    )

        return conjunctive_decide(
            crucible_authorize=crucible_authorize,
            warden_decide=warden_decide,
            destructive=destructive,
            destruction_authorize=destruction_authorize,
        )

    return gate
