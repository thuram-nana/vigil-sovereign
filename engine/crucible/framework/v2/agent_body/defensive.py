"""agent_body.defensive — a deterministic safety kernel for narrowly-typed DEFENSIVE containment actions (M4.3).

ADDITIVE and DEFAULT-OFF. This module introduces a small, fixed vocabulary of DEFENSIVE containment action
kinds and the gate logic that authorizes them. It changes nothing about the existing ``ProposedAction`` kinds
(``http_get`` and the rest): :func:`gate_defensive_action` returns ``None`` for any kind it does not own, so a
body routes every non-defensive action through its existing gate byte-for-byte. The capability requirement
applies ONLY to the new defensive kinds.

WHAT A DEFENSIVE KIND IS. Containment only — the actions a defender takes to STOP an incident:
``isolate_endpoint``, ``revoke_session``, ``block_ip``, ``quarantine_host``. Offensive / exploit kinds
(``run_command`` and anything that executes code, opens a shell, or drives an exploit) can NEVER be a
defensive kind: :func:`register_defensive_kind` refuses them, so a capability cannot be minted to authorize
one through this seam.

CAPABILITY != AUTHORIZATION. A defensive action must CARRY an owner-signed ``vigil_core.Capability`` in its
params. The token is the owner's grant; it authorizes nothing by itself. The GATE is the authority:
:func:`gate_defensive_action` runs between ``propose`` and ``execute`` and VERIFIES the token with
``verify_capability`` — owner-signed, within its (attenuated) window at ``now``, engagement-bound,
non-destructive, not revoked, its attenuation chain intact and narrow-only — then checks the action's kind is
in the (attenuated) allowlist, that the capability is bound to the action's target (impact-bounding), and, for
a pinned (non-bearer) audience, that the presenter proves possession of the audience key over a fresh kernel
challenge. A defensive action with no valid capability is REFUSED (fail-closed): absent token, wrong owner,
expired / not-yet-valid, wrong engagement, kind not in the allowlist, wrong target, revoked, over the rate
limit, or a missing / stale / forged wielder proof each produce a DENY carrying its own reason.

The kernel's trusted inputs — ``trusted_owner_pubkey``, ``engagement``, ``now``, ``challenge``,
``revoked_ids`` — are supplied by the deterministic safety context, never read from the untrusted proposing
body. The body only CARRIES the capability token (and, when pinned, a wielder proof) in ``action.params``.

NOT AN ORACLE. The capability is an authorization artifact only. It is never an oracle input and mints no
FACT; this module imports nothing from the verify / oracle layer and the frozen 15-member oracle set is
untouched.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Union

from vigil_core import digest_payload
from vigil_core.capability import (
    Attenuation,
    Capability,
    CapabilityError,
    EffectiveCapability,
    WielderProof,
    sign_capability,
    verify_capability,
    verify_wielder_proof,
)

from .interface import AgentBody, GateDecision, ProposedAction

__all__ = [
    "DefensiveCapabilityError",
    "DEFENSIVE_KINDS",
    "ISOLATE_ENDPOINT",
    "REVOKE_SESSION",
    "BLOCK_IP",
    "QUARANTINE_HOST",
    "register_defensive_kind",
    "is_defensive_kind",
    "defensive_kinds",
    "defensive_target_digest",
    "mint_defensive_capability",
    "DefensiveRateLimiter",
    "gate_defensive_action",
    "CapabilityGatedBody",
]

_BEARER = "*"


class DefensiveCapabilityError(Exception):
    """A defensive-kind registration or defensive-capability mint was asked to cover an offensive / unknown
    kind, or was otherwise malformed. Fail-closed: the caller gets no defensive capability."""


# -------------------------------------------------------------------------------------------------------
# The defensive-kind vocabulary + its registration guard.
# -------------------------------------------------------------------------------------------------------
# Offensive / exploit kinds that must NEVER be authorizable as defensive containment. Matched exactly and by
# substring, so a disguised variant (``exec_run_command``, ``deploy_payload``) is caught too. The PRIMARY
# control is that the defensive vocabulary is the fixed four built-ins below; this denylist makes an attempt
# to register an offensive kind fail LOUDLY rather than silently widen the vocabulary.
_OFFENSIVE_KINDS = frozenset({
    "run_command", "command", "exec", "exec_command", "execute", "shell", "shell_exec", "spawn",
    "subprocess", "system", "popen", "fork", "exploit", "run_exploit", "reverse_shell", "bind_shell",
    "rce", "code_exec", "eval", "sql_injection", "sqli", "nosql_injection", "ssti", "xss", "inject",
    "injection", "payload", "deploy_payload", "upload_webshell", "webshell", "exfiltrate", "exfil",
    "lateral_move", "privilege_escalation", "privesc", "persist", "persistence", "backdoor", "implant",
})
_OFFENSIVE_SUBSTRINGS = (
    "command", "shell", "exploit", "exec", "inject", "payload", "exfil", "webshell", "backdoor",
    "implant", "rce", "spawn", "privesc",
)

_DEFENSIVE_KINDS: set[str] = set()


def _is_offensive(kind: str) -> bool:
    k = str(kind).strip().lower()
    if k in _OFFENSIVE_KINDS:
        return True
    return any(sub in k for sub in _OFFENSIVE_SUBSTRINGS)


def register_defensive_kind(kind: str) -> str:
    """Register ``kind`` as an authorizable DEFENSIVE containment kind, returning it. Raises
    :class:`DefensiveCapabilityError` for an empty kind, or for any offensive / exploit kind
    (``run_command`` and the like) — an offensive kind can never be made authorizable through the defensive
    seam. Idempotent for an already-registered defensive kind."""
    if not isinstance(kind, str) or not kind.strip():
        raise DefensiveCapabilityError("a defensive kind must be a non-empty string")
    k = kind.strip()
    if _is_offensive(k):
        raise DefensiveCapabilityError(
            f"{k!r} is an offensive/exploit kind and cannot be a defensive capability kind")
    _DEFENSIVE_KINDS.add(k)
    return k


# The fixed, narrow defensive vocabulary. Each is registered through the SAME guard, so the guard is proven
# real on the built-ins themselves (an offensive built-in would fail at import).
ISOLATE_ENDPOINT = register_defensive_kind("isolate_endpoint")
REVOKE_SESSION = register_defensive_kind("revoke_session")
BLOCK_IP = register_defensive_kind("block_ip")
QUARANTINE_HOST = register_defensive_kind("quarantine_host")

# A frozen snapshot of the built-in vocabulary, for callers and tests. The live membership check is
# :func:`is_defensive_kind` (it honors any later :func:`register_defensive_kind`).
DEFENSIVE_KINDS = frozenset(_DEFENSIVE_KINDS)


def is_defensive_kind(kind: str) -> bool:
    """True iff ``kind`` is a registered defensive containment kind (the kernel owns it)."""
    return isinstance(kind, str) and kind.strip() in _DEFENSIVE_KINDS


def defensive_kinds() -> frozenset[str]:
    """The current set of registered defensive kinds (the built-ins plus any later registrations)."""
    return frozenset(_DEFENSIVE_KINDS)


# -------------------------------------------------------------------------------------------------------
# Target binding (impact-bounding) + owner-side minting.
# -------------------------------------------------------------------------------------------------------
_TARGET_DOMAIN = "defensive-target"


def defensive_target_digest(target: str) -> str:
    """The stable digest a defensive capability binds to via its ``identity_digest`` field, so a grant for one
    target cannot authorize an action against another (impact-bounding by target). Pure and offline."""
    return digest_payload({"domain": _TARGET_DOMAIN, "target": str(target)})


def mint_defensive_capability(owner_key, *, engagement: str, target: str, kinds: list[str],
                              not_before: int, not_after: int, rate_limit: int, revocation_id: str,
                              audience: str = _BEARER) -> Capability:
    """Owner-mint a defensive containment capability: bound to ``target`` (via ``identity_digest``), scoped to
    ``kinds`` (each MUST be a registered defensive kind — an offensive kind is refused here too), short-lived
    (``[not_before, not_after]``), rate-limited, and revocable (``revocation_id``). A thin wrapper over
    ``vigil_core.sign_capability`` that sets ``identity_digest = defensive_target_digest(target)`` and validates
    the kinds. Raises :class:`DefensiveCapabilityError` for an empty / offensive / unregistered kind, and
    propagates ``vigil_core.CapabilityError`` for a footgun grant (inverted window, empty revocation_id, ...)."""
    ks = list(kinds)
    if not ks:
        raise DefensiveCapabilityError("a defensive capability needs at least one defensive kind")
    for k in ks:
        if _is_offensive(k):
            raise DefensiveCapabilityError(
                f"{k!r} is an offensive/exploit kind and cannot be in a defensive capability allowlist")
        if not is_defensive_kind(k):
            raise DefensiveCapabilityError(f"{k!r} is not a registered defensive kind")
    return sign_capability(owner_key, engagement=engagement, identity_digest=defensive_target_digest(target),
                           class_allowlist=ks, not_before=int(not_before), not_after=int(not_after),
                           rate_limit=int(rate_limit), revocation_id=str(revocation_id), audience=str(audience))


# -------------------------------------------------------------------------------------------------------
# Rate limiting (impact-bounding) — a per-capability authorization counter.
# -------------------------------------------------------------------------------------------------------
@dataclass
class DefensiveRateLimiter:
    """An in-memory per-capability authorization counter, keyed by ``revocation_id``. A capability's
    ``rate_limit`` is the maximum number of ALLOW decisions the gate will grant it; the kernel records a grant
    only on a full ALLOW, so a REFUSED action never consumes budget. In-memory and per-process by design — a
    durable or cross-process limiter is the integrator's to supply by implementing the same two methods
    (:meth:`would_exceed` and :meth:`record`)."""

    _counts: dict[str, int] = field(default_factory=dict)

    def granted(self, key: str) -> int:
        """How many ALLOW decisions have been recorded for ``key``."""
        return self._counts.get(key, 0)

    def would_exceed(self, key: str, limit: int) -> bool:
        """True iff recording one more grant for ``key`` would exceed ``limit`` (i.e. it is already at limit)."""
        return self.granted(key) >= int(limit)

    def record(self, key: str) -> None:
        """Record one granted authorization for ``key``."""
        self._counts[key] = self.granted(key) + 1


# -------------------------------------------------------------------------------------------------------
# The kernel.
# -------------------------------------------------------------------------------------------------------
_PARAM_CAPABILITY = "capability"
_PARAM_ATTENUATIONS = "attenuations"
_PARAM_WIELDER_PROOF = "wielder_proof"

_REFUSE = "defensive gate refused: "


def _coerce_capability(obj: Any) -> Optional[Capability]:
    if isinstance(obj, Capability):
        return obj
    if isinstance(obj, Mapping):
        try:
            return Capability.model_validate(dict(obj))
        except Exception:
            return None
    return None


def _coerce_attenuations(obj: Any) -> list[Attenuation]:
    if obj is None:
        return []
    out: list[Attenuation] = []
    try:
        items = list(obj)
    except TypeError as e:
        raise CapabilityError("attenuations must be a list") from e
    for a in items:
        if isinstance(a, Attenuation):
            out.append(a)
        elif isinstance(a, Mapping):
            try:
                out.append(Attenuation.model_validate(dict(a)))
            except Exception as e:
                raise CapabilityError(f"malformed attenuation in the capability bundle: {e}") from e
        else:
            raise CapabilityError("malformed attenuation in the capability bundle")
    return out


def _coerce_proof(obj: Any) -> Optional[WielderProof]:
    if isinstance(obj, WielderProof):
        return obj
    if isinstance(obj, Mapping):
        try:
            return WielderProof.model_validate(dict(obj))
        except Exception:
            return None
    return None


def gate_defensive_action(action: ProposedAction, *, trusted_owner_pubkey: str, engagement: str, now: int,
                          challenge: str, revoked_ids: frozenset[str] = frozenset(),
                          rate_limiter: DefensiveRateLimiter) -> Optional[GateDecision]:
    """The deterministic safety kernel for DEFENSIVE containment actions, run BETWEEN ``propose`` and
    ``execute``.

    Returns:
      * ``None`` if ``action.kind`` is not a defensive kind — the caller then gates it exactly as before
        (every existing kind, ``http_get`` included, is untouched and byte-identical);
      * ``GateDecision(authorized=True, ...)`` iff the action carries a capability that VERIFIES: owner-signed,
        within its (attenuated) window at ``now``, engagement-bound, non-destructive, not revoked, chain intact;
        its kind is in the (attenuated) allowlist; it is bound to ``action.target``; for a pinned audience, a
        valid :class:`WielderProof` over ``challenge`` proves possession; and the grant is within its rate limit;
      * ``GateDecision(authorized=False, reason=...)`` otherwise — fail-closed, with a distinct reason per cause.

    The kernel's trusted inputs are supplied by the caller's safety context, never read from the proposing body.
    The body only CARRIES the capability (key ``capability``), optional ``attenuations``, and, for a pinned
    audience, a ``wielder_proof`` in ``action.params``. The gate is the authority that verifies them."""
    if not is_defensive_kind(action.kind):
        return None   # DEFAULT-OFF: non-defensive kinds flow through the existing gate unchanged.

    params = action.params or {}
    cap = _coerce_capability(params.get(_PARAM_CAPABILITY))
    if cap is None:
        return GateDecision(False, _REFUSE + "no capability token for a defensive action")

    # verify_capability enforces: owner signature, engagement, non-destructive, window at `now`, revocation,
    # and a narrow-only attenuation chain. Any failure is a fail-closed DENY carrying its specific reason.
    try:
        attenuations = _coerce_attenuations(params.get(_PARAM_ATTENUATIONS))
        eff: EffectiveCapability = verify_capability(
            cap, trusted_owner_pubkey=trusted_owner_pubkey, now=int(now), engagement=engagement,
            attenuations=attenuations, revoked_ids=revoked_ids)
    except CapabilityError as e:
        return GateDecision(False, _REFUSE + str(e))

    # The kind must be in the (attenuated) allowlist. verify_capability returns the allowlist but does not
    # check a specific kind against it — the gate does, so a cap for `revoke_session` cannot `block_ip`.
    if action.kind not in set(eff.class_allowlist):
        return GateDecision(False, _REFUSE + f"kind {action.kind!r} not in the capability allowlist")

    # Impact-bounding: the capability is bound to exactly one target via identity_digest.
    if eff.identity_digest != defensive_target_digest(action.target):
        return GateDecision(False, _REFUSE + "capability is not bound to this target")

    # Proof-of-possession of the EFFECTIVE (post-attenuation) audience key — skipped only for a bearer grant
    # (no key to prove). A byte-holding thief without the audience private key cannot produce it.
    if eff.audience != _BEARER:
        proof = _coerce_proof(params.get(_PARAM_WIELDER_PROOF))
        try:
            verify_wielder_proof(proof, expected_audience=eff.audience, challenge=challenge, capability=cap)
        except CapabilityError as e:
            return GateDecision(False, _REFUSE + f"wielder proof: {e}")

    # Rate limit LAST, so an otherwise-invalid action never consumes budget and the earlier reason is returned.
    if rate_limiter.would_exceed(eff.revocation_id, eff.rate_limit):
        return GateDecision(False, _REFUSE + f"over the capability rate limit ({eff.rate_limit})")

    rate_limiter.record(eff.revocation_id)
    return GateDecision(True, f"defensive gate authorized: {action.kind} on {action.target!r} "
                              f"under capability {eff.revocation_id!r}")


# -------------------------------------------------------------------------------------------------------
# A reusable body that wires the kernel into the AgentBody gate() seam.
# -------------------------------------------------------------------------------------------------------
_NowInput = Union[int, Callable[[], int]]
_ChallengeInput = Union[str, Callable[[ProposedAction], str]]
_BaseGate = Callable[[ProposedAction], GateDecision]


class CapabilityGatedBody(AgentBody):
    """A reusable :class:`AgentBody` base that implements ONLY the gate seam: a DEFENSIVE containment kind is
    authorized solely by a valid capability (through :func:`gate_defensive_action`), and every other kind is
    delegated to ``base_gate`` byte-identically — so adding this seam does not change how a body gates
    ``http_get`` or any existing kind. A concrete body supplies ``think`` / ``propose`` / ``execute`` / ``learn``.

    The trusted kernel inputs (owner pubkey, engagement, clock, challenge, revoked set, rate limiter) are held
    by the body and passed to the kernel on every gate call — never read from the proposing side. ``now`` and
    ``challenge`` accept a value or a callable, so an operator context can supply fresh values per authorization;
    ``base_gate`` is the body's real conjunctive gate for non-defensive kinds (default: fail-closed DENY)."""

    def __init__(self, *, trusted_owner_pubkey: str, engagement: str, now: _NowInput,
                 challenge: _ChallengeInput = "", revoked_ids: frozenset[str] = frozenset(),
                 rate_limiter: Optional[DefensiveRateLimiter] = None,
                 base_gate: Optional[_BaseGate] = None) -> None:
        self._trusted_owner_pubkey = trusted_owner_pubkey
        self._engagement = engagement
        self._now = now
        self._challenge = challenge
        self._revoked_ids = revoked_ids
        self._rate_limiter = rate_limiter if rate_limiter is not None else DefensiveRateLimiter()
        self._base_gate = base_gate

    def _now_value(self) -> int:
        return int(self._now() if callable(self._now) else self._now)

    def _challenge_value(self, action: ProposedAction) -> str:
        return self._challenge(action) if callable(self._challenge) else self._challenge

    def base_gate(self, action: ProposedAction) -> GateDecision:
        """The gate for NON-defensive kinds. Delegates to the injected ``base_gate`` callable, or fail-closed
        DENY. Overriding it (or injecting one) does not touch the defensive seam."""
        if self._base_gate is not None:
            return self._base_gate(action)
        return GateDecision(False, "no base gate configured for a non-defensive kind")

    def gate(self, action: ProposedAction) -> GateDecision:
        decision = gate_defensive_action(
            action, trusted_owner_pubkey=self._trusted_owner_pubkey, engagement=self._engagement,
            now=self._now_value(), challenge=self._challenge_value(action), revoked_ids=self._revoked_ids,
            rate_limiter=self._rate_limiter)
        if decision is not None:
            return decision
        return self.base_gate(action)
