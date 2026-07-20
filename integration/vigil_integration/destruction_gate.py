"""
destruction_gate — m-of-n threshold authorization for destructive / high-blast-radius offense
actions (VIGIL I4, LOCKED decision 2: "destructive/high-blast actions need the m-of-n threshold").

This is the highest-consequence gate in the system. A single autonomous (prompt-injectable) offense
worker must NOT be able to perform an irreversible or high-blast action on its own authority. So on
top of the P7 conjunctive WARDEN+CRUCIBLE gate, a destructive action additionally requires a
**threshold authorization** that a quorum of independent authorizers signed — and, mandatorily, the
OWNER among them. The plan's shape (§6): offense-worker key + owner YubiKey/HSM + policy key.

Five properties, all fail-closed (first failure wins; any error or malformed input is a DENY):

  1. **m-of-n threshold** — admitted only if a quorum of DISTINCT trusted authorizers signed it
     (``vigil_core.verify_threshold``; low-order/duplicate keys already barred at the crypto core).
     This delivers the RFC-9591 *m-of-n authorization* security property; true FROST single-signature
     aggregation is a size/verification refinement that does NOT change the property, deferred like
     the I2 OpenTimestamps anchor.
  2. **Mandatory owner** — the mandatory signer set (the owner, and any other non-optional signer)
     is part of the immutable, deployment-time :class:`DestructionAuthority`, bound to the SAME
     provisioned artifact as the keys. It is NOT a per-call string: a per-call ``owner_key_id`` could
     be renamed to a compromised worker's own id (the worker is itself a registered authorizer), so
     the mandatory set is fixed at deployment and the gate refuses unless EVERY mandatory signer is
     among the valid signers. A worker+policy quorum without the owner authorizes nothing.
  3. **Action binding** — the signed authorization names the action (engagement, target, blast class,
     action_id); it cannot be replayed to authorize a DIFFERENT authorization. NOTE: ``action_id`` is
     an opaque string to this gate — binding to the real command depends on the signer computing
     ``action_id = digest(command)`` and the executor re-deriving it; the gate never sees the command
     and cannot enforce that. Property 3 is exact at the (engagement, target, class, action_id) level.
  4. **Dead-man's-switch (anti-dormancy)** — the validity window is bounded (``not_after`` and a
     policy-capped lifetime). A pre-signed, long-lived "sleeper" authorization is void; a quorum must
     re-authorize close in time to execution, bounding autonomy.
  5. **Single-use** — an authorization carries one nonce. The gate CHECKS it against a caller-supplied
     ``is_consumed`` (required; no permissive default) and returns the nonce for the caller to record
     as consumed. Consumption itself is the caller's atomic commit against the append-only spine (the
     spine append, with nonce uniqueness enforced there, is the serialization point) — the pure gate
     offers the check, not the atomic check-and-consume, so a caller MUST record consumption
     atomically at/after execution or a concurrent re-use of the SAME authorization could double-fire
     that one action. Single-use survives restart because ``is_consumed`` is re-derived from the spine.

Import-clean: ``vigil_core`` only (no ``framework.*``/``strix.*``) — the verification is sovereign-
safe and runs in either environment; the offense worker consults it, it does not import the worker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from numbers import Real
from typing import Callable, Iterable

from vigil_core import (
    IntegrityError,
    Signature,
    TrustRoot,
    canonical_json,
    sign,
    verify_threshold,
)

# Fresh domain tag: a destruction authorization signature can NEVER be replayed as an evidence
# certificate, a transparency checkpoint, an offense-gate open, or any other signed artifact.
_DESTRUCTION_DOMAIN = b"vigil-destruction-authorization-v1\x00"

# Blast classes that REQUIRE a threshold authorization. Anything else is handled by the ordinary
# conjunctive gate; these are the irreversible / high-radius classes.
DESTRUCTIVE = "destructive"
HIGH_BLAST = "high-blast"
_GATED_CLASSES = frozenset({DESTRUCTIVE, HIGH_BLAST})


def _is_real(x: object) -> bool:
    # a genuine real number, but NOT bool (bool is an int subclass; a boolean window is malformed)
    return isinstance(x, Real) and not isinstance(x, bool)


@dataclass(frozen=True)
class DestructionAuthority:
    """Immutable, deployment-time destruction trust config: the quorum ``trust_root`` PLUS the set of
    MANDATORY signer key_ids (the owner, and any other non-optional signer). Bundling the mandatory
    set with the keys binds "who must sign" to the same provisioned artifact as the keys, so it
    cannot be renamed per call. Validated fail-closed at construction: the mandatory set must be
    non-empty and a subset of the trust root's authorizers."""

    trust_root: TrustRoot
    mandatory_signer_ids: frozenset = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mandatory_signer_ids", frozenset(self.mandatory_signer_ids))
        if not self.mandatory_signer_ids:
            raise ValueError("DestructionAuthority needs >=1 mandatory signer (the owner)")
        registered = {a.key_id for a in self.trust_root.authorizers}
        missing = self.mandatory_signer_ids - registered
        if missing:
            raise ValueError(f"mandatory signer(s) not registered in the trust root: {sorted(missing)}")


@dataclass(frozen=True)
class DestructiveAction:
    """The concrete action an offense worker wants to perform. ``action_id`` should be a stable
    digest of the exact operation (command + params) so the authorization binds to *this* action."""

    action_id: str
    engagement_slug: str
    target: str
    blast_class: str  # DESTRUCTIVE | HIGH_BLAST

    def requires_threshold(self) -> bool:
        return self.blast_class in _GATED_CLASSES


@dataclass(frozen=True)
class DestructionAuthorization:
    """What the quorum signs: the exact action, a bounded validity window, and a single-use nonce."""

    action_id: str
    engagement_slug: str
    target: str
    blast_class: str
    not_before: float
    not_after: float
    nonce: str

    def signing_payload(self) -> dict:
        return {
            "action_id": self.action_id,
            "engagement_slug": self.engagement_slug,
            "target": self.target,
            "blast_class": self.blast_class,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "nonce": self.nonce,
        }

    def matches(self, action: DestructiveAction) -> bool:
        return (
            self.action_id == action.action_id
            and self.engagement_slug == action.engagement_slug
            and self.target == action.target
            and self.blast_class == action.blast_class
        )

    def to_spine_payload(self) -> dict:
        """Inert audit record of an authorization appended to the spine (never code)."""
        return {"kind": "destruction-authorization", **self.signing_payload()}


@dataclass(frozen=True)
class SignedDestructionAuthorization:
    authorization: DestructionAuthorization
    signatures: tuple[Signature, ...] = ()


@dataclass(frozen=True)
class DestructionPolicy:
    """The dead-man's-switch bound. A destruction authorization whose window exceeds
    ``max_authorization_lifetime`` seconds is VOID — a quorum cannot pre-sign a long-lived sleeper."""

    max_authorization_lifetime: float = 900.0  # 15 minutes


DEFAULT_POLICY = DestructionPolicy()


@dataclass(frozen=True)
class DestructionDecision:
    authorized: bool
    reason: str
    nonce: str = ""  # on authorized=True, the nonce the caller must record as consumed on execution


class DestructionRefused(RuntimeError):
    """A destructive action was not threshold-authorized — it must not proceed. Fail-closed; must
    never be silently caught (it is the last line before an irreversible action)."""


def authorization_signing_bytes(auth: DestructionAuthorization) -> bytes:
    return _DESTRUCTION_DOMAIN + canonical_json(auth.signing_payload())


def sign_authorization(
    auth: DestructionAuthorization, signers: Iterable[tuple[str, str]]
) -> SignedDestructionAuthorization:
    """Provisioning/test helper: each (key_id, private_key_b64) signs the authorization."""
    msg = authorization_signing_bytes(auth)
    sigs = tuple(Signature(key_id=kid, signature_b64=sign(priv, msg)) for kid, priv in signers)
    return SignedDestructionAuthorization(authorization=auth, signatures=sigs)


def _well_formed(action, signed) -> str:
    """Return "" if the inputs are structurally sound, else a deny reason. Guards every field that
    reaches canonical_json / verify_threshold so a type-confused input becomes a DENY, not a raise.

    Uses EXACT-type checks (``type(x) is C``), not ``isinstance``: a caller-supplied subclass could
    override ``matches``/``signing_payload`` to decouple the action-binding or dead-man's-switch from
    the signed bytes, so only the concrete records are accepted (worker request data must be
    deserialized into concrete final types, never a behavior-overriding subclass)."""
    if type(action) is not DestructiveAction or type(signed) is not SignedDestructionAuthorization:
        return "malformed action or authorization"
    auth = signed.authorization
    if type(auth) is not DestructionAuthorization:
        return "malformed authorization"
    for name in ("action_id", "engagement_slug", "target", "blast_class", "nonce"):
        if type(getattr(auth, name)) is not str:
            return f"authorization field {name!r} is not a string"
    if not _is_real(auth.not_before) or not _is_real(auth.not_after):
        return "authorization window is not numeric"
    if type(signed.signatures) is not tuple or not all(
        type(s) is Signature for s in signed.signatures
    ):
        return "malformed signature list"
    return ""


def authorize_destruction(
    action: DestructiveAction,
    signed: SignedDestructionAuthorization,
    *,
    authority: DestructionAuthority,
    now: float,
    is_consumed: Callable[[str], bool],
    policy: DestructionPolicy = DEFAULT_POLICY,
) -> DestructionDecision:
    """Fail-closed decision on whether ``action`` is threshold-authorized right now. First failure
    wins; any error (malformed material, etc.) is a DENY, never an exception a caller might swallow
    into an allow. ``is_consumed`` is REQUIRED (no permissive default) — pass the spine-derived
    single-use check. Returns the nonce to consume on success."""
    reason = _well_formed(action, signed)
    if reason:
        return DestructionDecision(False, reason)
    if not _is_real(now):
        return DestructionDecision(False, "now is not numeric")
    auth = signed.authorization

    # (0) only gated classes need (and can use) this gate; refuse an unknown/ungated class here so a
    #     caller cannot mislabel a destructive action as benign to dodge the threshold.
    if action.blast_class not in _GATED_CLASSES:
        return DestructionDecision(False, f"blast class {action.blast_class!r} is not threshold-gated")

    # (1) action binding — the quorum signed THIS exact action, not a broader/other one.
    if not auth.matches(action):
        return DestructionDecision(False, "authorization does not match this action (binding)")

    # (2) validity window (nan compares False → deny).
    if not (auth.not_before <= now <= auth.not_after):
        return DestructionDecision(False, "outside the authorization validity window (expired/early)")

    # (3) dead-man's-switch: a bounded, sane, non-sleeper window.
    if not (auth.not_after > auth.not_before):
        return DestructionDecision(False, "non-positive authorization window")
    if (auth.not_after - auth.not_before) > policy.max_authorization_lifetime:
        return DestructionDecision(
            False, "authorization window exceeds max lifetime (dormant-authorization bound)"
        )

    # (4) single-use — a consumed authorization can never re-fire.
    if not auth.nonce:
        return DestructionDecision(False, "authorization has no nonce (single-use undecidable)")
    try:
        if is_consumed(auth.nonce):
            return DestructionDecision(False, "authorization already consumed (replay)")
    except Exception:
        return DestructionDecision(False, "single-use check errored — fail closed")

    # (5) m-of-n threshold + (6) mandatory signers, over the exact signed bytes.
    try:
        result = verify_threshold(
            authorization_signing_bytes(auth), list(signed.signatures), authority.trust_root
        )
    except (IntegrityError, TypeError, ValueError):
        return DestructionDecision(False, "malformed signature/key material — fail closed")
    if not result.satisfied:
        return DestructionDecision(False, f"threshold not met ({result.reason})")
    missing = authority.mandatory_signer_ids - set(result.valid_signers)
    if missing:
        return DestructionDecision(False, f"missing mandatory signer(s): {sorted(missing)}")

    return DestructionDecision(True, "threshold-authorized", nonce=auth.nonce)


def require_destruction_authorization(
    action: DestructiveAction,
    signed: SignedDestructionAuthorization,
    **kwargs,
) -> str:
    """Raise :class:`DestructionRefused` fail-closed unless ``action`` is threshold-authorized.
    Returns the nonce to record as consumed. This is called by the PRIVILEGED EXECUTOR (the trusted
    host-side call site that holds the deployment ``authority``) immediately before an irreversible
    action — NOT by the injectable agent, which only proposes the action. It MUST NOT be wrapped in a
    bare ``except``. ``authority`` must come from immutable deployment config, never from the request."""
    decision = authorize_destruction(action, signed, **kwargs)
    if not decision.authorized:
        raise DestructionRefused(decision.reason)
    return decision.nonce
