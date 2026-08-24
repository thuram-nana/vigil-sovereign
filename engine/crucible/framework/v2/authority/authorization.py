"""
authority.authorization — the signed EngagementAuthorization (W13-3 #496).

An engagement's authorization has THREE legs, and until now only two of
them existed as artifacts:

  * the **contract** leg — the authorization *letter* a customer signs
    (``framework/templates/authorization-letter.md``);
  * the **runtime** leg — the ``charter.md`` scope table the engine reads
    at gate time (``common.ethics.parse_scope``); and
  * the **technical** leg — a machine-verifiable, threshold-signed object
    the executor can honour byte-for-byte.

This module is that third leg. :class:`EngagementAuthorization` is a signed
object that carries FOUR enforcement bounds — a **danger ceiling**, a
**validity window**, a **rate limit**, and a **concurrency limit** — and the
:class:`EngagementExecutor` HONOURS all four: an action above the ceiling,
outside the window, beyond the rate, or beyond the concurrency limit is
REFUSED with a distinct, typed :class:`~common.errors.EthicsViolation`.

This is NOT a second policy engine. It makes no fresh authorization
decision of its own:

  * the **danger ceiling** is expressed in — and compared against — the ONE
    WARDEN classifier of record (:mod:`vigil_core.warden_tiers`); there is
    no new danger taxonomy here;
  * the **signature** reuses the entitlement layer's Ed25519 m-of-n
    threshold crypto and the SAME governance ``TrustRoot`` that signs
    entitlements and engagement authorities; and
  * the **scope** it carries is cross-checked against the letter and the
    charter (:mod:`authority.crosscheck`) so the contract, runtime, and
    technical legs cannot drift apart.

Composition with the neighbours: the entitlement layer says *which
capabilities this deployment may run at all*; the :class:`EngagementAuthority`
(W13-2) says *what host scope / environment / destructive posture this
engagement has*; this :class:`EngagementAuthorization` bounds *how dangerous,
how fast, how many at once, and until when* the executor may act. Each is a
distinct, orthogonal bound; none re-implements another's policy.
"""

from __future__ import annotations

import json
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator

from pydantic import BaseModel, ConfigDict, Field, model_validator
from vigil_core.warden_tiers import Tier, classify

from ..common.errors import (
    AuthorityExpired,
    ConcurrencyLimitExceeded,
    DangerCeilingExceeded,
    EthicsViolation,
    RateLimitExceeded,
)
from ..entitlement.models import Signature, TrustRoot
from .models import ActionRequest

# ---------------------------------------------------------------------------
# The signed object
# ---------------------------------------------------------------------------

_TIER_BY_LABEL = {t.label: t for t in Tier}


class EngagementAuthorization(BaseModel):
    """The unsigned core that is canonicalised and signed. Every field here
    is covered by the signature; changing any byte invalidates it.

    Carries the four enforcement bounds the executor honours (``danger_ceiling``,
    the ``not_before``/``not_after`` window, ``rate_limit`` per ``rate_window_seconds``,
    and ``concurrency_limit``) plus the ``scope`` that the letter / charter /
    this object are cross-checked against so the three legs cannot drift."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    authorization_id: str = Field(min_length=1, description="Stable unique id (uuid).")
    engagement_slug: str = Field(min_length=1)
    issuer: str = Field(min_length=1, description="Issuing governance authority name.")
    scope: list[str] = Field(
        min_length=1,
        description="In-scope host patterns. Cross-checked against the "
        "authorization letter and charter.md scope tables (authority.crosscheck).",
    )
    danger_ceiling: str = Field(
        pattern=r"^A[0-3]$",
        description="The maximum WARDEN autonomy tier (A0..A3) an action may "
        "classify to. Reuses the ONE WARDEN classifier of record — not a second "
        "danger taxonomy. An action classifying above this is refused.",
    )
    not_before: datetime
    not_after: datetime
    rate_limit: int = Field(
        ge=1,
        description="Maximum number of actions permitted within any "
        "rate_window_seconds sliding window.",
    )
    rate_window_seconds: float = Field(
        default=60.0, gt=0.0, description="Length of the rate-limit sliding window."
    )
    concurrency_limit: int = Field(
        ge=1, description="Maximum number of actions permitted in flight at once."
    )
    issued_at: datetime

    @model_validator(mode="after")
    def _check_window(self) -> "EngagementAuthorization":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self

    @property
    def ceiling_tier(self) -> Tier:
        """The danger ceiling as a WARDEN :class:`Tier` (validated by the field
        pattern, so the lookup is total)."""
        return _TIER_BY_LABEL[self.danger_ceiling]


class SignedEngagementAuthorization(BaseModel):
    """An EngagementAuthorization plus the governance signatures over its
    canonical form. Verified against the same TrustRoot the entitlement and
    engagement-authority layers use."""

    model_config = ConfigDict(extra="forbid")

    document: EngagementAuthorization
    signatures: list[Signature] = Field(min_length=1)


# ---------------------------------------------------------------------------
# Canonical signing bytes
# ---------------------------------------------------------------------------

# Domain-separation tag, distinct from the entitlement, revocation, authority,
# and deployment-profile domains — so an authorization signature can never be
# replayed as any other kind of signature. Never change without a
# schema_version bump and migration.
_AUTHORIZATION_DOMAIN = b"crucible-engagement-authorization-v1\x00"


def authorization_signing_bytes(document: EngagementAuthorization) -> bytes:
    """The exact bytes an authoriser signs / a verifier checks."""
    body = json.dumps(
        document.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _AUTHORIZATION_DOMAIN + body


def sign_authorization(
    document: EngagementAuthorization, signers: dict[str, str]
) -> SignedEngagementAuthorization:
    """Sign an authorization with each (key_id -> private_key_b64). The caller
    supplies at least the trust root's threshold of authorised signers.
    Provisioning act (operator side); the runtime only ever verifies."""
    from ..entitlement.crypto import sign

    msg = authorization_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedEngagementAuthorization(document=document, signatures=signatures)


def verify_authorization(
    signed: SignedEngagementAuthorization, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return (ok, reason). True iff at least the threshold of distinct
    trust-root authorisers validly signed the authorization's canonical form."""
    from ..entitlement.crypto import verify_threshold

    result = verify_threshold(
        authorization_signing_bytes(signed.document), signed.signatures, trust_root
    )
    return result.satisfied, result.reason


# ---------------------------------------------------------------------------
# The executor gate — honours all four bounds
# ---------------------------------------------------------------------------


class EngagementAuthorizationDecision(BaseModel):
    """The verdict for one action against a signed authorization's four
    enforcement bounds."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    denial_code: str = Field(
        default="",
        description="expired | above_ceiling | rate_limited | concurrency_limited "
        "— empty when allowed.",
    )
    danger_tier: str = Field(description="The action's classified WARDEN tier (A0..A3).")
    ceiling: str = Field(description="The authorization's danger ceiling (A0..A3).")
    checked_at: datetime


_DENIAL_ERRORS: dict[str, type[EthicsViolation]] = {
    "expired": AuthorityExpired,
    "above_ceiling": DangerCeilingExceeded,
    "rate_limited": RateLimitExceeded,
    "concurrency_limited": ConcurrencyLimitExceeded,
}


def action_danger(operation: str) -> Tier:
    """Classify an operation/tool name to a WARDEN tier using the ONE shared
    classifier of record. Exposed so a caller uses the SAME classification the
    kernel and offense gate use, never a private copy."""
    return classify(operation)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def authorize_engagement_action(
    authorization: EngagementAuthorization,
    *,
    danger: Tier,
    actions_in_window: int,
    in_flight: int,
    now: datetime | None = None,
) -> EngagementAuthorizationDecision:
    """Evaluate one action against the four enforcement bounds of a signed
    authorization. First failure wins; fail-closed throughout. Pure — the
    caller supplies the current window count and in-flight count (the
    :class:`EngagementExecutor` tracks them).

    Check order:
      1. validity window  -> EXPIRED           (denial_code "expired")
      2. danger ceiling   -> DangerCeiling      (denial_code "above_ceiling")
      3. rate limit       -> RateLimit          (denial_code "rate_limited")
      4. concurrency      -> Concurrency         (denial_code "concurrency_limited")
    """
    ts = now or _utcnow()
    ceiling = authorization.ceiling_tier

    def decide(allowed: bool, reason: str, code: str = "") -> EngagementAuthorizationDecision:
        return EngagementAuthorizationDecision(
            allowed=allowed,
            reason=reason,
            denial_code=code,
            danger_tier=danger.label,
            ceiling=ceiling.label,
            checked_at=ts,
        )

    # 1. validity window
    if ts < _as_utc(authorization.not_before):
        return decide(
            False,
            f"authorization not yet valid (not_before {authorization.not_before.isoformat()})",
            "expired",
        )
    if ts > _as_utc(authorization.not_after):
        return decide(
            False,
            f"authorization expired (not_after {authorization.not_after.isoformat()})",
            "expired",
        )

    # 2. danger ceiling — the WARDEN tier of the action must not exceed the ceiling.
    if int(danger) > int(ceiling):
        return decide(
            False,
            f"action danger tier {danger.label} exceeds the authorization ceiling "
            f"{ceiling.label}",
            "above_ceiling",
        )

    # 3. rate limit — actions already taken in the window must be below the cap.
    if actions_in_window >= authorization.rate_limit:
        return decide(
            False,
            f"rate limit reached ({actions_in_window}/{authorization.rate_limit} "
            f"actions within {authorization.rate_window_seconds:g}s)",
            "rate_limited",
        )

    # 4. concurrency — in-flight actions must be below the cap.
    if in_flight >= authorization.concurrency_limit:
        return decide(
            False,
            f"concurrency limit reached ({in_flight}/{authorization.concurrency_limit} "
            f"actions in flight)",
            "concurrency_limited",
        )

    return decide(True, f"authorized (danger {danger.label} <= ceiling {ceiling.label})")


@dataclass
class EngagementExecutor:
    """Enforces a signed authorization's four bounds at the action boundary.

    The executor is where "the authorization is HONOURED" becomes literally
    true: it maintains the sliding-window action timestamps (for the rate
    limit) and the in-flight count (for the concurrency limit), classifies each
    operation with the ONE WARDEN classifier (for the danger ceiling), and
    checks the validity window — refusing, with a distinct typed
    :class:`~common.errors.EthicsViolation`, any action that breaches a bound.

    It holds the *document* (an already-verified authorization). Verifying the
    signature is a separate, prior step (:func:`verify_authorization` /
    ``authority.store``); the executor never acts on an unverified document
    because it is only ever handed a verified one.
    """

    authorization: EngagementAuthorization
    _recent: deque[float] = field(default_factory=deque)
    _in_flight: int = 0

    def _prune(self, now: datetime) -> None:
        cutoff = now.timestamp() - self.authorization.rate_window_seconds
        while self._recent and self._recent[0] <= cutoff:
            self._recent.popleft()

    @property
    def in_flight(self) -> int:
        return self._in_flight

    def actions_in_window(self, now: datetime | None = None) -> int:
        self._prune(now or _utcnow())
        return len(self._recent)

    def authorize(
        self, operation: str, *, now: datetime | None = None
    ) -> EngagementAuthorizationDecision:
        """Evaluate an operation without reserving anything (does not mutate
        rate/concurrency state). Classifies ``operation`` with WARDEN."""
        ts = now or _utcnow()
        self._prune(ts)
        return authorize_engagement_action(
            self.authorization,
            danger=action_danger(operation),
            actions_in_window=len(self._recent),
            in_flight=self._in_flight,
            now=ts,
        )

    @contextmanager
    def execute(
        self, operation: str, *, now: datetime | None = None
    ) -> Iterator[EngagementAuthorizationDecision]:
        """Authorize ``operation`` and, if allowed, RESERVE it (record the
        action in the rate window and increment the in-flight count for the
        duration of the ``with`` block). Raises the matching typed
        EthicsViolation if any of the four bounds is breached — the executor
        refusing to act. The reservation is released on exit even if the body
        raises."""
        ts = now or _utcnow()
        decision = self.authorize(operation, now=ts)
        if not decision.allowed:
            err = _DENIAL_ERRORS.get(decision.denial_code, EthicsViolation)
            raise err(decision.reason)
        self._recent.append(ts.timestamp())
        self._in_flight += 1
        try:
            yield decision
        finally:
            self._in_flight -= 1

    def require(
        self, request: ActionRequest, *, now: datetime | None = None
    ) -> EngagementAuthorizationDecision:
        """Authorize an :class:`ActionRequest` (its ``action_kind`` is the
        operation classified) or raise. Non-reserving; use :meth:`execute` to
        reserve for the duration of the action."""
        decision = self.authorize(request.action_kind, now=now)
        if not decision.allowed:
            err = _DENIAL_ERRORS.get(decision.denial_code, EthicsViolation)
            raise err(decision.reason)
        return decision
