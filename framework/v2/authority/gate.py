"""
authority.gate — authorize one action against authority + kill-switch.

Check order (first failure wins), fail-closed throughout:

  1. kill-switch tripped  -> HALTED   (the absolute stop, checked first)
  2. outside time window  -> EXPIRED
  3. target out of scope  -> denied (out_of_scope)
  4. destructive & not permitted            -> denied (destructive)
  5. destructive on LIVE without 2nd ack     -> denied (live_destructive)
  6. action budget exhausted                 -> denied (budget)
  7. otherwise            -> allowed

`authorize_action` returns a decision (for callers that branch);
`require_authorization` raises the matching typed EthicsViolation (for
call sites that must hard-stop). Both consult the kill-switch first, so a
tripped engagement cannot take any action by any path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from ..common.errors import (
    AuthorityExpired,
    BudgetExhausted,
    DestructiveActionRefused,
    EngagementHalted,
    EthicsViolation,
    OutOfScope,
)
from ..common.ethics import host_matches_scope
from .killswitch import KillSwitch
from .models import (
    ActionRequest,
    AuthorityState,
    AuthorizationDecision,
    EngagementAuthority,
    TargetEnvironment,
)


def _host_of(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return (parsed.hostname or "").strip()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def authorize_action(
    authority: EngagementAuthority,
    request: ActionRequest,
    *,
    killswitch: KillSwitch | None = None,
    actions_taken: int = 0,
    now: datetime | None = None,
) -> AuthorizationDecision:
    """Evaluate one action. Pure except for reading the kill-switch file."""
    ts = now or _utcnow()

    def decide(
        allowed: bool, state: AuthorityState, reason: str, code: str = ""
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            allowed=allowed, state=state, target=request.target,
            reason=reason, denial_code=code, checked_at=ts,
        )

    # 1. kill-switch — the absolute stop, checked before anything else.
    if killswitch is not None and killswitch.is_tripped():
        return decide(
            False, AuthorityState.HALTED,
            f"engagement halted: {killswitch.reason()}", "halted",
        )

    # 2. validity window
    if ts < _as_utc(authority.not_before):
        return decide(False, AuthorityState.EXPIRED,
                      f"authority not yet valid (not_before {authority.not_before.isoformat()})",
                      "expired")
    if ts > _as_utc(authority.not_after):
        return decide(False, AuthorityState.EXPIRED,
                      f"authority expired (not_after {authority.not_after.isoformat()})",
                      "expired")

    # 3. scope
    host = _host_of(request.target)
    if not host or not host_matches_scope(host, authority.scope):
        return decide(False, AuthorityState.ACTIVE,
                      f"target {request.target!r} (host {host!r}) is not in scope "
                      f"{authority.scope}", "out_of_scope")

    # 4 & 5. destructive controls
    if request.destructive:
        if not authority.allow_destructive:
            return decide(False, AuthorityState.ACTIVE,
                          "destructive action refused: authority does not permit "
                          "destructive actions", "destructive")
        if (
            authority.environment is TargetEnvironment.LIVE
            and not authority.live_destructive_acknowledged
        ):
            return decide(False, AuthorityState.ACTIVE,
                          "destructive action against a LIVE environment requires a "
                          "second explicit acknowledgement "
                          "(live_destructive_acknowledged); run it against the TWIN "
                          "first", "live_destructive")

    # 6. budget
    if actions_taken >= authority.max_actions:
        return decide(False, AuthorityState.ACTIVE,
                      f"action budget exhausted ({actions_taken}/{authority.max_actions})",
                      "budget")

    # 7. allowed
    return decide(True, AuthorityState.ACTIVE,
                  f"authorized against {authority.environment.value} environment")


_DENIAL_ERRORS: dict[str, type[EthicsViolation]] = {
    "halted": EngagementHalted,
    "expired": AuthorityExpired,
    "out_of_scope": OutOfScope,
    "destructive": DestructiveActionRefused,
    "live_destructive": DestructiveActionRefused,
    "budget": BudgetExhausted,
}


def require_authorization(
    authority: EngagementAuthority,
    request: ActionRequest,
    *,
    killswitch: KillSwitch | None = None,
    actions_taken: int = 0,
    now: datetime | None = None,
) -> AuthorizationDecision:
    """Authorize or raise. The typed EthicsViolation must not be silently
    caught — it is the engagement refusing to act."""
    decision = authorize_action(
        authority, request, killswitch=killswitch, actions_taken=actions_taken, now=now,
    )
    if not decision.allowed:
        err = _DENIAL_ERRORS.get(decision.denial_code, EthicsViolation)
        raise err(decision.reason)
    return decision
