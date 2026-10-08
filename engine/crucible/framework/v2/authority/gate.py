"""
authority.gate — authorize one action against authority + kill-switch.

Check order (first failure wins), fail-closed throughout:

  1. kill-switch tripped  -> HALTED   (the absolute stop, checked first)
  2. outside time window  -> EXPIRED
  3. target out of scope  -> denied (out_of_scope)
  4. destructive & not permitted            -> denied (destructive)
  5. destructive on LIVE without 2nd ack     -> denied (live_destructive)
  6. action budget exhausted                 -> denied (budget)
  6b. blast-radius over ceiling (OPT-IN)     -> denied (blast_radius)
  6c. witness quorum unmet (OPT-IN)          -> denied (witness_quorum)
  7. otherwise            -> allowed

Step 6b is DEFAULT-OFF and ADVISORY: it runs ONLY when the caller injects both a
`blast_radius_fn` predictor and a `blast_ceiling`, and only AFTER every other check has
otherwise cleared the action (so a denied action keeps its original code and the predictor is
not even consulted). The predictor is a read-only forward world-model query injected as a
callable — the gate never imports the world model, which informs the decision but mints no FACT
and is no oracle input. Absent those two kwargs the decision is byte-identical to before.

Step 6c is DEFAULT-OFF and DEMOTE-ONLY, and mirrors 6b exactly. It runs ONLY when the caller
injects `witness_quorum_fn` (the re-executed oracle-witness quorum evaluator), and only AFTER
every other check — including 6b — has cleared the action, so a prior denial keeps its own code
and the quorum is never consulted for a refused action. The evaluator RE-EXECUTES the
deterministic oracle over the finding's retained `witness_context` and counts DISTINCT
oracle-witness kinds; a producer-carried corroboration set or a critic/RL/LLM vote can never
satisfy N (only a re-fired oracle signal is a witness). It can ONLY map an otherwise-allowed
action to a denied one — it NEVER promotes, and it MINTS NOTHING (no FACT, certificate or spine
row): it only returns this decision. The oracle remains the sole mint authority. An operator may
PROCEED-BELOW-QUORUM for THIS action only by injecting `witness_quorum_ack` (a verified,
action-bound acknowledgement) — which lifts the ACTION veto without promoting the finding. Absent
`witness_quorum_fn` (and the policy + `witness_context` it keys on) the decision is byte-identical
to before. Both the predictor and the quorum evaluator are injected as callables — the gate never
imports the world model NOR the oracle/veracity layer.

`authorize_action` returns a decision (for callers that branch);
`require_authorization` raises the matching typed EthicsViolation (for
call sites that must hard-stop). Both consult the kill-switch first, so a
tripped engagement cannot take any action by any path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import urlparse

from ..common.errors import (
    AuthorityExpired,
    BlastRadiusExceeded,
    BudgetExhausted,
    DestructiveActionRefused,
    EngagementHalted,
    EthicsViolation,
    OutOfScope,
    WitnessQuorumUnmet,
)
from ..common.ethics import host_matches_scope
from ..entitlement.models import TrustRoot
from .killswitch import KillSwitch
from .models import (
    ActionRequest,
    AuthorityState,
    AuthorizationDecision,
    EngagementAuthority,
    TargetEnvironment,
)
from .store import load_authority, load_verified_authority


def _host_of(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return (parsed.hostname or "").strip()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


class BlastRadiusVerdict(Protocol):
    """The structural shape the optional blast-radius veto reads back from an injected predictor.

    Deliberately a Protocol, NOT an import of ``worldmodel.impact.ForwardBlastResult``: the gate
    stays decoupled from the world model (the world model is ADVISORY — injected as a callable,
    never imported here, so this engine module never pulls in the graph layer). Any object with these
    two attributes satisfies it; ``ForwardBlastResult`` does, structurally."""

    @property
    def incremental_blast(self) -> float: ...

    @property
    def newly_reachable_jewels(self) -> list[str]: ...


class WitnessQuorumVerdict(Protocol):
    """The structural shape the optional witness-quorum veto reads back from an injected quorum
    evaluator.

    Deliberately a Protocol, NOT an import of ``veracity.witness_quorum.QuorumOutcome``: the gate stays
    decoupled from the oracle/veracity layer (the quorum is ADVISORY to the authority gate — injected as
    a callable, never imported here, so this engine module never pulls in the verify/oracle layer and
    never becomes an oracle input). Any object with these attributes satisfies it; ``QuorumOutcome``
    does, structurally. The gate acts on ``applicable`` and ``ok`` ONLY — so the veto can only ever
    WITHHOLD (map allowed True->False), never promote — and uses ``reason`` for the denial message."""

    @property
    def applicable(self) -> bool: ...

    @property
    def ok(self) -> bool: ...

    @property
    def reason(self) -> str: ...


def authorize_action(
    authority: EngagementAuthority,
    request: ActionRequest,
    *,
    killswitch: KillSwitch | None = None,
    actions_taken: int = 0,
    now: datetime | None = None,
    blast_radius_fn: Callable[[ActionRequest], BlastRadiusVerdict] | None = None,
    blast_ceiling: float | None = None,
    witness_quorum_fn: Callable[[ActionRequest], WitnessQuorumVerdict] | None = None,
    witness_quorum_ack: Callable[[ActionRequest, WitnessQuorumVerdict], bool] | None = None,
) -> AuthorizationDecision:
    """Evaluate one action. Pure except for reading the kill-switch file and — only when the
    optional pre-action blast-radius veto is wired — calling the injected read-only predictor.

    The blast-radius veto (``blast_radius_fn`` + ``blast_ceiling``) is DEFAULT-OFF and ADVISORY. It
    runs ONLY when BOTH are supplied, and ONLY as the final conjunct — after every other check has
    cleared the action — so a kill-switch/window/scope/destructive/budget denial always wins and the
    predictor is not consulted for an action that is refused anyway. When wired, it DENIES
    (code ``blast_radius``) any otherwise-allowed action whose predicted INCREMENTAL blast — the
    summed business impact of the crown jewels it would newly expose — strictly exceeds the ceiling.
    A predictor that raises propagates (the veto fails loud, never silently allowing). Absent either
    kwarg this function behaves and returns byte-identically to before, so every existing caller is
    unaffected.

    The witness-quorum veto (``witness_quorum_fn`` [+ optional ``witness_quorum_ack``]) is DEFAULT-OFF
    and DEMOTE-ONLY, and mirrors the blast veto. It runs ONLY when ``witness_quorum_fn`` is supplied,
    and ONLY as the FINAL conjunct — after every other check (6b included) has cleared the action — so
    any prior denial keeps its own code and the evaluator is not consulted for a refused action. When
    wired, it DENIES (code ``witness_quorum``) an otherwise-allowed action whose injected verdict is
    ``applicable and not ok`` — i.e. the finding's retained ``witness_context``, RE-EXECUTED by the
    evaluator, re-fires fewer than N DISTINCT independent oracle-witness kinds for an operator-critical
    class. It can ONLY map allowed True->False (never promote), and this function MINTS NOTHING — it
    only returns a decision. An operator may PROCEED-BELOW-QUORUM for THIS action only via
    ``witness_quorum_ack`` (a verified, action-bound acknowledgement): when it returns True the ACTION
    is authorized below the quorum WITHOUT promoting the finding to a FACT. Absent ``witness_quorum_fn``
    (and the policy + ``witness_context`` it keys on) this function is byte-identical to before. The
    evaluator and ack are injected as callables — the gate imports neither the oracle/veracity layer
    nor any crypto, so it never becomes an oracle input."""
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

    # 6b. blast-radius veto — OPT-IN, DEFAULT-OFF, ADVISORY. Runs only when BOTH a predictor and a
    #     ceiling are supplied; absent either, this block is skipped and the decision is byte-identical
    #     to before. Placed last so it vetoes only an OTHERWISE-ALLOWED action (every prior denial keeps
    #     its own code and the predictor is never consulted for a refused action). The predictor is the
    #     read-only forward world-model query injected as a callable — advisory to the gate, no FACT.
    if blast_radius_fn is not None and blast_ceiling is not None:
        verdict = blast_radius_fn(request)
        if verdict.incremental_blast > blast_ceiling:
            return decide(
                False, AuthorityState.ACTIVE,
                f"blast-radius veto: action would newly expose crown jewels worth "
                f"{verdict.incremental_blast} (> ceiling {blast_ceiling}): "
                f"{verdict.newly_reachable_jewels}", "blast_radius")

    # 6c. witness-quorum veto — OPT-IN, DEFAULT-OFF, DEMOTE-ONLY. Mirrors 6b: runs only when an
    #     evaluator is injected; absent it this block is skipped and the decision is byte-identical to
    #     before. Placed LAST (after 6b) so it vetoes only an OTHERWISE-ALLOWED action — every prior
    #     denial keeps its own code and the evaluator is never consulted for a refused action. The
    #     evaluator RE-EXECUTES the deterministic oracle over the finding's retained witness_context
    #     and returns a verdict; the gate acts on ``applicable`` and ``ok`` ONLY, so it can only
    #     WITHHOLD an under-corroborated action (map allowed True->False), NEVER promote. It MINTS
    #     NOTHING — no FACT, certificate or spine row; only this decision is returned. A producer-
    #     carried corroboration set or a critic/RL/LLM vote cannot satisfy N (that exclusion is
    #     enforced by the injected evaluator, which counts only re-fired oracle signals). An
    #     action-bound operator PROCEED-BELOW-QUORUM ack (``witness_quorum_ack``) may lift the veto for
    #     THIS action only — authorizing the ACTION without promoting the finding.
    if witness_quorum_fn is not None:
        wq = witness_quorum_fn(request)
        if wq.applicable and not wq.ok:
            if witness_quorum_ack is None or not witness_quorum_ack(request, wq):
                return decide(
                    False, AuthorityState.ACTIVE,
                    f"witness-quorum veto: {wq.reason}", "witness_quorum")
            # else: a valid, action-bound PROCEED-BELOW-QUORUM acknowledgement authorizes THIS action
            # below the quorum. The ACTION proceeds; the finding is NOT promoted to a FACT (the oracle
            # layer is untouched and nothing is minted here).

    # 7. allowed
    return decide(True, AuthorityState.ACTIVE,
                  f"authorized against {authority.environment.value} environment")


def authorize_oob_egress(authority: EngagementAuthority, relay_host: str) -> bool:
    """Authorize OOB relay egress against the authority's DEDICATED ``oob_relay_host`` field.

    This is a SEPARATE gate from :func:`authorize_action`'s general host-scope matcher, on purpose: the OOB
    collaborator relay is an EGRESS destination the operator hosts, not a scan TARGET, so authorizing it must
    NOT widen ``authority.scope`` (which would make the relay a first-class attack target and a charter
    in-scope row). Fail-closed: an authority with no signed ``oob_relay_host``, or a relay host that does not
    match it EXACTLY, is denied — the scanner may only reach the relay the owner explicitly named. Exact
    single-host match (no scope patterns, no CIDR); the relay host is a single literal hostname the sovereign
    ceremony validated with the same hard floor as a scan host."""
    want = (getattr(authority, "oob_relay_host", "") or "").strip().lower()
    if not want:
        return False
    got = (_host_of(relay_host) or str(relay_host or "").strip()).lower()
    return bool(got) and got == want


_DENIAL_ERRORS: dict[str, type[EthicsViolation]] = {
    "halted": EngagementHalted,
    "expired": AuthorityExpired,
    "out_of_scope": OutOfScope,
    "destructive": DestructiveActionRefused,
    "live_destructive": DestructiveActionRefused,
    "budget": BudgetExhausted,
    "blast_radius": BlastRadiusExceeded,
    "witness_quorum": WitnessQuorumUnmet,
}


def require_authorization(
    authority: EngagementAuthority,
    request: ActionRequest,
    *,
    killswitch: KillSwitch | None = None,
    actions_taken: int = 0,
    now: datetime | None = None,
    blast_radius_fn: Callable[[ActionRequest], BlastRadiusVerdict] | None = None,
    blast_ceiling: float | None = None,
    witness_quorum_fn: Callable[[ActionRequest], WitnessQuorumVerdict] | None = None,
    witness_quorum_ack: Callable[[ActionRequest, WitnessQuorumVerdict], bool] | None = None,
) -> AuthorizationDecision:
    """Authorize or raise. The typed EthicsViolation must not be silently
    caught — it is the engagement refusing to act. The optional blast-radius veto
    (``blast_radius_fn`` + ``blast_ceiling``) and witness-quorum veto (``witness_quorum_fn`` [+
    ``witness_quorum_ack``]) are forwarded unchanged; when the blast veto fires it raises
    ``BlastRadiusExceeded`` and when the quorum veto fires it raises ``WitnessQuorumUnmet``. Absent all
    of these kwargs this is byte-identical to before."""
    decision = authorize_action(
        authority, request, killswitch=killswitch, actions_taken=actions_taken, now=now,
        blast_radius_fn=blast_radius_fn, blast_ceiling=blast_ceiling,
        witness_quorum_fn=witness_quorum_fn, witness_quorum_ack=witness_quorum_ack,
    )
    if not decision.allowed:
        err = _DENIAL_ERRORS.get(decision.denial_code, EthicsViolation)
        raise err(decision.reason)
    return decision


def load_authority_for_gate(
    slug: str,
    *,
    trust_root: TrustRoot | None = None,
    path: Path | None = None,
) -> EngagementAuthority:
    """Load the authority the gate should enforce, choosing the load path.

    This is the single, first-class entry point a caller uses to obtain an
    authority before feeding it to :func:`authorize_action` /
    :func:`require_authorization`.

    - If ``trust_root`` is supplied, the *verified* (threshold-signed) load
      path is used: the on-disk document must carry at least the trust
      root's threshold of valid governance signatures or the load fails
      closed (raises ``AuthorityUnsigned``). This is the recommended,
      high-assurance path — pass a trust root and unsigned/tampered
      documents cannot arm an engagement.
    - If ``trust_root`` is ``None``, the legacy unsigned load path is used
      (compat for deployments not yet running signed authorities).

    Selecting the verified path is therefore as simple as passing a trust
    root; nothing else about the call changes.
    """
    if trust_root is not None:
        return load_verified_authority(slug, trust_root, path)
    return load_authority(slug, path)
