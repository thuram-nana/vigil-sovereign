"""
agents.tier3_validation — the gated Tier-3 *validation* layer.

This is the doctrine-MAXIMUM slice of CRUCIBLE's offensive surface, and it is
deliberately the narrowest. It does exactly one thing: prove, to the operator,
that an *already oracle-CONFIRMED* finding is real — by re-executing the
minimal proof the oracle already fired on — and it does so ONLY when a full
stack of fail-closed gates all say yes, against a LOCALHOST / authorized test
target, with a human approving that specific action.

It is NOT a generic exploit engine. It mints no new payloads, drives no
weaponization, establishes no persistence, and performs no lateral movement.
The "minimal PoC" is the veracity-firewall move (AUTONOMY-CHARTER.md §4.6,
CLAUDE.md invariant "prove by re-execution"): take the finding's retained
`oracle_context` — the exact evidence the deterministic oracle already
confirmed — and re-fire the oracle over it. If, and only if, the retained
proof re-fires does the layer report "impact validated". A proof that no
longer re-fires demotes to a refusal; it never asserts impact it cannot
re-prove.

WHAT IS DELIBERATELY NOT BUILT HERE (hard-excluded, per AUTONOMY-CHARTER.md
§4.6 / §5.4 and this workstream's charter — refuse, never build):

  * detection-evasion / anti-defender / stealth
  * C2 / persistence / implants
  * full-chain exploitation / turnkey weapons for real targets
  * credential-attack suites
  * identity-rotation / proxy-chaining
  * ANY action against live / remote / third-party hosts, ANY unattended action

The only entitlement this layer ever requires is
`Capability.EXPLOIT_EXECUTION` — the same one `ExploitAgent` already requires.
It never requests `DEFENDER_EVASION`, `FULL_CHAIN_EXPLOITATION`, or
`SELF_IMPROVEMENT_MERGE` (see `FORBIDDEN_CAPABILITIES` and the doctrine-boundary
tests). The forbidden capabilities are unreachable from this code path.

THE GATE STACK (all fail-closed, all required, evaluated in this order; the
first failure records a `refusal` on the immutable spine and stops):

  1. kill-switch      — the absolute stop, checked first (tripped/ambiguous → refuse)
  2. Tier-3 latch     — opt-in, DEFAULT-OFF process latch; not engaged → refuse.
                        This is what keeps the layer inert (byte-identical) until
                        an operator deliberately turns it on.
  3. finding CONFIRMED — the finding must be oracle-CONFIRMED
                        (verified_by_oracle + critique_status=='confirmed' +
                        retained oracle_context). An unconfirmed finding → refuse.
  4. charter scope    — ethics.require_in_scope(slug, target) (out of scope → refuse)
  5. localhost gate   — the target host must resolve ONLY to loopback
                        (non-loopback / unresolvable → refuse)
  6. entitlement      — require_capability(EXPLOIT_EXECUTION); denied → record a
                        refusal on the spine and RAISE (never silently caught)
  7. operator approval — per-action human y/N, DENY on timeout / non-tty

Only when all seven pass does the layer run the minimal PoC (re-fire the
retained oracle proof) and post a proof-of-impact `observation` to the spine.
Every decision and every refusal is written to the append-only, hash-linkable,
signable blackboard spine (`agents/blackboard.py`, chained/signed via
`agents/spine_chain.py`) — the audit trail.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from ..common import ethics
from ..common import logging as v2log
from ..common.errors import CrucibleError, EntitlementViolation, OutOfScope
from ..entitlement import Capability, require_capability
from ..authority import KillSwitch
from ..kernel import sovereignty
from ..verify.adapter import FindingContext
from ..verify.confirmation import confirm_finding
from .blackboard import Blackboard

_log = v2log.get_logger(__name__)


# ---------------------------------------------------------------------------
# Capability contract — what this layer may and may NOT require.
# ---------------------------------------------------------------------------

#: The single entitlement a Tier-3 validation ever requires. Identical to the
#: one ExploitAgent already gates on — this layer adds gates, never power.
TIER3_REQUIRED_CAPABILITY: Capability = Capability.EXPLOIT_EXECUTION

#: Capabilities this layer must NEVER request or reach. Asserted by the
#: doctrine-boundary tests. These correspond to the hard-excluded classes
#: (evasion, multi-bug weaponization, self-modification) which this workstream
#: refuses to build.
FORBIDDEN_CAPABILITIES: frozenset[Capability] = frozenset({
    Capability.DEFENDER_EVASION,
    Capability.FULL_CHAIN_EXPLOITATION,
    Capability.SELF_IMPROVEMENT_MERGE,
})

#: The gate identifiers, in evaluation order. Every one is fail-closed and
#: required; a Tier-3 validation runs only if all of them pass.
GATE_ORDER: tuple[str, ...] = (
    "kill-switch",
    "tier3-latch",
    "finding-confirmed",
    "charter-scope",
    "localhost",
    "entitlement",
    "operator-approval",
)

#: The environment flag an operator sets to engage the (default-off) latch.
TIER3_LATCH_ENV = "CRUCIBLE_TIER3_VALIDATION"
_TRUTHY = {"1", "true", "yes", "on"}

_LOOPBACK_HOST_LITERALS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class Tier3NotConfigured(CrucibleError):
    """Raised when Tier-3 validation is requested on a path that was never
    wired with a Tier3ValidationLayer. Fail-closed: the capability is
    unreachable unless an operator explicitly constructed and injected the
    layer."""


# ---------------------------------------------------------------------------
# Approval hook
# ---------------------------------------------------------------------------

#: (question, timeout_seconds) -> granted?  Deny on timeout / non-interactive.
ApprovalHook = Callable[[str, float], bool]


def _default_approval_hook() -> ApprovalHook:
    """The canonical per-action operator prompt (POSIX TTY y/N, default-deny on
    timeout / non-tty). Reused verbatim from the http_executor so there is one
    approval implementation, not two. Imported lazily to keep this module's
    import graph light."""
    from .http_executor import stdin_prompt_with_timeout
    return stdin_prompt_with_timeout


# ---------------------------------------------------------------------------
# Localhost resolution (fail-closed)
# ---------------------------------------------------------------------------


def _host_of(target_url: str) -> str:
    parts = urlsplit(target_url if "://" in target_url else "http://" + target_url)
    return (parts.hostname or "").strip().lower()


def resolves_to_loopback(host: str) -> tuple[bool, str]:
    """Return (ok, reason). ``ok`` is True ONLY if ``host`` is a loopback IP
    literal, or resolves through the system resolver to loopback addresses and
    *nothing else*. Any non-loopback address in the result set, an unparseable
    address, an unresolvable name, or an empty host all fail CLOSED — a name
    that resolves to both 127.0.0.1 and a public IP is refused, closing the
    rebinding trick."""
    if not host:
        return False, "empty host"
    literal = host.strip("[]")
    try:
        ip = ipaddress.ip_address(literal)
        return ip.is_loopback, (
            f"literal {ip} is {'loopback' if ip.is_loopback else 'NON-loopback'}"
        )
    except ValueError:
        pass  # not an IP literal — resolve the name
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return False, f"host {host!r} is unresolvable ({exc})"
    addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        return False, f"host {host!r} resolved to no addresses"
    for addr in addrs:
        try:
            if not ipaddress.ip_address(addr).is_loopback:
                return False, f"host {host!r} resolves to non-loopback address {addr}"
        except ValueError:
            return False, f"host {host!r} resolved to unparseable address {addr!r}"
    return True, f"host {host!r} resolves only to loopback {addrs}"


# ---------------------------------------------------------------------------
# Tier-3 latch — opt-in, default-OFF, fail-closed
# ---------------------------------------------------------------------------


@dataclass
class Tier3Latch:
    """The sovereignty-preserving Tier-3 latch.

    Default DISENGAGED. It engages only when an operator explicitly sets
    ``CRUCIBLE_TIER3_VALIDATION`` to a truthy value (or a test/host injects
    ``engaged=True``). While disengaged, every Tier-3 validation refuses — this
    is the mechanism that keeps the whole layer inert and byte-identical until
    an operator deliberately turns it on. It can only PERMIT the attempt to run
    the (still fully-gated) validation; it never relaxes any other gate and
    never weakens the sovereignty posture it reports."""

    #: None → read the env each call (operator toggles at runtime). True/False
    #: → an explicit override (host wiring / tests).
    engaged: bool | None = None

    def is_engaged(self) -> bool:
        if self.engaged is not None:
            return bool(self.engaged)
        return os.environ.get(TIER3_LATCH_ENV, "").strip().lower() in _TRUTHY

    def explain(self) -> str:
        state = "ENGAGED" if self.is_engaged() else "DISENGAGED (default)"
        try:
            tier = sovereignty.current().tier.value
        except Exception:  # pragma: no cover - sovereignty always resolves
            tier = "unknown"
        return f"tier3-latch={state}; sovereignty_tier={tier}"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tier3ValidationResult:
    """The outcome of a Tier-3 validation attempt.

    ``validated=True`` means every gate passed AND the finding's retained oracle
    proof re-fired — the finding's impact is re-proven. ``validated=False``
    means a gate refused (see ``refused_gate``) or the retained proof did not
    re-fire; either way NO new offensive action was taken."""

    validated: bool
    finding_slug: str
    refused_gate: str = ""
    reason: str = ""
    oracle_kind: str | None = None
    confidence: float | None = None
    proof_marker: str | None = None
    rationale: str = ""
    decision_event_id: int | None = None


# ---------------------------------------------------------------------------
# The layer
# ---------------------------------------------------------------------------


@dataclass
class Tier3ValidationLayer:
    """Isolated, gated Tier-3 validation.

    Construct one per engagement and hand it a finding + the target URL it was
    confirmed against. ``validate()`` runs the full fail-closed gate stack and,
    only if all gates pass, re-fires the retained oracle proof as the minimal
    PoC. Everything is written to the spine.

    Injectables (all default to the safe, production behavior):
      - ``killswitch``   : auto-wired to KillSwitch(slug) when None — the
                           off-switch is always present.
      - ``latch``        : defaults to a Tier3Latch reading the env (default OFF).
      - ``approval_hook``: defaults to the http_executor's stdin y/N prompt
                           (deny on timeout / non-tty).
      - ``scope_check``  : defaults to ethics.require_in_scope (strict charter
                           scope). Injectable so gate-ordering tests need not
                           materialise a charter.
    """

    bb: Blackboard
    engagement_slug: str
    killswitch: KillSwitch | None = None
    latch: Tier3Latch | None = None
    approval_hook: ApprovalHook | None = None
    approval_timeout_s: float = 30.0
    scope_check: Callable[[str, str], None] | None = None
    verifier: Any | None = None

    _engagement_id: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        if self.killswitch is None:
            self.killswitch = KillSwitch(self.engagement_slug)
        if self.latch is None:
            self.latch = Tier3Latch()
        if self.approval_hook is None:
            self.approval_hook = _default_approval_hook()
        if self.scope_check is None:
            self.scope_check = ethics.require_in_scope
        self._engagement_id = self.bb.engagement_id(self.engagement_slug)

    # ---- public API ----

    def validate(
        self,
        finding_payload: dict[str, Any],
        *,
        target_url: str,
        operator_note: str = "",
    ) -> Tier3ValidationResult:
        """Attempt to re-prove ``finding_payload``'s impact against
        ``target_url``. Runs the full gate stack; returns a
        ``Tier3ValidationResult``. Raises ``EntitlementViolation`` (after
        recording a refusal) when the entitlement gate denies — that gate is
        the one hard-stop that must never be swallowed."""
        slug_hint = str(finding_payload.get("finding_slug", "?"))
        decision_id = self._post_decision(
            question=(
                f"Tier-3 validation of confirmed finding {slug_hint!r} "
                f"against {target_url}"
            ),
            choice="requested",
            rationale=operator_note or "operator-initiated Tier-3 validation",
        )

        # G1. kill-switch — the absolute stop, checked first.
        assert self.killswitch is not None
        if self.killswitch.is_tripped():
            return self._refuse(
                "kill-switch", slug_hint, decision_id,
                f"engagement halted by kill-switch: {self.killswitch.reason()}",
                gate_label="kill-switch",
            )

        # G2. Tier-3 latch — opt-in, default-OFF. The sovereignty-preserving
        # arming latch; a disengaged latch is a sovereignty refusal.
        assert self.latch is not None
        if not self.latch.is_engaged():
            return self._refuse(
                "tier3-latch", slug_hint, decision_id,
                "Tier-3 validation latch is DISENGAGED (default). An operator "
                f"must set {TIER3_LATCH_ENV}=1 (or inject an engaged latch) to "
                "arm it. " + self.latch.explain(),
                gate_label="sovereignty",
            )

        # G3. finding must be oracle-CONFIRMED.
        ok, why = _finding_is_oracle_confirmed(finding_payload)
        if not ok:
            return self._refuse(
                "finding-confirmed", slug_hint, decision_id,
                f"finding is not oracle-CONFIRMED: {why}. Tier-3 validation only "
                "re-proves findings a deterministic oracle already confirmed.",
                gate_label="epistemic",
            )

        # G4. charter scope.
        assert self.scope_check is not None
        try:
            self.scope_check(self.engagement_slug, target_url)
        except OutOfScope as exc:
            return self._refuse(
                "charter-scope", slug_hint, decision_id,
                f"target out of charter scope: {exc}", gate_label="scope",
            )

        # G5. localhost / authorized-test-target — resolve, fail closed.
        host = _host_of(target_url)
        loop_ok, loop_why = resolves_to_loopback(host)
        if not loop_ok:
            return self._refuse(
                "localhost", slug_hint, decision_id,
                f"target is not a localhost/authorized test target: {loop_why}",
                gate_label="scope",
            )

        # G6. entitlement — the one hard gate that RAISES (recorded, never
        # silently caught). require_capability raises EntitlementViolation
        # under an enforced deployment when EXPLOIT_EXECUTION is not granted.
        try:
            require_capability(TIER3_REQUIRED_CAPABILITY)
        except EntitlementViolation as exc:
            self._post_refusal(
                "entitlement", slug_hint, decision_id,
                f"EXPLOIT_EXECUTION not entitled: {exc}",
                gate_label="entitlement",
            )
            raise

        # G7. per-action operator approval — deny on timeout / non-tty.
        assert self.approval_hook is not None
        question = (
            f"Tier-3 VALIDATION: re-execute the retained oracle proof for "
            f"confirmed finding {slug_hint!r} against {target_url} (localhost)? "
            "This demonstrates the already-confirmed impact; no new payloads."
        )
        granted = self.approval_hook(question, self.approval_timeout_s)
        if not granted:
            return self._refuse(
                "operator-approval", slug_hint, decision_id,
                "operator did not approve this action (declined or prompt "
                "timeout — default-deny)",
                gate_label="ethics",
            )

        # ---- all gates passed: run the MINIMAL PoC ----
        return self._run_minimal_poc(finding_payload, target_url, decision_id, slug_hint)

    # ---- minimal PoC ----

    def _run_minimal_poc(
        self,
        finding_payload: dict[str, Any],
        target_url: str,
        decision_id: int | None,
        slug_hint: str,
    ) -> Tier3ValidationResult:
        """The minimal PoC: reconstruct the finding's retained oracle evidence
        and RE-FIRE the deterministic oracle over it. This re-proves the exact
        impact the oracle already confirmed — no new traffic, no new payloads,
        no weaponization. If the retained proof no longer re-fires, demote to a
        refusal (the veracity firewall can only demote)."""
        raw_ctx = finding_payload.get("oracle_context")
        try:
            ctx = FindingContext.model_validate(raw_ctx)
        except Exception as exc:  # malformed retained context → refuse
            return self._refuse(
                "finding-confirmed", slug_hint, decision_id,
                f"retained oracle_context did not parse: {type(exc).__name__}: {exc}",
                gate_label="epistemic",
            )

        confirmed = confirm_finding(finding_payload, ctx, self.verifier)
        if confirmed is None:
            return self._refuse(
                "finding-confirmed", slug_hint, decision_id,
                "the finding's retained oracle proof did NOT re-fire — refusing "
                "to assert an impact that can no longer be re-proven",
                gate_label="epistemic",
            )

        proof_marker = _proof_marker(raw_ctx, confirmed.confirmed_by)
        summary = (
            f"Tier-3 validation PROVED impact of confirmed finding {slug_hint!r}: "
            f"oracle {confirmed.confirmed_by} re-fired over the retained proof "
            f"(confidence={confirmed.confidence:.3f}). {confirmed.rationale}"
        ).strip()

        # audit: proof-of-impact observation on the spine, parented to the decision.
        self.bb.post(
            engagement=self._engagement_id, kind="observation",
            agent_name="tier3-validation", parent_id=decision_id,
            payload={
                "source": "tier3-validation",
                "surface": target_url,
                "summary": summary,
                "raw_excerpt": f"proof_marker={proof_marker!r}",
                "confidence": float(confirmed.confidence),
            },
        )
        _log.info(
            "agents.tier3_validation.validated",
            finding=slug_hint, oracle_kind=str(confirmed.confirmed_by),
            confidence=float(confirmed.confidence), target=target_url,
        )
        return Tier3ValidationResult(
            validated=True,
            finding_slug=slug_hint,
            oracle_kind=str(confirmed.confirmed_by),
            confidence=float(confirmed.confidence),
            proof_marker=proof_marker,
            rationale=confirmed.rationale,
            decision_event_id=decision_id,
        )

    # ---- spine helpers ----

    def _post_decision(self, *, question: str, choice: str, rationale: str) -> int:
        return self.bb.post(
            engagement=self._engagement_id, kind="decision",
            agent_name="tier3-validation",
            payload={"question": question, "choice": choice, "rationale": rationale},
        )

    def _post_refusal(
        self, gate: str, slug_hint: str, parent_id: int | None, reason: str,
        *, gate_label: str | None = None,
    ) -> int:
        return self.bb.post(
            engagement=self._engagement_id, kind="refusal",
            agent_name="tier3-validation", parent_id=parent_id,
            payload={
                "gate": gate_label or gate,
                "action_refused": f"tier3-validation:{slug_hint}",
                "reason": f"[{gate}] {reason}",
                "fatal": True,
            },
        )

    def _refuse(
        self, gate: str, slug_hint: str, parent_id: int | None, reason: str,
        *, gate_label: str | None = None,
    ) -> Tier3ValidationResult:
        self._post_refusal(gate, slug_hint, parent_id, reason, gate_label=gate_label)
        _log.warning(
            "agents.tier3_validation.refused", gate=gate, finding=slug_hint,
            reason=reason,
        )
        return Tier3ValidationResult(
            validated=False, finding_slug=slug_hint,
            refused_gate=gate, reason=reason, decision_event_id=parent_id,
        )


# ---------------------------------------------------------------------------
# Free helpers
# ---------------------------------------------------------------------------


def _finding_is_oracle_confirmed(finding_payload: dict[str, Any]) -> tuple[bool, str]:
    """A finding is validate-able only if a deterministic oracle already
    confirmed it AND its confirming evidence was retained. All three conditions
    are required (fail-closed):
      - critique_status == 'confirmed'
      - verified_by_oracle is True
      - oracle_context present (the retained evidence to re-fire)."""
    status = finding_payload.get("critique_status")
    if status != "confirmed":
        return False, f"critique_status={status!r} (need 'confirmed')"
    if finding_payload.get("verified_by_oracle") is not True:
        return False, "verified_by_oracle is not True (no oracle carried the confirmation)"
    if not finding_payload.get("oracle_context"):
        return False, "no retained oracle_context to re-fire"
    return True, "oracle-confirmed with retained evidence"


def _proof_marker(raw_ctx: Any, confirmed_by: Any) -> str:
    """The human-facing proof marker: the side-effect canary the oracle keyed
    on when present, else the name of the oracle kind that re-fired."""
    if isinstance(raw_ctx, dict):
        marker = raw_ctx.get("marker")
        if marker:
            return str(marker)
    return str(confirmed_by)
