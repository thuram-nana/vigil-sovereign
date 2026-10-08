"""
authority.witness_quorum_gate — the bridge that arms the authority gate's OPT-IN, DEFAULT-OFF,
DEMOTE-ONLY witness-quorum veto (``authority.gate`` conjunct 6c, M4.4), plus the per-action
PROCEED-BELOW-QUORUM operator acknowledgement.

Why this lives OUTSIDE ``authority.gate``. The gate stays decoupled from the oracle/veracity layer
exactly as it stays decoupled from the world model (M4.2): the blast-radius veto is injected as a
read-only callable, never imported by the gate, and the witness-quorum veto is armed the SAME way.
``authorize_action`` takes two injected callables (``witness_quorum_fn`` + ``witness_quorum_ack``),
both default ``None``; this module builds them. So the gate module never imports ``veracity`` /
``verify`` / the oracle layer, and absent an injected policy the gate is byte-identical.

Two pieces:

  * :func:`witness_quorum_predicate` — the quorum EVALUATOR. Given an operator
    :class:`~framework.v2.veracity.witness_quorum.WitnessQuorumConfig`, it returns a callable the gate
    consults for ONE action: it RE-EXECUTES the deterministic oracle over the finding's RETAINED
    ``witness_context`` (``witness_quorum.evaluate``) and counts how many DISTINCT independent
    oracle-witness kinds re-fire. A producer-carried corroboration set, or a critic / RL / reflection /
    LLM vote, can NEVER satisfy N — only a re-fired oracle signal is a witness (the exclusion is
    structural: a non-oracle signal never enters the re-executed ``VerificationResult.signals`` the
    quorum counts). An action with NO ``witness_context`` (not tied to a finding) is INAPPLICABLE, so
    the gate is a no-op for it (byte-identical). The evaluator can only ever WITHHOLD — it never
    promotes, and the oracle remains the sole mint authority.

  * the PROCEED-BELOW-QUORUM ACK — :class:`ProceedBelowQuorumAck` + :func:`proceed_below_quorum_checker`.
    When the quorum blocks an action, the ONLY way past it (short of REQUIRE-MORE — running further
    oracle arms until N distinct kinds re-fire) is an operator-SIGNED authority object cryptographically
    bound to {engagement, target, bug_class, witness_kinds_present, required_N, action}. It authorizes
    THIS action ONLY: a different target / action / bug-class, or a different re-fired witness set,
    fails the binding, so the ack never generalises. The operator NEVER promotes the finding to a FACT
    — the ack lifts the ACTION veto (mirroring how ``live_destructive_acknowledged`` lifts the
    live-destructive veto), and mints nothing. Verification reuses the shared ``vigil_core`` crypto
    (``verify_threshold`` over a governance trust root), domain-separated so this signature can never
    be replayed as any other signed artifact.

Import-clean across the two-env boundary: this module imports ``vigil_core`` (sovereign-safe) and the
engine-side ``veracity.witness_quorum`` — never ``vigil_integration`` / ``strix``. It is itself NOT
imported by ``authority.gate`` (only the callables it builds are injected), so the gate's decoupling
AST-invariant is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from vigil_core import (
    IntegrityError,
    Signature,
    TrustRoot,
    canonical_json,
    sign,
    verify_threshold,
)

from ..veracity.witness_quorum import QuorumOutcome, WitnessQuorumConfig, evaluate
from .models import ActionRequest

# Fresh domain tag: a PROCEED-BELOW-QUORUM acknowledgement signature can NEVER be replayed as a
# destruction authorization, an evidence certificate, an offense-gate open, or any other signed
# artifact. Distinct byte prefix ⇒ distinct signed-message space.
_WITNESS_ACK_DOMAIN = b"vigil-proceed-below-witness-quorum-v1\x00"


class WitnessQuorumVerdict:
    """The structural shape the gate reads back from an injected witness-quorum evaluator — satisfied
    by :class:`~framework.v2.veracity.witness_quorum.QuorumOutcome`. Named here only for documentation;
    the gate uses its own ``Protocol``. The gate acts on ``applicable`` and ``ok`` ONLY (so it can only
    ever WITHHOLD), and uses ``reason`` for the denial message."""

    applicable: bool
    ok: bool
    required: int
    got: int
    kinds: "tuple[str, ...]"
    reason: str


def witness_quorum_predicate(
    config: "WitnessQuorumConfig | None",
    *,
    verifier: Any = None,
) -> Callable[[ActionRequest], QuorumOutcome]:
    """Build the read-only quorum evaluator the gate consults for ONE action.

    RE-EXECUTES the deterministic oracle over ``request.witness_context`` under ``request.bug_class``
    (via :func:`veracity.witness_quorum.evaluate`) and reports whether >= N DISTINCT oracle-witness
    kinds re-fire. An action with ``witness_context is None`` is INAPPLICABLE (the quorum is a no-op —
    the action is not tied to a finding), so the gate stays byte-identical for it. Pure and
    deterministic (the oracle layer is); mints nothing; can only WITHHOLD. Injected into
    ``authorize_action(..., witness_quorum_fn=...)``; absent it the gate never evaluates the quorum."""

    def predict(request: ActionRequest) -> QuorumOutcome:
        ctx = getattr(request, "witness_context", None)
        bug_class = getattr(request, "bug_class", "") or ""
        if ctx is None:
            # The action is not tied to a finding's retained evidence ⇒ the quorum does not apply, so
            # the gate is a no-op for it (one half of the "policy+context" activation condition).
            return QuorumOutcome(
                applicable=False, required=0, got=0, kinds=(), ok=True,
                reason="no witness_context — action not tied to a finding; witness quorum not enforced")
        return evaluate(ctx, bug_class=bug_class, config=config, verifier=verifier)

    return predict


@dataclass(frozen=True)
class ProceedBelowQuorumAck:
    """What the operator signs to PROCEED-BELOW-QUORUM for ONE action. Bound to the exact action and
    the exact under-quorum witness set, so it authorises THIS action only and never generalises.

    * ``engagement_slug`` / ``target`` / ``action_kind`` — WHICH action.
    * ``bug_class`` — the finding class the quorum was enforced for.
    * ``witness_kinds_present`` — the DISTINCT oracle-witness kinds that DID re-fire (the under-quorum
      set the operator is explicitly accepting). Sorted. If the retained evidence later re-fires a
      DIFFERENT set, the binding fails (the ack cannot be reused across changed evidence).
    * ``required_n`` — the N the quorum required (so an ack accepting "1 of 2" never covers a run that
      required 3).
    """

    engagement_slug: str
    target: str
    bug_class: str
    witness_kinds_present: "tuple[str, ...]"
    required_n: int
    action_kind: str = "offense"

    def signing_payload(self) -> dict:
        return {
            "engagement_slug": self.engagement_slug,
            "target": self.target,
            "bug_class": self.bug_class,
            "witness_kinds_present": list(self.witness_kinds_present),
            "required_n": int(self.required_n),
            "action_kind": self.action_kind,
        }


@dataclass(frozen=True)
class SignedProceedBelowQuorumAck:
    """A :class:`ProceedBelowQuorumAck` plus the quorum of operator/governance signatures over it."""

    ack: ProceedBelowQuorumAck
    signatures: "tuple[Signature, ...]" = ()


def ack_signing_bytes(ack: ProceedBelowQuorumAck) -> bytes:
    """Domain-separated canonical bytes the operator signs. The SAME bytes are re-derived at the gate,
    so a signature binds to exactly these fields and nothing else."""
    return _WITNESS_ACK_DOMAIN + canonical_json(ack.signing_payload())


def sign_ack(
    ack: ProceedBelowQuorumAck, signers: "Iterable[tuple[str, str]]"
) -> SignedProceedBelowQuorumAck:
    """Provisioning / test helper: each ``(key_id, private_key_b64)`` signs the ack."""
    msg = ack_signing_bytes(ack)
    sigs = tuple(Signature(key_id=kid, signature_b64=sign(priv, msg)) for kid, priv in signers)
    return SignedProceedBelowQuorumAck(ack=ack, signatures=sigs)


def _binding_reason(
    ack: ProceedBelowQuorumAck,
    *,
    engagement_slug: str,
    request: ActionRequest,
    outcome: "WitnessQuorumVerdict | QuorumOutcome",
) -> str:
    """Return "" if ``ack`` binds to EXACTLY this action + this under-quorum witness set, else a deny
    reason. Fail-closed on any divergence — an ack for a different target / action / class, or for a
    different re-fired witness set / required N, does NOT cover this action."""
    if ack.engagement_slug != engagement_slug:
        return (f"ack engagement {ack.engagement_slug!r} does not match the gate {engagement_slug!r}")
    if ack.target != request.target:
        return f"ack target {ack.target!r} does not match the action target {request.target!r}"
    if ack.bug_class != (request.bug_class or ""):
        return f"ack bug_class {ack.bug_class!r} does not match the action bug_class {request.bug_class!r}"
    if ack.action_kind != request.action_kind:
        return (f"ack action_kind {ack.action_kind!r} does not match the action "
                f"{request.action_kind!r}")
    if tuple(ack.witness_kinds_present) != tuple(getattr(outcome, "kinds", ())):
        return ("ack witness_kinds_present does not match the re-fired witness set "
                f"({list(ack.witness_kinds_present)} != {list(getattr(outcome, 'kinds', ()))}) — "
                "the retained evidence re-fires a different set; the ack cannot be reused")
    if int(ack.required_n) != int(getattr(outcome, "required", -1)):
        return (f"ack required_n {ack.required_n} does not match the enforced quorum "
                f"{getattr(outcome, 'required', None)}")
    return ""


def ack_authorizes(
    signed: "SignedProceedBelowQuorumAck | None",
    *,
    engagement_slug: str,
    request: ActionRequest,
    outcome: "WitnessQuorumVerdict | QuorumOutcome",
    trust_root: TrustRoot,
) -> "tuple[bool, str]":
    """Fail-closed decision on whether a valid PROCEED-BELOW-QUORUM ack authorises THIS action to
    proceed below the quorum. First failure wins; any error (malformed material, bad signature) is a
    DENY, never an exception a caller might swallow into an allow. Returns ``(ok, reason)``.

    The ack NEVER promotes the finding to a FACT: a True here authorises the ACTION only, and this
    function mints nothing (no FACT, cert, or spine row) — it returns a boolean verdict. The signature
    quorum is verified over the domain-separated action-bound bytes against the GOVERNANCE trust root,
    so the model cannot forge it (it holds no governance key)."""
    if type(signed) is not SignedProceedBelowQuorumAck:
        return False, "no (or malformed) PROCEED-BELOW-QUORUM acknowledgement"
    ack = signed.ack
    if type(ack) is not ProceedBelowQuorumAck:
        return False, "malformed acknowledgement body"
    if type(signed.signatures) is not tuple or not all(type(s) is Signature for s in signed.signatures):
        return False, "malformed signature list"
    reason = _binding_reason(ack, engagement_slug=engagement_slug, request=request, outcome=outcome)
    if reason:
        return False, reason
    try:
        result = verify_threshold(ack_signing_bytes(ack), list(signed.signatures), trust_root)
    except (IntegrityError, TypeError, ValueError):
        return False, "malformed signature/key material — fail closed"
    if not result.satisfied:
        return False, f"ack threshold not met ({result.reason})"
    return True, "PROCEED-BELOW-QUORUM authorised for this action only"


def proceed_below_quorum_checker(
    signed: "SignedProceedBelowQuorumAck | None",
    *,
    engagement_slug: str,
    trust_root: TrustRoot,
) -> Callable[[ActionRequest, "WitnessQuorumVerdict"], bool]:
    """Build the ``witness_quorum_ack`` callable the gate consults when the quorum would block.

    Returns ``gate_ack(request, verdict) -> bool`` — True iff a valid operator ack is bound to THIS
    action and the exact under-quorum witness set the verdict reports. Injected into
    ``authorize_action(..., witness_quorum_ack=...)``. Absent it the gate simply denies an
    under-quorum action (the ack is opt-in; its absence is never an allow)."""

    def gate_ack(request: ActionRequest, verdict: "WitnessQuorumVerdict") -> bool:
        ok, _reason = ack_authorizes(
            signed, engagement_slug=engagement_slug, request=request, outcome=verdict,
            trust_root=trust_root)
        return ok

    return gate_ack
