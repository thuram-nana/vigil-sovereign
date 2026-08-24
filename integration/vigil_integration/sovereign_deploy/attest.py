"""
sovereign_deploy.attest — challenge-response attestation that rejects a REPLAY and never blocks an op (W13-8).

Property 3 of the sovereign / air-gapped deployment slice (#501), in two halves:

  1. **Integrity.** An out-of-band auditor/vendor may CHALLENGE a deployment to prove its identity: it issues
     a FRESH random nonce, the deployment SIGNS it with its own key, and the verifier accepts only a valid
     signature over a nonce it has not seen before. A REPLAYED challenge — a captured, cryptographically
     valid ``(nonce, signature)`` pair presented a second time — is REJECTED (``REJECTED_REPLAY``), because
     the nonce is single-use. This reuses the challenge/nonce discipline of ``challenge_oracle`` (a fresh
     ``secrets`` token, so a captured response cannot satisfy a new challenge) and the reviewed
     ``vigil_core.crypto`` Ed25519 verification.

  2. **Sovereignty (the load-bearing half).** A FAILED, REJECTED, or UNREACHABLE attestation NEVER blocks an
     individual operation. Attestation is advisory, OFF the critical path: :func:`run_operation` runs the
     operation UNCONDITIONALLY and reports the attestation outcome beside the result, but the operation's
     execution does not read that outcome. There is therefore no per-operation dependency on a vendor
     service — a vendor that goes dark, or actively returns "rejected", cannot stop the deployment doing its
     work. (Contrast the operator's OWN local usage-attestation ledger, ``vigil_integration.attestation``,
     which is deliberately fail-CLOSED — that is the customer's own control, not a vendor's.)

FAIL-CLOSED on the verify side / FAIL-OPEN on the operate side — on purpose. ``verify_attestation`` is total
and never mints a false VERIFIED (malformed input, an untrusted key, a bad signature, or a reused nonce all
resolve to a REJECT/UNREACHABLE outcome). ``run_operation`` is total and never lets an attestation failure
propagate into the operation's success.

Import-clean (FATAL-2): stdlib + ``vigil_core`` only.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from vigil_core.canonical import canonical_json
from vigil_core.crypto import verify_one
from vigil_core.models import Signature

__all__ = [
    "AttestationChallenge",
    "AttestationResponse",
    "AttestationOutcome",
    "ReplayGuard",
    "SignerFn",
    "ResolveKeyFn",
    "issue_challenge",
    "respond",
    "verify_attestation",
    "OperationResult",
    "run_operation",
]

#: Domain tag over which an attestation nonce is signed — distinct from every other signing seam so a
#: signature minted here can never be replayed as (say) a build-manifest or spine-head signature.
_DOMAIN = b"vigil.w13-8.deployment-attestation.v1\x00"
_PURPOSE = "vigil-deployment-attestation-v1"
_MIN_NONCE_LEN = 16  # >= 64 bits; reject a degenerate low-entropy nonce even from a weak injected factory

# signer(message: bytes) -> Signature (key_id == the deployment's attestation-key fingerprint).
SignerFn = Callable[[bytes], Signature]
# resolve_key(key_id: str) -> the trusted public_key_b64 for that key_id, or None if untrusted.
ResolveKeyFn = Callable[[str], Optional[str]]


class AttestationOutcome(str, Enum):
    """The verdict of :func:`verify_attestation`. Only ``VERIFIED`` is an accept; every other value is a
    fail-closed reject/none, and NONE of them may block an operation (that is ``run_operation``'s job)."""

    VERIFIED = "verified"
    REJECTED_REPLAY = "rejected_replay"          # valid signature, but the nonce was already consumed
    REJECTED_SIGNATURE = "rejected_signature"    # untrusted key or an invalid signature
    REJECTED_MALFORMED = "rejected_malformed"    # missing/typed-wrong fields, nonce/purpose mismatch
    UNREACHABLE = "unreachable"                  # the attestation could not be performed at all


@dataclass(frozen=True)
class AttestationChallenge:
    """A fresh, single-use challenge. ``nonce`` is unpredictable (``secrets`` by default); ``purpose`` domain-
    separates deployment attestation from any other challenge use."""

    nonce: str
    purpose: str = _PURPOSE


@dataclass(frozen=True)
class AttestationResponse:
    """A deployment's signed answer to a challenge: the echoed ``nonce``/``purpose`` and an Ed25519
    ``signature`` over the domain-tagged signing bytes of that pair."""

    nonce: str
    purpose: str
    signature: Signature


def _signing_bytes(nonce: str, purpose: str) -> bytes:
    """The exact bytes signed and verified — a pure function of ``(nonce, purpose)``, canonicalised so mint
    and verify derive byte-identical input."""
    return _DOMAIN + canonical_json({"nonce": nonce, "purpose": purpose})


def _valid_nonce(nonce: object) -> bool:
    return isinstance(nonce, str) and len(nonce) >= _MIN_NONCE_LEN


def issue_challenge(*, nonce_factory: Callable[[], str] = lambda: secrets.token_hex(16)) -> AttestationChallenge:
    """Issue a fresh challenge. ``nonce_factory`` is injectable for deterministic tests; the default is 128
    bits of ``secrets`` entropy, so a captured response to an old challenge cannot satisfy a new one."""
    return AttestationChallenge(nonce=nonce_factory(), purpose=_PURPOSE)


def respond(challenge: AttestationChallenge, signer: SignerFn) -> AttestationResponse:
    """Sign a challenge with the deployment's key. ``signer`` returns a ``Signature`` whose ``key_id`` the
    verifier must trust (e.g. ``vigil_integration.attestation.operator_signer``). Reuses deterministic
    Ed25519 signing — no wall-clock, no extra RNG beyond the nonce the challenger already chose."""
    sig = signer(_signing_bytes(challenge.nonce, challenge.purpose))
    return AttestationResponse(nonce=challenge.nonce, purpose=challenge.purpose, signature=sig)


class ReplayGuard:
    """Single-use nonce ledger. A nonce may be consumed exactly once; a second presentation is a replay.
    In-memory by default (an auditor keeps it for the life of a challenge round); inject a persisted set for
    durability. Total and thread-naive (the caller serialises verification)."""

    def __init__(self, seen: "Optional[set[str]]" = None) -> None:
        self._seen: "set[str]" = set(seen) if seen else set()

    def is_fresh(self, nonce: str) -> bool:
        return nonce not in self._seen

    def record(self, nonce: str) -> None:
        self._seen.add(nonce)

    def check_and_record(self, nonce: str) -> bool:
        """True (and records it) iff ``nonce`` is fresh; False if it was already consumed (a replay)."""
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        return True


def verify_attestation(
    challenge: Any,
    response: Any,
    *,
    resolve_key: ResolveKeyFn,
    replay_guard: ReplayGuard,
) -> AttestationOutcome:
    """Verify a challenge-response, TOTAL and fail-closed. The outcome is:

      * ``REJECTED_MALFORMED`` — a non-model input, or a response whose ``nonce``/``purpose`` does not match
        the challenge, or a degenerate/low-entropy nonce;
      * ``REJECTED_SIGNATURE`` — the response's ``key_id`` is untrusted (``resolve_key`` returns None) or the
        Ed25519 signature does not verify;
      * ``REJECTED_REPLAY`` — the signature is VALID but the nonce was already consumed (the replay case);
      * ``VERIFIED`` — a valid signature over a FRESH nonce (the nonce is recorded as consumed).

    Order matters: signature is checked BEFORE the replay ledger, so a genuine replay (valid signature over a
    seen nonce) is labelled ``REJECTED_REPLAY``, while a forged signature is ``REJECTED_SIGNATURE`` whether or
    not the nonce was seen. Never raises; never records a nonce it did not accept."""
    if not isinstance(challenge, AttestationChallenge) or not isinstance(response, AttestationResponse):
        return AttestationOutcome.REJECTED_MALFORMED
    if not isinstance(response.signature, Signature):
        return AttestationOutcome.REJECTED_MALFORMED
    if response.nonce != challenge.nonce or response.purpose != challenge.purpose:
        return AttestationOutcome.REJECTED_MALFORMED
    if not _valid_nonce(challenge.nonce):
        return AttestationOutcome.REJECTED_MALFORMED

    try:
        pub = resolve_key(response.signature.key_id)
    except Exception:  # noqa: BLE001 — a misbehaving resolver is treated as "untrusted key", never a crash
        pub = None
    if not (isinstance(pub, str) and pub):
        return AttestationOutcome.REJECTED_SIGNATURE

    try:
        ok = verify_one(pub, _signing_bytes(response.nonce, response.purpose), response.signature.signature_b64)
    except Exception:  # noqa: BLE001 — malformed signature/key bytes → reject, never a false VERIFIED
        ok = False
    if not ok:
        return AttestationOutcome.REJECTED_SIGNATURE

    # The signature is genuine. It is a VERIFIED attestation only if the nonce has not been used before.
    if not replay_guard.check_and_record(challenge.nonce):
        return AttestationOutcome.REJECTED_REPLAY
    return AttestationOutcome.VERIFIED


# ── sovereignty: attestation is advisory and NEVER on the operation's critical path ─────────────────────


@dataclass(frozen=True)
class OperationResult:
    """The outcome of running an operation under (advisory) attestation. ``completed`` reflects the
    OPERATION alone; ``attestation`` is recorded beside it but never gates it. The two are independent —
    ``completed`` can be True with a failed attestation and False with a VERIFIED one."""

    completed: bool
    value: Any
    attestation: AttestationOutcome
    attestation_error: str = ""
    operation_error: str = ""


def run_operation(
    operation: Callable[[], Any],
    *,
    attestor: Optional[Callable[[], AttestationOutcome]] = None,
) -> OperationResult:
    """Run ``operation`` UNCONDITIONALLY and report it beside a best-effort attestation.

    The load-bearing invariant: the operation's execution does not read the attestation outcome, so a FAILED,
    REJECTED, or UNREACHABLE attestation cannot block it — there is no per-operation dependency on a vendor
    service. The ``attestor`` (a vendor/auditor-facing challenge-response) is called best-effort; if it
    raises, or returns a non-outcome, that degrades to ``UNREACHABLE`` and is recorded in
    ``attestation_error`` — never propagated into ``completed``. Conversely a VERIFIED attestation cannot
    rescue an operation that fails on its own: ``completed`` tracks the operation, full stop.

    Total: neither the attestor's failure nor the operation's own exception escapes; both are captured."""
    outcome = AttestationOutcome.UNREACHABLE
    att_err = ""
    if attestor is not None:
        try:
            res = attestor()
            outcome = res if isinstance(res, AttestationOutcome) else AttestationOutcome.UNREACHABLE
            if not isinstance(res, AttestationOutcome):
                att_err = f"attestor returned a non-outcome: {type(res).__name__}"
        except Exception as exc:  # noqa: BLE001 — a dark/erroring vendor attestor NEVER blocks the operation
            outcome = AttestationOutcome.UNREACHABLE
            att_err = f"{type(exc).__name__}: {exc}"

    # The operation runs regardless of `outcome`. `outcome` is not referenced in this branch — attestation
    # is not a gate.
    try:
        value = operation()
        return OperationResult(completed=True, value=value, attestation=outcome, attestation_error=att_err)
    except Exception as exc:  # noqa: BLE001 — the operation's OWN failure is reported; attestation is irrelevant
        return OperationResult(
            completed=False, value=None, attestation=outcome, attestation_error=att_err,
            operation_error=f"{type(exc).__name__}: {exc}",
        )
