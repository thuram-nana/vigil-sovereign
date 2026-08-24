"""W13-8 (#501) property 3 — challenge-response attestation rejects a REPLAY, and never blocks an operation.

Runs in the SOVEREIGN leg of the required "integration two-env boundary (P5)" CI job. Pins, per #501:

  * REPLAY REJECTION: a valid signed response to a FRESH nonce is VERIFIED; presenting that same
    ``(challenge, response)`` a SECOND time is REJECTED_REPLAY (the nonce is single-use).
  * A FAILED attestation NEVER blocks an operation: ``run_operation`` runs the operation regardless of the
    attestor. Two crossed cases prove independence — op succeeds while the attestor is dark (completed=True),
    and op fails while the attestor is VERIFIED (completed=False). So there is no per-operation dependency on
    a vendor service.
  * NEGATIVE CONTROLS (same run): a FRESH nonce is VERIFIED (so REJECTED_REPLAY is a real difference, not a
    verifier that always rejects); a forged signature -> REJECTED_SIGNATURE; an untrusted key ->
    REJECTED_SIGNATURE; malformed input -> REJECTED_MALFORMED.
  * STRUCTURAL: the operation-authorization path (``conjunctive_gate`` / ``vigil_core.gate`` /
    ``sovereign_bridge``) does not import ``sovereign_deploy.attest`` — attestation is provably off that path.

FAILS WITHOUT THE FIX: imports ``vigil_integration.sovereign_deploy.attest`` at module scope.
"""
from __future__ import annotations

import ast
from pathlib import Path

from vigil_core.crypto import generate_keypair, sign
from vigil_core.models import Signature
from vigil_integration.sovereign_deploy.attest import (
    AttestationOutcome,
    AttestationResponse,
    ReplayGuard,
    issue_challenge,
    respond,
    run_operation,
    verify_attestation,
)

_REPO = Path(__file__).resolve().parents[2]


def _deployment_signer(key_id: str = "deploy-key-1"):
    kp = generate_keypair()

    def signer(msg: bytes) -> Signature:
        return Signature(key_id=key_id, signature_b64=sign(kp.private_key_b64, msg))

    def resolve(kid: str):
        return kp.public_key_b64 if kid == key_id else None

    return signer, resolve, kp


# ---------------------------------------------------------------------------------------------------------
# REPLAY REJECTION (+ its fresh-accept negative control)
# ---------------------------------------------------------------------------------------------------------
def test_fresh_challenge_is_verified_then_a_replay_is_rejected():
    signer, resolve, _ = _deployment_signer()
    guard = ReplayGuard()
    ch = issue_challenge(nonce_factory=lambda: "n" * 32)
    resp = respond(ch, signer)

    # fresh -> VERIFIED (the negative control: rejection is NOT a constant)
    assert verify_attestation(ch, resp, resolve_key=resolve, replay_guard=guard) is AttestationOutcome.VERIFIED
    # the SAME valid response replayed -> REJECTED_REPLAY (the property)
    assert verify_attestation(ch, resp, resolve_key=resolve, replay_guard=guard) is AttestationOutcome.REJECTED_REPLAY


def test_a_second_distinct_challenge_is_independently_verified():
    # a genuinely new nonce is accepted even after another was consumed — the guard rejects REPLAYS, not
    # every-second-request.
    signer, resolve, _ = _deployment_signer()
    guard = ReplayGuard()
    for tok in ("a" * 32, "b" * 32, "c" * 32):
        ch = issue_challenge(nonce_factory=lambda t=tok: t)
        assert verify_attestation(ch, respond(ch, signer), resolve_key=resolve,
                                  replay_guard=guard) is AttestationOutcome.VERIFIED


# ---------------------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS on the verifier — a forged / untrusted / malformed attestation never VERIFIES.
# ---------------------------------------------------------------------------------------------------------
def test_negative_control_forged_signature_is_rejected():
    signer, resolve, _ = _deployment_signer()
    ch = issue_challenge(nonce_factory=lambda: "n" * 32)
    forged = AttestationResponse(nonce=ch.nonce, purpose=ch.purpose,
                                 signature=Signature(key_id="deploy-key-1", signature_b64="Zm9vYmFy"))
    assert verify_attestation(ch, forged, resolve_key=resolve,
                              replay_guard=ReplayGuard()) is AttestationOutcome.REJECTED_SIGNATURE


def test_negative_control_untrusted_key_is_rejected():
    signer, _resolve, _ = _deployment_signer(key_id="deploy-key-1")
    ch = issue_challenge(nonce_factory=lambda: "n" * 32)
    resp = respond(ch, signer)
    # a resolver that trusts NOBODY -> the (otherwise valid) signature is from an untrusted key
    assert verify_attestation(ch, resp, resolve_key=lambda _k: None,
                              replay_guard=ReplayGuard()) is AttestationOutcome.REJECTED_SIGNATURE


def test_negative_control_malformed_and_mismatched_inputs_are_rejected():
    signer, resolve, _ = _deployment_signer()
    ch = issue_challenge(nonce_factory=lambda: "n" * 32)
    resp = respond(ch, signer)
    g = ReplayGuard()
    assert verify_attestation(None, resp, resolve_key=resolve, replay_guard=g) is AttestationOutcome.REJECTED_MALFORMED
    assert verify_attestation(ch, None, resolve_key=resolve, replay_guard=g) is AttestationOutcome.REJECTED_MALFORMED
    # nonce mismatch (response for a different challenge)
    other = issue_challenge(nonce_factory=lambda: "m" * 32)
    assert verify_attestation(other, resp, resolve_key=resolve,
                              replay_guard=g) is AttestationOutcome.REJECTED_MALFORMED
    # a low-entropy nonce is refused even before signature check
    weak = issue_challenge(nonce_factory=lambda: "short")
    assert verify_attestation(weak, respond(weak, signer), resolve_key=resolve,
                              replay_guard=g) is AttestationOutcome.REJECTED_MALFORMED


# ---------------------------------------------------------------------------------------------------------
# FAIL-OPEN — attestation is advisory; it never blocks an operation (and never rescues one).
# ---------------------------------------------------------------------------------------------------------
def test_dark_attestor_does_not_block_the_operation():
    def op():
        return "work completed"

    def dark():
        raise ConnectionError("vendor attestation service unreachable")

    r = run_operation(op, attestor=dark)
    assert r.completed is True and r.value == "work completed"        # op ran despite attestation failure
    assert r.attestation is AttestationOutcome.UNREACHABLE            # and we KNOW attestation was attempted+failed
    assert "ConnectionError" in r.attestation_error


def test_rejected_attestation_does_not_block_the_operation():
    r = run_operation(lambda: 42, attestor=lambda: AttestationOutcome.REJECTED_REPLAY)
    assert r.completed is True and r.value == 42                      # even an explicit REJECT cannot block


def test_negative_control_verified_attestation_cannot_rescue_a_failing_operation():
    # The crossed control: op fails, attestation VERIFIED -> completed=False. Proves `completed` tracks the
    # OPERATION, not the attestation (so run_operation is not just "always succeed").
    def failing_op():
        raise RuntimeError("the operation itself failed")

    r = run_operation(failing_op, attestor=lambda: AttestationOutcome.VERIFIED)
    assert r.completed is False
    assert r.attestation is AttestationOutcome.VERIFIED
    assert "RuntimeError" in r.operation_error


def test_no_attestor_still_runs_the_operation():
    r = run_operation(lambda: "ok")  # attestor=None
    assert r.completed is True and r.value == "ok"
    assert r.attestation is AttestationOutcome.UNREACHABLE


# ---------------------------------------------------------------------------------------------------------
# STRUCTURAL — the per-operation authorization path does not depend on attestation.
# ---------------------------------------------------------------------------------------------------------
def test_operation_authorization_path_does_not_import_attestation():
    """The real operation-authorization modules must not import the deployment-attestation module, so a
    vendor attestation can never become a per-operation dependency by wiring."""
    gate_path_files = [
        _REPO / "integration" / "vigil_integration" / "conjunctive_gate.py",
        _REPO / "integration" / "vigil_integration" / "sovereign_bridge.py",
        _REPO / "packages" / "core" / "vigil_core" / "vigil_core" / "gate.py",
    ]
    scanned = 0
    for f in gate_path_files:
        if not f.is_file():
            continue
        scanned += 1
        src = f.read_text(encoding="utf-8")
        assert "sovereign_deploy.attest" not in src and "sovereign_deploy import attest" not in src, (
            f"{f.name} imports the deployment-attestation module — attestation must stay off the "
            "per-operation authorization path"
        )
    assert scanned >= 2, f"expected to scan the gate path modules, scanned {scanned}"
