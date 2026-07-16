"""aegis.rampart — the proof-carrying edge: a real signed PCF certificate for every inline BLOCK.

FORGE RAMPART, slice 1 (`docs/FORGE-RAMPART-CHARTER.md`). RAMPART's differentiator is not that it blocks —
every WAF blocks — it is that **every block is a re-runnable certificate**. The AEGIS gateway
(`aegis/gateway.py::AegisGatewayHandler`) already blocks ONLY on a fired request-side oracle and already
retains the offline-re-runnable oracle evidence as a ``CertRef``. This module upgrades that block's evidence
to a real, signed, third-party-re-verifiable **PCF v0.1 certificate** over the SAME real evidence layer
Phase A wired findings onto (`evidence/pcf.py`) — retiring the RAMPART prototype's standalone PCF-verify
reimpl as the reference the real layer now supersedes.

This is a thin, reuse-first seam: no new oracle, no new evidence primitive, no target traffic. It maps the
block's retained `oracle_context` (the normalized-request evidence the oracle judged) into a signed PCF
certificate whose five offline checks (schema+vocabulary, m-of-n signature, evidence-digest integrity,
oracle RE-FIRE, claim-grounded) a third party can re-run with no trust in RAMPART. Off the
scan/engage/benchmark gate path (lazy imports), so `make gate` stays byte-identical.

Invariants (inherited): a certificate exists ONLY for a genuinely-fired oracle (a benign, ALLOWED request
produces no block and no certificate); the certificate re-verifies by RE-FIRING the oracle over the retained
context (prove-by-re-execution), never by trusting RAMPART; fail-closed on tamper; determinism (no
wall-clock/RNG in the signed bytes — the caller supplies ``seq``).
"""

from __future__ import annotations

from typing import Any

from .models import CertRef, Verdict


def certref_of(verdict: Verdict) -> CertRef | None:
    """The block's ``CertRef`` iff the verdict is a genuine BLOCK (``decision == "confirmed"`` — a fired
    oracle with retained evidence). A ``lead``/``clear`` verdict has no certificate and yields ``None``:
    RAMPART mints a proof ONLY for what it actually blocked, never for a belief or a benign pass."""
    if not isinstance(verdict, Verdict):
        return None
    if verdict.decision != "confirmed":
        return None
    return verdict.certificate


def block_pcf_certificate(block: "Verdict | CertRef", *, signers: list[tuple[str, str]],
                          seq: int, collected_by: str = "aegis/rampart") -> dict[str, Any] | None:
    """Mint a real signed **PCF v0.1** certificate for an inline BLOCK. ``block`` is either the blocking
    ``Verdict`` or its ``CertRef``. Returns the PCF wire dict, or ``None`` when there is nothing to certify
    (a non-block verdict / no certificate) — RAMPART never fabricates a proof for an unblocked request.

    The certificate carries the fired oracle's bug class + canonical kind, ``verdict.fired = true``, and the
    retained ``oracle_context`` as the authenticated evidence, so a third party re-verifies it offline by
    recomputing the evidence digest and RE-FIRING the same request-side oracle. Pure over its inputs +
    ``seq``; no wall-clock, no RNG."""
    ref = block if isinstance(block, CertRef) else certref_of(block)
    if ref is None:
        return None
    # total over `seq` too: an invalid sequence yields NO certificate (fail-closed), never an exception —
    # `seq` is an internal monotonic counter, never adversary-controlled, but the seam promises totality.
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return None
    # lazy import: keep evidence/PCF off the gate path
    from ..evidence.certify import build_certificate, sign_certificate
    from ..evidence.pcf import to_pcf
    finding = {
        "check_id": ref.cert_id,
        "bug_class": ref.bug_class,
        "confirmed_by": ref.confirmed_by,
        "confidence": ref.confidence,
        "oracle_context": dict(ref.oracle_context),
    }
    signed = sign_certificate(build_certificate(finding, seq=seq), signers)
    return to_pcf(signed, oracle_context=dict(ref.oracle_context))


def verify_block_pcf(pcf: dict[str, Any], trust_root: Any, *, evidence_root: str | None = None):
    """Re-verify a block's PCF certificate OFFLINE (the five fail-closed PCF steps), delegating entirely to
    the real ``evidence/pcf.py`` verifier — schema+vocabulary, m-of-n signature, evidence-digest integrity,
    oracle RE-FIRE over the retained request context, and claim-grounded. Fails closed on any tamper class
    and when no trust root is provisioned. No trust in RAMPART is required to establish the block was
    justified."""
    from ..evidence.pcf import verify_pcf
    return verify_pcf(pcf, trust_root, evidence_root=evidence_root)
