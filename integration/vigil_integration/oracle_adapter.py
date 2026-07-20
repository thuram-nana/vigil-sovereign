"""
oracle_adapter — the no-hallucinated-findings pipeline (VIGIL P9, the headline differentiator).

An LLM agent (Strix) PROPOSES a finding; it becomes a signed FACT only when CRUCIBLE's
deterministic oracle CONFIRMS it and the finding's class is one we actually have an oracle for.
This adapter is the bridge: it drives the existing CRUCIBLE authority (it does NOT reinvent
confirmation), and enforces the honesty invariant that is the whole point of the system.

Flow for one proposed finding (which carries its retained ``oracle_context`` — the baseline/mutated
responses, probe rounds, timing samples, OOB hits that a real target produced):

  1. ``confirm_finding(finding, oracle_context)`` re-runs the pure deterministic oracle over the
     retained context. It returns ``None`` unless an oracle actually FIRED at ≥ high-confidence —
     there is no assertion-only path, so an LLM's say-so never confirms anything.
  2. Honesty invariant: a signed FACT additionally requires the confirmed ``bug_class`` to be a
     KNOWN oracle-mapped class (``is_known_bug_class`` → in ``BUG_CLASS_ORACLES``). A fire from a
     generic oracle on an unmapped class stays a **labelled lead**, never a signed fact — claiming
     otherwise would be the very hallucination this system exists to kill.
  3. On a confirmed, oracle-mapped finding, mint a proof-carrying ``EvidenceCertificate`` (binding
     the ``oracle_context_digest``) and sign it with the governance authorisers (m-of-n). The
     ``SignedEvidence`` is what later crosses the P5 inert seam to the sovereign spine (P10).

Anything not confirmed, or confirmed-but-unmapped, is returned as a ``lead`` with the reason —
retained, honest, replayable, but never asserted as a machine-verified fact.

Offense-side: it drives ``framework.v2`` (CRUCIBLE). The ``framework`` imports are LAZY so this
module stays import-clean and does not break the sovereign env's offense-free boundary (which
never calls it). The live re-drive of a scope-gated baseline+probe pair (vs. re-running the
retained context) is a documented refinement for a later slice — it needs a live target + the
egress gate, the same deferral shape as P8's live-fire.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AdapterResult:
    status: str            # "fact" (oracle-confirmed + oracle-mapped + signed) | "lead"
    reason: str
    bug_class: str
    finding_ref: str
    signed: Any = None     # a CRUCIBLE SignedEvidence when status == "fact", else None
    confirmed_by: str = ""  # the oracle kind that fired (empty for an unconfirmed lead)
    confidence: float = 0.0

    @property
    def is_fact(self) -> bool:
        return self.status == "fact"


def _finding_ref(finding: dict) -> str:
    return str(
        finding.get("check_id") or finding.get("finding_slug")
        or finding.get("bug_class") or "finding"
    )


def confirm_and_certify(
    finding: dict,
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    seq: int = 0,
    verifier: Any = None,
) -> AdapterResult:
    """Drive CRUCIBLE's oracle over ``finding['oracle_context']`` and, on a confirmed + oracle-
    mapped finding, mint + sign a proof-carrying certificate. ``signers`` = [(key_id, priv_b64)]
    (governance authorisers). Returns a ``fact`` (with SignedEvidence) or a labelled ``lead``.
    """
    # Lazy CRUCIBLE imports — offense-side only; keeps the module import-clean for the sovereign env.
    from framework.v2.evidence.certify import build_certificate, sign_certificate
    from framework.v2.verify.confirmation import confirm_finding
    from framework.v2.verify.verifier import is_known_bug_class, normalize_bug_class

    oracle_context = finding.get("oracle_context") or {}
    bug_class = normalize_bug_class(str(finding.get("bug_class", "")))

    # 1. deterministic confirmation — None unless an oracle actually fired at high confidence.
    confirmed = confirm_finding(finding, oracle_context, verifier)
    if confirmed is None:
        return AdapterResult(
            "lead", "oracle did not fire — the retained context does not reproduce the finding",
            bug_class, _finding_ref(finding),
        )

    # 2. honesty invariant — a signed FACT requires a known oracle-mapped class.
    confirmed_class = normalize_bug_class(str(confirmed.bug_class or bug_class))
    if not is_known_bug_class(confirmed_class):
        return AdapterResult(
            "lead",
            f"confirmed by {confirmed.confirmed_by} but {confirmed_class!r} has no deterministic "
            f"oracle mapping — retained as a labelled lead, not a signed fact",
            confirmed_class, _finding_ref(finding),
            confirmed_by=str(confirmed.confirmed_by), confidence=float(confirmed.confidence),
        )

    # 3. mint + sign the proof-carrying certificate over the exact confirmed evidence.
    enriched = {
        **finding,
        "bug_class": confirmed_class,
        "confirmed_by": str(confirmed.confirmed_by),
        "confidence": float(confirmed.confidence),
        "oracle_context": oracle_context,
    }
    cert = build_certificate(enriched, engagement_slug=engagement_slug, seq=seq)
    signed = sign_certificate(cert, signers)
    return AdapterResult(
        "fact",
        f"oracle-confirmed by {confirmed.confirmed_by} and signed (proof-carrying certificate)",
        confirmed_class, cert.finding_ref, signed=signed,
        confirmed_by=str(confirmed.confirmed_by), confidence=float(confirmed.confidence),
    )
