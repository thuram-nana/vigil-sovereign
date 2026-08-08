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
  2b. Provenance gate (audit G4): a signed FACT ALSO requires the ``oracle_context`` to be REPRODUCED
     from a non-LLM channel (``provenance`` ∈ {``reproduced``, ``live_redrive``}). A context the model
     emitted (its ``extracted_info``, ``provenance="llm"`` — the default) stays a **labelled lead** even
     when the oracle fires, because a crafted-but-firing context is an LLM-influenced route to a FACT.
  3. On a confirmed, oracle-mapped, REPRODUCED finding, mint a proof-carrying ``EvidenceCertificate``
     (binding the ``oracle_context_digest``) and sign it with the governance authorisers (m-of-n). The
     ``SignedEvidence`` is what later crosses the P5 inert seam to the sovereign spine (P10).

Anything not confirmed, confirmed-but-unmapped, or confirmed-but-LLM-provenanced is returned as a
``lead`` with the reason — retained, honest, replayable, but never asserted as a machine-verified fact.

Offense-side: it drives ``framework.v2`` (CRUCIBLE). The ``framework`` imports are LAZY so this
module stays import-clean and does not break the sovereign env's offense-free boundary (which
never calls it). The live re-drive of a scope-gated baseline+probe pair (vs. re-running the
retained context) is a documented refinement for a later slice — it needs a live target + the
egress gate, the same deferral shape as P8's live-fire.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Outcome(str, Enum):
    """The typed adjudication outcome for one probe/tool result — the six distinct states VIGIL keeps
    separate (criterion 7), so a caller never conflates "the oracle proved a channel-confirmed negative"
    with "no oracle had a channel" with "the tool errored". Only POSITIVE is a signed FACT.

      POSITIVE     — an oracle fired at high confidence, the class is oracle-mapped, the context is
                     runner-owned/reproduced, and the certificate is signed (the sole FACT state).
      CLEAN        — an applicable oracle had an observable channel and CONCLUSIVELY did not fire
                     (a channel-confirmed negative — the coverage `clean` verdict).
      INCONCLUSIVE — an oracle ran but had no decisive channel (a one-sided non-signal); NEVER clean.
      UNSUPPORTED  — an oracle fired but VIGIL structurally cannot mint a FACT: the class has no oracle
                     mapping, or the context is not runner-owned/reproduced (LLM-provenanced). A LEAD.
      ERROR        — the tool/probe errored (timeout / spawn failure / crash). Set by the runner.
      SKIPPED      — not attempted (no capture channel for this class, budget/scope refusal). Set by the
                     runner.
    """
    POSITIVE = "positive"
    CLEAN = "clean"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    SKIPPED = "skipped"


# Provenance of the oracle_context — WHERE the evidence the oracle re-fires over came from. Only a
# context REPRODUCED from a non-LLM channel (the executor-captured raw tool output, or a live re-drive of
# the scope-gated target) may back a signed FACT; a context the LLM emitted (its ``extracted_info``) is a
# LEAD no matter how confidently the deterministic oracle fires over it — a crafted context that fires is
# exactly the LLM-influenced route to a FACT this gate exists to close (audit G4).
_REPRODUCED_PROVENANCE = frozenset({"reproduced", "live_redrive"})


@dataclass(frozen=True)
class AdapterResult:
    status: str            # "fact" (oracle-confirmed + oracle-mapped + reproduced + signed) | "lead"
    reason: str
    bug_class: str
    finding_ref: str
    signed: Any = None     # a CRUCIBLE SignedEvidence when status == "fact", else None
    confirmed_by: str = ""  # the oracle kind that fired (empty for an unconfirmed lead)
    confidence: float = 0.0
    outcome: str = ""      # the typed Outcome value (positive/clean/inconclusive/unsupported/error/skipped).
                           # `status` stays the authoritative FACT-vs-not flag; `outcome` refines the LEAD
                           # bucket into distinct states (criterion 7). Default "" only for legacy callers.

    @property
    def is_fact(self) -> bool:
        return self.status == "fact"


def _finding_ref(finding: dict) -> str:
    return str(
        finding.get("check_id") or finding.get("finding_slug")
        or finding.get("bug_class") or "finding"
    )


def _kind_str(kind: Any) -> str:
    """The oracle kind's canonical ``.value`` string. OracleKind is ``(str, Enum)``, NOT a
    ``StrEnum``, so ``str(kind)`` yields the repr ``'OracleKind.X'`` — which the CRUCIBLE
    reproduction / ``verify_certificate`` layer (it compares against ``kind.value``) rejects as
    tampered, and which ``_oracle_version`` cannot resolve. Always store the ``.value``."""
    return getattr(kind, "value", None) or str(kind)


def confirm_and_certify(
    finding: dict,
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    seq: int = 0,
    verifier: Any = None,
    provenance: str = "llm",
) -> AdapterResult:
    """Drive CRUCIBLE's oracle over ``finding['oracle_context']`` and, on a confirmed + oracle-mapped +
    REPRODUCED finding, mint + sign a proof-carrying certificate. ``signers`` = [(key_id, priv_b64)]
    (governance authorisers). Returns a ``fact`` (with SignedEvidence) or a labelled ``lead``.

    ``provenance`` (audit G4 — the sovereign anti-hallucination gate): WHERE the ``oracle_context`` came
    from. A signed FACT is minted ONLY when ``provenance`` is a non-LLM channel
    (``"reproduced"`` = built from the executor-captured raw tool output; ``"live_redrive"`` = re-driven
    against the scope-gated target). The DEFAULT ``"llm"`` — the context is the model's own
    ``extracted_info`` — is demoted to a LEAD even if the deterministic oracle fires, because a crafted
    context that fires is an LLM-influenced route to a FACT. Every caller that cannot prove reproduction
    from a non-LLM channel gets a LEAD (fail-closed); the deterministic oracle still runs, so the LEAD is
    honestly labelled with what fired.
    """
    if not signers:
        raise ValueError(
            "confirm_and_certify requires governance signers to mint a signed fact; it will not "
            "label an unsigned (zero-signature) certificate a 'fact' (fail-closed)."
        )
    # Lazy CRUCIBLE imports — offense-side only; keeps the module import-clean for the sovereign env.
    from framework.v2.evidence.certify import build_certificate, sign_certificate
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result
    from framework.v2.verify.verifier import OracleVerifier, is_known_bug_class, normalize_bug_class
    from framework.v2.scanner.engine import probe_verdict

    oracle_context = finding.get("oracle_context") or {}
    bug_class = normalize_bug_class(str(finding.get("bug_class", "")))

    # 1. deterministic adjudication. adjudicate_finding + confirmed_from_result is EXACTLY confirm_finding
    #    (same FACT decision, verified in confirmation.py), but it also retains the full VerificationResult
    #    so we can classify the NON-fired outcome as CLEAN (conclusive channel, did not fire) vs
    #    INCONCLUSIVE (no decisive channel) — the criterion-7 distinction confirm_finding discards.
    verifier = verifier or OracleVerifier()
    result = adjudicate_finding(finding, oracle_context, verifier)
    confirmed = confirmed_from_result(result, finding, verifier)
    if confirmed is None:
        verdict, _kinds = probe_verdict(result)   # "clean" | "inconclusive" (never "finding" here)
        oc = Outcome.CLEAN if verdict == "clean" else Outcome.INCONCLUSIVE
        reason = ("oracle CONCLUSIVELY did not fire over the retained context (channel-confirmed negative)"
                  if oc is Outcome.CLEAN else
                  "no applicable oracle had a decisive channel over the retained context (inconclusive)")
        return AdapterResult(
            "lead", reason, bug_class, _finding_ref(finding), outcome=oc.value,
        )

    # 2. honesty invariant — a signed FACT requires a known oracle-mapped class.
    confirmed_class = normalize_bug_class(str(confirmed.bug_class or bug_class))
    if not is_known_bug_class(confirmed_class):
        return AdapterResult(
            "lead",
            f"confirmed by {_kind_str(confirmed.confirmed_by)} but {confirmed_class!r} has no deterministic "
            f"oracle mapping — retained as a labelled lead, not a signed fact",
            confirmed_class, _finding_ref(finding),
            confirmed_by=_kind_str(confirmed.confirmed_by), confidence=float(confirmed.confidence),
            outcome=Outcome.UNSUPPORTED.value,
        )

    # 2b. sovereign anti-hallucination gate (audit G4) — a signed FACT requires the oracle_context to be
    #     REPRODUCED from a non-LLM channel. An LLM-provenanced context (the model's own extracted_info)
    #     that fires is retained as a labelled LEAD, never signed — a crafted-but-firing context must not
    #     mint a FACT. This mirrors the is_known_bug_class demotion above: demote BEFORE build/sign.
    if provenance not in _REPRODUCED_PROVENANCE:
        return AdapterResult(
            "lead",
            f"confirmed by {_kind_str(confirmed.confirmed_by)} but the oracle_context is LLM-provenanced "
            f"({provenance!r}) — a signed FACT requires reproduction from a non-LLM channel (executor-"
            f"captured raw output / live re-drive); retained as a labelled lead",
            confirmed_class, _finding_ref(finding),
            confirmed_by=_kind_str(confirmed.confirmed_by), confidence=float(confirmed.confidence),
            outcome=Outcome.UNSUPPORTED.value,
        )

    # 3. mint + sign the proof-carrying certificate over the exact confirmed evidence.
    enriched = {
        **finding,
        "bug_class": confirmed_class,
        "confirmed_by": _kind_str(confirmed.confirmed_by),
        "confidence": float(confirmed.confidence),
        "oracle_context": oracle_context,
    }
    cert = build_certificate(enriched, engagement_slug=engagement_slug, seq=seq)
    signed = sign_certificate(cert, signers)
    return AdapterResult(
        "fact",
        f"oracle-confirmed by {_kind_str(confirmed.confirmed_by)} and signed (proof-carrying certificate)",
        confirmed_class, cert.finding_ref, signed=signed,
        confirmed_by=_kind_str(confirmed.confirmed_by), confidence=float(confirmed.confidence),
        outcome=Outcome.POSITIVE.value,
    )


def certify_to_scitt(
    result: AdapterResult,
    signers: "list[tuple[str, str]]",
    *,
    author: str,
    timestamp: str,
    log: Any = None,
) -> Any:
    """Bridge a CONFIRMED :class:`AdapterResult` to the standards-native, offline-verifiable SCITT
    form of its proof-carrying certificate: an OpenVEX ``affected`` statement, DSSE-signed m-of-n and
    (with a ``log``) registered with an inclusion receipt. Only a FACT (oracle-confirmed + oracle-
    mapped + signed) is minted — a lead has no signed certificate, so it is refused fail-closed
    (claiming a lead is 'affected' would be the hallucination the pipeline exists to kill).

    Returns ``(SignedStatement, Receipt|None)``. Import-clean seam: ``scitt`` is vigil_core-only, so
    the minted statement is sovereign-verifiable; this function reads the CRUCIBLE cert offense-side.
    """
    from .scitt import mint_finding_statement

    if not getattr(result, "is_fact", False) or result.signed is None:
        raise ValueError(
            "certify_to_scitt only mints a confirmed fact — a lead has no signed certificate to "
            "express as an OpenVEX 'affected' statement (fail-closed honesty invariant)."
        )
    cert = result.signed.certificate.model_dump(mode="json")
    return mint_finding_statement(
        cert, signers, confirmed=True, author=author, timestamp=timestamp, log=log
    )
