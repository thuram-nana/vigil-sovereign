"""
confidence.decision — the Scientific Confidence Engine at the vulnerability gate.

A scanner emits "XSS, confidence 0.9". A scientist asks: *how likely is it really,
what else could explain what we saw, and what one test would settle it?* This adapter
turns a confirmed finding into exactly that — a `ScientificHypothesis` (the bug is
real) weighed against the benign explanations that most often masquerade as that bug
class (a MECE set), with the oracle confirmation entered as evidence and the cheapest
decisive follow-up attached — then runs it through `assess`.

It is NON-INVASIVE and it does not override the oracle. The oracle stays the authority
on confirmation; this layer expresses HOW CONFIDENT that confirmation leaves us, in
calibrated, competing-hypothesis terms — so a gate can say "posterior 0.994, top
alternative 0.004, reaches target" instead of trusting a bare scalar. A finding the
oracle confirmed with a replayable certificate earns strong affirming evidence; a
merely passive/heuristic signal earns little, and its alternatives stay live.
"""

from __future__ import annotations

from .engine import assess
from .models import (
    AlternativeHypothesis,
    CandidateObservation,
    ConfidenceReport,
    Evidence,
    Provenance,
    ScientificHypothesis,
)

# How much the confirmation METHOD moves the odds the bug is real (likelihood ratio of
# seeing this confirmation if the bug is real vs if it is the benign alternative).
_CONFIRMATION_LR: dict[str, float] = {
    "oracle": 60.0,        # a deterministic oracle fired (side-effect / differential / OOB)
    "differential": 25.0,  # a strong differential signal
    "reflected": 6.0,      # reflection seen but execution not proven
    "heuristic": 3.0,
    "passive": 2.0,        # a passive indicator only
    "": 3.0,
}

# The benign explanation that most often masquerades as each bug class — the specific
# alternative a careful tester rules out. Kept small and data-driven.
_ALTERNATIVES: dict[str, tuple[str, str]] = {
    "xss": ("reflected-escaped", "input reflected but escaped/encoded — does not execute"),
    "sqli": ("error-not-injectable", "error/differential response not driven by SQL injection"),
    "ssrf": ("fetch-no-reach", "server fetched the URL but reached nothing internal/sensitive"),
    "idor": ("authorized-access", "object returned but the caller was actually authorized"),
    "bola": ("authorized-access", "object returned but the caller was actually authorized"),
    "broken_access_control": ("authorized-access", "resource returned but access was authorized"),
    "deserialization": ("parsed-not-executed", "payload parsed but no code path executed it"),
    "open_redirect": ("same-origin-only", "redirect constrained to same origin"),
}
_GENERIC_ALT = ("benign", "a benign behaviour that resembles this bug class")


def _get(finding: object, attr: str, default=None):
    if isinstance(finding, dict):
        return finding.get(attr, default)
    return getattr(finding, attr, default)


def assess_finding(
    finding: object,
    *,
    corroborations: list[Evidence] | None = None,
    candidates: list[CandidateObservation] | None = None,
    target_confidence: float = 0.99,
) -> ConfidenceReport:
    """Assess a confirmed finding as a scientific hypothesis. ``finding`` is a scanner
    AuditFinding (or a dict) exposing ``bug_class``, ``confidence``, ``confirmed_by``,
    and optionally ``oracle_context``. ``corroborations`` are extra Evidence (e.g. an
    independent re-confirmation, or an intel observation that the surface is real).
    Returns a `ConfidenceReport` — posterior, competing alternatives, credible interval,
    and the single most decisive next observation."""
    bug_class = str(_get(finding, "bug_class", "") or "")
    prior = float(_get(finding, "confidence", 0.5) or 0.5)
    confirmed_by = str(_get(finding, "confirmed_by", "") or "")
    has_cert = _get(finding, "oracle_context", None) is not None

    lr = _CONFIRMATION_LR.get(confirmed_by, _CONFIRMATION_LR[""])
    if has_cert and confirmed_by == "oracle":
        lr *= 1.5   # a replayable certificate is independently checkable — stronger

    focal_evidence = [Evidence(
        seq=0, observation=f"{bug_class or 'finding'} confirmed_by={confirmed_by or 'n/a'}"
        + (" (+cert)" if has_cert else ""),
        likelihood_ratio=lr, weight=1.0, independence=1.0,
        provenance=Provenance(source="oracle", note=confirmed_by))]
    focal_evidence += list(corroborations or [])

    alt_id, alt_stmt = _ALTERNATIVES.get(bug_class, _GENERIC_ALT)
    focal_prior = min(0.9, max(0.05, prior))   # the scanner's scalar seeds it, never pins it
    # the remaining mass is a REAL competitor (the benign explanation) plus a residual —
    # a genuine MECE contest, so the alternative can actually win when evidence is weak.
    alt_prior = (1.0 - focal_prior) * 0.7
    hypothesis = ScientificHypothesis(
        id=f"REAL:{bug_class or 'finding'}",
        statement=f"the {bug_class or 'reported'} finding is a real, exploitable bug",
        surface=str(_get(finding, "insertion_point", "") or _get(finding, "param", "") or ""),
        bug_class=bug_class,
        prior=focal_prior,
        evidence=focal_evidence,
        alternatives=[AlternativeHypothesis(id=alt_id, statement=alt_stmt, prior=alt_prior)],
        residual_prior=(1.0 - focal_prior) * 0.3,
        refute_on=f"a test that distinguishes '{alt_stmt}' from a real {bug_class or 'bug'}",
    )
    return assess(hypothesis, candidates=candidates, target_confidence=target_confidence)
