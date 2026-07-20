"""
report.grounding — grade every finding at report time by RE-EXECUTING its proof.

This is the prove-don't-guess gate for the report layer. A finding is not trusted
because it was once recorded ``confirmed``; it is trusted only if its retained
``oracle_context`` still re-fires NOW. We reuse the platform's own authority — the
veracity firewall (``veracity.admit`` over a ``claim_from_finding`` claim) — exactly
as ``agents/reporter_agent.py`` does, so a report and the reporter-agent grade a
finding identically. ``admit_for_report`` is the single shared entry point;
``reporter_agent`` delegates to it.

Three grades, mutually exclusive:

  FACT     the finding's own oracle re-fired for its bug_class → a proven fact,
           rendered with its certificate reference (the sha256 digest that binds
           the retained evidence — reusable via ``python3 -m framework.v2 verify``).
  DEMOTED  recorded oracle-confirmed, but the retained proof did NOT reproduce at
           report time (altered evidence, a relabelled bug_class, or a dry-run stub)
           → a LEAD, never asserted as a fact.
  LEAD     no deterministic oracle signal at all (LLM-advisory) → a lead to verify.

Pure and read-only: it re-runs pure oracles over retained evidence and sends no
traffic. Deterministic: the same finding grades identically every time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..agents.models import FindingPayload

# The three grades a report assigns. FACT is the ONLY one presented as a proven
# fact; DEMOTED and LEAD are both leads (unconfirmed), distinguished only so the
# operator knows a demoted finding *claimed* a proof that no longer reproduces.
GRADE_FACT = "fact"
GRADE_DEMOTED = "demoted"
GRADE_LEAD = "lead"


def admit_for_report(finding: Any, *, source: str = "report") -> Any:
    """Re-execute a finding's retained ``oracle_context`` through the veracity firewall
    and return the ``AdmittedClaim`` (or ``None`` on any error).

    ``match_confidence=False``: a blackboard finding's recorded confidence is the
    CALIBRATED value, not the raw oracle output, so the gate checks that the oracle
    re-fires for the bound bug_class WITHOUT falsely demoting on the legitimate
    calibration delta. The oracle re-runs over retained evidence only — pure,
    read-only, no traffic. This is the shared authority ``reporter_agent`` reuses."""
    try:
        from ..veracity import admit, claim_from_finding

        claim = claim_from_finding(finding, source=source, match_confidence=False)
        return admit(claim, world=None)
    except Exception:
        return None


def coerce_finding(obj: Any) -> FindingPayload:
    """Accept a ``FindingPayload`` or an equivalent mapping and return a
    ``FindingPayload``. Lets callers feed findings straight from the blackboard
    (already models) or from a JSON document (dicts) through the same grader."""
    if isinstance(obj, FindingPayload):
        return obj
    return FindingPayload.model_validate(obj)


def _certificate_digest(finding: FindingPayload) -> str | None:
    """The re-runnable certificate reference for a fact: the sha256 of the retained
    ``oracle_context`` in the platform's canonical form (the exact discipline evidence
    integrity uses to bind a certificate to the bytes the oracle judged). ``None`` when
    there is no retained context to reference."""
    oc = finding.oracle_context
    if not isinstance(oc, dict) or not oc:
        return None
    try:
        from ..evidence import digest_payload

        return digest_payload(oc)
    except Exception:
        return None


@dataclass(frozen=True)
class GradedFinding:
    """A finding paired with its report-time grade — the unit every renderer consumes.

    Immutable so the three reports share one, consistent grading. ``oracle_kind``,
    ``confidence`` and ``certificate_digest`` are populated ONLY for a FACT (a
    re-firing proof); for a lead they are ``None`` so no renderer can accidentally
    dress a lead in a fact's provenance."""

    finding: FindingPayload
    grade: str
    event_id: int | None = None
    reason: str = ""
    oracle_kind: str | None = None
    confidence: float | None = None
    certificate_digest: str | None = None

    @property
    def is_fact(self) -> bool:
        return self.grade == GRADE_FACT

    @property
    def is_lead(self) -> bool:
        """A lead is anything not proven — both the LLM-advisory and the demoted case."""
        return self.grade in (GRADE_DEMOTED, GRADE_LEAD)


def grade_finding(finding: Any, *, event_id: int | None = None) -> GradedFinding:
    """Grade one finding by re-executing its proof. Mirrors ``reporter_agent`` exactly:
    a re-firing oracle → FACT; a recorded-oracle finding whose proof no longer
    re-fires → DEMOTED; anything else → LEAD."""
    f = coerce_finding(finding)
    admitted = admit_for_report(f)

    if admitted is not None and getattr(admitted, "is_fact", False):
        return GradedFinding(
            finding=f,
            grade=GRADE_FACT,
            event_id=event_id,
            reason="retained oracle proof re-fired at report time",
            oracle_kind=f.oracle_kind or None,
            confidence=f.confidence,
            certificate_digest=_certificate_digest(f),
        )

    if f.verified_by_oracle:
        why = getattr(admitted, "reason", "") if admitted is not None else ""
        return GradedFinding(
            finding=f,
            grade=GRADE_DEMOTED,
            event_id=event_id,
            reason=why or "retained oracle proof did not re-verify at report time",
        )

    dryrun = bool(getattr(f, "critique_dryrun", False))
    return GradedFinding(
        finding=f,
        grade=GRADE_LEAD,
        event_id=event_id,
        reason=(
            "LLM-advisory lead produced by a DRY-RUN model call (not a live inference)"
            if dryrun
            else "LLM-advisory lead — no deterministic oracle signal"
        ),
    )


def grade_findings(
    findings: Iterable[Any] | Iterable[tuple[Any, int | None]],
) -> list[GradedFinding]:
    """Grade a batch. Each item is either a finding, or a ``(finding, event_id)`` pair.
    Order is preserved; the renderers do their own deterministic sorting."""
    out: list[GradedFinding] = []
    for item in findings:
        if isinstance(item, tuple) and len(item) == 2:
            out.append(grade_finding(item[0], event_id=item[1]))
        else:
            out.append(grade_finding(item))
    return out
