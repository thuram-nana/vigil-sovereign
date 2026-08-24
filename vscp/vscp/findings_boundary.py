"""The assessment-findings boundary — VSCP has NO path to read assessment findings.

This is the *runtime* half of the isolation guarantee (the *static* half is the import
scanner in :mod:`vscp.isolation`). VSCP never links the product's finding stores, so it
cannot read a finding by accident; this module makes the refusal EXPLICIT and testable:

  * :func:`read_assessment_finding` is the one function a caller might reach for to pull a
    finding across the boundary. It does not do it — it raises :class:`FindingsAccessDenied`,
    unconditionally. There is no argument that turns it into a read.
  * :func:`finding_boundary_gate` is a gate (in the ``sovereign_bridge`` sense) that any
    VSCP authorization request passes through: a request that references an assessment
    finding / the offense blackboard is DENIED, so a control-plane action can never be a
    covert finding read.

Stdlib only.
"""
from __future__ import annotations

from typing import Any, Mapping, NoReturn

from .gate import GateOutcome

__all__ = [
    "FindingsAccessDenied",
    "FINDING_REFERENCE_MARKERS",
    "read_assessment_finding",
    "request_references_finding",
    "finding_boundary_gate",
]


class FindingsAccessDenied(RuntimeError):
    """Raised whenever code attempts to read an assessment finding from VSCP."""


# Field names / values that denote an assessment-finding artifact. A VSCP authorization
# request carrying any of these is trying to reach across the isolation boundary.
FINDING_REFERENCE_MARKERS: tuple[str, ...] = (
    "finding",
    "finding_id",
    "finding_ref",
    "assessment_finding",
    "blackboard",
    "oracle_context",
    "evidence_finding",
    "spine_finding",
)


def read_assessment_finding(*_args: Any, **_kwargs: Any) -> NoReturn:
    """Refuse — VSCP is isolated from the assessment product and has no path to its
    findings. This is deliberately total: no argument, flag, or mode makes it return."""
    raise FindingsAccessDenied(
        "VSCP is isolated from the assessment product: it has no import or network path "
        "to read assessment findings (W13-7 / #500). This refusal is unconditional."
    )


def request_references_finding(request: Mapping[str, Any] | Any) -> bool:
    """True if a request references an assessment finding — by a marker key, or by a
    string value that names one (case-insensitive substring match on the markers)."""
    if isinstance(request, Mapping):
        for key, value in request.items():
            k = str(key).lower()
            if any(marker in k for marker in FINDING_REFERENCE_MARKERS):
                return True
            if isinstance(value, str):
                v = value.lower()
                if any(marker in v for marker in FINDING_REFERENCE_MARKERS):
                    return True
    return False


def finding_boundary_gate(request: Mapping[str, Any] | Any) -> GateOutcome:
    """A gate over the findings boundary: DENY any request that references an assessment
    finding, ALLOW otherwise. Fail-closed for a malformed request is not needed here (a
    non-mapping simply references no finding and passes this leg — other gates still
    apply), but a reference is always refused."""
    if request_references_finding(request):
        return GateOutcome(
            allow=False,
            reason=(
                "request references an assessment finding; VSCP is isolated from the "
                "product's findings and refuses to read one (W13-7)"
            ),
            code="FINDINGS_BOUNDARY_DENY",
        )
    return GateOutcome(allow=True, reason="no assessment-finding reference", code="FINDINGS_BOUNDARY_OK")
