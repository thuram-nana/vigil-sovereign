"""
knowledge_base.models — the read-only record types of the per-ORG knowledge-base corpus.

The knowledge base is a READ / INDEX / QUERY layer over the engagement artifacts that ALREADY
live on disk under the active tenant's ``CRUCIBLE_ROOT`` (``targets/<slug>/``). It introduces NO
new storage: these records are a typed, aggregated *view* of what the scanner, reporter and
operator already wrote. Every record is keyed ``(tenant_id, slug)`` — ``tenant_id`` is the OUTER
org key (``common.paths.active_tenant()``; ``None`` when the process is unsharded / single-tenant,
treated as the default/global scope) and ``slug`` is the INNER per-engagement key.

These are frozen, hashable value objects (stdlib ``dataclass``) with a ``to_dict()`` for a JSON
surface (a future ``vigil kb`` verb / API). No pydantic, no I/O, no framework coupling beyond the
string/number values read from the artifacts — so the model layer stays trivially importable on the
offense/framework plane (FATAL-2: no sovereign / integration imports).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# The display label for the unsharded / single-tenant default scope (``active_tenant()`` is ``None``).
GLOBAL_SCOPE_LABEL = "(global)"

# Canonical severity ordering (most→least severe), used for stable sorting and bucket display.
SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Confirmed": 5,
}


def scope_label(tenant_id: Optional[str]) -> str:
    """A human-readable scope label: the tenant id, or ``(global)`` for the unsharded default."""
    return tenant_id if tenant_id else GLOBAL_SCOPE_LABEL


def severity_rank(severity: str) -> int:
    """Sort key for a severity string (unknown / empty sorts last)."""
    return SEVERITY_ORDER.get((severity or "").strip().title(), 99)


@dataclass(frozen=True)
class FindingRecord:
    """One finding (or lead) indexed into the corpus, keyed ``(tenant_id, slug)``.

    ``source`` records provenance and is the honest line between proof and lead:
      * ``scan:active``  — an oracle-CONFIRMED active-audit finding read from ``<slug>.report.json``
        (``ScanReport.active_findings``). ``oracle_confirmed`` is True; ``oracle_kind`` names the
        oracle that fired.
      * ``finding-file`` — an operator/agent-authored finding doc (``findings/NNN-*.md``). By the
        OBSIDIAN doctrine a finding file exists only once confirmed, so ``confirmed`` is True — but
        it is NOT oracle-grounded, so ``oracle_confirmed`` stays False (no overclaim).
      * ``scan:passive`` — a passive finding (``ScanReport.passive_findings``): a LEAD, never a
        confirmed fact, so ``confirmed`` is False.
    """

    tenant_id: Optional[str]
    slug: str
    ref: str
    title: str
    severity: str
    bug_class: str
    source: str
    confirmed: bool
    oracle_confirmed: bool
    status: str = ""
    oracle_kind: str = ""
    endpoint: str = ""
    confidence: Optional[float] = None
    path: str = ""

    @property
    def key(self) -> tuple[Optional[str], str]:
        return (self.tenant_id, self.slug)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "slug": self.slug,
            "ref": self.ref,
            "title": self.title,
            "severity": self.severity,
            "bug_class": self.bug_class,
            "source": self.source,
            "confirmed": self.confirmed,
            "oracle_confirmed": self.oracle_confirmed,
            "status": self.status,
            "oracle_kind": self.oracle_kind,
            "endpoint": self.endpoint,
            "confidence": self.confidence,
            "path": self.path,
        }


@dataclass(frozen=True)
class ReportRecord:
    """One rendered report document (``reports/*.md``) indexed into the corpus, keyed ``(tenant_id, slug)``.

    The corpus indexes reports — it does not re-render or mutate them (the reporter-agent owns
    ``reports/technical.md``; the operator owns the executive / remediation docs)."""

    tenant_id: Optional[str]
    slug: str
    name: str
    path: str
    title: str = ""
    size_bytes: int = 0

    @property
    def key(self) -> tuple[Optional[str], str]:
        return (self.tenant_id, self.slug)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "slug": self.slug,
            "name": self.name,
            "path": self.path,
            "title": self.title,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class Engagement:
    """A per-engagement summary row, keyed ``(tenant_id, slug)``. ``finding_count`` counts CONFIRMED
    findings (oracle-confirmed active findings + authored finding files); ``lead_count`` counts the
    unconfirmed passive findings. All derived from the on-disk artifacts under the active root."""

    tenant_id: Optional[str]
    slug: str
    has_charter: bool
    has_scan_report: bool
    finding_count: int
    lead_count: int
    report_count: int
    target: str = ""

    @property
    def key(self) -> tuple[Optional[str], str]:
        return (self.tenant_id, self.slug)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "slug": self.slug,
            "has_charter": self.has_charter,
            "has_scan_report": self.has_scan_report,
            "finding_count": self.finding_count,
            "lead_count": self.lead_count,
            "report_count": self.report_count,
            "target": self.target,
        }


@dataclass(frozen=True)
class Corpus:
    """The aggregated per-ORG knowledge base for ONE scope (``tenant_id``): every engagement under the
    active tenant's ``targets/`` tree, its confirmed findings + leads, and its report documents.

    ``tenant_id`` is the org key (``None`` == the unsharded/global default). The corpus is a snapshot:
    reading it never mutates anything, and it is strictly scoped — it only ever contains artifacts from
    under the ACTIVE tenant's root (see ``knowledge_base.aggregate`` for the fail-closed scope guard)."""

    tenant_id: Optional[str]
    engagements: tuple[Engagement, ...] = field(default_factory=tuple)
    findings: tuple[FindingRecord, ...] = field(default_factory=tuple)
    reports: tuple[ReportRecord, ...] = field(default_factory=tuple)

    @property
    def scope(self) -> str:
        return scope_label(self.tenant_id)

    def slugs(self) -> list[str]:
        return [e.slug for e in self.engagements]

    def is_empty(self) -> bool:
        return not self.engagements and not self.findings and not self.reports

    def confirmed_findings(self) -> list[FindingRecord]:
        """Findings that are confirmed (oracle-confirmed active findings + authored finding files) —
        the leads (passive findings) are excluded."""
        return [f for f in self.findings if f.confirmed]

    def leads(self) -> list[FindingRecord]:
        return [f for f in self.findings if not f.confirmed]

    def by_severity(self) -> dict[str, int]:
        """Severity histogram over CONFIRMED findings. A confirmed finding with no explicit severity is
        bucketed as ``Confirmed`` (mirrors ``ScanReport.by_severity`` for oracle-confirmed active
        findings, which are exploitable-by-construction and may carry no textbook severity label)."""
        counts: dict[str, int] = {}
        for f in self.confirmed_findings():
            label = (f.severity or "").strip().title() or "Confirmed"
            counts[label] = counts.get(label, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "scope": self.scope,
            "engagements": [e.to_dict() for e in self.engagements],
            "findings": [f.to_dict() for f in self.findings],
            "reports": [r.to_dict() for r in self.reports],
            "summary": {
                "engagement_count": len(self.engagements),
                "confirmed_finding_count": len(self.confirmed_findings()),
                "lead_count": len(self.leads()),
                "report_count": len(self.reports),
                "by_severity": self.by_severity(),
            },
        }
