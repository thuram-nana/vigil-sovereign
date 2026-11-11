"""
knowledge_base — the per-ORG knowledge-base corpus (enterprise KNOWLEDGE-BASE wave, slice 1).

A read / index / query layer over the engagement artifacts that ALREADY live on disk under the active
tenant's ``CRUCIBLE_ROOT`` (``targets/<slug>/`` findings + reports). It adds NO storage; it aggregates
and queries, strictly scoped to the active org (``active_tenant()``) and keyed ``(tenant_id, slug)``.

Public API (see ``knowledge_base.aggregate``):

    active_org()                 -> the org (tenant id) this process serves, or None (global/default).
    list_engagements(tenant=…)   -> the org's engagements (one row per slug).
    corpus(tenant=…)             -> the full aggregated Corpus (findings + reports across the org's slugs).
    query(tenant=…, **filters)   -> filtered FindingRecords across the org's corpus.
    show(slug, tenant=…)         -> one engagement's {engagement, findings, reports} slice.

A caller for org A can NEVER read org B's artifacts: the active ``CRUCIBLE_ROOT`` is the boundary, and
an explicit cross-org request fails CLOSED with :class:`KnowledgeBaseScopeError`.
"""

from __future__ import annotations

from .aggregate import (
    KnowledgeBaseError,
    KnowledgeBaseScopeError,
    active_org,
    corpus,
    list_engagements,
    query,
    show,
)
from .models import (
    Corpus,
    Engagement,
    FindingRecord,
    ReportRecord,
    scope_label,
    severity_rank,
)

__all__ = [
    "KnowledgeBaseError",
    "KnowledgeBaseScopeError",
    "active_org",
    "corpus",
    "list_engagements",
    "query",
    "show",
    "Corpus",
    "Engagement",
    "FindingRecord",
    "ReportRecord",
    "scope_label",
    "severity_rank",
]
