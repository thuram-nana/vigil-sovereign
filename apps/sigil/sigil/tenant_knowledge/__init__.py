"""Per-tenant customer KNOWLEDGE corpus (gated by ``config.customer_knowledge_enabled``).

Customers upload their own organization documents so the security assistant knows their org. Everything is scoped to
ONE tenant by a one-way hash of org_id, in that org's OWN per-org spine + vector index + graph dir under
``config.CUSTOMER_KNOWLEDGE_DIR`` - NEVER the owner's global single-tenant stores and NEVER another tenant's corpus.
See :mod:`sigil.tenant_knowledge.store` for the isolation + fail-closed contract.
"""
from __future__ import annotations

from .store import (
    KnowledgeCapError,
    KnowledgeError,
    KnowledgeIsolationError,
    TenantKnowledge,
    corpus_root,
    ingest_document,
    list_documents,
    query,
)

__all__ = [
    "KnowledgeError", "KnowledgeCapError", "KnowledgeIsolationError", "TenantKnowledge",
    "ingest_document", "list_documents", "query", "corpus_root",
]
