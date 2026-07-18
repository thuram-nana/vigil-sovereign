"""Promotion (SIGIL §6.3.5) — write gate verdicts to the spine as NEW records, idempotently.

A GROUNDED candidate becomes a first-class `decision`/`commitment`/`entity`/`contradiction`
record whose served content is the BYTE-verbatim record span (the gate's `text`), and whose
`alpha` counts the DISTINCT records that re-verified it (corroboration, never the model's
confidence number). A DEMOTED candidate is not dropped — it is recorded honestly as a
`refusal` tagged `llm:ungrounded`, filtered out of the tools. Idempotency: a stable
`promotion_key` over (kind, subject, verbatim-quote content) [+ owner/due for commitments] —
re-running the same window never double-promotes."""
from __future__ import annotations

from dataclasses import dataclass

from ..reuse import canonical_json, sha256_hex
from ..spine.store import SpineStore
from .grounding import CONSOLIDATE_SOURCE, is_grounded
from .models import CandidateFact, GateVerdict
from .revise import promotion_ledgers


@dataclass
class PromoteStats:
    grounded: int = 0
    ungrounded: int = 0
    skipped: int = 0            # already promoted in a prior run (idempotent)
    contradictions: int = 0     # grounded contradiction records written THIS run


def promotion_key(cand: CandidateFact) -> str:
    return sha256_hex(canonical_json(cand.key_fields()))[:16]


def promote_all(store: SpineStore, admitted: list[tuple[CandidateFact, GateVerdict]]) -> PromoteStats:
    """Persist each (candidate, verdict). Grounded → fact record; demoted → refusal record.

    GROUNDED verdicts are processed FIRST, and a prior demote (refusal) NEVER blocks a
    grounded promotion — so if the same fact is demoted in one batch/run and grounded in
    another, the grounded promotion wins. A refusal is written only if that fact was neither
    already grounded nor already refused (idempotent, and it never suppresses a real fact)."""
    grounded_seen, refused_seen = promotion_ledgers(store)
    stats = PromoteStats()
    # group by key so within THIS run a grounded verdict always beats an ungrounded one.
    grounded_first = sorted(admitted, key=lambda cv: 0 if is_grounded(cv[1].grounding) else 1)
    for cand, verdict in grounded_first:
        key = promotion_key(cand)
        if is_grounded(verdict.grounding):
            if key in grounded_seen:
                stats.skipped += 1
                continue
            grounded_seen.add(key)
            distinct = sorted(set(verdict.verified_seqs))     # distinct corroborating records (finding 3)
            parent = min(distinct) if distinct else None      # anchor to a VERIFIED record, not a claimed one
            payload = {
                "subject": cand.subject, "statement": cand.statement,
                "quote": verdict.text or cand.quote,          # BYTE-verbatim record span (finding 9)
                "source_seqs": cand.source_seqs, "verified_seqs": distinct,
                "grounding": verdict.grounding,
                "alpha": 1 + len(distinct), "beta": 1,        # corroboration, not model confidence
                "confidence_basis": "grounded-corroboration",
                "model_confidence": cand.model_confidence,
                "promotion_key": key, "extractor": cand.extractor,
            }
            if cand.kind == "commitment":
                payload["owner"] = cand.owner
                payload["due_iso"] = cand.due_iso
            elif cand.kind == "contradiction":
                # extractor-judged opposition, gate-verified: conflicting_seqs are ONLY the
                # records that verbatim-verified (never an unverified cited seq). Flagged, never adjudicated.
                payload["conflicting_seqs"] = distinct
                payload["resolved"] = False
                stats.contradictions += 1
            store.append(kind=cand.kind, source=CONSOLIDATE_SOURCE, actor=CONSOLIDATE_SOURCE,
                         payload=payload, parent_id=parent)
            stats.grounded += 1
        else:
            if key in grounded_seen or key in refused_seen:   # already a fact, or already refused
                stats.skipped += 1
                continue
            refused_seen.add(key)
            # demote, don't drop — honest commentary, filtered out of the tools by grounding tag.
            store.append(kind="refusal", source=CONSOLIDATE_SOURCE, actor=CONSOLIDATE_SOURCE,
                         payload={"candidate_kind": cand.kind, "subject": cand.subject,
                                  "statement": cand.statement, "grounding": verdict.grounding,
                                  "reason": verdict.reason, "source_seqs": cand.source_seqs,
                                  "promotion_key": key, "extractor": cand.extractor},
                         parent_id=(min(cand.source_seqs) if cand.source_seqs else None))
            stats.ungrounded += 1
    return stats
