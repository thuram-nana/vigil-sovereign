"""Append-only supersession + current-view read (ported from agents/blackboard.py's
post/supersede/read discipline). The spine is never edited; a revised fact is SUPERSEDED by
a later record whose `supersedes_id` names it. `iter_current` returns the live view — the
consolidation records that nothing later has superseded — which is what the MCP tools serve."""
from __future__ import annotations

from typing import Iterator

from ..spine.models import SpineRecord
from ..spine.store import SpineStore
from .grounding import CONSOLIDATE_SOURCE


def consolidation_records(store: SpineStore, kinds: set[str] | None = None) -> Iterator[SpineRecord]:
    """Every record the ARCHIVIST wrote (source=archivist), optionally filtered by kind."""
    for r in store.iter_records():
        if r.source == CONSOLIDATE_SOURCE and (kinds is None or r.kind in kinds):
            yield r


def iter_current(store: SpineStore, kinds: set[str] | None = None) -> list[SpineRecord]:
    """The live view: consolidation records of `kinds` that nothing later has superseded."""
    recs = list(consolidation_records(store, kinds))
    superseded = {r.supersedes_id for r in recs if r.supersedes_id is not None}
    return [r for r in recs if r.seq not in superseded]


def promotion_ledgers(store: SpineStore) -> tuple[set[str], set[str]]:
    """Two SEPARATE idempotency ledgers: keys already promoted as GROUNDED facts, and keys
    already recorded as demoted refusals. Kept apart so a prior DEMOTE never blocks a later
    GROUNDED promotion of the same fact — demote-only must not become demote-permanent."""
    grounded: set[str] = set()
    refused: set[str] = set()
    for r in consolidation_records(store):
        k = r.payload.get("promotion_key")
        if k is None:
            continue
        (refused if r.kind == "refusal" else grounded).add(k)
    return grounded, refused
