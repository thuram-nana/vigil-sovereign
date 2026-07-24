"""Append-only supersession + current-view read (ported from agents/blackboard.py's
post/supersede/read discipline). The spine is never edited; a revised fact is SUPERSEDED by
a later record whose `supersedes_id` names it. `iter_current` returns the live view — the
consolidation records that nothing later has superseded — which is what the MCP tools serve."""
from __future__ import annotations

from typing import Iterator

from ..spine.models import SpineRecord
from ..spine.snapshot import SnapshotState
from ..spine.store import SpineStore
from .grounding import CONSOLIDATE_SOURCE


def consolidation_records(store: SpineStore, kinds: set[str] | None = None) -> Iterator[SpineRecord]:
    """Every record the ARCHIVIST wrote (source=archivist), optionally filtered by kind."""
    st = SnapshotState.load(store)
    # Snapshot prefix [0..base_seq): the pre-folded FULL fact-kind archivist records (ascending seq, every
    # one < base_seq; superseded ones RETAINED so iter_current recomputes the live view at query time).
    yield from st.archivist_records_of(kinds)
    # Live window [base_seq..T]: since_seq = base_seq - 1 yields seq >= base_seq, filtered BYTE-FOR-BYTE as
    # today. Under the empty snapshot base_seq==0 => since_seq==-1 (the full genesis scan) and
    # archivist_records_of yields [] => byte-identical to the old single-pass genesis scan.
    for r in store.iter_records(since_seq=st.base_seq - 1):
        if r.source == CONSOLIDATE_SOURCE and (kinds is None or r.kind in kinds):
            yield r


def iter_current(store: SpineStore, kinds: set[str] | None = None) -> list[SpineRecord]:
    """The live view: consolidation records of `kinds` that nothing later has superseded. Records are
    DECRYPTED (G1 slice-4) — the served fact's `quote`/`statement` are sealed content fields, so the 3
    recall tools + the nightly brief that consume this MUST get plaintext; a locked vault fails closed
    (raises) rather than serving ciphertext. The supersede/grounding filters key only on plaintext
    metadata, so sealing does not affect them."""
    recs = list(consolidation_records(store, kinds))
    superseded = {r.supersedes_id for r in recs if r.supersedes_id is not None}
    return [store.decrypted(r) for r in recs if r.seq not in superseded]


def promotion_ledgers(store: SpineStore) -> tuple[set[str], set[str]]:
    """Two SEPARATE idempotency ledgers: keys already promoted as GROUNDED facts, and keys
    already recorded as demoted refusals. Kept apart so a prior DEMOTE never blocks a later
    GROUNDED promotion of the same fact — demote-only must not become demote-permanent."""
    st = SnapshotState.load(store)
    # Seed from the pruned prefix's folded ledgers (a COPY — never mutate the cached snapshot state).
    grounded: set[str] = set(st.grounded_keys)
    refused: set[str] = set(st.refused_keys)
    # Fold the LIVE archivist records [base_seq..T]. The `source == CONSOLIDATE_SOURCE` filter that
    # consolidation_records applied is inlined here; the inner ledger body is BYTE-FOR-BYTE as today. Under
    # the empty snapshot base_seq==0 => since_seq==-1 (full genesis scan) and both seeds are EMPTY, so this
    # is byte-identical to the old genesis scan over consolidation_records.
    for r in store.iter_records(since_seq=st.base_seq - 1):
        if r.source != CONSOLIDATE_SOURCE:
            continue
        k = r.payload.get("promotion_key")
        if k is None:
            continue
        (refused if r.kind == "refusal" else grounded).add(k)
    return grounded, refused
