"""Read helpers that power the 3 consolidation MCP tools and the nightly brief. All serve
ONLY grounded, current (non-superseded) records, each carrying its spine citation."""
from __future__ import annotations

from typing import Any

from ..spine.store import SpineStore
from .grounding import belief_lcb, belief_mean, is_grounded
from .revise import iter_current


def _cite(r) -> dict[str, Any]:
    p = r.payload
    # `text` is the AUTHORITATIVE grounded fact — the verbatim record quote, negation and word
    # order intact. The model's `statement` is served only as an advisory `summary` (never the
    # fact). Cite the VERIFIED subset (what actually re-executed), not the model's full claim.
    return {"seq": r.seq, "entry_hash": r.entry_hash, "when": r.ts,
            "subject": p.get("subject"), "text": p.get("quote"), "summary": p.get("statement"),
            "source_seqs": p.get("verified_seqs") or p.get("source_seqs"), "grounding": p.get("grounding"),
            "belief": round(belief_mean(p.get("alpha", 1), p.get("beta", 1)), 3)}


def _grounded_current(store: SpineStore, kinds: set[str]) -> list:
    return [r for r in iter_current(store, kinds) if is_grounded(r.payload.get("grounding"))]


def open_threads(store: SpineStore, limit: int = 25) -> list[dict[str, Any]]:
    """The owner's live loops: current grounded decisions + commitments, most-stale first
    (oldest source record), each cited. Superseded/resolved records are already excluded."""
    recs = _grounded_current(store, {"decision", "commitment"})
    recs.sort(key=lambda r: (min(r.payload.get("source_seqs") or [r.seq]), r.seq))  # oldest = stalest
    out = []
    for r in recs[:limit]:
        d = _cite(r)
        d["kind"] = r.kind
        if r.kind == "commitment":
            d["owner"] = r.payload.get("owner")
            d["due"] = r.payload.get("due_iso")
        out.append(d)
    return out


def due_commitments(store: SpineStore, *, before_iso: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Current grounded commitments that carry a due date, earliest-due first. Deduped by
    (subject, owner) to the LATEST record, so a rescheduled deadline serves the new due, not a
    stale one. `before_iso` (explicit → deterministic) filters to those due on/before it."""
    recs = [r for r in _grounded_current(store, {"commitment"}) if r.payload.get("due_iso")]
    # keep the CHRONOLOGICALLY latest promise per (subject, owner). Recency is the source-record
    # chronology (max cited seq), NOT the promoted record's own seq — that follows the extractor's
    # emit order, so a reschedule emitted first would otherwise wrongly serve the stale due (finding 1).
    def _recency(r):
        return (max(r.payload.get("source_seqs") or [r.seq]), r.seq)
    latest: dict[tuple, Any] = {}
    for r in recs:
        k = (str(r.payload.get("subject", "")).strip().lower(), str(r.payload.get("owner", "")).strip().lower())
        if k not in latest or _recency(r) > _recency(latest[k]):
            latest[k] = r
    recs = list(latest.values())
    if before_iso:
        recs = [r for r in recs if str(r.payload.get("due_iso")) <= before_iso]
    recs.sort(key=lambda r: (str(r.payload.get("due_iso")), r.seq))
    out = []
    for r in recs[:limit]:
        d = _cite(r)
        d["owner"] = r.payload.get("owner")
        d["due"] = r.payload.get("due_iso")
        out.append(d)
    return out


def pending_contradictions(store: SpineStore, limit: int = 25) -> list[dict[str, Any]]:
    """Current, unresolved self-contradictions — extractor-JUDGED opposition, gate-verified,
    flagged never adjudicated. Each names the conflicting record seqs so the owner can resolve
    them, and carries the verbatim quote that grounded the flag."""
    recs = [r for r in iter_current(store, {"contradiction"})
            if not r.payload.get("resolved") and is_grounded(r.payload.get("grounding"))]
    recs.sort(key=lambda r: r.seq)
    return [{"seq": r.seq, "entry_hash": r.entry_hash, "when": r.ts,
             "subject": r.payload.get("subject"),
             "conflicting_seqs": r.payload.get("conflicting_seqs"),
             "detail": r.payload.get("statement"), "quote": r.payload.get("quote")}
            for r in recs[:limit]]
