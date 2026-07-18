"""SIGIL MCP memory server (Phase 0a: memory.search).

A gated, read-only, loopback stdio server exposing the owner's total recall to any Claude
surface. Ports the CRUCIBLE MCP posture (framework/v2/mcp/server.py): a fail-closed tool
allowlist, no write path, and provenance on every result — each hit is a real, tamper-
evident spine record (seq + entry_hash) so answers are CITED, and an empty result says so
rather than inviting fabrication (SIGIL doctrine §1.5, prove-don't-guess).
"""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..config import EMBED_MODEL, QDRANT_URL
from ..reuse import assert_no_offense
from ..spine.checkpoint import verify_checkpoint
from ..spine.store import SpineStore
from ..vectors.index import VectorIndex

assert_no_offense()  # doctrine §12: no engine module may be loaded in a SIGIL process

mcp = FastMCP("sigil-memory")
_index: VectorIndex | None = None


def _idx() -> VectorIndex:
    global _index
    if _index is None:
        _index = VectorIndex()
    return _index


@mcp.tool()
def memory_search(query: str, k: int = 8) -> dict[str, Any]:
    """Search the owner's ENTIRE Claude history — everything they've built, decided, or
    discussed — and return ranked memory records WITH PROVENANCE so you can cite them.

    Each result is a real, tamper-evident spine record: `seq` + `entry_hash` uniquely
    identify it, `when`/`session`/`project` locate it. When you answer from these, CITE
    the seq(s). If `results` is empty, memory genuinely has nothing — say so; do NOT
    fabricate an answer.

    Args:
        query: what to recall (natural language).
        k: max results (default 8).
    """
    hits, is_grounded = _idx().grounded(query, k=max(1, min(int(k), 25)))
    if not is_grounded:
        return {"results": [],
                "note": "No strongly-grounded match in SIGIL memory for this query. Do not fabricate — "
                        "tell the owner memory has nothing solid on this (optionally suggest rephrasing)."}
    return {
        "results": [
            {
                "seq": h["seq"], "kind": h["kind"], "when": h.get("ts"),
                "session": h.get("session_id"), "project": h.get("project"),
                "entry_hash": h.get("entry_hash"), "score": round(h["score"], 4),
                "text": h.get("text"),
            }
            for h in hits
        ],
        "provenance": "Each result is a tamper-evident spine record; cite its `seq` (and `entry_hash`) when you answer.",
    }


@mcp.tool()
def episodic_range(start_seq: int = 0, end_seq: int | None = None,
                   kind: str | None = None, limit: int = 25) -> dict[str, Any]:
    """Read a CONTIGUOUS window of the owner's episodic spine in seq order — the raw record
    stream (messages, tool calls, commits, docs), not a semantic search. Use this to
    reconstruct *what happened* around a known point (e.g. after `memory_search` gives you a
    seq, read the seqs around it for context), or to page through a session/day.

    Every record is tamper-evident (seq + entry_hash). Cite seqs when you answer.

    Args:
        start_seq: first seq to return (inclusive, default 0 = beginning).
        end_seq: last seq (inclusive); default = newest.
        kind: optional filter (message | tool_call | tool_result | commit | document | session | decision | commitment | brief).
        limit: max records (default 25, hard cap 200).
    """
    store = SpineStore()
    limit = max(1, min(int(limit), 200))
    hi = (store.next_seq - 1) if end_seq is None else int(end_seq)
    lo = max(0, int(start_seq))
    out: list[dict[str, Any]] = []
    for r in store.iter_records(since_seq=lo - 1):  # yields seq >= lo
        if r.seq > hi:
            break
        if kind and r.kind != kind:
            continue
        out.append({
            "seq": r.seq, "kind": r.kind, "source": r.source, "actor": r.actor,
            "when": r.ts, "session": r.payload.get("session_id"), "project": r.payload.get("project"),
            "parent_id": r.parent_id, "supersedes_id": r.supersedes_id,
            "entry_hash": r.entry_hash, "text": (r.text() or "")[:800],
        })
        if len(out) >= limit:
            break
    return {"range": {"start_seq": lo, "end_seq": hi}, "kind": kind, "count": len(out),
            "records": out,
            "provenance": "Each record is a tamper-evident spine entry; cite its `seq` when you answer."}


@mcp.tool()
def ingest_status(verify: bool = True) -> dict[str, Any]:
    """Report the health of SIGIL memory: how much is stored, how much is embedded for
    semantic recall, and — with `verify` — whether the spine's integrity chain and signed
    head still hold (tamper-evidence). Use this to tell the owner how current/trustworthy
    their memory is before relying on it.

    Args:
        verify: also run the (heavier) integrity + signed-head check (default true).
    """
    store = SpineStore()
    vi = _idx()
    status: dict[str, Any] = {
        "spine_records": store.count(),
        "next_seq": store.next_seq,
        "vectors_indexed": vi.count(),
        "last_indexed_seq": vi.last_indexed_seq(),
        "embedding_model": EMBED_MODEL,
        "qdrant_mode": "server" if QDRANT_URL else "local-embedded",
    }
    if verify:
        ok, msg = store.verify()
        hok, hmsg = verify_checkpoint(store)
        status["chain"] = {"ok": ok, "detail": msg}
        status["signed_head"] = {"ok": hok, "detail": hmsg}
    return status


@mcp.tool()
def graph_entity(name: str) -> dict[str, Any]:
    """Look up a structural entity in the owner's memory graph and return it WITH its
    neighbours and spine anchors. Resolves `name` as a Project, then a Session id, a Commit
    hash prefix, or a Document path substring. Use this for a structured overview — e.g.
    `graph_entity("PENTEST-main")` returns the project's sessions, commits, and documents.

    The graph is a deterministic, rebuilt view of the spine; every node cites the spine
    `anchor_seq` that minted it, so you can `episodic_range` around it for detail.
    """
    from ..graph import entity as _entity
    try:
        return _entity(name)
    except Exception as e:  # noqa: BLE001 — graph may be unbuilt; report, don't crash the tool
        return {"error": str(e), "hint": "the graph may not be built yet"}


@mcp.tool()
def graph_query(cypher: str, limit: int = 50) -> dict[str, Any]:
    """Run a READ-ONLY Cypher query over the owner's memory graph (a deterministic view of
    the spine) and return columns + rows. Writes/DDL are refused.

    Node labels: `Project(name, sessions, commits, documents, messages)`,
    `Session(id, title, project, messages, first_seq, last_seq, anchor_seq)`,
    `Document(path, title, project, chunks)`, `Commit(hash, repo, subject, author, date)`.
    Edges (all point at a Project): `IN_PROJECT_S` (Session), `IN_PROJECT_D` (Document),
    `IN_PROJECT_C` (Commit). Example: `MATCH (c:Commit) RETURN c.subject, c.date ORDER BY c.anchor_seq DESC`.
    """
    from ..graph import query as _query
    try:
        return _query(cypher, limit=limit)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "hint": "the graph may not be built yet"}


@mcp.tool()
def threads_open(limit: int = 25) -> dict[str, Any]:
    """List the owner's OPEN loops — current, grounded decisions and commitments that nothing
    later has superseded — most-stale first, each cited by spine seq. Use this to answer
    "what's still open / unresolved for me?". Only facts the consolidation gate GROUNDED
    appear here; if empty, either nothing is open or the consolidation pass hasn't run.
    """
    from ..consolidate import open_threads
    return {"threads": open_threads(SpineStore(), limit=max(1, min(int(limit), 100))),
            "provenance": "each thread is a grounded consolidation record; cite its `seq` (and `source_seqs`)."}


@mcp.tool()
def commitments_due(within_days: int | None = None, limit: int = 50) -> dict[str, Any]:
    """Return the owner's commitment ledger — grounded promises that carry a due date,
    earliest-due first. `within_days` (optional) limits to those due within that many days
    from now. Each is cited by spine seq. Answers "what have I promised, and by when?".
    """
    from ..consolidate import due_commitments
    before = None
    if within_days is not None:
        from datetime import datetime, timedelta, timezone
        before = (datetime.now(timezone.utc) + timedelta(days=int(within_days))).isoformat()
    return {"commitments": due_commitments(SpineStore(), before_iso=before, limit=max(1, min(int(limit), 200))),
            "provenance": "each commitment is a grounded consolidation record; cite its `seq`."}


@mcp.tool()
def contradictions_pending(limit: int = 25) -> dict[str, Any]:
    """Surface unresolved self-contradictions — subjects on which the owner has more than one
    live decision. These are FLAGGED for review, never auto-resolved: each names the
    conflicting decision seqs. Answers "where have I contradicted myself?".
    """
    from ..consolidate import pending_contradictions
    return {"contradictions": pending_contradictions(SpineStore(), limit=max(1, min(int(limit), 100))),
            "provenance": "each is a consolidation contradiction record; the conflicting decisions are cited by seq."}


def run() -> None:
    mcp.run()  # stdio transport


if __name__ == "__main__":
    run()
