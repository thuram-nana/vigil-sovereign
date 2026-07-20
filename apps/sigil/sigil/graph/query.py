"""Read-only queries over the current Kùzu graph (powers the graph.* MCP tools).

Opens `current/` read-only. Every returned entity carries its spine anchor (seq + hash) so
a graph answer resolves back to tamper-evident memory. `query()` is a guarded Cypher
passthrough: writes are refused (both by a keyword guard and by the read-only connection).
"""
from __future__ import annotations

from typing import Any

from .rebuild import CURRENT, _DB

_WRITE_KW = ("CREATE", "SET ", "DELETE", "MERGE", "DROP", "ALTER", "COPY", "INSTALL", "ATTACH")


class GraphUnavailable(RuntimeError):
    """The graph has not been rebuilt yet (no current/ db)."""


def _conn():
    import kuzu
    dbfile = CURRENT / _DB
    if not dbfile.exists():
        raise GraphUnavailable("graph not built yet — run `sigil graph` to rebuild it from the spine")
    db = kuzu.Database(str(dbfile), read_only=True)
    return kuzu.Connection(db)


def _rows(conn, cypher: str, params: dict | None = None) -> list[list[Any]]:
    res = conn.execute(cypher, parameters=params or {})
    out = []
    while res.has_next():
        out.append(res.get_next())
    return out


def query(cypher: str, limit: int = 50) -> dict[str, Any]:
    """Run a READ-ONLY Cypher query and return columns + rows. Writes are refused."""
    up = cypher.upper()
    if any(kw in up for kw in _WRITE_KW):
        return {"error": "read-only: write/DDL statements are refused", "cypher": cypher}
    conn = _conn()
    if " LIMIT " not in up:
        cypher = f"{cypher.rstrip().rstrip(';')} LIMIT {max(1, min(int(limit), 500))}"
    res = conn.execute(cypher, parameters={})
    cols = res.get_column_names()
    rows = []
    while res.has_next():
        rows.append(res.get_next())
    return {"columns": cols, "rows": rows, "count": len(rows)}


def _one(conn, cypher, params, keys):
    r = _rows(conn, cypher, params)
    return [dict(zip(keys, row)) for row in r]


def entity(name: str) -> dict[str, Any]:
    """Resolve `name` to a structural entity and return it with its neighbours + spine anchor.
    Tries Project → Session(id) → Commit(hash prefix) → Document(path substring)."""
    conn = _conn()
    # Project
    proj = _one(conn, "MATCH (p:Project) WHERE p.name=$n RETURN p.name,p.sessions,p.commits,p.documents,p.messages",
                {"n": name}, ["name", "sessions", "commits", "documents", "messages"])
    if proj:
        sessions = _one(conn,
            "MATCH (s:Session)-[:IN_PROJECT_S]->(p:Project) WHERE p.name=$n "
            "RETURN s.id,s.title,s.messages,s.last_ts,s.anchor_seq ORDER BY s.last_seq DESC LIMIT 25",
            {"n": name}, ["id", "title", "messages", "last_ts", "anchor_seq"])
        commits = _one(conn,
            "MATCH (c:Commit)-[:IN_PROJECT_C]->(p:Project) WHERE p.name=$n "
            "RETURN c.hash,c.subject,c.author,c.date,c.anchor_seq ORDER BY c.anchor_seq DESC LIMIT 25",
            {"n": name}, ["hash", "subject", "author", "date", "anchor_seq"])
        docs = _one(conn,
            "MATCH (d:Document)-[:IN_PROJECT_D]->(p:Project) WHERE p.name=$n "
            "RETURN d.path,d.title,d.chunks,d.anchor_seq LIMIT 25",
            {"n": name}, ["path", "title", "chunks", "anchor_seq"])
        return {"type": "Project", "entity": proj[0],
                "sessions": sessions, "commits": commits, "documents": docs}
    # Session by id
    sess = _one(conn,
        "MATCH (s:Session) WHERE s.id=$n RETURN s.id,s.title,s.project,s.messages,s.first_ts,s.last_ts,"
        "s.first_seq,s.last_seq,s.anchor_hash", {"n": name},
        ["id", "title", "project", "messages", "first_ts", "last_ts", "first_seq", "last_seq", "anchor_hash"])
    if sess:
        return {"type": "Session", "entity": sess[0],
                "hint": "read `episodic_range(start_seq=first_seq, end_seq=last_seq)` for the full session"}
    # Commit by hash prefix
    com = _one(conn,
        "MATCH (c:Commit) WHERE starts_with(c.hash,$n) RETURN c.hash,c.repo,c.subject,c.author,c.date,c.anchor_seq LIMIT 5",
        {"n": name}, ["hash", "repo", "subject", "author", "date", "anchor_seq"])
    if com:
        return {"type": "Commit", "matches": com}
    # Document by path substring
    doc = _one(conn,
        "MATCH (d:Document) WHERE contains(d.path,$n) RETURN d.path,d.title,d.project,d.chunks,d.anchor_seq LIMIT 10",
        {"n": name}, ["path", "title", "project", "chunks", "anchor_seq"])
    if doc:
        return {"type": "Document", "matches": doc}
    return {"type": None, "note": f"no structural entity named/matching '{name}' in the graph"}


def health() -> dict[str, Any]:
    """Node counts of the current graph + how far it trails the spine head."""
    import json

    from ..spine.store import SpineStore
    conn = _conn()

    def n(label: str) -> int:
        r = _rows(conn, f"MATCH (x:{label}) RETURN count(x)")
        return r[0][0] if r else 0

    counts = {lbl: n(lbl) for lbl in ("Project", "Session", "Document", "Commit")}
    manifest = CURRENT / "manifest.json"
    rebuilt_seq = json.loads(manifest.read_text()).get("rebuilt_seq", -1) if manifest.exists() else -1
    head = SpineStore().next_seq - 1
    return {"nodes": counts, "rebuilt_through_seq": rebuilt_seq, "spine_head_seq": head,
            "in_sync": rebuilt_seq == head,
            "note": "the graph is a rebuilt view of the spine; run `sigil graph` to refresh it"}
