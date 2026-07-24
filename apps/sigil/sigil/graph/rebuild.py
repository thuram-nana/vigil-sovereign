"""Deterministic rebuild of the Kùzu graph from the spine (SIGIL §6.2, vigil-apex mirror).

Replays the append-only spine in seq order into a FRESH Kùzu database under `staging/`,
then atomically swaps it in as `current/`. The graph is therefore always regenerable from
the signed spine, never edited in place — and because the replay is order-deterministic and
extraction-free, two rebuilds over the same spine produce identical node/edge sets. Each
node records the spine seq + entry_hash that minted it, so a graph answer cites memory.

Mirror health = (highest seq replayed) vs (spine head seq); they match ⇒ the view is current.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

from ..config import GRAPH_DIR
from ..spine.store import SpineStore
from .schema import DDL, normalize_project

CURRENT = GRAPH_DIR / "current"
STAGING = GRAPH_DIR / "staging"
_DB = "db.kuzu"

_SESSION_KINDS = ("message", "tool_call", "tool_result", "session")


@dataclass
class MirrorHealth:
    rebuilt_seq: int
    spine_head_seq: int
    projects: int
    sessions: int
    documents: int
    commits: int
    edges: int

    @property
    def in_sync(self) -> bool:
        return self.rebuilt_seq == self.spine_head_seq

    def as_dict(self) -> dict:
        d = asdict(self)
        d["in_sync"] = self.in_sync
        return d


def _accumulate(store: SpineStore):
    """One pass over the spine → structural entity dicts (deterministic, extraction-free)."""
    sessions: dict[str, dict] = {}
    documents: dict[str, dict] = {}
    commits: dict[str, dict] = {}
    max_seq = -1
    for r in store.iter_records():
        r = store.decrypted(r)   # G1 slice-4: plaintext content for the graph (locked vault raises before the destructive swap)
        max_seq = r.seq
        proj = normalize_project(r.payload.get("project") or "")
        k = r.kind
        if k in _SESSION_KINDS:
            sid = r.payload.get("session_id")
            if not sid:
                continue
            s = sessions.get(sid)
            if s is None:
                s = sessions[sid] = {
                    "title": None, "project": proj, "messages": 0,
                    "first_seq": r.seq, "last_seq": r.seq, "first_ts": r.ts, "last_ts": r.ts,
                    "anchor_seq": r.seq, "anchor_hash": r.entry_hash,
                }
            s["last_seq"], s["last_ts"] = r.seq, r.ts
            if proj != "unknown" and s["project"] == "unknown":
                s["project"] = proj
            if k == "message":
                s["messages"] += 1
            elif k == "session" and r.payload.get("text"):
                s["title"] = r.payload["text"][:200]   # latest ai-title wins (seq order)
        elif k == "document":
            path = r.payload.get("path")
            if not path:
                continue
            d = documents.get(path)
            if d is None:
                d = documents[path] = {
                    "title": r.payload.get("title") or Path(path).name, "project": proj,
                    "chunks": 0, "anchor_seq": r.seq, "anchor_hash": r.entry_hash,
                }
            d["chunks"] += 1
        elif k == "commit":
            h = r.payload.get("hash")
            if h and h not in commits:
                commits[h] = {
                    "repo": normalize_project(r.payload.get("repo") or ""),
                    "subject": (r.payload.get("subject") or "")[:300],
                    "author": r.actor, "date": r.ts,
                    "anchor_seq": r.seq, "anchor_hash": r.entry_hash,
                }
    return sessions, documents, commits, max_seq


def _project_rollup(sessions, documents, commits) -> dict[str, dict]:
    projects: dict[str, dict] = {}

    def p(name: str) -> dict:
        return projects.setdefault(name, {"sessions": 0, "commits": 0, "documents": 0, "messages": 0})

    for s in sessions.values():
        row = p(s["project"])
        row["sessions"] += 1
        row["messages"] += s["messages"]
    for d in documents.values():
        p(d["project"])["documents"] += 1
    for c in commits.values():
        p(c["repo"])["commits"] += 1
    return projects


def rebuild(store: SpineStore | None = None) -> MirrorHealth:
    import kuzu

    store = store or SpineStore()
    sessions, documents, commits, max_seq = _accumulate(store)
    projects = _project_rollup(sessions, documents, commits)

    if STAGING.exists():
        shutil.rmtree(STAGING)
    STAGING.mkdir(parents=True, exist_ok=True)
    db = kuzu.Database(str(STAGING / _DB))
    conn = kuzu.Connection(db)
    for stmt in DDL:
        conn.execute(stmt)

    for name, row in projects.items():
        conn.execute(
            "CREATE (:Project {name:$name, sessions:$s, commits:$c, documents:$d, messages:$m})",
            parameters={"name": name, "s": row["sessions"], "c": row["commits"],
                        "d": row["documents"], "m": row["messages"]})
    edges = 0
    for sid, s in sessions.items():
        conn.execute(
            "CREATE (:Session {id:$id, title:$t, project:$p, messages:$m, first_seq:$fs, "
            "last_seq:$ls, first_ts:$ft, last_ts:$lt, anchor_seq:$asq, anchor_hash:$ah})",
            parameters={"id": sid, "t": s["title"] or "", "p": s["project"], "m": s["messages"],
                        "fs": s["first_seq"], "ls": s["last_seq"], "ft": s["first_ts"],
                        "lt": s["last_ts"], "asq": s["anchor_seq"], "ah": s["anchor_hash"]})
        conn.execute(
            "MATCH (x:Session),(p:Project) WHERE x.id=$id AND p.name=$proj "
            "CREATE (x)-[:IN_PROJECT_S]->(p)", parameters={"id": sid, "proj": s["project"]})
        edges += 1
    for path, d in documents.items():
        conn.execute(
            "CREATE (:Document {path:$path, title:$t, project:$p, chunks:$c, anchor_seq:$asq, anchor_hash:$ah})",
            parameters={"path": path, "t": d["title"], "p": d["project"], "c": d["chunks"],
                        "asq": d["anchor_seq"], "ah": d["anchor_hash"]})
        conn.execute(
            "MATCH (x:Document),(p:Project) WHERE x.path=$path AND p.name=$proj "
            "CREATE (x)-[:IN_PROJECT_D]->(p)", parameters={"path": path, "proj": d["project"]})
        edges += 1
    for h, c in commits.items():
        conn.execute(
            "CREATE (:Commit {hash:$h, repo:$r, subject:$s, author:$a, date:$d, anchor_seq:$asq, anchor_hash:$ah})",
            parameters={"h": h, "r": c["repo"], "s": c["subject"], "a": c["author"], "d": c["date"],
                        "asq": c["anchor_seq"], "ah": c["anchor_hash"]})
        conn.execute(
            "MATCH (x:Commit),(p:Project) WHERE x.hash=$h AND p.name=$proj "
            "CREATE (x)-[:IN_PROJECT_C]->(p)", parameters={"h": h, "proj": c["repo"]})
        edges += 1

    conn.close()
    db.close()

    mh = MirrorHealth(rebuilt_seq=max_seq, spine_head_seq=store.next_seq - 1,
                      projects=len(projects), sessions=len(sessions),
                      documents=len(documents), commits=len(commits), edges=edges)
    # manifest carries the true replay high-water (max seq CONSUMED) — nodes anchor at their
    # FIRST record, so a node-anchor max would understate how far the rebuild actually read.
    # Written into staging so it swaps in atomically with the db.
    (STAGING / "manifest.json").write_text(json.dumps(mh.as_dict()), encoding="utf-8")

    # atomic-ish swap: replace current/ with the freshly-built staging/
    if CURRENT.exists():
        shutil.rmtree(CURRENT)
    STAGING.rename(CURRENT)
    return mh
