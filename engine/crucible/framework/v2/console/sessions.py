"""console.sessions — first-class, operator-managed engagement SESSIONS (F2).

A "session" used to be only a chat transcript. This promotes it to a durable, renamable, deletable object
the operator manages: a named container linking the runs (and the chat transcript) of one line of work, so
several engagements can be organised, reopened, renamed, and removed from history at will.

Persistence: ``<VIGIL_LIVE_DIR>/sessions/<id>/session.json`` (dir 0700, file 0600, atomic tmp+rename). The
registry lives on the operator's machine next to the chat transcripts; it stores operator free-text (a name)
+ run pointers, never a secret.

Ordering coordinate: a MONOTONIC per-registry ``seq`` (NOT wallclock). It is the per-session graph
partition's coordinate (the graph forbids wallclock/rng) — so ``created_seq``/``updated_seq`` are
counter-derived. A separate wallclock ``updated_ts`` drives UI sort only.

Per-session GRAPH (wired, not planned): every session owns a graph PARTITION keyed by its id, materialised
by the DEFAULT embedded (file-backed) ``graph.store`` — a PURE, ONE-WAY projection of the append-only signed
spine of the session's engagement(s). ``project_session_graph`` (re)builds it from spine events ONLY (no
wallclock/rng), so the same spine yields a byte-identical partition. The load-bearing invariant: NOTHING
here is EVER read back into a tier / grant / authorization / FACT — the store structurally exposes no such
surface; this module only PROJECTS (write) and READS nodes/edges for the UI/handoff. A partition is
rebuildable, disposable state: dropping it loses no authority (the spine, the sole authority, is untouched).
Neo4j is an OPTIONAL backend behind the SAME interface — its sealed password reaches this plane only via the
sovereign check-secret broker's env delivery — and is NEVER required to run; the embedded store is the default.

Authority: the registry mints NO facts, reads NO tier/grant, and authorizes nothing. Creating / renaming /
deleting a session changes no finding and no gate. Deletion is fail-safe: SOFT tombstones (retains the chat
transcript, the linked run metas, and — always — the append-only signed spine); HARD additionally removes the
registry entry and drops the rebuildable per-session graph partition, but never touches the spine or a FACT.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from . import actions

_MAX_ID = 128
_MAX_NAME = 200
_MAX_LIST = 500
_KINDS = ("engagement", "chat", "mixed")

# The console runs on a ThreadingHTTPServer (one handler thread per request), so every registry MUTATION
# (mint a seq, write a record) must be serialised in-process — otherwise concurrent creates race the seq
# counter (duplicate/non-monotonic ids, and a shared temp file → a crash). A reentrant lock lets a public
# mutator call another (ensure_session → create_session) without deadlocking. Reads are lock-free (a torn
# read is tolerated). Each atomic write also uses a UNIQUE temp (mkstemp), so even an unlocked path never
# collides on a shared temp name.
_LOCK = threading.RLock()


def _live_dir() -> Path:
    """The operator-machine base (same ``.vigil-live`` the chat transcripts + live plane use)."""
    return Path(os.environ.get("VIGIL_LIVE_DIR") or ".vigil-live")


def _sessions_dir() -> Path:
    d = _live_dir() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)                 # operator free-text engagement context is not world-readable
    except OSError:
        pass
    return d


def _safe_session_id(raw: str) -> str:
    """Path-component guard (no separators / .. / leading dot — no traversal) + a length cap, so a
    character-safe but over-long id is a clean ValueError (→ 404), never an OSError deep in a write."""
    rid = actions._safe_run_id(raw)        # reuse the console's one traversal guard
    if len(rid) > _MAX_ID:
        raise ValueError(f"session id too long (> {_MAX_ID})")
    return rid


def _safe_name(raw: str) -> str:
    """A display name: strip, drop control chars (JSON/log/line safety), cap length. Empty is allowed
    (the UI shows a fallback); a name is never a path component, so no traversal concern."""
    s = "".join(c for c in str(raw or "") if c == " " or (c.isprintable() and c not in "\r\n\t"))
    return s.strip()[:_MAX_NAME]


def _session_path(session_id: str) -> Path:
    return _sessions_dir() / _safe_session_id(session_id) / "session.json"


def _seq_path() -> Path:
    return _sessions_dir() / ".seq"


def _next_seq() -> int:
    """A monotonic, UNIQUE per-registry counter (NOT wallclock). The read-increment-write is serialised
    under ``_LOCK`` so concurrent handler threads each get a distinct, strictly increasing value (this is
    the F3/F4 graph coordinate — duplicates/regressions would corrupt it). The write goes to a UNIQUE temp
    then an atomic replace; a missing/corrupt counter restarts at 0. Fail-safe: an I/O error on the persist
    is swallowed and the in-memory next value is still returned (the counter may briefly not advance on
    disk, but a handler never 500s and the returned value is still unique within the lock hold)."""
    with _LOCK:
        p = _seq_path()
        try:
            cur = int(p.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            cur = 0
        nxt = cur + 1
        try:
            fd, tmp = tempfile.mkstemp(prefix=".seq.", dir=str(_sessions_dir()))
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(str(nxt))
            os.replace(tmp, p)
        except OSError:
            pass                       # never raise a persist error into a request handler
        return nxt


def _read(session_id: str) -> Optional[dict]:
    try:
        rec = json.loads(_session_path(session_id).read_text(encoding="utf-8"))
        return rec if isinstance(rec, dict) else None
    except (OSError, ValueError):
        return None


def _write(rec: dict) -> None:
    """Atomically persist a session record (0600 file under a 0700 per-session dir). Uses a UNIQUE temp in
    the target dir (mkstemp) so concurrent writers never collide on a shared temp name, then an atomic
    replace. Called under ``_LOCK`` by every mutator."""
    p = _session_path(rec["id"])
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p.parent, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".session.", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(rec, fh, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _public(rec: dict) -> dict:
    """The UI-facing view of a session record (all fields are non-secret)."""
    return {
        "id": rec.get("id", ""),
        "name": rec.get("name", "") or "(unnamed session)",
        "kind": rec.get("kind", "engagement"),
        "run_ids": list(rec.get("run_ids", []) or []),
        "slug": rec.get("slug", ""),
        "connections": list(rec.get("connections", []) or []),
        "deleted": bool(rec.get("deleted", False)),
        "created_seq": int(rec.get("created_seq", 0)),
        "updated_seq": int(rec.get("updated_seq", 0)),
        "updated": float(rec.get("updated_ts", 0.0)),
    }


# --- CRUD ------------------------------------------------------------------------------------------

def create_session(*, name: str = "", kind: str = "engagement", session_id: Optional[str] = None) -> dict:
    """Create a new named session. ``session_id`` defaults to a fresh path-safe id. Returns
    ``{"ok": True, "session": <public>}`` or ``{"error": ...}`` (fail-closed on an unsafe id/kind)."""
    if kind not in _KINDS:
        return {"error": f"unknown session kind {kind!r} (expected one of {list(_KINDS)})"}
    with _LOCK:                        # seq-mint + existence-check + write is ONE atomic critical section
        seq = _next_seq()
        # an AUTO-minted id appends the (unique) seq so two creates never collide on _new_run_id()'s
        # timestamp; a caller-supplied id (ensure_session's chat id) is used verbatim.
        sid = session_id if session_id is not None else f"{actions._new_run_id()}-s{seq}"
        try:
            sid = _safe_session_id(sid)
        except ValueError as e:
            return {"error": str(e)}
        if _read(sid) is not None:
            return {"error": f"session {sid!r} already exists"}
        now = time.time()
        rec = {"id": sid, "name": _safe_name(name), "kind": kind, "run_ids": [], "slug": "",
               "connections": [], "deleted": False,
               "created_seq": seq, "updated_seq": seq, "created_ts": now, "updated_ts": now}
        _write(rec)
        return {"ok": True, "session": _public(rec)}


def ensure_session(session_id: str, *, kind: str = "chat", name: str = "") -> dict:
    """Get-or-create the session ``session_id`` (used by chat_send + a direct engagement launch so every
    line of work is a first-class session). Returns the public record."""
    sid = _safe_session_id(session_id)
    with _LOCK:
        rec = _read(sid)
        if rec is None:
            create_session(name=name, kind=kind, session_id=sid)
            rec = _read(sid) or {}
        return _public(rec)


def rename_session(session_id: str, name: str) -> dict:
    sid = _safe_session_id(session_id)
    with _LOCK:
        rec = _read(sid)
        if rec is None:
            return {"error": f"no such session {sid!r}"}
        rec["name"] = _safe_name(name)
        rec["updated_seq"] = _next_seq()
        rec["updated_ts"] = time.time()
        _write(rec)
        return {"ok": True, "session": _public(rec)}


def delete_session(session_id: str, *, hard: bool = False) -> dict:
    """SOFT (default): tombstone — the chat transcript, linked run metas, and the append-only spine are
    all retained. HARD: additionally remove the registry entry and drop the rebuildable per-session graph
    partition. Neither ever touches the signed spine or a FACT."""
    sid = _safe_session_id(session_id)
    with _LOCK:
        rec = _read(sid)
        if rec is None:
            return {"error": f"no such session {sid!r}"}
        if hard:
            p = _session_path(sid)
            try:
                p.unlink(missing_ok=True)
                p.parent.rmdir()           # remove the now-empty per-session dir; ignore if not empty
            except OSError:
                pass
            # Drop the rebuildable per-session graph PARTITION — a ONE-WAY projection of the spine. The signed
            # spine (the authority) is NEVER touched; dropping a projection loses no authority or FACT.
            try:
                _open_graph_store().drop_partition(sid)
            except Exception:  # noqa: BLE001 — a projection is disposable; a drop failure never blocks delete
                pass
            return {"ok": True, "deleted": "hard", "id": sid}
        rec["deleted"] = True
        rec["updated_seq"] = _next_seq()
        rec["updated_ts"] = time.time()
        _write(rec)
        return {"ok": True, "deleted": "soft", "session": _public(rec)}


def link_run(session_id: str, run_id: str, *, slug: str = "") -> dict:
    """Attach a run (and its charter slug) to a session — called when a run launches into a session.
    Idempotent (dedupe by run_id); a chat session that gains an engagement run becomes ``mixed``."""
    sid = _safe_session_id(session_id)
    rid = actions._safe_run_id(run_id)     # validate the run id BEFORE taking the lock (raises → 404)
    with _LOCK:
        rec = _read(sid)
        if rec is None:                    # the launcher may run before an explicit create → ensure it
            create_session(kind="engagement", session_id=sid)
            rec = _read(sid) or {}
        runs = list(rec.get("run_ids", []) or [])
        if rid not in runs:
            runs.append(rid)
        rec["run_ids"] = runs
        if slug:
            rec["slug"] = str(slug)
        if rec.get("kind") == "chat" and rid:
            rec["kind"] = "mixed"
        rec["updated_seq"] = _next_seq()
        rec["updated_ts"] = time.time()
        _write(rec)
        result = {"ok": True, "session": _public(rec)}
    # The per-session graph PARTITION tracks the session's runs: re-project it (best-effort, OUTSIDE the
    # registry lock) from the append-only spine now that a run is linked. A projection failure never breaks
    # the link — the partition is a rebuildable derived view, and the spine (the authority) is untouched.
    _try_project_session_graph(sid)
    return result


# --- per-session GRAPH partition (a pure, ONE-WAY projection of the signed spine) -------------------
# Every session owns a graph PARTITION keyed by its id, materialised by the DEFAULT embedded (file-backed)
# graph.store as a PURE projection of the append-only spine of the session's engagement(s): same spine in →
# byte-identical partition out (no wallclock/rng). The load-bearing invariant is ONE-WAY — nothing here is
# EVER read back into a tier/grant/authorization/FACT. The store structurally exposes no such surface; this
# module only PROJECTS (write) and READS nodes/edges for the UI/handoff. A partition is rebuildable,
# disposable state: dropping it loses no authority (the spine, the sole authority, is untouched).

_GRAPH_BACKEND_ENV = "VIGIL_GRAPH_BACKEND"


def _graph_dir() -> Path:
    """The operator-machine base for per-session graph partitions (next to the sessions registry + chats)."""
    d = _live_dir() / "graph"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)                 # a projection can mirror non-public engagement structure
    except OSError:
        pass
    return d


def _open_graph_store():
    """The DEFAULT per-session graph backend: the embedded, file-backed store (no external DB required).

    Neo4j is an OPTIONAL backend behind the SAME interface, selected only when the operator has opted in
    (``VIGIL_GRAPH_BACKEND=neo4j``) AND sealed Neo4j creds are present in this plane's env (delivered by
    ``vigil up`` from the sovereign Settings / check-secret broker — never argv, never logged). Neo4j is a
    documented scaffold today, so if it cannot be constructed we fail SAFE back to the embedded default
    (honest omission): the embedded store is always the working default and Neo4j is never required to run."""
    if (os.environ.get(_GRAPH_BACKEND_ENV) or "").strip().lower() == "neo4j":
        uri = (os.environ.get("NEO4J_URI") or "").strip()
        user = (os.environ.get("NEO4J_USERNAME") or "").strip()
        pw = (os.environ.get("NEO4J_PASSWORD") or "").strip()
        if uri and user and pw:
            try:
                from ..graph.store import Neo4jGraphStore
                return Neo4jGraphStore(uri, auth=(user, pw))
            except Exception:  # noqa: BLE001 — scaffold/unreachable ⇒ honest omission, embedded default
                pass
    from ..graph.store import EmbeddedGraphStore
    return EmbeddedGraphStore(_graph_dir())


def _session_engagements(rec: dict) -> list[str]:
    """The engagement slug(s) whose spine a session projects: the session's own ``slug`` plus each linked
    run's ``meta.json`` slug. Deterministic (sorted, deduped). A read error on a run meta is skipped (the
    projection stays total). Never a secret — a slug is the charter engagement name."""
    slugs: set[str] = set()
    top = str(rec.get("slug") or "").strip()
    if top:
        slugs.add(top)
    for rid in (rec.get("run_ids", []) or []):
        try:
            meta = json.loads((actions.run_dir(str(rid)) / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(meta, dict):
            sl = str(meta.get("slug") or "").strip()
            if sl:
                slugs.add(sl)
    return sorted(slugs)


def session_graph_partition(session_id: str) -> str:
    """The graph PARTITION key for a session — its path-safe id. A POINTER only: resolving it to nodes/edges
    is a pure re-projection of the spine (``session_graph``); nothing is ever read back as an authority."""
    return _safe_session_id(session_id)


def project_session_graph(session_id: str) -> dict:
    """(Re)build the session's graph PARTITION as a PURE, ONE-WAY projection of the signed spine.

    A FULL rebuild from the append-only spine events of the session's engagement(s) — a pure function of
    those events (no wallclock/rng), so the same spine yields a byte-identical partition. The projection
    NEVER reads a tier/grant/FACT back (the store has no such surface); it only WRITES the partition and
    returns counts + the partition pointer for the UI/handoff. Total + fail-safe: an unregistered slug or a
    spine read error is skipped, never raised. Returns ``{ok, session_id, partition, engagements, nodes,
    edges, backend}`` or ``{error}`` for an unknown session."""
    sid = _safe_session_id(session_id)
    rec = _read(sid)
    if rec is None:
        rec = _legacy_chat_entry(sid)      # a legacy chat has no linked runs → an (empty) but valid partition
    if rec is None:
        return {"error": f"no such session {sid!r}"}
    slugs = _session_engagements(rec)
    events: list = []
    if slugs:
        from ..agents.blackboard import open_blackboard   # lazy: only touch the spine when projecting
        bb = open_blackboard()
        try:
            for slug in slugs:
                try:
                    # include_superseded=True → the FULL audit history so the projection carries the
                    # supersedes edges; project_events sorts by spine id, so the read order never matters.
                    events.extend(bb.read(engagement=slug, include_superseded=True, limit=100_000))
                except Exception:  # noqa: BLE001 — unregistered slug / read error ⇒ skip (total)
                    continue
        finally:
            try:
                bb.close()
            except Exception:  # noqa: BLE001
                pass
    store = _open_graph_store()
    store.project_from_spine(events, partition=sid)      # one-way WRITE; the spine is never mutated
    return {"ok": True, "session_id": sid, "partition": sid, "engagements": slugs,
            "nodes": len(store.nodes(sid)), "edges": len(store.edges(sid)),
            "backend": type(store).__name__}


def _try_project_session_graph(session_id: str) -> None:
    """Best-effort projection: the partition is a rebuildable derived view, so a projection failure (an
    absent spine, an unavailable backend) must NEVER break a registry mutation or a read. Swallow all."""
    try:
        project_session_graph(session_id)
    except Exception:  # noqa: BLE001
        pass


def session_graph(session_id: str, *, project: bool = True) -> dict:
    """The session's partition nodes/edges — the UI/handoff view. With ``project=True`` (default) it first
    re-projects from the spine so the view is current. READ-ONLY: nothing returned here is ever an authority
    (the graph mints nothing, grants nothing). Total: an unknown session yields an empty partition."""
    sid = _safe_session_id(session_id)
    if project:
        _try_project_session_graph(sid)
    store = _open_graph_store()
    return {"partition": sid, "nodes": store.nodes(sid), "edges": store.edges(sid)}


def open_threads(session_id: str) -> list[dict]:
    """A HANDOFF hint: the session's runs NOT in a terminal state (``done``/``error``/…) — the unfinished
    lines of work a successor should pick up. Derived from each linked run's ``meta.json`` (deterministic
    given the metas); ADVISORY only — it mints nothing and reads no authority. Total: an unreadable meta is
    treated as an open thread (status unknown), never a raise."""
    sid = _safe_session_id(session_id)
    rec = _read(sid)
    if rec is None:
        return []
    terminal = {"done", "complete", "completed", "finished", "error", "failed", "cancelled", "canceled"}
    out: list[dict] = []
    for rid in (rec.get("run_ids", []) or []):
        status, target, slug = "unknown", None, None
        try:
            meta = json.loads((actions.run_dir(str(rid)) / "meta.json").read_text(encoding="utf-8"))
            if isinstance(meta, dict):
                status = str(meta.get("status", "unknown") or "unknown")
                target = meta.get("target")
                slug = meta.get("slug")
        except (OSError, ValueError):
            pass
        if status.strip().lower() not in terminal:
            out.append({"run_id": str(rid), "status": status, "target": target, "slug": slug})
    return out


_MAX_CONNECTIONS = 32


def connect_session(session_id: str, other_id: str) -> dict:
    """F4: CONNECT session A → B so A's runs may draw on B's knowledge as PRIORS. The connection is
    DIRECTIONAL (A reads B; B does not read A unless separately connected) and the POST that calls this
    IS the operator's consent. It stores only B's id in A's ``connections`` set — a read-time scope, NOT a
    graph merge: nothing of B is copied into A, so ``disconnect`` re-isolates A instantly. Bounded; a
    session cannot connect to itself; both ids are path-safe. Never mints a fact; never widens scope."""
    a = _safe_session_id(session_id)
    b = _safe_session_id(other_id)
    if a == b:
        return {"error": "a session cannot connect to itself"}
    with _LOCK:
        rec = _read(a)
        if rec is None:
            return {"error": f"no such session {a!r}"}
        if _read(b) is None and _legacy_chat_entry(b) is None:
            return {"error": f"no such session {b!r} to connect to"}
        conns = list(rec.get("connections", []) or [])
        if b in conns:
            return {"ok": True, "session": _public(rec)}          # idempotent
        if len(conns) >= _MAX_CONNECTIONS:
            return {"error": f"too many connections (max {_MAX_CONNECTIONS})"}
        conns.append(b)
        rec["connections"] = conns
        rec["updated_seq"] = _next_seq()
        rec["updated_ts"] = time.time()
        _write(rec)
        return {"ok": True, "session": _public(rec)}


def disconnect_session(session_id: str, other_id: str) -> dict:
    """F4: DISCONNECT A → B. Because the connection is only a read-time scope entry (B was never copied
    into A), removing it re-isolates A on its NEXT retrieval — no residue. Idempotent."""
    a = _safe_session_id(session_id)
    b = _safe_session_id(other_id)
    with _LOCK:
        rec = _read(a)
        if rec is None:
            return {"error": f"no such session {a!r}"}
        conns = [c for c in (rec.get("connections", []) or []) if c != b]
        rec["connections"] = conns
        rec["updated_seq"] = _next_seq()
        rec["updated_ts"] = time.time()
        _write(rec)
        return {"ok": True, "session": _public(rec)}


def connections_of(session_id: str) -> list[str]:
    """A session's CONSENTED connected-session ids — the partitions a ``vigil engage --session <id>`` run may
    UNION as priors (passed as ``--connect`` by the console→live-engine bridge for a graph-backed loopback
    run). EVERY returned id is re-validated through ``_safe_session_id`` (defense in depth: these flow into a
    subprocess argv, so the safety must not rest solely on ``connect_session`` being the only writer — a
    tampered/legacy entry is dropped, never emitted). Total: [] for an unknown/legacy/unsafe session."""
    try:
        sid = _safe_session_id(session_id)
    except ValueError:
        return []
    rec = _read(sid)
    if not rec:
        return []
    out: list[str] = []
    for c in (rec.get("connections", []) or []):
        try:
            out.append(_safe_session_id(c))
        except ValueError:
            continue                          # drop a tampered/unsafe entry — never let it reach the argv
    return out


def get_session(session_id: str) -> dict:
    """One session for the UI. Returns the registry record, or — for a legacy chat with no registry
    entry — a synthesized (non-persisted) view so old chats still open. Fail-closed: an unsafe id raises
    ValueError (→ 404); an unknown id returns ``{"error": ...}``."""
    sid = _safe_session_id(session_id)
    rec = _read(sid)
    if rec is not None:
        return {"ok": True, "session": _public(rec)}
    legacy = _legacy_chat_entry(sid)
    if legacy is not None:
        return {"ok": True, "session": legacy}
    return {"error": f"no such session {sid!r}"}


# --- listing (+ legacy chat adoption, read-only: synthesized, never written) -----------------------

def _legacy_chat_entry(chat_id: str) -> Optional[dict]:
    """Synthesize a public session view for a chat transcript that predates the registry (so old chats
    appear + open). NOT persisted here — it materialises only when the operator renames/links it."""
    p = _live_dir() / "chats" / (chat_id + ".jsonl")
    if not p.exists():
        return None
    name, turns = "", 0
    try:
        for ln in p.read_text(encoding="utf-8").split("\n"):
            ln = ln.strip()
            if not ln:
                continue
            turns += 1
            if not name:
                try:
                    obj = json.loads(ln)
                    if obj.get("role") == "user" and obj.get("text"):
                        name = str(obj["text"])[:80]
                except (ValueError, TypeError):
                    pass
    except OSError:
        return None
    return {"id": chat_id, "name": name or "(chat)", "kind": "chat", "run_ids": [], "slug": "",
            "connections": [], "deleted": False, "created_seq": 0, "updated_seq": 0,
            "updated": p.stat().st_mtime, "legacy": True}


def list_sessions(*, include_deleted: bool = False) -> dict:
    """All sessions newest-first: registry entries + synthesized legacy chat sessions (a chat with no
    registry entry). Soft-deleted sessions are hidden unless ``include_deleted``. Never a secret."""
    out: dict[str, dict] = {}
    for d in _sessions_dir().glob("*/session.json"):
        try:
            rec = json.loads(d.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict) or "id" not in rec:
            continue
        if rec.get("deleted") and not include_deleted:
            continue
        out[str(rec["id"])] = _public(rec)
    # adopt legacy chats not already represented (read-only synthesis)
    chats = _live_dir() / "chats"
    if chats.is_dir():
        for f in chats.glob("*.jsonl"):
            if f.stem in out:
                continue
            entry = _legacy_chat_entry(f.stem)
            if entry is not None:
                out[f.stem] = entry
    rows = sorted(out.values(), key=lambda r: r.get("updated", 0.0), reverse=True)[:_MAX_LIST]
    return {"sessions": rows}
