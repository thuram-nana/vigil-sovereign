"""Customer-safe engagement AGENT-GRAPH + rich-activity seam — the one format + path the OFFENSE projector
and the SOVEREIGN reader agree on, so the customer Live view can show a LIVE graph of the real sub-agents and
stream their reasoning / tool activity WITHOUT ever crossing the FATAL-2 boundary with code.

This is the richer sibling of :mod:`vigil_core.live_activity`. Where that seam mirrors only the engagement's
high-level PHASE transitions, this seam mirrors the append-only AGENT EVENT SPINE (the blackboard) as a bounded,
customer-safe projection: one row per real recorded blackboard event, carrying ONLY the agent's ROLE, the
event KIND, a provenance ref (the blackboard event id), the delegation edge back to the driving agent, and
whether the step is oracle-verified. From those rows BOTH the live graph (nodes = the real agents/phases that
actually posted, edges = recorded delegation/phase-sequence/attachment) AND the streaming transcript are
DERIVED — the graph is a deterministic fold over the SAME recorded rows, so a node or edge can never show
activity the events do not contain (AS-4a honesty: a quiet engagement reads as quiet, never a fake heartbeat).

WHY HERE. ``vigil_core`` is the only module BOTH planes import, so the emit (the offense graph projector,
offense plane) and the read (the sovereign custui adapter) share ONE definition of the file, its path, and —
crucially — its CUSTOMER-SAFE PROJECTION. Data crosses the plane boundary only as this bounded JSONL file.

CUSTOMER-SAFE BY CONSTRUCTION. A row's ``node`` / ``from`` are ``agent:<role>`` / ``phase:<stage>`` where the
role is on a FIXED allowlist of agent-role names (recon / exploit / critique / grounding / …) and the stage on
the FIXED engagement-stage allowlist; ``kind`` is one of the FIXED event kinds. There is NO free text, NO
target detail, NO IP, NO secret, NO payload excerpt — the projector writes only these enum-ish fields and the
reader DROPS any row whose node/kind is off the allowlist and NORMALISES an unknown agent role to the generic
``agent`` node. So a leak is impossible even if a hostile line is injected directly into the file.

INCREMENTAL + REPLAY. ``seq`` is the row's line index; :func:`read` takes a ``since`` cursor and returns only
rows after it, so the UI streams new activity without re-downloading history (a tightened poll). ``since=-1``
returns the whole recorded stream from the start — the honest REPLAY/scrub of what actually happened, grounded
in the tamper-evident spine (each row's ``ref`` links back to its blackboard event).

GENERATION / EPOCH. ``seq`` is only meaningful WITHIN one run: the slug is per (org, host) and REUSED by every
relaunch, and :func:`reset` unlinks the file so a new run restarts at ``seq`` 0. A viewer holding a stale cursor
from a prior run would therefore mistake a SUFFIX of the new run for a continuation of the old one (splicing two
engagements — an AS-4a violation). So :func:`reset` stamps a fresh GENERATION/EPOCH token (a persisted monotone
counter — deterministic, no wall-clock, no RNG) that :func:`epoch` / :func:`graph` return alongside the cursor;
the sovereign reader compares it to the epoch ITS cursor belongs to and, on a change, resyncs from ``seq`` 0
instead of appending. So a prior generation's cursor can never return a suffix of a new generation as a
continuation.

BOUNDED + FAIL-CLOSED. The reader caps a single read's output, AND caps the TOTAL bytes / lines it will ever
parse from a seam (``_MAX_TOTAL_BYTES`` / ``_MAX_TOTAL_LINES``): an oversized seam reads as EMPTY, so the fold is
never unbounded. Best-effort: emit NEVER raises into the engine; read/graph NEVER raise into the edge (a
missing / corrupt / oversized file reads as empty).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

# ── Agent-role allowlist. The KEYS are the real blackboard ``agent_name`` role constants (see
# framework/v2/agents/*.py ``name = "…"``); the projector maps an unknown name to the generic ``agent`` role, and
# the reader independently normalises anything off this list to ``agent`` too (defense in depth). The VALUES are
# the customer-facing label + a coarse GROUP (recon / exploit / assurance / report / orchestration / engine) so
# the UI can lane the graph the way a Strix run lanes recon/exploit/post-exploit — free of any target detail.
_AGENT_ROLES: "dict[str, tuple[str, str]]" = {
    "recon": ("Reconnaissance agent", "recon"),
    "hypothesis": ("Hypothesis agent", "recon"),
    "memory": ("Memory agent", "support"),
    "planner": ("Planner", "orchestration"),
    "coordinator": ("Coordinator", "orchestration"),
    "autonomy": ("Autonomy driver", "orchestration"),
    "daa": ("Decision agent", "orchestration"),
    "exploit": ("Exploitation agent", "exploit"),
    "tier3-validation": ("Validation agent", "assurance"),
    "critique": ("Critique agent", "assurance"),
    "grounding": ("Grounding critic", "assurance"),
    "provenance": ("Provenance critic", "assurance"),
    "calibration": ("Calibration critic", "assurance"),
    "multi-critic": ("Critic panel", "assurance"),
    "reflection": ("Reflection agent", "assurance"),
    "reporter": ("Reporter", "report"),
    "spine": ("Engine", "engine"),
    "agent": ("Specialist agent", "support"),     # the generic bucket an unknown role normalises to
}

# ── Engagement-stage allowlist. Byte-for-byte the live_activity stage allowlist (framework.v2.phase_ledger
# ORDERED_PHASES); kept here as a literal so this leaf imports no framework. The VALUES are the customer-facing
# stage labels (free of target detail). Also carries the canonical ORDER so the graph's phase backbone is drawn
# in the real engagement sequence.
_STAGES: "dict[str, str]" = {
    "preflight": "Preparing the authorized assessment",
    "intel_recon": "Reviewing reachable services",
    "transfer_priors": "Loading the engagement scope",
    "scan": "Running authorized checks",
    "intel_finalize": "Correlating reconnaissance",
    "assess_findings": "Evaluating observations",
    "chaining": "Chaining attack paths",
    "assess_grounding": "Confirming evidence with the oracle",
    "fusion": "Fusing corroborated findings",
    "defender_pass": "Deriving defensive guidance",
    "reasoning_pass": "Recording the assessment evidence",
}
_STAGE_ORDER: "dict[str, int]" = {name: i for i, name in enumerate(_STAGES)}

# ── Event-kind allowlist → the customer-facing transcript label. The KEYS are the blackboard event kinds
# (framework.v2.agents.models EventKind); a ``phase`` pseudo-kind carries a stage transition. NO payload text is
# ever shown — the label is a FIXED string per kind, so what the customer reads is "what CRUCIBLE did", never a
# raw internal detail.
_EVENT_LABELS: "dict[str, str]" = {
    "phase": "Stage",
    "observation": "Observed a signal",
    "hypothesis": "Formed a hypothesis",
    "plan": "Planned the next step",
    "action": "Took an authorized action",
    "result": "Recorded a result",
    "finding": "Recorded a finding",
    "critique": "Critiqued a finding",
    "decision": "Made a decision",
    "reward": "Scored an outcome",
    "critic_verdict": "Critic returned a verdict",
    "reflection": "Reflected and re-oriented",
    "refusal": "A safety gate refused an action",
    "tool_call": "Requested a tool / sensor",
    "tool_result": "A tool / sensor returned",
    "agent_message": "Coordinated with another agent",
}
# The verified variant of a finding — the one place the label changes on a payload-DERIVED boolean (never text).
_FINDING_VERIFIED_LABEL = "Confirmed a finding (oracle-verified)"

_PHASE_STATUSES = frozenset({"started", "completed", "skipped", "failed", "halted"})
# phase lifecycle status -> the node's DISPLAY status in the graph.
_STATUS_DISPLAY: "dict[str, str]" = {
    "started": "running", "completed": "done", "skipped": "skipped",
    "failed": "failed", "halted": "paused",
}
_EDGE_KINDS = frozenset({"sequence", "delegation", "attach"})

_MAX_READ = 2000          # bound a single read (an engagement spine is ~hundreds of events on the customer path)
_MAX_LINE = 320           # a row is tiny; cap the bytes we ever parse per line
_MAX_ROLE = 32
_MAX_REF = 10 ** 12       # a sane upper bound on a provenance ref (a blackboard event id / phase seq)
# Total-seam fail-closed bounds (defense against an oversized / runaway file: _read_rows / read / graph must honour
# the docstring's "oversized file reads as empty"). _MAX_TOTAL_LINES is a generous ceiling (10x a single read
# window — a customer spine is ~hundreds of events); _MAX_TOTAL_BYTES is the matching byte ceiling at _MAX_LINE
# per row. A seam over EITHER bound reads as [] (fail-closed), so the fold is never unbounded.
_MAX_TOTAL_LINES = 20000
_MAX_TOTAL_BYTES = _MAX_TOTAL_LINES * _MAX_LINE       # == 6_400_000
_MAX_EPOCH = 10 ** 15     # a sane upper bound on the generation/epoch counter (wraps to 1 beyond it)


def _safe_component(slug: str) -> Optional[str]:
    s = str(slug or "")
    if not s or ".." in s or "/" in s or "\\" in s or s.startswith(".") or len(s) > 128:
        return None
    return s


def _path(base: Any, slug: str) -> Optional[Path]:
    comp = _safe_component(slug)
    if comp is None or base is None:
        return None
    return Path(str(base)) / f"{comp}.graph.jsonl"


def _epoch_path(base: Any, slug: str) -> Optional[Path]:
    """The sidecar holding ``slug``'s GENERATION/EPOCH token — a tiny file beside the seam. Kept OUT of the JSONL
    so the row file stays byte-identical (``seq`` = physical line index) and the epoch survives the file's unlink
    on :func:`reset`. Same safe-component gate as the seam path."""
    comp = _safe_component(slug)
    if comp is None or base is None:
        return None
    return Path(str(base)) / f"{comp}.graph.epoch"


def _norm_role(role: Any) -> Optional[str]:
    """A role token iff it is a safe ``[a-z0-9-]`` word within bound — else None. An EMPTY/oversized/odd token is
    rejected; a well-formed but unknown token is accepted here and the reader maps it to the generic ``agent``."""
    r = str(role or "").strip().lower()
    if not r or len(r) > _MAX_ROLE:
        return None
    for ch in r:
        if not (ch.isdigit() or ("a" <= ch <= "z") or ch == "-"):
            return None
    return r


def _node_id(kind: str, token: str) -> Optional[str]:
    """Build a validated node id ``agent:<role>`` / ``phase:<stage>``. None (drop) when the token is unsafe or,
    for a phase node, off the stage allowlist. An unknown AGENT role is normalised to ``agent`` (never dropped —
    a real agent still shows as a real node, just generically labelled)."""
    tok = _norm_role(token)
    if tok is None:
        return None
    if kind == "phase":
        return f"phase:{tok}" if tok in _STAGES else None
    if kind == "agent":
        return f"agent:{tok if tok in _AGENT_ROLES else 'agent'}"
    return None


def _split_node(node_id: Any) -> "Optional[tuple[str, str]]":
    """``"agent:exploit"`` -> ``("agent", "exploit")`` iff it is a well-formed, allowlisted node id, else None."""
    s = str(node_id or "")
    if ":" not in s:
        return None
    kind, _, tok = s.partition(":")
    if kind not in ("agent", "phase"):
        return None
    nid = _node_id(kind, tok)
    if nid is None:
        return None
    k2, _, t2 = nid.partition(":")
    return (k2, t2)


def emit(base: Any, slug: str, node: str, kind: str, *, ts: float, ref: int = 0,
         from_node: str = "", edge: str = "", status: str = "", verified: bool = False) -> None:
    """Append ONE customer-safe graph/activity row for ``slug`` under the shared seam ``base``. ``node`` is the
    node this row is ABOUT (``agent:<role>`` / ``phase:<stage>``), ``kind`` the event kind (or ``phase``),
    ``ref`` the provenance ref (the blackboard event id / phase seq), ``from_node`` + ``edge`` an optional
    recorded edge back to the driving node, ``status`` the phase lifecycle status (phase rows only), ``verified``
    whether an oracle fired for this finding. Only allowlisted node/kind rows are written; anything else is
    silently ignored. Best-effort: NEVER raises (a filesystem error must never perturb the engine). Called by
    the offense graph projector."""
    p = _path(base, slug)
    if p is None or _split_node(node) is None or kind not in _EVENT_LABELS:
        return
    row: "dict[str, Any]" = {"ts": float(ts), "node": str(node), "kind": str(kind)}
    try:
        iref = int(ref)
    except (TypeError, ValueError):
        iref = 0
    if 0 < iref <= _MAX_REF:
        row["ref"] = iref
    if from_node and _split_node(from_node) is not None and str(edge) in _EDGE_KINDS:
        row["from"] = str(from_node)
        row["edge"] = str(edge)
    if status in _PHASE_STATUSES:
        row["status"] = str(status)
    if verified:
        row["verified"] = True
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(row, ensure_ascii=False)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        return


def epoch(base: Any, slug: str) -> int:
    """``slug``'s current GENERATION/EPOCH token — a monotone counter :func:`reset` bumps on every relaunch of the
    reused (org, host) slug. The sovereign reader compares this to the epoch ITS cursor belongs to and, on a
    change, resyncs the client from ``seq`` 0 (a new run began; the prior cursor is a different generation's line
    index, so appending its suffix would splice two engagements). ``0`` when no run has reset the seam yet.
    Deterministic (a persisted counter — NO wall-clock, NO RNG), bounded, fail-closed (an unreadable/odd token
    reads as ``0``)."""
    p = _epoch_path(base, slug)
    if p is None:
        return 0
    try:
        raw = p.read_text(encoding="utf-8")[:32]
    except OSError:
        return 0
    try:
        v = int(raw.strip() or "0")
    except ValueError:
        return 0
    return v if 0 <= v <= _MAX_EPOCH else 0


def _bump_epoch(base: Any, slug: str) -> None:
    """Stamp a fresh generation: the persisted counter + 1 (deterministic — no wall-clock, no RNG), published
    atomically. Best-effort: NEVER raises (a stamp failure just leaves the epoch unchanged — at worst the client
    misses one resync and self-heals on the next poll)."""
    p = _epoch_path(base, slug)
    if p is None:
        return
    nxt = epoch(base, slug) + 1
    if nxt > _MAX_EPOCH:
        nxt = 1
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(str(nxt))
        os.replace(tmp, p)            # atomic publish of the new generation
    except OSError:
        return


def reset(base: Any, slug: str) -> None:
    """Begin a FRESH graph trail for ``slug`` — the engine calls this when a new run attempt starts (preflight),
    so the customer graph shows the CURRENT run, not the concatenation of every past run on the same host (the
    slug is per (org, host), reused across launches). Best-effort: NEVER raises.

    Also BUMPS the GENERATION/EPOCH token (:func:`epoch`) FIRST — BEFORE clearing the rows, so even a reset of a
    not-yet-created seam still moves the epoch — so a reader whose cursor belongs to the PRIOR run detects the
    relaunch and resyncs from ``seq`` 0 instead of appending a suffix of the new run onto the old one. (A reader
    whose cursor is merely beyond the now-shorter file also auto-recovers to the start — see :func:`read` — but
    that alone does NOT catch a new run that has already written MORE rows than the stale cursor; the epoch does.)"""
    p = _path(base, slug)
    if p is None:
        return
    _bump_epoch(base, slug)           # stamp a fresh generation first (deterministic monotone counter)
    try:
        p.unlink()
    except OSError:
        return


def _read_rows(base: Any, slug: str) -> "list[dict[str, Any]]":
    """Every well-formed, customer-safe row for ``slug`` in line (seq) order — the shared, bounded, fail-closed
    parse under both :func:`read` and :func:`graph`. A row whose node/kind is off the allowlist is DROPPED; an
    unknown agent role is normalised to the generic ``agent`` node. Each row is returned as
    ``{seq, ts, node, role, nodekind, kind, status, ref, from, edge, verified}`` — ONLY these fixed fields, so an
    injected extra key never surfaces.

    BOUNDED + FAIL-CLOSED: a seam larger than ``_MAX_TOTAL_BYTES`` reads as EMPTY (the size is checked via stat
    BEFORE any bytes are read, so an oversized file is never loaded), and parsing stops fail-closed if the line
    count would exceed ``_MAX_TOTAL_LINES`` — honouring the module's "oversized file reads as empty" contract so
    neither :func:`read` nor :func:`graph` can ever fold an unbounded number of rows."""
    p = _path(base, slug)
    if p is None:
        return []
    try:
        if p.stat().st_size > _MAX_TOTAL_BYTES:
            return []                                  # oversized seam -> empty (fail-closed; never loaded)
    except OSError:
        return []                                      # missing / unstat-able -> empty
    out: "list[dict[str, Any]]" = []
    try:
        with p.open("r", encoding="utf-8") as fh:
            for seq, line in enumerate(fh):            # stream line-by-line (never readlines() the whole file)
                if seq >= _MAX_TOTAL_LINES:
                    return []                          # too many lines -> empty (fail-closed; nothing above the bound parsed)
                if len(line) > _MAX_LINE:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                parts = _split_node(rec.get("node"))
                kind = rec.get("kind")
                if parts is None or kind not in _EVENT_LABELS:
                    continue                           # off-allowlist -> dropped (customer-safe)
                nodekind, role = parts
                nid = f"{nodekind}:{role}"
                ts = rec.get("ts")
                ref = rec.get("ref")
                status = rec.get("status")
                frm = _split_node(rec.get("from"))
                edge = rec.get("edge")
                out.append({
                    "seq": seq,
                    "ts": float(ts) if isinstance(ts, (int, float)) else 0.0,
                    "node": nid,
                    "role": role,
                    "nodekind": nodekind,
                    "kind": str(kind),
                    "status": str(status) if status in _PHASE_STATUSES else "",
                    "ref": int(ref) if isinstance(ref, int) and 0 < ref <= _MAX_REF else 0,
                    "from": f"{frm[0]}:{frm[1]}" if (frm is not None and edge in _EDGE_KINDS) else "",
                    "edge": str(edge) if (frm is not None and edge in _EDGE_KINDS) else "",
                    "verified": bool(rec.get("verified")) and str(kind) == "finding",
                })
    except OSError:
        return []                                      # a read error mid-stream -> empty (fail-closed)
    return out


def _label_for(row: "dict[str, Any]") -> str:
    """The customer-facing transcript label for one row — a FIXED string per (kind[, verified][, stage]); no
    payload text ever surfaces."""
    kind = row["kind"]
    if kind == "phase":
        _, _, stage = row["node"].partition(":")
        return _STAGES.get(stage, "Stage")
    if kind == "finding" and row["verified"]:
        return _FINDING_VERIFIED_LABEL
    return _EVENT_LABELS.get(kind, "Activity")


def read(base: Any, slug: str, *, since: int = -1, limit: int = 400,
         node: str = "") -> "list[dict[str, Any]]":
    """The customer-safe ACTIVITY TRANSCRIPT rows for ``slug`` with line-index ``seq`` > ``since`` (the cursor is
    an EXCLUSIVE last-seen seq; the default -1 returns from the first row — the full REPLAY), newest at the end.
    Each row is ``{seq, ts, node, role, label, kind, status, ref, verified}`` with a friendly ``label``. ``node``
    optionally filters to ONE node (what the UI does when a graph node is selected). Pure-stdlib, bounded,
    fail-closed: a missing / corrupt / oversized file reads as ``[]``; an off-allowlist row is DROPPED (never
    shown).

    If ``since`` is at or beyond the file's current length the trail was RESET under the cursor (a new run began
    via :func:`reset`): the cursor is stale, so read restarts from the first row rather than returning nothing.
    That in-reader recovery only catches a reset that left the file SHORTER than the cursor; when the NEW run has
    already written MORE rows than the stale cursor, the suffix it would return is caught by the caller comparing
    the :func:`epoch` token to the one its cursor belongs to (see the ``graph_activity`` endpoint)."""
    rows = _read_rows(base, slug)
    lim = max(1, min(int(limit or 400), _MAX_READ))
    start = int(since if since is not None else -1)
    if rows and start >= len(rows):     # cursor beyond the file -> the trail was reset under us; resync from start
        start = -1
    want = _split_node(node) if node else None
    want_id = f"{want[0]}:{want[1]}" if want is not None else None
    out: "list[dict[str, Any]]" = []
    for r in rows:
        if r["seq"] <= start:
            continue
        if want_id is not None and r["node"] != want_id:
            continue
        out.append({"seq": r["seq"], "ts": r["ts"], "node": r["node"], "role": r["role"],
                    "label": _label_for(r), "kind": r["kind"], "status": r["status"],
                    "ref": r["ref"], "verified": r["verified"]})
        if len(out) >= lim:
            break
    return out


def graph(base: Any, slug: str) -> "dict[str, Any]":
    """The customer-safe live AGENT/ENGAGEMENT GRAPH for ``slug`` — a DETERMINISTIC FOLD over the SAME recorded
    rows the transcript streams, so a node/edge can never show activity the events do not contain. Returns
    ``{nodes, edges, generation, epoch, cursor}`` where:

      * ``nodes`` — one per distinct node that ACTUALLY posted: ``{id, kind, role, group, label, status, events,
        verified, last_ts, first_ref}``. A PHASE node's ``status`` is its latest lifecycle status mapped to a
        display status (running / done / failed / paused / skipped); an AGENT node is ``active`` (it posted real
        events). ``events`` is the count of real recorded events on that node; ``verified`` the count that were
        oracle-grounded; ``first_ref`` the earliest blackboard ref (provenance anchor).
      * ``edges`` — the deduped recorded edges: ``{src, dst, kind}`` with kind ``sequence`` (the phase backbone,
        in real engagement order), ``delegation`` (one agent drove another's event), or ``attach`` (an agent was
        active during a phase). Only edges whose BOTH endpoints are present nodes are kept.
      * ``generation`` — the number of rows folded (a monotone counter the UI diffs to know the graph grew).
      * ``epoch`` — the RUN/GENERATION token (:func:`epoch`): it changes when the reused slug is relaunched
        (:func:`reset`), so the reader knows its ``cursor`` belongs to a prior run and must resync from ``seq`` 0
        rather than append a suffix of the new run. (Distinct from ``generation``, which only grows within a run.)
      * ``cursor`` — the newest seq (the transcript poll cursor).

    Pure-stdlib, bounded, fail-closed: a missing / empty / corrupt file yields an empty graph (NOT a fabricated
    one). Read-only; it mints nothing."""
    rows = _read_rows(base, slug)
    nodes: "dict[str, dict[str, Any]]" = {}
    edges: "dict[tuple[str, str, str], None]" = {}
    for r in rows:
        nid = r["node"]
        nodekind, role = r["nodekind"], r["role"]
        n = nodes.get(nid)
        if n is None:
            if nodekind == "phase":
                _, _, stage = nid.partition(":")
                label = _STAGES.get(stage, "Stage")
                group = "stage"
                status = "pending"
            else:
                label, group = _AGENT_ROLES.get(role, _AGENT_ROLES["agent"])
                status = "active"
            n = nodes[nid] = {"id": nid, "kind": nodekind, "role": role, "group": group,
                              "label": label, "status": status, "events": 0, "verified": 0,
                              "last_ts": 0.0, "first_ref": 0}
        n["events"] += 1
        if r["verified"]:
            n["verified"] += 1
        if r["ts"] > n["last_ts"]:
            n["last_ts"] = r["ts"]
        if r["ref"] and (n["first_ref"] == 0 or r["ref"] < n["first_ref"]):
            n["first_ref"] = r["ref"]
        if nodekind == "phase" and r["kind"] == "phase" and r["status"] in _STATUS_DISPLAY:
            n["status"] = _STATUS_DISPLAY[r["status"]]      # latest lifecycle status wins (rows are in order)
        if r["from"] and r["edge"] in _EDGE_KINDS:
            edges[(r["from"], nid, r["edge"])] = None
    # keep only edges whose BOTH endpoints are real present nodes (never draw an edge to a node that never posted)
    edge_list = [{"src": s, "dst": d, "kind": k} for (s, d, k) in edges if s in nodes and d in nodes and s != d]
    # stable, honest ordering: phases in real engagement order first, then agents by first appearance.
    def _nkey(n: "dict[str, Any]") -> "tuple[int, int, str]":
        if n["kind"] == "phase":
            _, _, stage = n["id"].partition(":")
            return (0, _STAGE_ORDER.get(stage, 99), n["id"])
        return (1, n["first_ref"] or 10 ** 12, n["id"])
    node_list = sorted(nodes.values(), key=_nkey)
    return {"nodes": node_list, "edges": edge_list, "generation": len(rows),
            "epoch": epoch(base, slug), "cursor": (rows[-1]["seq"] if rows else -1)}
