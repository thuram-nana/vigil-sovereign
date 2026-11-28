"""Live Control — the SOVEREIGN adapter for the customer mission-steering surface (#/live).

Customer Live Control composes mostly already-working reads (the launches list, pause/resume, the report/proof
heads). The one genuinely new WRITE it adds is MISSION STEERING: a customer tells their OWN running engagement
what to prioritise ("focus on auth", "check the admin API") WHILE it runs — the feature a user drives an agent
with, without restarting the assessment.

This module is the thin sovereign adapter that turns such a request into an entry on the OFFENSE-local,
advisory, exactly-once instruction queue (``vigil_integration.live.instructions``) the engine's OODA loop
already drains at the top of every reasoning cycle. REUSE, don't rebuild: NO second queue, NO second store.
The safety model is the queue's own — an instruction is folded into the engine's UNTRUSTED think context; it
fires no tool, relaxes no scope and mints no fact (see live/instructions.py). So this adds NO new execution
authority: it is no more privileged than the objective the run already carried.

TENANT ISOLATION. The engagement slug is resolved SERVER-SIDE from (session org, host) via the
domain-separated ``_customer_slug`` AFTER confirming the host is one the org has actually ownership-proven — a
browser can neither name another tenant's slug nor steer a host its org never proved. The caller (the
provisioner) has already admitted the requester for the org (``run_engagement``) and tenant-bound the session;
``host`` is the only steering input that rides the request body, and it is validated against the org's own
proven set here.

IDEMPOTENCY. A client-supplied ``idem_key`` makes a double-click / reconnect a no-op: a repeat returns the
original sequence number and enqueues nothing. The ledger is a small bounded ring next to the queue; the
provisioner serialises the check-and-enqueue under its own lock (single-process exactly-once; a multi-process
race is bounded and at worst enqueues a duplicate advisory line, which is harmless).

FATAL-2. Sovereign-only. The offense-local queue module is imported LAZILY (it is pure-stdlib + import-clean —
the same crossing pattern ``customer_launches`` uses for the live credit-lease readers); engine code is never
pulled into the customer venv. Data crosses the plane boundary only as the queue's JSONL files.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

_MAX_IDEM = 128            # bound the per-engagement idempotency ring
_IDEM_KEY_MAX = 128


def _proven_slug(store: Any, org_id: str, host: str) -> Optional[str]:
    """The engagement slug for (org, host) IFF the org has ownership-proven ``host`` — else None (fail-closed).
    ``_customer_slug`` is a domain-separated hash the browser cannot forge, and it is resolved ONLY for a host
    the org actually proved, so another tenant's engagement is structurally unreachable.

    EVER-proven, by design — the same tier as the other customer READS of an engagement a host once started
    (``customer_launches``, the findings/posture reads): you can watch and advise a run you legitimately launched
    even if the host's proof has since lapsed, exactly as you can still read that run's findings. This is
    deliberately NOT the ``has_current_proof`` LINCHPIN, which gates STARTING a run (``launch_reserve`` /
    ``monitoring_authority``): Live Control mints no execution authority — the activity read is a pure projection
    and steering is advisory-only — and a FUTURE run still cannot start on a lapsed host without re-proving, so
    the current-proof gate that governs any actual tool-fire is not weakened. Org-namespaced, so a new owner of
    the host gets a different slug and can never reach this org's trail."""
    from ..governor.asset_ownership import AssetOwnershipRegistry
    from .target_authorization import _customer_slug
    h = str(host or "").strip()
    if not h:
        return None
    proven = set(AssetOwnershipRegistry(store, owner_key=None).ever_proven_hosts(str(org_id)))
    if h not in proven:
        return None
    return _customer_slug(str(org_id), h)


def _idem_path(slug: str) -> Path:
    """The per-engagement idempotency ring, beside the advisory instruction queue in the shared live dir (so an
    enqueue and its idempotency record always agree on WHERE they live). ``slug`` is the server-computed
    ``_customer_slug`` hash — a safe single path component by construction."""
    from vigil_integration.live.instructions import resolve_live_dir
    d = resolve_live_dir() / "instructions"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)          # operator free-text + its idempotency keys are not world-readable
    except OSError:
        pass
    return d / (str(slug) + ".idem")


def _idem_lookup(slug: str, key: str) -> Optional[int]:
    if not key:
        return None
    try:
        rows = json.loads(_idem_path(slug).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and r.get("key") == key:
            seq = r.get("seq")
            if isinstance(seq, (int, str)):
                try:
                    return int(seq)
                except (TypeError, ValueError):
                    return None
    return None


def _idem_record(slug: str, key: str, seq: int) -> None:
    if not key:
        return
    p = _idem_path(slug)
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            rows = []
    except (OSError, ValueError):
        rows = []
    rows.append({"key": str(key), "seq": int(seq)})
    rows = rows[-_MAX_IDEM:]
    tmp = p.with_name(p.name + ".tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(rows, ensure_ascii=False))
        os.replace(tmp, p)          # atomic publish of the ring
    except OSError:
        pass


def submit_instruction(store: Any, org_id: str, host: str, text: str, *, idem_key: str = "") -> dict:
    """Enqueue ONE advisory mission-steering instruction for the (org, host) engagement. Returns
    ``{ok, slug, seq, idempotent}``. Raises ``ValueError`` (fail-closed) on a host the org has not proven or on
    empty/oversized text — the caller surfaces it honestly. Idempotent on ``idem_key``: a repeat (double-click
    / reconnect) returns the original ``seq`` and enqueues nothing. ADVISORY-ONLY: this never runs a tool,
    relaxes scope, or mints a fact; the engine folds the text into its untrusted think context."""
    slug = _proven_slug(store, org_id, host)
    if slug is None:
        raise ValueError("no such engagement for this org")   # host not proven by this org (tenant-safe)
    key = str(idem_key or "")[:_IDEM_KEY_MAX]
    prior = _idem_lookup(slug, key)
    if prior is not None:
        return {"ok": True, "slug": slug, "seq": prior, "idempotent": True}
    from vigil_integration.live.instructions import enqueue
    res = enqueue(slug, text)        # fail-closed on empty/oversized/unsafe text; advisory-only
    seq = int(res.get("seq", 0))
    _idem_record(slug, key, seq)
    return {"ok": True, "slug": slug, "seq": seq, "idempotent": False}


def agent_graph(store: Any, org_id: str, host: str) -> dict:
    """The customer-safe LIVE AGENT/ENGAGEMENT GRAPH of the (org, host) engagement — a DERIVED fold over the same
    recorded agent-spine rows the activity transcript streams, so a node/edge can never show activity the events
    do not contain (AS-4a honesty). Resolves the slug SERVER-side (ONLY for a host the org has ownership-proven —
    tenant-safe) and reads the shared live-graph seam. Returns ``{ok, slug, nodes, edges, generation, cursor}``:
    nodes = the real sub-agents / phases that actually posted (per-node status + provenance ref + oracle-verified
    count), edges = the recorded delegation / phase-sequence / attachment links. Raises ``ValueError`` on an
    unproven host (fail-closed, tenant-safe). A read-only projection; it mints nothing and promotes no LEAD."""
    slug = _proven_slug(store, org_id, host)
    if slug is None:
        raise ValueError("no such engagement for this org")
    from vigil_core.live_graph import graph as _graph
    from vigil_core.seam_base import resolve_seam_base
    g = _graph(resolve_seam_base(), slug)
    return {"ok": True, "slug": slug, "nodes": g.get("nodes", []), "edges": g.get("edges", []),
            "generation": int(g.get("generation", 0)), "cursor": int(g.get("cursor", -1))}


def graph_activity(store: Any, org_id: str, host: str, *, since: int = -1, limit: int = 300,
                   node: str = "") -> dict:
    """The customer-safe RICH ACTIVITY TRANSCRIPT of the (org, host) engagement — the sub-agents' reasoning +
    tool events as the spine recorded them, each grounded in a real blackboard event (its ``ref``). Resolves the
    slug SERVER-side (tenant-safe) and reads the shared live-graph seam incrementally with a ``since`` cursor;
    ``since=-1`` returns the whole recorded stream (the honest REPLAY / scrub). ``node`` optionally filters to
    ONE node (what the UI does when a graph node is selected). Returns ``{ok, slug, rows, cursor}`` where each row
    is ``{seq, ts, node, role, label, kind, status, ref, verified}`` (fixed-field, customer-safe — the seam drops
    anything else). Raises ``ValueError`` on an unproven host. A read-only projection; it mints nothing."""
    slug = _proven_slug(store, org_id, host)
    if slug is None:
        raise ValueError("no such engagement for this org")
    from vigil_core.live_graph import read as _read
    from vigil_core.seam_base import resolve_seam_base
    rows = _read(resolve_seam_base(), slug, since=int(since), limit=int(limit), node=str(node or ""))
    cursor = rows[-1]["seq"] if rows else int(since)
    return {"ok": True, "slug": slug, "rows": rows, "cursor": cursor}


def activity(store: Any, org_id: str, host: str, *, since: int = -1, limit: int = 200) -> dict:
    """The customer-safe LIVE ACTIVITY of the (org, host) engagement — the phase transitions the engine
    mirrored onto the shared seam ("Running authorized checks", "Recording the assessment evidence", ...).
    Resolves the slug SERVER-side (ONLY for a host the org has ownership-proven — tenant-safe) and reads the
    shared activity seam incrementally with a ``since`` cursor. Returns ``{ok, slug, rows, cursor}`` where each
    row is ``{seq, ts, phase, label, status}`` (fixed-field, customer-safe — the seam drops anything else) and
    ``cursor`` is the newest seq (poll again with ``since=cursor``). Raises ``ValueError`` on an unproven host.
    A read-only projection of the signed-engagement lifecycle; it mints nothing and never promotes a LEAD."""
    slug = _proven_slug(store, org_id, host)
    if slug is None:
        raise ValueError("no such engagement for this org")
    from vigil_core.live_activity import read as _read
    from vigil_core.seam_base import resolve_seam_base
    rows = _read(resolve_seam_base(), slug, since=int(since), limit=int(limit))
    cursor = rows[-1]["seq"] if rows else int(since)
    return {"ok": True, "slug": slug, "rows": rows, "cursor": cursor}
