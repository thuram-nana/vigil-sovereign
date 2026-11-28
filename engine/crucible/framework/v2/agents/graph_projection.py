"""
agents.graph_projection — mirror the append-only agent SPINE onto the customer-safe live-graph seam.

This is the OFFENSE half of the customer live AGENT-GRAPH feature. The sovereign Live view must show a LIVE
graph of the real sub-agents (recon / exploit / critique / grounding / …) and stream their reasoning + tool
activity — but the FATAL-2 boundary forbids the sovereign plane from reading the offense blackboard directly.
So this projector, running on the OFFENSE plane, does an incremental, read-only replay of the blackboard spine
for one engagement and mirrors each real recorded event as ONE customer-safe row on the shared
``vigil_core.live_graph`` seam (a bounded JSONL file under the seam base — the only thing that crosses the
boundary). From those rows the sovereign reader DERIVES both the graph and the transcript.

HONEST BY CONSTRUCTION. Every emitted row is grounded in a real blackboard event (its ``ref`` is the event id):
there is no synthetic node, no placeholder agent, no fabricated heartbeat. A quiet engagement projects nothing,
so the customer graph reads as quiet — never a fake pulse (AS-4a). The projection carries ONLY the agent's ROLE,
the event KIND, the provenance ref, the delegation/phase edge, and the oracle-verified flag; NO payload text,
target detail, IP or secret crosses — the seam itself drops anything off its allowlist (defense in depth).

READ-ONLY + BEST-EFFORT. It only calls ``Blackboard.replay(since_id=…)`` (the unified read-only cursor API);
it never posts, supersedes or edits, so the spine stays append-only and a dead projector can never perturb the
engine. Every operation is swallow-on-error — a projection failure is a no-op, never a raise into the run. It
is driven by the phase ledger (default-OFF behind ``VIGIL_CUSTOMER_LIVE_GRAPH``), so when the flag is off this
module is never constructed and behaviour is byte-identical.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .. import phase_ledger as _pl

# agent_name (blackboard ``agent_name``) -> the customer-safe role token the seam allowlists. Unknown names
# normalise to the generic ``agent`` role (a real agent still shows as a real node, just generically labelled —
# never dropped, never invented). Kept in sync with vigil_core.live_graph._AGENT_ROLES by
# test_graph_projection.py::test_every_projected_role_is_on_the_seam_allowlist.
_ROLE_BY_AGENT: "dict[str, str]" = {
    "recon": "recon", "hypothesis": "hypothesis", "memory": "memory", "planner": "planner",
    "coordinator": "coordinator", "autonomy": "autonomy", "daa": "daa", "exploit": "exploit",
    "tier3-validation": "tier3-validation", "critique": "critique", "grounding": "grounding",
    "provenance": "provenance", "calibration": "calibration", "multi-critic": "multi-critic",
    "reflection": "reflection", "reporter": "reporter", "spine": "spine",
}
_MAX_ID_MAP = 5000        # bound the id->node map used for delegation-edge resolution


def _role(agent_name: Any) -> str:
    return _ROLE_BY_AGENT.get(str(agent_name or "").strip().lower(), "agent")


def _epoch(posted_at: Any, fallback: float) -> float:
    """Parse a blackboard ISO ``posted_at`` to epoch seconds, best-effort (fallback on any parse failure)."""
    s = str(posted_at or "")
    if not s:
        return fallback
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, OSError):
        return fallback


class GraphProjector:
    """Incremental, read-only projector of ONE engagement's blackboard spine onto the customer-safe live-graph
    seam. Owned by the phase ledger: :meth:`on_phase` is called at every phase transition (it drains the agent
    events posted since the last call, attaching them to the phase that was active, then mirrors the phase
    transition itself as the graph's backbone). Constructed only when the customer live-graph flag is on.

    All state is in-process (a durable cursor plus a bounded id->node map for delegation edges). Best-effort:
    every method swallows its own errors — a projection failure never perturbs the engagement."""

    def __init__(self, bb: Any, slug: str, base: Any) -> None:
        self._bb = bb
        self._slug = str(slug or "")
        self._base = base
        self._cursor = 0                      # blackboard id high-water (durable replay cursor)
        self._id_to_node: "dict[int, str]" = {}
        self._cur_phase_node: str = ""        # the phase node agent events attach to (the active stage)
        self._last_started_phase: str = ""    # for the phase-backbone sequence edge
        self._phase_seq = 0                   # a monotone ref for phase rows (distinct from blackboard ids)

    # ---- the public drive point (called by the phase ledger) ----

    def reset(self) -> None:
        """Begin a FRESH graph trail (a new run attempt) — clears the seam file and the in-process cursors so the
        customer graph shows the CURRENT run, not the concatenation of past runs on the same host. CRUCIALLY the
        replay cursor is anchored at the spine's CURRENT high-water, because the blackboard is keyed per slug and
        the slug is reused by every launch of the same (org, host): without this anchor a re-launch would replay
        the PRIOR run's events onto the new graph (stale, dishonest). Anchoring here means only events posted
        from NOW ON — this run — are ever mirrored. Best-effort: never raises."""
        try:
            from vigil_core import live_graph as lg
            lg.reset(self._base, self._slug)
        except Exception:  # noqa: BLE001 — a reset failure must never perturb the engine
            pass
        anchor = 0
        try:
            anchor = int(self._bb.latest_event_id(engagement=self._slug))   # only THIS run's events, not prior
        except Exception:  # noqa: BLE001 — a fresh/absent spine anchors at 0
            anchor = 0
        self._cursor = anchor
        self._id_to_node = {}
        self._cur_phase_node = ""
        self._last_started_phase = ""
        self._phase_seq = 0

    def on_phase(self, stage: str, status: str, *, ts: float) -> None:
        """Mirror one phase transition. First DRAIN the agent events posted since the last call (attaching them
        to the phase that was active), THEN record the phase transition itself — so the drained tail of a phase
        attaches to that phase, and the backbone edge links consecutive stages in real engagement order.
        Best-effort: any failure is swallowed (a customer-graph mirror never perturbs the engine)."""
        try:
            self._drain(ts)
            self._emit_phase(stage, status, ts=ts)
        except Exception:  # noqa: BLE001 — totally best-effort
            return

    # ---- internals ----

    def _emit_phase(self, stage: str, status: str, *, ts: float) -> None:
        from vigil_core import live_graph as lg
        node = f"phase:{str(stage).strip().lower()}"
        self._phase_seq += 1
        frm, edge = "", ""
        if status == "started":
            if self._last_started_phase and self._last_started_phase != node:
                frm, edge = self._last_started_phase, "sequence"   # the phase backbone, in real order
            self._last_started_phase = node
            self._cur_phase_node = node                            # agent events now attach to this stage
        lg.emit(self._base, self._slug, node, "phase", ts=float(ts), ref=self._phase_seq,
                from_node=frm, edge=edge, status=str(status))

    def _remember(self, event_id: int, node: str) -> None:
        if len(self._id_to_node) >= _MAX_ID_MAP:
            return                                 # bounded — beyond the cap, parents fall back to phase-attach
        self._id_to_node[int(event_id)] = node

    def _drain(self, ts: float) -> None:
        """Mirror every blackboard event appended since the cursor as ONE customer-safe seam row, attaching each
        to the agent that DROVE it (delegation) or, failing that, to the active phase (attach). Read-only."""
        bb = self._bb
        if bb is None or not self._slug:
            return
        try:
            rows = bb.replay(engagement=self._slug, since_id=self._cursor)
        except Exception:  # noqa: BLE001 — an unregistered/absent spine is "nothing yet"
            return
        from vigil_core import live_graph as lg
        for row in rows:
            try:
                rid = int(getattr(row, "id", 0) or 0)
            except (TypeError, ValueError):
                continue
            if rid > self._cursor:
                self._cursor = rid
            kind = getattr(row, "kind", "") or ""
            role = _role(getattr(row, "agent_name", ""))
            node = f"agent:{role}"
            payload = getattr(row, "payload", None) or {}
            verified = bool(kind == "finding" and isinstance(payload, dict)
                            and payload.get("verified_by_oracle"))
            # the recorded edge back to the driving event: a DELEGATION when the parent is a *different* agent we
            # have already mirrored, else ATTACH to the active phase. Both are grounded (parent_id / phase order).
            frm, edge = "", ""
            parent_id = getattr(row, "parent_id", None)
            parent_node = self._id_to_node.get(int(parent_id)) if isinstance(parent_id, int) else None
            if parent_node and parent_node != node:
                frm, edge = parent_node, "delegation"
            elif self._cur_phase_node:
                frm, edge = self._cur_phase_node, "attach"
            self._remember(rid, node)
            lg.emit(self._base, self._slug, node, str(kind), ts=_epoch(getattr(row, "posted_at", ""), ts),
                    ref=rid, from_node=frm, edge=edge, verified=verified)


def flag_enabled() -> bool:
    """True iff the OFFENSE-side customer live-graph mirror is on (``VIGIL_CUSTOMER_LIVE_GRAPH`` affirmative).
    DEFAULT-OFF: unset / any non-affirmative token is off, and the projector is never constructed, so the engine
    is byte-identical. The SAME env var the sovereign plane gates its read routes on, so emit and read agree."""
    import os
    return (os.environ.get("VIGIL_CUSTOMER_LIVE_GRAPH") or "").strip().lower() in ("1", "true", "yes", "on")


# Re-export the phase-ledger stage constants so a caller/test can assert the projector's stage vocabulary matches
# the ledger's without importing both. (Kept trivial — the ledger is the single source of truth.)
ORDERED_PHASES = _pl.ORDERED_PHASES
