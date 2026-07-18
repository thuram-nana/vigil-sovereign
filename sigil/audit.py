"""Self-audit (SIGIL C18, §5) — answers "what did you do and why" VERBATIM from the signed action
log. Every agent record carries its actor, tier, governor decision + reason; this reconstructs that
trail with each row cited to a spine seq. Read-only, A0 — it fabricates nothing, it only reports what
the append-only log already proves (which is the whole point of C18)."""
from __future__ import annotations

from collections import Counter
from typing import List, Optional

from .spine.store import SpineStore

_DECISIONS = ("auto", "queued", "denied")


def self_audit(store: SpineStore, *, agent: Optional[str] = None, since_seq: int = -1,
               limit: int = 500) -> List[dict]:
    """Every governed agent action since `since_seq`, most-recent last, each cited. `agent` filters."""
    rows: List[dict] = []
    for r in store.iter_records(since_seq=since_seq):
        if r.source != "agent":
            continue
        if agent and r.actor != agent:
            continue
        p = r.payload
        dec = p.get("decision")
        if dec not in _DECISIONS:
            continue
        rows.append({
            "seq": r.seq, "entry_hash": r.entry_hash, "when": r.ts, "agent": r.actor,
            "kind": r.kind, "tier": p.get("tier"), "decision": dec,
            "why": p.get("governor") or "(recorded before the governor)",
            "what": p.get("subject") or p.get("summary") or (r.text()[:80]),
            "parent_id": r.parent_id,
        })
    return rows[-limit:]


def render_audit(rows: List[dict], *, agent: Optional[str] = None) -> str:
    who = agent or "the agent mesh"
    lines = [f"# SIGIL self-audit — what {who} did, and why", ""]
    if not rows:
        lines.append("- no governed agent actions on record for that window.")
        return "\n".join(lines)
    by_dec = Counter(r["decision"] for r in rows)
    by_agent = Counter(r["agent"] for r in rows)
    lines.append(f"{len(rows)} action(s): "
                 + ", ".join(f"{n} {d}" for d, n in by_dec.items()) + ".")
    lines.append("by agent: " + ", ".join(f"{a} {n}" for a, n in by_agent.most_common()) + ".")
    lines.append("")
    for r in rows[-40:]:
        lines.append(f"- seq {r['seq']} [{r['tier']}/{r['decision']}] {r['agent']} · {r['kind']}: "
                     f"{r['what']}")
        lines.append(f"    why: {r['why']}   ({r['when'][:19]})")
    return "\n".join(lines)
