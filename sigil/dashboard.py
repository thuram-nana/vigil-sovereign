"""Read-only operator dashboard (SIGIL §9.4, C39/C40) — a glanceable status surface over the spine:
kill-switch state, per-agent activity, the tiered decision breakdown (auto/queued/denied), the
pending approval queue, today's budget usage, and ingest lag. LOOPBACK, READ-ONLY, ZERO-IMPACT: it
only reads the append-only log and writes nothing (same posture as the CRUCIBLE ops console). A
proper TUI/web view renders this same dict; here it renders to text."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from .spine.store import SpineStore


def snapshot(store: SpineStore, *, day_iso: Optional[str] = None, lookback: int = 300) -> dict:
    from .agents.approvals import pending
    from .governor import KillSwitch
    head = store.next_seq - 1
    day = day_iso or datetime.now(timezone.utc).date().isoformat()

    per_agent: Counter = Counter()
    decisions: Counter = Counter()
    interrupts_today: Counter = Counter()
    actions_today: Counter = Counter()
    last_checkpoint = -1
    last_consolidation = -1
    for r in store.iter_records():
        if r.kind == "warden_checkpoint":
            last_checkpoint = r.seq
        if r.kind in ("entity", "contradiction") and r.source == "agent":
            last_consolidation = max(last_consolidation, r.seq)
        if r.source == "agent" and (r.ts or "").startswith(day):
            actions_today[r.actor] += 1
            if r.kind == "event":
                interrupts_today[r.actor] += 1
        if r.source == "agent" and r.seq > head - lookback:
            per_agent[r.actor] += 1
            decisions[str(r.payload.get("decision"))] += 1

    pend = pending(store)
    return {
        "head_seq": head,
        "kill_switch": "ENGAGED" if KillSwitch(store).is_engaged() else "released",
        "recent_by_agent": dict(per_agent.most_common()),
        "recent_decisions": dict(decisions),
        "pending_approvals": [{"seq": r.seq, "tier": r.payload.get("tier"), "kind": r.kind,
                               "agent": r.actor, "subject": r.payload.get("subject")} for r in pend],
        "budget_today": {a: {"actions": actions_today[a], "interrupts": interrupts_today[a]}
                         for a in sorted(actions_today)},
        "ingest_lag": {"head_seq": head, "last_checkpoint_seq": last_checkpoint,
                       "records_since_checkpoint": (head - last_checkpoint) if last_checkpoint >= 0 else None,
                       "last_consolidation_seq": last_consolidation},
        "day": day,
    }


def render_dashboard(d: dict) -> str:
    lines = [f"# SIGIL dashboard — {d['day']}  (spine head seq {d['head_seq']})", ""]
    ks = d["kill_switch"]
    lines.append(f"Kill switch: {'🛑 ENGAGED — mesh halted (observe only)' if ks == 'ENGAGED' else '● released (mesh live)'}")
    lag = d["ingest_lag"]
    lines.append(f"Ingest lag: {lag['records_since_checkpoint']} record(s) since last checkpoint "
                 f"(checkpoint seq {lag['last_checkpoint_seq']}, consolidation seq {lag['last_consolidation_seq']})")
    lines.append("")
    lines.append(f"## Pending approvals ({len(d['pending_approvals'])})")
    if d["pending_approvals"]:
        for a in d["pending_approvals"][:12]:
            lines.append(f"- seq {a['seq']} [{a['tier']}] {a['agent']} · {a['kind']}: {a.get('subject')}"
                         f"   → sigil approve {a['seq']} / sigil deny {a['seq']}")
    else:
        lines.append("- none awaiting approval.")
    lines.append("")
    lines.append("## Recent activity (last window)")
    lines.append("  agents: " + (", ".join(f"{a} {n}" for a, n in d["recent_by_agent"].items()) or "quiet"))
    lines.append("  decisions: " + (", ".join(f"{k} {v}" for k, v in d["recent_decisions"].items()) or "none"))
    if d["budget_today"]:
        lines.append("")
        lines.append("## Budget usage today")
        for a, u in d["budget_today"].items():
            lines.append(f"  {a}: {u['actions']} action(s), {u['interrupts']} interrupt(s)")
    return "\n".join(lines)
