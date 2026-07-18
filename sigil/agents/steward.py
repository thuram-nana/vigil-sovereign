"""STEWARD (SIGIL §4.7) — personal operations: the morning brief, the commitment ledger,
recurring admin. Ceiling A2 (calendar writes queue until trust promotes them). The morning
BRIEF is the Phase-3 acceptance deliverable: an unprompted, prioritized sitrep composed only
from grounded memory — due/overdue commitments first, then open threads, then flagged
contradictions, then a recent-activity summary. Every line is cited to a spine seq."""
from __future__ import annotations

from collections import Counter
from typing import List, Optional

from ..consolidate.queries import due_commitments, open_threads, pending_contradictions
from .base import Agent, AgentResult, Proposal, Tier


def _recent_activity(store, since_seq: int) -> Counter:
    c: Counter = Counter()
    for r in store.iter_records(since_seq=since_seq):
        c[r.kind] += 1
    return c


def compose_brief(store, *, date_label: str = "today", lookback: int = 400) -> str:
    threads = open_threads(store, limit=8)
    due = due_commitments(store, limit=8)
    contras = pending_contradictions(store, limit=5)
    head = store.next_seq - 1
    activity = _recent_activity(store, max(-1, head - lookback))

    lines = [f"# SIGIL morning brief — {date_label}", "Good morning. Here's where things stand.", ""]

    lines.append(f"## Commitments ({len(due)})")
    if due:
        for c in sorted(due, key=lambda d: str(d.get("due"))):
            lines.append(f"- due {c['due']} — {(c.get('text') or '')[:80]}  (owner {c.get('owner')}, seq {c['seq']})")
    else:
        lines.append("- none with a due date on record.")

    lines.append(f"\n## Open threads ({len(threads)})")
    if threads:
        for t in threads[:8]:
            lines.append(f"- [{t['kind']}] {(t.get('text') or '')[:90]}  (seq {t['seq']})")
    else:
        lines.append("- nothing open — the consolidation pass has surfaced no live decisions/commitments yet.")

    if contras:
        lines.append(f"\n## Flagged for review ({len(contras)})")
        for x in contras:
            lines.append(f"- {x.get('subject')}: conflicting decisions at seqs {x.get('conflicting_seqs')}")

    alerts = [r for r in store.iter_records(since_seq=max(-1, head - 60))
              if r.kind == "event" and r.actor == "SENTINEL"]
    if alerts:
        lines.append(f"\n## Alerts (SENTINEL, {len(alerts)})")
        for a in alerts[-6:]:
            lines.append(f"- {a.payload.get('summary')}  (salience {a.payload.get('salience')})")

    # BASTION defensive posture (§4.8): cert/CVE/uptime findings surface here (Phase-5 acceptance).
    # Dedup to the LATEST record per finding IDENTITY (asset, check, CVE) — the CVE discriminator keeps
    # N concurrent CVEs distinct (RP-2) — then DROP any whose latest state is `resolved`, so a fixed
    # problem never lingers in the brief as current (RP-1/RP-5).
    posture: dict = {}
    for r in store.iter_records(since_seq=max(-1, head - 400)):
        if r.kind == "finding" and r.actor == "BASTION":
            posture[(r.payload.get("asset"), r.payload.get("check"), r.payload.get("cve"))] = r
    active = [r for r in posture.values() if not r.payload.get("resolved")]
    if active:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        active.sort(key=lambda r: (order.get(str(r.payload.get("severity")), 4), r.seq))
        lines.append(f"\n## Infrastructure posture (BASTION, {len(active)})")
        for r in active[:8]:
            p = r.payload
            lines.append(f"- [{p.get('severity', '?')}] {p.get('summary')}  "
                         f"({p.get('quote')}, seq {r.seq})")

    lines.append("\n## Recent activity")
    interesting = {"commit": "commits", "decision": "decisions", "commitment": "commitments",
                   "message": "messages", "event": "events", "finding": "findings"}
    summary = ", ".join(f"{activity[k]} {label}" for k, label in interesting.items() if activity.get(k))
    lines.append(f"- last {lookback} records: {summary or 'quiet'}.")
    return "\n".join(lines)


class Steward(Agent):
    name = "STEWARD"
    mandate = "run the life layer: calendar, briefs, commitments, recurring admin"
    ceiling = Tier.A2

    def run(self, *, date_label: str = "today") -> AgentResult:
        text = compose_brief(self.store, date_label=date_label)
        # the brief is a reversible internal write → A1, auto.
        return self._dispatch([Proposal("brief", {"text": text, "subject": "morning brief"}, Tier.A1)])

    def brief_text(self, *, date_label: str = "today") -> str:
        return compose_brief(self.store, date_label=date_label)
