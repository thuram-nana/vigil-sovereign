"""SENTINEL (SIGIL §4.3) — perception & monitoring: see everything, report only what matters.
Ceiling A1 (writes only event records). The failure mode is NOISE, so SENTINEL applies a
SALIENCE threshold and an ALERT BUDGET: at most `alert_budget` events per run, highest-salience
first; the rest are suppressed (and counted). Watchers are pluggable — the built-ins read the
spine + local system; live watchers (IMAP IDLE, CalDAV, uptime probes) are optional additions."""
from __future__ import annotations

import shutil
from typing import List, Protocol, runtime_checkable

from .base import Agent, AgentResult, Proposal, Tier


@runtime_checkable
class Watcher(Protocol):
    def poll(self) -> List[dict]: ...   # each: {kind, summary, salience(0..1), detail?}


class SpineActivityWatcher:
    """Salient signals derived from the spine: a burst of new commits, and any pending
    self-contradiction the consolidation flagged."""
    def __init__(self, store, since_seq: int, commit_burst: int = 3):
        self.store, self.since_seq, self.commit_burst = store, since_seq, commit_burst

    def poll(self) -> List[dict]:
        out: List[dict] = []
        commits = sum(1 for r in self.store.iter_records(since_seq=self.since_seq) if r.kind == "commit")
        if commits >= self.commit_burst:
            out.append({"kind": "commits", "summary": f"{commits} new commits since last check",
                        "salience": min(1.0, 0.4 + commits / 20.0)})
        from ..consolidate.queries import pending_contradictions
        for c in pending_contradictions(self.store, limit=5):
            out.append({"kind": "contradiction", "summary": f"unresolved contradiction on '{c.get('subject')}'",
                        "salience": 0.9, "detail": c.get("conflicting_seqs")})
        return out


class SystemHealthWatcher:
    """Local system posture — low disk is salient (BASTION-adjacent, own-infra only)."""
    def __init__(self, path: str = "/home/kali", low_pct: float = 10.0):
        self.path, self.low_pct = path, low_pct

    def poll(self) -> List[dict]:
        try:
            total, used, free = shutil.disk_usage(self.path)
        except OSError:
            return []
        free_pct = 100.0 * free / total if total else 100.0
        if free_pct < self.low_pct:
            return [{"kind": "disk", "summary": f"disk low: {free_pct:.0f}% free on {self.path}", "salience": 0.85}]
        return []


class Sentinel(Agent):
    name = "SENTINEL"
    mandate = "see everything, report only what matters"
    ceiling = Tier.A1

    def __init__(self, store=None, *, salience_floor: float = 0.5, alert_budget: int = 10):
        super().__init__(store)
        self.salience_floor = salience_floor
        self.alert_budget = alert_budget

    def run(self, watchers: List[Watcher]) -> AgentResult:
        candidates: List[dict] = []
        for w in watchers:
            candidates.extend(w.poll())
        salient = sorted((c for c in candidates if c.get("salience", 0) >= self.salience_floor),
                         key=lambda c: c.get("salience", 0), reverse=True)
        kept = salient[:self.alert_budget]
        proposals = [Proposal("event", {"summary": c.get("summary", "(no summary)"),
                                        "signal": c.get("kind", "?"),
                                        "salience": round(c.get("salience", 0), 3), "detail": c.get("detail")},
                              Tier.A1) for c in kept]  # defensive .get — one malformed watcher must not drop the run
        res = self._dispatch(proposals)
        suppressed = len(candidates) - len(kept)   # honest total: below-floor drops + over-budget
        res.notes.append(f"{len(candidates)} candidate(s) → {len(kept)} alerted"
                         + (f", {suppressed} suppressed (below floor or over budget)" if suppressed else ""))
        return res
