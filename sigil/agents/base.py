"""The SIGIL agent mesh framework (SIGIL §4/§5). Each agent has a MANDATE and an AUTONOMY
CEILING (A0–A3); everything it does is a `Proposal` carrying a tier. Proposals at or below the
auto bar (A1) and at or below the agent's ceiling are AUTO-APPLIED (written to the spine);
anything higher is QUEUED as a pending record a human must approve — never auto-executed.

The doctrine is enforced STRUCTURALLY, not by discipline: an agent literally cannot take an
external-effect action, because no agent has a send/deploy/spend code path. ENVOY, in
particular, drafts only — its ceiling is A2 and there is no method that transmits. Agent output
is provenance-linked spine records, so a brief or a draft is auditable back to what produced it."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional

from ..spine.store import SpineStore

AGENTS_SOURCE = "agent"


class Tier(IntEnum):
    """Mirror of the WARDEN tiers (SIGIL §5), ordered so `<=` compares autonomy."""
    A0 = 0   # observe / answer
    A1 = 1   # reversible internal act (write a report/brief/event) — the AUTO bar
    A2 = 2   # external-visible / semi-reversible (send, calendar write) — QUEUED
    A3 = 3   # destructive / financial / security — explicit, never auto

    def label(self) -> str:
        return self.name


AUTO_BAR = Tier.A1  # A0/A1 auto-apply; A2/A3 queue for human approval


@dataclass
class Proposal:
    """One thing an agent wants to do: emit a record (auto) or take a gated action (queued)."""
    kind: str                       # spine record kind (event/finding/brief/interaction/draft/...)
    payload: dict
    tier: Tier = Tier.A1
    parent_id: Optional[int] = None
    supersedes_id: Optional[int] = None   # this record supersedes an earlier one (e.g. a resolution)


@dataclass
class AgentResult:
    agent: str
    applied: List[int] = field(default_factory=list)     # seqs written (auto)
    queued: List[dict] = field(default_factory=list)      # proposals held for approval
    notes: List[str] = field(default_factory=list)


class Agent:
    """Base agent. Subclasses implement `run()` and use `propose()`; the base enforces the
    ceiling + auto/queue gate and records everything to the spine."""
    name: str = "AGENT"
    mandate: str = ""
    ceiling: Tier = Tier.A1

    def __init__(self, store: Optional[SpineStore] = None):
        self.store = store or SpineStore()

    def run(self) -> AgentResult:
        raise NotImplementedError

    def _dispatch(self, proposals: List[Proposal]) -> AgentResult:
        res = AgentResult(agent=self.name)
        for p in proposals:
            effective = max(p.tier, Tier.A0)
            # a proposal above the agent's ceiling can NEVER auto-run; above the auto bar → queued.
            if effective <= self.ceiling and effective <= AUTO_BAR:
                seq = self.store.append(
                    kind=p.kind, source=AGENTS_SOURCE, actor=self.name,
                    payload={**p.payload, "agent": self.name, "tier": effective.label(), "decision": "auto"},
                    parent_id=p.parent_id, supersedes_id=p.supersedes_id)
                res.applied.append(seq)
            else:
                # queued: recorded as a pending/draft the human approves; NEVER auto-executed.
                seq = self.store.append(
                    kind=p.kind, source=AGENTS_SOURCE, actor=self.name,
                    payload={**p.payload, "agent": self.name, "tier": effective.label(),
                             "decision": "queued", "status": "awaiting-approval"},
                    parent_id=p.parent_id, supersedes_id=p.supersedes_id)
                res.queued.append({"seq": seq, "kind": p.kind, "tier": effective.label(),
                                   "subject": p.payload.get("subject") or p.payload.get("to")})
        return res
