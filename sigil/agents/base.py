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
from typing import TYPE_CHECKING, List, Optional

from ..spine.store import SpineStore

if TYPE_CHECKING:
    from ..governor.budget import Usage

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
    usage: Optional["Usage"] = None       # provider token/cost for this action (metered on the spine);
    # OPTIONAL — when None nothing is stamped and the record is byte-identical to the pre-metering path


@dataclass
class AgentResult:
    agent: str
    applied: List[int] = field(default_factory=list)     # seqs written (auto)
    queued: List[dict] = field(default_factory=list)      # proposals held for approval
    notes: List[str] = field(default_factory=list)


class Agent:
    """Base agent. Subclasses implement `run()`; the base routes every Proposal through the GOVERNOR
    (SIGIL §5: kill switch, budgets, promotion — Phase 6) and records the outcome on the spine.
    Backward compatible: with no kill/cap/promotion the governor reproduces the original gate."""
    name: str = "AGENT"
    mandate: str = ""
    ceiling: Tier = Tier.A1

    def __init__(self, store: Optional[SpineStore] = None, *, governor=None):
        self.store = store or SpineStore()
        if governor is None:
            from ..governor import Governor
            governor = Governor(self.store)
        self.governor = governor

    def run(self) -> AgentResult:
        raise NotImplementedError

    def _dispatch(self, proposals: List[Proposal]) -> AgentResult:
        from ..governor import Outcome
        res = AgentResult(agent=self.name)
        prices = None
        for p in proposals:
            effective = max(p.tier, Tier.A0)
            # promotion scope = the RECORD KIND (the real action written), not a self-asserted label:
            # a promotion is "this agent may auto-approve A2 records of this kind" (red-pen RP-3).
            decision = self.governor.decide(agent=self.name, tier=effective,
                                            ceiling=self.ceiling, scope=p.kind)
            common = {**p.payload, "agent": self.name, "tier": effective.label(),
                      "governor": decision.reason}
            # Metering seam (opt-in): a provider call may attach per-action token/cost usage. Stamp it
            # onto the TAKEN record's payload so the spine stays the sole ledger (BudgetLedger derives
            # token/cost from exactly this datum). Frozen once here; a denied action gets a refusal
            # record with NO usage below → it consumes no budget. No usage supplied → nothing stamped,
            # the record is byte-identical to the pre-metering path.
            if p.usage is not None:
                if prices is None:
                    from ..governor.budget import load_prices
                    prices = load_prices()
                common["usage"] = p.usage.to_payload(prices)
            if decision.outcome == Outcome.AUTO:
                seq = self.store.append(kind=p.kind, source=AGENTS_SOURCE, actor=self.name,
                                        payload={**common, "decision": "auto"},
                                        parent_id=p.parent_id, supersedes_id=p.supersedes_id)
                res.applied.append(seq)
            elif decision.outcome == Outcome.QUEUE:
                seq = self.store.append(kind=p.kind, source=AGENTS_SOURCE, actor=self.name,
                                        payload={**common, "decision": "queued", "status": "awaiting-approval"},
                                        parent_id=p.parent_id, supersedes_id=p.supersedes_id)
                res.queued.append({"seq": seq, "kind": p.kind, "tier": effective.label(),
                                   "subject": p.payload.get("subject") or p.payload.get("to")})
            else:  # DENY — kill switch or budget; record the refusal, take no action
                self.store.append(kind="refusal", source=AGENTS_SOURCE, actor=self.name,
                                  payload={"agent": self.name, "tier": effective.label(),
                                           "decision": "denied", "governor": decision.reason,
                                           "of_kind": p.kind, "subject": p.payload.get("subject")},
                                  parent_id=p.parent_id)
                res.notes.append(f"DENIED {p.kind} ({effective.label()}): {decision.reason}")
        return res
