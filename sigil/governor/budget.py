"""Per-agent daily budgets (SIGIL §5) — action and interrupt caps, enforced FAIL-CLOSED (at cap →
deny). The spine IS the ledger: spend is derived by counting an agent's own records for the UTC day,
so there is no separate counter to drift or forge. Caps default to None (uncapped) → budgets are
opt-in and the default dispatch behavior is unchanged; a configured cap is hard-enforced.

Token/cost caps are a documented seam: the mesh does not yet meter provider tokens per action, so
`daily_actions`/`daily_interrupts` are the enforced dimensions today (interrupt = an A1 event/alert —
the SENTINEL failure mode §4.3)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class BudgetCaps:
    daily_actions: Optional[int] = None       # max records an agent may write per UTC day
    daily_interrupts: Optional[int] = None    # max A1 events/alerts (the noise budget) per UTC day


class BudgetLedger:
    def __init__(self, store, caps: Optional[BudgetCaps] = None):
        self.store = store
        self.caps = caps or BudgetCaps()

    def spent(self, agent: str, day_iso: str) -> Tuple[int, int]:
        """(#records this agent wrote today, #of those that were interrupt events). `day_iso` is the
        UTC date prefix (YYYY-MM-DD) — the ts is informational, so bucketing is by wallclock date."""
        actions = interrupts = 0
        for r in self.store.iter_records():
            if r.source != "agent" or r.actor != agent:
                continue
            if not (r.ts or "").startswith(day_iso):
                continue
            # count only actions actually TAKEN (auto/queued) — a denial consumes no budget, so a
            # flood of denied attempts can't self-reinforce the cap.
            if r.payload.get("decision") not in ("auto", "queued"):
                continue
            actions += 1
            if r.kind == "event":
                interrupts += 1
        return actions, interrupts

    def over_budget(self, agent: str, day_iso: str) -> Tuple[bool, str]:
        if self.caps.daily_actions is None and self.caps.daily_interrupts is None:
            return False, ""
        actions, interrupts = self.spent(agent, day_iso)
        if self.caps.daily_actions is not None and actions >= self.caps.daily_actions:
            return True, f"daily action cap ({self.caps.daily_actions}) reached for {agent}"
        if self.caps.daily_interrupts is not None and interrupts >= self.caps.daily_interrupts:
            return True, f"daily interrupt cap ({self.caps.daily_interrupts}) reached for {agent}"
        return False, ""
