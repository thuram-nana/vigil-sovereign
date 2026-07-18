"""The Governor (SIGIL §5) — the single decision point the agent dispatch gate consults for EVERY
proposal. It composes the kill switch, budgets, and promotion policy into one fail-closed verdict:
AUTO (write it), QUEUE (hold for human approval), or DENY (refuse + log). The order matters and is
deliberately conservative: observe is always allowed; a kill halts everything above observe; budget
is checked before any auto-grant; A2 auto-approves only under an explicit promotion; A3 never autos.

Kill/promotion are read FRESH per decision (a mid-run kill halts the rest of the run). Backward
compatible: with no kill, no cap, and no promotion, A0/A1≤ceiling → AUTO and A2/A3 → QUEUE, exactly
as the pre-Phase-6 gate behaved."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .budget import BudgetCaps, BudgetLedger
from .killswitch import KillSwitch
from .promotion import PromotionPolicy


class Outcome(Enum):
    AUTO = "auto"
    QUEUE = "queue"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str


def _utc_day() -> str:
    return datetime.now(timezone.utc).date().isoformat()   # runtime bucketing only (never digested)


def _load_caps() -> BudgetCaps:
    """Optional per-agent caps from ~/.sigil/budgets.json ({daily_actions, daily_interrupts}).
    Absent/malformed → uncapped (budgets opt-in; default behavior unchanged)."""
    try:
        import json

        from ..config import SIGIL_HOME
        f = SIGIL_HOME / "budgets.json"
        if not f.exists():
            return BudgetCaps()
        d = json.loads(f.read_text(encoding="utf-8"))
        return BudgetCaps(daily_actions=d.get("daily_actions"), daily_interrupts=d.get("daily_interrupts"))
    except (OSError, ValueError, TypeError):
        return BudgetCaps()


class Governor:
    def __init__(self, store, *, caps: Optional[BudgetCaps] = None, day_iso: Optional[str] = None,
                 owner_key=None, trusted_pubkey: Optional[str] = None):
        from .identity import owner_keypair, owner_pubkey
        self.store = store
        ok = owner_key if owner_key is not None else owner_keypair()
        tp = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        self.kill = KillSwitch(store, owner_key=ok, trusted_pubkey=tp)
        self.promo = PromotionPolicy(store, owner_key=ok, trusted_pubkey=tp)
        self.budget = BudgetLedger(store, caps if caps is not None else _load_caps())
        self._day = day_iso

    def decide(self, *, agent: str, tier, ceiling, scope: Optional[str] = None) -> Decision:
        from ..agents.base import AUTO_BAR, Tier
        scope = scope or "*"

        # A0 observe/read is ALWAYS allowed — even under a kill switch (perception + memory stay alive).
        if tier <= Tier.A0:
            return Decision(Outcome.AUTO, "observe (A0)")

        # KILL SWITCH: the mesh is halted; nothing above observe may act.
        if self.kill.is_engaged():
            return Decision(Outcome.DENY, "kill switch engaged — agent mesh halted (A0 observe only)")

        # BUDGET: fail-closed — at cap, deny.
        over, why = self.budget.over_budget(agent, self._day or _utc_day())
        if over:
            return Decision(Outcome.DENY, why)

        # Within the auto bar (A0/A1) and the agent's ceiling → auto, as always.
        if tier <= AUTO_BAR and tier <= ceiling:
            return Decision(Outcome.AUTO, f"within auto bar ({tier.label()})")

        # A2 may auto-approve ONLY under an explicit per-scope promotion (never for ENVOY).
        if tier == Tier.A2 and tier <= ceiling and self.promo.is_promoted(agent, scope):
            return Decision(Outcome.AUTO, f"A2 auto-approved by promotion ({agent}/{scope})")

        # Everything else (A2 unpromoted, A3, or above ceiling) queues for explicit human approval.
        return Decision(Outcome.QUEUE, f"queued for approval ({tier.label()})")
