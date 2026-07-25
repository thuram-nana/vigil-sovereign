"""SIGIL governor (Phase 6, SIGIL §5 mechanics) — the runtime enforcement of the WARDEN autonomy
model for the AGENT MESH (the Rust `kernel/` WARDEN governs kernel-level actions; this is its
Python-side mirror for agents). Every agent Proposal is decided here BEFORE it is written:

  • KILL SWITCH (sealed latch): when engaged, the mesh is halted — only A0 observe/read survives.
  • BUDGETS: per-agent daily action/interrupt caps, fail-closed (over budget → deny + log).
  • PROMOTION: a per-(agent, scope) grant may auto-approve A2 — EXCEPT ENVOY outbound, which has NO
    promotion path by construction (SIGIL §4.6). A3 never auto-promotes.

All state lives on the append-only spine (kill/promotion are events; budget spend is derived from
the log), so the governor's every decision is itself auditable — which is what makes the acceptance
bar ("zero unauthorized A2/A3 in the audit log") provable rather than promised. Offense-free by
doctrine (assert_no_offense)."""
from ..reuse import assert_no_offense

assert_no_offense()

from .budget import (  # noqa: E402
    DEFAULT_PRICES,
    BudgetCaps,
    BudgetLedger,
    Spend,
    Usage,
    load_prices,
)
from .capability import CAPABILITIES, CapabilityGate  # noqa: E402
from .core import Decision, Governor, Outcome  # noqa: E402
from .killswitch import KillSwitch  # noqa: E402
from .offense_gate import (  # noqa: E402
    OffenseGate,
    OffenseGateClosed,
    OffenseGateState,
    assert_offense_gated,
)
from .promotion import PromotionPolicy  # noqa: E402

__all__ = ["Governor", "Decision", "Outcome", "KillSwitch", "BudgetCaps", "BudgetLedger",
           "Spend", "Usage", "load_prices", "DEFAULT_PRICES", "PromotionPolicy",
           "OffenseGate", "OffenseGateClosed", "OffenseGateState", "assert_offense_gated",
           "CapabilityGate", "CAPABILITIES"]
