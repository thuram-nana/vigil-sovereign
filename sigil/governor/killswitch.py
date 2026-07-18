"""The kill switch (SIGIL §5) — a single latch that halts the agent mesh while leaving perception
and memory-read (A0 observe) alive. State is append-only on the spine (engage/release events), so
the latch itself is auditable and there is no separate flag to drift. Latest event wins; default
released. Reading fresh on every decision means a kill engaged mid-run halts the REST of that run."""
from __future__ import annotations

SIGNAL = "governor.killswitch"


class KillSwitch:
    def __init__(self, store):
        self.store = store

    def engage(self, *, by: str = "owner", reason: str = "") -> int:
        return self.store.append(kind="event", source="governor", actor="WARDEN",
                                 payload={"signal": SIGNAL, "state": "engaged", "by": by,
                                          "reason": reason, "tier": "A0", "decision": "auto"})

    def release(self, *, by: str = "owner", reason: str = "") -> int:
        return self.store.append(kind="event", source="governor", actor="WARDEN",
                                 payload={"signal": SIGNAL, "state": "released", "by": by,
                                          "reason": reason, "tier": "A0", "decision": "auto"})

    def is_engaged(self) -> bool:
        state = "released"
        for r in self.store.iter_records():
            if r.payload.get("signal") == SIGNAL and r.payload.get("state") in ("engaged", "released"):
                state = r.payload["state"]       # seq-ascending iter → last wins
        return state == "engaged"
