"""Per-scope promotion policy (SIGIL §5). An owner may promote a specific (agent, scope) so its A2
proposals auto-approve instead of queuing — EXCEPT ENVOY, whose outbound has NO promotion path by
construction (SIGIL §4.6: "outbound comms stay human-gated permanently"). A3 never promotes.

Grants/revokes are append-only spine events (auditable); latest per (agent, scope) wins. A grant of
scope "*" promotes every scope for that agent. A promotion request for a no-promotion agent is
REFUSED and logged, never silently ignored."""
from __future__ import annotations

SIGNAL = "governor.promotion"
NO_PROMOTION_AGENTS = frozenset({"ENVOY"})   # structural: outbound stays human-gated forever (§4.6)


class PromotionPolicy:
    def __init__(self, store):
        self.store = store

    def grant(self, agent: str, scope: str = "*", *, by: str = "owner"):
        if agent in NO_PROMOTION_AGENTS:
            self.store.append(kind="refusal", source="governor", actor="WARDEN",
                              payload={"signal": SIGNAL, "decision": "refused", "agent": agent,
                                       "scope": scope, "tier": "A0",
                                       "reason": f"{agent} has no promotion path (SIGIL §4.6) — outbound stays human-gated"})
            return None
        return self.store.append(kind="event", source="governor", actor="WARDEN",
                                 payload={"signal": SIGNAL, "state": "granted", "agent": agent,
                                          "scope": scope, "by": by, "tier": "A0", "decision": "auto"})

    def revoke(self, agent: str, scope: str = "*", *, by: str = "owner") -> int:
        return self.store.append(kind="event", source="governor", actor="WARDEN",
                                 payload={"signal": SIGNAL, "state": "revoked", "agent": agent,
                                          "scope": scope, "by": by, "tier": "A0", "decision": "auto"})

    def is_promoted(self, agent: str, scope: str = "*") -> bool:
        if agent in NO_PROMOTION_AGENTS:
            return False                          # never — structural, not policy
        state: dict = {}
        for r in self.store.iter_records():
            p = r.payload
            if p.get("signal") == SIGNAL and p.get("state") in ("granted", "revoked"):
                state[(p.get("agent"), p.get("scope"))] = p["state"]   # latest wins
        return state.get((agent, scope)) == "granted" or state.get((agent, "*")) == "granted"
