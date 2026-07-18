"""Per-scope promotion policy (SIGIL §5). An owner may promote a specific (agent, scope) so its A2
proposals auto-approve instead of queuing — EXCEPT ENVOY, which has NO promotion path (§4.6). A3
never promotes.

AUTHENTICATED (Phase 6 red-pen RP-2/RP-4): a grant/revoke is meaningless unless SIGNED by the owner
key and verified against the persisted trusted pubkey. `is_promoted` ignores any grant that does not
verify — so a forged grant written by a prompt-injected agent via `self.store` grants nothing. The
gate scope is the proposal's RECORD KIND (the real action written), not a self-asserted label
(RP-3), so a promotion is "agent X may auto-approve A2 records of kind K." """
from __future__ import annotations

from typing import Optional

from .authn import signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.promotion"
NO_PROMOTION_AGENTS = frozenset({"ENVOY", "DELEGATE"})   # outbound + account actions stay human-gated forever
_CORE = ("signal", "state", "agent", "scope")


class PromotionPolicy:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def grant(self, agent: str, scope: str = "*"):
        if agent in NO_PROMOTION_AGENTS:
            self.store.append(kind="refusal", source="governor", actor="WARDEN",
                              payload={"signal": SIGNAL, "decision": "refused", "agent": agent,
                                       "scope": scope, "tier": "A0",
                                       "reason": f"{agent} has no promotion path (SIGIL §4.6) — outbound stays human-gated"})
            return None
        core = {"signal": SIGNAL, "state": "granted", "agent": agent, "scope": scope}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def revoke(self, agent: str, scope: str = "*") -> int:
        core = {"signal": SIGNAL, "state": "revoked", "agent": agent, "scope": scope}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def is_promoted(self, agent: str, scope: str = "*") -> bool:
        if agent in NO_PROMOTION_AGENTS:
            return False                          # never — structural, not policy
        state: dict = {}
        for r in self.store.iter_records():
            p = r.payload
            if p.get("signal") != SIGNAL or p.get("state") not in ("granted", "revoked"):
                continue
            if not verify_signed(p, _CORE, self.trusted_pubkey):
                continue                          # fail-closed: an unsigned/forged grant grants nothing
            state[(p.get("agent"), p.get("scope"))] = p["state"]   # latest verified wins
        return state.get((agent, scope)) == "granted" or state.get((agent, "*")) == "granted"
