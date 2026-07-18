"""The kill switch (SIGIL §5) — a single latch that halts the agent mesh while leaving perception and
memory-read (A0 observe) alive. State is append-only on the spine.

ASYMMETRIC AUTHENTICATION (Phase 6 red-pen RP-2): halting is always the safe direction, so ANY
engage event halts (a nuisance forged-engage is at worst a fail-safe DoS). UN-halting is the
dangerous direction, so a RELEASE is honored ONLY if it is signed by the owner key and verifies
against the trusted pubkey — a forged release can never revive a halted mesh. Read fresh per decision
so a release (or engage) takes effect immediately."""
from __future__ import annotations

from typing import Optional

from .authn import signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.killswitch"
_CORE = ("signal", "state")


class KillSwitch:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def engage(self, *, by: str = "owner", reason: str = "") -> int:
        core = {"signal": SIGNAL, "state": "engaged"}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def release(self, *, by: str = "owner", reason: str = "") -> int:
        core = {"signal": SIGNAL, "state": "released"}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def is_engaged(self) -> bool:
        engaged = False
        for r in self.store.iter_records():
            p = r.payload
            if p.get("signal") != SIGNAL:
                continue
            state = p.get("state")
            if state == "engaged":
                engaged = True                      # honor ANY engage — halting is fail-safe
            elif state == "released" and verify_signed(p, _CORE, self.trusted_pubkey):
                engaged = False                     # only an OWNER-SIGNED release un-halts (fail-closed)
        return engaged
