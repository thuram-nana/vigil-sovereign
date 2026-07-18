"""SessionGate (Phase 8, WS-F, THE KEYSTONE) — the ONLY authority that injects input, and only inside
an owner-armed session. Two enforcement layers so a gesture can NEVER trigger an unintended action:

  Layer 1 — the SESSION: `arm()` REQUIRES the owner key (it cannot be armed without the owner
  identity) and appends a signed `gesture.session_armed` record — the tamper-evident AUDIT proof-of-
  authorization, indicator-lit. The INJECTION gate itself is the live in-memory session, held ONLY by
  the owner's own running daemon process; it is BOUNDED by a TTL and ended by disarm / hand-loss /
  expiry. Injection is REFUSED with no live session.

  Layer 2 — per intent, the tier is DERIVED from the WARDEN oracle (`hid.*` names): A1 (pointer
  move/click/scroll/drag) injects within the session; A2 (type/combo/app.launch) is QUEUED for a
  verified owner/device approval bound to `sha256(session_id|tool|args)` and NEVER auto-injected — so
  a gesture alone can never type a password or launch an app.

Only arm/disarm + DISCRETE actions (click/scroll/drag injected; type/launch queued) hit the spine —
per-frame pointer MOVES are telemetry (30 FPS records would DoS the append-only log)."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Optional

from ..agents.base import Tier
from ..reuse import sha256_hex
from .components import InputBackend
from .types import GestureIntent

SESSION_ARMED = "gesture.session_armed"
SESSION_DISARMED = "gesture.session_disarmed"
ACTION_SIGNAL = "gesture.action"

INTENT_TOOL = {
    "move": "hid.pointer.move", "click": "hid.pointer.click",
    "scroll_left": "hid.pointer.scroll", "scroll_right": "hid.pointer.scroll",
    "drag": "hid.pointer.drag", "type": "hid.type", "combo": "hid.combo", "launch": "hid.app.launch",
}


@dataclass
class Session:
    session_id: str
    live: bool = True
    expires_at: float = 0.0            # wallclock deadline — a session is BOUNDED, never indefinite

    def expired(self, now: float) -> bool:
        return self.expires_at > 0.0 and now >= self.expires_at


class SessionGate:
    def __init__(self, store, backend: InputBackend, *, classifier=None, owner_key=None):
        self.store = store
        self.backend = backend
        self._classifier = classifier
        self._owner_key = owner_key
        self.session: Optional[Session] = None

    def _cls(self):
        if self._classifier is None:
            from ..agents.kernel_classify import KernelClassifier
            self._classifier = KernelClassifier()
        return self._classifier

    # --- Layer 1: the owner-armed session ---------------------------------------------------------
    def arm(self, *, owner_key=None, ttl_seconds: float = 1800.0) -> Session:
        from ..governor.authn import signed_payload
        from ..governor.identity import owner_keypair
        ok = owner_key if owner_key is not None else (self._owner_key or owner_keypair())
        if ok is None:
            raise RuntimeError("cannot arm a gesture session without the owner key (BLOCK-3)")
        sid = uuid.uuid4().hex
        core = {"signal": SESSION_ARMED, "session_id": sid}
        self.store.append(kind="event", source="gesture", actor="OWNER",
                          payload={**signed_payload(core, ok), "tier": "A0", "decision": "auto",
                                   "ttl_seconds": ttl_seconds,
                                   "summary": "gesture session ARMED (indicator lit — opt-in)"})
        self.session = Session(sid, live=True, expires_at=time.time() + ttl_seconds)
        return self.session

    def disarm(self) -> None:
        if self.session is not None:
            self.store.append(kind="event", source="gesture", actor="OWNER",
                              payload={"signal": SESSION_DISARMED, "session_id": self.session.session_id,
                                       "tier": "A0", "decision": "auto", "summary": "gesture session DISARMED"})
            self.session.live = False
        self.session = None

    # --- Layer 2: per-intent tier gate ------------------------------------------------------------
    def handle(self, intent: GestureIntent) -> dict:
        """Authorize + act on ONE intent. Returns a verdict dict. Injection ONLY inside a live session
        and ONLY for A1 tools; A2+ queues for approval and injects NOTHING; a danger name → refused."""
        if intent.kind == "hand_lost":
            self.disarm()
            return {"injected": False, "reason": "hand lost — session disarmed"}
        if self.session is None or not self.session.live:
            return {"injected": False, "reason": "no armed session — injection refused"}
        if self.session.expired(time.time()):             # BLOCK-2: a session is bounded, never indefinite
            self.disarm()
            return {"injected": False, "reason": "session expired — disarmed"}
        tool = INTENT_TOOL.get(intent.kind)
        if tool is None:
            return {"injected": False, "reason": f"unknown intent {intent.kind}"}
        tier = self._cls().classify(tool)                 # DERIVED, fail-closed A3 on any error
        args = f"{intent.dx:.4f},{intent.dy:.4f},{intent.arg}"
        if tier <= Tier.A1:
            self._inject(intent)
            # BLOCK-1: log the DISCRETE A1 injections that actually take effect (click/scroll/drag);
            # per-frame `move` is telemetry (logging it at 30 FPS would DoS the append-only spine).
            if intent.kind != "move":
                self.store.append(kind="event", source="gesture", actor="OWNER",
                                  payload={"signal": ACTION_SIGNAL, "decision": "auto", "tier": tier.label(),
                                           "tool": tool, "session_id": self.session.session_id,
                                           "summary": f"gesture {tool} injected"})
            return {"injected": True, "tier": tier.label(), "tool": tool}
        # A2/A3 → QUEUE an approval bound to this exact action; inject NOTHING
        token = sha256_hex(f"{self.session.session_id}|{tool}|{args}".encode("utf-8"))
        seq = self.store.append(kind="event", source="gesture", actor="PERCEPTION",
                                payload={"signal": ACTION_SIGNAL, "decision": "queued",
                                         "status": "awaiting-approval", "tier": tier.label(),
                                         "tool": tool, "action_token": token, "args": args,
                                         "subject": f"gesture action {tool} (awaiting approval)"})
        return {"injected": False, "queued": seq, "tier": tier.label(), "tool": tool, "action_token": token}

    def _inject(self, intent: GestureIntent) -> None:
        b = self.backend
        if intent.kind == "move" or intent.kind == "drag":
            b.move(intent.dx, intent.dy)
        elif intent.kind == "click":
            b.click()
        elif intent.kind == "scroll_left":
            b.scroll(-1, 0)
        elif intent.kind == "scroll_right":
            b.scroll(1, 0)
