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

import math
import time
import uuid
from dataclasses import dataclass
from typing import Optional

_KS_MIN_RESCAN = 0.05  # re-scan the kill-switch at most ~20x/s even on a churning spine (a cost floor)

from ..agents.base import Tier
from ..reuse import sha256_hex
from .components import InputBackend
from .types import GestureIntent

SESSION_ARMED = "gesture.session_armed"
SESSION_DISARMED = "gesture.session_disarmed"
ACTION_SIGNAL = "gesture.action"
ARM_REQUEST = "gesture.arm_request"

MAX_DEVICE_TTL = 300.0        # a DEVICE-armed session is deliberately SHORTER than a local owner arm (1800)
ARM_FRESHNESS = 30.0          # a device arm request must be recent (anti-stale / bounds the replay window)
_ARM_CORE = ("signal", "device_id", "nonce", "ts", "ttl_seconds")

INTENT_TOOL = {
    "move": "hid.pointer.move", "click": "hid.pointer.click",
    "scroll_left": "hid.pointer.scroll", "scroll_right": "hid.pointer.scroll",
    "drag": "hid.pointer.drag", "type": "hid.type", "combo": "hid.combo", "launch": "hid.app.launch",
}


def pending_device_arms(store, trusted_pubkey=None):
    """ALL RECORDED device arm requests (written by the bridge's `submit_arm_request`) that have NOT yet
    armed a session, OLDEST-FIRST — candidates for `arm_by_device`, which RE-VERIFIES each fully (auth /
    freshness / kill-switch / replay / single-session / TTL). Returns a list (possibly empty). Oldest-first
    + returning ALL candidates means a newer STALE request never shadows an older still-valid one. This is
    the wiring that makes the remote-arm path reachable end-to-end (the gesture daemon consumes it)."""
    armed = set()
    cands = []
    for r in store.iter_records():
        p = r.payload
        if p.get("signal") == SESSION_ARMED and p.get("armed_by") == "device":
            armed.add((p.get("device_pubkey"), p.get("nonce")))
        elif (p.get("signal") == ARM_REQUEST and p.get("decision") == "auto"
              and p.get("sig") and p.get("pubkey")):
            cands.append(dict(p))
    return [c for c in cands if (c.get("pubkey"), c.get("nonce")) not in armed]


def arm_request_message(core: dict) -> bytes:
    """The canonical bytes a device signs to request an arm — ONLY the signed core fields, so a caller
    cannot smuggle unsigned extras. Mirrors the approval/envelope canonical-json contract."""
    from ..reuse import canonical_json
    m = canonical_json({k: core.get(k) for k in _ARM_CORE})
    return m if isinstance(m, bytes) else m.encode("utf-8")


def sign_arm_request(device_key, *, device_id: str, nonce, ts: float, ttl_seconds: float) -> dict:
    """Phone-side: build a device-signed arm request. The device signs with its OWN key (never the owner
    trust-root); the owner authorized this device once via the mesh ledger. This is the credential the
    bridge records and `SessionGate.arm_by_device` verifies."""
    from ..reuse import sign
    core = {"signal": ARM_REQUEST, "device_id": device_id, "nonce": nonce, "ts": ts, "ttl_seconds": ttl_seconds}
    return {**core, "pubkey": device_key.public_key_b64,
            "sig": sign(device_key.private_key_b64, arm_request_message(core))}


@dataclass
class Session:
    session_id: str
    live: bool = True
    expires_at: float = 0.0            # wallclock deadline — a session is BOUNDED, never indefinite

    def expired(self, now: float) -> bool:
        return self.expires_at > 0.0 and now >= self.expires_at


class SessionGate:
    def __init__(self, store, backend: InputBackend, *, classifier=None, owner_key=None, trusted_pubkey=None):
        self.store = store
        self.backend = backend
        self._classifier = classifier
        self._owner_key = owner_key
        self._trusted_pubkey = trusted_pubkey
        self.session: Optional[Session] = None
        self._ks_engaged = False
        self._ks_size = -1                # last-scanned spine size; -1 forces a fresh check on the first consult
        self._ks_checked_at = -1e9

    def _trusted(self):
        if self._trusted_pubkey is None:
            from ..governor.identity import owner_pubkey
            self._trusted_pubkey = owner_pubkey()
        return self._trusted_pubkey

    def _killswitch_engaged(self, now: float) -> bool:
        """Kill-switch state for the per-intent gate. Re-scans the AUTHORITATIVE `KillSwitch` (which
        verifies the owner-signed release — never re-implemented here) ONLY when the append-only spine
        has GROWN since the last scan: a panic APPENDS a record → the file grows → the halt is honored
        within ~1-2 frames (≤ the rescan floor + one frame, ≈66 ms worst case), not a fixed 0.5 s. A
        pure-movement gesture appends nothing, so this is
        O(1) (a `stat`) with NO scan at all. A short `_KS_MIN_RESCAN` floor stops a churning spine from
        forcing a per-frame O(spine) scan (worst-case latency ≤ the floor). The arm path checks FRESH."""
        try:
            size = self.store.path.stat().st_size
        except OSError:
            size = self._ks_size
        if size != self._ks_size and (now - self._ks_checked_at) >= _KS_MIN_RESCAN:
            from ..governor.killswitch import KillSwitch
            self._ks_engaged = KillSwitch(self.store).is_engaged()
            self._ks_size = size
            self._ks_checked_at = now
        return self._ks_engaged

    def _cls(self):
        if self._classifier is None:
            from ..agents.kernel_classify import KernelClassifier
            self._classifier = KernelClassifier()
        return self._classifier

    def _backend_available(self) -> bool:
        """True if the input backend can actually inject (SEAM-HONESTY). A backend with no
        `available()` — e.g. the `RecordingInputBackend` test spy, which faithfully records every
        call — is treated as able. A platform SEAM whose `available()` returns False (macOS/Windows
        native path not wired, or Linux with no ydotool/xdotool) is honestly INERT: it no-ops, so an
        injection is NEVER recorded/returned as done when it physically did nothing."""
        probe = getattr(self.backend, "available", None)
        if probe is None:
            return True
        try:
            return bool(probe())
        except Exception:  # noqa: BLE001 — a backend that can't even answer is treated as unavailable
            return False

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

    # --- Layer 1b: DEVICE-signed remote arm (a deliberate, reviewed trust-widening) ----------------
    def arm_by_device(self, request: dict, *, now: Optional[float] = None) -> Optional[Session]:
        """Arm on a VERIFIED, owner-authorized DEVICE signature (SIGIL §remote-arm). Every downstream
        bound is UNCHANGED — the A1-inject/A2-queue tier gate, the TTL, hand-loss/expiry disarm, and an
        owner disarm/kill that always wins. Fail-closed at each step; a refusal is recorded, never armed."""
        from ..governor.killswitch import KillSwitch
        from ..mesh import authorized_devices
        from ..reuse import verify_one
        now = time.time() if now is None else now
        # (1) kill-switch FIRST — an owner halt (incl. a phone panic) beats any arm.
        if KillSwitch(self.store).is_engaged():
            self._refuse_arm(request, "kill-switch engaged")
            return None
        # (2) owner-minted device key + valid signature over the signed core (RP-APPROVAL-2: the
        #     authorized set is owner-signed only, so a merely-presented key is never trusted).
        if request.get("signal") != ARM_REQUEST:
            self._refuse_arm(request, "not an arm request")
            return None
        pub = request.get("pubkey")
        authorized = authorized_devices(self.store, self._trusted())
        core = {k: request.get(k) for k in _ARM_CORE}
        try:                                            # verify_one RAISES on a malformed-length sig — treat as refusal
            sig_ok = bool(pub) and pub in authorized and verify_one(pub, arm_request_message(core), request.get("sig", ""))
        except Exception:  # noqa: BLE001 — any crypto/decoding error is a fail-closed refusal, never a crash
            sig_ok = False
        if not sig_ok:
            self._refuse_arm(request, "unauthorized or invalid device signature")
            return None
        # (3) freshness — bounds the replay window and rejects a stale captured request. Written
        #     fail-CLOSED for non-finite input: `nan > 30` is False, so a signed NaN ts would slip a
        #     `>`-style gate; require finite AND within-window explicitly.
        try:
            # request is a caller-supplied dict; a missing/None ts hits the except below (fail-closed)
            ts = float(request.get("ts"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            self._refuse_arm(request, "missing/invalid timestamp")
            return None
        if not math.isfinite(ts) or not (abs(now - ts) <= ARM_FRESHNESS):
            self._refuse_arm(request, "stale or non-finite timestamp")
            return None
        # (4) replay — this (device, nonce) must not have armed before (the append-only spine is witness).
        nonce = request.get("nonce")
        for r in self.store.iter_records():
            p = r.payload
            if (p.get("signal") == SESSION_ARMED and p.get("armed_by") == "device"
                    and p.get("device_pubkey") == pub and p.get("nonce") == nonce):
                self._refuse_arm(request, "replayed arm nonce")
                return None
        # (5) single live session — a device arm NEVER displaces an existing/owner session.
        if self.session is not None and self.session.live and not self.session.expired(now):
            self._refuse_arm(request, "a gesture session is already live")
            return None
        # (6) TTL clamp — shorter than a local owner arm; a deliberate trust-narrowing inside the widening.
        #     Reject non-finite/non-positive BEFORE the min() (min(nan,300)=nan → a never-expiring session).
        try:
            raw_ttl = float(request.get("ttl_seconds", MAX_DEVICE_TTL))
        except (TypeError, ValueError):
            self._refuse_arm(request, "invalid ttl")
            return None
        if not math.isfinite(raw_ttl) or raw_ttl <= 0:
            self._refuse_arm(request, "non-finite or non-positive ttl")
            return None
        ttl = min(raw_ttl, MAX_DEVICE_TTL)
        sid = uuid.uuid4().hex
        # The record's AUTHORIZATION is the verified device signature — self-verifying vs the owner-signed
        # device ledger; actor=DEVICE mirrors submit_device_approval. Store the ORIGINAL SIGNED core
        # fields (so the sig re-verifies for ANY ttl, incl. a clamped one) + the effective TTL separately,
        # and ONLY known fields (never `**request` — no unsigned extras persisted).
        self.store.append(kind="event", source="gesture", actor="DEVICE",
                          payload={"signal": SESSION_ARMED, "session_id": sid, "armed_by": "device",
                                   "device_id": core["device_id"], "device_pubkey": pub,
                                   "nonce": core["nonce"], "ts": core["ts"],
                                   "ttl_seconds": core["ttl_seconds"],   # ORIGINAL signed value → sig re-verifies
                                   "effective_ttl": ttl,                 # the CLAMPED ttl actually enforced
                                   "sig": request.get("sig"), "pubkey": pub, "authorization": "device-signed",
                                   "tier": "A0", "decision": "auto",
                                   "summary": "gesture session ARMED by authorized device (remote)"})
        self.session = Session(sid, live=True, expires_at=now + ttl)
        return self.session

    def _refuse_arm(self, request: dict, reason: str) -> None:
        self.store.append(kind="refusal", source="gesture", actor="DEVICE",
                          payload={"signal": ARM_REQUEST, "decision": "refused", "tier": "A0",
                                   "device_id": request.get("device_id"), "reason": reason,
                                   "summary": f"device gesture arm refused: {reason}"})
        return None

    # --- Layer 2: per-intent tier gate ------------------------------------------------------------
    def handle(self, intent: GestureIntent) -> dict:
        """Authorize + act on ONE intent. Returns a verdict dict. Injection ONLY inside a live session
        and ONLY for A1 tools; A2+ queues for approval and injects NOTHING; a danger name → refused."""
        if intent.kind == "hand_lost":
            self.disarm()
            return {"injected": False, "reason": "hand lost — session disarmed"}
        # An owner halt (incl. a phone panic_engage) neuters injection mid-session — critical for a
        # device-armed session the owner may not be watching. `_killswitch_engaged` only re-scans when the
        # spine GREW (a panic appends → detected within ~1-2 frames), so a 30fps movement loop never
        # re-scans per frame; latency is bounded by the rescan floor, not a fixed TTL.
        if self._killswitch_engaged(time.time()):
            self.disarm()
            return {"injected": False, "reason": "kill-switch engaged — session disarmed"}
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
            acted = self._backend_available()   # a platform SEAM (available()==False) is honestly inert
            self._inject(intent)                # an inert backend no-ops → NOTHING is physically injected
            # BLOCK-1: log the DISCRETE A1 injections that actually take effect (click/scroll/drag);
            # per-frame `move` is telemetry (logging it at 30 FPS would DoS the append-only spine).
            # SEAM-HONESTY: never let the audit log CLAIM an injection the backend didn't perform —
            # when the backend is inert, record honestly (`backend_inert: True`, "NOT injected"), and
            # return injected=False. The A2-queue path below is unchanged.
            if intent.kind != "move":
                payload = {"signal": ACTION_SIGNAL, "decision": "auto", "tier": tier.label(),
                           "tool": tool, "session_id": self.session.session_id,
                           "summary": (f"gesture {tool} injected" if acted
                                       else f"gesture {tool} NOT injected — input backend inert (no-op)")}
                if not acted:
                    payload["backend_inert"] = True
                self.store.append(kind="event", source="gesture", actor="OWNER", payload=payload)
            verdict = {"injected": bool(acted), "tier": tier.label(), "tool": tool}
            if not acted:
                verdict["backend_inert"] = True
                verdict["reason"] = "input backend inert — no physical injection performed"
            return verdict
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
