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
from .navmode import nav_mode_on as _nav_mode_on
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

# S3: in owner-enabled nav-mode, these DISCRETE gestures NAVIGATE the UI instead of scrolling/clicking —
# an A1 `sigil.nav` SIGNAL that injects NOTHING (no hid.*). Swipe-right → next screen, swipe-left → prev,
# pinch → home. Checked ONLY for these kinds, so a 30 fps `move` never reads the nav-mode latch; every
# other intent (move/drag/type/launch) is unchanged whether nav-mode is on or off.
_NAV_GESTURE_MAP = {"scroll_right": ("nav", "next"), "scroll_left": ("nav", "prev"),
                    "click": ("screen_id", "home")}


def pending_device_arms(store, trusted_pubkey=None):
    """ALL RECORDED device arm requests (written by the bridge's `submit_arm_request`) that have NOT yet
    armed a session, OLDEST-FIRST — candidates for `arm_by_device`, which RE-VERIFIES each fully (auth /
    freshness / kill-switch / replay / single-session / TTL). Returns a list (possibly empty). Oldest-first
    + returning ALL candidates means a newer STALE request never shadows an older still-valid one. This is
    the wiring that makes the remote-arm path reachable end-to-end (the gesture daemon consumes it)."""
    from ..spine.snapshot import SnapshotState
    st = SnapshotState.load(store)
    # SEED the `armed` set-union replay ledger from the folded pruned prefix [0..base_seq) (a COPY — never
    # mutate the cached snapshot), then fold ONLY the live records [base_seq..T]. The arm ledger is the
    # snapshot-covered `consumed_arm_nonces`, which is NOT pubkey-dependent (build() unions every device arm
    # unconditionally, no verify_signed), so `trusted_pubkey` needs no trust-anchor bypass here.
    # NOTE: the `cands` list (unconsumed ARM_REQUESTs) is NOT snapshot-covered — a pruned unconsumed
    # ARM_REQUEST does not survive into `st`. This is BEHAVIOR-PRESERVING because ARM_FRESHNESS (30s) <<
    # spine retention: any arm-request old enough to be pruned is already past freshness, so arm_by_device
    # would refuse it as stale — a pruned arm-request is un-armable and never belongs in a live candidate.
    # Byte-identical under the empty snapshot: base_seq==0 => since_seq==-1 => the current full genesis scan,
    # and arm_set() == {} seeds `armed` empty => the same `armed`/`cands`/result as before.
    armed = set(st.arm_set())
    cands = []
    for r in store.iter_records(since_seq=st.base_seq - 1):
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
    # For a DEVICE-armed session (arm_by_device), the arming device's pubkey. `handle` re-checks that this
    # key is still owner-authorized every frame (bounded), so an owner `mesh revoke` terminates an in-flight
    # session immediately — not at TTL. None for an owner-armed session (not device-gated).
    armed_by_device: Optional[str] = None

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
        self._ks_token: tuple | None = None   # last-scanned spine change token; None forces a fresh check first
        self._ks_checked_at = -1e9
        # device-revocation rescan cache (mirrors the kill-switch cache) — for a device-armed session, has
        # the arming device been revoked. `_dev_authorized=True` until the first scan (the device WAS
        # authorized at arm time); reset on every arm_by_device.
        self._dev_token: tuple | None = None
        self._dev_checked_at = -1e9
        self._dev_authorized = True
        # gesture-capability latch rescan cache (mirrors the kill-switch cache). `_cap_gesture=True` until the
        # first scan (default enabled); an owner `capability gesture off` APPENDS → the token moves → the
        # disable is honored within ~1-2 frames, not at TTL.
        self._cap_gesture = True
        self._cap_token: tuple | None = None
        self._cap_checked_at = -1e9

    def _trusted(self):
        if self._trusted_pubkey is None:
            from ..governor.identity import owner_pubkey
            self._trusted_pubkey = owner_pubkey()
        return self._trusted_pubkey

    def _killswitch_engaged(self, now: float) -> bool:
        """Kill-switch state for the per-intent gate. Re-scans the AUTHORITATIVE `KillSwitch` (which
        verifies the owner-signed release — never re-implemented here) ONLY when the store's ROTATION-AWARE
        change token has moved since the last scan: a panic APPENDS a record → the token changes → the halt
        is honored within ~1-2 frames (≈66 ms worst case), not a fixed 0.5 s. A pure-movement gesture
        appends nothing, so the token is unchanged and this is cheap with NO scan. Using the change token
        (invariant 9 / A4) rather than `store.path.stat()` is what keeps a panic observable AFTER a
        migration — a bare size check would raise/freeze once spine.jsonl is renamed away, silently
        stranding a device-armed session in the un-halted state. A short `_KS_MIN_RESCAN` floor caps a
        churning spine at per-floor scanning. The arm path checks FRESH."""
        token = self.store.change_token()
        if token != self._ks_token and (now - self._ks_checked_at) >= _KS_MIN_RESCAN:
            from ..governor.killswitch import KillSwitch
            self._ks_engaged = KillSwitch(self.store).is_engaged()
            self._ks_token = token
            self._ks_checked_at = now
        return self._ks_engaged

    def _cap_gesture_enabled(self, now: float) -> bool:
        """Gesture-capability latch for the per-intent gate, bounded by the SAME rotation-aware change-token
        + rescan floor as the kill-switch: an owner `capability gesture off` APPENDS a record → the token
        moves → the disable is honored within ~1-2 frames, while a 30fps pure-movement loop appends nothing →
        the token is unchanged → no re-scan (cheap, O(1)). `CapabilityGate.is_enabled` is itself fail-closed
        (any read/scan error → disabled), so a scan failure here safely resolves toward disabled."""
        token = self.store.change_token()
        if token != self._cap_token and (now - self._cap_checked_at) >= _KS_MIN_RESCAN:
            from ..governor.capability import CapabilityGate
            self._cap_gesture = CapabilityGate(self.store, trusted_pubkey=self._trusted()).is_enabled("gesture")
            self._cap_token = token
            self._cap_checked_at = now
        return self._cap_gesture

    def _arming_device_revoked(self, now: float) -> bool:
        """For a DEVICE-armed session, True once the arming device's key is NO LONGER owner-authorized —
        so an owner `sigil mesh revoke` terminates an in-flight session within the same ~1-2 frame window
        as a kill-switch, not at TTL (closing the eventual-revocation gap on the gesture-injection path).
        Owner-armed sessions (``armed_by_device`` is None) are never device-gated. Bounded by the SAME
        rotation-aware change-token + rescan floor as the kill-switch: a `device_revoked` record APPENDS →
        the token moves → the revoke is honored within ~1-2 frames, while a 30fps pure-movement loop
        appends nothing → the token is unchanged → no re-scan (cheap). Fail-closed: a scan error leaves the
        cached verdict unchanged (never silently re-authorizes)."""
        s = self.session
        if s is None or s.armed_by_device is None:
            return False
        token = self.store.change_token()
        if token != self._dev_token and (now - self._dev_checked_at) >= _KS_MIN_RESCAN:
            from ..mesh import authorized_devices
            try:
                self._dev_authorized = s.armed_by_device in authorized_devices(self.store, self._trusted())
            except Exception:  # noqa: BLE001 — cannot confirm authorization ⇒ FAIL-CLOSED: treat as revoked
                self._dev_authorized = False   # a scan failure must never let a possibly-revoked device act
            self._dev_token = token
            self._dev_checked_at = now
        return not self._dev_authorized

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
        # gesture-capability latch — a disabled gesture capability refuses even an owner-local arm (loud
        # refusal, recorded), so the owner's own toggle governs the local path too.
        from ..governor.capability import CapabilityGate
        if not CapabilityGate(self.store, trusted_pubkey=self._trusted()).is_enabled("gesture"):
            self.store.append(kind="refusal", source="gesture", actor="OWNER",
                              payload={"signal": SESSION_ARMED, "decision": "refused", "tier": "A0",
                                       "reason": "gesture capability disabled",
                                       "summary": "gesture arm refused: capability disabled (governed latch)"})
            raise RuntimeError("gesture capability disabled (governed latch)")
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
        # (1.5) gesture-capability latch — a disabled gesture capability refuses any (device) arm, fail-safe.
        from ..governor.capability import CapabilityGate
        if not CapabilityGate(self.store, trusted_pubkey=self._trusted()).is_enabled("gesture"):
            self._refuse_arm(request, "gesture capability disabled")
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
        from ..spine.snapshot import SnapshotState
        st = SnapshotState.load(self.store)
        # The pruned prefix's consumed (device, nonce) arms are folded into the snapshot's set-union arm
        # ledger; if this (pub, nonce) already armed in [0..base_seq), refuse. `nonce` type is preserved
        # VERBATIM (int vs str — arm_set() rows round-trip type-exact; do NOT stringify). This fold is NOT
        # pubkey-dependent (build() unions every device arm unconditionally), so no trust-anchor bypass.
        # Byte-identical under the empty snapshot: arm_set() == {} (never matches) and base_seq==0 =>
        # since_seq==-1 => the current full genesis scan below.
        if (pub, nonce) in st.arm_set():
            self._refuse_arm(request, "replayed arm nonce")
            return None
        for r in self.store.iter_records(since_seq=st.base_seq - 1):
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
        # reset the device-revocation rescan cache for this new session (the device is authorized right
        # now — we just verified its signature against the authorized set), then record it on the session
        # so `handle` re-checks its continued authorization every frame.
        self._dev_token, self._dev_checked_at, self._dev_authorized = None, -1e9, True
        self.session = Session(sid, live=True, expires_at=now + ttl, armed_by_device=pub)
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
        # A governed `capability gesture off` latch neuters injection mid-session within the same ~1-2 frame
        # window (bounded exactly like the kill-switch), so an owner can shut gesture control off from the
        # cockpit/CLI/phone and it stops almost immediately — not at TTL. Fail-safe: disabled wins.
        if not self._cap_gesture_enabled(time.time()):
            self.disarm()
            return {"injected": False, "reason": "gesture capability disabled (governed latch) — session disarmed"}
        # A revoked arming device neuters its own in-flight session within ~1-2 frames (the 0.05s rescan
        # floor, bounded exactly like the kill-switch), NOT at TTL — an owner who revokes a lost/
        # compromised phone stops it almost immediately instead of up to MAX_DEVICE_TTL later.
        if self._arming_device_revoked(time.time()):
            self.disarm()
            return {"injected": False, "reason": "arming device revoked — session disarmed"}
        if self.session is None or not self.session.live:
            return {"injected": False, "reason": "no armed session — injection refused"}
        if self.session.expired(time.time()):             # BLOCK-2: a session is bounded, never indefinite
            self.disarm()
            return {"injected": False, "reason": "session expired — disarmed"}
        # S3: nav-mode — a DISCRETE gesture NAVIGATES the UI (an A1 sigil.nav SIGNAL that injects NOTHING)
        # instead of scrolling/clicking. Reached only AFTER every per-frame gate above (kill-switch, gesture
        # capability, device-revoke, live+unexpired armed session) — so a nav gesture is subject to the exact
        # same guards, and it maps to NO hid.* tool: nothing is ever typed, launched, or injected into the OS.
        if intent.kind in _NAV_GESTURE_MAP and _nav_mode_on(self.store):
            return self._emit_nav_gesture(intent.kind)
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

    def _emit_nav_gesture(self, kind: str) -> dict:
        """Emit an A1 sigil.nav SIGNAL for a nav-mode gesture and inject NOTHING. Swipe → a relative
        direction (next/prev, stepped by the browser); pinch → an absolute screen_id ("home"). The payload
        carries no CONTENT_FIELDS (fully plaintext, no vault). Calls NO input backend — the OS is untouched."""
        key, val = _NAV_GESTURE_MAP[kind]
        payload = {"signal": "sigil.nav", "tier": "A1", "decision": "auto", "source": "gesture",
                   "session_id": self.session.session_id, key: val}
        seq = self.store.append(kind="event", source="gesture", actor="OWNER", payload=payload)
        return {"injected": False, "nav": val, "seq": seq, "tool": None}

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
