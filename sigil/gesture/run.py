"""The live gesture-control daemon (Phase 8, WS-F F7) — camera stream → landmarks → classify → FSM →
SessionGate, mirroring `voice/run.py run_mic`. Arms the session on start (indicator lit), disarms in a
`finally` (indicator cleared even on crash). Graceful fallbacks; components are injectable so the
whole loop runs deterministically on scripted doubles with no camera/model/OS input."""
from __future__ import annotations

from typing import Optional

from .pipeline import GesturePipeline
from .session import SessionGate


def run_gesture(*, store=None, owner_key=None, source=None, landmarker=None, classifier=None,
                backend=None, pipeline=None, gate=None, max_frames: Optional[int] = None,
                auto_arm: bool = True, device_arm: bool = False, trusted_pubkey=None) -> int:
    """Run the loop; returns the number of frames processed. Injectable for tests.

    `auto_arm=True` (default) is the camera path: owner-arm the session locally on start. `auto_arm=False`
    is for a caller that passes an ALREADY-ARMED `gate` — e.g. a LOCAL owner-armed session consuming a
    `remote.RemoteLandmarkSource` (owner arms at the PC; the phone streams landmarks in).

    `device_arm=True` (with `auto_arm=False`) is the REMOTE-arm path: while no session is live, each frame
    the loop consumes the newest RECORDED, not-yet-used device arm request (written by the bridge's
    `submit_arm_request`) via `SessionGate.arm_by_device`, which RE-VERIFIES it fully. Once armed, the
    phone's landmark stream drives the pointer, bounded exactly as a local arm (A1 inject / A2 queue,
    kill-switch/expiry/hand-loss disarm). This is the wiring that makes the trust-widening reachable."""
    if store is None:
        from ..spine.store import SpineStore
        store = SpineStore()
    if source is None:
        from ..perception.camera_stream import CameraStreamSource
        source = CameraStreamSource()
    if landmarker is None:
        from .landmark import OnnxHandLandmarker
        landmarker = OnnxHandLandmarker()
    # STRICT fail-closed egress gate (Phase 9 W2-H): this loop injects HID off a live camera stream,
    # so it refuses UNLESS the landmarker is EXPLICITLY on-box (`egresses is False`) — stricter than
    # perceive's default-safe `getattr(..., "egresses", False)` form, because an unset/unknown flag
    # here would mean streaming owner PIXELS off-box while driving the pointer. This gate refuses a
    # model that would EGRESS owner imagery; a future `RemoteLandmarker` with `egresses=False` (an
    # authorized INBOUND landmark-DATA stream over the owner's own tunnel) is a DISTINCT,
    # separately-authorized thing — it egresses nothing and passes this gate.
    if getattr(landmarker, "egresses", True) is not False:
        store.append(kind="refusal", source="gesture", actor="OWNER",
                     payload={"signal": "gesture.refused", "decision": "refused", "tier": "A0",
                              "reason": "landmark model would egress owner imagery — the gesture "
                                        "loop is on-box only"})
        return 0  # inject NOTHING; never armed
    if classifier is None:
        from .features import RuleClassifier
        classifier = RuleClassifier()
    if backend is None:
        from ..platform import input_backend
        backend = input_backend()
    pipe = pipeline or GesturePipeline()
    g = gate or SessionGate(store, backend, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    if auto_arm:
        g.arm(owner_key=owner_key)   # camera path: owner-arm locally. When False, the caller's gate is
        # already armed (a LOCAL owner-armed session) and we consume it without a second arm.
    n = 0
    try:
        for frame in source.frames():
            if device_arm and (g.session is None or not g.session.live):
                from .session import pending_device_arm     # REMOTE-arm: consume a recorded arm request
                req = pending_device_arm(store, trusted_pubkey)
                if req is not None:
                    g.arm_by_device(req)                    # re-verifies fully; no-op if it doesn't pass
            reading = classifier.classify(landmarker.detect(frame))
            intent = pipe.on_frame(reading)
            if intent is not None:
                g.handle(intent)
            n += 1
            if max_frames is not None and n >= max_frames:
                break
    finally:
        g.disarm()
    return n
