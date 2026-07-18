"""The live gesture-control daemon (Phase 8, WS-F F7) — camera stream → landmarks → classify → FSM →
SessionGate, mirroring `voice/run.py run_mic`. Arms the session on start (indicator lit), disarms in a
`finally` (indicator cleared even on crash). Graceful fallbacks; components are injectable so the
whole loop runs deterministically on scripted doubles with no camera/model/OS input."""
from __future__ import annotations

from typing import Optional

from .pipeline import GesturePipeline
from .session import SessionGate


def run_gesture(*, store=None, owner_key=None, source=None, landmarker=None, classifier=None,
                backend=None, pipeline=None, gate=None, max_frames: Optional[int] = None) -> int:
    """Run the loop; returns the number of frames processed. Injectable for tests."""
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
    g = gate or SessionGate(store, backend, owner_key=owner_key)
    g.arm(owner_key=owner_key)
    n = 0
    try:
        for frame in source.frames():
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
