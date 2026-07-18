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
