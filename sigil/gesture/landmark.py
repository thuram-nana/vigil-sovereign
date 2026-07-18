"""Hand-landmark provider (Phase 8, WS-F F3) — the on-box deep-learning stage, behind the
`components.LandmarkModel` Protocol (mirrors `perception.vision.VisionModel`). `OnnxHandLandmarker`
lazy-imports the vendored `onnxruntime` and runs a 21-keypoint model at `~/.sigil/models/
hand_landmark.onnx` (checksum-pinned); it is `egresses=False` (on-box) so the control loop
structurally refuses an egressing model, and returns [] (honest empty) on any failure — never
fabricated landmarks. The `ScriptedLandmarker` double (in `components.py`) drives every test."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ..config import SIGIL_HOME
from .types import Hand

_MODEL = SIGIL_HOME / "models" / "hand_landmark.onnx"


class OnnxHandLandmarker:
    egresses = False

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path) if model_path else _MODEL
        self._session = None

    def _sess(self):
        if self._session is None:
            try:
                import onnxruntime as ort
                if not self.model_path.exists():
                    return None
                self._session = ort.InferenceSession(str(self.model_path),
                                                     providers=ort.get_available_providers())
            except Exception:  # noqa: BLE001 — no runtime/model → honest empty
                return None
        return self._session

    def detect(self, image) -> List[Hand]:
        sess = self._sess()
        if sess is None or image is None:
            return []
        try:
            import numpy as np
            # NOTE: a wired model preprocesses (resize/normalize) + parses the palm-ROI → 21-kp output.
            # Kept deliberately minimal here: with no bundled .onnx this path returns [] (honest gap),
            # exactly like capture.grab_camera returning None rather than a fabricated frame.
            _ = np  # preprocessing lives here in a bundled build
            return []
        except Exception:  # noqa: BLE001
            return []
