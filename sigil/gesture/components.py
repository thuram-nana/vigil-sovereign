"""Gesture component Protocols + zero-dependency deterministic doubles (Phase 8, WS-F) — mirrors
`voice/components.py`. Every FSM/session/gate test runs against these scripted doubles: no camera, no
model, no OS input. The real providers (`landmark.OnnxHandLandmarker`, `classifier.*`, the platform
`InputBackend`s) live behind the same Protocols and lazy-import their heavy deps."""
from __future__ import annotations

from typing import List, Optional, Protocol, runtime_checkable

from .types import GestureReading, Hand


@runtime_checkable
class LandmarkModel(Protocol):
    egresses: bool                                    # on-box models are False; the loop refuses egressing ones
    def detect(self, image) -> List[Hand]: ...        # 21-keypoint hands, or [] (honest empty)


@runtime_checkable
class GestureModel(Protocol):
    def classify(self, hands: List[Hand]) -> GestureReading: ...


@runtime_checkable
class InputBackend(Protocol):
    def move(self, dx: float, dy: float) -> None: ...
    def click(self, button: str = "left") -> None: ...
    def scroll(self, dx: int, dy: int) -> None: ...
    def type(self, text: str) -> None: ...
    def combo(self, keys: str) -> None: ...


# --- deterministic doubles ------------------------------------------------------------------------
class ScriptedLandmarker:
    """Ignores the image; replays a scripted sequence of hand observations."""
    egresses = False

    def __init__(self, sequence: List[List[Hand]]):
        self._seq = list(sequence)
        self._i = 0

    def detect(self, image) -> List[Hand]:
        if self._i >= len(self._seq):
            return []
        obs = self._seq[self._i]
        self._i += 1
        return obs


class ScriptedGestures:
    """Replays a scripted sequence of GestureReadings (bypasses the model)."""
    def __init__(self, readings: List[GestureReading]):
        self._seq = list(readings)
        self._i = 0

    def classify(self, hands: List[Hand]) -> GestureReading:
        if self._i >= len(self._seq):
            return GestureReading("neutral", 0.0)
        r = self._seq[self._i]
        self._i += 1
        return r


class RecordingInputBackend:
    """Records every injection call; touches NO OS. The double every gate test drives."""
    def __init__(self):
        self.calls: List[tuple] = []

    def move(self, dx, dy): self.calls.append(("move", dx, dy))
    def click(self, button="left"): self.calls.append(("click", button))
    def scroll(self, dx, dy): self.calls.append(("scroll", dx, dy))
    def type(self, text): self.calls.append(("type", text))
    def combo(self, keys): self.calls.append(("combo", keys))
