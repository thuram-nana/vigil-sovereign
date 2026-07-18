"""GesturePipeline (Phase 8, WS-F) — a frame-driven, debounced intent FSM, a structural copy of
`voice/pipeline.py`: timing in FRAME COUNTS (not wallclock), hysteresis so one noisy frame fires
NOTHING. `on_frame(reading) -> Optional[GestureIntent]`. Fail-safe by construction:

  • a POINT pose drives continuous pointer `move` intents (deadzone-filtered);
  • a discrete gesture (pinch→click, swipe→scroll, spread→launch, twofinger→type) fires ONLY after
    `confirm_frames` consecutive identical HIGH-confidence, HIGH-margin readings, then a cooldown;
  • low confidence OR a small top1−top2 margin ⇒ NEUTRAL ⇒ counter resets ⇒ nothing fires (ambiguity
    does nothing);
  • `hand_lost_frames` of no-hand/neutral ⇒ a `hand_lost` intent so the session AUTO-DISARMS.

The FSM decides INTENT; authorization (a live armed session + the WARDEN tier) is the SessionGate's
job — so this stays a pure, deterministically-testable state machine."""
from __future__ import annotations

from typing import Optional

from .types import GestureIntent, GestureReading

# discrete gesture label → intent kind (a POINT pose is the continuous move driver, handled separately)
DISCRETE = {
    "pinch": "click", "swipe_left": "scroll_left", "swipe_right": "scroll_right",
    "spread": "launch", "twofinger": "type", "grab": "drag",
}


class GesturePipeline:
    def __init__(self, *, confirm_frames: int = 4, cooldown_frames: int = 6, hand_lost_frames: int = 8,
                 conf_min: float = 0.6, margin_min: float = 0.15, deadzone: float = 0.002):
        self.confirm_frames = confirm_frames
        self.cooldown_frames = cooldown_frames
        self.hand_lost_frames = hand_lost_frames
        self.conf_min = conf_min
        self.margin_min = margin_min
        self.deadzone = deadzone
        self._label: Optional[str] = None
        self._count = 0
        self._cool = 0
        self._lost = 0

    def on_frame(self, reading: Optional[GestureReading]) -> Optional[GestureIntent]:
        if self._cool > 0:
            self._cool -= 1
        # no hand / explicit neutral → count toward auto-disarm; a discrete streak is broken
        if reading is None or not reading.label or reading.label == "neutral":
            self._label, self._count = None, 0
            self._lost += 1
            if self._lost >= self.hand_lost_frames:
                self._lost = 0
                return GestureIntent("hand_lost")
            return None
        self._lost = 0
        # AMBIGUITY → nothing (fail-safe): a single noisy or low-margin frame cannot fire
        if reading.confidence < self.conf_min or reading.margin < self.margin_min:
            self._label, self._count = None, 0
            return None
        if reading.label == "point":                       # continuous pointer control
            self._label, self._count = None, 0
            if abs(reading.dx) < self.deadzone and abs(reading.dy) < self.deadzone:
                return None
            return GestureIntent("move", dx=reading.dx, dy=reading.dy)
        # a discrete gesture: require `confirm_frames` consecutive identical readings (hysteresis)
        if reading.label == self._label:
            self._count += 1
        else:
            self._label, self._count = reading.label, 1
        if self._count >= self.confirm_frames and self._cool == 0:
            self._count = 0
            self._cool = self.cooldown_frames
            kind = DISCRETE.get(reading.label, "none")
            return GestureIntent(kind, arg=reading.label) if kind != "none" else None
        return None
