"""SIGIL Perception subsystem (Phase 5, SIGIL §8). On-demand screen/camera capture → a grounded
perception answer. The DISCIPLINE mirrors SCHOLAR's serve-the-quote gate: the CAPTURED TEXT
(accessibility tree / OCR) is the AUTHORITATIVE ground truth; the VLM's visual reading is
ADVISORY only, never asserted as the screen's content. Ambient vision (C6) is opt-in, indicator-
lit, and escalates only on a detected change — nothing persists beyond event records.

Offense-free by doctrine: perception observes the owner's OWN screen/camera; it takes no
external action (ceiling A0/A1)."""
from ..reuse import assert_no_offense

assert_no_offense()

from .capture import Frame, grab_camera, grab_screen  # noqa: E402
from .delta import changed  # noqa: E402
from .perceive import Perceptor, compose_perception  # noqa: E402
from .recall import recall  # noqa: E402
from .veracity import corroborate  # noqa: E402
from .vision import ClaudeVision, MoondreamVision, VisionModel  # noqa: E402

__all__ = ["Frame", "grab_screen", "grab_camera", "Perceptor", "compose_perception",
           "VisionModel", "ClaudeVision", "MoondreamVision", "corroborate", "recall", "changed"]
