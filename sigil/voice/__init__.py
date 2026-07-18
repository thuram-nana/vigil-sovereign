"""SIGIL voice subsystem (Phase 2, SIGIL §8) — wake word → VAD → streaming ASR → KERNEL → TTS,
full-duplex with barge-in. Offense-free by doctrine (assert_no_offense at import). Voice is just
another interface onto the one authorized KERNEL path; recognized text crosses the same T0 router
+ WARDEN gate + signed action log as any other request."""
from ..reuse import assert_no_offense
from ..config import SIGIL_HOME  # noqa: F401 — importing config runs its ~/.sigil/sigil.env loader

assert_no_offense()

from .dispatch import KernelDispatch  # noqa: E402
from .pipeline import State, VoicePipeline  # noqa: E402

__all__ = ["VoicePipeline", "State", "KernelDispatch"]
