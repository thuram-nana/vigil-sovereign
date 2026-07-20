"""SIGIL-HAND (Phase 8, WS-F) — fast, owner-armed hand-gesture control: a device camera → on-box
deep-learning hand tracking → a debounced intent FSM → WARDEN-gated input injection. Observes the
owner's OWN hand and controls the owner's OWN device — offense-free. Injection happens ONLY inside an
owner-armed session; discrete actions (type/launch) are queued for approval; a gesture can never type
a password or launch an app on its own."""
from ..reuse import assert_no_offense

assert_no_offense()

from .pipeline import GesturePipeline  # noqa: E402
from .session import Session, SessionGate  # noqa: E402
from .types import GestureIntent, GestureReading, Hand  # noqa: E402

__all__ = ["GesturePipeline", "SessionGate", "Session", "Hand", "GestureReading", "GestureIntent"]
