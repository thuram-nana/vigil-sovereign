"""Range Control — the operator cockpit that drives the real VIGIL verbs against MERIDIAN.

Security posture: the runner executes only a CLOSED SET of curated verb templates with the target and slug
FIXED (127.0.0.1 / meridian). No browser-supplied string ever reaches an argv. It invokes VIGIL's normal,
gated CLI — it never bypasses the charter, scope gate, or kill-switch. It is a launcher + viewer.
"""

from __future__ import annotations

from .console import build_control_router

__all__ = ["build_control_router"]
