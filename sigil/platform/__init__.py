"""Per-OS backend abstraction (Phase 7, WS-D D-i). The stack above (perception, voice) speaks the
`Frame` contract; this layer selects a `HostBackend` for the current OS at runtime, so the same
code runs on Linux/macOS/Windows. Linux wraps the existing capture verbatim; macOS/Windows are
additive; every backend returns `None` on unavailability (the honest-gap posture). Offense-free."""
from __future__ import annotations

import sys

from ..reuse import assert_no_offense
from .base import CapabilityDescriptor, HostBackend

assert_no_offense()


def host() -> HostBackend:
    """The backend for this OS (selected by `sys.platform`)."""
    if sys.platform == "darwin":
        from .macos import MacOSBackend
        return MacOSBackend()
    if sys.platform.startswith("win"):
        from .windows import WindowsBackend
        return WindowsBackend()
    from .linux import LinuxBackend
    return LinuxBackend()


__all__ = ["host", "HostBackend", "CapabilityDescriptor"]
