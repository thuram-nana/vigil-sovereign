"""Per-OS backend abstraction (Phase 7, WS-D D-i). The stack above (perception, voice) speaks the
`Frame` contract; this layer selects a `HostBackend` for the current OS at runtime, so the same
code runs on Linux/macOS/Windows. Linux wraps the existing capture verbatim; macOS/Windows are
additive; every backend returns `None` on unavailability (the honest-gap posture). Offense-free."""
from __future__ import annotations

import sys

from ..reuse import assert_no_offense
from .base import CapabilityDescriptor, HostBackend

assert_no_offense()


def input_backend():
    """The InputBackend for this OS (WS-F gesture injection). Always routed through the SessionGate."""
    from .input import input_backend as _ib
    return _ib()


def _is_termux() -> bool:
    """True iff this Python core is running under Termux on Android. Termux reports
    `sys.platform == "linux"`, so it is detected by environment/path signals instead."""
    import os
    from pathlib import Path
    if os.environ.get("TERMUX_VERSION"):
        return True
    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    if os.environ.get("ANDROID_ROOT"):
        return True
    try:
        return Path("/data/data/com.termux/files/usr").exists()
    except OSError:
        return False


def host() -> HostBackend:
    """The backend for this OS (selected by `sys.platform`, then a Termux/Android probe)."""
    if sys.platform == "darwin":
        from .macos import MacOSBackend
        return MacOSBackend()
    if sys.platform.startswith("win"):
        from .windows import WindowsBackend
        return WindowsBackend()
    if _is_termux():                       # Termux reports linux — describe the phone honestly
        from .android import AndroidBackend
        return AndroidBackend()
    from .linux import LinuxBackend
    return LinuxBackend()


__all__ = ["host", "input_backend", "HostBackend", "CapabilityDescriptor"]
