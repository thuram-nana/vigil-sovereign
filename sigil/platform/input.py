"""Per-OS input-injection backends (Phase 8, WS-F F5) — implement `gesture.components.InputBackend`.
Heavy/native deps are detected/lazy so the package imports everywhere; a backend with no available
method is honest-inert (no-ops) rather than fabricating success. `input_backend()` selects by
`sys.platform`. Injection is ALWAYS routed through the SessionGate (a live armed session + the WARDEN
tier) — a backend is never called directly on an auto path."""
from __future__ import annotations

import shutil
import subprocess
import sys


def _run(argv) -> None:
    try:
        subprocess.run(argv, capture_output=True, timeout=5)
    except (subprocess.SubprocessError, OSError):
        pass


class LinuxInputBackend:
    """Prefers `ydotool` (Wayland-capable) then X11 `xdotool`; inert if neither is present."""
    def __init__(self):
        self.method = "ydotool" if shutil.which("ydotool") else ("xdotool" if shutil.which("xdotool") else None)

    def available(self) -> bool:
        return self.method is not None

    def move(self, dx, dy):
        if self.method == "xdotool":
            _run(["xdotool", "mousemove_relative", "--", str(int(dx)), str(int(dy))])
        elif self.method == "ydotool":
            _run(["ydotool", "mousemove", "-x", str(int(dx)), "-y", str(int(dy))])

    def click(self, button="left"):
        if self.method == "xdotool":
            _run(["xdotool", "click", {"left": "1", "middle": "2", "right": "3"}.get(button, "1")])
        elif self.method == "ydotool":
            _run(["ydotool", "click", "0xC0"])

    def scroll(self, dx, dy):
        if self.method == "xdotool":
            _run(["xdotool", "click", "5" if dx > 0 else "4"])
        elif self.method == "ydotool":
            _run(["ydotool", "mousemove", "-w", "-y", str(int(dx))])

    def type(self, text):
        if self.method == "xdotool":
            _run(["xdotool", "type", "--", text])
        elif self.method == "ydotool":
            _run(["ydotool", "type", text])

    def combo(self, keys):
        if self.method == "xdotool":
            _run(["xdotool", "key", keys])
        elif self.method == "ydotool":
            _run(["ydotool", "key", keys])


class _SeamInputBackend:
    """A documented native seam (macOS CGEvent via pyobjc / Windows SendInput via ctypes). Inert until
    the native path is wired — honest no-op, never a fabricated injection."""
    native = ""

    def available(self) -> bool:
        return False

    def move(self, dx, dy): pass
    def click(self, button="left"): pass
    def scroll(self, dx, dy): pass
    def type(self, text): pass
    def combo(self, keys): pass


class MacOSInputBackend(_SeamInputBackend):
    native = "CGEvent (pyobjc); requires Accessibility permission"


class WindowsInputBackend(_SeamInputBackend):
    native = "SendInput (ctypes)"


def input_backend():
    if sys.platform == "darwin":
        return MacOSInputBackend()
    if sys.platform.startswith("win"):
        return WindowsInputBackend()
    return LinuxInputBackend()


def has_hid_inject() -> bool:
    b = input_backend()
    return b.available()
