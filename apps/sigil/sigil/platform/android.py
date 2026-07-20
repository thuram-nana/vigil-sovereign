"""Android/Termux backend (Phase 9, W2-J) — a phone that runs the SIGIL Python core under Termux.
This is the SECONDARY phone path (the primary is the PWA client in another workstream); it exists so
a Termux host is described HONESTLY instead of silently masquerading as Linux — on Termux
`sys.platform == "linux"`, so without this the `host()` selector would return a LinuxBackend that
lies about `os` and probes `/dev/video0` that a phone does not have.

Camera via `termux-camera-photo` from the `termux-api` package; screen via Android's `screencap`
when present (usually unavailable without root — honest `None` then). A phone does NOT inject HID
into the PC, so `has_hid_inject` is honestly `False`. Additive; every capture returns `None` on any
failure (subprocess with a timeout, no shell). Offense-free."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..perception.capture import Frame, _ocr
from .base import CapabilityDescriptor, host_id


def _has_camera() -> bool:
    return shutil.which("termux-camera-photo") is not None


def _has_screencap() -> bool:
    return shutil.which("screencap") is not None


class AndroidBackend:
    def capture_screen(self) -> Optional[Frame]:
        if not _has_screencap():
            return None                                # honest gap — no screencap (often root-only)
        out = tempfile.mktemp(suffix=".png", prefix="sigil-screen-")
        try:
            subprocess.run(["screencap", "-p", out], capture_output=True, timeout=20)
        except (subprocess.SubprocessError, OSError):
            return None
        if Path(out).exists() and Path(out).stat().st_size > 0:
            return Frame.from_image("screen", out, text=_ocr(out))
        return None

    def capture_camera(self) -> Optional[Frame]:
        if not _has_camera():
            return None                                # honest gap — termux-api not installed
        out = tempfile.mktemp(suffix=".jpg", prefix="sigil-cam-")
        try:
            subprocess.run(["termux-camera-photo", "-c", "0", out],
                           capture_output=True, timeout=30)
        except (subprocess.SubprocessError, OSError):
            return None
        if Path(out).exists() and Path(out).stat().st_size > 0:
            return Frame.from_image("camera", out, text=_ocr(out))
        return None

    def capabilities(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            host_id=host_id(), os="android",
            has_screen=_has_screencap(), has_camera=_has_camera(),
            has_gpu_vlm=False, always_on=False,
            has_hid_inject=False, has_camera_stream=False)
