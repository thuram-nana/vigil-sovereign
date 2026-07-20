"""macOS backend (Phase 7, WS-D) — screen via `screencapture`; camera left as an honest gap
(`imagesnap` is an optional add). Additive; returns None when the native tool is absent."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..perception.capture import Frame, _ocr
from .base import CapabilityDescriptor, host_id, probe_always_on, probe_gpu_vlm


class MacOSBackend:
    def capture_screen(self) -> Optional[Frame]:
        if not shutil.which("screencapture"):
            return None
        out = tempfile.mktemp(suffix=".png", prefix="sigil-screen-")
        try:
            subprocess.run(["screencapture", "-x", out], capture_output=True, timeout=20)
        except (subprocess.SubprocessError, OSError):
            return None
        if Path(out).exists() and Path(out).stat().st_size > 0:
            return Frame.from_image("screen", out, text=_ocr(out))
        return None

    def capture_camera(self) -> Optional[Frame]:
        return None                                   # honest gap (optional imagesnap add)

    def capabilities(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            host_id=host_id(), os="macos", has_screen=bool(shutil.which("screencapture")),
            has_camera=False, has_gpu_vlm=probe_gpu_vlm(), always_on=probe_always_on())
