"""Linux backend (Phase 7, WS-D) — wraps the existing perception capture verbatim (behaviour-
preserving; the whole stack above is unchanged)."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from ..perception.capture import Frame, grab_camera, grab_screen
from .base import CapabilityDescriptor, host_id, probe_always_on, probe_gpu_vlm

_SCREEN_TOOLS = ("scrot", "gnome-screenshot", "spectacle", "import")


class LinuxBackend:
    def capture_screen(self) -> Optional[Frame]:
        return grab_screen()

    def capture_camera(self) -> Optional[Frame]:
        return grab_camera()

    def capabilities(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            host_id=host_id(), os="linux",
            has_screen=any(shutil.which(t) for t in _SCREEN_TOOLS),
            has_camera=Path("/dev/video0").exists(),
            has_gpu_vlm=probe_gpu_vlm(), always_on=probe_always_on())
