"""Windows backend (Phase 7, WS-D) — screen via the optional `mss` package; camera an honest gap.
Additive; returns None when `mss` is unavailable."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

from ..perception.capture import Frame, _ocr
from .base import CapabilityDescriptor, host_id, probe_always_on, probe_gpu_vlm


def _has_mss() -> bool:
    try:
        import mss  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


class WindowsBackend:
    def capture_screen(self) -> Optional[Frame]:
        try:
            import mss
            out = tempfile.mktemp(suffix=".png", prefix="sigil-screen-")
            with mss.mss() as sct:
                sct.shot(output=out)
            if Path(out).exists() and Path(out).stat().st_size > 0:
                return Frame.from_image("screen", out, text=_ocr(out))
        except Exception:  # noqa: BLE001 — no mss / grab failure → honest None
            return None
        return None

    def capture_camera(self) -> Optional[Frame]:
        return None

    def capabilities(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            host_id=host_id(), os="windows", has_screen=_has_mss(), has_camera=False,
            has_gpu_vlm=probe_gpu_vlm(), always_on=probe_always_on())
