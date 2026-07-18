"""Capture backends (SIGIL §8). A `Frame` is the immutable record of one capture: the image bytes'
sha256 (integrity), the OCR/accessibility TEXT (the GROUND TRUTH a query is answered from), and a
path to the image. Real backends shell out to whatever is installed (screenshot tool + tesseract,
v4l2/ffmpeg); every backend returns `None` on any failure — a missing camera is no capture, never a
fabricated one (same posture as SCHOLAR.read_source). `StaticFrame` is the deterministic test double.

HONEST GAPS: headless hosts often lack a screenshot tool / tesseract / a camera, so the real
backends degrade to `None` or an image-only Frame (text=""). The richest real screen source is the
OS accessibility tree (C4); it is not available on a headless box and is left as a documented seam."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..reuse import sha256_hex

_SCREENSHOT_TOOLS = (
    ("scrot", ["scrot", "-o"]),
    ("gnome-screenshot", ["gnome-screenshot", "-f"]),
    ("spectacle", ["spectacle", "-b", "-n", "-o"]),
    ("import", ["import", "-window", "root"]),   # ImageMagick
)


@dataclass(frozen=True)
class Frame:
    kind: str                       # "screen" | "camera"
    sha256: str                     # integrity of the captured image bytes
    text: str                       # OCR / accessibility text — the GROUND TRUTH; "" if none
    image_path: Optional[str] = None
    width: int = 0
    height: int = 0

    @classmethod
    def from_image(cls, kind: str, image_path: str, *, text: str = "") -> "Frame":
        data = Path(image_path).read_bytes()
        return cls(kind=kind, sha256=sha256_hex(data), text=text, image_path=image_path)


def _ocr(image_path: str) -> str:
    """Extract text via tesseract if present; '' otherwise (no OCR is not a failure of capture)."""
    if not shutil.which("tesseract"):
        return ""
    try:
        proc = subprocess.run(["tesseract", image_path, "stdout"],
                              capture_output=True, text=True, timeout=30)
        return (proc.stdout or "").strip()
    except (subprocess.SubprocessError, OSError):
        return ""


def grab_screen() -> Optional[Frame]:
    """Screenshot the current display + OCR it. Returns None if no screenshot tool is available
    or the grab fails. The accessibility-tree path (richer, C4) is a documented seam, not wired
    on headless hosts."""
    out = tempfile.mktemp(suffix=".png", prefix="sigil-screen-")
    for name, argv in _SCREENSHOT_TOOLS:
        if not shutil.which(name):
            continue
        try:
            proc = subprocess.run([*argv, out], capture_output=True, text=True, timeout=20)
        except (subprocess.SubprocessError, OSError):
            continue
        if proc.returncode == 0 and Path(out).exists() and Path(out).stat().st_size > 0:
            return Frame.from_image("screen", out, text=_ocr(out))
    return None


def grab_camera(device: str = "/dev/video0") -> Optional[Frame]:
    """Grab a single frame from a v4l2 camera via ffmpeg. Returns None if ffmpeg or the device is
    absent, or the grab fails. Camera frames rarely carry text, so OCR is best-effort."""
    if not shutil.which("ffmpeg") or not Path(device).exists():
        return None
    out = tempfile.mktemp(suffix=".png", prefix="sigil-cam-")
    try:
        proc = subprocess.run(
            ["ffmpeg", "-y", "-f", "v4l2", "-i", device, "-frames:v", "1", out],
            capture_output=True, text=True, timeout=20)
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode == 0 and Path(out).exists() and Path(out).stat().st_size > 0:
        return Frame.from_image("camera", out, text=_ocr(out))
    return None


def StaticFrame(*, kind: str = "screen", text: str = "", tag: str = "") -> Frame:
    """Deterministic test/double frame — no filesystem, sha256 derived from (tag or text) so
    identical content hashes identically (drives ambient change-detection)."""
    return Frame(kind=kind, sha256=sha256_hex((tag or text).encode()), text=text, image_path=None)
