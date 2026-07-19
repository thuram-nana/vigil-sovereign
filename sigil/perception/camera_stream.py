"""Persistent low-latency camera stream (Phase 8, WS-F F2) — a `voice.backends.MicAudioSource`-style
generator over ONE warm `ffmpeg` rawvideo pipe. Unlike `capture.grab_camera` (which cold-starts an
ffmpeg process + writes a PNG + OCRs PER FRAME — hundreds of ms, unusable for control), this keeps the
device handle open and reads raw RGB frames off stdout. Drop-to-latest so inference never queues
behind a slow frame. Honest-empty (no frames) if ffmpeg/device/numpy absent — never a fabricated
frame. `grab_camera` is left untouched (backward-compatible single-shot)."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterator, List, Optional


class CameraStreamSource:
    def __init__(self, device: str = "/dev/video0", width: int = 640, height: int = 480, fps: int = 30):
        self.device, self.width, self.height, self.fps = device, width, height, fps

    def available(self) -> bool:
        return bool(shutil.which("ffmpeg")) and Path(self.device).exists()

    def frames(self) -> Iterator:
        """Yield raw RGB frames (numpy HxWx3 uint8) from a single warm ffmpeg process. Ends silently
        if unavailable."""
        if not self.available():
            return
        try:
            import numpy as np
        except Exception:  # noqa: BLE001 — no numpy → no stream (honest)
            return
        frame_bytes = self.width * self.height * 3
        proc: Optional[subprocess.Popen] = None
        try:
            proc = subprocess.Popen(
                ["ffmpeg", "-loglevel", "quiet", "-f", "v4l2", "-i", self.device,
                 "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{self.width}x{self.height}",
                 "-r", str(self.fps), "pipe:1"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            assert proc.stdout is not None  # stdout=PIPE guarantees a readable stream
            while True:
                buf = proc.stdout.read(frame_bytes)
                if not buf or len(buf) < frame_bytes:
                    break
                yield np.frombuffer(buf, dtype=np.uint8).reshape((self.height, self.width, 3))
        except (OSError, ValueError):
            return
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:  # noqa: BLE001
                    proc.kill()


class ScriptedFrameSource:
    """Deterministic double — yields a fixed list of frames (ndarrays or any placeholder). No device."""
    def __init__(self, frames: List):
        self._frames = list(frames)

    def available(self) -> bool:
        return True

    def frames(self) -> Iterator:
        yield from self._frames
