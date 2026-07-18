"""The VLM seam (SIGIL §8 / C4-C6). A `VisionModel` turns a captured Frame + a question into a
free-text visual reading. That reading is ADVISORY — the perception layer serves the frame's
captured OCR TEXT as the authoritative answer and labels the model's reading as unverified (see
`perceive.compose_perception`). Cascade doctrine: a cheap LOCAL model runs freely (on-box, A0); the
FRONTIER model is a data-egress hop and is gated (see `perception.egress`).

Providers:
  • `MoondreamVision` — a local moondream-class VLM via Ollama. Fully offline, zero egress → A0.
    The default reader. Returns '' on any failure (honest empty, never a fabricated reading).
  • `ClaudeVision` — the frontier Anthropic vision API. `describe()` performs a REAL image UPLOAD
    (private screen bytes leave the box), so it MUST only be invoked through `perception.egress`,
    which classifies the upload A2 via the WARDEN oracle and requires a verified owner approval.
    Never call `ClaudeVision.describe` on an auto path."""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from .capture import Frame


@runtime_checkable
class VisionModel(Protocol):
    # `egresses` = does describe() send bytes off the box? On-box models (moondream) are False and may
    # run on the auto A0 path; frontier models are True and may ONLY be invoked through the egress gate
    # (`Perceptor.frontier`). `perceive`/`ambient_watch` STRUCTURALLY refuse an egressing model.
    egresses: bool
    def describe(self, frame: Frame, question: str) -> str: ...   # advisory free-text reading


def _b64_image(frame: Frame) -> Optional[str]:
    if not frame.image_path:
        return None
    try:
        return base64.b64encode(Path(frame.image_path).read_bytes()).decode("ascii")
    except OSError:
        return None


class MoondreamVision:
    """Local VLM (Ollama, on-box, A0 — nothing leaves the machine). POSTs the frame image + question
    to `{host}/api/generate` with `images:[b64]`. Mirrors `consolidate.extract.LocalProvider`."""
    egresses = False   # on-box — safe on the auto perceive/ambient path

    def __init__(self, model: str = "moondream", host: Optional[str] = None, timeout: int = 60):
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"
        self.timeout = timeout

    def describe(self, frame: Frame, question: str) -> str:
        b64 = _b64_image(frame)
        if b64 is None:
            return ""
        body = json.dumps({"model": self.model, "prompt": (question or "Describe what is visible."),
                           "images": [b64], "stream": False}).encode("utf-8")
        req = urllib.request.Request(f"{self.host.rstrip('/')}/api/generate", data=body, method="POST",
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            return ""   # no reading (honest empty), never a fabricated one
        return str(payload.get("response", "")).strip()[:2000]


class ClaudeVision:
    """FRONTIER Anthropic vision API — `describe()` UPLOADS the image (data egress). Gate it via
    `perception.egress`; do not call directly on an auto path. Mirrors `extract.ApiProvider`."""
    egresses = True    # sends bytes off-box — perceive/ambient refuse it; only frontier() may use it

    def __init__(self, model: str = "claude-sonnet-5", api_key: Optional[str] = None,
                 timeout: int = 60, max_tokens: int = 512):
        self.model = model
        self.api_key = api_key or os.environ.get("SIGIL_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self.timeout = timeout
        self.max_tokens = max_tokens

    def describe(self, frame: Frame, question: str) -> str:
        b64 = _b64_image(frame)
        if b64 is None or not self.api_key:
            return ""
        media = "image/png" if (frame.image_path or "").lower().endswith(".png") else "image/jpeg"
        body = json.dumps({
            "model": self.model, "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": media, "data": b64}},
                {"type": "text", "text": (question or "Describe what is visible.")},
            ]}],
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body, method="POST",
            headers={"content-type": "application/json", "x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            return ""
        return "".join(b.get("text", "") for b in payload.get("content", [])
                       if isinstance(b, dict)).strip()[:2000]
