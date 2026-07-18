"""The VLM seam (SIGIL §8 / C4-C6). A `VisionModel` turns a captured Frame + a question into a
free-text visual reading. That reading is ADVISORY — the perception layer serves the frame's
captured TEXT as the authoritative answer and labels the model's reading as unverified (see
`perceive.compose_perception`). This mirrors the cascade doctrine: the frontier VLM is a tool
SIGIL CALLS, not the source of truth.

HONEST GAP: a real VLM call needs either the metered Anthropic vision API or a local moondream-
class model; neither is wired offline here. `ClaudeVision` is the documented real seam and returns
'' when no endpoint is configured (an absent reading is empty, never fabricated). Tests inject a
deterministic double."""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from .capture import Frame


@runtime_checkable
class VisionModel(Protocol):
    def describe(self, frame: Frame, question: str) -> str: ...   # advisory free-text reading


class ClaudeVision:
    """Documented real provider: base64 the frame → a frontier VLM (Anthropic vision API or an MCP
    image tool) → a short reading. Left inert offline: with no configured endpoint it returns ''
    so the perception answer stands on the captured text alone (never on a fabricated reading)."""
    def __init__(self, endpoint: Optional[str] = None, model: str = "claude-sonnet-5", timeout: int = 60):
        self.endpoint, self.model, self.timeout = endpoint, model, timeout

    def describe(self, frame: Frame, question: str) -> str:
        if not self.endpoint or not frame.image_path:
            return ""   # no endpoint / no image → no reading (honest empty, not a guess)
        # A wired implementation would POST the base64 image + question to self.endpoint here.
        # Deliberately not faked: an unconfigured VLM must not manufacture a description.
        return ""
