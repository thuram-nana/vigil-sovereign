"""Voice pipeline component contracts (SIGIL §8) + deterministic mocks.

The pipeline is defined against small Protocols so the real ML backends (Silero VAD, openWakeWord,
faster-whisper, Piper) and the deterministic test mocks are interchangeable. A `Frame` is a chunk
of mono 16-kHz audio (numpy int16/float32); the pipeline is frame-driven so full-duplex + barge-in
are testable without any audio hardware."""
from __future__ import annotations

from typing import Iterator, List, Protocol, runtime_checkable

try:
    import numpy as np
    Frame = "np.ndarray"
except Exception:  # numpy is present in the venv, but keep the import soft
    np = None  # type: ignore
    Frame = object  # type: ignore

SAMPLE_RATE = 16000
FRAME_MS = 20
FRAME_SAMPLES = SAMPLE_RATE * FRAME_MS // 1000  # 320 samples @ 16 kHz


@runtime_checkable
class Vad(Protocol):
    """Voice-activity detection over a single frame."""
    def is_speech(self, frame) -> bool: ...


@runtime_checkable
class WakeWord(Protocol):
    """Streaming wake-word detector — returns True on the frame that completes the wake phrase."""
    def detect(self, frame) -> bool: ...
    def reset(self) -> None: ...


@runtime_checkable
class Asr(Protocol):
    """Transcribe a captured utterance (a list of frames) to text."""
    def transcribe(self, frames: List) -> str: ...


@runtime_checkable
class Tts(Protocol):
    """Synthesize speech as a stream of audio chunks the pipeline plays incrementally (so it can
    be CANCELLED mid-utterance for barge-in)."""
    def synth(self, text: str) -> Iterator: ...


@runtime_checkable
class AudioSink(Protocol):
    """Where synthesized audio goes (speaker, or a file/buffer in tests)."""
    def play(self, frame) -> None: ...


@runtime_checkable
class Dispatch(Protocol):
    """Send recognized text to the KERNEL and return the spoken response."""
    def send(self, text: str) -> str: ...


# --------------------------------------------------------------------------------------------
# Deterministic mocks — drive the state machine in tests with zero audio/ML dependency.
# --------------------------------------------------------------------------------------------

class ScriptedVad:
    """is_speech follows a per-frame script (list of bools), then repeats the last value."""
    def __init__(self, script: List[bool]):
        self.script = script
        self.i = 0

    def is_speech(self, frame) -> bool:
        v = self.script[min(self.i, len(self.script) - 1)] if self.script else False
        self.i += 1
        return v


class ScriptedWake:
    """detect fires True exactly ONCE ever, on frame index `fire_at` (latched — a real wake word
    fires per-utterance, so `reset` re-arms the frame counter but does not re-trigger a past hit)."""
    def __init__(self, fire_at: int):
        self.fire_at = fire_at
        self.i = 0
        self.fired = False

    def detect(self, frame) -> bool:
        hit = self.i == self.fire_at and not self.fired
        if hit:
            self.fired = True
        self.i += 1
        return hit

    def reset(self) -> None:
        self.i = 0


class FixedAsr:
    def __init__(self, text: str):
        self.text = text
        self.calls: List[int] = []

    def transcribe(self, frames: List) -> str:
        self.calls.append(len(frames))
        return self.text


class ChunkTts:
    """Yields `chunks` opaque audio chunks; records whether it was fully consumed (not cancelled)."""
    def __init__(self, chunks: int = 5):
        self.chunks = chunks
        self.spoken: List[str] = []
        self.completed = False

    def synth(self, text: str) -> Iterator:
        self.spoken.append(text)
        self.completed = False
        for k in range(self.chunks):
            yield ("chunk", text, k)
        self.completed = True


class BufferSink:
    def __init__(self):
        self.frames: List = []

    def play(self, frame) -> None:
        self.frames.append(frame)


class EchoDispatch:
    def __init__(self, response: str = "done"):
        self.response = response
        self.received: List[str] = []

    def send(self, text: str) -> str:
        self.received.append(text)
        return self.response
