"""The SIGIL voice pipeline (SIGIL §8) — a frame-driven, full-duplex state machine.

    IDLE ──wake word──▶ LISTENING ──end-of-speech──▶ THINKING ──▶ SPEAKING ──done──▶ IDLE
      ▲                    │                                          │
      └────timeout─────────┘                       barge-in (VAD)─────┘  (cancel TTS, re-LISTEN)

Full-duplex + barge-in are the acceptance bar (§8): while SPEAKING, every input frame is
VAD-checked, and `barge_in_frames` CONSECUTIVE speech frames (hysteresis) cancel the TTS and
re-enter LISTENING. The machine is driven one input frame at a time and holds no audio/ML deps
itself (those are the injected components), so the whole behaviour is deterministically testable.

LIVE-PATH NOTE: on a real mic+speaker the assistant's own TTS is captured by the mic, so
barge-in needs acoustic-echo cancellation (AEC) or output ducking; without it, run the live
loop half-duplex (gate the mic while SPEAKING). Hysteresis alone does not defeat sustained
self-echo — AEC is the real fix and is a runtime/hardware concern, not a state-machine one."""
from __future__ import annotations

from collections.abc import Iterator
from enum import Enum
from typing import Any, List, Optional

from .components import Asr, AudioSink, Dispatch, Tts, Vad, WakeWord


class State(Enum):
    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    SPEAKING = "speaking"


class VoicePipeline:
    def __init__(self, vad: Vad, wake: WakeWord, asr: Asr, tts: Tts, sink: AudioSink, dispatch: Dispatch,
                 *, silence_frames: int = 25, min_speech_frames: int = 3, listen_timeout_frames: int = 150,
                 max_utterance_frames: int = 1000, barge_in_frames: int = 4,
                 on_state: Optional[Any] = None):
        self.vad, self.wake, self.asr, self.tts, self.sink, self.dispatch = vad, wake, asr, tts, sink, dispatch
        # S4: an OPTIONAL observer called once per FSM transition with {state, transcript, feedback} so the
        # on-screen HUD can reflect idle/listening/thinking/speaking. Default None ⇒ the FSM is byte-identical
        # + deterministic (no side effect); an observer error is swallowed so it can never break the pipeline.
        self._on_state = on_state
        self.silence_frames = silence_frames          # ~500 ms of trailing silence ends the utterance
        self.min_speech_frames = min_speech_frames     # require real speech before ending
        self.listen_timeout_frames = listen_timeout_frames  # give up if no speech after wake (~3 s)
        self.max_utterance_frames = max_utterance_frames    # absolute cap so LISTENING always terminates (~20 s)
        self.barge_in_frames = barge_in_frames         # consecutive speech frames to CONFIRM a barge-in (hysteresis)

        self.state = State.IDLE
        self.transcript: Optional[str] = None
        self.response: Optional[str] = None
        self.events: List[str] = []
        self._captured: List = []
        self._silence = 0
        self._speech = 0
        self._listen = 0
        self._tts_iter: Optional[Iterator[Any]] = None
        self._barge = 0
        self._barge_buf: List = []

    # --- one input frame drives the machine --------------------------------------------------
    def on_frame(self, frame) -> None:
        if self.state is State.IDLE:
            if self.wake.detect(frame):
                self._to_listening([])
        elif self.state is State.LISTENING:
            self._listening(frame)
        elif self.state is State.SPEAKING:
            self._speaking(frame)
        # THINKING is transient (handled synchronously on entry); it never awaits input frames.

    def _listening(self, frame) -> None:
        self._captured.append(frame)
        self._listen += 1
        if self.vad.is_speech(frame):
            self._speech += 1
            self._silence = 0
        else:
            self._silence += 1
        if self._speech >= self.min_speech_frames and self._silence >= self.silence_frames:
            self._to_thinking()
        elif self._listen >= self.max_utterance_frames:
            # absolute cap — LISTENING can never wedge (e.g. VAD stuck-high on ambient noise)
            if self._speech >= self.min_speech_frames:
                self.events.append("listening→thinking (max utterance)")
                self._to_thinking()
            else:
                self.events.append("listening→idle (max, no speech)")
                self._to_idle()
        elif self._speech < self.min_speech_frames and self._listen >= self.listen_timeout_frames:
            self.events.append("listening→idle (timeout, no speech)")
            self._to_idle()

    def _speaking(self, frame) -> None:
        # full-duplex barge-in with HYSTERESIS: only `barge_in_frames` CONSECUTIVE speech frames
        # count as a real interruption, so a single cough/click/TTS-echo blip can't self-abort the
        # answer. During the short confirm window the TTS keeps playing; on a silence frame the
        # counter resets. (A real mic+speaker still needs AEC or ducking — see the module note.)
        if self.vad.is_speech(frame):
            self._barge += 1
            self._barge_buf.append(frame)
            if self._barge >= self.barge_in_frames:
                self.events.append("barge-in: speaking→listening")
                self._tts_iter = None
                self._to_listening(self._barge_buf, speech=self._barge)
            else:
                self._advance_tts()
        else:
            self._barge = 0
            self._barge_buf = []
            self._advance_tts()

    def _advance_tts(self) -> None:
        assert self._tts_iter is not None  # only called while SPEAKING, where _to_speaking set the iterator
        try:
            self.sink.play(next(self._tts_iter))
        except StopIteration:
            self.events.append("speaking→idle")
            self._to_idle()

    # --- transitions -------------------------------------------------------------------------
    def _emit_state(self) -> None:
        """S4: notify the optional HUD observer of the current FSM state (+ the heard transcript / the
        first line of the spoken feedback). Pure output — default-None makes it a no-op; an observer error
        never propagates into the FSM."""
        if self._on_state is None:
            return
        try:
            feedback = ""
            if self.state is State.SPEAKING and self.response:
                feedback = self.response.splitlines()[0][:200] if self.response.strip() else ""
            self._on_state({
                "state": self.state.value,
                "transcript": (str(self.transcript or "")[:200] if self.state is not State.IDLE else ""),
                "feedback": feedback,
            })
        except Exception:  # noqa: BLE001 — the HUD is pure telemetry; a sink error never breaks the pipeline
            pass

    def _to_listening(self, captured: List, speech: int = 0) -> None:
        if self.state is State.IDLE:
            self.events.append("wake→listening")
        self.state = State.LISTENING
        self._captured = list(captured)
        self._silence = 0
        self._speech = speech
        self._listen = len(captured)
        self._emit_state()

    def _to_thinking(self) -> None:
        self.events.append("listening→thinking")
        self.state = State.THINKING
        # synchronous v1: transcribe → dispatch to the KERNEL → speak the response.
        self.transcript = self.asr.transcribe(self._captured)
        self._emit_state()                              # HUD: thinking, showing what was heard
        self.response = self.dispatch.send(self.transcript)
        self._to_speaking(self.response)

    def _to_speaking(self, text: str) -> None:
        self.events.append("thinking→speaking")
        self.state = State.SPEAKING
        self._tts_iter = iter(self.tts.synth(text))
        self._barge = 0
        self._barge_buf = []
        self._emit_state()

    def _to_idle(self) -> None:
        self.state = State.IDLE
        self._captured = []
        self._tts_iter = None
        self.wake.reset()
        self._emit_state()

    # --- driver: pump an audio source through the machine ------------------------------------
    def run(self, frames) -> None:
        """Drive the pipeline from any iterable of input frames (a mic stream or a file). After a
        FINITE stream ends (file mode), drain any in-flight TTS so the whole answer is emitted
        (live/infinite streams play the TTS in real time, one chunk per input frame)."""
        for frame in frames:
            self.on_frame(frame)
        self.drain()

    def drain(self) -> None:
        while self.state is State.SPEAKING and self._tts_iter is not None:
            self._advance_tts()
