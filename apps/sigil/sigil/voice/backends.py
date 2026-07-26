"""Real voice backends (SIGIL §8). Two tiers:

  * ZERO-dep, always-available: `EnergyVad` (RMS), `EnergyWake` (speech-onset gate),
    `FileAudioSource`/`FileSink` (stdlib `wave` + numpy), `SilenceTts` (fallback). These let the
    whole pipeline run on a WAV file with no model downloads.
  * OPTIONAL ML (lazy-imported, graceful if absent): `SileroVad`, `OpenWakeWord`, `WhisperAsr`
    (faster-whisper), `PiperTts`, `MicAudioSource`, `SpeakerSink`.

The pipeline (`pipeline.VoicePipeline`) is agnostic to which tier is wired."""
from __future__ import annotations

from typing import Iterator, List

import numpy as np

from .components import FRAME_SAMPLES, SAMPLE_RATE


# ---- zero-dependency backends ---------------------------------------------------------------

class EnergyVad:
    """RMS voice-activity detection over an int16 frame — no model. A reasonable default; Silero
    is the upgrade for noisy environments."""
    def __init__(self, threshold: float = 500.0):
        self.threshold = threshold

    def is_speech(self, frame) -> bool:
        x = np.asarray(frame, dtype=np.float32)
        if x.size == 0:
            return False
        return float(np.sqrt(np.mean(x * x))) >= self.threshold


class EnergyWake:
    """A trivial 'wake' that fires after `onset_frames` consecutive speech frames — a stand-in for
    the real custom-'SIGIL' openWakeWord model (which needs training data). Good for push-to-talk
    / always-listening use; swap in OpenWakeWord for hands-free wake."""
    def __init__(self, vad: EnergyVad | None = None, onset_frames: int = 3):
        self.vad = vad or EnergyVad()
        self.onset_frames = onset_frames
        self._run = 0

    def detect(self, frame) -> bool:
        if self.vad.is_speech(frame):
            self._run += 1
        else:
            self._run = 0
        if self._run >= self.onset_frames:
            self._run = 0
            return True
        return False

    def reset(self) -> None:
        self._run = 0


def _resample_i16(audio: np.ndarray, src: int, dst: int) -> np.ndarray:
    if src == dst or audio.size == 0:
        return audio
    n = int(round(len(audio) * dst / src))
    xp = np.linspace(0, 1, num=len(audio), endpoint=False)
    x = np.linspace(0, 1, num=n, endpoint=False)
    return np.interp(x, xp, audio.astype(np.float32)).astype(np.int16)


class _FrameBuffer:
    """Slice an arbitrary int16 stream into fixed-size frames, carrying the leftover across pushes
    (so no partial-frame audio is dropped between chunks); `flush` emits the final zero-padded frame."""
    def __init__(self, frame_samples: int = FRAME_SAMPLES):
        self.n = frame_samples
        self._resid = np.zeros(0, dtype=np.int16)

    def push(self, audio) -> Iterator[np.ndarray]:
        buf = np.concatenate([self._resid, np.asarray(audio, dtype=np.int16)])
        i = 0
        while i + self.n <= len(buf):
            yield buf[i:i + self.n]
            i += self.n
        self._resid = buf[i:].copy()

    def flush(self) -> Iterator[np.ndarray]:
        if self._resid.size:
            frame = np.zeros(self.n, dtype=np.int16)
            frame[:self._resid.size] = self._resid
            self._resid = np.zeros(0, dtype=np.int16)
            yield frame


def _decode_wav(raw: bytes, sampwidth: int) -> np.ndarray:
    if sampwidth == 2:
        return np.frombuffer(raw, dtype=np.int16)
    if sampwidth == 1:  # 8-bit unsigned PCM → int16
        return ((np.frombuffer(raw, dtype=np.uint8).astype(np.int32) - 128) * 256).astype(np.int16)
    raise ValueError(f"unsupported WAV sample width {sampwidth * 8}-bit (need 8- or 16-bit PCM)")


class FileAudioSource:
    """Yield 20-ms int16 mono frames from a WAV (stdlib `wave`), down-mixed + resampled to 16 kHz.
    Handles 8-/16-bit PCM, and emits the final (zero-padded) partial frame — no audio dropped."""
    def __init__(self, path: str, frame_samples: int = FRAME_SAMPLES, rate: int = SAMPLE_RATE):
        self.path, self.frame_samples, self.rate = path, frame_samples, rate

    def frames(self) -> Iterator[np.ndarray]:
        import wave
        with wave.open(self.path, "rb") as w:
            src_rate, ch, n, sw = w.getframerate(), w.getnchannels(), w.getnframes(), w.getsampwidth()
            raw = w.readframes(n)
        audio = _decode_wav(raw, sw)
        if ch > 1:
            audio = audio.reshape(-1, ch).mean(axis=1).astype(np.int16)
        audio = _resample_i16(audio, src_rate, self.rate)
        fb = _FrameBuffer(self.frame_samples)
        yield from fb.push(audio)
        yield from fb.flush()


class FileSink:
    """Collect played frames and write them to a WAV on close (16 kHz mono int16)."""
    def __init__(self, path: str, rate: int = SAMPLE_RATE):
        self.path, self.rate = path, rate
        self._buf: List[np.ndarray] = []

    def play(self, frame) -> None:
        arr = frame if isinstance(frame, np.ndarray) else np.zeros(FRAME_SAMPLES, dtype=np.int16)
        self._buf.append(np.asarray(arr, dtype=np.int16))

    def close(self) -> None:
        import wave
        data = np.concatenate(self._buf) if self._buf else np.zeros(0, dtype=np.int16)
        with wave.open(self.path, "wb") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(self.rate)
            w.writeframes(data.tobytes())


class SilenceTts:
    """Fallback TTS: emits ~`dur_per_char` of silence per character as 20-ms frames — so the
    full-duplex/barge-in pipeline runs (and its timing is realistic) without a real voice model."""
    def __init__(self, ms_per_char: int = 60):
        self.ms_per_char = ms_per_char

    def synth(self, text: str) -> Iterator[np.ndarray]:
        n_frames = max(1, (len(text) * self.ms_per_char) // 20)
        for _ in range(n_frames):
            yield np.zeros(FRAME_SAMPLES, dtype=np.int16)


# ---- optional ML backends (lazy imports) ----------------------------------------------------

class WhisperAsr:
    """faster-whisper streaming ASR. `model` defaults to 'tiny' (fast; ~40 MB). Lazy-loaded."""
    def __init__(self, model: str = "tiny", compute_type: str = "int8"):
        from faster_whisper import WhisperModel  # optional dep
        self._m = WhisperModel(model, device="cpu", compute_type=compute_type)

    def transcribe(self, frames: List) -> str:
        if not frames:
            return ""
        audio = np.concatenate([np.asarray(f, dtype=np.int16) for f in frames]).astype(np.float32) / 32768.0
        segments, _ = self._m.transcribe(audio, language="en", vad_filter=False)
        return " ".join(s.text.strip() for s in segments).strip()


class SileroVad:
    def __init__(self, threshold: float = 0.5):
        import torch  # optional dep
        model, _ = torch.hub.load("snakers4/silero-vad", "silero_vad", trust_repo=True)
        self._m, self._t, self._torch = model, threshold, torch

    def is_speech(self, frame) -> bool:
        x = self._torch.from_numpy(np.asarray(frame, dtype=np.float32) / 32768.0)
        return float(self._m(x, SAMPLE_RATE).item()) >= self._t


class OpenWakeWord:
    def __init__(self, model: str = "hey_jarvis", threshold: float = 0.5):
        from openwakeword.model import Model  # optional dep; custom 'SIGIL' model trains later
        self._m, self._t, self._name = Model(wakeword_models=[model]), threshold, model

    def detect(self, frame) -> bool:
        scores = self._m.predict(np.asarray(frame, dtype=np.int16))
        return any(v >= self._t for v in scores.values())

    def reset(self) -> None:
        try:
            self._m.reset()
        except Exception:
            pass


class PiperTts:
    """Piper local TTS. `voice` is a path to a .onnx voice model (downloaded separately)."""
    def __init__(self, voice: str):
        from piper.voice import PiperVoice  # optional dep
        self._v = PiperVoice.load(voice)

    def synth(self, text: str) -> Iterator[np.ndarray]:
        fb = _FrameBuffer(FRAME_SAMPLES)
        for chunk in self._v.synthesize_stream_raw(text):
            yield from fb.push(np.frombuffer(chunk, dtype=np.int16))
        yield from fb.flush()


class ElevenLabsTts:
    """ElevenLabs cloud TTS (SIGIL owner's choice). Requests raw pcm_16000 so the pipeline can
    play/barge-in at the frame level. Needs ELEVENLABS_API_KEY (env or ~/.sigil/sigil.env). NOTE:
    a third-party service — the response TEXT leaves the machine; the local `PiperTts` is the
    sovereign alternative."""
    def __init__(self, voice_id: str | None = None, model_id: str = "eleven_flash_v2_5",
                 api_key: str | None = None, timeout: int = 30):
        import os
        # the JARVIS voice_id (found via find_voices/`--find-voice jarvis`) is persisted as
        # SIGIL_TTS_VOICE_ID; fall back to the stock 'Rachel' only if nothing is configured.
        self.voice_id = voice_id or os.environ.get("SIGIL_TTS_VOICE_ID") or "21m00Tcm4TlvDq8ikWAM"
        self.model_id, self.timeout = model_id, timeout
        self.api_key = api_key or os.environ.get("SIGIL_ELEVENLABS_API_KEY") or os.environ.get("ELEVENLABS_API_KEY")

    def synth(self, text: str) -> Iterator[np.ndarray]:
        import json
        import urllib.request
        if not self.api_key:
            raise RuntimeError("ElevenLabsTts needs ELEVENLABS_API_KEY (env or ~/.sigil/sigil.env)")
        url = (f"https://api.elevenlabs.io/v1/text-to-speech/{self.voice_id}/stream"
               f"?output_format=pcm_16000")
        body = json.dumps({"text": text, "model_id": self.model_id}).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"xi-api-key": self.api_key, "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            pcm = resp.read()
        fb = _FrameBuffer(FRAME_SAMPLES)
        yield from fb.push(np.frombuffer(pcm, dtype=np.int16))
        yield from fb.flush()


class ElevenLabsAsr:
    """ElevenLabs 'Scribe' cloud STT (SIGIL owner's choice). Sends the captured utterance as a WAV
    to /v1/speech-to-text. Needs ELEVENLABS_API_KEY. NOTE: a third-party service — the AUDIO leaves
    the machine; the local `WhisperAsr` is the sovereign alternative."""
    def __init__(self, model_id: str = "scribe_v1", api_key: str | None = None, timeout: int = 30):
        import os
        self.model_id, self.timeout = model_id, timeout
        self.api_key = api_key or os.environ.get("SIGIL_ELEVENLABS_API_KEY") or os.environ.get("ELEVENLABS_API_KEY")

    def transcribe(self, frames: List) -> str:
        import io
        import json
        import urllib.request
        import uuid
        import wave
        if not self.api_key:
            raise RuntimeError("ElevenLabsAsr needs ELEVENLABS_API_KEY (env or ~/.sigil/sigil.env)")
        if not frames:
            return ""
        # assemble the frames into an in-memory 16 kHz mono WAV
        audio = np.concatenate([np.asarray(f, dtype=np.int16) for f in frames])
        buf = io.BytesIO()
        with wave.open(buf, "wb") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(SAMPLE_RATE); w.writeframes(audio.tobytes())
        wav_bytes = buf.getvalue()
        # minimal multipart/form-data (model_id + file)
        boundary = f"----sigil{uuid.uuid4().hex}"
        parts = [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"model_id\"\r\n\r\n{self.model_id}\r\n".encode(),
            (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n"
             f"Content-Type: audio/wav\r\n\r\n").encode(),
            wav_bytes, b"\r\n", f"--{boundary}--\r\n".encode(),
        ]
        req = urllib.request.Request(
            "https://api.elevenlabs.io/v1/speech-to-text", data=b"".join(parts), method="POST",
            headers={"xi-api-key": self.api_key, "content-type": f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return str(payload.get("text", "")).strip()


def find_voices(query: str = "jarvis", api_key: str | None = None, timeout: int = 30) -> List[dict]:
    """Search the ElevenLabs SHARED voice library for `query` (e.g. 'jarvis' → the Iron-Man-style
    British butler voice). Returns [{name, voice_id, accent, category, description}] so the owner
    can pick + pin one via `set_voice`."""
    import json
    import os
    import urllib.parse
    import urllib.request
    key = api_key or os.environ.get("SIGIL_ELEVENLABS_API_KEY") or os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        raise RuntimeError("find_voices needs ELEVENLABS_API_KEY (env or ~/.sigil/sigil.env)")
    url = "https://api.elevenlabs.io/v1/shared-voices?" + urllib.parse.urlencode({"search": query, "page_size": 25})
    req = urllib.request.Request(url, headers={"xi-api-key": key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    out = []
    for v in payload.get("voices", []):
        langs = v.get("verified_languages") or []
        out.append({
            "name": v.get("name"),
            "voice_id": v.get("voice_id"),
            "accent": v.get("accent") or (langs[0].get("accent", "") if langs else ""),
            "category": v.get("category"),
            "description": (v.get("description") or "")[:90],
        })
    return out


def set_voice(voice_id: str) -> None:
    """Persist the chosen TTS voice_id as SIGIL_TTS_VOICE_ID in ~/.sigil/sigil.env (loaded by
    config at import), so ElevenLabsTts uses it by default everywhere."""
    from ..config import SIGIL_HOME
    env_path = SIGIL_HOME / "sigil.env"
    lines = []
    if env_path.exists():
        # Parse on "\n" ONLY (not str.splitlines()) so an existing value carrying a Unicode line separator
        # (U+0085/U+2028/U+2029) is never re-split into a second `KEY=value` line here. Blank lines dropped.
        lines = [ln for ln in env_path.read_text(encoding="utf-8").split("\n")
                 if ln.strip() and not ln.strip().startswith("SIGIL_TTS_VOICE_ID=")]
    lines.append(f"SIGIL_TTS_VOICE_ID={voice_id}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class MicAudioSource:
    def __init__(self, frame_samples: int = FRAME_SAMPLES, rate: int = SAMPLE_RATE):
        self.frame_samples, self.rate = frame_samples, rate

    def frames(self) -> Iterator[np.ndarray]:
        import sounddevice as sd  # optional dep
        with sd.InputStream(samplerate=self.rate, channels=1, dtype="int16", blocksize=self.frame_samples) as stream:
            while True:
                data, _ = stream.read(self.frame_samples)
                yield data[:, 0].copy()


class SpeakerSink:
    def __init__(self, rate: int = SAMPLE_RATE):
        import sounddevice as sd  # optional dep
        self._stream = sd.OutputStream(samplerate=rate, channels=1, dtype="int16")
        self._stream.start()

    def play(self, frame) -> None:
        self._stream.write(np.asarray(frame, dtype=np.int16))

    def close(self) -> None:
        try:
            self._stream.stop(); self._stream.close()
        except Exception:
            pass
