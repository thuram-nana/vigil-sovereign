"""Drivers that wire the voice pipeline to real backends: `run_file` (a WAV in → response WAV out,
zero hardware needed) and `run_mic` (live full-duplex; needs a mic + speaker + optional ML)."""
from __future__ import annotations

from .pipeline import VoicePipeline


class _StubAsr:
    """Used when faster-whisper is not installed — the pipeline still runs end-to-end (segmenting
    real audio, dispatching, speaking); only the transcript is a placeholder."""
    def transcribe(self, frames):
        return "(no ASR model installed — run: pip install faster-whisper)"


def _make_asr(kind: str):
    if kind == "stub":
        return _StubAsr()
    if kind == "elevenlabs":
        from .backends import ElevenLabsAsr
        a = ElevenLabsAsr()
        if not a.api_key:
            print("  [asr] ElevenLabs key not set (ELEVENLABS_API_KEY); using stub")
            return _StubAsr()
        return a
    try:
        from .backends import WhisperAsr
        return WhisperAsr(model="tiny")
    except Exception as e:  # noqa: BLE001
        print(f"  [asr] faster-whisper unavailable ({e}); using stub")
        return _StubAsr()


def _make_tts(kind: str, voice: str | None):
    from .backends import SilenceTts
    if kind == "elevenlabs":
        from .backends import ElevenLabsTts
        t = ElevenLabsTts(voice_id=voice)   # JARVIS voice via SIGIL_TTS_VOICE_ID / --tts-voice
        if not t.api_key:
            print("  [tts] ElevenLabs key not set (ELEVENLABS_API_KEY); using silence fallback")
            return SilenceTts()
        return t
    if kind == "piper" and voice:
        from .backends import PiperTts
        return PiperTts(voice)
    return SilenceTts()


def run_file(wav_in: str, wav_out: str, *, asr: str = "auto", tts: str = "silence",
             tts_voice: str | None = None) -> VoicePipeline:
    """Run the full pipeline over a WAV file (EnergyVad + EnergyWake + ASR + KERNEL + TTS → WAV).
    Returns the pipeline so the caller can read transcript / response / events."""
    from .backends import EnergyVad, EnergyWake, FileAudioSource, FileSink
    from .dispatch import KernelDispatch

    vad = EnergyVad()
    sink = FileSink(wav_out)
    p = VoicePipeline(vad, EnergyWake(vad), _make_asr(asr), _make_tts(tts, tts_voice), sink, KernelDispatch())
    p.run(FileAudioSource(wav_in).frames())
    sink.close()
    return p


def run_mic(*, asr: str = "elevenlabs", wake: str = "energy", tts: str = "elevenlabs",
            tts_voice: str | None = None) -> None:
    """Live full-duplex loop (needs a working mic + speaker). ASR/TTS default to ElevenLabs (the
    owner's choice); wake=openWakeWord if `wake=oww`, else the energy-onset stand-in."""
    from ..governor.capability import CapabilityGate
    from ..spine.store import SpineStore
    from .backends import EnergyVad, EnergyWake, MicAudioSource, OpenWakeWord, SpeakerSink
    from .dispatch import KernelDispatch

    # governed voice-capability latch: refuse to even START the live mic loop when voice is disabled.
    if not CapabilityGate(SpineStore()).is_enabled("voice"):
        print("SIGIL voice: capability disabled (governed latch) — re-enable from the cockpit "
              "or run `sigil capability voice on`")
        return
    vad = EnergyVad()
    wake_c = OpenWakeWord() if wake == "oww" else EnergyWake(vad)
    sink = SpeakerSink()
    # voice_channel=True → this live pipeline's dispatch is gated by the `voice` latch (belt-and-suspenders
    # with the entry guard above, so a mid-session disable also stops dispatch).
    p = VoicePipeline(vad, wake_c, _make_asr(asr), _make_tts(tts, tts_voice), sink,
                      KernelDispatch(voice_channel=True))
    print("SIGIL voice: listening (Ctrl-C to stop) …")
    try:
        p.run(MicAudioSource().frames())
    except KeyboardInterrupt:
        pass
    finally:
        sink.close()
