"""SIGIL voice pipeline — the full-duplex state machine, barge-in (with hysteresis), the absolute
LISTENING cap, and TTS drain — driven by deterministic mocks (no audio/ML deps).
Run: ~/.sigil/venv/bin/python tests/test_voice.py"""
from sigil.voice.components import (
    BufferSink, ChunkTts, EchoDispatch, FixedAsr, ScriptedVad, ScriptedWake,
)
from sigil.voice.pipeline import State, VoicePipeline


def _pipe(vad_script, wake_at, *, asr="hello", resp="done", tts_chunks=3,
          silence=3, min_speech=2, timeout=50, max_utt=1000, barge=4):
    vad = ScriptedVad(vad_script)
    tts = ChunkTts(tts_chunks)
    disp = EchoDispatch(resp)
    sink = BufferSink()
    p = VoicePipeline(vad, ScriptedWake(wake_at), FixedAsr(asr), tts, sink, disp,
                      silence_frames=silence, min_speech_frames=min_speech,
                      listen_timeout_frames=timeout, max_utterance_frames=max_utt, barge_in_frames=barge)
    return p, tts, disp, sink


def test_normal_flow_wake_to_answer_to_idle():
    p, tts, disp, sink = _pipe([True, True] + [False] * 20, wake_at=0)
    p.run(range(10))
    assert p.transcript == "hello" and disp.received == ["hello"]
    assert p.asr.calls == [5], f"ASR got the 5 captured frames, not a coincidence: {p.asr.calls}"
    assert tts.completed and len(sink.frames) == 3, "answer spoken to completion (3 chunks drained)"
    assert p.state is State.IDLE
    assert p.events == ["wake→listening", "listening→thinking", "thinking→speaking", "speaking→idle"]


def test_tts_drains_after_a_short_input_stream():
    # only 7 frames of input, but the answer is 6 chunks — run() must DRAIN the rest, not truncate.
    p, tts, disp, sink = _pipe([True, True, False, False, False] + [False] * 5, wake_at=0, tts_chunks=6)
    p.run(range(7))  # ends mid-answer; drain plays the remaining chunks
    assert tts.completed and len(sink.frames) == 6, f"all 6 chunks must be emitted, got {len(sink.frames)}"


def test_single_vad_blip_does_NOT_barge_in():
    # one spurious speech frame during SPEAKING must NOT abort the answer (hysteresis).
    p, tts, disp, sink = _pipe([True, True, False, False, False, False, True, False] + [False] * 10,
                               wake_at=0, tts_chunks=10, barge=4)
    p.run(range(14))
    assert not any("barge-in" in e for e in p.events), "a single blip must not cancel the answer"


def test_sustained_barge_in_cancels_tts():
    # 4 consecutive speech frames over the TTS DO cancel it (real interruption).
    p, tts, disp, sink = _pipe([True, True, False, False, False, False, False, True, True, True, True] + [False] * 6,
                               wake_at=0, tts_chunks=10, barge=4)
    p.run(range(12))  # stop right after the barge-in fires (frame 11), before a 2nd utterance ends
    assert not tts.completed, "sustained speech must CANCEL the TTS mid-answer"
    assert "barge-in: speaking→listening" in p.events
    assert p.state is State.LISTENING, "barge-in re-enters LISTENING to capture the interrupting speech"


def test_listening_cannot_hang_on_stuck_high_vad():
    # VAD stuck True (ambient noise) — the absolute max-utterance cap must force termination
    # (without it, neither end-of-speech nor the no-speech timeout could ever fire → wedge).
    p, tts, disp, sink = _pipe([True] * 50, wake_at=0, max_utt=20)
    p.run(range(22))  # reach the cap once (frame 20 → thinking) rather than oscillate
    assert any("max utterance" in e for e in p.events), "the cap must force LISTENING to terminate"
    assert p.state is not State.LISTENING, "the machine left the LISTENING wedge"


def test_no_speech_after_wake_times_out_to_idle():
    p, tts, disp, sink = _pipe([False] * 20, wake_at=0, timeout=5)
    p.run(range(8))
    assert p.transcript is None and disp.received == [] and p.state is State.IDLE


def test_empty_asr_result_still_completes_cleanly():
    p, tts, disp, sink = _pipe([True, True] + [False] * 20, wake_at=0, asr="")
    p.run(range(10))
    assert p.transcript == "" and disp.received == [""], "empty transcript is dispatched, no crash"
    assert p.state is State.IDLE


def test_no_wake_stays_idle():
    p, tts, disp, sink = _pipe([True] * 20, wake_at=999)
    p.run(range(20))
    assert p.state is State.IDLE and disp.received == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"{passed}/{len(fns)} voice-pipeline guarantees hold")
