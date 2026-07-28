"""
S4 — the on-screen SIGIL HUD: the VoicePipeline `on_state` observer + the ephemeral 0600 status file.

Doctrine under test:
  * the pipeline emits its FSM state (idle→listening→thinking→speaking→idle) to an OPTIONAL observer,
    default-None so the FSM stays byte-identical + deterministic (covered by the existing test_voice.py);
  * an observer error NEVER breaks the pipeline (HUD telemetry is pure output);
  * the StatusSink writes a 0600 file (never the spine) and round-trips; absent/oversized → None.
"""

from __future__ import annotations

import os
import tempfile

from sigil.voice.components import (
    BufferSink,
    ChunkTts,
    EchoDispatch,
    FixedAsr,
    ScriptedVad,
    ScriptedWake,
)
from sigil.voice.hud_status import StatusSink, read_status
from sigil.voice.pipeline import State, VoicePipeline


def _pipe(on_state):
    return VoicePipeline(
        ScriptedVad([True, True] + [False] * 20), ScriptedWake(0), FixedAsr("open settings"),
        ChunkTts(3), BufferSink(), EchoDispatch("done"),
        silence_frames=3, min_speech_frames=2, listen_timeout_frames=50, on_state=on_state)


# ---- the FSM observer -------------------------------------------------------

def test_pipeline_emits_fsm_states_to_the_observer():
    seen: list = []
    p = _pipe(seen.append)
    p.run(range(10))
    states = [s["state"] for s in seen]
    assert "listening" in states and "thinking" in states and "speaking" in states and "idle" in states
    assert states[-1] == "idle" and p.state is State.IDLE            # ends idle
    thinking = next(s for s in seen if s["state"] == "thinking")
    assert thinking["transcript"] == "open settings"                # thinking shows what was heard
    speaking = next(s for s in seen if s["state"] == "speaking")
    assert speaking["feedback"] == "done"                           # speaking shows the reply's first line


def test_observer_error_never_breaks_the_pipeline():
    def _boom(_st):
        raise RuntimeError("hud sink down")
    p = _pipe(_boom)
    p.run(range(10))                                                # must complete despite the raising sink
    assert p.state is State.IDLE and p.transcript == "open settings"


def test_default_none_observer_is_a_noop():
    p = _pipe(None)
    p.run(range(10))
    assert p.state is State.IDLE                                    # byte-identical, no side effect


# ---- the ephemeral 0600 status file -----------------------------------------

def test_status_sink_writes_0600_and_round_trips():
    p = tempfile.mktemp(suffix=".json")
    StatusSink(p)({"state": "listening", "transcript": "hi", "feedback": ""})
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    assert read_status(p) == {"state": "listening", "transcript": "hi", "feedback": ""}


def test_read_status_absent_or_bad_is_none():
    assert read_status(tempfile.mktemp(suffix=".json")) is None      # absent
    bad = tempfile.mktemp(suffix=".json")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write("not json")
    assert read_status(bad) is None                                  # unparseable


def test_status_sink_truncates_long_fields():
    p = tempfile.mktemp(suffix=".json")
    StatusSink(p)({"state": "speaking", "transcript": "x" * 500, "feedback": "y" * 500})
    rec = read_status(p)
    assert len(rec["transcript"]) <= 200 and len(rec["feedback"]) <= 200


def test_status_sink_as_pipeline_observer_end_to_end():
    p = tempfile.mktemp(suffix=".json")
    pipe = _pipe(StatusSink(p))
    pipe.run(range(10))
    assert read_status(p)["state"] == "idle"                         # the file reflects the final state
