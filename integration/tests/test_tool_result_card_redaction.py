"""The richer tool-call card (W-UX5) must carry the executor's REDACTED command + output on the spine — and
must NEVER leak the raw output. The engine copies `exec_res.record.stdout`/`record.argv` (F3-redacted by
`_build_record` via `_redact_str`) onto the tool_result event, and uses the RAW `exec_res.stdout` only for a
byte COUNT.

This guards the load-bearing property: a future edit that "helpfully" put the raw stdout on the card would
stream secrets to the UI/spine. Pure fakes (no framework, no network) — runs in both CI legs.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from vigil_integration.agent import ActionType, LLMDecision, OutputAnalysis, ToolCall
from vigil_integration.live.engine import EngineSeams, VigilEngine
from vigil_integration.live.think_claude import ReplayThinker

TARGET = "http://127.0.0.1:19010/records/search?q=test"
_SECRET = "SUPERSECRET123"          # appears ONLY in the RAW stdout — must never reach the spine


def _allow_gate(tool_name, target, destructive):
    return SimpleNamespace(allowed=True, outcome="allow", reason="in scope (loopback)")


def _attest_allow(**kw):
    return SimpleNamespace(allowed=True, reason="attested",
                           attestation=SimpleNamespace(record_hash="att-" + "a" * 60))


def _run_tool_with_redacted_record(tool, phase, seq):
    # RAW stdout carries a secret; the signed RECORD is the F3-redacted copy the executor actually produces.
    redacted_out = "register hit: token=[REDACTED] title=Home MERIDIAN"
    return SimpleNamespace(
        ran=True, outcome="ran", tool=tool.tool_name, tier="A1", target="127.0.0.1:19010",
        destructive=False, exit_code=0, timed_out=False, truncated=False,
        stdout="register hit: token=" + _SECRET + " title=Home MERIDIAN",   # RAW — must NOT reach the spine
        stderr="warn: token=" + _SECRET,                                    # RAW
        argv=("httpx", "-u", "http://127.0.0.1:19010/", "-H", "Authorization: [REDACTED]"),
        record=SimpleNamespace(
            record_id="rec-1",
            argv=["httpx", "-u", "http://127.0.0.1:19010/", "-H", "Authorization: [REDACTED]"],
            stdout=redacted_out, stderr="warn: token=[REDACTED]"),
    )


def _use_tool():
    return LLMDecision(action=ActionType.USE_TOOL,
                       tool=ToolCall(tool_name="httpx", tool_args={"target": TARGET}),
                       output_analysis=OutputAnalysis(exploit_succeeded=None))


def _complete():
    return LLMDecision(action=ActionType.COMPLETE, summary="done")


def _run_and_capture():
    events = []

    def spine_post(kind, payload, parent_id=None):
        events.append((kind, payload))
        return len(events)

    eng = VigilEngine(slug="loopback", max_iterations=4, seams=EngineSeams(
        attest=_attest_allow, think=ReplayThinker([_use_tool(), _complete()]),
        gate=_allow_gate, run_tool=_run_tool_with_redacted_record, spine_post=spine_post))
    eng.engage(TARGET)
    return events


def test_tool_result_card_carries_redacted_command_and_output():
    events = _run_and_capture()
    tr = [p for (k, p) in events if k == "tool_result"]
    assert tr, "no tool_result event was posted"
    p = tr[0]
    # the COMMAND is the redacted argv (no secret), and the OUTPUT excerpt is the redacted record output
    assert p.get("argv") == ["httpx", "-u", "http://127.0.0.1:19010/", "-H", "Authorization: [REDACTED]"]
    assert p.get("output_excerpt") == "register hit: token=[REDACTED] title=Home MERIDIAN"
    assert p.get("exit_code") == 0 and p.get("timed_out") is False and p.get("truncated") is False
    # the byte count reflects the RAW output length (the count is not secret)
    assert p.get("output_bytes") == len("register hit: token=" + _SECRET + " title=Home MERIDIAN")


def test_raw_secret_never_reaches_any_spine_event():
    events = _run_and_capture()
    blob = json.dumps(events, default=str)
    assert _SECRET not in blob, "the RAW stdout secret leaked onto the spine — the card must use record.stdout"


def test_refused_tool_result_has_no_command_or_output():
    # authorize_edge ALLOWS but the EXECUTOR denies (ran=False, record=None) — the card must not fabricate a
    # command/output for a call that never ran.
    events = []
    eng = VigilEngine(slug="loopback", max_iterations=4, seams=EngineSeams(
        attest=_attest_allow, think=ReplayThinker([_use_tool(), _complete()]),
        gate=_allow_gate, run_tool=lambda t, ph, s: SimpleNamespace(
            ran=False, outcome="deny", reason="executor denied", tool="httpx", record=None),
        spine_post=lambda k, p, parent_id=None: events.append((k, p)) or len(events)))
    eng.engage(TARGET)
    tr = [p for (k, p) in events if k == "tool_result"]
    assert tr and tr[0].get("refused") is True
    assert "argv" not in tr[0] and "output_excerpt" not in tr[0]
