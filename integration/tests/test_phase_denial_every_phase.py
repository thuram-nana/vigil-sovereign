"""B3 — an unlisted tool is DENIED in EVERY phase, proven through the REAL executor and the REAL manifest.

The prior coverage was synthetic: a one-tool phase-view like ``{"sqlmap": [EXPLOITATION]}``, exercised in
a single phase. The claim that actually mattered when the drift guard was generalised — "9 denials out of
9 attempts across every phase, against the PRODUCTION manifest" — was done by hand and never encoded, so a
regression that opened a tool in a phase it must not run in could merge green.

This encodes it. Every tool that has a typed builder is driven through the real ``execute()`` with the
real ``wiring.DEFAULT_TOOL_VIEW`` in every ``Phase`` it is NOT registered for, and must be denied with
nothing spawned. A separate set of names that appear on NO manifest at all (ncat/socat/an invented name)
is denied in every phase too.

The injected gate ALLOWS and the runner is a fake that records argv without spawning: the whole point is
that the PHASE gate denies BEFORE the conjunctive gate is consulted, so an allowing gate cannot rescue an
out-of-phase call, and a denied call reaches no subprocess. Nothing here runs a real tool.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from vigil_integration.agent.state import Phase
from vigil_integration.live import executor, wiring
from vigil_integration.live.executor import RunOutcome, execute

REAL_VIEW = wiring.DEFAULT_TOOL_VIEW
ALL_PHASES = list(Phase)


def _det_signer(data: bytes) -> str:
    return "sig-" + hashlib.sha256(data).hexdigest()[:24]


class _FakeRun:
    """Records argv, never spawns. If the phase gate works, this is never even called."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout, output_cap):
        self.calls.append(list(argv))
        return RunOutcome(exit_code=0, stdout="OK", stderr="")


def _allow_gate(tool_name, target, destructive):
    # The conjunctive gate ALLOWS everything — so any denial below comes from the PHASE gate alone.
    return SimpleNamespace(outcome="allow", allowed=True, reason="ok")


def _dview():
    # Destructive flags are irrelevant to this test: the phase gate denies before the destructive/
    # conjunctive legs are consulted. All-False keeps the call as permissive as possible so a denial
    # cannot be attributed to anything but the phase manifest.
    return {t: False for t in REAL_VIEW}


def _args():
    # Denial happens before argv construction, so a minimal loopback arg of each shape suffices.
    return {"target": "127.0.0.1:19006", "url": "http://127.0.0.1:19006/"}


def _run(tool, phase):
    fr = _FakeRun()
    res = execute(tool, _args(), phase, gate=_allow_gate, view=REAL_VIEW,
                  destructive_view=_dview(), run=fr, signer=_det_signer, seq=1, now=0)
    return res, fr


def test_a_builder_tool_is_denied_in_every_phase_it_is_not_registered_for():
    offenders: list[str] = []
    for tool in sorted(executor._BUILDERS):
        allowed = set(REAL_VIEW.get(tool, []))
        for phase in ALL_PHASES:
            if phase.value in allowed:
                continue  # legitimately registered in this phase — not the case under test
            res, fr = _run(tool, phase)
            if res.ran or fr.calls:
                offenders.append(f"{tool} in {phase.value}: ran={res.ran}, spawned={bool(fr.calls)}")
    assert not offenders, (
        "a builder tool ran in a phase the production manifest does not register it for — an allowing "
        "gate rescued an out-of-phase call:\n  " + "\n  ".join(offenders)
    )


def test_a_tool_on_no_manifest_is_denied_in_every_phase():
    unlisted = ["ncat", "socat", "chisel", "totally_unknown_tool_xyz"]
    for tool in unlisted:
        assert tool not in REAL_VIEW, f"{tool} unexpectedly appears in the manifest — pick another"
        for phase in ALL_PHASES:
            res, fr = _run(tool, phase)
            assert res.ran is False and not fr.calls, (
                f"{tool!r} (on no manifest) was allowed to run in phase {phase.value}")


def test_there_are_real_out_of_phase_cases_to_test():
    """MUTATION CONTROL. The builder loop passes vacuously if ``_BUILDERS`` is empty, the phase set is
    empty, or every builder is registered in every phase (no out-of-phase case exists). Pin a floor so
    the denial test cannot silently become a no-op."""
    cases = sum(1 for tool in executor._BUILDERS for phase in ALL_PHASES
                if phase.value not in set(REAL_VIEW.get(tool, [])))
    assert cases >= 3, f"only {cases} out-of-phase cases — the manifest or builder set changed shape"
    assert len(executor._BUILDERS) >= 6 and len(ALL_PHASES) >= 2
