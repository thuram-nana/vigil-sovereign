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


def test_the_phase_gate_is_what_denies_at_least_some_of_those_cases():
    """MEASURED DISCRIMINATING POWER, because "9 denials out of 9 attempts" overstated it.

    A review removed the authorization leg entirely and found that 2 of the 9 out-of-phase cases were
    still denied — by the argv-builder lookup, which runs first. Those two prove nothing about the phase
    gate. The honest number is 7 of 9, and this pins that the phase manifest is doing real work rather
    than riding on a denial that would happen anyway: every case counted here is a tool that HAS a
    builder (so the builder lookup cannot be the thing refusing it) and is out of phase."""
    discriminating = [
        (tool, phase) for tool in executor._BUILDERS for phase in ALL_PHASES
        if phase.value not in set(REAL_VIEW.get(tool, []))
    ]
    assert len(discriminating) >= 5, (
        f"only {len(discriminating)} cases where a BUILDABLE tool is out of phase — the phase gate has "
        f"little left to prove, which would make the test above mostly decorative")
    for tool, phase in discriminating:
        res, fr = _run(tool, phase)
        assert res.ran is False and not fr.calls, f"{tool} ran out-of-phase in {phase.value}"


def test_a_tool_on_no_manifest_is_denied_and_spawns_nothing():
    """A tool with no argv builder is refused before anything is spawned.

    HONESTLY LABELLED, AFTER A REVIEW SHOWED THE ORIGINAL CLAIM WAS WRONG. This was called
    "denied in every phase", implying the PHASE gate did the work. It does not: ``execute`` refuses an
    unknown tool at the builder lookup, which runs BEFORE authorization — proved by deleting the entire
    authorization leg, after which this still passed. The phase loop was decoration.

    It is still worth asserting (fail-closed on an unknown tool, nothing spawned), so it is kept — under
    a name that says what it actually shows. The phase gate's real coverage is the test above."""
    unlisted = ["ncat", "socat", "chisel", "totally_unknown_tool_xyz"]
    for tool in unlisted:
        assert tool not in REAL_VIEW, f"{tool} unexpectedly appears in the manifest — pick another"
        assert tool not in executor._BUILDERS, f"{tool} has a builder — it is no longer 'unknown'"
        res, fr = _run(tool, ALL_PHASES[0])
        assert res.ran is False and not fr.calls, f"{tool!r} (unknown tool) was allowed to run"


def test_there_are_real_out_of_phase_cases_to_test():
    """MUTATION CONTROL. The builder loop passes vacuously if ``_BUILDERS`` is empty, the phase set is
    empty, or every builder is registered in every phase (no out-of-phase case exists). Pin a floor so
    the denial test cannot silently become a no-op."""
    cases = sum(1 for tool in executor._BUILDERS for phase in ALL_PHASES
                if phase.value not in set(REAL_VIEW.get(tool, [])))
    assert cases >= 3, f"only {cases} out-of-phase cases — the manifest or builder set changed shape"
    assert len(executor._BUILDERS) >= 6 and len(ALL_PHASES) >= 2
