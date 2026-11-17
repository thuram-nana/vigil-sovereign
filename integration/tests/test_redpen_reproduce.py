"""R1 — the sandbox reproduction runner (redpen.reproduce).

Doctrine under test (design §7.2 §3):
  * a PoC that FIRES on every required run (twice) is a reproduction; provenance is then "reproduced";
  * a PoC that fires FEWER than twice (a flake / no fire) is NOT reproduced and carries no provenance —
    the twice-fire bar ("no flakes") is load-bearing;
  * the sandbox being unavailable is an HONEST SKIP (status="unavailable"), never a reproduction and
    never a FACT;
  * a candidate with no fire markers, or a timed-out run, cannot be judged "fired" (fail-closed).

Pure fakes — no bwrap, no network, no framework (so no importorskip is needed here).
"""

from __future__ import annotations

from vigil_integration.live.sandbox_exec import SandboxOutcome, SandboxUnavailable
from vigil_integration.redpen import LensCandidate, reproduce_candidate


def _candidate(markers=("SINK",), mode="any", cmd="python poc.py", **kw):
    return LensCandidate(lens="injection", bug_class="sqli_attempt", channel="request_payload",
                         poc_command=cmd, fire_markers=markers, fire_mode=mode,
                         request_value="' OR '1'='1", **kw)


def _fire(stdout="SINK reached", stderr="", timed_out=False, exit_code=0):
    return SandboxOutcome(exit_code=exit_code, stdout=stdout, stderr=stderr, timed_out=timed_out)


def _scripted(outcomes):
    """A fake sandbox returning the next scripted SandboxOutcome per call."""
    seq = {"n": 0}

    def run(_cmd):
        o = outcomes[min(seq["n"], len(outcomes) - 1)]
        seq["n"] += 1
        return o

    return run


def test_firing_on_both_runs_is_reproduced_with_reproduced_provenance():
    r = reproduce_candidate(_candidate(), workspace="/tmp", sandbox=_scripted([_fire(), _fire()]))
    assert r.status == "reproduced" and r.fired_twice is True and r.fires == 2
    assert r.provenance == "reproduced"
    assert "SINK" in (r.stdout + r.stderr)


def test_firing_only_once_is_not_reproduced_and_has_no_provenance():
    # The second run does not fire -> a flake, not a finding. This is the twice-fire bar.
    r = reproduce_candidate(_candidate(), workspace="/tmp", sandbox=_scripted([_fire(), _fire("quiet")]))
    assert r.status == "not_reproduced" and r.fired_twice is False and r.fires == 1
    assert r.provenance == ""


def test_never_firing_is_not_reproduced():
    r = reproduce_candidate(_candidate(), workspace="/tmp",
                            sandbox=_scripted([_fire("quiet"), _fire("quiet")]))
    assert r.status == "not_reproduced" and r.fired_twice is False and r.fires == 0 and r.provenance == ""


def test_sandbox_unavailable_is_an_honest_skip_not_a_fact():
    def unavailable(_cmd):
        raise SandboxUnavailable("bwrap not installed")

    r = reproduce_candidate(_candidate(), workspace="/tmp", sandbox=unavailable)
    assert r.status == "unavailable" and r.fired_twice is False and r.provenance == ""
    assert "unavailable" in r.reason


def test_a_candidate_with_no_markers_cannot_fire():
    # Fail-closed: a reproduction must positively demonstrate the defect's signature.
    r = reproduce_candidate(_candidate(markers=()), workspace="/tmp", sandbox=_scripted([_fire(), _fire()]))
    assert r.status == "not_reproduced" and r.fired_twice is False


def test_a_timed_out_run_does_not_count_as_a_fire():
    r = reproduce_candidate(_candidate(), workspace="/tmp",
                            sandbox=_scripted([_fire(timed_out=True), _fire(timed_out=True)]))
    assert r.fired_twice is False and r.status == "not_reproduced"


def test_all_mode_requires_every_marker_present():
    cand = _candidate(markers=("SINK", "TAINT"), mode="all")
    only_one = _scripted([_fire("SINK only"), _fire("SINK only")])
    assert reproduce_candidate(cand, workspace="/tmp", sandbox=only_one).fired_twice is False
    both = _scripted([_fire("SINK and TAINT here"), _fire("SINK and TAINT here")])
    assert reproduce_candidate(cand, workspace="/tmp", sandbox=both).fired_twice is True


def test_an_empty_poc_command_is_not_reproduced():
    r = reproduce_candidate(_candidate(cmd="   "), workspace="/tmp", sandbox=_scripted([_fire(), _fire()]))
    assert r.status == "not_reproduced" and r.provenance == ""


def test_a_sandbox_run_error_demotes_never_promotes():
    def boom(_cmd):
        raise RuntimeError("runner exploded")

    r = reproduce_candidate(_candidate(), workspace="/tmp", sandbox=boom)
    assert r.status == "error" and r.fired_twice is False and r.provenance == ""
