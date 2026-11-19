"""APEX PR-3 Deliverable 3 — the CONTINUOUS autonomous retest scheduler.

The through-line: a fixed finding is re-fired on a cadence to prove the fix STAYS fixed, and the moment an old
vulnerability comes back the finding is RE-OPENED (a regression is flagged on the transition). Silence
(INCONCLUSIVE) never clears and never re-opens. Deterministic (injected clock + injected re-fire). No framework.

PYTHONPATH=integration:packages/core/vigil_core (keyless; no framework at module scope).
"""
from __future__ import annotations

from vigil_core.retest_reproof import CLEARED, INCONCLUSIVE, STILL_PRESENT
from vigil_integration.jobs.apex_retest_scheduler import (
    RetestRegistry,
    WatchedFinding,
    run_cadence_tick,
)

INTERVAL = 100.0


def _registry(path=None, ref="errsqli-1"):
    reg = RetestRegistry(path)
    reg.watch(WatchedFinding(slug="cust_a", finding_ref=ref, bug_class="error_based_sqli", interval_s=INTERVAL))
    return reg


def _refire_seq(*verdicts):
    """A deterministic re-fire driven by a scripted list of ``fired`` values (True/False/None)."""
    seq = list(verdicts)
    state = {"i": 0}

    def refire(_wf):
        i = min(state["i"], len(seq) - 1)
        state["i"] += 1
        return {"fired": seq[i], "reason": f"scripted:{seq[i]}"}
    return refire


# =====================================================================================================
# the headline — prove-clean, stay-clean, then a regression RE-OPENS it
# =====================================================================================================


def test_cleared_then_regression_reopens(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    reg = _registry()
    # the fix holds across two cadence ticks, then the vulnerability returns
    refire = _refire_seq(False, False, True, True, False)

    o1 = run_cadence_tick(reg, now=0.0, refire=refire)
    assert [o.verdict for o in o1] == [CLEARED] and not o1[0].regression and not o1[0].reopened

    o2 = run_cadence_tick(reg, now=INTERVAL, refire=refire)       # due again → re-fire → still clean
    assert o2[0].verdict == CLEARED and not o2[0].regression and not o2[0].reopened

    o3 = run_cadence_tick(reg, now=2 * INTERVAL, refire=refire)   # the bug is back → REGRESSION on this tick
    assert o3[0].verdict == STILL_PRESENT and o3[0].regression and o3[0].reopened
    assert [w.finding_ref for w in reg.reopened_findings()] == ["errsqli-1"]

    o4 = run_cadence_tick(reg, now=3 * INTERVAL, refire=refire)   # still present → re-opened, but not a NEW regression
    assert o4[0].verdict == STILL_PRESENT and not o4[0].regression and o4[0].reopened

    o5 = run_cadence_tick(reg, now=4 * INTERVAL, refire=refire)   # re-fixed → clears the re-opened flag
    assert o5[0].verdict == CLEARED and not o5[0].reopened
    assert reg.reopened_findings() == []


def test_still_present_without_prior_clear_is_not_a_regression(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    reg = _registry()
    out = run_cadence_tick(reg, now=0.0, refire=_refire_seq(True))
    # never cleared ⇒ a STILL_PRESENT is just still-vulnerable, NOT a re-opened fix
    assert out[0].verdict == STILL_PRESENT and not out[0].regression and not out[0].reopened


# =====================================================================================================
# silence is never a fix — INCONCLUSIVE neither clears nor re-opens, and never masks a later regression
# =====================================================================================================


def test_inconclusive_never_clears(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    reg = _registry()
    out = run_cadence_tick(reg, now=0.0, refire=_refire_seq(None))
    assert out[0].verdict == INCONCLUSIVE
    wf = reg.findings["errsqli-1"]
    assert not wf.ever_cleared and wf.consecutive_clear == 0 and not wf.reopened


def test_inconclusive_does_not_mask_a_regression(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    reg = _registry()
    # cleared → inconclusive → still_present: the ever-cleared signal survives the silence, so the final fire
    # is still a provable regression.
    refire = _refire_seq(False, None, True)
    run_cadence_tick(reg, now=0.0, refire=refire)
    run_cadence_tick(reg, now=INTERVAL, refire=refire)           # INCONCLUSIVE — no clear, no reopen
    o3 = run_cadence_tick(reg, now=2 * INTERVAL, refire=refire)
    assert o3[0].verdict == STILL_PRESENT and o3[0].regression and o3[0].reopened


def test_refire_error_is_inconclusive_never_a_false_clear(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    reg = _registry()

    def _boom(_wf):
        raise RuntimeError("sandbox unavailable")
    out = run_cadence_tick(reg, now=0.0, refire=_boom)
    assert out[0].verdict == INCONCLUSIVE and not reg.findings["errsqli-1"].ever_cleared


# =====================================================================================================
# the cadence — a finding is re-fired only when due
# =====================================================================================================


def test_due_cadence(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    reg = _registry()
    assert [w.finding_ref for w in reg.due(0.0)] == ["errsqli-1"]        # never run ⇒ due
    run_cadence_tick(reg, now=0.0, refire=_refire_seq(False))
    assert reg.due(INTERVAL - 1) == []                                   # not yet due
    assert [w.finding_ref for w in reg.due(INTERVAL)] == ["errsqli-1"]   # due at the interval boundary
    # a tick before the cadence is due is a no-op
    assert run_cadence_tick(reg, now=INTERVAL - 1, refire=_refire_seq(True)) == []


# =====================================================================================================
# default-OFF — inert, byte-identical
# =====================================================================================================


def test_flag_off_is_inert(monkeypatch):
    monkeypatch.delenv("VIGIL_APEX_IMPACT", raising=False)
    reg = _registry()
    out = run_cadence_tick(reg, now=0.0, refire=_refire_seq(True))
    assert out == []
    wf = reg.findings["errsqli-1"]
    assert wf.last_run is None and wf.runs == 0 and wf.last_verdict == ""   # untouched


# =====================================================================================================
# durable registry — state survives a reload (so a long-running scheduler resumes exactly)
# =====================================================================================================


def test_registry_persists_across_reload(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    path = tmp_path / "retest-registry.json"
    reg = _registry(path)
    run_cadence_tick(reg, now=0.0, refire=_refire_seq(False))             # clears it (persisted on tick)
    run_cadence_tick(reg, now=INTERVAL, refire=_refire_seq(True))         # regression (persisted)

    reloaded = RetestRegistry(path)
    wf = reloaded.findings["errsqli-1"]
    assert wf.ever_cleared and wf.reopened and wf.last_verdict == STILL_PRESENT
    assert [w.finding_ref for w in reloaded.reopened_findings()] == ["errsqli-1"]
