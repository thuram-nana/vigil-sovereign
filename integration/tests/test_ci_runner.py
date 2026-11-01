"""jobs.ci_runner — assemble + drive the W4 CI scan.

Pins:
  * run_ci_scan ENQUEUES the CI job and drains it through the ONE authorized runner — the worker runs only
    when the gate ALLOWS (sole-executor invariant: a denied job never runs the worker).
  * a CI re-run of the same (repo, pr, commit) is idempotent (exactly-once via the shared delivery key).
  * findings_of reads only `done` results; exit_code fails on a job failure OR an oracle-confirmed FACT at/
    above --fail-on, and NEVER on a LEAD (prove-don't-guess: an unconfirmed lead must not break a build).
"""

from __future__ import annotations

from vigil_integration.jobs.authorize import GateOutcome
from vigil_integration.jobs.ci_runner import exit_code, findings_of, run_ci_scan
from vigil_integration.jobs.ci_trigger import ci_job_from_inputs

_ALLOW = lambda job: GateOutcome(True, "test-allow")              # noqa: E731
_DENY = lambda job: GateOutcome(False, "test-deny", "policy")     # noqa: E731

_RESULT = {"findings": [
    {"title": "weak hash", "bug_class": "broken-crypto", "severity": "High",
     "location": "a.py:1", "static_oracle_confirmed": True},                 # oracle-confirmed FACT
    {"title": "shell true", "bug_class": "os-command", "severity": "Critical",
     "location": "b.py:2"},                                                  # a LEAD (no oracle confirmation)
]}


def _job():
    return ci_job_from_inputs(repo="github.com/o/r", commit="c0ffee", pr_number=1, ci_run_id="7")


def _kw(tmp_path, **over):
    base = dict(queue_root=str(tmp_path / "q"), base_dir=str(tmp_path / "base"), trust_root=None,
                workspace=str(tmp_path), base_ref="B", head_ref="H")
    base.update(over)
    return base


def test_run_ci_scan_enqueues_and_runs_the_authorized_worker(tmp_path) -> None:
    seen = []
    outcomes = run_ci_scan(_job(), **_kw(tmp_path, _gate=_ALLOW,
                                         _worker=lambda j: seen.append(j) or _RESULT))
    assert [o.state for o in outcomes] == ["done"]
    assert seen and seen[0].source == "ci" and seen[0].repo == "github.com/o/r"
    findings = findings_of(outcomes)
    assert len(findings) == 2


def test_denied_gate_refuses_without_running_the_worker(tmp_path) -> None:
    ran = []
    outcomes = run_ci_scan(_job(), **_kw(tmp_path, _gate=_DENY, _worker=lambda j: ran.append(j) or {}))
    assert [o.state for o in outcomes] == ["refused"]
    assert ran == []                      # the gate is the SOLE executor — a denied job never runs


def test_ci_rerun_is_idempotent_exactly_once(tmp_path) -> None:
    n = []
    kw = _kw(tmp_path, _gate=_ALLOW, _worker=lambda j: n.append(1) or {"findings": []})
    run_ci_scan(_job(), **kw)             # first run scans
    out2 = run_ci_scan(_job(), **kw)      # same (repo,pr,commit) -> duplicate delivery -> nothing to drain
    assert sum(n) == 1 and out2 == []     # scanned exactly once across re-runs


def test_findings_of_reads_only_done_results() -> None:
    class _O:
        def __init__(self, state, result=None):
            self.state, self.result = state, result
    outs = [_O("refused"), _O("done", {"findings": [{"a": 1}]}), _O("failed"),
            _O("done", {"findings": [{"b": 2}]}), _O("done", "not-a-dict")]
    assert findings_of(outs) == [{"a": 1}, {"b": 2}]


def test_exit_code_gates_on_failure_and_on_confirmed_facts_only() -> None:
    class _O:
        def __init__(self, state):
            self.state, self.reason, self.denial_code = state, "", ""
    done, failed = [_O("done")], [_O("failed")]
    fact_high = [{"severity": "High", "static_oracle_confirmed": True}]
    lead_crit = [{"severity": "Critical"}]                     # a LEAD (no oracle)
    assert exit_code(failed, [], fail_on="") == 1              # a worker/gate failure always exits non-zero
    assert exit_code(done, fact_high, fail_on="") == 0         # no threshold -> never gates on findings
    assert exit_code(done, fact_high, fail_on="high") == 1     # a confirmed High FACT trips --fail-on high
    assert exit_code(done, fact_high, fail_on="critical") == 0 # ...but not --fail-on critical
    assert exit_code(done, lead_crit, fail_on="high") == 0     # a Critical LEAD NEVER breaks the build
    assert exit_code([_O("refused")], [], fail_on="high") == 0 # refused is a normal state, not a failure
