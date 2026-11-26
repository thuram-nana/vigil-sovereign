"""AS-30 (D17, #1202) — the per-tenant job-substrate runner (defense plane).

The acceptance is *"killed job degrades TT-A only"*: two per-tenant runners, TT-A's job is killed, and
TT-B's substrate projection is BYTE-IDENTICAL to a baseline where TT-A never ran — proven with the
vigil_core primitive's deterministic ``isolation_witness``. Also pins the default-OFF flag (inert /
flag-off byte-identical), fault containment (a crashing job never crashes the runner), FATAL-2 (no
``sigil`` / ``strix`` import), and determinism.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from framework.v2.aegis import job_runner as R
from framework.v2.aegis.job_runner import JobSpec, KilledJob, PerTenantRunner, RunnerError
from vigil_core.job_substrate import JobState, SubstrateState, TenantHealth, isolation_witness


def _spec(tenant: str, kind: str = "rule_compile", **payload: object) -> JobSpec:
    return JobSpec(tenant=tenant, kind=kind, payload=dict(payload) or {"n": 1})


def _ok(_job):  # a clean job body
    return "done"


def _raises(_job):  # an ordinary failure
    raise ValueError("rule compile blew up")


def _killed(_job):  # an out-of-band terminate (OOM / relocate / crash-loop cap)
    raise KilledJob("oom-killed under TT-A cgroup")


# -- 1. default-OFF flag: inert, flag-off byte-identical -------------------------------------------
def test_flag_default_off_runner_is_inert(monkeypatch):
    monkeypatch.delenv(R.JOBS_ENV, raising=False)
    runner = PerTenantRunner("TT-A")
    assert runner.enabled is False
    out = runner.run_job(_spec("TT-A"), _ok)
    assert out.enabled is False
    assert out.state is None
    assert runner.state == SubstrateState()                 # nothing admitted
    assert runner.health() is TenantHealth.NOMINAL
    # flag-off byte-identical: the disabled outcome is a FIXED value independent of the spec.
    out2 = runner.run_job(_spec("TT-A", kind="heartbeat", x=99), _ok)
    assert out == out2
    assert out.projection_digest == SubstrateState().tenant_projection_digest("TT-A")


@pytest.mark.parametrize("token,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("", False), ("0", False), ("off", False), ("nope", False),
])
def test_flag_token_parsing(monkeypatch, token, expected):
    monkeypatch.setenv(R.JOBS_ENV, token)
    assert R.jobs_enabled() is expected


# -- 2. enabled runner: clean run, contained failure, contained kill ------------------------------
def test_enabled_runner_runs_job_to_success():
    runner = PerTenantRunner("TT-A", enabled=True)
    out = runner.run_job(_spec("TT-A"), _ok)
    assert out.enabled is True
    assert out.state is JobState.SUCCEEDED
    assert out.health is TenantHealth.NOMINAL


def test_failing_job_is_contained_and_degrades_only_this_tenant():
    runner = PerTenantRunner("TT-A", enabled=True)
    # the exception MUST NOT escape the runner (fault containment)
    out = runner.run_job(_spec("TT-A"), _raises)
    assert out.state is JobState.FAILED
    assert out.health is TenantHealth.DEGRADED
    assert "ValueError" in out.detail


def test_killed_job_is_marked_killed_and_degrades():
    runner = PerTenantRunner("TT-A", enabled=True)
    out = runner.run_job(_spec("TT-A"), _killed)
    assert out.state is JobState.KILLED
    assert out.health is TenantHealth.DEGRADED
    assert "oom" in out.detail


def test_runner_refuses_a_foreign_tenant_job():
    runner = PerTenantRunner("TT-A", enabled=True)
    with pytest.raises(RunnerError, match="one tenant per runner"):
        runner.run_job(_spec("TT-B"), _ok)


# -- 3. THE ACCEPTANCE: a killed job degrades TT-A only -------------------------------------------
def test_killed_job_degrades_tt_a_only():
    # Baseline: TT-B runs its job alone, TT-A idle.
    ttb_baseline = PerTenantRunner("TT-B", enabled=True)
    ttb_baseline.run_job(_spec("TT-B", kind="heartbeat"), _ok)
    b_digest_baseline = ttb_baseline.projection_digest()

    # Now two separate per-tenant runners. TT-A's job is KILLED first; TT-B then runs the same job.
    tta = PerTenantRunner("TT-A", enabled=True)
    ttb = PerTenantRunner("TT-B", enabled=True)

    a_out = tta.run_job(_spec("TT-A", kind="rule_compile"), _killed)   # the kill event
    b_out = ttb.run_job(_spec("TT-B", kind="heartbeat"), _ok)          # TT-B unaffected by TT-A's kill

    # TT-A degraded; TT-B nominal and BYTE-IDENTICAL to the baseline where TT-A never existed.
    assert a_out.health is TenantHealth.DEGRADED and a_out.state is JobState.KILLED
    assert b_out.health is TenantHealth.NOMINAL and b_out.state is JobState.SUCCEEDED
    assert ttb.projection_digest() == b_digest_baseline

    # The fleet/console merged view: against a baseline where only TT-B ran, killing TT-A's job moved
    # EXACTLY TT-A's projection and nothing else (deterministic witness from the vigil_core primitive).
    baseline_merged = SubstrateState(jobs=ttb.state.jobs)
    after_merged = SubstrateState(jobs=tta.state.jobs + ttb.state.jobs)
    assert isolation_witness(baseline_merged, after_merged) == frozenset({"TT-A"})


def test_a_second_killed_tenant_still_leaves_the_third_untouched():
    runners = {t: PerTenantRunner(t, enabled=True) for t in ("TT-A", "TT-B", "TT-CI")}
    runners["TT-A"].run_job(_spec("TT-A"), _killed)
    runners["TT-B"].run_job(_spec("TT-B"), _raises)
    c_out = runners["TT-CI"].run_job(_spec("TT-CI"), _ok)
    assert runners["TT-A"].health() is TenantHealth.DEGRADED
    assert runners["TT-B"].health() is TenantHealth.DEGRADED
    assert c_out.health is TenantHealth.NOMINAL
    # merged witness: only the two degraded tenants moved off a TT-CI-only baseline.
    baseline = SubstrateState(jobs=runners["TT-CI"].state.jobs)
    after = SubstrateState(jobs=sum((runners[t].state.jobs for t in runners), ()))
    assert isolation_witness(baseline, after) == frozenset({"TT-A", "TT-B"})


# -- 4. determinism -------------------------------------------------------------------------------
def test_two_runners_same_calls_are_byte_identical():
    r1 = PerTenantRunner("TT-A", enabled=True)
    r2 = PerTenantRunner("TT-A", enabled=True)
    o1 = r1.run_job(_spec("TT-A", kind="rule_compile", seclang="x"), _ok)
    o2 = r2.run_job(_spec("TT-A", kind="rule_compile", seclang="x"), _ok)
    assert o1.job_id == o2.job_id
    assert o1.projection_digest == o2.projection_digest
    assert r1.state.digest() == r2.state.digest()


# -- 5. FATAL-2 structural: the runner imports no sovereign / strix engine -------------------------
def test_runner_imports_no_sigil_or_strix():
    src = Path(R.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    assert "sigil" not in roots, "job_runner must never import the sovereign plane (FATAL-2)"
    assert "strix" not in roots, "job_runner must never import strix"
    assert "vigil_core" in roots, "job_runner must drive the vigil_core job-substrate primitive"


def test_non_canonical_payload_is_fault_contained_not_raised():
    """A payload content_id cannot canonicalise (e.g. a set) is a malformed ADMISSION, not a crash:
    run_job must contain it as FAILED and degrade ONLY this tenant, never let the exception escape
    (the run_job contract: 'The exception NEVER escapes')."""
    runner = PerTenantRunner("TT-A", enabled=True)
    out = runner.run_job(_spec("TT-A", v={1, 2, 3}), lambda job: None)   # a set -> not JSON-canonical
    assert out.state is JobState.FAILED
    assert out.health is TenantHealth.DEGRADED
    assert "TypeError" in out.detail
    # a second unadmissible job is independent and gets a distinct id (seq-scoped) -> deterministic ids
    out2 = runner.run_job(_spec("TT-A", v={4, 5}), lambda job: None)
    assert out2.state is JobState.FAILED and out2.job_id != out.job_id
    # a sibling tenant is untouched by TT-A's malformed admission
    ok = PerTenantRunner("TT-B", enabled=True).run_job(_spec("TT-B"), lambda job: None)
    assert ok.state is JobState.SUCCEEDED
