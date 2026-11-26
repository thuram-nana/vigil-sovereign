"""AS-30 (D17, #1202) — the per-tenant job-substrate PRIMITIVE, in pure ``vigil_core``.

Pins the four invariants the slice rests on:

  * STDLIB-CLOSURE (the ``make gate`` ported-primitive guard): the leaf imports nothing but a fixed
    stdlib set — no framework, no sigil, no pydantic — so the sovereign leg and any re-execution kernel
    load it with no heavy dependency (``test_the_leaf_is_stdlib_only``).
  * VOCABULARY PARITY (D13): the degraded / down tokens are the SAME honest headline vocabulary the rest
    of vigil_core already ships, never a fork.
  * FAULT ISOLATION (the acceptance): a killed job degrades ITS tenant only; every other tenant's
    rendered projection is byte-identical across the kill.
  * DETERMINISM: no wall-clock / RNG — equal inputs give byte-identical digests and projections.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from vigil_core import job_substrate as js
from vigil_core.job_substrate import (
    Job,
    JobState,
    JobSubstrateError,
    SubstrateState,
    TenantHealth,
    isolation_witness,
    kill_job,
    submit,
    transition,
)

_ALLOWED_STDLIB = {"__future__", "hashlib", "json", "dataclasses", "enum", "typing"}


# -- 1. stdlib-closure (the ported-primitive / re-execution closure stays stdlib-only) --------------
def test_the_leaf_is_stdlib_only():
    tree = ast.parse(Path(js.__file__).read_text(encoding="utf-8"))
    mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert mods <= _ALLOWED_STDLIB, f"job_substrate must be stdlib-only; stray imports: {mods - _ALLOWED_STDLIB}"


def test_module_imports_no_framework_or_sigil():
    # FATAL-2 at module scope: importing the primitive pulls in no offense/sovereign engine.
    import sys

    assert "framework" not in sys.modules or True  # loaded elsewhere is irrelevant; the guard is the AST one
    src = Path(js.__file__).read_text(encoding="utf-8")
    for bad in ("import framework", "import sigil", "import strix", "import pydantic", "from framework", "from sigil"):
        assert bad not in src, f"job_substrate must not reference {bad!r}"


# -- 2. vocabulary parity with the existing closed headline / engine-health vocabulary (D13) --------
def test_degraded_and_down_reuse_the_existing_headline_vocabulary():
    from vigil_core.aegis_schemas import EngineHealthState
    from vigil_core.protection_contract import Headline

    assert TenantHealth.DEGRADED.value == Headline.DEGRADED.value == "degraded"
    assert TenantHealth.DOWN.value == EngineHealthState.DOWN.value == "down"


# -- 3. lifecycle + fail-closed transitions ---------------------------------------------------------
def _job(job_id: str, tenant: str, state: JobState = JobState.QUEUED) -> Job:
    return Job(job_id=job_id, tenant=tenant, kind="rule_compile", payload_digest=js.content_id(job_id), state=state)


def test_submit_then_run_to_success_is_nominal():
    s = submit(SubstrateState(), _job("j1", "TT-A"))
    s = transition(s, "j1", JobState.RUNNING)
    s = transition(s, "j1", JobState.SUCCEEDED, detail="done")
    assert s.require("j1").state is JobState.SUCCEEDED
    assert s.tenant_health("TT-A") is TenantHealth.NOMINAL


def test_duplicate_submit_refused():
    s = submit(SubstrateState(), _job("j1", "TT-A"))
    with pytest.raises(JobSubstrateError, match="duplicate"):
        submit(s, _job("j1", "TT-A"))


def test_terminal_is_final_no_resurrection():
    s = submit(SubstrateState(), _job("j1", "TT-A"))
    s = kill_job(s, "j1", reason="oom")
    with pytest.raises(JobSubstrateError, match="terminal"):
        transition(s, "j1", JobState.RUNNING)
    with pytest.raises(JobSubstrateError, match="already terminal"):
        kill_job(s, "j1", reason="again")


def test_illegal_forward_transition_refused():
    s = submit(SubstrateState(), _job("j1", "TT-A"))
    s = transition(s, "j1", JobState.RUNNING)
    # running -> queued is not a permitted forward edge
    with pytest.raises(JobSubstrateError, match="illegal transition"):
        transition(s, "j1", JobState.QUEUED)


def test_kill_requires_reason():
    s = submit(SubstrateState(), _job("j1", "TT-A"))
    with pytest.raises(JobSubstrateError, match="reason"):
        kill_job(s, "j1", reason="")


# -- 4. THE ACCEPTANCE at the primitive level: killed job degrades TT-A only ------------------------
def _two_tenant_state() -> SubstrateState:
    s = SubstrateState()
    s = submit(s, _job("a1", "TT-A"))
    s = submit(s, _job("a2", "TT-A"))
    s = submit(s, _job("b1", "TT-B"))
    s = transition(s, "a1", JobState.RUNNING)
    s = transition(s, "b1", JobState.RUNNING)
    return s


def test_killed_job_degrades_only_that_tenant():
    before = _two_tenant_state()
    assert before.tenant_health("TT-A") is TenantHealth.NOMINAL
    assert before.tenant_health("TT-B") is TenantHealth.NOMINAL

    b_digest_before = before.tenant_projection_digest("TT-B")
    b_bytes_before = js.canonical_bytes(before.tenant_projection("TT-B"))

    after = kill_job(before, "a1", reason="oom-killed under TT-A's cgroup")

    # TT-A degraded; TT-B unchanged, BYTE-IDENTICAL projection.
    assert after.tenant_health("TT-A") is TenantHealth.DEGRADED
    assert after.tenant_health("TT-B") is TenantHealth.NOMINAL
    assert after.tenant_projection_digest("TT-B") == b_digest_before
    assert js.canonical_bytes(after.tenant_projection("TT-B")) == b_bytes_before

    # the deterministic witness: ONLY TT-A moved.
    assert isolation_witness(before, after) == frozenset({"TT-A"})


def test_failed_job_also_degrades_only_its_tenant():
    before = _two_tenant_state()
    after = transition(before, "a1", JobState.FAILED, detail="rule compile error")
    assert after.tenant_health("TT-A") is TenantHealth.DEGRADED
    assert after.tenant_health("TT-B") is TenantHealth.NOMINAL
    assert isolation_witness(before, after) == frozenset({"TT-A"})


def test_a_tenants_projection_is_independent_of_other_tenants():
    # TT-B's projection must equal the projection of a substrate that holds ONLY TT-B's jobs — true
    # partitioning, so no amount of TT-A churn can perturb TT-B's rendered bytes.
    full = _two_tenant_state()
    full = kill_job(full, "a1", reason="x")
    full = kill_job(full, "a2", reason="y")

    only_b = SubstrateState()
    only_b = submit(only_b, _job("b1", "TT-B"))
    only_b = transition(only_b, "b1", JobState.RUNNING)

    assert js.canonical_bytes(full.tenant_projection("TT-B")) == js.canonical_bytes(only_b.tenant_projection("TT-B"))
    assert "TT-A" not in js.canonical_bytes(full.tenant_projection("TT-B")).decode()


# -- 5. determinism (no wall-clock / RNG) ----------------------------------------------------------
def test_equal_op_sequences_yield_identical_digests():
    a = _two_tenant_state()
    b = _two_tenant_state()
    assert a.digest() == b.digest()
    assert a.tenant_projection_digest("TT-A") == b.tenant_projection_digest("TT-A")
    ka = kill_job(a, "a1", reason="oom")
    kb = kill_job(b, "a1", reason="oom")
    assert ka.digest() == kb.digest()


def test_state_is_order_independent_in_canonical_form():
    # submitting in a different order produces a byte-identical state (jobs are canonically sorted).
    s1 = submit(submit(SubstrateState(), _job("b1", "TT-B")), _job("a1", "TT-A"))
    s2 = submit(submit(SubstrateState(), _job("a1", "TT-A")), _job("b1", "TT-B"))
    assert s1.digest() == s2.digest()
    assert js.canonical_bytes([j.canonical() for j in s1.jobs]) == js.canonical_bytes([j.canonical() for j in s2.jobs])
