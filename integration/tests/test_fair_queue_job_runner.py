"""Consumer PR-F — the tenant-fair claim on the PRODUCTION job path: ``SecurityJobQueue`` (→ ``EngagementScheduler``).

The engine scheduler's fair claim (``VIGIL_CUSTOMER_FAIR_QUEUE``) is unit-tested in
``framework/v2/tests/test_engagement_scheduler_fair.py``. This pins the INTEGRATION WRAPPER the customer launch
actually rides: the customer-launch ``SecurityJob`` (``source="api"``, ``tenant_id`` = the lease's org,
``engagement_slug`` = its ``cust_<hash>``, ``extra.nonce`` = the lease nonce) is enqueued through the durable,
idempotent ``SecurityJobQueue``, and ``SecurityJobQueue.claim_next`` — the single, atomic, single-winner claim the
drain rides — serves it tenant-fair: the fairness group the claim reads is that job's ``tenant_id``, so one tenant's
backlog cannot starve another tenant's launch. Flag off: arrival order, byte-identical, no ``fair/`` state.

FAIRNESS IS A CLAIM-ORDER PROPERTY OF THE SHARED QUEUE, proven here at the ``claim_next`` seam (where the scheduler
decides), exactly as the customer rides it. EXECUTION stays process-/root-per-tenant: a tagged job runs only in its
own tenant's sharded drain (``CRUCIBLE_TENANT``; ``authorize_job._reconcile_tenant`` refuses a cross-tenant job by
construction — ``test_jobs_securityjob_slice1``), so the gate-still-decides leg runs ONE sharded tenant through the
real ``JobRunner`` and shows the gate — not the tenant guard — deciding every run. The claim never lifts a gate.
"""

from __future__ import annotations

import pytest

from vigil_integration.jobs.authorize import GateOutcome
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.jobs.runner import JobRunner

# The queue/scheduler drive the offense engine (EngagementScheduler, SlugLease) via LAZY imports: skip where
# `framework` is absent (the sovereign CI leg); the OFFENSE leg lists this file (test_ci_framework_tests_run_in_offense_leg.py).
pytest.importorskip("framework.v2.engagement_scheduler",
                    reason="the job queue drives the offense engine; executes in the offense CI leg")

_FLAG = "VIGIL_CUSTOMER_FAIR_QUEUE"
_ALLOW = lambda job: GateOutcome(True, "test-allow")          # noqa: E731
_DENY = lambda job: GateOutcome(False, "test-deny", "policy")  # noqa: E731


def _launch(org: str, n: int) -> SecurityJob:
    """A customer-launch job shaped as LaunchTrigger builds it (one per published owner-signed lease)."""
    slug = f"cust_{org}_{n:03d}"
    return SecurityJob.normalize(source="api", repo=f"{org}-{n}.example", engagement_slug=slug, tenant_id=org,
                                 commit=f"nonce-{org}-{n}", delivery_id=f"launch:{slug}:{n}",
                                 extra={"nonce": f"nonce-{org}-{n}", "org_id": org})


def _claim_tenants(q: SecurityJobQueue, n: int) -> "list[str]":
    """Claim → complete one job per tick (a single free slot) through the PRODUCTION queue; the tenant of each
    claim, in the order the scheduler serves it. This is the drain's own claim path (``claim_next`` →
    ``EngagementScheduler.claim_next`` → the fair claim), minus the per-tenant worker."""
    order: "list[str]" = []
    for _ in range(n):
        claimed = q.claim_next()
        if claimed is None:
            break
        order.append(claimed.job.tenant_id)
        q.complete(claimed)
    return order


def test_with_the_flag_on_one_tenants_backlog_cannot_starve_another(tmp_path, monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    q = SecurityJobQueue(tmp_path / "jobs")
    for i in range(6):
        assert q.enqueue(_launch("org_hog", i)).enqueued
    first, second = q.claim_next(), q.claim_next()                  # the hog now has 2 jobs RUNNING + a backlog
    assert {first.job.tenant_id, second.job.tenant_id} == {"org_hog"}
    assert q.enqueue(_launch("org_late", 0)).enqueued               # a single latecomer, behind the backlog
    nxt = q.claim_next()
    assert nxt.job.tenant_id == "org_late", "the hog's backlog was claimed before a tenant with nothing running"


def test_with_the_flag_off_the_queue_claims_in_arrival_order(tmp_path, monkeypatch):
    monkeypatch.delenv(_FLAG, raising=False)
    q = SecurityJobQueue(tmp_path / "jobs")
    for i in range(6):
        assert q.enqueue(_launch("org_hog", i)).enqueued
    assert q.enqueue(_launch("org_late", 0)).enqueued
    assert _claim_tenants(q, 7).index("org_late") == 6              # arrival order: the latecomer waits
    assert not (tmp_path / "jobs" / "fair").exists()                # off: no fairness state is ever written


def test_ten_tenants_each_claimed_within_the_first_ten(tmp_path, monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    tenants = [f"org_t{k}" for k in range(10)]
    q = SecurityJobQueue(tmp_path / "jobs")
    for t in tenants:                                              # 50 launches, enqueued tenant by tenant
        for i in range(5):
            assert q.enqueue(_launch(t, i)).enqueued
    order = _claim_tenants(SecurityJobQueue(tmp_path / "jobs"), 50)
    assert set(order[:10]) == set(tenants), order[:10]            # every tenant served in the first round
    assert sorted(order) == sorted(t for t in tenants for _ in range(5))   # nothing lost, nothing doubled


def test_the_gate_decides_every_run_for_the_sharded_tenant(tmp_path, monkeypatch):
    """The claim reorders; AUTHORITY is unchanged. One tenant's own sharded drain (``CRUCIBLE_TENANT``) runs its
    launches through the real ``JobRunner``: a DENY gate refuses every job (the gate's ``policy`` code, never the
    tenant guard), and an ALLOW gate runs the worker under the per-slug lease."""
    monkeypatch.setenv(_FLAG, "1")
    monkeypatch.setenv("CRUCIBLE_TENANT", "org_a")                 # this drain is sharded for org_a (its only tenant)

    qd = SecurityJobQueue(tmp_path / "deny")
    for i in range(2):
        assert qd.enqueue(_launch("org_a", i)).enqueued
    deny = JobRunner(queue=qd, gate=_DENY, assert_tenant=lambda: None,
                     worker=lambda job: pytest.fail("the worker ran on a denied job"))
    deny_out = deny.drain()
    assert [o.state for o in deny_out] == ["refused", "refused"]
    assert [o.denial_code for o in deny_out] == ["policy", "policy"], "refused by the tenant guard, not the gate"

    qa = SecurityJobQueue(tmp_path / "allow")
    for i in range(2):
        assert qa.enqueue(_launch("org_a", i)).enqueued
    ran: "list[str]" = []
    allow = JobRunner(queue=qa, gate=_ALLOW, worker=lambda job: ran.append(job.tenant_id),
                      assert_tenant=lambda: None)
    assert [o.state for o in allow.drain()] == ["done", "done"]
    assert ran == ["org_a", "org_a"]                               # the worker ran, under the lease, for its tenant
