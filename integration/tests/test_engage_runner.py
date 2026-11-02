"""K4-3 — the customer-launch worker + gate + runner.

The customer-launch EXECUTION path, mock-only (production targets stay DISABLED behind the K4 flag):
  * build_customer_launch_gate — a fail-closed CONJUNCTION at the scheduling boundary: a verified CUSTOMER
    EngagementAuthority (issued_by customer:, never an operator one) ∧ the owner-signed CreditLaunchLease
    (verify_customer_launch_lease consume=False — floor NOT burned) ∧ the K4 prod-flag (a LIVE target is
    refused while the flag is off) ∧ authorize_action (scope/window/kill-switch over the EXACT-host scope);
  * make_engage_worker — invoked ONLY by JobRunner.run_one; binds the seed host AUTHORITATIVELY from the
    verified authority scope (never the advisory job.extra), re-checks the prod-flag at execution, then drives
    run_engagement (injected here as a mock engine — the real arm consumes the single-use lease + re-runs the
    engine gate chain);
  * make_engage_scan_runner — SecurityJobQueue + JobRunner(gate, worker): execution SOLELY via run_one.

Runs on the integration PYTHONPATH (framework + vigil_core); framework is imported lazily by the gate/worker,
so this is the integration test leg.
"""
from __future__ import annotations

import datetime as _dt
import tempfile
from datetime import timezone

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs.authorize import build_customer_launch_gate
from vigil_integration.jobs.engage_worker import make_engage_worker
from vigil_integration.jobs.launch_runner import make_engage_scan_runner
from vigil_integration.jobs.launch_trigger import LaunchTrigger, launch_delivery_id
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.live.credit_lease_broker import record_lease_settlement, write_credit_lease

SLUG, HOST, ORG = "cust_abc123", "apme.cm", "org_a"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, nonce="n1", issued=1000.0):
    t = _dt.datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=SLUG, org_id=ORG, scope_host=HOST, units_reserved=10,
                            not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _customer_authority(slug, scope, *, env="twin", issued_by="customer:org_a", now=1000.0):
    from framework.v2.authority.models import EngagementAuthority
    t = _dt.datetime.fromtimestamp(now, tz=timezone.utc)           # window around the SAME simulated clock as the lease
    return EngagementAuthority(engagement_slug=slug, environment=env, scope=scope, issued_by=issued_by,
                              not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8))


def _rig(monkeypatch, owner, *, env="twin", issued_by="customer:org_a", write_lease=True,
         settled=False, now=1000.0):
    """Write a REAL owner-signed lease to a fresh seam (so the lease pre-check verifies for real) and
    monkeypatch the offense authority store: load_authority_root → the owner root (for the lease verify),
    load_verified_authority → a constructed customer authority (so authorize_action runs over it for real)."""
    from framework.v2.authority import store as authz_store
    base = tempfile.mkdtemp()
    if write_lease:
        write_credit_lease(base, SLUG, _lease(owner, nonce="n1", issued=now), _owner_root(owner))
        if settled:
            record_lease_settlement(base, SLUG, "n1")
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _customer_authority(slug, [HOST], env=env, issued_by=issued_by))
    return base


def _job(*, tenant=ORG, seed_host=HOST):
    return SecurityJob.normalize(
        source="api", repo=HOST, engagement_slug=SLUG, tenant_id=tenant,
        delivery_id=launch_delivery_id(SLUG, "n1"),
        extra={"seed_url": f"https://{seed_host}", "host": seed_host, "nonce": "n1", "org_id": ORG})


# ---- the gate: a fail-closed conjunction --------------------------------------------------------------

def test_gate_allows_a_verified_customer_lease_on_a_twin_target(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="twin")
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is True, out.reason


def test_gate_refuses_without_a_verified_authority(monkeypatch):
    from framework.v2.authority import store as authz_store
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    monkeypatch.setattr(authz_store, "load_verified_authority", lambda slug, root, path=None: None)
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is False and out.denial_code == "unverified_authority"


def test_gate_refuses_an_operator_authority_billing_is_not_testing(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, issued_by="owner")        # an OPERATOR authority (issued_by != customer:)
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is False and out.denial_code == "not_customer"


def test_gate_refuses_without_a_lease(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, write_lease=False)        # verified authority, but NO owner-signed lease
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is False and out.denial_code == "no_lease"


def test_gate_refuses_a_settled_lease(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, settled=True)             # K4-1: settled (slug, nonce)
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is False and out.denial_code == "no_lease" and "settled" in out.reason.lower()


def test_gate_refuses_a_live_target_when_the_flag_is_off_and_allows_when_on(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="live")
    off = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0,
                                     prod_execution_enabled=lambda: False)(_job())
    assert off.allowed is False and off.denial_code == "customer_prod_disabled"
    on = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0,
                                    prod_execution_enabled=lambda: True)(_job())
    assert on.allowed is True, on.reason                     # a LIVE target is allowed once the owner opts in


def test_gate_refuses_a_live_target_via_the_REAL_default_env_read(monkeypatch):
    # HIGH (red-pen): the fail-closed DEFAULT must be exercised through the REAL posture read, not only an
    # injected callable — else a fail-OPEN wiring regression (default callable wrong) ships green. No
    # prod_execution_enabled injected here; the env is UNSET, so the real customer_prod_execution_enabled()
    # must return False and the gate must refuse the LIVE customer target.
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="live")
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())  # NO injected flag
    assert out.allowed is False and out.denial_code == "customer_prod_disabled"
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")          # explicit owner opt-in via the REAL env
    on = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert on.allowed is True, on.reason


def test_gate_binds_host_from_authority_scope_ignoring_a_tampered_extra(monkeypatch):
    # MED (red-pen): the gate must bind the lease-verify host + authorize_action target from the VERIFIED
    # authority scope[0], never the advisory job.extra. A job whose extra claims a different host still
    # authorizes against the authority host (the lease exists for the authority host) — proving extra is
    # ignored (had the gate used extra='evil.example', it would look for a lease there and refuse).
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="twin")                      # lease + authority are for HOST (apme.cm)
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job(seed_host="evil.example"))
    assert out.allowed is True, out.reason                           # bound to the authority host, not the tampered extra


def test_gate_does_not_burn_the_single_use_floor(monkeypatch):
    # the scheduling-time gate uses consume=False, so the engine ARM (consume=True) can still consume once.
    from framework.v2.launch_lease import verify_customer_launch_lease
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="twin")
    assert build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job()).allowed
    assert build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job()).allowed  # twice
    assert verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)[0]    # arm still works


# ---- the worker: authoritative host binding + execution-boundary flag re-check -------------------------

def test_worker_seeds_authoritatively_from_scope_ignoring_a_tampered_extra(monkeypatch):
    owner = generate_keypair()
    _rig(monkeypatch, owner, env="twin")
    calls = []
    w = make_engage_worker(trust_root=object(), run=lambda **kw: calls.append(kw) or {"facts": 0})
    assert w(_job(seed_host="evil.example")) == {"facts": 0}          # a TAMPERED extra seed
    assert calls == [{"slug": SLUG, "seed_url": f"https://{HOST}"}]    # ...is ignored — seed is the authority host


def test_worker_refuses_a_live_target_when_the_flag_is_off(monkeypatch):
    owner = generate_keypair()
    _rig(monkeypatch, owner, env="live")
    w = make_engage_worker(trust_root=object(), run=lambda **kw: {"facts": 0},
                           prod_execution_enabled=lambda: False)
    with pytest.raises(RuntimeError, match="production-target customer execution is disabled"):
        w(_job())


def test_worker_refuses_an_operator_authority(monkeypatch):
    owner = generate_keypair()
    _rig(monkeypatch, owner, issued_by="owner")
    w = make_engage_worker(trust_root=object(), run=lambda **kw: {"facts": 0})
    with pytest.raises(RuntimeError, match="not a customer engagement authority"):
        w(_job())


def test_worker_prod_flag_via_the_REAL_default_env_read(monkeypatch):
    # HIGH (red-pen): the worker's EXECUTION-boundary flag re-check must be exercised through the REAL posture
    # read (no injected callable). Env unset -> a LIVE customer arm is refused; env enabled -> it runs.
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)
    owner = generate_keypair()
    _rig(monkeypatch, owner, env="live")
    w = make_engage_worker(trust_root=object(), run=lambda **kw: {"facts": 0})   # NO injected flag
    with pytest.raises(RuntimeError, match="production-target customer execution is disabled"):
        w(_job())
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")          # explicit owner opt-in via the REAL env
    calls = []
    w2 = make_engage_worker(trust_root=object(), run=lambda **kw: calls.append(kw) or {"facts": 1})
    assert w2(_job())["facts"] == 1 and calls == [{"slug": SLUG, "seed_url": f"https://{HOST}"}]


# ---- the runner: execution SOLELY via run_one ---------------------------------------------------------

def test_runner_drives_an_authorized_launch_through_run_one(monkeypatch, tmp_path):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="twin")
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)               # shard for org_a so _reconcile_tenant matches
    calls = []
    runner = make_engage_scan_runner(str(tmp_path / "q"), base_dir=base, trust_root=object(), now=1000.0,
                                     run=lambda **kw: calls.append(kw) or {"facts": 1},
                                     assert_tenant=lambda: None)   # skip the isolation-root check in-process
    job = LaunchTrigger(base_dir=base, now=1000.0).poll()[0]       # K4-2 trigger produces the job (end-to-end)
    assert runner.queue.enqueue(job).enqueued is True
    out = runner.run_one()
    assert out.state == "done", out.reason
    assert calls == [{"slug": SLUG, "seed_url": f"https://{HOST}"}]  # the engage worker ran under the lease


def test_runner_refuses_a_job_with_no_authority_worker_never_runs(monkeypatch, tmp_path):
    from framework.v2.authority import store as authz_store
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    monkeypatch.setattr(authz_store, "load_verified_authority", lambda slug, root, path=None: None)
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)
    ran = []
    runner = make_engage_scan_runner(str(tmp_path / "q"), base_dir=base, trust_root=object(), now=1000.0,
                                     run=lambda **kw: ran.append(kw), assert_tenant=lambda: None)
    runner.queue.enqueue(LaunchTrigger(base_dir=base, now=1000.0).poll()[0])
    out = runner.run_one()
    assert out.state == "refused" and not ran                 # the worker is NEVER invoked on a refusal


def test_runner_refuses_a_live_target_when_the_flag_is_off(monkeypatch, tmp_path):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="live")
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)
    ran = []
    runner = make_engage_scan_runner(str(tmp_path / "q"), base_dir=base, trust_root=object(), now=1000.0,
                                     run=lambda **kw: ran.append(kw), prod_execution_enabled=lambda: False,
                                     assert_tenant=lambda: None)
    runner.queue.enqueue(LaunchTrigger(base_dir=base, now=1000.0).poll()[0])
    out = runner.run_one()
    assert out.state == "refused" and out.denial_code == "customer_prod_disabled" and not ran


def test_runner_worker_error_marks_failed_and_releases_delivery(monkeypatch, tmp_path):
    def _boom(**kw):
        raise RuntimeError("engine blew up")
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="twin")
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)
    runner = make_engage_scan_runner(str(tmp_path / "q"), base_dir=base, trust_root=object(), now=1000.0,
                                     run=_boom, assert_tenant=lambda: None)
    job = LaunchTrigger(base_dir=base, now=1000.0).poll()[0]
    runner.queue.enqueue(job)
    out = runner.run_one()
    assert out.state == "failed" and "engine blew up" in out.reason
    # a FAILED run released its permanent delivery marker, so the same (slug, nonce) can be re-driven
    assert runner.queue.enqueue(job).enqueued is True


def test_runner_refuses_a_live_customer_by_default_and_runs_only_when_enabled(monkeypatch, tmp_path):
    # MED (red-pen): the REALISTIC customer shape is env='live' (add_customer_target always mints LIVE). Drive
    # BOTH the real default (unset env → refused end-to-end) AND the owner-enabled path (engine runs → done).
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, env="live")
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)
    ran = []
    r1 = make_engage_scan_runner(str(tmp_path / "q1"), base_dir=base, trust_root=object(), now=1000.0,
                                 run=lambda **kw: ran.append(kw), assert_tenant=lambda: None)
    r1.queue.enqueue(LaunchTrigger(base_dir=base, now=1000.0).poll()[0])
    out = r1.run_one()
    assert out.state == "refused" and out.denial_code == "customer_prod_disabled" and not ran   # default off
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")          # deliberate gated owner opt-in
    calls = []
    r2 = make_engage_scan_runner(str(tmp_path / "q2"), base_dir=base, trust_root=object(), now=1000.0,
                                 run=lambda **kw: calls.append(kw) or {"facts": 2}, assert_tenant=lambda: None)
    r2.queue.enqueue(LaunchTrigger(base_dir=base, now=1000.0).poll()[0])
    out2 = r2.run_one()
    assert out2.state == "done", out2.reason                         # the realistic LIVE production path runs
    assert calls == [{"slug": SLUG, "seed_url": f"https://{HOST}"}]
