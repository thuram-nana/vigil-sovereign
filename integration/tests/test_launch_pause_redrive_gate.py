"""pause/resume PR-4 (HARD #1) — a launch paused AFTER it was enqueued RE-DRIVES on resume, never strands.

PR-3 halts a RUNNING launch. This closes the other money-critical window the PR-3 red-pen flagged: a job
already sitting in the durable queue when its lease is paused. The customer-launch gate now classifies a
REVERSIBLE paused-lease refusal (`LEASE_PAUSED_DENIAL`) distinctly from a TERMINAL one (`no_lease`), and
`JobRunner.run_one` RELEASES the one-shot delivery on the paused one — so the seam poller re-produces it once
the pause clears, instead of `complete()`ing it with the delivery marker kept (which made the paid launch
un-re-admittable: the strand).

Pinned: gate classification (paused ⇒ `lease_paused`; settled ⇒ `no_lease`; clean ⇒ allowed; fail-SAFE toward
terminal); `run_one` releases the delivery ONLY on `lease_paused` (keeps it on a terminal refusal); the full
enqueue → pause → refuse → resume → RE-ADMIT-and-run loop; default-OFF byte-identical.

Mutation-verify targets (each neuter reds a NAMED test here):
  * gate always returns "no_lease" (drop the _lease_refusal_is_pause branch) -> test_gate_classifies_a_paused_lease_as_reversible
  * run_one releases on EVERY refusal / never (drop the denial_code guard)   -> test_run_one_keeps_delivery_on_a_terminal_refusal / test_run_one_releases_delivery_only_on_a_paused_refusal
"""
from __future__ import annotations

import datetime as _dt
from datetime import timezone

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs.authorize import LEASE_PAUSED_DENIAL, GateOutcome, build_customer_launch_gate
from vigil_integration.jobs.launch_trigger import launch_delivery_id
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.jobs.runner import JobRunner
from vigil_integration.live.credit_lease_broker import record_lease_settlement, write_credit_lease

# The gate + queue import framework LAZILY; framework is not on the sovereign leg, so skip cleanly there and
# run in the offense/integration CI leg (same posture as test_engage_runner / test_ci_runner).
pytest.importorskip("framework.v2.authority.store", reason="framework (offense) not importable in the sovereign leg")
pytest.importorskip("framework.v2.engagement_scheduler", reason="framework (offense) not importable in the sovereign leg")
_clp = pytest.importorskip("vigil_integration.live.credit_lease_pause")
record_lease_pause = _clp.record_lease_pause
clear_lease_pause = _clp.clear_lease_pause

SLUG, HOST, ORG = "cust_pr4gate", "apme.cm", "org_a"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, nonce="n1", issued=1000.0):
    t = _dt.datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=SLUG, org_id=ORG, scope_host=HOST, units_reserved=10,
                            not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _customer_authority(slug, scope, *, now=1000.0):
    from framework.v2.authority.models import EngagementAuthority
    t = _dt.datetime.fromtimestamp(now, tz=timezone.utc)
    return EngagementAuthority(engagement_slug=slug, environment="twin", scope=scope, issued_by="customer:org_a",
                               not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8))


def _rig(monkeypatch, owner, *, settled=False):
    import tempfile

    from framework.v2.authority import store as authz_store
    base = tempfile.mkdtemp()
    write_credit_lease(base, SLUG, _lease(owner), _owner_root(owner))
    if settled:
        record_lease_settlement(base, SLUG, "n1")
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _customer_authority(slug, [HOST]))
    return base


def _job(*, nonce="n1"):
    return SecurityJob.normalize(
        source="api", repo=HOST, engagement_slug=SLUG, tenant_id=ORG, commit=nonce,
        delivery_id=launch_delivery_id(SLUG, nonce),
        extra={"seed_url": f"https://{HOST}", "host": HOST, "nonce": nonce, "org_id": ORG})


def _untagged_job(*, nonce="n1"):
    # UNtagged (tenant_id="") so _reconcile_tenant passes without sharding — isolates run_one's delivery handling
    # from the tenant boundary (the real gate's tenant bind is covered by the classification tests above).
    return SecurityJob.normalize(
        source="api", repo=HOST, engagement_slug=SLUG, tenant_id="", commit=nonce,
        delivery_id=launch_delivery_id(SLUG, nonce),
        extra={"seed_url": f"https://{HOST}", "host": HOST, "nonce": nonce})


# ------------------------------------------------------------------ gate classification (real lease) --
def test_gate_classifies_a_paused_lease_as_reversible(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    gate = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)
    assert gate(_job()).allowed is True                       # clean ⇒ allowed (default-OFF byte-identical)
    record_lease_pause(base, SLUG, "n1")
    out = gate(_job())
    assert out.allowed is False and out.denial_code == LEASE_PAUSED_DENIAL   # REVERSIBLE, not no_lease
    clear_lease_pause(base, SLUG, "n1")
    assert gate(_job()).allowed is True                       # resume ⇒ allowed again


def test_gate_terminal_refusal_stays_no_lease(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, settled=True)             # a SETTLED lease is TERMINAL, not reversible
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is False and out.denial_code == "no_lease"


# ------------------------------------------------------------------ run_one delivery handling ---------
def _runner(q, gate):
    return JobRunner(queue=q, gate=gate, worker=lambda j: {"ok": 1}, assert_tenant=lambda: None)


def test_run_one_releases_delivery_only_on_a_paused_refusal(tmp_path):
    q = SecurityJobQueue(str(tmp_path / "q"))
    assert q.enqueue(_untagged_job()).enqueued is True
    out = _runner(q, lambda j: GateOutcome(False, "paused", LEASE_PAUSED_DENIAL)).run_one()
    assert out.state == "refused" and out.denial_code == LEASE_PAUSED_DENIAL
    # delivery was RELEASED ⇒ the SAME delivery re-admits (the poller can re-produce the launch on resume)
    assert q.enqueue(_untagged_job()).enqueued is True


def test_run_one_keeps_delivery_on_a_terminal_refusal(tmp_path):
    q = SecurityJobQueue(str(tmp_path / "q"))
    assert q.enqueue(_untagged_job()).enqueued is True
    assert _runner(q, lambda j: GateOutcome(False, "nope", "no_lease")).run_one().state == "refused"
    # delivery KEPT (terminal) ⇒ a re-delivery coalesces as duplicate, exactly as before PR-4
    assert q.enqueue(_untagged_job()).enqueued is False


def test_full_redrive_enqueue_pause_refuse_resume_readmit(tmp_path):
    q = SecurityJobQueue(str(tmp_path / "q"))
    state = {"paused": True}
    ran: list = []

    def gate(j):
        return GateOutcome(False, "paused", LEASE_PAUSED_DENIAL) if state["paused"] else GateOutcome(True, "ok")

    r = JobRunner(queue=q, gate=gate, worker=lambda j: ran.append(j) or {"ok": 1}, assert_tenant=lambda: None)
    assert q.enqueue(_untagged_job()).enqueued is True
    assert r.run_one().denial_code == LEASE_PAUSED_DENIAL      # paused ⇒ refused + delivery released
    assert ran == []                                           # never ran while paused
    state["paused"] = False                                    # resume
    assert q.enqueue(_untagged_job()).enqueued is True         # re-admitted (delivery was released)
    assert r.run_one().state == "done"
    assert len(ran) == 1                                       # ran EXACTLY once, on resume — never stranded, never doubled
