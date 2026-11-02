"""K4-2 — the customer-launch trigger adapter (jobs.launch_trigger).

The sovereign plane publishes an owner-signed ``CreditLaunchLease`` to the seam; this adapter reads it and
PRODUCES one ``SecurityJob(source="api")`` per lease that passes the KEYLESS ``consume=False`` pre-check
(owner-PIN verify + bind + the K4-1 settlement re-check), WITHOUT burning the single-use ``issued_at`` floor
— the engine ARM is the ONE authoritative consume. A produced job grants NO bypass (the runner's
``authorize_job`` gate is the sole executor). These pin: one valid lease → one job keyed to the cust_
engagement slug; absent / expired / settled / forged → none; the pre-check does NOT burn the floor; the
delivery_id is content-addressed ``(slug, nonce)`` so re-polls coalesce in the durable queue.

Runs on the integration PYTHONPATH (framework + vigil_core + vigil_integration); the keyless verify imports
framework LAZILY, so this module would COLLECT but ERROR in the sovereign-only leg (same as the queue/runner
tests) — it belongs to the integration test leg.
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs.launch_trigger import (
    LaunchTrigger, launch_delivery_id, launch_jobs_from_seam,
)
from vigil_integration.live.credit_lease_broker import record_lease_settlement, write_credit_lease

SLUG = "cust_abc123"
HOST = "apme.cm"
ORG = "org_a"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, slug=SLUG, org=ORG, host=HOST, nonce="n1", issued=1000.0):
    t = datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=10,
                            not_before=t - timedelta(hours=1), not_after=t + timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _rig(monkeypatch, owner, signed, *, base=None):
    base = base or tempfile.mkdtemp()
    write_credit_lease(base, signed.document.engagement_slug, signed, _owner_root(owner))
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    return base


def test_one_valid_lease_produces_one_api_job_keyed_to_the_cust_slug(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    jobs = launch_jobs_from_seam(base, now=1000.0)
    assert len(jobs) == 1
    j = jobs[0]
    assert j.source == "api" and j.tenant_id == ORG and j.repo == HOST
    assert j.engagement_slug == SLUG and j.slug == SLUG       # the override drives the queue slug, not repo-derived
    assert j.delivery_id == launch_delivery_id(SLUG, "n1")    # content-addressed (slug, nonce)
    assert j.extra["seed_url"] == f"https://{HOST}" and j.extra["host"] == HOST
    assert j.extra["nonce"] == "n1" and j.extra["org_id"] == ORG


def test_absent_seam_produces_no_job(monkeypatch):
    owner = generate_keypair()
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    assert launch_jobs_from_seam(tempfile.mkdtemp(), now=1000.0) == []


def test_expired_lease_produces_no_job(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    assert launch_jobs_from_seam(base, now=9e12) == []        # now past not_after -> outside window


def test_settled_lease_produces_no_job(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce="n1"))
    assert len(launch_jobs_from_seam(base, now=1000.0)) == 1
    record_lease_settlement(base, SLUG, "n1")                 # K4-1: settle/cancel marks (slug, nonce)
    assert launch_jobs_from_seam(base, now=1000.0) == []      # the pre-check's settlement re-check refuses it


def test_forged_lease_produces_no_job(monkeypatch):
    owner = generate_keypair()
    attacker = generate_keypair()
    base = tempfile.mkdtemp()
    forged = sign_credit_launch_lease(_lease(owner).document, {"owner": attacker.private_key_b64})
    write_credit_lease(base, SLUG, forged, _owner_root(attacker))    # attacker co-lists only their own key
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))  # PIN owner
    assert launch_jobs_from_seam(base, now=1000.0) == []      # does not verify under the pinned owner key


def test_pre_check_does_not_burn_the_single_use_floor(monkeypatch):
    from framework.v2.launch_lease import verify_customer_launch_lease
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    launch_jobs_from_seam(base, now=1000.0)                   # pre-check (consume=False)
    launch_jobs_from_seam(base, now=1000.0)                   # ...twice
    # the ENGINE arm (consume=True) must still succeed exactly once — the poll did NOT burn the floor
    assert verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)[0]
    # ...and only NOW is a second arm the single-use replay refusal (the arm consumed it, not the poll)
    assert not verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=True)[0]


def test_trigger_poll_coalesces_in_the_durable_queue(monkeypatch, tmp_path):
    from vigil_integration.jobs.queue import SecurityJobQueue
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    trig = LaunchTrigger(base_dir=base, now=1000.0)
    jobs = trig.poll()
    assert len(jobs) == 1 and jobs[0].slug == SLUG
    q = SecurityJobQueue(str(tmp_path / "q"))
    r1 = q.enqueue(jobs[0])
    r2 = q.enqueue(trig.poll()[0])        # a re-poll yields the SAME delivery_id -> coalesces
    assert r1.enqueued is True
    assert r2.enqueued is False and r2.reason == "duplicate_delivery"
    assert q.pending_count() == 1         # one scheduler row, keyed to the cust_ engagement slug
    claimed = q.claim_next()
    assert claimed is not None and claimed.job.slug == SLUG and claimed.job.extra["host"] == HOST


def test_trigger_poll_is_total_on_a_flaky_seam():
    # a non-existent / unreadable base never crashes the drain — poll() returns [] (model.drain also guards)
    assert LaunchTrigger(base_dir="/nonexistent/\x00bad", now=1000.0).poll() == []
