"""K4-5c — the customer-launch seam poller (vigil_integration.launch_drain.LaunchSeamDrain).

The sovereign plane publishes an owner-signed ``CreditLaunchLease`` to the seam; this poller — the sibling of
``webhook_drain`` — reads it through the K4-2 ``LaunchTrigger`` (keyless ``consume=False`` pre-check: owner-pin
+ bind + K4-1 settlement re-check, floor NOT burned) and ENQUEUES one ``SecurityJob(source="api")`` per
currently-valid lease onto the durable idempotent queue. It is ENQUEUE-ONLY — execution stays SOLELY behind
the authorized runner + the K4-3 customer-launch gate. These pin the money/idempotency invariants at the
DRAIN layer:
  * one published valid lease → exactly one enqueued job keyed to the cust_ engagement slug;
  * a re-drain of the SAME published lease COALESCES on the queue's permanent content-addressed delivery_id
    (``duplicate``, never a second queued row) — exactly-once across the poll loop;
  * once a run SETTLES (K4-1 marks ``(slug, nonce)`` + tombstones), the lease drains to NOTHING;
  * a genuine RE-LEASE (new nonce) re-enqueues even while the earlier launch is in flight (never dropped);
  * ENQUEUE-ONLY — the drain NEVER runs a job (a spy queue sees only ``enqueue``);
  * a transient enqueue ``OSError`` is DEFERRED and the next drain retries off the UNTOUCHED seam (no loss,
    no double).

Runs on the integration PYTHONPATH (framework + vigil_core + vigil_integration); the keyless verify imports
framework LAZILY, so this belongs to the integration test leg (same as ``test_launch_trigger``).
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs.launch_trigger import launch_delivery_id
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.launch_drain import LaunchSeamDrain
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


def _drain(base, q, *, now=1000.0):
    return LaunchSeamDrain(base_dir=base, queue=q, now=now)


def test_one_published_lease_enqueues_one_job_keyed_to_the_cust_slug(monkeypatch, tmp_path):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    q = SecurityJobQueue(str(tmp_path / "q"))
    out = _drain(base, q).drain()
    assert out == {"enqueued": 1, "duplicate": 0, "deferred": 0}, out
    assert q.pending_count() == 1
    claimed = q.claim_next()
    assert claimed is not None and claimed.job.slug == SLUG          # the owner-signed cust_ slug drives the queue
    assert claimed.job.source == "api" and claimed.job.extra["host"] == HOST
    assert claimed.job.delivery_id == launch_delivery_id(SLUG, "n1")  # content-addressed (slug, nonce)


def test_re_drain_of_the_same_lease_coalesces_no_double_enqueue(monkeypatch, tmp_path):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    q = SecurityJobQueue(str(tmp_path / "q"))
    drain = _drain(base, q)
    assert drain.drain() == {"enqueued": 1, "duplicate": 0, "deferred": 0}
    # the SAME published lease re-polled yields the SAME delivery_id → coalesced in the queue's permanent seen-set
    assert drain.drain() == {"enqueued": 0, "duplicate": 1, "deferred": 0}
    assert q.pending_count() == 1                                    # still exactly one queued row (no double launch)


def test_settled_lease_drains_to_nothing(monkeypatch, tmp_path):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce="n1"))
    q = SecurityJobQueue(str(tmp_path / "q"))
    drain = _drain(base, q)
    assert drain.drain()["enqueued"] == 1
    record_lease_settlement(base, SLUG, "n1")                        # K4-1: a settled/canceled run marks (slug, nonce)
    out = drain.drain()
    assert out == {"enqueued": 0, "duplicate": 0, "deferred": 0}, out  # the consume=False settlement re-check refuses it


def test_a_genuine_re_lease_re_enqueues_while_the_earlier_launch_is_in_flight(monkeypatch, tmp_path):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner, nonce="n1"))
    q = SecurityJobQueue(str(tmp_path / "q"))
    assert _drain(base, q).drain()["enqueued"] == 1                  # launch n1 in flight
    write_credit_lease(base, SLUG, _lease(owner, nonce="n2", issued=2000.0), _owner_root(owner))  # genuine re-lease
    out = LaunchSeamDrain(base_dir=base, queue=q, now=2000.0).drain()
    assert out == {"enqueued": 1, "duplicate": 0, "deferred": 0}, out  # distinct (slug, nonce) delivery_id + fingerprint
    assert q.pending_count() == 2                                    # both separately-paid launches queued


def test_drain_is_enqueue_only_never_executes(monkeypatch, tmp_path):
    # The drain must only ENQUEUE — never claim/run a job. A spy queue records every method the drain calls.
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))

    class _SpyQueue:
        def __init__(self):
            self.calls = []

        def enqueue(self, job):
            self.calls.append(("enqueue", job.slug))
            from vigil_integration.jobs.queue import EnqueueResult
            return EnqueueResult(enqueued=True, reason="enqueued", job_id="j", seq=1)

    spy = _SpyQueue()
    assert _drain(base, spy).drain() == {"enqueued": 1, "duplicate": 0, "deferred": 0}
    assert spy.calls == [("enqueue", SLUG)]                          # ONLY enqueue — no claim/run/complete


def test_transient_enqueue_oserror_is_deferred_then_retries_off_the_untouched_seam(monkeypatch, tmp_path):
    # A transient durable-insert OSError must DEFER (not drop, not loop): the lease is untouched on the seam,
    # so the NEXT drain re-polls it and enqueues cleanly. (enqueue rolls back its own markers — no un-claim.)
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, _lease(owner))
    q = SecurityJobQueue(str(tmp_path / "q"))
    drain = _drain(base, q)

    real_enqueue = q.enqueue
    calls = {"n": 0}

    def _flaky(job):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("transient durable-insert failure")
        return real_enqueue(job)

    monkeypatch.setattr(q, "enqueue", _flaky)
    assert drain.drain() == {"enqueued": 0, "duplicate": 0, "deferred": 1}  # first enqueue failed → deferred
    assert q.pending_count() == 0                                           # nothing queued, nothing lost
    assert drain.drain() == {"enqueued": 1, "duplicate": 0, "deferred": 0}  # retry off the untouched seam succeeds
    assert q.pending_count() == 1


def test_absent_or_flaky_seam_drains_to_zero(monkeypatch, tmp_path):
    owner = generate_keypair()
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    q = SecurityJobQueue(str(tmp_path / "q"))
    assert _drain(tempfile.mkdtemp(), q).drain() == {"enqueued": 0, "duplicate": 0, "deferred": 0}  # empty seam
    q2 = SecurityJobQueue(str(tmp_path / "q2"))
    assert LaunchSeamDrain(base_dir="/nonexistent/\x00bad", queue=q2, now=1000.0).drain() == {
        "enqueued": 0, "duplicate": 0, "deferred": 0}               # poll() is total — a flaky seam never crashes


def test_constructor_requires_a_queue_or_queue_root():
    with pytest.raises(ValueError):
        LaunchSeamDrain(base_dir=tempfile.mkdtemp())                 # neither queue nor queue_root → fail-closed
