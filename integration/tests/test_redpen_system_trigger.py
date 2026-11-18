"""Red-Pen R4 — the System-review trigger + enqueue drain (``jobs/redpen_system_trigger.py``) and ``vigil
redpen-schedule``.

Pinned: a ticket becomes exactly ONE ``SecurityJob(source="scheduled", profile="full")`` keyed to the ticket's
owner-signed ``cust_`` slug, carrying the lease for the gate; the drain is ENQUEUE-ONLY and idempotent by the
content-addressed (slug, nonce) delivery id (a re-poll coalesces through the queue's REAL delivery markers, a new
period re-enqueues); a ticket whose lease window has closed, or whose labels disagree with its signed lease, yields
no job; a transient enqueue failure is deferred, never lost; and the ``vigil`` verb is default-OFF. Framework-free:
the queue's durable FIFO is faked, its exactly-once markers are real.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs import redpen_system_trigger as rst
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.live.redpen_system_seam import tickets_root, write_system_ticket

OWNER = generate_keypair()
SLUG, ORG, REPO = "cust_" + "b" * 24, "org_a", "github.com/acme/widgets"
T0 = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
INSIDE = T0.timestamp() + 60                       # inside the 8 h lease window
AFTER = (T0 + timedelta(hours=8)).timestamp()      # the window has closed


def _ticket(base, nonce="sch-2026-W47", *, org=ORG, repo=REPO, label_org=None, label_repo=None):
    doc = CreditLaunchLease(engagement_slug=SLUG, org_id=org, scope_host=repo, units_reserved=5,
                            not_before=T0, not_after=T0 + timedelta(hours=8), nonce=nonce,
                            issued_at=T0.timestamp())
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                             public_key_b64=OWNER.public_key_b64)])
    signed = sign_credit_launch_lease(doc, {"owner": OWNER.private_key_b64})
    write_system_ticket(base, SLUG, org_id=label_org or org, repo=label_repo or repo, signed_lease=signed,
                        trust_root=root)
    return signed


class _FakeScheduler:
    def __init__(self):
        self.rows: list = []

    def enqueue(self, slug, *, params):
        self.rows.append((slug, params))
        return SimpleNamespace(job_id=f"j{len(self.rows)}", seq=len(self.rows))


def _queue(tmp_path, sched):
    return SecurityJobQueue(tmp_path / "queue", scheduler=sched)


# ---- the trigger --------------------------------------------------------------------------------------------
def test_a_ticket_becomes_one_full_profile_scheduled_job(tmp_path):
    signed = _ticket(tmp_path)
    (job,) = rst.system_jobs_from_seam(tmp_path, now=INSIDE)
    assert job.source == "scheduled" and job.profile == "full"
    assert job.slug == SLUG and job.engagement_slug == SLUG             # the owner-signed engagement, verbatim
    assert job.repo == REPO and job.tenant_id == ORG and job.commit == "sch-2026-W47"
    assert job.delivery_id == rst.system_delivery_id(SLUG, "sch-2026-W47")
    assert job.extra["lease"] == signed.model_dump(mode="json")         # the gate verifies THIS, owner-pinned
    assert job.extra["profile"] == "full" and job.extra["trust_root"]["authorizers"][0]["key_id"] == "owner"


def test_a_ticket_whose_lease_window_has_closed_yields_no_job(tmp_path):
    _ticket(tmp_path)
    assert rst.system_jobs_from_seam(tmp_path, now=AFTER) == []
    assert rst.RedPenSystemTrigger(tmp_path, now=AFTER).poll() == []


@pytest.mark.parametrize("label", [{"label_org": "org_evil"}, {"label_repo": "github.com/evil/repo"}])
def test_a_ticket_whose_labels_disagree_with_its_signed_lease_yields_no_job(tmp_path, label):
    _ticket(tmp_path, **label)
    assert rst.system_jobs_from_seam(tmp_path, now=INSIDE) == []


def test_a_malformed_ticket_is_skipped_and_never_sinks_the_others(tmp_path):
    _ticket(tmp_path)
    (tickets_root(tmp_path) / "zzz.json").write_text("{broken", encoding="utf-8")
    assert len(rst.system_jobs_from_seam(tmp_path, now=INSIDE)) == 1


def test_the_job_fingerprint_is_per_period(tmp_path):
    _ticket(tmp_path, "sch-2026-W47")
    (a,) = rst.system_jobs_from_seam(tmp_path, now=INSIDE)
    _ticket(tmp_path, "sch-2026-W48")
    (b,) = rst.system_jobs_from_seam(tmp_path, now=INSIDE)
    assert a.fingerprint != b.fingerprint and a.delivery_id != b.delivery_id and a.slug == b.slug


# ---- the drain (enqueue-only, idempotent) -------------------------------------------------------------------
def test_the_drain_enqueues_a_ticket_once_and_coalesces_every_repoll(tmp_path):
    _ticket(tmp_path)
    sched = _FakeScheduler()
    drain = rst.RedPenSystemDrain(base_dir=tmp_path, queue=_queue(tmp_path, sched), now=INSIDE)
    assert drain.drain() == {"enqueued": 1, "duplicate": 0, "deferred": 0}
    assert drain.drain() == {"enqueued": 0, "duplicate": 1, "deferred": 0}
    again = rst.RedPenSystemDrain(base_dir=tmp_path, queue=_queue(tmp_path, sched), now=INSIDE)   # a new process
    assert again.drain()["enqueued"] == 0 and len(sched.rows) == 1
    slug, params = sched.rows[0]
    assert slug == SLUG and params["profile"] == "full" and params["source"] == "scheduled"


def test_a_new_periods_ticket_re_enqueues(tmp_path):
    sched = _FakeScheduler()
    _ticket(tmp_path, "sch-2026-W47")
    rst.RedPenSystemDrain(base_dir=tmp_path, queue=_queue(tmp_path, sched), now=INSIDE).drain()
    _ticket(tmp_path, "sch-2026-W48")
    out = rst.RedPenSystemDrain(base_dir=tmp_path, queue=_queue(tmp_path, sched), now=INSIDE).drain()
    assert out["enqueued"] == 1 and [p["commit"] for _s, p in sched.rows] == ["sch-2026-W47", "sch-2026-W48"]


def test_a_transient_enqueue_failure_is_deferred_and_retried_off_the_untouched_seam(tmp_path):
    _ticket(tmp_path)

    class _Flaky:
        def __init__(self):
            self.calls = 0

        def enqueue(self, job):
            self.calls += 1
            if self.calls == 1:
                raise OSError("disk hiccup")
            return SimpleNamespace(enqueued=True, reason="enqueued")
    q = _Flaky()
    drain = rst.RedPenSystemDrain(base_dir=tmp_path, queue=q, now=INSIDE)
    assert drain.drain() == {"enqueued": 0, "duplicate": 0, "deferred": 1}
    assert drain.drain() == {"enqueued": 1, "duplicate": 0, "deferred": 0}


def test_the_drain_only_enqueues_it_never_claims_or_runs_a_job(tmp_path):
    _ticket(tmp_path)
    calls: list = []

    class _Spy:
        def enqueue(self, job):
            calls.append(("enqueue", job.profile))
            return SimpleNamespace(enqueued=True)

        def __getattr__(self, name):              # claim_next / try_lease / complete / ... would land here
            calls.append((name,))
            raise AssertionError(f"the drain touched {name}")
    rst.RedPenSystemDrain(base_dir=tmp_path, queue=_Spy(), now=INSIDE).drain()
    assert calls == [("enqueue", "full")]


def test_the_drain_needs_a_queue_or_a_queue_root():
    with pytest.raises(ValueError, match="queue"):
        rst.RedPenSystemDrain(base_dir="/x")


def test_watch_survives_a_failing_drain(tmp_path, capsys):
    class _Boom:
        def enqueue(self, job):
            raise RuntimeError("queue down")
    _ticket(tmp_path)
    ticks: list = []

    def _sleep(_s):
        ticks.append(1)
        if len(ticks) == 2:
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        rst.RedPenSystemDrain(base_dir=tmp_path, queue=_Boom(), now=INSIDE).watch(interval=0, sleep=_sleep)
    assert capsys.readouterr().err.count("WARNING drain error") == 2


# ---- `vigil redpen-schedule` --------------------------------------------------------------------------------
def _args(base, queue_root=""):
    return argparse.Namespace(base_dir=str(base), queue_root=queue_root, watch=False, interval=2.0)


def test_vigil_redpen_schedule_refuses_when_red_pen_is_off(tmp_path, monkeypatch, capsys):
    from vigil_integration import cli
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    built: list = []
    monkeypatch.setattr(rst, "RedPenSystemDrain", lambda **kw: built.append(kw))
    assert cli._cmd_redpen_schedule(_args(tmp_path)) == 2
    assert "Red-Pen is off" in capsys.readouterr().err and built == []          # no queue, no drain


def test_vigil_redpen_schedule_drains_into_the_backup_covered_queue_by_default(tmp_path, monkeypatch, capsys):
    from vigil_integration import cli
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    seen: dict = {}

    class _Drain:
        def __init__(self, **kw):
            seen.update(kw)

        def drain(self):
            return {"enqueued": 1, "duplicate": 0, "deferred": 0}
    monkeypatch.setattr(rst, "RedPenSystemDrain", _Drain)
    assert cli._cmd_redpen_schedule(_args(tmp_path)) == 0
    assert seen == {"base_dir": str(tmp_path), "queue_root": str(tmp_path / "jobs")}
    assert '"enqueued": 1' in capsys.readouterr().out


def test_the_verb_is_wired_into_the_vigil_parser():
    from vigil_integration import cli
    ns = cli.build_parser().parse_args(["redpen-schedule", "--base-dir", "/seam"])
    assert ns.func is cli._cmd_redpen_schedule and ns.base_dir == "/seam" and ns.queue_root == ""
