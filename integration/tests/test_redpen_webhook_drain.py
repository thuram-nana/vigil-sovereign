"""R3 — the Red-Pen inbound-webhook spool → Red-Pen SecurityJob queue drain.

Exercises the REAL SecurityJobQueue (so the delivery_id / fingerprint dedup and the enqueue-only contract are
genuinely tested). Pins:
  * a REVIEWABLE PR delivery (opened/synchronize/reopened) → ENQUEUED as a ``profile="redpen"`` job whose commit
    is the PR HEAD sha; the file archived; the job left PENDING (the drain never executes);
  * idempotency: identical bytes deduped at the spool; the same (repo,pr,commit) coalesced at the queue;
  * a NON-reviewable PR action (closed/labeled) and an installation connect/disconnect SYNC signal are
    ACKNOWLEDGED (archived), NEVER enqueued (a connect is owner-signed sovereign-side);
  * fail-closed quarantine on a missing delivery id, a wrong schema, non-JSON.

Uses the real queue, so (like ``test_webhook_drain.py``) it runs in the OFFENSE CI leg and skips in the sovereign
leg via importorskip.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.engagement_scheduler",
                    reason="the drain enqueues onto the real SecurityJobQueue; runs in the offense CI leg")

from vigil_integration.jobs.queue import SecurityJobQueue  # noqa: E402  (after importorskip)
from vigil_integration.redpen_webhook_drain import RedpenWebhookDrain  # noqa: E402

_SCHEMA = "vigil.webhook.github.redpen.v1"


def _pr_env(**kw) -> dict:
    e = {"schema": _SCHEMA, "delivery_id": "D1", "event": "pull_request", "action": "opened", "kind": "pr",
         "repo": "github.com/acme/widget", "commit": "c0ffee1234", "pr_number": 7}
    e.update(kw)
    return e


def _install_env(**kw) -> dict:
    e = {"schema": _SCHEMA, "delivery_id": "I1", "event": "installation", "action": "created",
         "kind": "installation", "installation_id": 42, "repos": ["github.com/acme/widget"]}
    e.update(kw)
    return e


def _spool_file(spool: Path, envelope: dict) -> Path:
    incoming = spool / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    p = incoming / (hashlib.sha256(data).hexdigest()[:32] + ".json")
    p.write_bytes(data)
    return p


def _drain(tmp_path: Path):
    spool = tmp_path / "spool"
    q = SecurityJobQueue(tmp_path / "queue")
    return RedpenWebhookDrain(spool_dir=spool, queue=q), spool, q


def test_a_reviewable_pr_is_enqueued_as_a_redpen_job_at_the_head_sha(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="D-1"))
    out = drain.drain()
    assert out["enqueued"] == 1 and out["rejected"] == 0 and out["acknowledged"] == 0
    assert q.pending_count() == 1
    claimed = q.claim_next()
    assert claimed is not None and claimed.job.repo == "github.com/acme/widget"
    assert claimed.job.pr_number == 7 and claimed.job.commit == "c0ffee1234"   # the check attaches at the head sha
    assert claimed.job.profile == "redpen" and claimed.job.source == "webhook"


def test_synchronize_and_reopened_also_review(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="s1", action="synchronize", commit="aaa1111", pr_number=5))
    _spool_file(spool, _pr_env(delivery_id="r1", action="reopened", commit="bbb2222", pr_number=6))
    out = drain.drain()
    assert out["enqueued"] == 2 and q.pending_count() == 2


def test_a_non_reviewable_pr_action_is_acknowledged_not_enqueued(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="c1", action="closed"))
    _spool_file(spool, _pr_env(delivery_id="l1", action="labeled", commit="dd33", pr_number=8))
    out = drain.drain()
    assert out["enqueued"] == 0 and out["acknowledged"] == 2 and q.pending_count() == 0   # nothing to review
    assert list((spool / "incoming").glob("*.json")) == []                                 # archived, not left


def test_an_installation_sync_is_acknowledged_never_enqueued(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _install_env(delivery_id="i-created", action="created"))
    _spool_file(spool, _install_env(delivery_id="i-deleted", action="deleted",
                                    event="installation_repositories"))
    out = drain.drain()
    # a CONNECT is owner-signed sovereign-side — the keyless offense drain never mints a review from it
    assert out["enqueued"] == 0 and out["acknowledged"] == 2 and q.pending_count() == 0


def test_only_a_pr_kind_envelope_ever_becomes_a_review_job(tmp_path):
    # the spool is untrusted at rest: an envelope tagged kind="installation" but shaped like a reviewable PR (repo,
    # pr, commit, an "opened" action) must still never be enqueued — only kind="pr" ever becomes a review job.
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="hostile", kind="installation"))
    out = drain.drain()
    assert out["enqueued"] == 0 and out["acknowledged"] == 1 and q.pending_count() == 0


def test_identical_bytes_dedup_at_the_spool(tmp_path):
    drain, spool, q = _drain(tmp_path)
    env = _pr_env(delivery_id="D-2")
    _spool_file(spool, env)
    assert drain.drain()["enqueued"] == 1
    _spool_file(spool, env)                                 # identical bytes again
    out = drain.drain()
    assert out["enqueued"] == 0 and out["deduped"] == 1 and q.pending_count() == 1


def test_same_work_coalesces_regardless_of_delivery_guid(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="GUID-1", commit="aaa", pr_number=5))
    assert drain.drain()["enqueued"] == 1
    _spool_file(spool, _pr_env(delivery_id="GUID-2", commit="aaa", pr_number=5))   # same work, new GUID
    out = drain.drain()
    assert out["enqueued"] == 0 and out["duplicate"] == 1 and q.pending_count() == 1


def test_a_redelivery_never_reruns_or_recharges_a_review_that_already_completed(tmp_path):
    # GitHub redelivers a webhook (timeout / manual "Redeliver") under a NEW GUID. Once the review of that exact
    # (repo, pr, commit) has COMPLETED, the queue's in-flight fingerprint is free again — only the permanent,
    # content-addressed work key stops a second review (and a second charge) of the same commit.
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="GUID-1", commit="aaa", pr_number=5))
    assert drain.drain()["enqueued"] == 1
    q.complete(q.claim_next())                                       # the review ran and finished
    _spool_file(spool, _pr_env(delivery_id="GUID-2", commit="aaa", pr_number=5))   # the redelivery
    out = drain.drain()
    assert out["enqueued"] == 0 and out["duplicate"] == 1 and q.pending_count() == 0


def test_a_new_head_commit_is_a_new_review(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="g1", commit="aaa", pr_number=5))
    assert drain.drain()["enqueued"] == 1
    _spool_file(spool, _pr_env(delivery_id="g2", commit="bbb", pr_number=5))        # same PR, new head
    assert drain.drain()["enqueued"] == 1 and q.pending_count() == 2


def test_missing_delivery_id_is_quarantined(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id=""))
    out = drain.drain()
    assert out["rejected"] == 1 and out["enqueued"] == 0 and q.pending_count() == 0


def test_wrong_schema_and_non_json_are_quarantined(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _pr_env(delivery_id="D-4", schema="vigil.webhook.github.v1"))   # the repo-connect schema
    (spool / "incoming" / "garbage.json").write_text("{not json", encoding="utf-8")
    out = drain.drain()
    assert out["rejected"] == 2 and out["enqueued"] == 0 and q.pending_count() == 0
