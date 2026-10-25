"""repo-connect Slice 2 — the inbound webhook spool → SecurityJob queue drain.

Exercises the REAL SecurityJobQueue (so the delivery_id / fingerprint dedup and the enqueue-only contract
are genuinely tested, not mocked). Pins:
  * a valid inert envelope → ENQUEUED (one pending job), the file archived to processed/, and the job left
    PENDING (never executed — the drain is enqueue-only);
  * spool-level idempotency (identical bytes drained twice → deduped, enqueued once);
  * queue-level idempotency (a replayed delivery_id, different bytes → duplicate, still one pending job);
  * fail-closed quarantine on a missing delivery_id, a wrong/absent schema, and non-JSON;
  * a transient enqueue failure DEFERS the file back to incoming/ (never archived, never dropped).

Uses the real queue, so (like the Slice-1 jobs tests) it runs in the OFFENSE CI leg and skips in the
sovereign leg via importorskip.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.engagement_scheduler",
                    reason="the drain enqueues onto the real SecurityJobQueue; runs in the offense CI leg")

from vigil_integration.jobs.queue import SecurityJobQueue   # noqa: E402  (after importorskip)
from vigil_integration.webhook_drain import WebhookSpoolDrain  # noqa: E402


def _env(**kw) -> dict:
    e = {"schema": "vigil.webhook.github.v1", "delivery_id": "D1", "event": "pull_request",
         "repo": "github.com/acme/widget", "commit": "c0ffee", "pr_number": 7}
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
    return WebhookSpoolDrain(spool_dir=spool, queue=q), spool, q


def test_valid_envelope_is_enqueued_archived_and_left_pending(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _env(delivery_id="D-1"))
    out = drain.drain()
    assert out["enqueued"] == 1 and out["rejected"] == 0 and out["deferred"] == 0
    assert q.pending_count() == 1                          # enqueued, NOT executed (drain is enqueue-only)
    assert list((spool / "incoming").glob("*.json")) == []  # claimed out of incoming/
    assert len(list((spool / "processed").glob("*.json"))) == 1  # archived to the dedup ledger
    # the job really is the one we spooled, and it is still claimable (pending)
    claimed = q.claim_next()
    assert claimed is not None and claimed.job.repo == "github.com/acme/widget" and claimed.job.pr_number == 7


def test_identical_bytes_dedup_at_the_spool(tmp_path):
    drain, spool, q = _drain(tmp_path)
    env = _env(delivery_id="D-2")
    _spool_file(spool, env)
    assert drain.drain()["enqueued"] == 1
    _spool_file(spool, env)                                # identical bytes again
    out = drain.drain()
    assert out["enqueued"] == 0 and out["deduped"] == 1
    assert q.pending_count() == 1                          # enqueued exactly once


def test_replayed_delivery_id_is_coalesced_by_the_queue(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _env(delivery_id="D-3", commit="aaa"))
    assert drain.drain()["enqueued"] == 1
    # a DIFFERENT file (different commit → different bytes → passes the spool sha256 check) but the SAME
    # delivery_id must be coalesced by the queue's permanent delivery seen-set, not re-enqueued.
    _spool_file(spool, _env(delivery_id="D-3", commit="bbb"))
    out = drain.drain()
    assert out["enqueued"] == 0 and out["duplicate"] == 1 and out["deduped"] == 0
    assert q.pending_count() == 1


def test_missing_delivery_id_is_quarantined_fail_closed(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _env(delivery_id=""))               # webhook source REQUIRES a delivery_id
    out = drain.drain()
    assert out["rejected"] == 1 and out["enqueued"] == 0 and q.pending_count() == 0
    rej = list((spool / "rejected").glob("*.json"))
    assert len(rej) == 1 and (spool / "rejected" / (rej[0].name + ".reason")).is_file()


def test_wrong_schema_and_non_json_are_quarantined(tmp_path):
    drain, spool, q = _drain(tmp_path)
    _spool_file(spool, _env(delivery_id="D-4", schema="something.else"))
    (spool / "incoming" / "garbage.json").write_text("{not json", encoding="utf-8")
    out = drain.drain()
    assert out["rejected"] == 2 and out["enqueued"] == 0 and q.pending_count() == 0


def test_deeply_nested_json_is_quarantined_not_a_crash(tmp_path):
    # a pathologically nested JSON (RecursionError in the C scanner, or a non-dict on success) must be
    # QUARANTINED, never crash the drain loop (fail-closed on any hostile body).
    drain, spool, q = _drain(tmp_path)
    (spool / "incoming").mkdir(parents=True, exist_ok=True)
    (spool / "incoming" / "nested.json").write_text("[" * 20000 + "]" * 20000, encoding="utf-8")
    out = drain.drain()
    assert out["rejected"] == 1 and out["enqueued"] == 0 and q.pending_count() == 0
    assert len(list((spool / "rejected").glob("*.json"))) == 1


def test_non_finite_pr_number_envelope_is_quarantined(tmp_path):
    # a hostile on-disk envelope with a non-finite pr_number (int(inf) → OverflowError in normalize) must
    # quarantine, not crash the loop.
    drain, spool, q = _drain(tmp_path)
    (spool / "incoming").mkdir(parents=True, exist_ok=True)
    (spool / "incoming" / "inf.json").write_text(
        '{"schema":"vigil.webhook.github.v1","delivery_id":"D-of","event":"pull_request",'
        '"repo":"github.com/a/b","commit":"c","pr_number":Infinity}', encoding="utf-8")
    out = drain.drain()
    assert out["rejected"] == 1 and out["enqueued"] == 0 and q.pending_count() == 0


def test_working_sweep_recovers_a_stranded_file(tmp_path):
    # simulate a crash mid-process: a valid envelope stranded in working/. The next drain re-claims it
    # (working/ → incoming/) and enqueues it — never lost.
    drain, spool, q = _drain(tmp_path)
    (spool / "working").mkdir(parents=True, exist_ok=True)
    data = json.dumps(_env(delivery_id="D-strand"), sort_keys=True).encode()
    (spool / "working" / (hashlib.sha256(data).hexdigest()[:32] + ".json")).write_bytes(data)
    out = drain.drain()
    assert out["enqueued"] == 1 and q.pending_count() == 1
    assert list((spool / "working").glob("*.json")) == []       # swept out of working/


def test_transient_enqueue_failure_defers_the_file(tmp_path):
    class _BoomQueue:
        def enqueue(self, job):
            raise OSError("durable insert failed")
    spool = tmp_path / "spool"
    drain = WebhookSpoolDrain(spool_dir=spool, queue=_BoomQueue())
    src = _spool_file(spool, _env(delivery_id="D-5"))
    out = drain.drain()
    assert out["deferred"] == 1 and out["enqueued"] == 0
    # the file is back in incoming/ (deferred to retry), NOT archived to processed/ and NOT quarantined
    assert src.exists() and list((spool / "processed").glob("*.json")) == []
    assert list((spool / "rejected").glob("*")) == []
