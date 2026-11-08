"""#75 — the offense backup CONTRACT now covers the durable SecurityJob queue + scheduler state.

The money-critical gap this closes: the paid customer-launch path RESERVES credits + mints an owner-signed
launch lease, then ENQUEUES a ``SecurityJob`` into a ``SecurityJobQueue``. Before #75 that queue was rooted at
an operator-chosen ``--queue-root`` OUTSIDE ``base_dir`` by construction, so ``create_offense_backup`` (which
captures the ``base_dir`` subtree) never saw it — a host loss STRANDED in-flight paid jobs (credits reserved,
lease signed, but the job to run them gone). #75 defaults the persisted queue UNDER ``base_dir``
(``<base_dir>/jobs`` — ``cli._default_queue_root``) so backup captures it, while keeping the capture bounded:
the completed-job AUDIT trail (``jobs/done/``) is deliberately NOT captured (unbounded, not needed to re-drive).

THE acceptance test (real, not fixture-theatre): seed a ``base_dir`` with a ``SecurityJobQueue`` at the #75
default root; leave one job PENDING, one STRANDED in ``running/`` under a DEAD claimer, and one COMPLETED in the
``done/`` audit trail; back it up; restore into a FRESH empty base; then prove against a ``SecurityJobQueue`` on
the restored tree that (a) the pending job survived, (b) the stranded job re-drives via ``requeue_stale()``,
(c) the ``delivery/`` exactly-once seen-set survived (a re-enqueue of the same ``delivery_id`` coalesces), and
(d) the ``done/`` audit trail was NOT captured.

Needs framework (the queue drives ``EngagementScheduler``/``SlugLease`` via LAZY imports) → runs in the offense
/ integration leg:
    PYTHONPATH="apps/sigil:integration:engine/crucible:gateway:packages/core/vigil_core:." \
        .venv-sovereign/bin/python -m pytest integration/tests/test_backup_covers_job_queue.py -q
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# The persisted queue drives the offense engine (EngagementScheduler/SlugLease) via LAZY imports, so this
# executes in the offense/integration CI leg (framework importable); skip cleanly in the sovereign-only leg.
pytest.importorskip("framework.v2.engagement_scheduler",
                    reason="the SecurityJob queue drives the offense scheduler; runs in the offense leg")

from vigil_core.vault import Vault
from vigil_integration.agent.state import AgentState, Finding, Phase
from vigil_integration.attestation.identity import load_or_create_operator_keypair
from vigil_integration.backup import create_offense_backup, restore_offense_backup
from vigil_integration.cli import _default_queue_root, _resolve_queue_root
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.live.governance_identity import (
    DEFAULT_GOVERNANCE_KEY_FILE,
    load_or_create_governance_keypair,
)
from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
from vigil_integration.live.spine_vigilcore import VigilCoreSpine

PW = "correct horse battery staple offense #75"
SLUG = "loopback"


def _seed_offense_home(base: Path) -> None:
    """A base_dir with the three persisted identity keys and a signed {slug}.spine, signed by the SAME
    offense-spine key that is persisted (so the post-restore integrity re-verify recovers a matching pubkey).
    Mirrors ``test_backup_roundtrip._seed_offense_home`` — ``create_offense_backup`` refuses a spine-free base."""
    vault = Vault(base / "vault")                       # unprovisioned → plaintext 0600 keys (no TPM in CI)
    spine_kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=vault)
    load_or_create_governance_keypair(path=str(base / DEFAULT_GOVERNANCE_KEY_FILE), vault=vault)
    load_or_create_operator_keypair(path=str(base / "operator.key"), vault=vault)
    spine = VigilCoreSpine(spine_kp, str(base / f"{SLUG}.spine"))
    for i in range(3):
        st = AgentState(engagement_slug=SLUG, phase=Phase.EXPLOITATION, iteration=i, objective="own the box")
        st.record_fact(Finding(ref=f"f-{i}", bug_class="sqli", title="auth bypass", severity="critical"),
                       evidence_ref=f"cert:evi-{i}")
        spine.write_state(st, seq=i, engagement=SLUG)


def _job(**kw) -> SecurityJob:
    """A SecurityJob on the paid ``api`` (customer-launch) path. Distinct commit ⇒ distinct work fingerprint;
    distinct delivery_id ⇒ distinct exactly-once key, so three jobs coexist without coalescing."""
    base = dict(source="api", repo="github.com/acme/widget", commit="c0ffee", delivery_id="d")
    base.update(kw)
    return SecurityJob.normalize(**base)


def _write_dead_claimer(running_file: Path) -> None:
    """Overwrite a ``running/<seq>.json`` claimer stamp so ``requeue_stale`` sees a CRASHED worker — the same
    idiom as ``test_engagement_scheduler`` (a bogus boot_id so a readable /proc boot_id mismatches it, plus an
    unused high pid as the no-boot_id fallback)."""
    doc = json.loads(running_file.read_text(encoding="utf-8"))
    doc["_claimer"] = {"pid": 2_147_483_600, "boot_id": "offense-75-dead-boot", "ts": 0}
    running_file.write_text(json.dumps(doc), encoding="utf-8")


def test_default_queue_root_is_under_base_dir_and_override_wins(tmp_path):
    """Focused unit test for the #75 default resolver: an EMPTY --queue-root falls back to the backup-covered
    ``<base_dir>/jobs``; an explicit --queue-root (operator override, incl. CI's ephemeral .vigil-queue) wins."""
    base = tmp_path / "live"
    assert _default_queue_root(str(base)) == os.path.join(str(base), "jobs")
    # empty / whitespace-only → the in-tree, backup-covered default
    assert _resolve_queue_root("", str(base)) == os.path.join(str(base), "jobs")
    assert _resolve_queue_root("   ", str(base)) == os.path.join(str(base), "jobs")
    # an explicit override ALWAYS wins, byte-for-byte (no behavior change when one is passed)
    assert _resolve_queue_root("/srv/ephemeral/.vigil-queue", str(base)) == "/srv/ephemeral/.vigil-queue"
    assert _resolve_queue_root(".vigil-queue", str(base)) == ".vigil-queue"


def test_backup_captures_live_job_queue_and_skips_done_audit_trail(tmp_path):
    base = tmp_path / "src-base"
    _seed_offense_home(base)

    # Seed the queue AT the #75 default root, located THROUGH the helper under test. That coupling is the point:
    # revert _default_queue_root to return a path OUTSIDE base_dir and the queue is no longer captured by
    # create_offense_backup → it restores as an EMPTY queue (pending_count 0) — the mutation-verify red.
    qroot = Path(_default_queue_root(str(base)))
    q = SecurityJobQueue(qroot)

    # job C: enqueue → claim → complete  ⇒ lands in jobs/done/ (the audit trail that must NOT be captured).
    assert q.enqueue(_job(delivery_id="dC", commit="cccc")).enqueued is True
    claimed_c = q.claim_next()
    assert claimed_c is not None
    q.complete(claimed_c)
    assert len(list((qroot / "done").glob("*.json"))) == 1, "setup: job C must be in the done/ audit trail"

    # job B: enqueue → claim → STRAND in running/ under a DEAD claimer (requeue_stale must reclaim it).
    assert q.enqueue(_job(delivery_id="dB", commit="bbbb")).enqueued is True
    claimed_b = q.claim_next()
    assert claimed_b is not None
    running_files = list((qroot / "running").glob("*.json"))
    assert len(running_files) == 1, "setup: job B must be the sole running job"
    _write_dead_claimer(running_files[0])

    # job A: enqueue only ⇒ stays PENDING in jobs/queue/.
    assert q.enqueue(_job(delivery_id="dA", commit="aaaa")).enqueued is True

    # back up the whole base_dir (captures <base_dir>/jobs minus done/), then restore into a FRESH empty base.
    dest = tmp_path / "offense.vglbk"
    summary = create_offense_backup(dest, PW, base_dir=str(base))
    assert summary["secrets"] == 3                       # the three re-wrapped identity keys

    new_base = tmp_path / "restored-base"
    res = restore_offense_backup(dest, str(new_base), PW)
    assert res["verified"] is True

    new_qroot = Path(_default_queue_root(str(new_base)))

    # (d) the completed-job AUDIT trail (jobs/done/) was NOT captured — assert BEFORE building the queue, which
    # would recreate an empty done/. Revert the backup done/-skip and C's done file reappears here → REDS.
    restored_done = new_qroot / "done"
    assert not restored_done.exists() or not list(restored_done.glob("*.json")), \
        "jobs/done/ (the completed-job audit trail) must NOT be captured by the backup"

    # Build a fresh queue on the RESTORED tree. The functional assertions below (pending_count, requeue_stale,
    # duplicate_delivery) are what prove the LIVE queue was captured — a queue that was NOT backed up restores
    # as an EMPTY one (pending_count 0, requeue_stale 0, re-enqueue succeeds), which is the mutation-verify red.
    q2 = SecurityJobQueue(new_qroot)

    # (a) the PENDING job (A) survived the backup→restore.
    assert q2.pending_count() >= 1, "the pending paid job must survive a host loss (nothing-lost)"

    # (c) the delivery/ exactly-once seen-set survived ⇒ a re-enqueue of the SAME delivery_id coalesces.
    redup = q2.enqueue(_job(delivery_id="dA", commit="aaaa"))
    assert redup.enqueued is False and redup.reason == "duplicate_delivery", \
        "the permanent delivery_id idempotency marker must survive backup→restore"

    # (b) the STRANDED running job (B, dead claimer) re-drives via requeue_stale().
    assert q2.requeue_stale() >= 1, "a crashed-worker job in running/ must be reclaimed after restore"
    assert q2.pending_count() >= 2, "after reclaim, both the pending and the reclaimed job are drivable"
    assert q2.claim_next() is not None, "the reclaimed job is claimable by a fresh worker"
