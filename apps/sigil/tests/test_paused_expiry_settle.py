"""E8 — a PAUSED customer launch whose lease window closes still SETTLES, exactly once, and never ahead of a
completion.

A pause holds a launch (the seam poller, the pickup gate and the arm refuse it; a run in flight halts with
``EngagementPaused`` and the worker emits NO completion). Once ``not_after`` passes they refuse the window too, so
the launch can never run again — and nothing settled it: (a) a run halted by a pause whose window closed before
the customer resumed it, and (b) a queued launch paused until its window closed, both kept their reservation
debited until an operator ran the default-OFF ``ops-sweep reservations --apply``. With
``VIGIL_PAUSED_EXPIRY_SETTLE=1`` the settle-drain (``CompletionSpoolWatcher.drain``) settles each one once the
grace has passed — a FULL refund until the metered settle lands — through the exactly-once ``settle_launch``.

Real spine file, real owner key, real seam files (lease, pause marker, expiry hold, settlement marker), the real
settle-drain and the real ``LaunchGate`` pause/resume; the cross-process test re-executes this file as a child
(``python <file> resume-child ...``) that resumes the launch from ANOTHER process while the parent settles. The
worker side (``EngagementPaused`` ⇒ no completion; a paused queued job ⇒ refused + released) is pinned by
``integration/tests/test_engage_worker_pause_redrive.py`` / ``test_launch_pause_redrive_gate.py``; here the
seam is left exactly as those leave it.

Mutation-verify targets (each neuter reds a NAMED test here):
  * drain() never runs the expiry pass                    -> test_b_a_queued_launch_paused_until_its_window_closed_is_refunded_exactly_once
  * drain() runs it with the flag OFF                     -> test_flag_off_is_byte_identical
  * expiry pass runs BEFORE the completions               -> test_a_completion_in_the_same_pass_is_charged_and_the_expiry_pass_sees_nothing
  * settle precondition drops the completion check        -> test_a_quarantined_completion_blocks_the_refund
  * settle precondition drops the still-due re-check      -> test_a_resume_that_lands_just_before_the_settle_restarts_the_grace
  * the scope bind is dropped                             -> test_a_scoped_drain_settles_only_its_own_launch
  * one raising settle aborts the pass                    -> test_one_failing_settle_never_blocks_the_others
  * an expired resume records no hold (flag on)           -> test_a_a_halted_run_resumed_after_its_window_closed_settles_once_the_grace_from_the_resume_passed
  * an expired resume records a hold for a never-paused lease -> test_an_expired_resume_of_a_launch_that_was_not_paused_records_no_hold
  * an IN-WINDOW resume records a hold too                -> test_an_in_window_resume_records_no_hold
  * the expired-pause settle charges the reservation      -> test_b_a_queued_launch_paused_until_its_window_closed_is_refunded_exactly_once
  * the pause is lifted before the hold is written        -> test_an_expired_resume_that_cannot_record_its_hold_lifts_nothing
  * an expired resume is taken outside the settle lock    -> test_a_resume_in_another_process_is_serialized_with_the_settle
"""
from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ORG, HOST = "org_a", "apme.cm"
UNITS, CREDITS = 30, 100
GRACE = 86400.0                                        # the default VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS


# =========================================================================================================
# child process: the cockpit resuming the launch from ANOTHER process
# =========================================================================================================

def _resume_child(argv: list) -> int:
    """``resume-child <spine> <lease.json> <now> <workdir>``: resume the lease; the expiry-hold write is slowed
    (TEST-ONLY) so the parent can start its settle while this resume is inside its critical section."""
    spine, lease_path, now, work = argv[0], argv[1], float(argv[2]), Path(argv[3])
    import vigil_integration.live.credit_lease_expiry as cle
    from sigil.spine.store import SpineStore
    from sigil.ui.launch_gate import LaunchGate
    orig = cle.record_expiry_hold

    def _slow(*a, **k):
        (work / "in-resume").write_text("1", encoding="utf-8")
        time.sleep(float(os.environ.get("E8_RESUME_WIDEN_S") or 1.5))
        return orig(*a, **k)

    cle.record_expiry_hold = _slow
    lease = json.loads(Path(lease_path).read_text(encoding="utf-8"))
    out = LaunchGate(SpineStore(spine)).resume_launch(signed_lease=lease, expect_org_id=ORG, now=now)
    (work / "resumed.json").write_text(json.dumps(out), encoding="utf-8")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "resume-child":
        raise SystemExit(_resume_child(sys.argv[2:]))
    raise SystemExit("run under pytest")


# =========================================================================================================
# parent (pytest)
# =========================================================================================================

import pytest  # noqa: E402

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_PAUSED_EXPIRY_SETTLE", "1")
    for k in ("VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS", "VIGIL_SETTLE_SPINE_RECORD"):
        monkeypatch.delenv(k, raising=False)


def _base() -> str:
    return os.environ["VIGIL_BASE_DIR"]


class _Launch:
    """One seated tenant with a STARTED launch: reserved (``UNITS`` of ``CREDITS``) at the real clock for a 1 h
    window, published to the seam, its settle delegation provisioned — what ``provision.launch_start`` leaves."""

    def __init__(self, store, *, org=ORG, host=HOST):
        from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
        from sigil.governor.identity import ensure_owner_keypair
        from sigil.governor.orgs import OrgRegistry
        from sigil.governor.wallet import WalletRegistry
        from sigil.ui.launch_gate import LaunchGate
        from sigil.ui.launch_governance import provision_launch_governance
        from sigil.ui.target_authorization import add_customer_target
        from vigil_core.delegation import DelegationCert
        self.store, self.org = store, org
        self.owner = ensure_owner_keypair()
        t0 = time.time()
        orgs = OrgRegistry(store)
        orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
        orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
        WalletRegistry(store).grant(org, CREDITS, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
        reg = AssetOwnershipRegistry(store)
        ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
        reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=t0, ttl_seconds=1e12)
        assert add_customer_target(host, org_id=org, store=store, now=t0)["ok"]
        self.gate = LaunchGate(store)
        r = self.gate.reserve_launch(requester="u", org_id=org, host=host, units=UNITS, now=t0, duration_hours=1)
        assert r["ok"], r
        assert self.gate.publish_lease(signed_lease=r["lease"], expect_org_id=org)["ok"]
        self.lease, self.slug, self.nonce = r["lease"], r["slug"], r["nonce"]
        self.not_after = t0 + 3600.0
        dp = provision_launch_governance(slug=self.slug, not_after=int(self.not_after) + 30 * 86400,
                                         base_dir=_base())
        self.deleg = DelegationCert.model_validate_json(Path(dp).read_text(encoding="utf-8"))
        self.spool = str(Path(_base()) / "completion-spool" / self.slug)   # the worker's per-slug default spool

    def avail(self) -> int:
        from sigil.governor.wallet import WalletRegistry
        return WalletRegistry(self.store).available(self.org)

    def pause(self) -> None:
        assert self.gate.pause_launch(signed_lease=self.lease, expect_org_id=self.org)["ok"]

    def resume(self, at: float) -> dict:
        return self.gate.resume_launch(signed_lease=self.lease, expect_org_id=self.org, now=at)

    def watcher(self, at: float, *, scope=None):
        from sigil.inbound.completion_spool import CompletionSpoolWatcher
        return CompletionSpoolWatcher(self.store, spool_dir=self.spool, owner_pubkey=self.owner.public_key_b64,
                                      delegation=self.deleg, scope=scope or self.slug, base_dir=_base(),
                                      now_fn=lambda: at)

    def drain(self, at: float, **kw) -> dict:
        return self.watcher(at, **kw).drain()

    def emit(self, outcome: str) -> Path:
        from vigil_integration.jobs.completion_signal import emit_completion_signal
        from vigil_integration.live.governance_identity import (
            DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
        )
        kp = load_or_create_governance_keypair(path=os.path.join(_base(), DEFAULT_GOVERNANCE_KEY_FILE))
        return emit_completion_signal(engagement_slug=self.slug, nonce=self.nonce, outcome=outcome,
                                      signers=[(GOVERNANCE_KEY_ID, kp.private_key_b64)], spool_dir=self.spool)

    def settled(self) -> bool:
        from vigil_integration.live.credit_lease_broker import is_lease_settled
        return is_lease_settled(_base(), self.slug, self.nonce)

    def published(self) -> bool:
        from vigil_integration.live.credit_lease_broker import read_credit_lease
        return read_credit_lease(_base(), self.slug) is not None


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _expired_rows(L: _Launch, at: float, **kw) -> list:
    """The drain's expiry pass alone, over ``L``'s completion spool (its watcher creates the spool dirs)."""
    from sigil.paused_expiry_settle import settle_expired_paused_launches
    L.watcher(at)
    return settle_expired_paused_launches(L.gate, now=at, completion_spool=L.spool, **kw)


# ---------------------------------------------------------------------------------------------------- the claims
def test_b_a_queued_launch_paused_until_its_window_closed_is_refunded_exactly_once():
    L = _Launch(_store())
    L.pause()                                         # paused while queued: the gate refuses it, nothing ran
    assert L.avail() == CREDITS - UNITS
    late = L.not_after + GRACE + 60
    out = L.drain(late)
    assert out == {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0, "expired_settled": 1,
                   "expired_unsettled": 0}, out
    assert L.avail() == CREDITS                       # FULL refund: nothing ran, nothing is charged
    assert L.settled() and not L.published()          # revoked + tombstoned like every settle
    for _ in range(2):                                # exactly once: later passes move nothing
        assert L.drain(late + 3600)["expired_settled"] == 0
    assert L.avail() == CREDITS


def test_a_a_halted_run_resumed_after_its_window_closed_settles_once_the_grace_from_the_resume_passed():
    from vigil_integration.live.credit_lease_expiry import expiry_hold_at
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    L = _Launch(_store())
    L.pause()                                         # the run in flight halts (EngagementPaused, no completion)
    resumed_at = L.not_after + 600                    # the customer resumes after the window closed
    r = L.resume(resumed_at)
    assert r["ok"] and r["expired"] is True           # the reply is unchanged: the pause is lifted ...
    assert not is_lease_paused(_base(), L.slug, L.nonce)
    assert expiry_hold_at(_base(), L.slug, L.nonce) == pytest.approx(resumed_at, abs=1e-3)   # ... and it stays due
    # the grace restarts at the resume (a run this resume let finish would settle through its completion first)
    assert L.drain(L.not_after + GRACE + 60)["expired_settled"] == 0
    assert L.avail() == CREDITS - UNITS and not L.settled()
    assert L.drain(resumed_at + GRACE + 1)["expired_settled"] == 1
    assert L.avail() == CREDITS and L.settled()
    assert L.drain(resumed_at + GRACE + 3600)["expired_settled"] == 0
    assert L.avail() == CREDITS


def test_nothing_settles_inside_the_window_or_the_grace():
    L = _Launch(_store())
    L.pause()
    for at in (L.not_after - 60, L.not_after + 1, L.not_after + GRACE - 1):
        assert L.drain(at)["expired_settled"] == 0
    assert L.avail() == CREDITS - UNITS and not L.settled() and L.published()


def test_a_completion_in_the_same_pass_is_charged_and_the_expiry_pass_sees_nothing():
    # A pause that landed after the run's last gated action lets the run complete; its COMPLETED is in the spool
    # when the window has closed. The pass charges it FIRST, so the expiry pass has nothing left to consider.
    L = _Launch(_store())
    L.pause()
    L.emit("completed")
    out = L.drain(L.not_after + GRACE + 60)
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0, "expired_settled": 0,
                   "expired_unsettled": 0}, out
    assert L.avail() == CREDITS - UNITS and L.settled()   # charged, never refunded


def test_a_quarantined_completion_blocks_the_refund():
    # A completion the drain could not settle (quarantined in rejected/) is a run that may have finished: the
    # expiry settle must leave the reservation alone (fail-closed) until an operator resolves it.
    L = _Launch(_store())
    L.pause()
    p = L.emit("completed")
    L.watcher(L.not_after)                            # creates the spool dirs
    os.replace(p, Path(L.spool) / "rejected" / p.name)
    rows = _expired_rows(L, L.not_after + GRACE + 60)
    assert [r["status"] for r in rows] == ["completion_pending"], rows
    assert L.avail() == CREDITS - UNITS and not L.settled() and L.published()


def test_a_resume_that_lands_just_before_the_settle_restarts_the_grace(monkeypatch):
    # The due list is read before the settle critical section; a customer resume serialized in between (it
    # records the hold under the same lock) restarts the grace, and the settle's in-lock re-check sees it.
    import vigil_integration.live.credit_lease_expiry as cle
    L = _Launch(_store())
    L.pause()
    late = L.not_after + GRACE + 60
    orig = cle.due_expired_pauses

    def _scan_then_resume(*a, **k):
        due = orig(*a, **k)
        assert L.resume(late)["ok"]
        return due

    monkeypatch.setattr(cle, "due_expired_pauses", _scan_then_resume)
    rows = _expired_rows(L, late)
    assert [r["status"] for r in rows] == ["not_due"], rows
    assert L.avail() == CREDITS - UNITS and not L.settled()


def test_a_scoped_drain_settles_only_its_own_launch():
    s = _store()
    a, b = _Launch(s, org="org_a", host="a.example"), _Launch(s, org="org_b", host="b.example")
    a.pause()
    b.pause()
    late = max(a.not_after, b.not_after) + GRACE + 60
    assert a.drain(late)["expired_settled"] == 1
    assert a.avail() == CREDITS and b.avail() == CREDITS - UNITS     # b is outside a's delegated scope
    assert b.drain(late)["expired_settled"] == 1 and b.avail() == CREDITS


def test_one_failing_settle_never_blocks_the_others(monkeypatch):
    s = _store()
    a, b = _Launch(s, org="org_a", host="a.example"), _Launch(s, org="org_b", host="b.example")
    a.pause()
    b.pause()
    gate = a.gate
    orig = gate.settle_launch

    def _settle(**kw):
        if kw["signed_lease"]["document"]["engagement_slug"] == a.slug:
            raise OSError("disk went away")
        return orig(**kw)

    monkeypatch.setattr(gate, "settle_launch", _settle)
    rows = _expired_rows(a, max(a.not_after, b.not_after) + GRACE + 60)
    got = {r["slug"]: r["status"] for r in rows}
    assert got == {a.slug: "settle_failed", b.slug: "settled"}, rows
    assert a.avail() == CREDITS - UNITS and b.avail() == CREDITS


def test_flag_off_is_byte_identical(monkeypatch):
    from vigil_integration.live.credit_lease_expiry import holds_root
    monkeypatch.delenv("VIGIL_PAUSED_EXPIRY_SETTLE")
    L = _Launch(_store())
    L.pause()
    r = L.resume(L.not_after + 600)                   # an expired resume records nothing new
    assert r["ok"] and r["expired"] is True and not holds_root(_base()).exists()
    L.pause()
    out = L.drain(L.not_after + GRACE + 3600)
    assert out == {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0}, out   # exactly the pre-E8 shape
    assert L.avail() == CREDITS - UNITS and not L.settled() and L.published()


def test_an_expired_resume_of_a_launch_that_was_not_paused_records_no_hold():
    # A launch that was never paused is not held: past its window a run of it may still be in flight, so an
    # (idempotent, no-op) resume must not make it look like one.
    from vigil_integration.live.credit_lease_expiry import holds_root
    L = _Launch(_store())
    assert L.resume(L.not_after + 600)["ok"]
    assert not holds_root(_base()).exists()
    assert L.drain(L.not_after + 600 + GRACE + 60)["expired_settled"] == 0
    assert L.avail() == CREDITS - UNITS


def test_an_in_window_resume_records_no_hold():
    # Resumed inside its window, the launch re-drives and may legitimately run past not_after + grace: it is a
    # normal, unpaused launch again, never one the expiry settle may refund.
    from vigil_integration.live.credit_lease_expiry import holds_root
    L = _Launch(_store())
    L.pause()
    r = L.resume(L.not_after - 60)
    assert r["ok"] and "expired" not in r
    assert not holds_root(_base()).exists()
    assert L.drain(L.not_after + GRACE + 60)["expired_settled"] == 0 and L.avail() == CREDITS - UNITS


def test_an_expired_resume_that_cannot_record_its_hold_lifts_nothing(monkeypatch):
    import vigil_integration.live.credit_lease_expiry as cle
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    L = _Launch(_store())
    L.pause()

    def _boom(*a, **k):
        raise OSError("seam is read-only")

    orig = cle.record_expiry_hold
    monkeypatch.setattr(cle, "record_expiry_hold", _boom)
    r = L.resume(L.not_after + 600)
    assert r["ok"] is False and "fail-closed" in r["error"]
    assert is_lease_paused(_base(), L.slug, L.nonce)  # the pause — itself evidence for the settle — stays
    monkeypatch.setattr(cle, "record_expiry_hold", orig)
    assert L.drain(L.not_after + GRACE + 60)["expired_settled"] == 1 and L.avail() == CREDITS


def test_settled_on_the_spine_is_not_refunded_twice_when_the_seam_is_rolled_back():
    # E3bc: the refund grant is on the spine, so a seam restored from before the settle (lease back, settlement
    # marker gone, pause back) re-lists the launch as due, and the settle finds it settled and moves nothing.
    import shutil
    L = _Launch(_store())
    L.pause()
    snap = Path(tempfile.mkdtemp()) / "seam"
    shutil.copytree(_base(), snap)
    late = L.not_after + GRACE + 60
    assert L.drain(late)["expired_settled"] == 1 and L.avail() == CREDITS
    shutil.rmtree(_base())
    shutil.copytree(snap, _base())                    # the seam rolled back: unsettled, published, paused
    assert not L.settled() and L.published()
    out = L.drain(late + 60)
    assert out["expired_settled"] == 0 and out["expired_unsettled"] == 0, out
    assert L.avail() == CREDITS                       # not 130: one refund, ever
    assert L.settled()                                # the revocation is re-asserted


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX multi-process harness")
def test_a_resume_in_another_process_is_serialized_with_the_settle():
    # The cockpit resumes an expired paused launch in ITS process while the settle-drain settles in its own. The
    # resume writes the hold and lifts the pause inside the settle critical section, so the settle either runs
    # first or sees the hold (grace restarted) — never the half-done resume.
    from sigil.governor import identity
    L = _Launch(_store())
    L.pause()
    late = L.not_after + GRACE + 60
    work = Path(tempfile.mkdtemp())
    lease = work / "lease.json"
    lease.write_text(json.dumps(L.lease), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) for p in sys.path if p)
    env["SIGIL_HOME"] = str(Path(identity.KEYS_DIR).parent.parent)      # the home this process's key lives in
    child = subprocess.Popen([sys.executable, os.path.abspath(__file__), "resume-child", L.store.path, str(lease),
                              str(late), str(work)], env=env)
    try:
        deadline = time.monotonic() + 60
        while not (work / "in-resume").exists():
            assert child.poll() is None, "the resume child died"
            assert time.monotonic() < deadline, "the resume child never reached its critical section"
            time.sleep(0.01)
        rows = _expired_rows(L, late)                 # blocks on the settle lock until the resume is done
        assert child.wait(timeout=60) == 0
    finally:
        if child.poll() is None:
            child.kill()
    assert json.loads((work / "resumed.json").read_text(encoding="utf-8"))["ok"] is True
    assert [r["status"] for r in rows] == ["not_due"], rows
    assert L.avail() == CREDITS - UNITS and not L.settled()
    assert L.drain(late + GRACE + 1)["expired_settled"] == 1 and L.avail() == CREDITS
