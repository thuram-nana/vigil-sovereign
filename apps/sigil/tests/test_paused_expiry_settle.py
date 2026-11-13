"""E8 — with ``VIGIL_PAUSED_EXPIRY_SETTLE=1`` the settle-drain SETTLES a paused customer launch whose lease window
closed, by the owner's paused-launch rule, exactly once and never ahead of a completion.

A pause holds a launch (the seam poller, the pickup gate and the arm refuse it; a run in flight halts and the worker
emits no completion). Once ``not_after`` passes they refuse the window too, so the launch can never run again. Two
shapes: (a) a run halted by a pause whose customer lifted it only after the window closed (``resume_launch`` then
writes the paused-past-expiry record before it clears the pause), and (b) a queued launch paused until its window
closed. The drain settles each one once the grace has passed (from the later of the window end, the pause and the
late resume): a launch published METERED is charged for what it used (nothing used: refunded), a FLAT one refunded —
the rule ``ops-sweep reservations --apply`` applies to the same launch.

Real spine file, real owner key, real seam files (lease, pause marker, paused-past-expiry record, settlement marker),
the real settle-drain and the real ``LaunchGate`` pause/resume. Every test runs with the settle record
(``VIGIL_SETTLE_SPINE_RECORD``) off and on. The seam records are written at the real clock, so a test that needs a
pause or a resume at a later (simulated) time sets that record's mtime, which is what the predicate reads.
"""
from __future__ import annotations

import itertools
import os
import tempfile
import time
from pathlib import Path

import pytest

from sigil import config
from vigil_core import model_metering as mm

ORG, HOST = "org_a", "apme.cm"
GRACE = 86400.0                                        # the default VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS
TEST_MARGIN = "0.5"                                    # a test fixture (markup 2), not a pricing decision
USAGE = mm.Usage(output_tokens=10_650)
USAGE_COST = 266_250_000                               # 54 credits at the test markup (as test_metered_billing)

_iss = itertools.count(1)


@pytest.fixture(autouse=True, params=["", "1"], ids=["record_off", "record_on"])
def _iso(monkeypatch, tmp_path, request):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_PAUSED_EXPIRY_SETTLE", "1")
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS", "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_METERED_BILLING",
              mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES", "VIGIL_RUN_MODEL",
              *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    if request.param:
        monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", request.param)


def _base() -> str:
    return os.environ["VIGIL_BASE_DIR"]


def _metered(monkeypatch):
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, TEST_MARGIN)
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _set_mtime(path, t: float) -> None:
    os.utime(path, (t, t))


class _Launch:
    """One seated tenant with a STARTED launch: reserved (``units`` of ``credits``) at the real clock for a 1 h
    window, published to the seam (metered when the flag is on), its settle delegation provisioned — what
    ``provision.launch_start`` leaves."""

    def __init__(self, store, *, org=ORG, host=HOST, units=30, credits=100):
        from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
        from sigil.governor.identity import ensure_owner_keypair
        from sigil.governor.orgs import OrgRegistry
        from sigil.governor.wallet import WalletRegistry
        from sigil.ui.launch_gate import LaunchGate
        from sigil.ui.launch_governance import provision_launch_governance
        from sigil.ui.target_authorization import add_customer_target
        from vigil_core.delegation import DelegationCert
        self.store, self.org, self.units, self.credits = store, org, units, credits
        self.owner = ensure_owner_keypair()
        t0 = time.time()
        orgs = OrgRegistry(store)
        orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
        orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
        reg = AssetOwnershipRegistry(store)
        ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
        reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=t0, ttl_seconds=1e12)
        assert add_customer_target(host, org_id=org, store=store, now=t0)["ok"]
        self.gate = LaunchGate(store)
        r = self.gate.reserve_launch(requester="u", org_id=org, host=host, units=units, now=t0, duration_hours=1)
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

    def pause(self, at=None) -> None:
        from vigil_integration.live.credit_lease_pause import pause_path
        assert self.gate.pause_launch(signed_lease=self.lease, expect_org_id=self.org)["ok"]
        if at is not None:
            _set_mtime(pause_path(_base(), self.slug), at)

    def resume(self, at: float) -> dict:
        """Resume at ``at``; an expired resume's paused-past-expiry record is stamped ``at``."""
        from vigil_integration.live.credit_lease_pause import _past_expiry_path
        out = self.gate.resume_launch(signed_lease=self.lease, expect_org_id=self.org, now=at)
        rec = _past_expiry_path(_base(), self.slug)
        if out.get("ok") and rec is not None and rec.exists():
            _set_mtime(rec, at)
        return out

    def spend(self) -> None:
        """One confirmed model request on the run's meter, as the gateway records it."""
        from sigil import model_gateway as gw
        from vigil_core.model_grant import ModelGrant
        g = ModelGrant(grant_id="0" * 32, org_id=self.org, engagement_slug=self.slug, nonce=self.nonce,
                       model="test-run-model", effort="high", cap_nano_usd=10 ** 12, not_after=self.not_after + 86400,
                       issued_at=self.not_after - 3600)
        m = gw.GrantMeter(config.MODEL_METER_DIR)
        rid, _reserved, reason = m.reserve(g, 10 ** 6, 25_000, now=self.not_after - 60)
        assert reason == "", reason
        m.commit(g, rid, USAGE, USAGE_COST, request_id="r", now=self.not_after - 60)

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


_NONE = {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0}


# ---------------------------------------------------------------------------------------------------- the claims
def test_b_a_queued_flat_launch_paused_until_its_window_closed_is_refunded_exactly_once():
    L = _Launch(_store())
    L.pause()                                         # paused while queued: the gate refuses it, nothing ran
    assert L.avail() == 70
    late = L.not_after + GRACE + 60
    out = L.drain(late)
    assert out == {**_NONE, "expired_settled": 1, "expired_unsettled": 0}, out
    assert L.avail() == 100                           # a flat launch has no meter: refunded in full
    assert L.settled() and not L.published()          # revoked + tombstoned like every settle
    for _ in range(2):                                # exactly once: later passes move nothing
        assert L.drain(late + 3600)["expired_settled"] == 0
    assert L.avail() == 100


def test_a_metered_launch_paused_until_its_window_closed_is_charged_for_what_it_used(monkeypatch):
    _metered(monkeypatch)
    L = _Launch(_store(), units=900, credits=1_000)
    L.spend()                                         # the run used 54 credits' worth before the pause
    L.pause()
    rows = _expired_rows(L, L.not_after + GRACE + 60)
    assert [(r["status"], r["charged"], r["refunded"]) for r in rows] == [("charged_paused", 54, 846)], rows
    assert L.avail() == 1_000 - 54 and L.settled()
    assert L.drain(L.not_after + GRACE + 3600)["expired_settled"] == 0 and L.avail() == 1_000 - 54


def test_a_metered_paused_launch_that_used_nothing_is_refunded(monkeypatch):
    _metered(monkeypatch)
    L = _Launch(_store(), units=900, credits=1_000)
    L.pause()
    out = L.drain(L.not_after + GRACE + 60)
    assert out["expired_settled"] == 1 and L.avail() == 1_000


@pytest.mark.parametrize("metered", [False, True], ids=["flat", "metered"])
def test_a_a_halted_run_resumed_after_its_window_closed_settles_once_the_grace_from_the_resume_passed(
        monkeypatch, metered):
    from vigil_integration.live.credit_lease_pause import is_lease_paused, paused_past_expiry
    if metered:
        _metered(monkeypatch)
    L = _Launch(_store(), units=900, credits=1_000)
    if metered:
        L.spend()
    L.pause()                                         # the run in flight halts (no completion)
    resumed_at = L.not_after + 600                    # the customer lifts the pause after the window closed
    r = L.resume(resumed_at)
    assert r["ok"] and r["expired"] is True
    assert not is_lease_paused(_base(), L.slug, L.nonce) and paused_past_expiry(_base(), L.slug, L.nonce) is True
    # the grace runs from the resume (a run this resume let finish would settle through its completion first)
    assert L.drain(L.not_after + GRACE + 60)["expired_settled"] == 0
    assert L.avail() == 100 and not L.settled()
    assert L.drain(resumed_at + GRACE + 1)["expired_settled"] == 1
    assert L.avail() == (1_000 - 54 if metered else 1_000) and L.settled()
    assert L.drain(resumed_at + GRACE + 3600)["expired_settled"] == 0


def test_nothing_settles_inside_the_window_or_the_grace():
    L = _Launch(_store())
    L.pause()
    for at in (L.not_after - 60, L.not_after + 1, L.not_after + GRACE - 1):
        assert L.drain(at)["expired_settled"] == 0
    assert L.avail() == 70 and not L.settled() and L.published()


def test_a_pause_recorded_after_the_window_gets_the_whole_grace():
    # pause_launch accepts an expired lease (the stop control of a run still in flight past not_after), so the
    # grace runs from the pause, not from the window end
    L = _Launch(_store())
    paused_at = L.not_after + 5_000
    L.pause(at=paused_at)
    assert L.drain(L.not_after + GRACE + 60)["expired_settled"] == 0 and L.avail() == 70
    assert L.drain(paused_at + GRACE + 1)["expired_settled"] == 1 and L.avail() == 100


def test_a_completion_in_the_same_pass_is_charged_and_the_expiry_pass_sees_nothing():
    # a pause that landed after the run's last gated action lets the run complete; its COMPLETED is in the spool when
    # the window has closed: the pass charges it FIRST, so the expiry pass has nothing left to consider
    L = _Launch(_store())
    L.pause()
    L.emit("completed")
    out = L.drain(L.not_after + GRACE + 60)
    assert out == {**_NONE, "settled": 1, "expired_settled": 0, "expired_unsettled": 0}, out
    assert L.avail() == 70 and L.settled()            # charged, never refunded


def test_a_quarantined_completion_blocks_the_settle(capsys):
    # a completion the drain could not settle (quarantined in rejected/) is a run that may have finished: the expiry
    # settle leaves the reservation alone (fail-closed) until an operator resolves it, and says so
    L = _Launch(_store())
    L.pause()
    p = L.emit("completed")
    L.watcher(L.not_after)                            # creates the spool dirs
    os.replace(p, Path(L.spool) / "rejected" / p.name)
    rows = _expired_rows(L, L.not_after + GRACE + 60)
    assert [r["status"] for r in rows] == ["completion_pending"], rows
    assert L.avail() == 70 and not L.settled() and L.published()
    out = L.drain(L.not_after + GRACE + 60)
    assert out["expired_settled"] == 0 and out["expired_unsettled"] == 1
    assert f"expired paused launch {L.slug} not settled: completion_pending" in capsys.readouterr().err


def test_a_completion_landing_after_the_up_front_read_is_rechecked_inside_the_settle(monkeypatch):
    L = _Launch(_store())
    L.pause()
    L.watcher(L.not_after)
    real = L.gate.settle_launch

    def _completion_lands_first(**kw):
        L.emit("completed")                           # between the pass's spool read and the settle critical section
        return real(**kw)

    monkeypatch.setattr(L.gate, "settle_launch", _completion_lands_first)
    rows = _expired_rows(L, L.not_after + GRACE + 60)
    assert [r["status"] for r in rows] == ["completion_pending"], rows
    assert L.avail() == 70 and not L.settled()


def test_a_resume_that_lands_just_before_the_settle_restarts_the_grace(monkeypatch):
    # the due list is read before the settle critical section; a late resume recorded in between restarts the grace,
    # and the settle's in-lock re-check sees it
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
    assert L.avail() == 70 and not L.settled()


def test_a_metered_launch_whose_pause_state_turns_unreadable_is_left_alone(monkeypatch):
    from vigil_integration.live.credit_lease_pause import pause_path
    _metered(monkeypatch)
    L = _Launch(_store(), units=900, credits=1_000)
    L.spend()
    L.pause()
    real = L.gate.settle_launch

    def _marker_corrupted_first(**kw):
        pause_path(_base(), L.slug).write_text("{not json", encoding="utf-8")
        return real(**kw)

    monkeypatch.setattr(L.gate, "settle_launch", _marker_corrupted_first)
    rows = _expired_rows(L, L.not_after + GRACE + 60)
    assert [r["status"] for r in rows] == ["pause_unknown"], rows
    assert L.avail() == 100 and not L.settled()


def test_a_scoped_drain_settles_only_its_own_launch():
    s = _store()
    a, b = _Launch(s, org="org_a", host="a.example"), _Launch(s, org="org_b", host="b.example")
    a.pause()
    b.pause()
    late = max(a.not_after, b.not_after) + GRACE + 60
    assert a.drain(late)["expired_settled"] == 1
    assert a.avail() == 100 and b.avail() == 70       # b is outside a's delegated scope
    assert b.drain(late)["expired_settled"] == 1 and b.avail() == 100


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
    assert a.avail() == 70 and b.avail() == 100


def test_flag_off_the_drain_is_unchanged(monkeypatch):
    monkeypatch.delenv("VIGIL_PAUSED_EXPIRY_SETTLE")
    L = _Launch(_store())
    L.pause()
    out = L.drain(L.not_after + GRACE + 3600)
    assert out == _NONE, out                          # exactly the pre-E8 shape
    assert L.avail() == 70 and not L.settled() and L.published()


def test_a_launch_that_was_never_paused_is_never_settled_by_the_expiry_pass():
    # a launch that was never paused is not held: past its window a run of it may still be in flight, so an
    # (idempotent, no-op) expired resume never makes it look like one
    L = _Launch(_store())
    assert L.resume(L.not_after + 600)["ok"]
    assert L.drain(L.not_after + 600 + GRACE + 60)["expired_settled"] == 0 and L.avail() == 70


def test_an_in_window_resume_is_never_settled_by_the_expiry_pass():
    # resumed inside its window the launch re-drives and may legitimately run past not_after + grace: it is a normal,
    # unpaused launch again
    L = _Launch(_store())
    L.pause()
    r = L.resume(L.not_after - 60)
    assert r["ok"] and "expired" not in r
    assert L.drain(L.not_after + GRACE + 60)["expired_settled"] == 0 and L.avail() == 70


def test_an_expired_resume_that_cannot_record_lifts_nothing_and_the_pause_still_settles(monkeypatch):
    import vigil_integration.live.credit_lease_pause as clp
    L = _Launch(_store())
    L.pause()
    orig = clp.record_paused_past_expiry
    monkeypatch.setattr(clp, "record_paused_past_expiry",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("seam is read-only")))
    r = L.resume(L.not_after + 600)
    assert r["ok"] is False and "fail-closed" in r["error"]
    assert clp.is_lease_paused(_base(), L.slug, L.nonce)   # the pause, itself the settle's evidence, stays
    monkeypatch.setattr(clp, "record_paused_past_expiry", orig)
    assert L.drain(L.not_after + GRACE + 60)["expired_settled"] == 1 and L.avail() == 100


def test_settled_on_the_spine_is_not_refunded_twice_when_the_seam_is_rolled_back():
    # the refund grant is on the spine, so a seam restored from before the settle (lease back, settlement marker
    # gone, pause back) re-lists the launch as due, and the settle finds it settled and moves nothing
    import shutil
    L = _Launch(_store())
    L.pause()
    snap = Path(tempfile.mkdtemp()) / "seam"
    shutil.copytree(_base(), snap)
    late = L.not_after + GRACE + 60
    assert L.drain(late)["expired_settled"] == 1 and L.avail() == 100
    shutil.rmtree(_base())
    shutil.copytree(snap, _base())                    # the seam rolled back: unsettled, published, paused
    assert not L.settled() and L.published()
    out = L.drain(late + 60)
    assert out["expired_settled"] == 0 and out["expired_unsettled"] == 0, out
    assert L.avail() == 100                           # one refund, ever
    assert L.settled()                                # the revocation is re-asserted


def test_the_cli_prints_the_expiry_counts_only_with_the_flag(monkeypatch, capsys):
    import argparse

    import sigil.cli as cli
    import sigil.inbound.completion_spool as csw
    L = _Launch(_store())
    L.pause()
    dpath = Path(tempfile.mkdtemp()) / "deleg.json"
    dpath.write_text(L.deleg.model_dump_json(), encoding="utf-8")
    w = L.watcher(L.not_after + GRACE + 60)           # the unit's watcher, at a clock past the window + the grace
    monkeypatch.setattr(cli, "SpineStore", lambda: L.store)
    monkeypatch.setattr(csw, "CompletionSpoolWatcher", lambda *a, **k: w)
    ns = argparse.Namespace(spool=L.spool, base_dir=_base(), delegation=str(dpath), scope=L.slug, settle_cmd="drain",
                            interval=1.0)
    try:
        cli.cmd_settle_drain(ns)
    except SystemExit as e:
        assert e.code in (0, None)
    assert "expired paused launches: 1 settled, 0 still held" in capsys.readouterr().out
    assert L.avail() == 100
