"""E3bc — the settle drain's finish pass reads the spine incrementally, misses nothing, and fails per lease.

With ``VIGIL_SETTLE_SPINE_RECORD`` on, every settle-drain pass finishes the recorded settles of the leases on its seam
(``ops_sweeps.finish_interrupted_settles``). This pins:

  * the pass reads only the spine records appended since the previous pass (a checkpoint beside the spool,
    ``settle_checkpoint``) — an idle pass reads nothing more — and still finishes a lease published after that pass
    listed the seam (every settlement record of it is after the checkpoint's ``listed_from``); a lease retired from
    the seam while a pass lists it keeps the next pass incremental, but a lease file still there unread at that
    listing, or a checkpoint that cannot be trusted (missing, unreadable, oversized, a symlink, another spine,
    owner key or scope, an anchor rewritten or gone, a pruned spine), means one full read; the continued evidence
    equals a full scan pass after pass, and a checkpoint above its size bound is not kept; the whole spine is read
    again at least every ``FULL_RESCAN_S`` (a bundle restored onto the seam from a backup is found then);
  * a spine the pass cannot read raises, so the drain reports ``settle_finish_error`` — never "nothing to finish"
    (a read-only report still reports nothing); so does a ledger (wallet, plan or postpaid) it cannot read while it
    checks what a recorded decision has left to land, and past the grace that failing pass alarms;
  * one unreadable settlement marker is that lease's ``settle_failed``, never the whole pass;
  * a completion's notification (NTF-3) is written right after its settle is finished, so a crash later in the pass
    cannot lose it.

Mutation-verify targets (each neuter turns a NAMED test red):
  * the checkpoint not used / not passed / since_seq ignored  -> test_an_idle_second_pass_reads_only_the_records_...,
                                                                 test_the_control_a_trusted_checkpoint_reads_only_...
  * the continued scan starting at the anchor for a new lease -> test_a_lease_published_while_a_pass_listed_the_seam_...
  * an unclean listing trusted / the listing always clean     -> test_a_lease_unreadable_at_the_checkpoints_listing_...,
                                                                 test_a_lease_retired_while_a_pass_lists_the_seam_...
  * a lease retired during the listing counted unclean        -> test_a_lease_retired_while_a_pass_lists_the_seam_...
  * each checkpoint check dropped (spine, owner, scope, anchor hash, anchor gone, live window, unknown lease,
    symlink, size)                                            -> test_a_checkpoint_that_cannot_be_trusted_means_...
  * the size bound on write dropped                           -> test_a_checkpoint_too_large_to_keep_is_not_written
  * the periodic full read dropped / a clock gone back trusted -> test_a_lease_restored_onto_the_seam_is_found_...,
                                                                 test_a_checkpoint_that_cannot_be_trusted_means_...
  * the carried evidence dropped                              -> test_the_continued_evidence_equals_a_full_scan_...
  * the finish pass swallowing a spine read error             -> test_a_finish_pass_that_cannot_read_the_spine_...
  * the finish pass swallowing a ledger read error (its strict check through the report's swallowing
    ``unlanded_settlement``)                                  -> test_a_finish_pass_that_cannot_read_a_ledger_...
  * is_lease_settled outside the per-lease try                -> test_one_unreadable_settlement_marker_is_that_...
  * NTF-3 written after the whole pass                        -> test_a_crash_later_in_the_pass_keeps_the_notice_...

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_finish_pass_incremental.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigil import ops_sweeps, settle_checkpoint
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.launch_settlement import scan_settlements
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.postpaid import PostpaidArrearsLedger
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.settle_checkpoint import CHECKPOINT_NAME
from sigil.spine.store import SpineError, SpineStore
from sigil.ui.launch_gate import LaunchGate
from test_settle_one_pass_evidence import (  # noqa: F401  (_iso: the autouse isolation fixture)
    _NONE, HOST, NOW, ORG, B, _avail, _base, _counting, _decisions, _iso, _kill, _outcomes, _plan, _published,
    _reserve, _seat, _settle, _spool, _store,
)
from vigil_core import AuthorizerKey, generate_keypair
from vigil_integration.live import settle_progress
from vigil_integration.live.credit_lease_broker import lease_path

OTHER = "other.cm"


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


def _drain(store, spool, clock, *, scope="*"):
    """A settle drain over ``spool`` whose clock is ``clock["t"]`` (scope ``*`` unless a slug is given)."""
    owner = ensure_owner_keypair()
    key = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=key.public_key_b64)],
        threshold=1, scope=scope, not_after=9_000_000_000)
    return CompletionSpoolWatcher(store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                                  scope=scope, base_dir=_base(), now_fn=lambda: clock["t"])


def _noise(store, n):
    for i in range(n):
        store.append(kind="event", source="x", actor="y", payload={"signal": "noise", "org_id": "o", "i": i})


def _decided_no_marker(monkeypatch, s, r, basis="cancel"):
    """A settle of ``r`` that recorded its decision and then could not write its seam marker (nothing moved)."""
    restore = _kill(monkeypatch, B, "record_lease_settlement", exc=OSError("seam unwritable"))
    assert _settle(s, r, 0, basis=basis).get("retry") is True
    restore()


# =====================================================================================================================
# the pass reads only what was appended since the previous one, and misses nothing
# =====================================================================================================================
@pytest.mark.parametrize("new", [0, 7])
def test_an_idle_second_pass_reads_only_the_records_appended_since_the_first(record_on, monkeypatch, new):
    s = _store()
    _seat(s, credits=1_000)
    _noise(s, 60)
    rA = _reserve(s, units=30, publish=True, hours=8, nonce="A" * 16)    # a live lease on the seam: nothing to finish
    spool, clock = _spool(), {"t": NOW + 60}
    w = _drain(s, spool, clock, scope=rA["slug"])
    seen, n, restore = _counting(monkeypatch, s)
    assert w.drain() == _NONE
    assert seen["visits"] == n, (seen, n)                                  # no checkpoint yet: the whole spine, once
    _noise(s, new)
    seen.update(visits=0, passes=0)
    assert w.drain() == _NONE
    assert seen["visits"] == new, seen                                     # then only what was appended since
    restore()


def test_a_lease_published_while_a_pass_listed_the_seam_is_finished_by_the_next_incremental_pass(record_on,
                                                                                                monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    _reserve(s, units=100, publish=True, hours=8, nonce="P" * 16)         # on the seam when the pass lists it
    r2 = _reserve(s, units=300, hours=8, nonce="Q" * 16, host=OTHER)      # reserved before it, published after
    cp = Path(_spool()) / CHECKPOINT_NAME
    real_list = B.list_credit_leases

    def listing_then_publish(base):
        out = real_list(base)
        monkeypatch.setattr(B, "list_credit_leases", real_list)
        assert LaunchGate(s).publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)["ok"]
        _decided_no_marker(monkeypatch, s, r2)                            # its decision lands before the pass reads
        return out

    monkeypatch.setattr(B, "list_credit_leases", listing_then_publish)
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90, checkpoint=cp) == []
    ck = json.loads(cp.read_text(encoding="utf-8"))
    (dec,) = _decisions(s)
    assert ck["listed_from"] < dec.seq <= ck["anchor"][0], (ck["listed_from"], dec.seq, ck["anchor"])
    assert [ORG, r2["slug"], r2["nonce"]] not in ck["leases"] and ck["listing_clean"] is True
    rows = ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 120, checkpoint=cp)
    assert [(r["slug"], r["status"]) for r in rows] == [(r2["slug"], "settle_completed")], rows
    assert _avail(s) == 1_000 - 100 and not _published(r2) and len(_decisions(s)) == 1


def test_a_lease_unreadable_at_the_checkpoints_listing_is_read_in_full_once_readable(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    _reserve(s, units=100, publish=True, hours=8, nonce="P" * 16)
    r3 = _reserve(s, units=300, publish=True, hours=8, nonce="R" * 16, host=OTHER)
    _decided_no_marker(monkeypatch, s, r3)                                # decided BEFORE the checkpoint's listing
    _noise(s, 5)
    p = lease_path(_base(), r3["slug"])
    good = p.read_bytes()
    p.write_bytes(b"{not json")                                           # unreadable while that pass lists the seam
    cp = Path(_spool()) / CHECKPOINT_NAME
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90, checkpoint=cp) == []
    assert json.loads(cp.read_text(encoding="utf-8"))["listing_clean"] is False
    p.write_bytes(good)
    rows = ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 120, checkpoint=cp)
    assert [(r["slug"], r["status"]) for r in rows] == [(r3["slug"], "settle_completed")], rows
    assert _avail(s) == 1_000 - 100


@pytest.mark.parametrize("race", ["retired_before_the_listing", "retired_during_the_listing", "unreadable"])
def test_a_lease_retired_while_a_pass_lists_the_seam_keeps_the_next_pass_incremental(record_on, monkeypatch, race):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER, "third.cm"))
    _noise(s, 40)
    _reserve(s, units=100, publish=True, hours=8, nonce="P" * 16)         # on the seam throughout
    r1 = _reserve(s, units=100, publish=True, hours=8, nonce="Q" * 16, host=OTHER)
    p = lease_path(_base(), r1["slug"])
    cp = Path(_spool()) / CHECKPOINT_NAME
    real_list, real_read = B.list_credit_leases, B._read_lease_file

    def retire_r1():                                                      # a settle retires r1: its money landed
        assert _settle(s, r1, 100, basis="completion:completed")["ok"] and not p.exists()

    def listing(base):                                                    # after the pass globbed the seam
        monkeypatch.setattr(B, "list_credit_leases", real_list)
        if race == "retired_before_the_listing":
            retire_r1()
        elif race == "unreadable":
            p.write_bytes(b"{not json")                                   # still on the seam, unreadable
        return real_list(base)

    def read_lease(path):                                                 # the listing globbed r1, then it went
        if path == p:
            monkeypatch.setattr(B, "_read_lease_file", real_read)
            retire_r1()
        return real_read(path)

    monkeypatch.setattr(B, "list_credit_leases", listing)
    if race == "retired_during_the_listing":
        monkeypatch.setattr(B, "_read_lease_file", read_lease)
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90, checkpoint=cp) == []
    ck = json.loads(cp.read_text(encoding="utf-8"))
    assert ck["listing_clean"] is (race != "unreadable"), ck["listing_clean"]
    assert p.exists() is (race == "unreadable")
    _reserve(s, units=100, publish=True, hours=8, nonce="R" * 16, host="third.cm")   # a new lease after that listing
    seen, n, restore = _counting(monkeypatch, s)
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 120, checkpoint=cp) == []
    restore()
    if race == "unreadable":
        assert seen["visits"] >= n, (seen, n)                             # a file still there unread: a full read
    else:
        assert seen["visits"] == n - 1 - ck["listed_from"] < n - 40, (seen, n, ck["listed_from"])   # from listed_from
    assert _avail(s) == 1_000 - 300                                         # three reserved, none refunded


def _tamper(field, value):
    def go(ck, s):
        ck[field] = value(ck, s) if callable(value) else value
    return go


@pytest.mark.parametrize("how", [
    "missing", "garbage", "oversized", "other_spine", "other_owner", "other_scope", "anchor_rewritten",
    "anchor_beyond_tip", "spine_pruned", "evidence_unknown_lease", "symlink", "full_read_due", "clock_went_back",
])
def test_a_checkpoint_that_cannot_be_trusted_means_one_full_read(record_on, monkeypatch, how, tmp_path):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    rA = _reserve(s, units=100, publish=True, hours=8, nonce="P" * 16)
    rB = _reserve(s, units=300, publish=True, hours=8, nonce="R" * 16, host=OTHER)
    _decided_no_marker(monkeypatch, s, rB)
    _noise(s, 20)
    cp = Path(_spool()) / CHECKPOINT_NAME
    first = ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90, checkpoint=cp)
    assert [r["status"] for r in first] == ["settle_completed"]            # rB finished on the first pass
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 95, checkpoint=cp) == []
    _noise(s, 3)
    ck = json.loads(cp.read_text(encoding="utf-8"))
    edits = {
        "other_spine": _tamper("spine", "/elsewhere/spine.jsonl"),
        "other_owner": _tamper("owner", generate_keypair().public_key_b64),
        "other_scope": _tamper("scope", rA["slug"]),
        "anchor_rewritten": _tamper("anchor", lambda c, s_: [c["anchor"][0], "0" * 64]),
        "anchor_beyond_tip": _tamper("anchor", lambda c, s_: [s_.next_seq + 10, c["anchor"][1]]),
        "spine_pruned": _tamper("live_from", 1),
        "full_read_due": _tamper("full_at", NOW + 120 - settle_checkpoint.FULL_RESCAN_S),
        "clock_went_back": _tamper("full_at", NOW + 121),
        "evidence_unknown_lease": _tamper("evidence", [[[ORG, "cust_x", "n"], {
            "record_seq": None, "malformed": False, "landed": ["wallet"], "decision": None}]]),
    }
    if how == "missing":
        cp.unlink()
    elif how == "garbage":
        cp.write_text("{", encoding="utf-8")
    elif how == "oversized":                                               # valid JSON, one byte over the bound
        pad = settle_checkpoint.MAX_BYTES + 1 - len(json.dumps({**ck, "pad": ""}))
        cp.write_text(json.dumps({**ck, "pad": "x" * pad}), encoding="utf-8")
        assert cp.stat().st_size == settle_checkpoint.MAX_BYTES + 1
    elif how == "symlink":
        real = tmp_path / "elsewhere.json"
        real.write_text(json.dumps(ck), encoding="utf-8")
        cp.unlink()
        cp.symlink_to(real)
    else:
        edits[how](ck, s)
        cp.write_text(json.dumps(ck), encoding="utf-8")
    seen, n, restore = _counting(monkeypatch, s)
    rows = ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 120, checkpoint=cp)
    restore()
    assert rows == [] and seen["visits"] >= n, (how, seen, n)              # read from seq 0, nothing to finish
    assert json.loads(cp.read_text(encoding="utf-8"))["anchor"][0] == s.next_seq - 1   # a fresh checkpoint


def test_a_lease_restored_onto_the_seam_is_found_by_the_periodic_full_read(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    _reserve(s, units=100, publish=True, hours=8, nonce="P" * 16)
    rK = _reserve(s, units=300, publish=True, hours=8, nonce="K" * 16, host=OTHER)
    _decided_no_marker(monkeypatch, s, rK)                                 # decided, only the spine shows it
    p = lease_path(_base(), rK["slug"])
    kept = p.read_bytes()
    p.unlink()                                                             # its bundle lost from the seam ...
    _noise(s, 5)
    cp = Path(_spool()) / CHECKPOINT_NAME
    full = settle_checkpoint.FULL_RESCAN_S
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90, checkpoint=cp) == []
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90 + full / 2, checkpoint=cp) == []
    p.write_bytes(kept)                                                    # ... and restored from a backup
    rows = ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90 + full, checkpoint=cp)
    assert [(r["slug"], r["status"]) for r in rows] == [(rK["slug"], "settle_completed")], rows
    assert _avail(s) == 1_000 - 100 and not _published(rK)


def test_the_control_a_trusted_checkpoint_reads_only_the_tail(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    _reserve(s, units=100, publish=True, hours=8, nonce="P" * 16)
    rB = _reserve(s, units=300, publish=True, hours=8, nonce="R" * 16, host=OTHER)
    _decided_no_marker(monkeypatch, s, rB)
    _noise(s, 20)
    cp = Path(_spool()) / CHECKPOINT_NAME
    assert [r["status"] for r in ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90,
                                                                       checkpoint=cp)] == ["settle_completed"]
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 95, checkpoint=cp) == []
    _noise(s, 3)
    seen, n, restore = _counting(monkeypatch, s)
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 120, checkpoint=cp) == []
    restore()
    assert seen["visits"] == 3, (seen, n)


def test_a_checkpoint_too_large_to_keep_is_not_written(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    _reserve(s, units=100, publish=True, hours=8, nonce="P" * 16)
    cp = Path(_spool()) / CHECKPOINT_NAME
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90, checkpoint=cp) == []
    size = cp.stat().st_size
    monkeypatch.setattr(settle_checkpoint, "MAX_BYTES", size - 1)
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 95, checkpoint=cp) == []
    assert not cp.exists()                                                 # never kept above the bound


def test_the_continued_evidence_equals_a_full_scan_pass_after_pass(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=10_000, hosts=(HOST, OTHER, "third.cm"))
    kp = ensure_owner_keypair()
    cp = Path(_spool()) / CHECKPOINT_NAME
    listed: "list[dict]" = []

    def a_pass():
        tip = settle_checkpoint.spine_tip(s)
        keys = [(ORG, r["slug"], r["nonce"]) for r in listed]
        got = settle_checkpoint.scan(s, kp.public_key_b64, keys=keys, path=cp, scope="*", listed_from=tip,
                                     listing_clean=True, now=NOW)
        want = scan_settlements(s, kp.public_key_b64, keys=keys)
        fields = ("through", "record_seq", "decision", "malformed", "landed")
        assert {k: [getattr(v, f) for f in fields] for k, v in got.items()} == {
            k: [getattr(v, f) for f in fields] for k, v in want.items()}

    listed.append(_reserve(s, units=30, publish=True, hours=8, nonce="a" * 16))
    a_pass()
    _noise(s, 4)
    a_pass()
    _decided_no_marker(monkeypatch, s, listed[0])
    a_pass()
    listed.append(_reserve(s, units=40, publish=True, hours=8, nonce="b" * 16, host=OTHER))
    a_pass()
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert _settle(s, listed[1], 10, basis="cancel").get("retry")         # decision + marker, nothing landed
    restore()
    a_pass()
    assert _settle(s, listed[0], 0, basis="cancel")["ok"] and _settle(s, listed[1], 0, basis="cancel")["ok"]
    a_pass()
    listed.append(_reserve(s, units=50, publish=True, hours=8, nonce="c" * 16, host="third.cm"))
    assert _settle(s, listed[2], 50, basis="completion:completed")["ok"]
    a_pass()
    a_pass()


# =====================================================================================================================
# a spine it cannot read is reported; one bad lease is that lease's failure; a finished settle's notice is kept
# =====================================================================================================================
def test_a_finish_pass_that_cannot_read_the_spine_reports_it_never_nothing_to_finish(record_on, monkeypatch,
                                                                                         capsys):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    _decided_no_marker(monkeypatch, s, rA)                                 # only the spine shows it
    real = SpineStore.iter_records

    def unreadable(self, *a, **k):
        raise SpineError("a sealed segment referenced by the manifest is missing")

    monkeypatch.setattr(SpineStore, "iter_records", unreadable)
    assert LaunchGate(s).interrupted_settlements([rA["lease"]]) == {}     # a report still reports nothing
    with pytest.raises(SpineError):                                        # the pass itself raises it ...
        ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90)
    w = _drain(s, _spool(), {"t": NOW + 60}, scope=rA["slug"])
    assert w.drain() == {**_NONE, "settle_finish_error": "SpineError"}    # ... and the drain reports it
    assert "interrupted settles not checked: SpineError" in capsys.readouterr().err
    monkeypatch.setattr(SpineStore, "iter_records", real)
    assert w.drain() == {**_NONE, "settle_completed": 1} and _avail(s) == 1_000


@pytest.mark.parametrize("ledger", ["wallet", "plan", "postpaid"])
def test_a_finish_pass_that_cannot_read_a_ledger_reports_it_and_alarms_past_the_grace(record_on, monkeypatch, capsys,
                                                                                      ledger):
    s = _store()
    if ledger == "postpaid":
        _seat(s, credits=0, postpaid=(5000, 30))
        cls, name, held = PostpaidArrearsLedger, "has_credit_entry", lambda: PostpaidArrearsLedger(s).accrued(ORG)
    elif ledger == "plan":
        _seat(s, credits=0, plan=1_000)
        cls, name, held = PlanCreditLedger, "has_grant_entry", lambda: 1_000 - _plan(s)
    else:
        _seat(s, credits=1_000)
        cls, name, held = WalletRegistry, "has_grant_entry", lambda: 1_000 - _avail(s)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    _decided_no_marker(monkeypatch, s, rA)                                 # only the spine shows it: nothing moved
    assert held() == 300
    restore = _kill(monkeypatch, cls, name, exc=OSError("the ledger cannot be read"))
    assert LaunchGate(s).interrupted_settlements([rA["lease"]]) == {}     # a report still reports nothing
    with pytest.raises(OSError):                                           # the pass itself raises it ...
        ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90)
    spool, clock = _spool(), {"t": NOW + 60}
    w = _drain(s, spool, clock, scope=rA["slug"])
    assert w.drain() == {**_NONE, "settle_finish_error": "OSError"}       # ... and the drain reports it
    assert "interrupted settles not checked: OSError" in capsys.readouterr().err
    clock["t"] += settle_progress.UNFINISHED_SETTLE_GRACE_S
    assert w.drain() == {**_NONE, "settle_finish_error": "OSError", "settle_stuck": 1}   # past the grace: an alarm
    assert "has failed for more than 600 s (OSError)" in capsys.readouterr().err
    assert settle_progress.overdue(settle_progress.read_state(spool), now=clock["t"]) == ([], "OSError")
    restore()
    clock["t"] += 60
    assert w.drain() == {**_NONE, "settle_completed": 1} and held() == 0  # readable again: finished, once
    assert not settle_progress.state_path(spool).exists() and len(_decisions(s)) == 1


def test_one_unreadable_settlement_marker_is_that_leases_failure_never_the_whole_pass(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    rA = _reserve(s, units=100, publish=True, hours=8, nonce="A" * 16)
    rX = _reserve(s, units=300, publish=True, hours=8, nonce="X" * 16, host=OTHER)
    restore = _kill(monkeypatch, B, "tombstone_credit_lease")              # rA: money landed, marker, still published
    with pytest.raises(SystemExit):
        _settle(s, rA, 0, basis="cancel")
    restore()
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert _settle(s, rX, 0, basis="cancel").get("retry")                 # rX: decision + marker, money pending
    restore()
    real = B.is_lease_settled

    def unreadable(base, slug, nonce):
        if slug == rA["slug"]:
            raise PermissionError(13, "the settlements dir is owned by root")
        return real(base, slug, nonce)

    monkeypatch.setattr(B, "is_lease_settled", unreadable)
    rows = {r["slug"]: r for r in ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90)}
    assert rows[rA["slug"]]["status"] == "settle_failed" and "PermissionError" in rows[rA["slug"]]["error"]
    assert rows[rX["slug"]]["status"] == "settle_completed" and _avail(s) == 1_000


def test_a_crash_later_in_the_pass_keeps_the_notice_of_a_completion_settle_it_finished(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, OTHER))
    r1 = _reserve(s, units=100, publish=True, hours=8, nonce="A" * 16)
    r2 = _reserve(s, units=300, publish=True, hours=8, nonce="B" * 16, host=OTHER)
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    for r in (r1, r2):
        assert _settle(s, r, 0, basis="completion:failed").get("retry")   # decision + marker, money pending
    restore()
    real, calls = WalletRegistry.grant, []

    def grant_then_die(self, *a, **k):
        if calls:
            raise SystemExit("killed mid-pass")
        calls.append(1)
        return real(self, *a, **k)

    monkeypatch.setattr(WalletRegistry, "grant", grant_then_die)
    spool, clock = _spool(), {"t": NOW + 60}
    with pytest.raises(SystemExit):
        _drain(s, spool, clock).drain()
    assert _outcomes(s) == ["failed"]                                     # the finished one's notice is kept
    monkeypatch.setattr(WalletRegistry, "grant", real)
    assert _drain(s, spool, clock).drain() == {**_NONE, "settle_completed": 1}
    assert _outcomes(s) == ["failed", "failed"] and _avail(s) == 1_000
