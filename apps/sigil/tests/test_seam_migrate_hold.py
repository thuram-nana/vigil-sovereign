"""A launch the seam migration HELD for the owner is never settled by any automatic path.

`sigil seam migrate --apply` holds an unsettled legacy launch it cannot hand to the settle drain (its window closed and
no completion names it anywhere in the spool). Held means no money moves until the owner decides: the settle drain's
expired-pause pass (``VIGIL_PAUSED_EXPIRY_SETTLE``), the abandoned-reservation sweep and the superseded-reservation
sweep each report it ``legacy_hold`` and settle nothing — checked up front and again INSIDE the settle's critical
section, where the migration commits its holds. While the migration journal exists but cannot be read, a held launch
cannot be ruled out, so none of them settles any launch (``journal_unreadable``).

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the expiry pass ignores the hold (up front)        -> test_a_held_paused_launch_is_never_settled_by_the_drain
  * the in-lock hold re-check dropped (each path)      -> test_a_hold_committed_before_the_settle_is_honoured_inside_it
  * the in-lock re-check ignores an unreadable journal -> test_a_hold_committed_before_the_settle_is_honoured_inside_it
  * an unreadable journal holds nothing (each path)    -> test_an_unreadable_journal_settles_nothing
"""
from __future__ import annotations

import time

import pytest

from sigil import ops_sweeps
from sigil.paused_expiry_settle import settle_expired_paused_launches
from sigil.ui.launch_gate import LaunchGate
from vigil_integration import seam_migration as sm
from vigil_integration.live.credit_lease_broker import is_lease_settled
from vigil_integration.live.credit_lease_pause import record_lease_pause

from tests.test_seam_migrate import LATE, NOW, _avail, _move, _reserve, _seat, _store, make_trees  # type: ignore
from tests.test_seam_migrate_requeue import _apply, _deleg, _drain  # type: ignore

FAR = time.time() + 400_000            # past every window and the expiry grace (the pause record is at the real clock)


@pytest.fixture
def trees(monkeypatch, tmp_path):
    legacy, seam, spool = make_trees(monkeypatch, tmp_path)
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    return legacy, seam, spool


def _held_paused_launch(trees, monkeypatch):
    """A paused legacy launch, expired with no completion: the migration holds it (and debits stay)."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    record_lease_pause(str(legacy), r["slug"], r["nonce"])                  # the customer paused it
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool)
    assert code == 1 and sm.held_launches(seam) == {(r["slug"], r["nonce"])}, rep
    assert _avail(s) == 70
    return s, r


@pytest.mark.parametrize("billing", ["flat", "metered"])
def test_a_held_paused_launch_is_never_settled_by_the_drain(trees, monkeypatch, billing):
    """Nothing is settled, and nothing is read or closed for it either: a metered launch's model meter stays open."""
    from sigil import config
    from sigil.model_gateway import GrantMeter
    from vigil_core import model_metering as mm
    from vigil_core.model_grant import meter_id
    _legacy, seam, spool = trees
    if billing == "metered":                                               # published metered (a test markup)
        monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
        monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
        monkeypatch.setenv(mm.CANCEL_ENV, "metered")
    s, r = _held_paused_launch(trees, monkeypatch)
    assert bool(LaunchGate(s)._launch_was_metered(r["slug"], r["nonce"])) is (billing == "metered")
    monkeypatch.setenv("VIGIL_PAUSED_EXPIRY_SETTLE", "1")
    _gov, deleg = _deleg()
    out = _drain(s, spool, deleg, seam, now=FAR)
    assert out["expired_settled"] == 0 and out["expired_unsettled"] == 1, out
    rows = settle_expired_paused_launches(LaunchGate(s), now=FAR, completion_spool=spool)
    assert [(x["nonce"], x["status"]) for x in rows] == [(r["nonce"], "legacy_hold")]
    assert not is_lease_settled(str(seam), r["slug"], r["nonce"]) and _avail(s) == 70
    assert not GrantMeter(config.MODEL_METER_DIR).is_closed(meter_id(r["slug"], r["nonce"]))


def _hold_on_settle(monkeypatch, gate, seam, method, change):
    """Right before the settle takes its lock, commit a hold for the launch being settled (as the migration does,
    under that lock) or leave the journal unreadable: the up-front read saw neither."""
    real = getattr(gate, method)

    def _wrapped(*a, **kw):
        if method == "settle_launch":
            doc = kw["signed_lease"]["document"]
            slug, nonce = doc["engagement_slug"], doc["nonce"]
        else:
            slug, nonce = kw["slug"], kw["nonce"]
        j = sm.new_journal(seam)
        j["sources"]["/former"] = {"state": "complete", "held": [{"slug": slug, "nonce": nonce, "why": "test"}]}
        sm.write_journal(seam, j)
        if change == "journal_unreadable":
            sm.journal_path(seam).write_text("{truncated")
        return real(*a, **kw)
    monkeypatch.setattr(gate, method, _wrapped)


def _superseded_on_seam(s):
    """Launch 1 on the seam, then launch 2 of the same target replaces its lease: launch 1 is superseded."""
    _seat(s)
    first = _reserve(s)
    _reserve(s, now=NOW + 100)
    return first


@pytest.mark.parametrize("change", ["legacy_hold", "journal_unreadable"])
@pytest.mark.parametrize("path", ["expiry_pass", "abandoned", "superseded"])
def test_a_hold_committed_before_the_settle_is_honoured_inside_it(trees, monkeypatch, path, change):
    _legacy, seam, spool = trees
    _move(monkeypatch, seam)
    s = _store()
    if path == "superseded":
        r = _superseded_on_seam(s)
        before = _avail(s)
        gate = LaunchGate(s)
        _hold_on_settle(monkeypatch, gate, seam, "release_superseded_reservation", change)
        out = ops_sweeps.sweep_superseded_reservations(gate, now=LATE + 700_000, ttl_s=50, apply=True,
                                                       completion_spool=str(spool))
        rows = [x for x in out["items"] if x["nonce"] == r["nonce"]]
    else:
        _seat(s)
        r = _reserve(s)
        if path == "expiry_pass":
            record_lease_pause(str(seam), r["slug"], r["nonce"])
        before = _avail(s)
        gate = LaunchGate(s)
        _hold_on_settle(monkeypatch, gate, seam, "settle_launch", change)
        if path == "expiry_pass":
            rows = settle_expired_paused_launches(gate, now=FAR, completion_spool=spool)
        else:
            rows = ops_sweeps.sweep_abandoned_reservations(gate, now=LATE + 90_000, ttl_s=50, apply=True,
                                                           completion_spool=str(spool))["items"]
    assert [x["status"] for x in rows] == [change], rows
    assert not is_lease_settled(str(seam), r["slug"], r["nonce"]) and _avail(s) == before


@pytest.mark.parametrize("path,apply,billing", [
    ("expiry_pass", True, "flat"), ("expiry_pass", True, "metered"), ("abandoned", False, "flat"),
    ("abandoned", True, "flat"), ("superseded", False, "flat"), ("superseded", True, "flat")])
def test_an_unreadable_journal_settles_nothing(trees, monkeypatch, path, apply, billing):
    from sigil import config
    from sigil.model_gateway import GrantMeter
    from vigil_core import model_metering as mm
    from vigil_core.model_grant import meter_id
    _legacy, seam, spool = trees
    if billing == "metered":
        monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
        monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
        monkeypatch.setenv(mm.CANCEL_ENV, "metered")
    s, r = _held_paused_launch(trees, monkeypatch)
    if path == "superseded":
        _reserve(s, now=LATE + 10)                                         # a later launch replaces it on the seam
    sm.journal_path(seam).write_text("{truncated")
    with pytest.raises(ValueError):
        sm.held_launches(seam)
    before = _avail(s)
    gate = LaunchGate(s)
    if path == "expiry_pass":                                              # (it has no report-only mode)
        rows = settle_expired_paused_launches(gate, now=FAR, completion_spool=spool)
    elif path == "abandoned":
        rows = ops_sweeps.sweep_abandoned_reservations(gate, now=FAR, ttl_s=50, apply=apply,
                                                       completion_spool=str(spool))["items"]
    else:
        rows = ops_sweeps.sweep_superseded_reservations(gate, now=FAR, ttl_s=50, apply=apply,
                                                        completion_spool=str(spool))["items"]
    rows = [x for x in rows if x["nonce"] == r["nonce"]]
    assert [x["status"] for x in rows] == ["journal_unreadable"], rows
    assert not is_lease_settled(str(seam), r["slug"], r["nonce"]) and _avail(s) == before
    assert not GrantMeter(config.MODEL_METER_DIR).is_closed(meter_id(r["slug"], r["nonce"]))
