"""E8 — the expired-paused-launch DUE predicate (``live/credit_lease_expiry``) and ``vigil doctor``'s HARD issue.

The settle-drain settles, and doctor reports, exactly the launches ``due_expired_pauses`` lists: a lease on the
seam that is not recorded settled and either (a) is POSITIVELY paused with ``now >= max(not_after, paused_at) +
grace`` (``paused_at`` = the pause marker's mtime) or (b) carries an expiry hold — recorded when an expired lease's
pause was lifted — with ``now >= max(not_after, resumed_at) + grace``. Real seam files throughout; framework-free
(sovereign / integration leg).

Mutation-verify targets (each neuter reds a NAMED test here):
  * an unreadable pause marker counted as paused (fail-closed reader) -> test_only_a_positively_paused_or_expiry_held_lease_is_ever_due
  * the pause marker's mtime ignored (a late pause gets no grace)     -> test_a_pause_recorded_after_the_window_gets_the_whole_grace
  * the hold's resume time ignored                                    -> test_only_a_positively_paused_or_expiry_held_lease_is_ever_due
  * a settled lease still listed                                      -> test_a_settled_lease_is_never_due
  * re-recording a hold keeps the EARLIER resume                      -> test_re_recording_a_hold_keeps_the_later_resume
  * an unreadable / non-finite grace shortens it                      -> test_the_grace_comes_from_the_env_and_never_shrinks_on_garbage
  * a hold file that cannot be read counts as a hold                  -> test_an_unreadable_hold_is_no_hold
  * doctor drops the expired-unsettled issue / makes it a note        -> test_doctor_reports_an_expired_unsettled_paused_launch_as_a_hard_issue
  * doctor always adds the "expired_unsettled" key                    -> test_doctor_is_unchanged_inside_the_grace
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import time
from pathlib import Path

import pytest

from vigil_integration import doctor as _doc
from vigil_integration.live.credit_lease_broker import record_lease_settlement, write_credit_lease
from vigil_integration.live.credit_lease_expiry import (
    DEFAULT_GRACE_SECONDS, due_expired_pauses, expiry_hold_at, holds_root, record_expiry_hold, settle_due_at,
    settle_grace_seconds,
)
from vigil_integration.live.credit_lease_pause import clear_lease_pause, pause_path, record_lease_pause

_REPO = Path(_doc.__file__).resolve().parents[2]
G = 1000.0


@pytest.fixture(autouse=True)
def _grace(monkeypatch):
    monkeypatch.delenv("VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS", raising=False)


def _publish(base, slug, nonce, *, not_after: float) -> None:
    """An owner-signed lease for ``slug`` on the seam whose window ends at ``not_after`` (POSIX seconds)."""
    from vigil_core import AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease
    kp = generate_keypair()
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                              public_key_b64=kp.public_key_b64)])
    na = _dt.datetime.fromtimestamp(not_after, tz=_dt.timezone.utc)
    lease = sign_credit_launch_lease(CreditLaunchLease(
        engagement_slug=slug, org_id="org_a", scope_host="probe.example", units_reserved=10,
        not_before=na - _dt.timedelta(hours=9), not_after=na, nonce=nonce, issued_at=not_after - 9 * 3600),
        {"owner": kp.private_key_b64})
    write_credit_lease(base, slug, lease, root)


def _set_mtime(path, t: float) -> None:
    os.utime(path, (t, t))


# ------------------------------------------------------------------------------------------------ the predicate
def test_only_a_positively_paused_or_expiry_held_lease_is_ever_due(tmp_path):
    b = str(tmp_path)
    na = time.time() - 10 * G
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) is None              # neither paused nor held
    record_lease_pause(b, "cust_a", "n1")
    _set_mtime(pause_path(b, "cust_a"), na - 60)                              # paused inside the window
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + G)
    assert settle_due_at(b, "cust_a", "n2", na, grace=G) is None              # nonce-scoped
    pause_path(b, "cust_a").write_text("{corrupt", encoding="utf-8")          # the HALT reader holds on this ...
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) is None              # ... but it is no evidence to refund
    record_expiry_hold(b, "cust_a", "n1", resumed_at=na + 300)                # resumed after the window closed
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + 300 + G)


def test_a_pause_recorded_after_the_window_gets_the_whole_grace(tmp_path):
    # pause_launch accepts an expired lease (it is the stop control of a run still in flight past not_after), so
    # the grace runs from the pause, not from the window end.
    b = str(tmp_path)
    na = time.time() - 10 * G
    record_lease_pause(b, "cust_a", "n1")
    _set_mtime(pause_path(b, "cust_a"), na + 5 * G)
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + 6 * G)


def test_a_settled_lease_is_never_due(tmp_path):
    b = str(tmp_path)
    na = time.time() - 10 * G
    _publish(b, "cust_a", "n1", not_after=na)
    record_lease_pause(b, "cust_a", "n1")
    _set_mtime(pause_path(b, "cust_a"), na - 60)
    (d,) = due_expired_pauses(b, now=na + G + 1, grace=G)
    assert (d.slug, d.nonce, d.not_after) == ("cust_a", "n1", pytest.approx(na))
    assert due_expired_pauses(b, now=na + G - 1, grace=G) == []               # not yet
    record_lease_settlement(b, "cust_a", "n1")
    assert due_expired_pauses(b, now=na + G + 1, grace=G) == []


def test_re_recording_a_hold_keeps_the_later_resume(tmp_path):
    b = str(tmp_path)
    record_expiry_hold(b, "cust_a", "n1", resumed_at=200.0)
    record_expiry_hold(b, "cust_a", "n1", resumed_at=100.0)                   # a clock step back never shortens it
    record_expiry_hold(b, "cust_a", "n2", resumed_at=50.0)                    # another launch of the slug
    assert expiry_hold_at(b, "cust_a", "n1") == 200.0 and expiry_hold_at(b, "cust_a", "n2") == 50.0
    record_expiry_hold(b, "cust_a", "n1", resumed_at=300.0)
    assert expiry_hold_at(b, "cust_a", "n1") == 300.0
    with pytest.raises(ValueError):
        record_expiry_hold(b, "../x", "n1", resumed_at=1.0)                   # never writes outside its dir


def test_an_unreadable_hold_is_no_hold(tmp_path):
    b = str(tmp_path)
    record_expiry_hold(b, "cust_a", "n1", resumed_at=100.0)
    p = holds_root(b) / "cust_a.json"
    for bad in ("{corrupt", json.dumps({"kind": "something-else", "holds": {"n1": 100.0}}),
                json.dumps({"kind": "vigil-credit-lease-expiry-hold-v1", "holds": {"n1": "100"}}),
                json.dumps({"kind": "vigil-credit-lease-expiry-hold-v1", "holds": {"n1": True}})):
        p.write_text(bad, encoding="utf-8")
        assert expiry_hold_at(b, "cust_a", "n1") is None, bad
        assert settle_due_at(b, "cust_a", "n1", 0.0, grace=0.0) is None, bad


def test_the_grace_comes_from_the_env_and_never_shrinks_on_garbage(monkeypatch):
    assert settle_grace_seconds() == DEFAULT_GRACE_SECONDS == 86400.0
    monkeypatch.setenv("VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS", "3600")
    assert settle_grace_seconds() == 3600.0
    for bad in ("-1", "nan", "inf", "soon"):
        monkeypatch.setenv("VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS", bad)
        assert settle_grace_seconds() == DEFAULT_GRACE_SECONDS, bad


# --------------------------------------------------------------------------------------------------- doctor
def _doctor(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    return _doc.collect(_REPO)


def test_doctor_reports_an_expired_unsettled_paused_launch_as_a_hard_issue(tmp_path, monkeypatch):
    b = tmp_path / "base"
    b.mkdir()
    na = time.time() - DEFAULT_GRACE_SECONDS - 600
    _publish(str(b), "cust_strand", "nonce-qx7strand", not_after=na)                        # paused until its window closed
    record_lease_pause(str(b), "cust_strand", "nonce-qx7strand")
    _set_mtime(pause_path(str(b), "cust_strand"), na - 60)
    _publish(str(b), "cust_resumed", "nonce-qx7resumed", not_after=na)                       # resumed after its window closed
    record_lease_pause(str(b), "cust_resumed", "nonce-qx7resumed")
    record_expiry_hold(str(b), "cust_resumed", "nonce-qx7resumed", resumed_at=na + 60)
    clear_lease_pause(str(b), "cust_resumed", "nonce-qx7resumed")
    _publish(str(b), "cust_done", "nonce-qx7done", not_after=na)                          # settled: nothing stranded
    record_lease_pause(str(b), "cust_done", "nonce-qx7done")
    record_lease_settlement(str(b), "cust_done", "nonce-qx7done")
    report = _doctor(tmp_path, monkeypatch)
    assert report["paused_launches"]["expired_unsettled"] == ["cust_resumed", "cust_strand"]
    (hit,) = [i for i in report["issues"] if "NOT settled" in i]
    assert hit.startswith("2 paused customer launch(es) whose lease window closed")
    assert "VIGIL_PAUSED_EXPIRY_SETTLE=1" in hit and "ops-sweep reservations --apply" in hit
    assert report["ok"] is False
    assert "nonce-qx7strand" not in json.dumps(report["issues"]) and "nonce-qx7resumed" not in json.dumps(report["issues"])   # no nonce


def test_doctor_is_unchanged_inside_the_grace(tmp_path, monkeypatch):
    b = tmp_path / "base"
    b.mkdir()
    na = time.time() - 600                                                     # closed, but inside the grace
    _publish(str(b), "cust_exp", "n1", not_after=na)
    record_lease_pause(str(b), "cust_exp", "n1")
    report = _doctor(tmp_path, monkeypatch)
    assert "expired_unsettled" not in report["paused_launches"]
    assert report["paused_launches"]["expired"]["slugs"] == ["cust_exp"]       # still the advisory note only
    assert not any("NOT settled" in i for i in report["issues"])
