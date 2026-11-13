"""E8 — the expired-paused-launch DUE predicate (``live/credit_lease_expiry``) and ``vigil doctor``'s HARD issue.

The settle-drain settles, and doctor reports, exactly the launches ``due_expired_pauses`` lists: a lease on the
seam that is not recorded settled and is (a) POSITIVELY paused (evidence time = the pause marker's mtime) and/or
(b) on the paused-past-expiry record a late resume writes (evidence time = the record's mtime), with ``now >=
max(not_after, every evidence time) + grace``. Real seam files throughout; framework-free (sovereign / integration
leg).
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
    DEFAULT_GRACE_SECONDS, due_expired_pauses, settle_due_at, settle_grace_seconds,
)
from vigil_integration.live.credit_lease_pause import (
    _past_expiry_path, clear_lease_pause, pause_path, record_lease_pause, record_paused_past_expiry,
)

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


def _late_resume(b, slug, nonce, at: float) -> None:
    """What ``LaunchGate.resume_launch`` does for an expired paused lease at ``at``: record, then clear."""
    record_paused_past_expiry(b, slug, nonce)
    _set_mtime(_past_expiry_path(b, slug), at)
    clear_lease_pause(b, slug, nonce)


# ------------------------------------------------------------------------------------------------ the predicate
def test_only_a_positively_paused_or_late_resumed_lease_is_ever_due(tmp_path):
    b = str(tmp_path)
    na = time.time() - 10 * G
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) is None              # neither paused nor resumed late
    record_lease_pause(b, "cust_a", "n1")
    _set_mtime(pause_path(b, "cust_a"), na - 60)                              # paused inside the window
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + G)
    assert settle_due_at(b, "cust_a", "n2", na, grace=G) is None              # nonce-scoped
    pause_path(b, "cust_a").write_text("{corrupt", encoding="utf-8")          # the HALT reader holds on this ...
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) is None              # ... but it is no evidence to settle
    record_paused_past_expiry(b, "cust_a", "n1")                              # resumed after the window closed
    _set_mtime(_past_expiry_path(b, "cust_a"), na + 300)
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + 300 + G)
    assert settle_due_at(b, "cust_a", "n2", na, grace=G) is None              # nonce-scoped


def test_a_pause_recorded_after_the_window_gets_the_whole_grace(tmp_path):
    b = str(tmp_path)
    na = time.time() - 10 * G
    record_lease_pause(b, "cust_a", "n1")
    _set_mtime(pause_path(b, "cust_a"), na + 5 * G)
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + 6 * G)


def test_a_pause_and_a_late_resume_together_wait_for_the_later_of_the_two(tmp_path):
    # a late resume followed by a fresh pause of the still-running launch, and the reverse order
    b = str(tmp_path)
    na = time.time() - 10 * G
    _late_resume(b, "cust_a", "n1", na + 300)
    record_lease_pause(b, "cust_a", "n1")
    _set_mtime(pause_path(b, "cust_a"), na + 5 * G)
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + 6 * G)
    _set_mtime(_past_expiry_path(b, "cust_a"), na + 7 * G)
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + 8 * G)


def test_the_pause_marker_is_read_before_the_late_resume_record(tmp_path, monkeypatch):
    # a late resume landing exactly while the predicate reads: it writes the record BEFORE it clears the pause, so
    # with the marker read first the predicate sees the pause or the record — never "never paused"
    import vigil_integration.live.credit_lease_expiry as cle
    b = str(tmp_path)
    na = time.time() - 10 * G
    record_lease_pause(b, "cust_a", "n1")
    real = cle.lease_pause_state

    def _resume_lands_now(base, slug, nonce):
        _late_resume(b, "cust_a", "n1", na + 300)
        return real(base, slug, nonce)

    monkeypatch.setattr(cle, "lease_pause_state", _resume_lands_now)
    assert settle_due_at(b, "cust_a", "n1", na, grace=G) == pytest.approx(na + 300 + G)


def test_the_predicate_never_raises_on_a_racing_or_odd_store(tmp_path, monkeypatch):
    # a marker read as paused can be gone by the time its time is read, and a slug can be unaddressable: each is
    # "no evidence", never an exception that sinks the drain or doctor
    import vigil_integration.live.credit_lease_expiry as cle
    b = str(tmp_path)
    monkeypatch.setattr(cle, "lease_pause_state", lambda base, slug, nonce: True)
    monkeypatch.setattr(cle, "paused_past_expiry", lambda base, slug, nonce: True)
    assert settle_due_at(b, "cust_gone", "n1", 0.0, grace=0.0) is None       # no file behind either record
    assert settle_due_at(b, "a b", "n1", 0.0, grace=0.0) is None             # an unsafe slug: no path at all

    def _boom(*a, **k):
        raise RuntimeError("store went away")

    monkeypatch.setattr(cle, "lease_pause_state", _boom)
    assert settle_due_at(b, "cust_a", "n1", 0.0, grace=0.0) is None


def test_an_unreadable_late_resume_record_is_no_evidence(tmp_path):
    b = str(tmp_path)
    na = time.time() - 10 * G
    _late_resume(b, "cust_a", "n1", na + 300)
    p = _past_expiry_path(b, "cust_a")
    for bad in ("{corrupt", json.dumps({"kind": "something-else", "nonces": ["n1"]})):
        p.write_text(bad, encoding="utf-8")
        assert settle_due_at(b, "cust_a", "n1", na, grace=G) is None, bad


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
    _publish(str(b), "cust_strand", "nonce-qx7strand", not_after=na)          # paused until its window closed
    record_lease_pause(str(b), "cust_strand", "nonce-qx7strand")
    _set_mtime(pause_path(str(b), "cust_strand"), na - 60)
    _publish(str(b), "cust_resumed", "nonce-qx7resumed", not_after=na)        # resumed after its window closed
    record_lease_pause(str(b), "cust_resumed", "nonce-qx7resumed")
    _late_resume(str(b), "cust_resumed", "nonce-qx7resumed", na + 60)
    _publish(str(b), "cust_done", "nonce-qx7done", not_after=na)              # settled: nothing held
    record_lease_pause(str(b), "cust_done", "nonce-qx7done")
    record_lease_settlement(str(b), "cust_done", "nonce-qx7done")
    report = _doctor(tmp_path, monkeypatch)
    assert report["paused_launches"]["expired_unsettled"] == ["cust_resumed", "cust_strand"]
    (hit,) = [i for i in report["issues"] if "NOT settled" in i]
    assert hit.startswith("2 paused customer launch(es) whose lease window closed")
    assert "VIGIL_PAUSED_EXPIRY_SETTLE=1" in hit and "ops-sweep reservations --apply" in hit
    assert report["ok"] is False
    issues = json.dumps(report["issues"])
    assert "nonce-qx7strand" not in issues and "nonce-qx7resumed" not in issues    # never a nonce


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
