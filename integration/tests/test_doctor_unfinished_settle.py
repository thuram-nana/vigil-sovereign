"""E3bc — ``vigil doctor`` reports a customer launch whose settle was recorded but has not finished, as a HARD issue.

A settle writes the lease's settlement marker BEFORE it moves any money and retires (tombstones) the lease LAST, so a
lease still published although its marker lists it — past a short grace — is a settle whose refund may not have
landed (and, while it has not, a relaunch on that host is refused with a retry). With ``VIGIL_SETTLE_SPINE_RECORD``
on, the settle drain finishes it on its next pass and retires the lease, after which doctor no longer lists it. With
the flag off nothing is added (default output unchanged). The issue and the report name slugs only, never a nonce.
Real seam files; framework-free (integration leg).

Mutation-verify targets (each neuter reds a NAMED test here):
  * the probe dropped / reported as a note                   -> test_doctor_reports_an_unfinished_settle_..._then_clears
  * the flag gate dropped (reported with the record off)     -> test_doctor_adds_nothing_with_the_settle_record_off
  * the flag read from os.environ only (not sigil.env)       -> test_doctor_reads_the_flag_from_sigil_env_too
  * the grace ignored                                        -> test_doctor_adds_nothing_inside_the_grace
  * a settled-and-retired / an unsettled lease listed        -> test_doctor_reports_an_unfinished_settle_..._then_clears
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import time
from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration.live.credit_lease_broker import (
    record_lease_settlement, settlement_path, tombstone_credit_lease, unfinished_settlements, write_credit_lease,
)

_REPO = Path(_doc.__file__).resolve().parents[2]
_HIT = "have not finished"


def _publish(base, slug, nonce) -> None:
    """An owner-signed lease for ``slug`` on the seam."""
    from vigil_core import AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease
    kp = generate_keypair()
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                              public_key_b64=kp.public_key_b64)])
    na = _dt.datetime.fromtimestamp(time.time() + 3600, tz=_dt.timezone.utc)
    lease = sign_credit_launch_lease(CreditLaunchLease(
        engagement_slug=slug, org_id="org_a", scope_host="probe.example", units_reserved=10,
        not_before=na - _dt.timedelta(hours=2), not_after=na, nonce=nonce, issued_at=time.time() - 3600),
        {"owner": kp.private_key_b64})
    write_credit_lease(str(base), slug, lease, root)


def _settled_long_ago(base, slug, nonce) -> None:
    """The lease's settle recorded its marker well past the grace ago and never got to retire the lease."""
    record_lease_settlement(str(base), slug, nonce)
    t = time.time() - _doc._UNFINISHED_SETTLE_GRACE_S - 60
    os.utime(settlement_path(str(base), slug), (t, t))


def _doctor(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    return _doc.collect(_REPO)


def _seam(tmp_path):
    b = tmp_path / "base"
    b.mkdir()
    _publish(b, "cust_unfinished", "nonce-qx7unfin")
    _settled_long_ago(b, "cust_unfinished", "nonce-qx7unfin")
    _publish(b, "cust_live", "nonce-qx7live")                                  # a live launch: never listed
    _publish(b, "cust_other", "nonce-qx7new")                                  # the marker lists an OLDER launch
    _settled_long_ago(b, "cust_other", "nonce-qx7old")
    return b


def test_doctor_reports_an_unfinished_settle_as_a_hard_issue_then_clears(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    b = _seam(tmp_path)
    assert unfinished_settlements(str(b), now=time.time(), grace=_doc._UNFINISHED_SETTLE_GRACE_S) == [
        ("cust_unfinished", "nonce-qx7unfin")]
    report = _doctor(tmp_path, monkeypatch)
    assert report["launch_settlements"] == {"unfinished": ["cust_unfinished"]}
    (hit,) = [i for i in report["issues"] if _HIT in i]
    assert hit.startswith("1 customer launch settle(s) were recorded but have not finished")
    assert "settle drain finishes it" in hit and "ops-sweep reservations" in hit
    assert report["ok"] is False
    assert "nonce-qx7" not in json.dumps(report["issues"]) + json.dumps(report["launch_settlements"])   # slugs only
    assert tombstone_credit_lease(str(b), "cust_unfinished", expect_nonce="nonce-qx7unfin")   # the settle's last step
    report = _doctor(tmp_path, monkeypatch)
    assert "launch_settlements" not in report and not any(_HIT in i for i in report["issues"])


def test_doctor_adds_nothing_with_the_settle_record_off(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_SETTLE_SPINE_RECORD", raising=False)
    _seam(tmp_path)
    report = _doctor(tmp_path, monkeypatch)
    assert "launch_settlements" not in report and not any(_HIT in i for i in report["issues"])


def test_doctor_reads_the_flag_from_sigil_env_too(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_SETTLE_SPINE_RECORD", raising=False)
    _seam(tmp_path)
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "sigil.env").write_text("VIGIL_SETTLE_SPINE_RECORD=1\n", encoding="utf-8")
    report = _doctor(tmp_path, monkeypatch)
    assert report["launch_settlements"] == {"unfinished": ["cust_unfinished"]}


def test_doctor_adds_nothing_inside_the_grace(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    b = tmp_path / "base"
    b.mkdir()
    _publish(b, "cust_inflight", "n1")
    record_lease_settlement(str(b), "cust_inflight", "n1")                    # a settle under way right now
    report = _doctor(tmp_path, monkeypatch)
    assert "launch_settlements" not in report and not any(_HIT in i for i in report["issues"])
    assert unfinished_settlements(str(b), now=time.time() + _doc._UNFINISHED_SETTLE_GRACE_S + 1,
                                  grace=_doc._UNFINISHED_SETTLE_GRACE_S) == [("cust_inflight", "n1")]


def test_the_predicate_is_total_on_an_odd_seam(tmp_path):
    b = tmp_path / "base"
    assert unfinished_settlements(str(b), now=time.time(), grace=0) == []    # no seam at all
    b.mkdir()
    _publish(b, "cust_x", "n1")
    root = b / "credit-lease-settlements"
    root.mkdir()
    (root / "cust_x.json").write_text("not json", encoding="utf-8")         # an unreadable marker: no evidence
    assert unfinished_settlements(str(b), now=time.time(), grace=0) == []
