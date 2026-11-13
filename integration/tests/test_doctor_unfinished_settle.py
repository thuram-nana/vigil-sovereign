"""E3bc — ``vigil doctor`` reports a customer launch whose settle was recorded but has not finished, as a HARD issue.

A settle writes the lease's settlement marker BEFORE it moves any money and retires (tombstones) the lease LAST, so a
lease still published although its marker lists it — past a short grace — is a settle whose refund may not have
landed (and, while it has not, a relaunch on that host is refused with a retry). With ``VIGIL_SETTLE_SPINE_RECORD``
on, the settle drain finishes it on its next pass and retires the lease, after which doctor no longer lists it. With
the flag off nothing is added (default output unchanged). The issue and the report name slugs only, never a nonce.
Real seam files; framework-free (integration leg).

The settle drain also records, beside its completion spool, the recorded settles it has not been able to finish and
since when (``live/settle_progress``) — a settle whose seam marker was never written included, which the marker
probe cannot see — and whether its finish pass itself keeps failing. Doctor reads that record too (the spool from
``VIGIL_SETTLE_SPOOL``, else ``settle-drain.env``, else the unit default) and raises each past the same grace as a
HARD issue; an unreadable record is a note.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the probe dropped / reported as a note                   -> test_doctor_reports_an_unfinished_settle_..._then_clears
  * the flag gate dropped (reported with the record off)     -> test_doctor_adds_nothing_with_the_settle_record_off
  * the flag read from os.environ only (not sigil.env)       -> test_doctor_reads_the_flag_from_sigil_env_too
  * the grace ignored                                        -> test_doctor_adds_nothing_inside_the_grace
  * a settled-and-retired / an unsettled lease listed        -> test_doctor_reports_an_unfinished_settle_..._then_clears
  * the drain's record not read / its grace ignored / gated off
                                                             -> test_doctor_reports_a_settle_the_drain_could_not_finish
  * the drain's failing finish pass not reported             -> test_doctor_reports_a_finish_pass_that_keeps_failing
  * the record's spool read from the wrong place             -> test_doctor_finds_the_drains_spool_in_its_env_file
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import time
from pathlib import Path

import pytest

from vigil_integration import doctor as _doc
from vigil_integration.live import settle_progress
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
    if "VIGIL_SETTLE_SPOOL" not in os.environ:               # never the real ~/.sigil spool of the machine
        monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(tmp_path / "no-spool"))
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


# ---- the settle drain's own record of the settles it could not finish ------------------------------------------
_DRAIN_HIT = "could not be finished by the settle drain"
_PASS_HIT = "finishes interrupted settles has failed"


def _drain_record(tmp_path, monkeypatch, *, age, error=None):
    """The drain's record, as its passes write it, of a settle (or a finish pass) left unfinished ``age`` s ago."""
    spool = tmp_path / "spool"
    spool.mkdir(exist_ok=True)
    monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(spool))
    settle_progress.state_path(spool).unlink(missing_ok=True)                    # a fresh record, never carried
    if error:
        settle_progress.update_state(spool, now=time.time() - age, unfinished=None, error=error)
    else:
        settle_progress.update_state(spool, now=time.time() - age, unfinished=[("cust_held", "nonce-qx7held")])
    return spool


def test_doctor_reports_a_settle_the_drain_could_not_finish(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    (tmp_path / "base").mkdir()                                                # no marker: the probe above is blind
    spool = _drain_record(tmp_path, monkeypatch, age=_doc._UNFINISHED_SETTLE_GRACE_S + 60)
    report = _doctor(tmp_path, monkeypatch)
    assert report["launch_settlements"] == {"drain_unfinished": ["cust_held"]}
    (hit,) = [i for i in report["issues"] if _DRAIN_HIT in i]
    assert hit.startswith("1 recorded customer launch settle(s) could not be finished by the settle drain for more "
                          "than 10 minutes") and "refused with a retry" in hit
    assert report["ok"] is False and "nonce-qx7" not in json.dumps(report["issues"])
    settle_progress.update_state(spool, now=time.time(), unfinished=[])          # the drain's next pass finished it
    report = _doctor(tmp_path, monkeypatch)
    assert "launch_settlements" not in report and not any(_DRAIN_HIT in i for i in report["issues"])
    _drain_record(tmp_path, monkeypatch, age=60)                                 # held, but inside the grace
    report = _doctor(tmp_path, monkeypatch)
    assert "launch_settlements" not in report and not any(_DRAIN_HIT in i for i in report["issues"])
    _drain_record(tmp_path, monkeypatch, age=_doc._UNFINISHED_SETTLE_GRACE_S + 60)
    monkeypatch.delenv("VIGIL_SETTLE_SPINE_RECORD")                              # the record flag off: nothing read
    report = _doctor(tmp_path, monkeypatch)
    assert "launch_settlements" not in report and not any(_DRAIN_HIT in i for i in report["issues"])


def test_doctor_reports_a_finish_pass_that_keeps_failing(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    (tmp_path / "base").mkdir()
    _drain_record(tmp_path, monkeypatch, age=_doc._UNFINISHED_SETTLE_GRACE_S + 60, error="SpineError")
    report = _doctor(tmp_path, monkeypatch)
    assert report["launch_settlements"] == {"drain_error": "SpineError"}
    (hit,) = [i for i in report["issues"] if _PASS_HIT in i]
    assert "(SpineError)" in hit and report["ok"] is False


def test_doctor_finds_the_drains_spool_in_its_env_file(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    (tmp_path / "base").mkdir()
    spool = _drain_record(tmp_path, monkeypatch, age=_doc._UNFINISHED_SETTLE_GRACE_S + 60)
    monkeypatch.delenv("VIGIL_SETTLE_SPOOL")
    cfg = tmp_path / "user" / ".config" / "vigil"
    cfg.mkdir(parents=True)
    (cfg / "settle-drain.env").write_text(f"VIGIL_SETTLE_SPOOL={spool}\n", encoding="utf-8")
    assert _doc._settle_spool_dir() == spool
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    report = _doc.collect(_REPO)
    assert report["launch_settlements"] == {"drain_unfinished": ["cust_held"]}
    (cfg / "settle-drain.env").unlink()                                          # the unit's default spool
    assert _doc._settle_spool_dir() == tmp_path / "user" / ".sigil" / "spool" / "settle"


@pytest.mark.parametrize("how", ["garbage", "oversized", "symlink", "bad_entry"])
def test_an_unreadable_drain_record_is_a_note_not_an_issue(tmp_path, monkeypatch, how):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    (tmp_path / "base").mkdir()
    spool = _drain_record(tmp_path, monkeypatch, age=_doc._UNFINISHED_SETTLE_GRACE_S + 60)   # overdue if it were read
    p = settle_progress.state_path(spool)
    rec = json.loads(p.read_text(encoding="utf-8"))
    if how == "garbage":
        p.write_text("not json", encoding="utf-8")
    elif how == "oversized":                                                    # valid JSON, one byte over the bound
        pad = settle_progress.MAX_BYTES + 1 - len(json.dumps({**rec, "pad": ""}))
        p.write_text(json.dumps({**rec, "pad": "x" * pad}), encoding="utf-8")
        assert p.stat().st_size == settle_progress.MAX_BYTES + 1
    elif how == "symlink":
        real = tmp_path / "elsewhere.json"
        real.write_text(json.dumps(rec), encoding="utf-8")
        p.unlink()
        p.symlink_to(real)
    else:
        rec["leases"][0]["first_seen"] = "long ago"
        p.write_text(json.dumps(rec), encoding="utf-8")
    report = _doctor(tmp_path, monkeypatch)
    assert report["launch_settlements"] == {"drain_record": "unreadable"}
    assert not any(_DRAIN_HIT in i for i in report["issues"])
    assert any("record of unfinished settles" in n and "cannot be read" in n for n in report["notes"])
