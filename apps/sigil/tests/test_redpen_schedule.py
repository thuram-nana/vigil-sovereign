"""Red-Pen R4 — the owner-signed per-repo System-review SCHEDULE registry (``governor/redpen_schedule.py``).

Invariants pinned here (each guard has a named test the mutation table reds):
  * a schedule is OWNER-SIGNED: a record signed by any other key is inert, a tampered record is inert, an unsigned
    active record is inert, and the cadence is inside the signed bytes;
  * anti-replay: a captured active record cannot resurrect a cleared schedule; a FRESH owner record re-activates;
  * clearing is the SAFE direction — honored even unsigned (never fails open);
  * a schedule is only set for a repository CURRENTLY connected for that org (necessary-not-sufficient);
  * weekly / monthly DUE is computed per calendar period (ISO week incl. the year boundary; calendar month), at most
    once per period, re-arming the next period;
  * a FORGED enqueue marker can never suppress a due review (fail-safe);
  * cross-tenant isolation: one org can neither read, schedule nor trigger another org's repository;
  * hard-prune durability: the tripwire refuses a prune that would strand a schedule's deciding record.
"""
from __future__ import annotations

import itertools
import tempfile
from datetime import datetime, timezone

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.redpen_schedule import (
    RUN_SIGNAL, SIGNAL, RedPenScheduleRegistry, period_key,
)
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)
ORG, OTHER, REPO = "acme", "evil", "github.com/acme/widgets"


def _ts(y: int, mo: int, d: int, h: int = 12, mi: int = 0) -> float:
    return datetime(y, mo, d, h, mi, tzinfo=timezone.utc).timestamp()


MON_W47 = _ts(2026, 11, 16)          # Monday of ISO week 2026-W47
SUN_W47 = _ts(2026, 11, 22, 23, 59)  # the last minute of 2026-W47
MON_W48 = _ts(2026, 11, 23)          # Monday of ISO week 2026-W48


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return RedPenScheduleRegistry(store, owner_key=key, trusted_pubkey=pub)


def _connect(store, org=ORG, repo=REPO, issued_at=None):
    ConnectedRepoRegistry(store, owner_key=OWNER, trusted_pubkey=OP).connect(
        org, 42, repo, issued_at=float(next(_c)) if issued_at is None else issued_at)


# ---- the owner signature ------------------------------------------------------------------------------------
def test_an_owner_signed_schedule_is_active_with_its_cadence():
    s = _store()
    _connect(s)
    _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=10.0)
    assert _reg(s).active(ORG, REPO) == "weekly"
    assert _reg(s).schedules_of_org(ORG) == [(REPO, "weekly")]


def test_a_schedule_signed_by_a_non_owner_key_is_refused():
    s = _store()
    _connect(s)
    RedPenScheduleRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP).set_schedule(
        ORG, REPO, cadence="weekly", issued_at=10.0)
    assert _reg(s).active(ORG, REPO) is None                   # signed under the attacker key -> inert
    assert _reg(s).due(MON_W47) == []                          # ... and it can never trigger a review


def test_an_unsigned_or_tampered_active_record_is_inert():
    s = _store()
    _connect(s)
    unsigned = {"signal": SIGNAL, "org_id": ORG, "repo": REPO, "cadence": "weekly", "state": "active",
                "issued_at": 5.0}
    s.append(kind="event", source="governor", actor="WARDEN", payload=unsigned)
    assert _reg(s).active(ORG, REPO) is None
    # an owner-signed weekly record re-labelled monthly (the cadence is inside the signed bytes) is inert
    good = signed_payload({"signal": SIGNAL, "org_id": ORG, "repo": REPO, "cadence": "weekly", "state": "active",
                           "issued_at": 6.0}, OWNER)
    s.append(kind="event", source="governor", actor="WARDEN", payload={**good, "cadence": "monthly", "issued_at": 7.0})
    assert _reg(s).active(ORG, REPO) is None
    s.append(kind="event", source="governor", actor="WARDEN", payload=good)
    assert _reg(s).active(ORG, REPO) == "weekly"


def test_setting_a_schedule_requires_the_owner_signing_key():
    s = _store()
    _connect(s)
    with pytest.raises(ValueError, match="owner signing key"):
        RedPenScheduleRegistry(s, owner_key=None, trusted_pubkey=OP).set_schedule(
            ORG, REPO, cadence="weekly", issued_at=1.0)


def test_an_unknown_cadence_is_refused_and_a_signed_bad_cadence_is_inert():
    s = _store()
    _connect(s)
    with pytest.raises(ValueError, match="cadence"):
        _reg(s).set_schedule(ORG, REPO, cadence="daily", issued_at=1.0)
    bad = signed_payload({"signal": SIGNAL, "org_id": ORG, "repo": REPO, "cadence": "daily", "state": "active",
                          "issued_at": 2.0}, OWNER)
    s.append(kind="event", source="governor", actor="WARDEN", payload=bad)
    assert _reg(s).active(ORG, REPO) is None


# ---- anti-replay + the safe direction -----------------------------------------------------------------------
def test_a_captured_active_record_cannot_resurrect_a_cleared_schedule():
    s = _store()
    _connect(s)
    r = _reg(s)
    r.set_schedule(ORG, REPO, cadence="weekly", issued_at=10.0)
    captured = [rec.payload for rec in s.iter_records() if rec.payload.get("signal") == SIGNAL][-1]
    r.clear_schedule(ORG, REPO)
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay the signed record
    assert r.active(ORG, REPO) is None and r.due(MON_W47) == []
    r.set_schedule(ORG, REPO, cadence="monthly", issued_at=20.0)                  # a FRESH owner record re-activates
    assert r.active(ORG, REPO) == "monthly"


def test_clearing_is_the_safe_direction_honored_even_unsigned():
    s = _store()
    _connect(s)
    _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=10.0)
    RedPenScheduleRegistry(s, owner_key=None, trusted_pubkey=OP).clear_schedule(ORG, REPO)   # no signing key
    assert _reg(s).active(ORG, REPO) is None and _reg(s).due(MON_W47) == []


# ---- the connected-repo authorization (necessary, not sufficient) -------------------------------------------
def test_a_schedule_is_refused_for_a_repository_that_is_not_connected():
    s = _store()
    with pytest.raises(ValueError, match="not connected"):
        _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=1.0)
    _connect(s)
    ConnectedRepoRegistry(s, owner_key=OWNER, trusted_pubkey=OP).disconnect(ORG, REPO)
    with pytest.raises(ValueError, match="not connected"):
        _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=2.0)
    _connect(s)
    _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=3.0)
    assert _reg(s).active(ORG, REPO) == "weekly"


# ---- weekly / monthly due -----------------------------------------------------------------------------------
@pytest.mark.parametrize("when,expected", [
    (_ts(2026, 11, 16), "2026-W47"),
    (_ts(2026, 12, 31), "2026-W53"),        # 2026 has 53 ISO weeks (1 Jan 2026 is a Thursday)
    (_ts(2027, 1, 1), "2026-W53"),          # the ISO YEAR, not the calendar year: still 2026's last week
    (_ts(2027, 1, 4), "2027-W01"),
])
def test_the_weekly_period_is_the_iso_week_across_the_year_boundary(when, expected):
    assert period_key("weekly", when) == expected


@pytest.mark.parametrize("when,expected", [
    (_ts(2026, 11, 30, 23, 59), "2026-11"),
    (_ts(2026, 12, 1, 0, 0), "2026-12"),
])
def test_the_monthly_period_is_the_calendar_month(when, expected):
    assert period_key("monthly", when) == expected


def test_a_weekly_schedule_is_due_once_per_iso_week():
    s = _store()
    _connect(s)
    r = _reg(s)
    r.set_schedule(ORG, REPO, cadence="weekly", issued_at=10.0)
    assert r.due(MON_W47) == [(ORG, REPO, "weekly")]
    r.record_enqueue(ORG, REPO, period=period_key("weekly", MON_W47), now=MON_W47)
    assert r.due(MON_W47) == [] and r.due(SUN_W47) == []       # the rest of the week: already enqueued
    assert r.due(MON_W48) == [(ORG, REPO, "weekly")]           # re-armed the next ISO week


def test_a_monthly_schedule_is_due_once_per_calendar_month():
    s = _store()
    _connect(s)
    r = _reg(s)
    r.set_schedule(ORG, REPO, cadence="monthly", issued_at=10.0)
    nov, end_nov, dec = _ts(2026, 11, 16), _ts(2026, 11, 30, 23, 59), _ts(2026, 12, 1, 0, 30)
    assert r.due(nov) == [(ORG, REPO, "monthly")]
    r.record_enqueue(ORG, REPO, period=period_key("monthly", nov), now=nov)
    assert r.due(end_nov) == []
    assert r.due(dec) == [(ORG, REPO, "monthly")]


def test_a_forged_enqueue_marker_never_suppresses_a_due_review():
    s = _store()
    _connect(s)
    _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=10.0)
    forged = signed_payload({"signal": RUN_SIGNAL, "org_id": ORG, "repo": REPO, "period": "2026-W47",
                             "issued_at": MON_W47}, ATTACKER)
    s.append(kind="event", source="governor", actor="WARDEN", payload=forged)
    assert _reg(s).last_enqueued_period(ORG, REPO) is None
    assert _reg(s).due(MON_W47) == [(ORG, REPO, "weekly")]      # still due: a forgery is fail-SAFE


def test_recording_an_enqueue_requires_the_owner_key_and_a_clean_period():
    s = _store()
    _connect(s)
    with pytest.raises(ValueError, match="owner signing key"):
        RedPenScheduleRegistry(s, owner_key=None, trusted_pubkey=OP).record_enqueue(
            ORG, REPO, period="2026-W47", now=MON_W47)
    for bad in ("", "a:b"):
        with pytest.raises(ValueError, match="period"):
            _reg(s).record_enqueue(ORG, REPO, period=bad, now=MON_W47)


# ---- cross-tenant isolation ---------------------------------------------------------------------------------
def test_one_org_can_neither_read_schedule_nor_trigger_another_orgs_repository():
    s = _store()
    _connect(s)                                                  # REPO is connected for ORG only
    _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=10.0)
    assert _reg(s).active(OTHER, REPO) is None
    assert _reg(s).schedules_of_org(OTHER) == []
    with pytest.raises(ValueError, match="not connected"):       # OTHER cannot schedule ORG's repository
        _reg(s).set_schedule(OTHER, REPO, cadence="monthly", issued_at=11.0)
    _reg(s).clear_schedule(OTHER, REPO)                          # OTHER's clear names OTHER's key only ...
    assert _reg(s).active(ORG, REPO) == "weekly"                 # ... so ORG's schedule is untouched
    assert [o for o, _r, _c in _reg(s).due(MON_W47)] == [ORG]


# ---- hard-prune durability (real sealed segments, mirrors the connected-repo tripwire tests) -------------------
def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def _segmented(tmp_path, *, clear=False):
    """The connect (seq 0) + schedule (seq 1) [+ clear, seq 2] in the FIRST sealed segment, then a second sealed
    segment and a live tail — so a prune to K=5 archives the schedule's deciding record."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _connect(s, issued_at=2.0)                                                  # seq 0
    _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=3.0)           # seq 1
    if clear:
        _reg(s).clear_schedule(ORG, REPO)                                      # seq 2 (tombstone)
    while s.next_seq < 5:
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})
    s.rotate()                                                                 # seal [0..4]
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})  # seq 5..9
    s.rotate()                                                                 # seal [5..9]
    _connect(s, issued_at=50.0)                  # the CONNECTION is re-asserted live, so only the schedule strands
    return s


def test_the_prune_tripwire_refuses_stranding_an_active_schedule(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    assert prune.stranded_active_redpen_schedules(s, _archived_below(s, 5), 5) == [f"{REPO}@{ORG}"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert f"{REPO}@{ORG}" in str(e.value) and "Red-Pen schedule" in str(e.value)


def test_the_prune_tripwire_allows_a_schedule_re_signed_live(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    _reg(s).set_schedule(ORG, REPO, cadence="weekly", issued_at=99.0)          # re-sign LIVE (seq >= 5)
    assert prune.stranded_active_redpen_schedules(s, _archived_below(s, 5), 5) == []


def test_a_below_k_schedule_blocks_the_prune_even_after_it_was_cleared(tmp_path, monkeypatch):
    # set + clear BOTH below K would reset the high-water, so a CAPTURED copy of the set could be replayed above K to
    # RESURRECT a cleared schedule (a review that fires again) — the tripwire is fail-closed and blocks it.
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path, clear=True)
    assert prune.stranded_active_redpen_schedules(s, _archived_below(s, 5), 5) == [f"{REPO}@{ORG}"]


def test_a_forged_below_k_schedule_never_blocks_a_prune(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    forged = signed_payload({"signal": SIGNAL, "org_id": ORG, "repo": REPO, "cadence": "weekly", "state": "active",
                             "issued_at": 3.0}, ATTACKER)
    s.append(kind="event", source="governor", actor="WARDEN", payload=forged)
    while s.next_seq < 5:
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})
    s.rotate()
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})
    s.rotate()
    assert prune.stranded_active_redpen_schedules(s, _archived_below(s, 5), 5) == []
