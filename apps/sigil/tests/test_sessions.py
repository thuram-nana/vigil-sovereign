"""Slice 1c-ii — the server-side SessionLedger (idle + absolute expiry, rotation, revoke, revoke-all)."""
from __future__ import annotations

import json
import os
import stat

from sigil.ui.sessions import SessionLedger


def _led(tmp_path, **kw):
    return SessionLedger(tmp_path / "sessions", **kw)


def test_create_resolve_roundtrip_and_0600(tmp_path):
    led = _led(tmp_path)
    sid = led.create("alice", "operator", now=1000.0)
    assert sid
    rec = led.resolve(sid, now=1000.0)
    assert rec and rec["username"] == "alice" and rec["role"] == "operator" and rec["is_owner"] is False
    # the marker is owner-only and named by the HASH, never the raw sid
    marker = led._marker(sid)
    assert stat.S_IMODE(os.stat(marker).st_mode) == 0o600
    assert sid not in os.listdir(led.dir), "the raw session id must never name a file on disk"
    assert led.resolve("no-such-sid", now=1000.0) is None


def test_absolute_expiry_is_a_hard_ceiling(tmp_path):
    led = _led(tmp_path, absolute_ttl=100.0, idle_ttl=100.0)
    sid = led.create("bob", "viewer", now=1000.0)
    assert led.resolve(sid, now=1099.0) is not None          # before the absolute deadline
    assert led.resolve(sid, now=1100.0) is None              # at the absolute deadline → dead
    assert led.resolve(sid, now=1100.0) is None              # and it was reaped


def test_idle_expiry(tmp_path):
    led = _led(tmp_path, idle_ttl=60.0, absolute_ttl=10_000.0)
    sid = led.create("carol", "analyst", now=1000.0)
    assert led.resolve(sid, now=1059.0) is not None          # active within the idle window
    assert led.resolve(sid, now=2000.0) is None              # idle too long → dead (well within absolute)


def test_activity_slides_idle_but_never_the_absolute_deadline(tmp_path):
    led = _led(tmp_path, idle_ttl=60.0, absolute_ttl=200.0)
    sid = led.create("dave", "operator", now=1000.0)
    # keep it active every 40s (< idle 60s), past what a single idle window would allow...
    assert led.resolve(sid, now=1040.0) is not None
    assert led.resolve(sid, now=1080.0) is not None
    assert led.resolve(sid, now=1120.0) is not None
    assert led.resolve(sid, now=1160.0) is not None
    # ...but the ABSOLUTE deadline (1000+200=1200) still kills it despite continuous activity
    assert led.resolve(sid, now=1200.0) is None


def test_rotation_mints_distinct_ids(tmp_path):
    led = _led(tmp_path)
    a = led.create("u", "viewer", now=1.0)
    b = led.create("u", "viewer", now=2.0)
    assert a and b and a != b, "each create must mint a FRESH id (no fixation)"


def test_revoke_and_revoke_all(tmp_path):
    led = _led(tmp_path)
    s1 = led.create("x", "viewer", now=1.0)
    s2 = led.create("y", "operator", now=1.0)
    assert led.revoke(s1) is True
    assert led.resolve(s1, now=1.0) is None and led.resolve(s2, now=1.0) is not None
    assert led.revoke(s1) is False                            # already gone
    s3 = led.create("z", "analyst", now=1.0)
    assert led.revoke_all() == 2                              # s2 + s3
    assert led.resolve(s2, now=1.0) is None and led.resolve(s3, now=1.0) is None


def test_corrupt_record_fails_closed(tmp_path):
    led = _led(tmp_path)
    sid = led.create("e", "viewer", now=1.0)
    led._marker(sid).write_text("{ not json", encoding="utf-8")   # corrupt the record
    assert led.resolve(sid, now=1.0) is None                 # fail-closed, not a crash
    # a record missing the deadline is also treated as expired (fail-closed)
    sid2 = led.create("f", "viewer", now=1.0)
    led._marker(sid2).write_text(json.dumps({"username": "f", "role": "viewer"}), encoding="utf-8")
    assert led.resolve(sid2, now=1.0) is None


def test_ledger_is_bounded(tmp_path):
    led = _led(tmp_path, max_sessions=3, absolute_ttl=10_000.0, idle_ttl=10_000.0)
    ids = [led.create("u", "viewer", now=1.0) for _ in range(3)]
    assert all(ids)
    assert led.create("u", "viewer", now=1.0) is None        # at cap → refuse (no unbounded growth)
