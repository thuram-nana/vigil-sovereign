"""AEGIS AS-3c — drain HARDENING (crash durability): "killed drain loses nothing", EXACTLY ONCE.

The AS-3a strict drain CLAIMS a report into ``working/<slug>/`` (atomic rename out of ``incoming/<slug>/``)
before it verifies/records; a drainer that dies between the claim and the archive to ``processed/`` strands the
file in ``working/`` — out of ``incoming/`` so no later drain saw it, and (if it died BEFORE the archive) with
no ``processed/<sha256>`` marker. AS-3c reclaims such files under a single-drainer ``flock``, and — crucially —
dedups them against the DURABLE spine by ``(org_id, report_id)`` so a report that spined just before the crash
(but never got its marker) is NOT double-spined. The content marker alone cannot catch that window.

Pinned here (counting RAW spine events — ``monitoring_events`` report_id-dedups on READ, so it would MASK a
double-spine): a crash-stranded report is reclaimed → spined EXACTLY ONCE; a report spined-then-crashed before
its marker is DEDUPED on reclaim, never double-spined (the regression test for the red-pen HIGH); a flat claim
is accounted, not lost; an unmovable report is never destroyed; a fresh report of the same name is never
overwritten; the single-drainer lock makes a second drainer ``busy`` without touching the spool, is RELEASED
after a refused drain, and refuses a non-regular (FIFO) or symlink lock; and the DEFAULT global drain takes no
lock and runs no reclaim.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
from sigil.inbound import monitoring_spool as ms
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
NOW = 1_000_000.0
A = ("org_a", "apme.cm")
B = ("org_b", "beta.cm")
SECRETS = {A: b"A" * 32, B: b"B" * 32}
_n = itertools.count(1)


def _store() -> SpineStore:
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _grant(store: SpineStore, org: str, host: str) -> MonitoringAuthorityRegistry:
    own = AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    ch = own.issue_challenge(org, host, issued_at=NOW - 100)
    own.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW - 99, ttl_seconds=1e9)
    reg = MonitoringAuthorityRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    reg.grant(org, host, not_before=NOW - 50, not_after=NOW + 1e6, now=NOW - 50)
    return reg


def _rig(domains=(A, B), grants=(A, B), **kw):
    s = _store()
    reg = None
    for o, h in grants:
        reg = _grant(s, o, h)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, domains=domains, **kw)
    return s, w


def _report(org="org_a", host="apme.cm", **kw) -> dict:
    rep = {"schema": ms.REPORT_SCHEMA, "org_id": org, "host": host, "ts": NOW - 10, "decision": "confirmed",
           "attack_class": "sqli", "action": "observe", "confidence": 0.9, "provenance_tier": "certified",
           "certificate_sha256": "c" * 64, "report_id": f"r{next(_n)}"}
    rep.update(kw)
    return rep


def _seal(rep: dict) -> str:
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(SECRETS[(rep["org_id"], rep["host"])], ms.REPORT_DOMAIN + body.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"schema": ms.REPORT_SCHEMA, "body": body, "mac": mac})


def _raw_events(s: SpineStore) -> list[dict]:
    """Every RAW aegis.monitoring_event on the spine — NOT report_id-deduped (unlike ms.monitoring_events), so a
    double-spine is actually observable as a count of 2."""
    return [r.payload for r in s.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ms.EVENT_SIGNAL]


def _domain_dir(w, org: str, host: str) -> Path:
    d = w.incoming / ms.domain_slug(org, host)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _drop_in_domain(w, env_text: str, org: str, host: str, name=None) -> Path:
    p = _domain_dir(w, org, host) / (name or f"{next(_n)}.json")
    p.write_text(env_text)
    return p


def _strand_in_working(w, env_text: str, org: str, host: str, name=None) -> Path:
    """Simulate a crash: write a sealed report straight into ``working/<slug>/`` as if a drainer claimed it and
    then died before archiving it to ``processed/`` (out of incoming/)."""
    slug = ms.domain_slug(org, host)
    wdir = w.working / slug
    wdir.mkdir(parents=True, exist_ok=True)
    p = wdir / (name or f"{next(_n)}.json")
    p.write_text(env_text)
    return p


# --- killed drain loses nothing, exactly once ----------------------------------------------------------------
def test_crash_stranded_report_is_reclaimed_and_spined_exactly_once():
    s, w = _rig()
    _strand_in_working(w, _seal(_report(org="org_a", host="apme.cm")), "org_a", "apme.cm")
    r = w.drain()
    assert r["recorded"] == 1 and not r.get("busy")
    assert len(_raw_events(s)) == 1               # the stranded report reached the spine, exactly once (RAW count)
    r2 = w.drain()
    assert r2["recorded"] == 0 and len(_raw_events(s)) == 1   # second pass adds nothing (idempotent)


def test_reclaim_does_not_double_spine_a_report_spined_before_the_crash():
    # THE regression for the red-pen HIGH. Recreate the crash window: the event is ALREADY on the spine but the
    # file is still in working/<slug>/ with NO processed marker (the drainer died between _record and the marker
    # write). The reclaim must DEDUP it against the durable spine, not re-append.
    s, w = _rig()
    env = _seal(_report(org="org_a", host="apme.cm"))
    _drop_in_domain(w, env, "org_a", "apme.cm")
    w.drain()                                                   # spined once, marker written
    assert len(_raw_events(s)) == 1
    (w.processed / (hashlib.sha256(env.encode()).hexdigest() + ".json")).unlink()   # as if the marker write never happened
    _strand_in_working(w, env, "org_a", "apme.cm")              # the same report, back in working/ (claimed, unmarked)
    r = w.drain()
    assert r["recorded"] == 0 and r["deduped"] == 1            # deduped via (org, report_id) spine baseline
    assert len(_raw_events(s)) == 1                             # STILL exactly one RAW spine event — no double-spine


def test_reclaimed_file_with_existing_marker_is_deduped_not_respined():
    s, w = _rig()
    env = _seal(_report(org="org_a", host="apme.cm"))
    (w.processed / (hashlib.sha256(env.encode()).hexdigest() + ".json")).write_text(env)
    _strand_in_working(w, env, "org_a", "apme.cm")
    r = w.drain()
    assert r["recorded"] == 0 and r["deduped"] == 1
    assert _raw_events(s) == []


def test_flat_working_claim_is_reclaimed_out_and_accounted_not_lost():
    s, w = _rig()
    (w.working / "stray.json").write_text(_seal(_report(org="org_a", host="apme.cm")))
    r = w.drain()
    assert not (w.working / "stray.json").exists()             # reclaimed OUT of working/ (not stranded, not destroyed)
    assert (w.rejected / "stray.json").exists() and r["off_domain"] >= 1   # accounted for by location


def test_reclaim_never_destroys_an_unmovable_report(monkeypatch):
    s, w = _rig()
    p = _strand_in_working(w, _seal(_report()), "org_a", "apme.cm")
    real_replace = os.replace

    def _boom(src, dst):
        if str(src) == str(p):
            raise OSError("simulated reclaim failure")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _boom)
    w.drain()
    assert p.exists()                                          # still in working/ — not destroyed


def test_reclaim_never_overwrites_a_fresh_report_of_the_same_name():
    # a stranded report and a FRESH report (distinct detections) share a producer filename: NEITHER may be
    # destroyed — both must reach the spine (the stranded one reclaimed under a content-derived name).
    s, w = _rig()
    fresh_rep, stale_rep = _report(org="org_a", host="apme.cm"), _report(org="org_a", host="apme.cm")
    _drop_in_domain(w, _seal(fresh_rep), "org_a", "apme.cm", name="dup.json")      # fresh, in incoming/<slug>/
    _strand_in_working(w, _seal(stale_rep), "org_a", "apme.cm", name="dup.json")   # stale, in working/<slug>/ (same name)
    w.drain()
    rids = {e.get("report_id") for e in _raw_events(s)}
    assert fresh_rep["report_id"] in rids and stale_rep["report_id"] in rids       # both preserved, neither destroyed
    assert len(_raw_events(s)) == 2


# --- single-drainer lock -------------------------------------------------------------------------------------
def test_second_concurrent_drainer_is_busy_and_touches_nothing(tmp_path=None):
    import fcntl
    s, w = _rig()
    p = _strand_in_working(w, _seal(_report()), "org_a", "apme.cm")
    held = os.open(str(w.working / ms._LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX)
    try:
        r = w.drain()
        assert r.get("busy") is True and r["recorded"] == 0
        assert _raw_events(s) == []                            # spine untouched
        assert p.exists()                                      # on-disk spool untouched (the stranded file stayed put)
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)


def test_lock_is_released_after_a_refused_drain():
    # a non-regular lock refuses the drain; the lock fd must be released so a SUBSEQUENT valid drain proceeds.
    s, w = _rig()
    lock = w.working / ms._LOCK_NAME
    os.mkfifo(lock)
    with pytest.raises((ms.MonitoringSpoolError, OSError)):
        w.drain()
    lock.unlink()                                              # remove the bad lock; a regular lock is re-created
    _strand_in_working(w, _seal(_report(org="org_a", host="apme.cm")), "org_a", "apme.cm")
    r = w.drain()                                              # must succeed — the earlier fd was not leaked
    assert r["recorded"] == 1


def test_non_regular_fifo_lock_refuses_the_drain():
    s, w = _rig()
    os.mkfifo(w.working / ms._LOCK_NAME)
    with pytest.raises((ms.MonitoringSpoolError, OSError)):
        w.drain()


def test_symlink_lock_refuses_the_drain():
    # O_NOFOLLOW defends the symlink vector: a symlink planted at the lock name must refuse the drain.
    s, w = _rig()
    os.symlink("/tmp/elsewhere", w.working / ms._LOCK_NAME)
    with pytest.raises((ms.MonitoringSpoolError, OSError)):
        w.drain()


# --- default global mode is unchanged (no lock, no reclaim) --------------------------------------------------
def test_default_global_drain_takes_no_lock_and_runs_no_reclaim():
    s = _store()
    reg = _grant(s, "org_a", "apme.cm")
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, domains=None)   # GLOBAL (default) mode
    (w.incoming / "r.json").write_text(_seal(_report(org="org_a", host="apme.cm")))
    (w.working / "stranded.json").write_text(_seal(_report(org="org_a", host="apme.cm")))   # a working/ file
    r = w.drain()
    assert r["recorded"] == 1 and "busy" not in r
    assert not (w.working / ms._LOCK_NAME).exists()           # global drain creates no drain lock
    assert (w.working / "stranded.json").exists()             # and runs NO reclaim — the working/ file is untouched
