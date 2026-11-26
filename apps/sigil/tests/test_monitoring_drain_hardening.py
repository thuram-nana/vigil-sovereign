"""AEGIS AS-3c — drain HARDENING (crash durability): "killed drain loses nothing".

The AS-3a strict drain CLAIMS a report into ``working/<slug>/`` (atomic rename out of ``incoming/<slug>/``)
before it verifies/records; a drainer that dies between the claim and the archive to ``processed/`` strands the
file in ``working/`` — out of ``incoming/`` so no later drain saw it, and not in ``processed/`` so it was never
spined: an authenticated gateway detection SILENTLY LOST. AS-3c closes that with a crash-recovery reclaim at the
start of every strict pass, run under a single-drainer ``flock`` so the reclaim can never race a live drainer.

Pinned here: a crash-stranded report is reclaimed → drained → spined EXACTLY ONCE; the reclaim is idempotent
(a file reclaimed after its marker already exists is deduped, not double-spined; a second pass adds nothing); a
flat (global-shaped) working claim is restored to ``incoming/`` root; the single-drainer lock makes a second
concurrent drainer report ``busy`` without touching anything; a non-regular lock refuses the drain (fail-closed);
and the DEFAULT global drain is unchanged — it takes no lock and creates no ``.drain.lock``.
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


def _events(s: SpineStore, org: str) -> list[dict]:
    return ms.monitoring_events(s, org)


def _strand_in_working(w, env_text: str, org: str, host: str, name=None) -> Path:
    """Simulate a crash: write a sealed report straight into ``working/<slug>/`` as if a drainer claimed it and
    then died before archiving it to ``processed/`` (out of incoming/, never spined)."""
    slug = ms.domain_slug(org, host)
    wdir = w.working / slug
    wdir.mkdir(parents=True, exist_ok=True)
    p = wdir / (name or f"{next(_n)}.json")
    p.write_text(env_text)
    return p


# --- killed drain loses nothing ------------------------------------------------------------------------------
def test_crash_stranded_report_is_reclaimed_and_drained_exactly_once():
    s, w = _rig()
    _strand_in_working(w, _seal(_report(org="org_a", host="apme.cm")), "org_a", "apme.cm")
    r = w.drain()
    assert r["recorded"] == 1 and not r.get("busy")
    assert len(_events(s, "org_a")) == 1          # the stranded report was NOT lost — it reached the spine
    # second pass: nothing left to reclaim, nothing to drain, no new spine events (idempotent)
    r2 = w.drain()
    assert r2["recorded"] == 0
    assert len(_events(s, "org_a")) == 1


def test_reclaimed_file_with_existing_marker_is_deduped_not_respined():
    s, w = _rig()
    env = _seal(_report(org="org_a", host="apme.cm"))
    # pre-create the content-addressed processed marker: the report already spined once before the crash.
    marker = w.processed / (hashlib.sha256(env.encode()).hexdigest() + ".json")
    marker.write_text(env)
    _strand_in_working(w, env, "org_a", "apme.cm")
    r = w.drain()
    assert r["recorded"] == 0 and r["deduped"] == 1   # reclaimed, then deduped — never double-spined
    assert _events(s, "org_a") == []


def test_flat_working_claim_is_reclaimed_out_and_accounted_not_lost():
    # a flat working/*.json (a global-shaped claim stranded by a crash) is restored out of working/ — not
    # destroyed — then, being under no declared slug, the SAME strict pass sweeps it off-domain into rejected/.
    # Either way it is ACCOUNTED FOR (never silently lost in working/).
    s, w = _rig()
    env = _seal(_report(org="org_a", host="apme.cm"))
    (w.working / "stray.json").write_text(env)
    r = w.drain()                                  # reclaim working/stray.json -> incoming/ -> swept off-domain
    assert not (w.working / "stray.json").exists()  # reclaimed OUT of working/ (not stranded, not destroyed)
    assert (w.rejected / "stray.json").exists() and r["off_domain"] >= 1  # accounted for by location


def test_reclaim_never_destroys_an_unmovable_report(monkeypatch):
    # if the move back fails, the file stays in working/ for the next sweep — never unlinked.
    s, w = _rig()
    p = _strand_in_working(w, _seal(_report()), "org_a", "apme.cm")
    real_replace = os.replace

    def _boom(src, dst):
        if str(src) == str(p):
            raise OSError("simulated reclaim failure")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _boom)
    w.drain()
    assert p.exists()                              # still in working/ — not destroyed


# --- single-drainer lock -------------------------------------------------------------------------------------
def test_second_concurrent_drainer_reports_busy_without_draining():
    import fcntl
    s, w = _rig()
    _strand_in_working(w, _seal(_report()), "org_a", "apme.cm")
    held = os.open(str(w.working / ms._LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX)
    try:
        r = w.drain()                              # cannot take the lock -> busy, touches nothing
        assert r.get("busy") is True and r["recorded"] == 0
        assert _events(s, "org_a") == []
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)


def test_non_regular_lock_refuses_the_drain():
    s, w = _rig()
    lock = w.working / ms._LOCK_NAME
    os.mkfifo(lock)                                # a FIFO planted at the lock name — not a regular file
    with pytest.raises((ms.MonitoringSpoolError, OSError)):
        w.drain()


# --- default global mode is unchanged (byte-identical) -------------------------------------------------------
def test_default_global_drain_takes_no_lock_and_no_reclaim():
    s = _store()
    reg = _grant(s, "org_a", "apme.cm")
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, domains=None)   # GLOBAL (default) mode
    (w.incoming / "r.json").write_text(_seal(_report(org="org_a", host="apme.cm")))
    r = w.drain()
    assert r["recorded"] == 1 and "busy" not in r
    assert not (w.working / ms._LOCK_NAME).exists()   # global drain creates no drain lock
