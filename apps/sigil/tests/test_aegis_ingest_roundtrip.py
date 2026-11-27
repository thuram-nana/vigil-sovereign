"""AEGIS AS-9b — the CROSS-PLANE round-trip (load-bearing): a record the ingest RECEIVER lands is drained
end-to-end by the REAL AS-3c-hardened sovereign ``MonitoringSpoolWatcher`` in STRICT mode.

TWO-ENV BOUNDARY (FATAL-2). The receiver is the ENGINE plane (imports ``framework.v2.aegis.*``); the drain is
the SOVEREIGN plane (``sigil.inbound.monitoring_spool``, which runs ``assert_no_offense`` at import). A single
process importing BOTH trips that assertion, so this test runs ENTIRELY sigil-side (it imports only
``sigil.*``) and LANDS each record by invoking the real receiver in a SEPARATE engine-leg SUBPROCESS
(``python -m framework.v2.aegis.receiver`` with the engine PYTHONPATH). The drain then consumes the landed
bytes with no engine import in this process.

Proven: the receiver's landed envelope is admitted by the drain's ACCEPT-SET for its own domain and RECORDED
once; a genuine (receiver-sealed) report of another tenant MIS-FILED into a foreign subtree is QUARANTINED
(accept-set); a re-POST / re-delivery is drained AT MOST ONCE (nothing double-spined).
"""
from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
from sigil.inbound import monitoring_spool as ms
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

_ROOT = Path(__file__).resolve().parents[3]            # apps/sigil/tests -> repo root
_ENGINE_PYTHONPATH = os.pathsep.join([str(_ROOT / "packages/core/vigil_core"), str(_ROOT / "engine/crucible")])
_RECEIVER_MODULE = "framework.v2.aegis.receiver"

OWNER = generate_keypair()
NOW = 1_000_000.0
A = ("org_a", "apme.cm")
B = ("org_b", "beta.cm")
SECRETS = {A: b"A" * 32, B: b"B" * 32}
_n = itertools.count(1)


def _engine_available() -> bool:
    return (_ROOT / "engine/crucible/framework/v2/aegis/receiver.py").is_file()


pytestmark = pytest.mark.skipif(not _engine_available(), reason="engine-leg receiver not present in this checkout")


def _store() -> SpineStore:
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _grant(store: SpineStore, org: str, host: str) -> MonitoringAuthorityRegistry:
    own = AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    ch = own.issue_challenge(org, host, issued_at=NOW - 100)
    own.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW - 99, ttl_seconds=1e9)
    reg = MonitoringAuthorityRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    reg.grant(org, host, not_before=NOW - 50, not_after=NOW + 1e6, now=NOW - 50)
    return reg


def _watcher(store, spool, reg, **kw):
    return ms.MonitoringSpoolWatcher(store, spool_dir=spool, secret_for=lambda o, h: SECRETS.get((o, h)),
                                     authority=reg, now_fn=lambda: NOW, domains=(A, B), **kw)


def _finding(org: str, host: str, **kw) -> dict:
    f = {"schema": "vigil.aegis.ingest.finding.v1", "org_id": org, "host": host, "ts": NOW - 10,
         "decision": "confirmed", "attack_class": "sqli", "action": "observe", "confidence": 0.9,
         "provenance_tier": "grounded", "certificate_sha256": "c" * 64}
    f.update(kw)
    return f


def _land_via_receiver(spool: str, org: str, host: str, finding: dict) -> dict:
    """Run the REAL receiver in a separate ENGINE-leg process to land one finding into ``spool``. Returns the
    receiver's IngestResult dict. This is the two-env boundary: no ``framework.*`` import in THIS process."""
    job = {"spool": spool, "org_id": org, "host": host, "report_secret_hex": SECRETS[(org, host)].hex(),
           "finding": finding, "require_auth": False}
    jobfile = os.path.join(tempfile.mkdtemp(), "job.json")
    Path(jobfile).write_text(json.dumps(job), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = _ENGINE_PYTHONPATH
    proc = subprocess.run([sys.executable, "-m", _RECEIVER_MODULE, jobfile],
                          capture_output=True, text=True, cwd=str(_ROOT), env=env, timeout=120)
    assert proc.returncode == 0, f"receiver subprocess failed: {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    # ``assert_no_offense`` must NOT have run here: this process imported only sigil.*
    assert not any(m.startswith("framework.") for m in sys.modules), "engine leaked into the sovereign test process"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _raw_events(s: SpineStore) -> list[dict]:
    return [r.payload for r in s.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ms.EVENT_SIGNAL]


def _ids(s: SpineStore, org: str) -> list[str]:
    return [p.get("report_id") for p in _raw_events(s) if p.get("org_id") == org]


# ======================================================================================================
def test_receiver_landed_record_is_drained_by_the_real_watcher():
    s = _store()
    reg = None
    for o, h in (A, B):
        reg = _grant(s, o, h)
    spool = tempfile.mkdtemp()
    res = _land_via_receiver(spool, *A, _finding(*A))
    assert res["outcome"] == "spooled" and res["report_id"]
    # The receiver filed under incoming/<domain_slug(A)>/ — exactly where the STRICT watcher looks.
    assert (Path(spool) / "incoming" / ms.domain_slug(*A) / res["filename"]).is_file()
    w = _watcher(s, spool, reg)
    r = w.drain()
    assert r["recorded"] == 1 and r["rejected"] == 0
    assert _ids(s, "org_a") == [res["report_id"]]      # the receiver's stable dedup id is what the drain spined


def test_accept_set_quarantines_a_misfiled_receiver_record():
    # A GENUINE receiver-sealed org_b report (B's real secret, B's active authority) MIS-FILED into org_a's
    # declared subtree: it passes the MAC + authority but the ACCEPT-SET rejects it (its (org_b, beta.cm) does
    # not slug to org_a's subtree). Same-domain org_a record still drains; org_b mis-file is quarantined.
    s = _store()
    reg = None
    for o, h in (A, B):
        reg = _grant(s, o, h)
    spool = tempfile.mkdtemp()
    good = _land_via_receiver(spool, *A, _finding(*A))
    bad = _land_via_receiver(spool, *B, _finding(*B))
    # move B's genuine envelope out of B's subtree into A's subtree (simulate a cross-tenant mis-file)
    b_sub = Path(spool) / "incoming" / ms.domain_slug(*B)
    a_sub = Path(spool) / "incoming" / ms.domain_slug(*A)
    os.replace(b_sub / bad["filename"], a_sub / bad["filename"])
    w = _watcher(s, spool, reg)
    r = w.drain()
    assert r["recorded"] == 1 and r["rejected"] == 1              # org_a admitted; mis-filed org_b quarantined
    assert _ids(s, "org_a") == [good["report_id"]] and _ids(s, "org_b") == []
    reasons = [p.read_text() for p in w.rejected.glob("*.reason")]
    assert any("accept-set" in t for t in reasons)


def test_reposted_record_drains_at_most_once():
    # The receiver is deterministic: a re-POST of the same finding yields the SAME content-addressed file, so
    # the drain's content marker dedups it. Prove the record is spined EXACTLY once across two drains, nothing
    # double-spined.
    s = _store()
    reg = None
    for o, h in (A, B):
        reg = _grant(s, o, h)
    spool = tempfile.mkdtemp()
    f = _finding(*A)
    first = _land_via_receiver(spool, *A, f)
    w = _watcher(s, spool, reg)
    assert w.drain()["recorded"] == 1
    # Re-land the SAME record (idempotent no-op on disk) and re-drain: nothing new is spined.
    again = _land_via_receiver(spool, *A, f)
    assert again["outcome"] in ("dedup_noop", "spooled") and again["report_id"] == first["report_id"]
    r2 = w.drain()
    assert r2["recorded"] == 0
    assert _ids(s, "org_a").count(first["report_id"]) == 1       # spined EXACTLY once (raw count)


def test_dedup_window_catches_a_fresh_envelope_with_the_same_report_id():
    # The (org, report_id) window closes the gap the content marker CANNOT: the SAME landed body re-wrapped in
    # a FRESH envelope (different bytes -> a different content hash) must still drain at most once. We take the
    # receiver's own sealed envelope and re-serialise it non-canonically (same body + mac, different bytes).
    s = _store()
    reg = None
    for o, h in (A, B):
        reg = _grant(s, o, h)
    spool = tempfile.mkdtemp()
    landed = _land_via_receiver(spool, *A, _finding(*A))
    a_sub = Path(spool) / "incoming" / ms.domain_slug(*A)
    env = json.loads((a_sub / landed["filename"]).read_bytes())
    w = _watcher(s, spool, reg)
    assert w.drain()["recorded"] == 1
    # a FRESH envelope: identical body+mac, different bytes (pretty-printed) -> a content hash the marker misses.
    fresh = json.dumps(env, indent=2).encode("utf-8")
    (a_sub / "redelivered.json").write_bytes(fresh)
    r = w.drain()
    assert r["recorded"] == 0 and r["deduped"] == 1
    assert _ids(s, "org_a").count(landed["report_id"]) == 1       # still spined EXACTLY once
