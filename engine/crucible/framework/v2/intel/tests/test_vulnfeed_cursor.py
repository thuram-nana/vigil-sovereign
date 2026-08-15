"""
K1 — the vulnfeed ingest CURSOR (a durable crash-recovery checkpoint for ``refresh_vulnintel``).

``refresh_vulnintel`` used to fetch every trusted source then ingest ONCE at the very end, so a crash
before that end-ingest lost every fetched observation and the recovery pull re-fetched the whole catalog.
This suite pins the checkpoint that fixes it, without relaxing any doctrine:

  * PERSISTS — ingest is incremental (per source, durable before the checkpoint advances) and the cursor
    file recording the highest durably-ingested seq is written to disk MID-pull, next to the intel store;
  * RESUMES / SKIPS-DONE — after a crash the surviving cursor lets the recovery pull re-project the durable
    leads LOCALLY and make NO network fetch for a finished source, pulling only the one that failed;
    nothing is double-counted in the durable store (idempotent);
  * REFRESHES — a pull that runs to completion CLEARS its checkpoint, so the next scheduled/manual pull
    does a fresh full refresh (the auto-updating feed keeps catching new CVEs / KEV entries);
  * FAIL-OPEN — a cursor read/write failure (corrupt file, un-writable dir) degrades to the old
    full-refresh behaviour and NEVER raises or aborts the pull.

LEAD, never a fact — the cursor records STATE only; nothing here mints or promotes a finding.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.intel import vulnfeed
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.store import IntelStore
from framework.v2.intel.transport import CollectorEgressRefused, RawRecord
from framework.v2.memory.store import open_store
from framework.v2.worldmodel.graph import WorldModel

# Fixture payloads (mirror test_vulnfeed) — a per-CVE NVD/OSV doc and a bulk CISA-KEV catalog.
_KEV = {"vulnerabilities": [
    {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget",
     "vulnerabilityName": "RCE", "shortDescription": "bad", "dateAdded": "2024-01-01",
     "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-79"]},
    {"cveID": "CVE-2024-0002", "vendorProject": "Beta", "product": "Gadget",
     "shortDescription": "worse", "dateAdded": "2024-02-02"},
]}
_NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-1111", "descriptions": [{"lang": "en", "value": "x"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}, "baseSeverity": "CRITICAL"}]},
    "configurations": []}}]}
_OSV = {"id": "OSV-2024-9", "aliases": ["CVE-2024-2222"], "summary": "osv bug",
        "affected": [{"package": {"name": "leftpad", "ecosystem": "npm"}}]}
_PAYLOAD_BY_NAME = {"nvd": _NVD, "osv": _OSV, "cisa-kev": _KEV}


class _RecTransport:
    """A per-source stand-in that records every fetch into a SHARED log and returns a fixed payload.
    A ``boom`` source raises on fetch (simulate a mid-run network crash); an ``on_fetch`` hook lets a
    test observe on-disk state at the exact moment a source is fetched."""

    def __init__(self, name, payload, log, boom, on_fetch):
        self.name = name
        self.payload = payload
        self.log = log
        self.boom = boom
        self.on_fetch = on_fetch

    def fetch(self, source_kind, query, *, seq):
        self.log.append((self.name, query, seq))
        if self.on_fetch is not None:
            self.on_fetch(self.name)
        if self.name in self.boom:
            raise RuntimeError(f"network boom for {self.name}")
        return RawRecord(source_kind=source_kind, query=query, payload=self.payload, ok=True)


def _factory(log, *, boom=frozenset(), refuse=frozenset(), on_fetch=None):
    """Build a transport_for(source) that records fetches, and can refuse / crash / probe named sources."""
    def transport_for(source):
        if source.name in refuse:
            raise CollectorEgressRefused(f"{source.name} refused")
        return _RecTransport(source.name, _PAYLOAD_BY_NAME[source.name], log, boom, on_fetch)
    return transport_for


def _plan(cve="CVE-2024-1111"):
    # nvd(per-cve, seq0) → osv(per-cve, seq1) → cisa-kev(bulk, seq2); last_seq 3.
    return vulnfeed.plan_for(vulnfeed.TRUSTED_VULN_SOURCES, [cve])


def _ingest(tmp_path: Path, slug="acme"):
    store = open_store(tmp_path / "mls.sqlite")
    istore = IntelStore(store)
    ing = IntelIngest(WorldModel(), store=istore, engagement_slug=slug)
    return store, istore, ing


def _cursor_file(tmp_path: Path):
    files = list((tmp_path / "vulnfeed_cursors").glob("*.json"))
    return files[0] if files else None


# ---- (a) the checkpoint PERSISTS (incrementally, durably, mid-pull) -------------

def test_checkpoint_persists_incrementally_during_a_pull(tmp_path):
    store, istore, ing = _ingest(tmp_path)
    seen_at_kev: dict = {}

    def probe(name):
        # when the LAST source (cisa-kev) is fetched, nvd(0)+osv(1) are already ingested + checkpointed
        if name == "cisa-kev":
            cf = _cursor_file(tmp_path)
            seen_at_kev["file_present"] = cf is not None
            seen_at_kev["last_seq"] = json.loads(cf.read_text())["last_ingested_seq"] if cf else None
            seen_at_kev["obs"] = istore.observation_count(engagement_slug="acme")

    r = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory([], on_fetch=probe), ingest=ing, seq=0)

    assert r.queries_run == 3 and r.applied > 0 and r.cancelled is False
    assert r.resumed_from_seq == -1                         # a fresh run resumes from nothing
    # the checkpoint was on disk (durable) BEFORE the last source, recording nvd+osv (seq 1)...
    assert seen_at_kev["file_present"] is True and seen_at_kev["last_seq"] == 1
    assert seen_at_kev["obs"] > 0                           # ...and their leads were already durable
    # a completed pull clears its checkpoint so the next pull refreshes in full
    assert _cursor_file(tmp_path) is None
    assert istore.observation_count(engagement_slug="acme") > 0
    store.close()


# ---- a completed pull refreshes; the store is never double-counted --------------

def test_completed_pull_clears_checkpoint_and_repull_refreshes(tmp_path):
    store, istore, ing1 = _ingest(tmp_path)
    log1: list = []
    r1 = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory(log1), ingest=ing1, seq=0)
    n_obs = istore.observation_count(engagement_slug="acme")
    assert r1.queries_run == 3 and len(log1) == 3 and _cursor_file(tmp_path) is None

    # a fresh re-pull re-fetches (feed stays current) — a persistent skip-list would starve the feed
    ing2 = IntelIngest(WorldModel(), store=istore, engagement_slug="acme")
    log2: list = []
    r2 = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory(log2), ingest=ing2, seq=0)
    assert r2.resumed_from_seq == -1 and r2.queries_run == 3   # no lingering checkpoint → full refresh
    assert istore.observation_count(engagement_slug="acme") == n_obs   # idempotent store — no double-count
    store.close()


# ---- (b) crash mid-op: keep-what's-done, resume skips it, pull only the rest ----

def test_crash_midop_keeps_ingested_and_resume_skips_done(tmp_path):
    store, istore, ing1 = _ingest(tmp_path)
    log1: list = []
    # cisa-kev (the LAST, bulk source at seq 2) crashes; nvd+osv (seq 0,1) ingest + checkpoint first.
    with pytest.raises(RuntimeError):
        vulnfeed.refresh_vulnintel(
            _plan(), transport_for=_factory(log1, boom={"cisa-kev"}), ingest=ing1, seq=0)

    # the interrupted pull's checkpoint SURVIVES and records the finished sources (up to osv @ 1)
    cf = _cursor_file(tmp_path)
    assert cf is not None and json.loads(cf.read_text())["last_ingested_seq"] == 1
    obs_after_crash = istore.observation_count(engagement_slug="acme")
    assert obs_after_crash > 0                              # what finished before the crash is durable

    # RESUME with a healthy transport: skip nvd+osv (no network), re-fetch ONLY the source that failed.
    ing2 = IntelIngest(WorldModel(), store=istore, engagement_slug="acme")
    log2: list = []
    r2 = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory(log2), ingest=ing2, seq=0)

    assert r2.resumed_from_seq == 1
    assert r2.queries_run == 1 and [c[0] for c in log2] == ["cisa-kev"]   # only the failed source
    assert set(r2.skipped_by_source) == {"nvd", "osv"}     # done sources skipped, not re-fetched
    assert r2.applied > 0                                   # the KEV leads are finally ingested
    assert istore.observation_count(engagement_slug="acme") > obs_after_crash
    assert _cursor_file(tmp_path) is None                  # resume completed → checkpoint cleared
    store.close()


# ---- (c) FAIL-OPEN: a cursor WRITE failure degrades, never raises ---------------

def test_cursor_write_failure_is_failopen(tmp_path, monkeypatch):
    store, istore, ing = _ingest(tmp_path)
    # force the atomic swap inside _write_cursor to blow up on every source completion
    def _boom_replace(*_a, **_k):
        raise OSError("disk full")
    monkeypatch.setattr(vulnfeed.os, "replace", _boom_replace)

    log: list = []
    r = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory(log), ingest=ing, seq=0)  # must NOT raise

    assert r.queries_run == 3 and r.applied > 0            # the full pull completed despite the failure
    assert _cursor_file(tmp_path) is None                  # persist failed → no checkpoint written
    n_obs = istore.observation_count(engagement_slug="acme")
    assert n_obs > 0                                        # leads still durable (the pull never aborted)

    # a follow-up pull simply degrades to a full refresh (no checkpoint to resume from), still no crash
    ing2 = IntelIngest(WorldModel(), store=istore, engagement_slug="acme")
    log2: list = []
    r2 = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory(log2), ingest=ing2, seq=0)
    assert r2.resumed_from_seq == -1 and r2.queries_run == 3
    assert istore.observation_count(engagement_slug="acme") == n_obs   # idempotent store — no double-count
    store.close()


# ---- (c') FAIL-OPEN: a corrupt cursor is ignored, never raises ------------------

def test_corrupt_cursor_is_ignored(tmp_path):
    store, istore, ing = _ingest(tmp_path)
    # pre-plant a corrupt cursor at the exact path this run will read
    cpath, _fp = vulnfeed._cursor_path(ing, _plan(), 0)
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text("{ this is not valid json")

    log: list = []
    r = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory(log), ingest=ing, seq=0)  # must NOT raise
    assert r.resumed_from_seq == -1 and r.queries_run == 3   # corrupt cursor ignored → full pull
    assert istore.observation_count(engagement_slug="acme") > 0
    assert _cursor_file(tmp_path) is None                    # completed pull cleared it
    store.close()


# ---- a surviving cursor from a DIFFERENT plan is never reused -------------------

def test_a_surviving_cursor_from_another_plan_is_not_reused(tmp_path):
    store, istore, ing1 = _ingest(tmp_path)
    # crash plan A so its checkpoint survives on disk
    with pytest.raises(RuntimeError):
        vulnfeed.refresh_vulnintel(_plan("CVE-2024-1111"),
                                   transport_for=_factory([], boom={"cisa-kev"}), ingest=ing1, seq=0)
    assert _cursor_file(tmp_path) is not None                # plan A's checkpoint is present

    # plan B (a DIFFERENT query set → different fingerprint) must NOT resume from plan A's cursor
    ing2 = IntelIngest(WorldModel(), store=istore, engagement_slug="acme")
    log2: list = []
    r2 = vulnfeed.refresh_vulnintel(_plan("CVE-2024-9999"),
                                    transport_for=_factory(log2), ingest=ing2, seq=0)
    assert r2.resumed_from_seq == -1 and r2.queries_run == 3   # full fetch — a foreign checkpoint is ignored
    assert r2.skipped_by_source == {}
    store.close()


# ---- a store-less (ephemeral) run keeps the old behaviour, no cursor ------------

def test_ephemeral_run_has_no_cursor_and_full_pulls(tmp_path):
    ing = IntelIngest(WorldModel())                         # no store → nothing durable to resume from
    log: list = []
    r = vulnfeed.refresh_vulnintel(_plan(), transport_for=_factory(log), ingest=ing, seq=0)
    assert r.queries_run == 3 and r.resumed_from_seq == -1 and r.skipped_by_source == {}
    assert not (tmp_path / "vulnfeed_cursors").exists()     # no cursor dir created for an ephemeral run
