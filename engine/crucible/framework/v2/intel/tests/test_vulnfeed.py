"""
K1 — the vulnerability-intelligence feed (vulnfeed + scheduler + KEV parse + CLI fail-closed).

Doctrine under test:
  * LEAD, never a fact — every entry is a ``VULN_DB`` observation minted by the SAME offline advisory
    parser, so nothing here is ever a confirmed fact;
  * EGRESS-GATED to concrete apex hosts — no wildcard / IP-literal source; a source overlapping target
    scope refuses to construct; nothing leaves for an off-allowlist host;
  * DETERMINISTIC + idempotent — the only clock is the injected monotonic seq; a re-pull applies nothing new;
  * STOPPABLE — ``cancel()`` / kill-switch is honoured before every source AND every per-CVE fetch;
  * FAIL-CLOSED — the CLI without ``--live`` fires NO traffic; it only reports intent.
"""

from __future__ import annotations

import argparse
import json

import pytest

from framework.v2.intel import scheduler, vulnfeed
from framework.v2.intel.cli import _refresh_vulnintel
from framework.v2.intel.from_threatintel import observations_from_kev
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind
from framework.v2.intel.transport import CollectorEgressRefused, RawRecord
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import NodeKind

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


class _FakeTransport:
    """A per-source stand-in that records fetches and returns a fixed payload (no network)."""

    def __init__(self, payload):
        self.payload = payload
        self.calls: list = []

    def fetch(self, source_kind, query, *, seq):
        self.calls.append((source_kind, query, seq))
        return RawRecord(source_kind=source_kind, query=query, payload=self.payload, ok=True)


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._p = payload
        self.text = ""

    def json(self):
        return self._p


class _RecordingClient:
    """A stand-in httpx client that records every .get(), to prove the guard checks the host first."""

    def __init__(self, status=200, payload=None):
        self.calls: list[str] = []
        self._status = status
        self._payload = payload if payload is not None else {}

    def get(self, url):
        self.calls.append(url)
        return _Resp(self._status, self._payload)


def _tfor(source):
    return _FakeTransport(_PAYLOAD_BY_NAME[source.name])


# ---- sources registry: concrete apex hosts, no wildcards --------------------

def test_sources_are_concrete_apex_hosts_no_wildcards():
    from framework.v2.agents.egress_guard import _collector_host_too_broad

    assert {s.name for s in vulnfeed.TRUSTED_VULN_SOURCES} == {"nvd", "osv", "cisa-kev"}
    for s in vulnfeed.TRUSTED_VULN_SOURCES:
        assert not _collector_host_too_broad(s.host), s.host    # no wildcard / public-suffix host
        assert "*" not in s.host and "/" not in s.host          # concrete, no path/scheme
    assert vulnfeed.source_by_name("NVD").name == "nvd"          # case-insensitive
    assert vulnfeed.source_by_name("nope") is None               # unknown → None (select by name only)


# ---- KEV parse: a LEAD, never a fact ---------------------------------------

def test_kev_parse_mints_exploit_known_leads():
    obs = observations_from_kev(_KEV, seq=7)
    nodes = [o for o in obs if o.relation is None and o.subject.kind is NodeKind.VULNERABILITY]
    assert len(nodes) == 2
    assert {o.subject.key.upper() for o in nodes} == {"CVE-2024-0001", "CVE-2024-0002"}
    assert all(o.source_kind is IntelSourceKind.VULN_DB for o in obs)          # lead tier, never a fact kind
    assert all(o.attrs.get("exploit_known") is True for o in nodes)            # KEV = known-exploited
    assert observations_from_kev({}, seq=0) == []                              # empty → [] (total)
    assert observations_from_kev({"vulnerabilities": "nope"}, seq=0) == []


def test_kev_parse_caps_an_oversized_feed():
    # KEV is fed by LIVE bytes from www.cisa.gov — an oversized (MITM'd / anomalous) catalog must be capped
    # at the module's _MAX_ITEMS like every sibling parser, so it can never explode node count.
    from framework.v2.intel.from_threatintel import _MAX_ITEMS
    big = {"vulnerabilities": [{"cveID": f"CVE-2024-{i:05d}", "product": f"p{i}", "vendorProject": "v"}
                               for i in range(_MAX_ITEMS + 500)]}
    nodes = [o for o in observations_from_kev(big, seq=0) if o.relation is None]
    assert len(nodes) == _MAX_ITEMS                                            # bounded, not 5500


def test_kev_parse_caps_per_entry_cwes_list():
    # a per-entry `cwes` list is also untrusted (live-fed) — cap it at _MAX_REFS like the sibling
    # refs/aliases lists, so the module's "every list is size-capped" invariant is literally true.
    from framework.v2.intel.from_threatintel import _MAX_REFS
    doc = {"vulnerabilities": [{"cveID": "CVE-2024-0009", "product": "p", "vendorProject": "v",
                               "cwes": [f"CWE-{i}" for i in range(_MAX_REFS + 200)]}]}
    node = next(o for o in observations_from_kev(doc, seq=0) if o.relation is None)
    assert len(node.attrs["cwes"]) == _MAX_REFS                               # bounded, not 232


# ---- refresh: deterministic + idempotent -----------------------------------

def test_refresh_is_deterministic_and_idempotent():
    ing = IntelIngest(WorldModel())
    plan = vulnfeed.plan_for(vulnfeed.TRUSTED_VULN_SOURCES, ["CVE-2024-1111"])
    r1 = vulnfeed.refresh_vulnintel(plan, transport_for=_tfor, ingest=ing, seq=0)
    assert r1.cancelled is False and r1.queries_run == 3        # nvd + osv (per-cve) + kev (bulk)
    assert r1.last_seq == 3                                     # one monotonic tick per fetch, seq 0..2
    assert r1.minted_by_source["cisa-kev"] >= 2 and r1.minted_by_source["nvd"] >= 1
    assert r1.applied > 0
    r2 = vulnfeed.refresh_vulnintel(plan, transport_for=_tfor, ingest=ing, seq=0)   # SAME ingest → dedup
    assert r2.applied == 0                                      # idempotent: nothing re-projected


# ---- stoppable: cancel / kill-switch honoured ------------------------------

def test_cancel_halts_before_any_fetch():
    r = vulnfeed.refresh_vulnintel(
        vulnfeed.plan_for(vulnfeed.TRUSTED_VULN_SOURCES, ["CVE-1"]),
        transport_for=_tfor, ingest=IntelIngest(WorldModel()), seq=0, cancel=lambda: True)
    assert r.cancelled is True and r.queries_run == 0 and r.applied == 0


def test_cancel_mid_plan_is_honoured():
    # allow the first source-start + first per-CVE fetch, then trip on the next check.
    n = {"c": 0}

    def cancel():
        n["c"] += 1
        return n["c"] >= 3

    r = vulnfeed.refresh_vulnintel(
        vulnfeed.plan_for(vulnfeed.TRUSTED_VULN_SOURCES, ["CVE-a", "CVE-b"]),
        transport_for=_tfor, ingest=IntelIngest(WorldModel()), seq=0, cancel=cancel)
    assert r.cancelled is True and r.queries_run == 1          # one fetch ran, then STOP halted the rest


# ---- egress gate: concrete host only, disjoint from target -----------------

def test_transport_refuses_source_overlapping_target_scope():
    nvd = vulnfeed.source_by_name("nvd")
    with pytest.raises(CollectorEgressRefused):
        vulnfeed.build_vulnintel_transport(nvd, target_hosts=("services.nvd.nist.gov",))


def test_transport_permits_only_its_own_host_and_calls_once():
    nvd = vulnfeed.source_by_name("nvd")
    client = _RecordingClient(status=200, payload=_NVD)
    t = vulnfeed.build_vulnintel_transport(nvd, client=client)
    rec = t.fetch(IntelSourceKind.VULN_DB, "CVE-2024-1111", seq=1)
    assert rec.ok and len(client.calls) == 1
    assert client.calls[0].startswith("https://services.nvd.nist.gov/")   # only its own apex host


def test_refresh_records_a_gate_refused_source_and_continues():
    # a source the egress gate refuses (e.g. it overlaps target scope — the CLI now wires the charter
    # scope so this guard actually fires) is recorded and skipped fail-closed; other sources still pull,
    # and the refused source consumes NO seq (no bytes left for it).
    def tfor(s):
        if s.name == "nvd":
            raise CollectorEgressRefused("nvd overlaps target scope")
        return _FakeTransport(_PAYLOAD_BY_NAME[s.name])

    r = vulnfeed.refresh_vulnintel(
        vulnfeed.plan_for(vulnfeed.TRUSTED_VULN_SOURCES, ["CVE-x"]),
        transport_for=tfor, ingest=IntelIngest(WorldModel()), seq=0)
    assert "nvd" in r.refused and r.minted_by_source.get("nvd", 0) == 0
    assert r.minted_by_source.get("cisa-kev", 0) >= 2      # the safe sources still pulled
    assert r.cancelled is False


# ---- scheduler: pure due() + tick, no daemon -------------------------------

def test_schedule_due_and_advance_are_pure():
    s = scheduler.FeedSchedule(interval=10)
    assert s.due(0) is True                                     # never run → due immediately
    s1 = s.advance(0)
    assert s1.due(5) is False and s1.due(10) is True            # cadence in monotonic ticks
    assert scheduler.FeedSchedule(interval=0).due(999) is False  # disabled schedule never due


def test_run_once_runs_only_when_due_and_not_cancelled():
    s = scheduler.FeedSchedule(interval=5)
    ran = {"n": 0}

    def refresh():
        ran["n"] += 1
        return "ok"

    t1 = scheduler.run_once(s, 0, refresh=refresh)
    assert t1.ran is True and t1.result == "ok" and t1.schedule.last_run == 0
    t2 = scheduler.run_once(t1.schedule, 2, refresh=refresh)    # not due yet
    assert t2.ran is False and ran["n"] == 1
    t3 = scheduler.run_once(t1.schedule, 9, refresh=refresh, cancel=lambda: True)  # due but stopped
    assert t3.ran is False and ran["n"] == 1


# ---- CLI: fail-closed (no --live → no traffic) -----------------------------

def _ns(**kw):
    base = {"sources": "", "cve": "", "slug": "", "live": False, "capture": ""}
    base.update(kw)
    return argparse.Namespace(**base)


def test_cli_without_live_fires_no_traffic(capsys):
    rc = _refresh_vulnintel(_ns(live=False, cve="CVE-2024-1111"))
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["live"] is False                                 # offline: nothing fetched
    assert "minted_by_source" not in out                       # no pull happened
    assert {s["name"] for s in out["sources"]} == {"nvd", "osv", "cisa-kev"}
    assert "offline" in out["note"].lower() and "LEAD" in out["doctrine"]


def test_cli_unknown_source_errors():
    assert _refresh_vulnintel(_ns(sources="nvd,bogus", live=True)) == 2   # unknown source → exit 2, no pull


# ---- ticker: drives the PURE scheduler on real time, stoppably ------------------

def test_ticker_fires_only_on_due_ticks():
    from framework.v2.intel import ticker
    calls = []
    # interval 3 ticks → due at ticks 0, 3, 6; max_ticks 7 → ticks 0..6, injected no-op sleep.
    summary = ticker.run_feed_daemon(interval_ticks=3, poll_seconds=0,
                                     refresh=lambda: calls.append(1) or "r",
                                     max_ticks=7, sleep=lambda _s: None)
    assert summary == {"ticks": 7, "refreshes": 3}
    assert len(calls) == 3


def test_ticker_cancel_halts_before_any_refresh_or_sleep():
    from framework.v2.intel import ticker
    calls = []

    def _no_sleep(_s):
        raise AssertionError("a cancelled daemon must not sleep")

    summary = ticker.run_feed_daemon(interval_ticks=1, poll_seconds=99,
                                     refresh=lambda: calls.append(1), cancel=lambda: True,
                                     max_ticks=100, sleep=_no_sleep)
    assert summary == {"ticks": 0, "refreshes": 0} and calls == []   # stopped at the top, never fired/slept


# ---- CLI feed-daemon: fail-closed (no --live → no traffic) ----------------------

def _ns_daemon(**kw):
    base = {"sources": "", "cve": "", "slug": "", "live": False, "capture": "",
            "interval": 3600, "poll": 30, "max_ticks": 0}
    base.update(kw)
    return argparse.Namespace(**base)


def test_feed_daemon_without_live_fires_no_traffic(capsys):
    from framework.v2.intel.cli import _feed_daemon
    assert _feed_daemon(_ns_daemon(live=False)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["live"] is False                                    # offline: nothing fetched, no loop entered
    assert "LIVE recurring egress" in out["note"] and "LEAD" in out["doctrine"]


def test_feed_daemon_unknown_source_errors_before_any_traffic():
    from framework.v2.intel.cli import _feed_daemon
    assert _feed_daemon(_ns_daemon(sources="nvd,bogus", live=True)) == 2   # exit 2 before the loop/egress


def test_feed_daemon_rejects_nonpositive_interval():
    from framework.v2.intel.cli import _feed_daemon
    assert _feed_daemon(_ns_daemon(live=True, interval=0)) == 2
    assert _feed_daemon(_ns_daemon(live=True, poll=0)) == 2
