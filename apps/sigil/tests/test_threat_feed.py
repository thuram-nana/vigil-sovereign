"""The live public THREAT FEED behind the consumer-app Overview globe + the public hero globe.

Everything here runs on FIXTURES — committed sample payloads of the REAL feeds — with NO live network, so CI
never reaches cisa.gov / isc.sans.edu. What is pinned:
  * each source's real sample payload parses to the right summary (CISA KEV totals/added/recent; DShield
    country aggregation);
  * DEFENSIVE parsing — a malformed / oversized / missing / wrong-typed external document never crashes or
    blows up, it shrinks to empty;
  * the cache's atomic write + TTL staleness + last-good-on-corruption;
  * the honest degraded state — a cold / unreachable feed answers `populated: false`, never a fabricated
    number, and a stale cache serves last-good flagged `stale`;
  * the `GET /api/threatfeed` route shape on BOTH keyless planes (pubui hero + custui Overview);
  * the globe's counter reading REAL numbers vs the honest-empty resting copy (app.js, under node).
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from sigil.threat_feed import feed, sources
from sigil.threat_feed.store import ThreatFeedCache

_FIX = Path(__file__).resolve().parent / "fixtures" / "threat_feed"
# A fixed "now": 2024-11-27 12:00:00 UTC. The KEV fixture's dates are chosen against this so added_24h/_7d
# are deterministic (no wall-clock flakiness).
_NOW = 1732708800.0 + 12 * 3600  # 2024-11-27T12:00:00Z


def _kev_doc() -> dict:
    return json.loads((_FIX / "cisa_kev_sample.json").read_text(encoding="utf-8"))


def _dshield_doc():
    return json.loads((_FIX / "dshield_sources_sample.json").read_text(encoding="utf-8"))


# ===================================================================================================
# CISA KEV — the primary live-activity summary (parse the real sample payload)
# ===================================================================================================
def test_kev_summary_parses_the_real_sample_payload():
    s = sources.kev_summary(_kev_doc(), now_epoch=_NOW)
    assert s["total"] == 4                      # five entries, the invalid-id one dropped
    assert s["catalog_version"] == "2024.11.27"
    assert s["added_24h"] == 1                   # only the 2024-11-27 entry is within a day of _NOW
    assert s["added_7d"] == 2                    # 2024-11-27 + 2024-11-26
    # recent is newest-first by dateAdded, bounded, each a flat validated record
    assert [r["cve"] for r in s["recent"]] == [
        "CVE-2024-9999", "CVE-2024-3400", "CVE-2023-34362", "CVE-2021-44228"]
    top = s["recent"][0]
    assert top == {"cve": "CVE-2024-9999", "name": "Acme Gateway Authentication Bypass",
                   "date_added": "2024-11-27", "vendor": "Acme", "product": "Gateway", "ransomware": True}
    assert s["recent"][1]["ransomware"] is False          # PAN-OS: knownRansomwareCampaignUse Unknown
    assert s["recent"][3]["cve"] == "CVE-2021-44228" and s["recent"][3]["ransomware"] is True


@pytest.mark.parametrize("bad", [
    None, {}, [], "nope", 123,
    {"vulnerabilities": "not-a-list"},
    {"vulnerabilities": [None, 123, "x", {"cveID": None}, {"cveID": "bogus"}, {"no": "id"}]},
    {"vulnerabilities": [{"cveID": "CVE-2024-0001", "dateAdded": {"nested": "evil"},
                          "vulnerabilityName": ["list", "not", "str"], "knownRansomwareCampaignUse": 5}]},
])
def test_kev_summary_is_defensive_against_malformed_or_hostile_shapes(bad):
    s = sources.kev_summary(bad, now_epoch=_NOW)
    # never raises; shape is always right; a hostile doc shrinks to empty, never a wrong type downstream
    assert set(s) == {"total", "added_24h", "added_7d", "catalog_version", "recent"}
    assert isinstance(s["total"], int) and isinstance(s["recent"], list)
    for r in s["recent"]:
        assert isinstance(r["cve"], str) and isinstance(r["name"], str) and isinstance(r["ransomware"], bool)


def test_kev_summary_bounds_recent_and_clamps_strings_on_a_huge_feed():
    huge = {"vulnerabilities": [
        {"cveID": f"CVE-2024-{1000 + i}", "dateAdded": "2024-11-27",
         "vulnerabilityName": "x" * 5000, "vendorProject": "y" * 5000} for i in range(2000)]}
    s = sources.kev_summary(huge, now_epoch=_NOW)
    assert s["total"] == 2000
    assert len(s["recent"]) <= 25                              # the recent list is bounded
    assert all(len(r["name"]) <= 300 and len(r["vendor"]) <= 80 for r in s["recent"])  # strings clamped


def test_kev_future_dated_entry_never_inflates_a_recent_count():
    doc = {"vulnerabilities": [{"cveID": "CVE-2099-0001", "dateAdded": "2099-01-01"}]}
    s = sources.kev_summary(doc, now_epoch=_NOW)
    assert s["total"] == 1 and s["added_24h"] == 0 and s["added_7d"] == 0   # a future (negative-age) date never counts


# ===================================================================================================
# SANS ISC / DShield — OPTIONAL country-aggregated geo (parse the sample; defensive)
# ===================================================================================================
def test_dshield_country_points_aggregates_the_sample_by_country():
    pts = sources.dshield_country_points(_dshield_doc())
    by_cc = {p["cc"]: p for p in pts}
    assert set(by_cc) == {"US", "CN", "RU", "DE"}             # ZZ (unknown centroid) dropped, not faked
    assert by_cc["US"]["weight"] == 1250                      # 950 + 300 summed
    assert pts[0]["cc"] == "US" and pts[0]["weight"] == 1250  # heaviest first
    assert all(isinstance(p["lat"], (int, float)) and isinstance(p["lon"], (int, float)) for p in pts)


@pytest.mark.parametrize("bad", [
    None, {}, "x", 5, [None, 1, "s", {"ascountry": 123}, {"ascountry": "ZZ", "attacks": 9},
                        {"ascountry": "US", "attacks": "not-a-number"}, {"country": "DE"}],
    {"sources": "not-a-list"},
])
def test_dshield_country_points_is_defensive(bad):
    pts = sources.dshield_country_points(bad)
    assert isinstance(pts, list)
    for p in pts:
        assert set(p) == {"cc", "lat", "lon", "weight"} and isinstance(p["weight"], int) and p["weight"] >= 0


def test_dshield_accepts_a_wrapped_sources_object():
    pts = sources.dshield_country_points({"sources": [{"ascountry": "US", "attacks": 3}]})
    assert pts and pts[0]["cc"] == "US"


def test_int_is_robust_against_nonfinite_and_overflow_numerics():
    # red-pen finding 1: a huge/infinite JSON numeric must never raise (OverflowError) past the parser.
    assert sources._int(1e400, 5) == 5                       # 1e400 → inf → rejected, returns default
    assert sources._int(float("inf"), 5) == 5
    assert sources._int(float("nan"), 5) == 5                # json.loads accepts NaN tokens
    assert sources._int(10 ** 400, 5) == 5                   # an int too large to even float → default
    assert sources._int("17", 5) == 17                       # a numeric string still parses
    assert sources._int("junk", 5) == 5
    assert sources._int(sources._INT_MAX * 1000, 0) == sources._INT_MAX   # a finite out-of-range value clamps


def test_dshield_drops_a_row_with_a_nonfinite_or_overflow_count():
    # a hostile count (1e400 → inf, or an int too large to float) is distrusted: the row is DROPPED, never
    # fabricated onto a real country, and it never raises OverflowError past this pure parser.
    pts = sources.dshield_country_points([
        {"ascountry": "US", "attacks": 1e400},              # inf → dropped
        {"ascountry": "CN", "attacks": 10 ** 400},          # int too large to float → dropped
        {"ascountry": "DE", "attacks": 7},                  # the one honest row survives
    ])
    by_cc = {p["cc"]: p for p in pts}
    assert set(by_cc) == {"DE"} and by_cc["DE"]["weight"] == 7


# ===================================================================================================
# fetch_json — the one outbound primitive: host-allowlisted + size-capped (no live network needed)
# ===================================================================================================
def test_fetch_json_refuses_a_non_allowlisted_host_no_ssrf():
    with pytest.raises(ValueError, match="non-allowlisted"):
        sources.fetch_json("https://evil.example.com/x.json")
    with pytest.raises(ValueError, match="non-allowlisted"):
        sources.fetch_json("http://169.254.169.254/latest/meta-data/")   # cloud metadata SSRF target


def test_fetch_json_caps_an_oversize_body(monkeypatch):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"x" * n                 # always returns the full requested size → triggers the > cap check

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())
    with pytest.raises(ValueError, match="too large"):
        sources.fetch_json(sources.KEV_URL, max_bytes=1024)


# ===================================================================================================
# the cache — atomic write, TTL staleness, last-good on corruption
# ===================================================================================================
def test_cache_round_trips_and_stamps_as_of(tmp_path):
    cache = ThreatFeedCache(tmp_path / "feed.json")
    cache.write({"hello": "world"}, now=_NOW)
    data, as_of = cache.read_data()
    assert data == {"hello": "world"} and as_of == _NOW


def test_cache_staleness_against_ttl(tmp_path):
    cache = ThreatFeedCache(tmp_path / "feed.json")
    cache.write({"k": 1}, now=_NOW)
    assert cache.is_stale(3600, now=_NOW + 10) is False
    assert cache.is_stale(3600, now=_NOW + 7200) is True


@pytest.mark.parametrize("blob", [b"", b"not json", b"[]", b'{"as_of": 1}', b'{"data": "not a dict"}'])
def test_cache_reads_none_on_missing_or_corrupt(tmp_path, blob):
    p = tmp_path / "feed.json"
    cache = ThreatFeedCache(p)
    assert cache.read() is None                     # missing file
    p.write_bytes(blob)
    assert cache.read() is None and cache.read_data() == (None, 0.0)
    assert cache.is_stale(3600) is True             # no good cache ⇒ stale


# ===================================================================================================
# the orchestrator — build_snapshot / refresh (fetch is injected; no network)
# ===================================================================================================
def test_build_snapshot_kev_only_leaves_geo_illustrative():
    snap = feed.build_snapshot(dshield=False, now_epoch=_NOW, fetch=lambda url, **k: _kev_doc())
    assert snap["kev"]["total"] == 4 and snap["geo"] == [] and snap["geo_source"] == "illustrative"
    assert snap["sources"] == [{"name": "cisa-kev", "status": "ok"}]


def test_build_snapshot_with_dshield_adds_real_geo():
    def _fetch(url, **k):
        return _dshield_doc() if "isc.sans.edu" in url else _kev_doc()
    snap = feed.build_snapshot(dshield=True, now_epoch=_NOW, fetch=_fetch)
    assert snap["geo_source"] == "dshield" and snap["geo"][0]["cc"] == "US"
    assert {"name": "dshield", "status": "ok"} in snap["sources"]


def test_build_snapshot_degrades_geo_when_dshield_fails_but_kev_survives():
    def _fetch(url, **k):
        if "isc.sans.edu" in url:
            raise urllib.error.URLError("dshield down")
        return _kev_doc()
    snap = feed.build_snapshot(dshield=True, now_epoch=_NOW, fetch=_fetch)
    assert snap["kev"]["total"] == 4 and snap["geo"] == [] and snap["geo_source"] == "illustrative"
    assert {"name": "dshield", "status": "unavailable"} in snap["sources"]


def test_build_snapshot_survives_a_hostile_dshield_numeric_and_keeps_kev():
    # red-pen finding 1: a huge/infinite DShield count must NOT escape the guard as an OverflowError and abort
    # the whole refresh — the KEV/CVE side survives and geo degrades to illustrative, never a crash.
    hostile = [{"ascountry": "US", "attacks": 1e400},        # inf
               {"ascountry": "CN", "attacks": 10 ** 400}]     # int too large to float

    def _fetch(url, **k):
        return hostile if "isc.sans.edu" in url else _kev_doc()
    snap = feed.build_snapshot(dshield=True, now_epoch=_NOW, fetch=_fetch)
    assert snap["kev"]["total"] == 4                          # the required KEV refresh survived — not aborted
    assert snap["geo"] == [] and snap["geo_source"] == "illustrative"   # hostile geo dropped, honest fallback


def test_refresh_keeps_last_good_when_kev_fetch_fails(tmp_path):
    cache = ThreatFeedCache(tmp_path / "feed.json")
    feed.refresh(cache, now_epoch=_NOW, fetch=lambda url, **k: _kev_doc())
    good, _ = cache.read_data()
    assert good["kev"]["total"] == 4

    def _boom(url, **k):
        raise urllib.error.URLError("kev down")
    with pytest.raises(urllib.error.URLError):
        feed.refresh(cache, now_epoch=_NOW + 100, fetch=_boom)
    # the cache is UNTOUCHED — last-good is preserved, nothing fabricated written
    still, as_of = cache.read_data()
    assert still["kev"]["total"] == 4 and as_of == _NOW


# ===================================================================================================
# the edge read — api_response: real, honest-empty, stale, geo real vs illustrative, catalog reuse
# ===================================================================================================
def _seed_catalog(tmp_path):
    from sigil.cve.catalog import CveCatalogStore
    db = tmp_path / "cat.db"
    st = CveCatalogStore(str(db))
    recent_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(_NOW - 2 * 86400))
    old_iso = "2015-01-01T00:00:00"
    st.merge_many([
        {"id": "CVE-2024-5555", "title": "recent", "published": recent_iso, "cvss_base": 9.1, "kev": True},
        {"id": "CVE-2015-0001", "title": "old", "published": old_iso, "cvss_base": 5.0},
    ])
    return db


def test_api_response_populated_with_real_numbers(tmp_path):
    cache = ThreatFeedCache(tmp_path / "feed.json")
    feed.refresh(cache, now_epoch=_NOW, fetch=lambda url, **k: _kev_doc())
    db = _seed_catalog(tmp_path)
    r = feed.api_response(tmp_path / "feed.json", db, ttl_seconds=3600, now_epoch=_NOW + 10)
    assert r["populated"] is True and r["stale"] is False
    assert r["metrics"]["kev_total"] == 4 and r["metrics"]["kev_added_24h"] == 1
    assert r["metrics"]["cve_total"] == 2 and r["metrics"]["cve_kev"] == 1 and r["metrics"]["cve_recent"] == 1
    assert r["recent"][0]["cve"] == "CVE-2024-9999"
    assert r["geo"] == [] and r["geo_source"] == "illustrative"      # KEV-only ⇒ illustrative
    assert isinstance(r["as_of"], int)


def test_api_response_is_honestly_empty_when_cold(tmp_path):
    # no cache written, no catalog → honest "warming up", never a fabricated number
    r = feed.api_response(tmp_path / "absent.json", tmp_path / "absent.db", ttl_seconds=3600, now_epoch=_NOW)
    assert r["populated"] is False and r["stale"] is True
    assert r["metrics"] == {"kev_total": 0, "kev_added_24h": 0, "kev_added_7d": 0,
                            "cve_recent": 0, "cve_total": 0, "cve_kev": 0}
    assert r["recent"] == [] and r["geo"] == [] and r["as_of"] is None


def test_api_response_marks_a_stale_cache_but_still_serves_last_good(tmp_path):
    cache = ThreatFeedCache(tmp_path / "feed.json")
    feed.refresh(cache, now_epoch=_NOW, fetch=lambda url, **k: _kev_doc())
    r = feed.api_response(tmp_path / "feed.json", None, ttl_seconds=3600, now_epoch=_NOW + 999999)
    assert r["populated"] is True and r["stale"] is True            # last-good numbers, flagged stale
    assert r["metrics"]["kev_total"] == 4


def test_api_response_serves_real_geo_when_dshield_cached(tmp_path):
    cache = ThreatFeedCache(tmp_path / "feed.json")

    def _fetch(url, **k):
        return _dshield_doc() if "isc.sans.edu" in url else _kev_doc()
    feed.refresh(cache, dshield=True, now_epoch=_NOW, fetch=_fetch)
    r = feed.api_response(tmp_path / "feed.json", None, ttl_seconds=3600, now_epoch=_NOW + 10)
    assert r["geo_source"] == "dshield" and r["geo"][0]["cc"] == "US"
    assert all(set(p) == {"cc", "lat", "lon", "weight"} for p in r["geo"])


def test_api_response_populated_from_catalog_alone_when_no_feed(tmp_path):
    db = _seed_catalog(tmp_path)
    r = feed.api_response(tmp_path / "absent.json", db, ttl_seconds=3600, now_epoch=_NOW)
    # the live KEV feed is cold but the local catalog has data ⇒ still populated (honest), just stale
    assert r["populated"] is True and r["stale"] is True
    assert r["metrics"]["cve_total"] == 2 and r["metrics"]["kev_total"] == 0


def test_api_response_never_raises_on_a_corrupt_cache(tmp_path):
    (tmp_path / "feed.json").write_bytes(b"\x00\x01 not json {{{")
    r = feed.api_response(tmp_path / "feed.json", None, ttl_seconds=3600, now_epoch=_NOW)
    assert r["populated"] is False and r["metrics"]["kev_total"] == 0


# ===================================================================================================
# the /api/threatfeed ROUTE SHAPE — public hero plane (pubui) and consumer plane (custui)
# ===================================================================================================
def _refresh_into(path: Path):
    feed.refresh(ThreatFeedCache(path), now_epoch=_NOW, fetch=lambda url, **k: _kev_doc())


def test_pubui_threatfeed_route_shape_populated_and_cold(tmp_path, monkeypatch):
    from sigil import config
    from sigil.ui.pubui import PublicHandler, PublicServer
    cache_path = tmp_path / "tf.json"
    monkeypatch.setattr(config, "THREAT_FEED_CACHE_PATH", cache_path)
    monkeypatch.setattr(config, "THREAT_FEED_TTL_SECONDS", 3600)
    db = _seed_catalog(tmp_path)
    srv = PublicServer(("127.0.0.1", 0), PublicHandler, catalog_path=str(db))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    port = srv.server_address[1]
    try:
        # cold cache: honest, populated via the catalog, no cookie, strict public headers
        status, hdrs, raw = _raw_get(port, "/api/threatfeed")
        d = json.loads(raw)
        assert status == 200 and hdrs.get("Content-Type", "").startswith("application/json")
        assert "Set-Cookie" not in hdrs and hdrs.get("X-Content-Type-Options") == "nosniff"
        # red-pen finding 4: the threat feed carries a `stale` flag + a freshness window, so it must be
        # no-store (NOT the CVE API's `public, max-age=300`) — a CDN must never serve a stale body as fresh.
        assert hdrs.get("Cache-Control") == "no-store"
        assert set(d) >= {"metrics", "recent", "geo", "geo_source", "populated", "stale", "as_of", "sources"}
        assert d["metrics"]["kev_total"] == 0 and d["metrics"]["cve_total"] == 2   # catalog reused
        # now a refreshed cache: real KEV numbers show
        _refresh_into(cache_path)
        d2 = json.loads(_raw_get(port, "/api/threatfeed")[2])
        assert d2["populated"] is True and d2["metrics"]["kev_total"] == 4 and d2["metrics"]["kev_added_24h"] == 1
    finally:
        srv.shutdown()


def test_custui_threatfeed_route_is_keyless_and_honest(tmp_path, monkeypatch):
    from sigil import config
    from sigil.ui.custui import build_customer_server
    cache_path = tmp_path / "tf.json"
    db = _seed_catalog(tmp_path)
    monkeypatch.setattr(config, "THREAT_FEED_CACHE_PATH", cache_path)
    monkeypatch.setattr(config, "CVE_CATALOG_PATH", db)
    monkeypatch.setattr(config, "THREAT_FEED_TTL_SECONDS", 3600)
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="hk", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "sess"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    port = srv.server_address[1]
    try:
        _refresh_into(cache_path)
        status, hdrs, raw = _raw_get(port, "/api/threatfeed")       # NO cookie sent — a keyless public read
        d = json.loads(raw)
        assert status == 200 and "Set-Cookie" not in hdrs           # unauthenticated: mints no session
        assert hdrs.get("Cache-Control") == "no-store"              # /api/* is never cached
        assert d["populated"] is True and d["metrics"]["kev_total"] == 4
        assert d["metrics"]["cve_total"] == 2 and d["recent"][0]["cve"] == "CVE-2024-9999"
        assert d["geo"] == [] and d["geo_source"] == "illustrative"
    finally:
        srv.shutdown()


def _raw_get(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# ===================================================================================================
# the globe's counter — app.js reads REAL numbers vs the honest-empty resting copy (under node)
# ===================================================================================================
_APP_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "app.js"


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    line = src[i:src.index("\n", i)]
    if line.count("{") and line.count("{") == line.count("}"):
        return line + "\n"
    return src[i:src.index("\n  }\n", i) + 4]


def _need_node() -> str:
    import shutil
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not available")
    return node


def _run_counter_js(script: str) -> dict:
    src = _APP_JS.read_text(encoding="utf-8")
    funcs = "\n".join(_fn(src, n) for n in ("threatText", "fmtN", "fmtAsOf", "loadThreatActivity"))
    prog = ("globalThis.window = globalThis;\n" + funcs
            + "\nconst out = {};\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
              " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_globe_counter_renders_real_numbers_when_populated():
    out = _run_counter_js(r"""
      out.added = threatText({ populated: true, metrics: { kev_total: 1234, kev_added_24h: 3, kev_added_7d: 9 } });
      out.onlyTotal = threatText({ populated: true, metrics: { kev_total: 1234, kev_added_24h: 0, kev_added_7d: 9 } });
      out.one = threatText({ populated: true, metrics: { kev_total: 1, kev_added_24h: 1, kev_added_7d: 1 } });
    """)
    # honest wording: kev_added_24h is CISA's dateAdded (catalogued), never "newly-exploited" (red-pen finding 3)
    assert "newly-exploited" not in out["added"] and "newly-exploited" not in out["one"]
    assert out["added"].startswith("3 added to the CISA KEV catalog · 24h")
    assert "1,234 known-exploited tracked" in out["added"]
    assert out["onlyTotal"] == "1,234 known-exploited vulnerabilities tracked · 9 added this week"
    assert out["one"].startswith("1 added to the CISA KEV catalog · 24h")   # live 24h window on a fresh cache


def test_globe_counter_is_honestly_empty_and_never_fabricates():
    out = _run_counter_js(r"""
      out.cold = threatText({ populated: false, metrics: { kev_total: 0 } });
      out.zero = threatText({ populated: true, metrics: { kev_total: 0, kev_added_24h: 0, kev_added_7d: 0 } });
      out.nullres = threatText(null);
    """)
    assert out["cold"] is None and out["zero"] is None and out["nullres"] is None   # keep the resting copy


def test_globe_counter_stale_feed_drops_the_live_24h_window_and_dates_the_as_of():
    # red-pen finding 2: on a STALE feed the frozen kev_added_24h must NOT be presented as a current 24h
    # window, and the staleness cue must carry a DATE (not just a clock that could read as "today").
    out = _run_counter_js(r"""
      out.stale = threatText({ populated: true, stale: true, as_of: 1732708800,
                               metrics: { kev_total: 1234, kev_added_24h: 3, kev_added_7d: 9 } });
    """)
    assert "· 24h" not in out["stale"]                       # no live "· 24h" label on a frozen count
    assert "newly-exploited" not in out["stale"]                  # and never the dishonest "newly-exploited"
    assert out["stale"].startswith("1,234 known-exploited vulnerabilities tracked")   # leads with the tracked total
    assert re.search(r"as of [A-Z][a-z]{2} \d", out["stale"])     # an explicit DATE (e.g. "as of Nov 27"), not just a clock


def test_globe_counter_load_sets_live_on_a_real_feed_and_leaves_resting_on_failure():
    out = _run_counter_js(r"""
      function fakeStrip() { return { classList: { _c: [], add(c){ this._c.push(c); }, has(c){ return this._c.indexOf(c)>=0; } } }; }
      // a populated feed → the line is filled and the strip goes live
      let line1 = { textContent: "warming up" }, strip1 = fakeStrip();
      window.fetch = async () => ({ ok: true, json: async () => ({ populated: true, metrics: { kev_total: 50, kev_added_24h: 2, kev_added_7d: 4 } }) });
      await loadThreatActivity(strip1, line1);
      out.liveText = line1.textContent; out.live = strip1.classList.has("is-live");
      // a failing fetch → the resting copy stays, never a fake number, never live
      let line2 = { textContent: "warming up" }, strip2 = fakeStrip();
      window.fetch = async () => { throw new Error("network down"); };
      await loadThreatActivity(strip2, line2);
      out.failText = line2.textContent; out.failLive = strip2.classList.has("is-live");
      // an honest-empty feed → resting copy stays
      let line3 = { textContent: "warming up" }, strip3 = fakeStrip();
      window.fetch = async () => ({ ok: true, json: async () => ({ populated: false, metrics: {} }) });
      await loadThreatActivity(strip3, line3);
      out.emptyText = line3.textContent; out.emptyLive = strip3.classList.has("is-live");
    """)
    assert out["live"] is True and out["liveText"].startswith("2 added to the CISA KEV catalog · 24h")
    assert out["failLive"] is False and out["failText"] == "warming up"
    assert out["emptyLive"] is False and out["emptyText"] == "warming up"


# ===================================================================================================
# the PUBLIC hero counter — home.js threatLine: same honest copy + stale semantics as the app (under node)
# ===================================================================================================
_HOME_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site" / "assets" / "home.js"


def _run_home_js(script: str) -> dict:
    src = _HOME_JS.read_text(encoding="utf-8")
    funcs = "\n".join(_fn(src, n) for n in ("fmt", "plural", "asOfLabel", "threatLine"))
    prog = ("globalThis.window = globalThis;\n" + funcs
            + "\nconst out = {};\n(() => {\n" + script
            + "\n})();\nprocess.stdout.write(JSON.stringify(out));")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_home_threat_line_live_copy_is_honest_about_catalogue_additions():
    # red-pen finding 3: the public hero copy must reflect that kev_added_24h is CISA's dateAdded (catalogued),
    # not "newly-exploited".
    out = _run_home_js(r"""
      out.live = threatLine({ metrics: { kev_total: 1234, kev_added_24h: 3, kev_added_7d: 9 } });
      out.onlyTotal = threatLine({ metrics: { kev_total: 1234, kev_added_24h: 0, kev_added_7d: 9 } });
    """)
    assert "newly-exploited" not in out["live"]
    assert out["live"].startswith("3 added to the CISA KEV catalog · 24h")
    assert "1,234 known-exploited tracked" in out["live"]
    assert out["onlyTotal"] == "1,234 known-exploited vulnerabilities tracked · 9 added this week"


def test_home_threat_line_stale_drops_24h_window_and_dates_the_as_of():
    # red-pen finding 2: a stale hero feed must not present the frozen count as a live 24h window, and the
    # staleness cue must carry the DATE of as_of.
    out = _run_home_js(r"""
      out.stale = threatLine({ stale: true, as_of: 1732708800,
                               metrics: { kev_total: 1234, kev_added_24h: 3, kev_added_7d: 9 } });
    """)
    assert "· 24h" not in out["stale"] and "newly-exploited" not in out["stale"]
    assert out["stale"].startswith("1,234 known-exploited vulnerabilities tracked")
    assert re.search(r"as of [A-Z][a-z]{2} \d", out["stale"])     # an explicit DATE, not just a clock


def test_home_threat_line_is_honestly_empty():
    out = _run_home_js(r"""
      out.cold = threatLine({ metrics: { kev_total: 0 } });
      out.nullres = threatLine(null);
    """)
    assert out["cold"] is None and out["nullres"] is None         # nothing real ⇒ keep the resting copy
