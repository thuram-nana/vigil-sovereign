"""The public CVE catalog store — a sovereign-side, offense-free SQLite mirror.

Invariants: strict CVE-id validation (it's a PK and a public path component); severity derived from the
CVSS base when absent; multi-feed MERGE combines NVD+OSV+KEV+EPSS into one row (scalars fill-if-empty,
lists union de-duped, feeds accumulate) without clobbering; filtered + paginated queries are parameterized.
"""
from __future__ import annotations

import tempfile

from sigil.cve.catalog import CveCatalogStore, normalize_cve_id, severity_for


def _store():
    return CveCatalogStore(tempfile.mktemp(suffix=".db"))


def test_cve_id_validation_and_severity_bands():
    assert normalize_cve_id("cve-2024-0001") == "CVE-2024-0001"
    assert normalize_cve_id("CVE-2021-44228") == "CVE-2021-44228"
    for bad in ("", "CVE-2024", "2024-0001", "CVE-20-1", "../etc", "CVE-abcd-0001"):
        assert normalize_cve_id(bad) is None
    assert severity_for(None) is None
    assert severity_for(0) == "none" and severity_for(3.9) == "low" and severity_for(4.0) == "medium"
    assert severity_for(7.0) == "high" and severity_for(9.8) == "critical"


def test_upsert_get_and_derived_fields():
    s = _store()
    assert s.upsert({"id": "CVE-2021-44228", "description": "Log4Shell", "cvss_base": 10.0,
                     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "kev": True,
                     "cwes": ["CWE-502"], "feeds": ["nvd"]})
    assert s.upsert({"id": "not-a-cve"}) is False            # rejected
    r = s.get("cve-2021-44228")                               # case-insensitive lookup
    assert r["id"] == "CVE-2021-44228" and r["year"] == 2021
    assert r["severity"] == "critical"                        # derived from base 10.0
    assert r["kev"] is True and r["cwes"] == ["CWE-502"] and r["feeds"] == ["nvd"]
    assert s.get("nope") is None and s.get("CVE-1999-9999") is None


def test_multi_feed_merge_combines_without_clobbering():
    s = _store()
    # NVD first: base score + a CWE + a reference
    s.merge({"id": "CVE-2024-1234", "description": "nvd desc", "cvss_base": 7.5, "cwes": ["CWE-79"],
             "refs": [{"url": "https://nvd/a"}], "feeds": ["nvd"]})
    # OSV adds an alias + another ref + an affected range (and a description that must NOT overwrite NVD's)
    s.merge({"id": "CVE-2024-1234", "description": "osv desc", "aliases": ["GHSA-xxxx"],
             "refs": [{"url": "https://osv/b"}], "affected": [{"ecosystem": "npm", "name": "x"}],
             "feeds": ["osv"]})
    # KEV marks it exploited; EPSS adds probability
    s.merge({"id": "CVE-2024-1234", "kev": True, "kev_date": "2024-06-01", "feeds": ["cisa-kev"]})
    s.merge({"id": "CVE-2024-1234", "epss_score": 0.97, "epss_pct": 0.99, "feeds": ["epss"]})
    r = s.get("CVE-2024-1234")
    assert r["description"] == "nvd desc"                      # fill-if-empty: NVD's description kept
    assert r["cvss_base"] == 7.5 and r["severity"] == "high"
    assert r["kev"] is True and r["kev_date"] == "2024-06-01"
    assert r["epss_score"] == 0.97
    assert r["cwes"] == ["CWE-79"] and r["aliases"] == ["GHSA-xxxx"]
    assert {x["url"] for x in r["refs"]} == {"https://nvd/a", "https://osv/b"}   # union
    assert sorted(r["feeds"]) == ["cisa-kev", "epss", "nvd", "osv"]              # all feeds accumulate
    # merging the SAME ref again does not duplicate
    s.merge({"id": "CVE-2024-1234", "refs": [{"url": "https://nvd/a"}], "feeds": ["nvd"]})
    assert len(s.get("CVE-2024-1234")["refs"]) == 2


def test_query_filters_pagination_and_order():
    s = _store()
    s.merge_many([
        {"id": "CVE-2024-0001", "published": "2024-01-01", "cvss_base": 9.9, "kev": True},
        {"id": "CVE-2024-0002", "published": "2024-02-01", "cvss_base": 5.0},
        {"id": "CVE-2023-0003", "published": "2023-03-01", "cvss_base": 2.0, "description": "sqli bug"},
        {"id": "CVE-2023-0004", "published": "2023-04-01", "cvss_base": 8.1, "kev": True},
    ])
    allq = s.query(per_page=2, page=1)
    assert allq["total"] == 4 and allq["pages"] == 2 and len(allq["items"]) == 2
    assert allq["items"][0]["id"] == "CVE-2024-0002"          # published_desc default
    assert s.query(severity="critical")["total"] == 1         # 9.9 (8.1 is High, not Critical)
    assert s.query(severity="high")["total"] == 1             # 8.1
    assert s.query(year=2023)["total"] == 2
    assert s.query(kev=True)["total"] == 2
    assert s.query(q="sqli")["items"][0]["id"] == "CVE-2023-0003"
    top = s.query(order="cvss_desc")["items"]
    assert top[0]["cvss_base"] == 9.9 and top[-1]["cvss_base"] == 2.0
    assert s.query(per_page=1000)["per_page"] == 100          # clamp


def test_years_and_stats():
    s = _store()
    s.merge_many([
        {"id": "CVE-2024-0001", "cvss_base": 9.9, "kev": True, "vigil_exploit": {"oracle_proven": True}},
        {"id": "CVE-2024-0002", "cvss_base": 5.0},
        {"id": "CVE-2023-0003", "cvss_base": 2.0},
    ])
    assert s.years() == [{"year": 2024, "count": 2}, {"year": 2023, "count": 1}]
    st = s.stats()
    assert st["total"] == 3 and st["kev"] == 1 and st["vigil_proven"] == 1
    assert st["by_severity"]["critical"] == 1 and st["by_severity"]["medium"] == 1
