"""Public CVE feed ingest — parsers (offline, fixtures) + the SSRF host-allowlist guard."""
from __future__ import annotations

import tempfile

import pytest

from sigil.cve.catalog import CveCatalogStore
from sigil.cve.ingest import (
    epss_records,
    fetch_json,
    ingest_kev,
    kev_records,
    nvd_records,
)

_KEV = {"vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
     "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10", "shortDescription": "RCE via JNDI.",
     "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-502"]},
    {"cveID": "not-a-cve", "product": "x"},                     # dropped
    {"cveID": "CVE-2023-0001", "vendorProject": "V", "product": "P", "shortDescription": "d",
     "dateAdded": "2023-01-01", "knownRansomwareCampaignUse": "Unknown", "cwes": []},
]}

_NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228", "published": "2021-12-10T10:15:09", "lastModified": "2023-11-07T03:00:00",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "es", "value": "ignorar"}, {"lang": "en", "value": "Apache Log4j2 JNDI..."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "version": "3.1", "baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE",
        "userInteraction": "NONE", "scope": "CHANGED", "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH", "availabilityImpact": "HIGH"}}]},
    "weaknesses": [{"description": [{"value": "CWE-502"}, {"value": "NVD-CWE-Other"}]}],
    "references": [{"url": "https://logging.apache.org/", "tags": ["Vendor Advisory"]}]}}]}

_EPSS = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97512", "percentile": "0.99981"},
                  {"cve": "junk", "epss": "x"}]}


def test_kev_records_parse():
    recs = kev_records(_KEV)
    assert len(recs) == 2                                      # the non-CVE id is dropped
    log4shell = next(r for r in recs if r["id"] == "CVE-2021-44228")
    assert log4shell["kev"] is True and log4shell["ransomware"] is True
    assert log4shell["kev_date"] == "2021-12-10" and log4shell["cwes"] == ["CWE-502"]
    assert log4shell["affected"] == [{"vendor": "Apache", "product": "Log4j"}]
    assert log4shell["feeds"] == ["cisa-kev"]
    other = next(r for r in recs if r["id"] == "CVE-2023-0001")
    assert other["ransomware"] is False


def test_nvd_records_parse_cvss_and_cwe():
    r = nvd_records(_NVD)[0]
    assert r["id"] == "CVE-2021-44228" and r["cvss_base"] == 10.0 and r["cvss_version"] == "3.1"
    assert r["cvss_vector"].startswith("CVSS:3.1/")
    assert r["cvss_metrics"]["av"] == "NETWORK" and r["cvss_metrics"]["scope"] == "CHANGED"
    assert r["cwes"] == ["CWE-502"]                            # NVD-CWE-Other filtered out
    assert r["description"].startswith("Apache Log4j2")        # English picked
    assert r["refs"][0]["tags"] == ["Vendor Advisory"]


def test_epss_records_parse():
    recs = epss_records(_EPSS)
    assert len(recs) == 1 and recs[0]["id"] == "CVE-2021-44228"
    assert recs[0]["epss_score"] == 0.97512 and recs[0]["epss_pct"] == 0.99981


def test_ingest_kev_then_enrich_merges_into_catalog():
    s = CveCatalogStore(tempfile.mktemp(suffix=".db"))
    n = ingest_kev(s, fetch=lambda url: _KEV)                  # stub fetch — no network
    assert n == 2 and s.count() == 2
    # enrich the same CVE with NVD CVSS + EPSS → one merged row with everything
    s.merge_many(nvd_records(_NVD)); s.merge_many(epss_records(_EPSS))
    r = s.get("CVE-2021-44228")
    assert r["kev"] is True and r["cvss_base"] == 10.0 and r["severity"] == "critical"
    assert r["epss_score"] == 0.97512 and sorted(r["feeds"]) == ["cisa-kev", "epss", "nvd"]


def test_fetch_json_refuses_non_allowlisted_host():
    # the ingest must never be an SSRF lever — only the four known feed hosts are fetchable
    for bad in ("https://evil.example.com/x", "http://169.254.169.254/latest/meta-data/",
                "https://services.nvd.nist.gov.evil.com/x"):
        with pytest.raises(ValueError):
            fetch_json(bad)
