"""Public CVE feed ingest → the catalog store. Offense-free, stdlib only.

Fetches the PUBLIC advisory feeds and merges them into `CveCatalogStore`:
  * CISA-KEV  — one bulk JSON of every CVE observed exploited in the wild (fast, primary);
  * NVD 2.0   — per-CVE enrichment: CVSS base/vector/metrics, CWEs, dates, references (rate-limited);
  * FIRST EPSS — exploitation-probability + percentile (bulk JSON API, paginated);
  * OSV       — per-advisory package ranges + aliases.

Every outbound request is HOST-ALLOWLISTED to the four known feed hosts (never a user-supplied host — this
code must never become an SSRF lever), size-capped, and timed out. `urllib` honors the environment's
HTTPS_PROXY. This is the ONE standing outbound path the public CVE catalog needs; it runs on a schedule /
on demand (`vigil cve ingest`), never at page-request time.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from ..reuse import assert_no_offense

assert_no_offense()

from .catalog import CveCatalogStore, normalize_cve_id  # noqa: E402

# the ONLY hosts this module will fetch from (third-party advisory sources, never a target)
_ALLOWED_HOSTS = frozenset({"www.cisa.gov", "services.nvd.nist.gov", "api.osv.dev", "api.first.org"})
_MAX_BYTES = 64 * 1024 * 1024        # a feed response over 64 MiB is anomalous — refuse
_MAX_ITEMS = 500_000                 # hard cap on parsed entries (anti-blowup on a hostile/huge response)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"
EPSS_BULK_URL = "https://api.first.org/data/v1/epss?limit={limit}&offset={offset}"
OSV_URL = "https://api.osv.dev/v1/vulns/{cve}"

Fetcher = Callable[[str], Any]


def fetch_json(url: str, *, timeout: float = 45.0, max_bytes: int = _MAX_BYTES) -> Any:
    """GET + parse JSON from a HOST-ALLOWLISTED feed URL. Fail-closed on a non-allowlisted host (never fetch
    an arbitrary host — no SSRF), an oversize body, or a non-JSON response. Honors HTTPS_PROXY via urllib."""
    host = (urlparse(url).hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise ValueError(f"refusing to fetch non-allowlisted host {host!r} (CVE feeds only)")
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "vigil-cve-ingest/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 — host is allowlisted above
        raw = r.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("feed response too large")
    return json.loads(raw.decode("utf-8", "replace"))


# --- parsers: feed document -> list of catalog record dicts (pure, testable without network) ----------
def kev_records(doc: Any) -> "list[dict]":
    """CISA-KEV bulk JSON → records. Each carries kev=True (+ ransomware), the dateAdded, vendor/product
    affected entry, CWEs, and the short description. KEV carries no CVSS — NVD enrichment adds that."""
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        return []
    out = []
    for e in vulns[:_MAX_ITEMS]:
        if not isinstance(e, dict):
            continue
        cid = normalize_cve_id(e.get("cveID", ""))
        if cid is None:
            continue
        vendor = str(e.get("vendorProject") or "").strip()
        product = str(e.get("product") or "").strip()
        ransom = str(e.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        rec: dict = {
            "id": cid, "feeds": ["cisa-kev"], "status": "published",
            "title": str(e.get("vulnerabilityName") or "").strip() or None,
            "description": str(e.get("shortDescription") or "").strip() or None,
            "kev": True, "kev_date": str(e.get("dateAdded") or "").strip() or None,
            "ransomware": ransom,
            "cwes": [str(c).strip() for c in (e.get("cwes") or []) if str(c).strip()],
            "affected": [{"vendor": vendor, "product": product}] if (vendor or product) else [],
        }
        due = str(e.get("dueDate") or "").strip()
        if due:
            rec["refs"] = [{"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "tags": [f"cisa-due:{due}"]}]
        out.append(rec)
    return out


def nvd_records(doc: Any) -> "list[dict]":
    """NVD 2.0 response → records: CVSS (prefer v3.1 > v3.0 > v2) base/vector/version + decomposed metrics,
    CWEs, published/lastModified, vulnStatus, the English description, and typed references."""
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        return []
    out = []
    for w in vulns[:_MAX_ITEMS]:
        cve = (w or {}).get("cve") if isinstance(w, dict) else None
        if not isinstance(cve, dict):
            continue
        cid = normalize_cve_id(cve.get("id", ""))
        if cid is None:
            continue
        descs = cve.get("descriptions") or []
        en = next((d.get("value") for d in descs if isinstance(d, dict) and d.get("lang") == "en"), None)
        metrics = cve.get("metrics") or {}
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if isinstance(arr, list) and arr and isinstance(arr[0], dict):
                cvss = arr[0].get("cvssData") or {}
                break
        cwes = []
        for weak in cve.get("weaknesses") or []:
            for d in (weak or {}).get("description") or []:
                v = str((d or {}).get("value") or "").strip()
                if v.upper().startswith("CWE-"):
                    cwes.append(v)
        refs = [{"url": str(r.get("url") or ""), "tags": list(r.get("tags") or [])}
                for r in (cve.get("references") or []) if isinstance(r, dict) and r.get("url")]
        rec: dict = {"id": cid, "feeds": ["nvd"],
                     "published": cve.get("published"), "last_modified": cve.get("lastModified"),
                     "status": str(cve.get("vulnStatus") or "published"),
                     "description": en, "cwes": cwes, "refs": refs}
        if isinstance(cvss, dict) and cvss.get("baseScore") is not None:
            rec["cvss_base"] = float(cvss["baseScore"])
            rec["cvss_vector"] = cvss.get("vectorString")
            rec["cvss_version"] = str(cvss.get("version") or "")
            rec["cvss_metrics"] = {k: cvss.get(v) for k, v in (
                ("av", "attackVector"), ("ac", "attackComplexity"), ("pr", "privilegesRequired"),
                ("ui", "userInteraction"), ("scope", "scope"), ("c", "confidentialityImpact"),
                ("i", "integrityImpact"), ("a", "availabilityImpact")) if cvss.get(v) is not None}
        out.append(rec)
    return out


def epss_records(doc: Any) -> "list[dict]":
    """FIRST EPSS JSON ({data:[{cve, epss, percentile}]}) → records with epss_score + epss_pct."""
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, list):
        return []
    out = []
    for e in data[:_MAX_ITEMS]:
        if not isinstance(e, dict):
            continue
        cid = normalize_cve_id(e.get("cve", ""))
        if cid is None:
            continue
        score, pct = e.get("epss"), e.get("percentile")
        if score is None or pct is None:
            continue
        try:
            out.append({"id": cid, "feeds": ["epss"],
                        "epss_score": float(score), "epss_pct": float(pct)})
        except (TypeError, ValueError):
            continue
    return out


# --- ingest drivers (fetch + merge) -------------------------------------------------------------------
def ingest_kev(store: CveCatalogStore, *, fetch: Fetcher = fetch_json) -> int:
    """Fetch the CISA-KEV bulk catalog and merge it. Returns the number of records merged."""
    return store.merge_many(kev_records(fetch(KEV_URL)))


def ingest_epss_bulk(store: CveCatalogStore, *, limit: int = 2000, max_pages: int = 5,
                     fetch: Fetcher = fetch_json) -> int:
    """Overlay EPSS scores for the highest-probability CVEs (paginated; bounded by max_pages)."""
    n = 0
    for page in range(max_pages):
        recs = epss_records(fetch(EPSS_BULK_URL.format(limit=limit, offset=page * limit)))
        if not recs:
            break
        n += store.merge_many(recs)
    return n


def enrich_nvd(store: CveCatalogStore, cve_ids: "list[str]", *, fetch: Fetcher = fetch_json,
               limit: "Optional[int]" = None) -> int:
    """Per-CVE NVD enrichment for a set of ids (e.g. the KEV set) — adds CVSS/CWE/dates. NVD rate-limits
    unauthenticated callers, so this is deliberately one-at-a-time and bounded by `limit`; the caller paces
    it. Returns the count enriched. A failed single fetch is skipped, never fatal."""
    n = 0
    for cid in cve_ids[: (limit if limit is not None else len(cve_ids))]:
        norm = normalize_cve_id(cid)
        if norm is None:
            continue
        try:
            recs = nvd_records(fetch(NVD_URL.format(cve=norm)))
        except (OSError, ValueError):
            continue
        n += store.merge_many(recs)
    return n
