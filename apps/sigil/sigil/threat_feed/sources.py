"""The keyless public threat-feed SOURCES: fetchers + DEFENSIVE parsers. Offense-free, stdlib only.

Two independent concerns live here, kept separate so the parsers are pure + testable WITHOUT network:
  * ``fetch_json`` — the ONE outbound primitive. HOST-ALLOWLISTED (never a user-supplied host — this must
    never become an SSRF lever), size-capped, timed-out, descriptive User-Agent, honours ``HTTPS_PROXY``.
  * ``kev_summary`` / ``dshield_country_points`` — pure functions that take an ALREADY-PARSED feed document
    (``json.loads`` output of UNTRUSTED external data) and return the small, SHAPE-VALIDATED summary the feed
    needs. They assume nothing about field presence, type, or length: every value is coerced, every list is
    bounded, every string is length-clamped. A hostile or malformed feed can shrink the result to empty but
    can never blow memory, inject a wrong type downstream, or crash the caller.

CISA KEV is US-gov PUBLIC DOMAIN (no key, commercial use fine). DShield/ISC country data is OPTIONAL and the
caller gates it OFF by default — its commercial-use terms are not clearly granted (see the module docstring).
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.parse import urlparse

from ..reuse import assert_no_offense

assert_no_offense()

# The ONLY hosts this module will ever fetch — third-party PUBLIC feed sources, never a target. Keyless both.
KEV_HOST = "www.cisa.gov"
DSHIELD_HOST = "isc.sans.edu"
_ALLOWED_HOSTS = frozenset({KEV_HOST, DSHIELD_HOST})

# CISA KEV bulk JSON (no key; US-gov public domain). The one catalogue of every CVE confirmed exploited.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# SANS ISC / DShield top attacking sources for a day, each carrying an ASN COUNTRY — so the globe gets
# country-aggregated points with NO per-IP geolocation DB to bundle. Keyless; terms unverified ⇒ OFF by
# default (the caller decides). ``<rows>`` top sources for ``<date>`` (``today`` is accepted by the API).
DSHIELD_SOURCES_URL = "https://isc.sans.edu/api/sources/{date}/{rows}/0?json"

# Bounds. A KEV response is a few MiB today; a source day is far smaller. Caps are generous but finite so a
# hostile/huge body is refused rather than read into memory.
_KEV_MAX_BYTES = 32 * 1024 * 1024
_DSHIELD_MAX_BYTES = 8 * 1024 * 1024
_MAX_PARSE_ITEMS = 500_000      # hard ceiling on entries we will even iterate (anti-blowup)
_MAX_RECENT = 25                # how many recent KEV items the summary carries (bounded list)
_MAX_GEO = 60                   # how many country points the geo summary carries (bounded list)
_STR_CAP = 300                  # every feed-derived string is clamped to this many chars

# A descriptive User-Agent (the CVE ingest sends one too). ISC/DShield asks callers to identify themselves;
# the operator can set a contact per the ISC AUP via VIGIL_THREATFEED_UA (config), never a personal detail.
DEFAULT_USER_AGENT = "vigil-threatfeed/1.0 (+https://sigilsovereign.com; public-threat-feed-aggregator)"


def fetch_json(url: str, *, timeout: float = 45.0, max_bytes: int = _KEV_MAX_BYTES,
               user_agent: str = DEFAULT_USER_AGENT) -> Any:
    """GET + parse JSON from a HOST-ALLOWLISTED feed URL. Fail-closed on a non-allowlisted host (no SSRF), an
    oversize body, or a non-JSON response. Honours ``HTTPS_PROXY`` via urllib. This is the ONLY place an
    outbound request is made, and it is reached only from the cadence refresh, never a page request."""
    host = (urlparse(url).hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise ValueError(f"refusing to fetch non-allowlisted host {host!r} (threat feeds only)")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 — host is allowlisted above
        raw = r.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("feed response too large")
    return json.loads(raw.decode("utf-8", "replace"))


# --- defensive coercion helpers (every feed value passes through one of these) ------------------------
def _s(v: Any, cap: int = _STR_CAP) -> str:
    """Any value → a clamped, single-line str (never a dict/list leaking downstream)."""
    if not isinstance(v, (str, int, float)):
        return ""
    s = str(v).strip().replace("\n", " ").replace("\r", " ")
    return s[:cap]


def _int(v: Any, default: int) -> int:
    """Any value → a bounded int, or ``default`` on anything non-numeric (a feed count may be a str or junk)."""
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _cve_id(v: Any) -> "str | None":
    """A value → a canonical ``CVE-YYYY-NNNN`` id, or None. Reuses the catalogue's strict validator so a
    path/primary-key id can never be a hostile string."""
    from ..cve.catalog import normalize_cve_id
    return normalize_cve_id(_s(v, 32))


def _iso_date(v: Any) -> "str | None":
    """A value → a ``YYYY-MM-DD`` string if it parses as one, else None (KEV dateAdded is date-granular)."""
    s = _s(v, 10)
    if len(s) != 10 or s[4] != "-" or s[7] != "-":
        return None
    y, m, d = s[0:4], s[5:7], s[8:10]
    if not (y.isdigit() and m.isdigit() and d.isdigit()):
        return None
    if not (1 <= int(m) <= 12 and 1 <= int(d) <= 31):
        return None
    return s


def _days_since(date_str: str, now_epoch: float) -> "float | None":
    """Days from a ``YYYY-MM-DD`` (interpreted at UTC midnight) to ``now_epoch``, or None if unparseable. May be
    NEGATIVE for a future-dated (anomalous) entry — the caller requires a non-negative age before counting it, so
    a bad future date can never inflate a ``recent`` count."""
    import calendar
    try:
        y, m, d = int(date_str[0:4]), int(date_str[5:7]), int(date_str[8:10])
        added = calendar.timegm((y, m, d, 0, 0, 0, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    return (now_epoch - added) / 86400.0


# --- CISA KEV: the primary live-activity summary ------------------------------------------------------
def kev_summary(doc: Any, *, now_epoch: float) -> dict:
    """UNTRUSTED CISA-KEV bulk JSON → a bounded, shape-validated summary dict:

        {"total": int, "added_24h": int, "added_7d": int, "catalog_version": str,
         "recent": [{"cve","name","date_added","vendor","product","ransomware"}, ...]}

    Defensive throughout: a non-dict doc, a non-list ``vulnerabilities``, a non-dict entry, a missing/typed
    field — each is skipped, never trusted. ``total`` counts only entries with a VALID CVE id. ``recent`` is
    the newest-by-date entries, length-bounded. Counts/lists can shrink to empty on a hostile feed; they can
    never crash or blow up."""
    out: dict = {"total": 0, "added_24h": 0, "added_7d": 0, "catalog_version": "", "recent": []}
    if not isinstance(doc, dict):
        return out
    out["catalog_version"] = _s(doc.get("catalogVersion"), 40)
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out
    total = added_24h = added_7d = 0
    recent: "list[dict]" = []
    for e in vulns[:_MAX_PARSE_ITEMS]:
        if not isinstance(e, dict):
            continue
        cid = _cve_id(e.get("cveID"))
        if cid is None:
            continue
        total += 1
        date_added = _iso_date(e.get("dateAdded"))
        if date_added is not None:
            age = _days_since(date_added, now_epoch)
            if age is not None and age >= 0.0:         # a future-dated (anomalous) entry never counts as recent
                if age <= 1.0:
                    added_24h += 1
                if age <= 7.0:
                    added_7d += 1
        recent.append({
            "cve": cid,
            "name": _s(e.get("vulnerabilityName")),
            "date_added": date_added or "",
            "vendor": _s(e.get("vendorProject"), 80),
            "product": _s(e.get("product"), 80),
            "ransomware": _s(e.get("knownRansomwareCampaignUse"), 16).lower() == "known",
        })
    # newest first by date_added (empty dates sort last), then bound the list
    recent.sort(key=lambda r: r.get("date_added") or "", reverse=True)
    out["total"] = total
    out["added_24h"] = added_24h
    out["added_7d"] = added_7d
    out["recent"] = recent[:_MAX_RECENT]
    return out


# --- SANS ISC / DShield: OPTIONAL country-aggregated geo points ---------------------------------------
# Rough centroids for the country codes DShield reports, so a country weight becomes a plottable globe point
# with NO bundled IP-geolocation dataset. A code we do not know is simply dropped (the point is omitted, the
# weight is not fabricated onto the wrong place).
_CC_CENTROID: "dict[str, tuple[float, float]]" = {
    "US": (39.8, -98.6), "CN": (35.9, 104.2), "RU": (61.5, 105.3), "DE": (51.2, 10.5),
    "NL": (52.1, 5.3), "GB": (54.0, -2.0), "FR": (46.2, 2.2), "BR": (-14.2, -51.9),
    "IN": (22.0, 79.0), "JP": (36.2, 138.3), "KR": (36.5, 127.9), "VN": (14.1, 108.3),
    "SG": (1.35, 103.8), "CA": (56.1, -106.3), "UA": (48.4, 31.2), "IR": (32.4, 53.7),
    "ID": (-0.8, 113.9), "TR": (39.0, 35.2), "TW": (23.7, 121.0), "HK": (22.3, 114.2),
    "IT": (41.9, 12.6), "ES": (40.4, -3.7), "PL": (51.9, 19.1), "RO": (45.9, 24.9),
    "ZA": (-30.6, 22.9), "AU": (-25.3, 133.8), "MX": (23.6, -102.6), "TH": (15.9, 100.9),
    "BG": (42.7, 25.5), "SE": (60.1, 18.6), "CH": (46.8, 8.2), "AR": (-38.4, -63.6),
    "EG": (26.8, 30.8), "NG": (9.1, 8.7), "KE": (-0.0, 37.9), "AE": (23.4, 53.8),
}


def dshield_country_points(doc: Any) -> "list[dict]":
    """UNTRUSTED DShield ``/api/sources`` JSON → bounded country points ``[{"cc","lat","lon","weight"}, ...]``.

    DShield returns top attacking source IPs, each carrying an ASN COUNTRY and an attack ``targets``/``attacks``
    count — so this aggregates by country WITHOUT any per-IP geolocation. Defensive: a non-list/odd shape →
    ``[]``; a country we have no centroid for is dropped; weights are summed as finite non-negative ints.
    Returns the heaviest countries first, length-bounded. ONLY reached when the operator has turned DShield on
    (its terms are not relied on by default)."""
    rows = doc if isinstance(doc, list) else (doc.get("sources") if isinstance(doc, dict) else None)
    if not isinstance(rows, list):
        return []
    weights: "dict[str, int]" = {}
    for r in rows[:_MAX_PARSE_ITEMS]:
        if not isinstance(r, dict):
            continue
        cc = _s(r.get("ascountry") or r.get("country"), 2).upper()
        if len(cc) != 2 or not cc.isalpha() or cc not in _CC_CENTROID:
            continue
        raw = r.get("attacks")
        if raw is None:
            raw = r.get("targets")
        w = max(0, _int(raw, 1))
        weights[cc] = weights.get(cc, 0) + max(1, w)
    ordered = sorted(weights.items(), key=lambda kv: kv[1], reverse=True)[:_MAX_GEO]
    return [{"cc": cc, "lat": _CC_CENTROID[cc][0], "lon": _CC_CENTROID[cc][1], "weight": w}
            for cc, w in ordered]


# --- fetch drivers (network + parse; used only by the cadence refresh) --------------------------------
def fetch_kev_summary(*, now_epoch: float, fetch=fetch_json, user_agent: str = DEFAULT_USER_AGENT) -> dict:
    return kev_summary(fetch(KEV_URL, max_bytes=_KEV_MAX_BYTES, user_agent=user_agent), now_epoch=now_epoch)


def fetch_dshield_points(*, date: str = "today", rows: int = 200, fetch=fetch_json,
                         user_agent: str = DEFAULT_USER_AGENT) -> "list[dict]":
    url = DSHIELD_SOURCES_URL.format(date=_s(date, 10) or "today", rows=max(1, min(int(rows), 1000)))
    return dshield_country_points(fetch(url, max_bytes=_DSHIELD_MAX_BYTES, user_agent=user_agent))
