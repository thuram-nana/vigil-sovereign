"""Assemble the threat-feed snapshot (cadence) and the ``/api/threatfeed`` response (edge). Offense-free.

Two sides, sharing nothing but the cache:
  * ``build_snapshot`` / ``refresh`` — run on a CADENCE (``sigil threatfeed refresh``). They DO egress (fetch
    the keyless sources, defensively summarise, write the cache). On a source failure they KEEP last-good: a
    failed KEV fetch leaves the cache untouched and raises; a failed optional DShield fetch degrades geo to
    illustrative without failing the whole refresh.
  * ``api_response`` — run on the EDGE, per page request. It does NO egress: it READS the cache + the local
    CVE catalogue and assembles the small JSON the globes read. It NEVER raises and NEVER fabricates — a cold
    or unreadable cache yields ``populated: false`` (honest "warming up"); a cache older than the TTL yields
    ``stale: true`` beside the last-good numbers.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..reuse import assert_no_offense

assert_no_offense()

from . import sources  # noqa: E402
from .store import ThreatFeedCache  # noqa: E402

# How many newest CVEs to sample from the catalogue when counting "recent" (published in the last 7 days).
# Bounded so the per-request catalogue read stays cheap; the count is honest for the sampled window.
_CVE_SAMPLE = 100
_RECENT_WINDOW_DAYS = 7


# --- cadence: fetch + summarise + cache ---------------------------------------------------------------
def build_snapshot(*, dshield: bool = False, now_epoch: "float | None" = None,
                   fetch=sources.fetch_json, user_agent: str = sources.DEFAULT_USER_AGENT) -> dict:
    """Fetch the keyless sources and return the cache ``data`` dict. KEV is required (raises on failure so the
    caller keeps last-good); DShield is OPTIONAL and OFF unless ``dshield=True`` AND the operator has verified
    its terms — a DShield error degrades geo to illustrative, it never fails the snapshot."""
    now = time.time() if now_epoch is None else float(now_epoch)
    kev = sources.fetch_kev_summary(now_epoch=now, fetch=fetch, user_agent=user_agent)
    geo: "list[dict]" = []
    geo_source = "illustrative"
    source_states = [{"name": "cisa-kev", "status": "ok"}]
    if dshield:
        try:
            geo = sources.fetch_dshield_points(fetch=fetch, user_agent=user_agent)
            geo_source = "dshield" if geo else "illustrative"
            source_states.append({"name": "dshield", "status": "ok" if geo else "empty"})
        except (OSError, ValueError):
            source_states.append({"name": "dshield", "status": "unavailable"})
    return {"kev": kev, "geo": geo, "geo_source": geo_source, "sources": source_states}


def refresh(cache: ThreatFeedCache, *, dshield: bool = False, now_epoch: "float | None" = None,
            fetch=sources.fetch_json, user_agent: str = sources.DEFAULT_USER_AGENT) -> dict:
    """Build a fresh snapshot and write it to ``cache`` (atomic). Returns the snapshot. If the KEV fetch
    fails the exception propagates and the cache is left as it was (last-good is preserved) — NOTHING fabricated
    is ever written."""
    now = time.time() if now_epoch is None else float(now_epoch)
    snap = build_snapshot(dshield=dshield, now_epoch=now, fetch=fetch, user_agent=user_agent)
    cache.write(snap, now=now)
    return snap


# --- edge: read cache + catalogue → the /api/threatfeed body (no egress, never raises) ----------------
def _cve_counts(catalog_path: "str | Path | None", *, now_epoch: float) -> dict:
    """Read the LOCAL CVE catalogue (the one ``/api/cve`` serves — reused, never re-fetched) for the globe's
    CVE context: total, KEV-flagged total, and a sampled count published in the last 7 days. Defensive: an
    absent / broken catalogue yields zeroes, never an error."""
    out = {"cve_total": 0, "cve_kev": 0, "cve_recent": 0}
    if catalog_path is None:
        return out
    p = Path(catalog_path)
    if not p.exists():
        return out
    try:
        from ..cve.catalog import CveCatalogStore
        store = CveCatalogStore(str(p))
        out["cve_total"] = int(store.count())
        try:
            out["cve_kev"] = int(store.stats().get("kev", 0))
        except Exception:  # noqa: BLE001 — stats must never 500 the edge
            out["cve_kev"] = 0
        recent = 0
        cutoff = now_epoch - _RECENT_WINDOW_DAYS * 86400.0
        items = store.query(page=1, per_page=_CVE_SAMPLE, order="published_desc").get("items", [])
        for it in items:
            if _published_epoch(it.get("published")) >= cutoff:
                recent += 1
        out["cve_recent"] = recent
    except Exception:  # noqa: BLE001 — a broken catalogue must never 500 the edge
        return {"cve_total": 0, "cve_kev": 0, "cve_recent": 0}
    return out


def _published_epoch(value: Any) -> float:
    """An NVD ``published`` timestamp (ISO-8601, e.g. ``2024-01-02T03:04:05.000``) → epoch seconds, or 0.0 on
    anything unparseable (so a bad date never counts as 'recent')."""
    if not isinstance(value, str) or len(value) < 10:
        return 0.0
    import calendar
    s = value.strip().replace("Z", "")
    try:
        y, mo, d = int(s[0:4]), int(s[5:7]), int(s[8:10])
        hh = int(s[11:13]) if len(s) >= 13 and s[11:13].isdigit() else 0
        mi = int(s[14:16]) if len(s) >= 16 and s[14:16].isdigit() else 0
        return float(calendar.timegm((y, mo, d, hh, mi, 0, 0, 0, 0)))
    except (ValueError, OverflowError):
        return 0.0


def api_response(cache_path: "str | Path", catalog_path: "str | Path | None", *,
                 ttl_seconds: float, now_epoch: "float | None" = None) -> dict:
    """The ``GET /api/threatfeed`` body. Reads the cache + the local CVE catalogue only (no egress) and NEVER
    raises. Shape:

        {"metrics": {"kev_total","kev_added_24h","kev_added_7d","cve_recent","cve_total","cve_kev"},
         "recent": [{"cve","name","date_added","vendor","product","ransomware"}, ...],
         "geo": [{"cc","lat","lon","weight"}, ...], "geo_source": "dshield"|"illustrative",
         "populated": bool, "stale": bool, "as_of": <epoch|null>, "sources": [...]}

    ``populated`` is false only when there is NOTHING real to show (no cache AND an empty/absent catalogue):
    the frontend then shows its honest "live feed warming up" state, never a fabricated number."""
    now = time.time() if now_epoch is None else float(now_epoch)
    data, as_of = ThreatFeedCache(cache_path).read_data()
    d: dict = data or {}
    kev = d["kev"] if isinstance(d.get("kev"), dict) else {}
    geo = d["geo"] if isinstance(d.get("geo"), list) else []
    geo_source = d["geo_source"] if isinstance(d.get("geo_source"), str) else "illustrative"
    sources_states = d["sources"] if isinstance(d.get("sources"), list) else []

    cve = _cve_counts(catalog_path, now_epoch=now)
    metrics = {
        "kev_total": int(kev.get("total") or 0),
        "kev_added_24h": int(kev.get("added_24h") or 0),
        "kev_added_7d": int(kev.get("added_7d") or 0),
        "cve_recent": int(cve["cve_recent"]),
        "cve_total": int(cve["cve_total"]),
        "cve_kev": int(cve["cve_kev"]),
    }
    recent = kev["recent"] if isinstance(kev.get("recent"), list) else []

    have_cache = bool(data) and metrics["kev_total"] > 0
    have_catalog = metrics["cve_total"] > 0
    populated = have_cache or have_catalog
    stale = (not have_cache) or ((now - as_of) > float(ttl_seconds))

    return {
        "metrics": metrics,
        "recent": recent,
        "geo": geo if geo_source == "dshield" else [],
        "geo_source": geo_source if geo else "illustrative",
        "populated": populated,
        "stale": bool(stale),
        "as_of": (int(as_of) if as_of else None),
        "sources": sources_states,
    }
