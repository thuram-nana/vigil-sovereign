"""VIGIL public THREAT-FEED — the real, keyless live-activity data behind the globes.

Offense-free, plane-neutral (pure stdlib). This subsystem turns a handful of FREE, NO-API-KEY, public
threat feeds into the small, honest JSON the consumer-app Overview globe and the public-site hero globe read
same-origin at ``GET /api/threatfeed``:

  * CISA KEV (Known Exploited Vulnerabilities) — the US-gov public-domain catalogue of CVEs confirmed
    exploited in the wild. The PRIMARY live-activity driver: ``kev_total`` + ``kev_added_24h``/``_7d`` + a
    bounded ``recent`` list. No key, no licence friction (public domain).
  * The PUBLIC CVE catalogue VIGIL already ships (``sigil.cve.catalog``, served at ``/api/cve``) — REUSED for
    the CVE counts, never re-fetched or duplicated here.
  * SANS ISC / DShield country-aggregated attack data — OPTIONAL and OFF BY DEFAULT. Its commercial-use terms
    are not clearly granted, so VIGIL does not rely on it unless the operator verifies the ISC AUP and turns
    it on (``VIGIL_THREATFEED_DSHIELD=1``). When off, the globe's geo-points are ILLUSTRATIVE (the frontend's
    own hub animation), never fabricated geolocation presented as real.

The ARCHITECTURE mirrors the CVE catalogue exactly: every outbound request happens on a CADENCE
(``sigil threatfeed refresh``, host-allowlisted + size-capped + timed-out + DEFENSIVELY parsed), writing a
small on-disk cache; the edge route only ever READS that cache + the local CVE catalogue, so there is no
egress at page-request time and nothing for the keyless plane to leak. On a cold or unreachable feed the
response is honestly ``populated: false`` / ``stale: true`` — never a fabricated number ("prove, don't
guess").
"""
from .store import ThreatFeedCache  # noqa: F401
from .feed import api_response, build_snapshot, refresh  # noqa: F401
