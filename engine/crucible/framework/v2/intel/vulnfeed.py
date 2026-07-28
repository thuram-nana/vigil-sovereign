"""
intel.vulnfeed — the OPT-IN, egress-gated, auto-updating vulnerability-intelligence feed (K1).

Doctrine (never relaxed):
  * **Lead, never a fact.** Everything this mints enters the world-model as an intel-tier LEAD
    (``VULN_DB`` / ``GROUNDING_INTEL``) via the SAME offline parsers the file-ingest path uses. Only a
    fired deterministic oracle mints a FACT — the feed advises where to look, it never confirms.
  * **Egress-gated, concrete hosts only.** Every fetch routes through a ``GuardedHttpTransport`` scoped to
    a single CONCRETE apex host (no wildcard, no IP literal, never the target, never Strix ``web_search``).
    With no live opt-in the feed is offline-only — it never makes a silent unguarded call.
  * **Deterministic.** The only clock is an injected monotonic ``seq``; there is no wallclock/rng here.
    ``IntelIngest`` is seq-keyed idempotent, so a re-pull never double-counts.
  * **Stoppable.** ``cancel()`` (STOP / kill-switch) is honoured before every source and every per-CVE
    fetch, so an in-flight refresh halts cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .from_threatintel import (
    CISA_KEV_ENDPOINT,
    build_threatintel_live_transport,
    live_cve_observations,
    observations_from_kev,
)
from .models import IntelSourceKind
from .transport import CollectorEgressRefused

# Per-CVE query endpoints — `{query}` is the url-safe CVE / advisory id. NVD and OSV are third-party
# advisory APIs (queried ABOUT a CVE), never the target.
_NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query}"
_OSV_ENDPOINT = "https://api.osv.dev/v1/vulns/{query}"


@dataclass(frozen=True)
class VulnSource:
    """One trusted third-party vulnerability source.

    ``mode`` is ``"per_cve"`` (fetch one CVE at a time via the ``{query}`` template) or ``"bulk"`` (one
    fetch returns the whole catalog). ``host`` is a CONCRETE apex host — it is the transport's single-host
    egress allowlist, so it must never be a wildcard or IP literal.
    """

    name: str
    host: str
    endpoint: str
    mode: str = "per_cve"          # "per_cve" | "bulk"
    source_kind: IntelSourceKind = IntelSourceKind.VULN_DB


# The fixed registry of trusted sources. K1 pulls ONLY from these named apex hosts — there is no
# arbitrary-URL pull here (that is K4's separate, sovereign, scope-gated learner).
TRUSTED_VULN_SOURCES: tuple[VulnSource, ...] = (
    VulnSource("nvd", "services.nvd.nist.gov", _NVD_ENDPOINT, "per_cve"),
    VulnSource("osv", "api.osv.dev", _OSV_ENDPOINT, "per_cve"),
    VulnSource("cisa-kev", "www.cisa.gov", CISA_KEV_ENDPOINT, "bulk"),
)

_SOURCE_BY_NAME = {s.name: s for s in TRUSTED_VULN_SOURCES}


def source_by_name(name: str) -> VulnSource | None:
    """A trusted source by name (case-insensitive), or None — callers select by NAME, never by URL."""
    return _SOURCE_BY_NAME.get((name or "").strip().lower())


def build_vulnintel_transport(source: VulnSource, *, target_hosts=(), capture_dir=None, client=None):
    """A gated transport SCOPED TO ONE trusted source (a single concrete apex host + its one endpoint).

    One transport per source keeps egress tightly scoped and sidesteps the endpoint-key collision (NVD and
    OSV are both ``VULN_DB`` but different URLs). Every fetch is host-allowlisted to this source's single
    apex host and refuses ANY other host before bytes leave (the unconditional ``GuardedHttpTransport.fetch``
    check) — so it cannot be pointed at an internal/metadata address. When ``target_hosts`` is supplied (the
    CLI passes the engagement's charter scope under a ``--slug``), construction ALSO refuses if the source
    host overlaps target scope — belt-and-braces on top of the fixed third-party source registry.
    """
    return build_threatintel_live_transport(
        collector_hosts=(source.host,),
        endpoints={source.source_kind: source.endpoint},
        target_hosts=tuple(target_hosts),
        capture_dir=capture_dir,
        client=client,
    )


def plan_for(sources, cves) -> list:
    """Pair each source with the CVE queries it needs: per-CVE sources get the id list, bulk sources get
    an empty list (one fetch returns everything). Deterministic order (registry order)."""
    ids = [str(c).strip() for c in (cves or []) if str(c).strip()]
    return [(s, list(ids) if s.mode == "per_cve" else []) for s in sources]


@dataclass
class VulnfeedResult:
    minted_by_source: dict            # source name -> observations minted from its responses
    applied: int                      # observations projected by IntelIngest (deduped, idempotent)
    queries_run: int                  # transport fetches actually performed
    cancelled: bool                   # STOP / kill-switch halted the refresh mid-run
    last_seq: int                     # next free seq after the refresh (monotonic)
    refused: dict = field(default_factory=dict)   # source name -> reason the egress gate refused it


def refresh_vulnintel(plan, *, transport_for, ingest, seq: int = 0, cancel=None) -> VulnfeedResult:
    """Pull each planned source through its gated transport and ingest the (lead-only) observations.

    ``plan`` is a list of ``(VulnSource, [cve_query, ...])``. ``transport_for(source)`` returns the gated
    transport for a source (in production ``build_vulnintel_transport``; in tests a ``FixtureTransport``).
    ``ingest`` is an ``IntelIngest``. ``seq`` is the base of the monotonic clock — every fetch consumes one
    tick, so ids stay deterministic and idempotent across re-pulls. ``cancel()`` is honoured before each
    source AND each per-CVE fetch: a tripped STOP / kill-switch halts the refresh and is reported, not
    swallowed. Nothing minted is ever promoted to a fact.
    """
    cancel = cancel or (lambda: False)
    minted: dict = {}
    refused: dict = {}
    all_obs: list = []
    cur = int(seq)
    qrun = 0
    cancelled = False

    for source, queries in plan:
        if cancel():
            cancelled = True
            break
        try:
            transport = transport_for(source)
        except CollectorEgressRefused as exc:
            # the gate refused this source (e.g. it overlaps target scope) — record it and move on,
            # fail-closed per source. No seq is consumed and no bytes left for this source.
            refused[source.name] = str(exc)
            continue
        got = 0
        if source.mode == "bulk":
            fetch_seq = cur
            cur += 1
            rec = transport.fetch(source.source_kind, "", seq=fetch_seq)
            qrun += 1
            if rec.ok:
                obs = observations_from_kev(rec.payload, seq=fetch_seq)
                all_obs.extend(obs)
                got += len(obs)
        else:
            for q in queries:
                if cancel():
                    cancelled = True
                    break
                fetch_seq = cur
                cur += 1
                obs = live_cve_observations(transport, q, seq=fetch_seq, source_kind=source.source_kind)
                qrun += 1
                all_obs.extend(obs)
                got += len(obs)
        minted[source.name] = minted.get(source.name, 0) + got
        if cancelled:
            break

    applied = ingest.ingest(all_obs).applied if all_obs else 0
    return VulnfeedResult(minted_by_source=minted, applied=applied, queries_run=qrun,
                          cancelled=cancelled, last_seq=cur, refused=refused)
