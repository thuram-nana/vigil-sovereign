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

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

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
    queries_run: int                  # transport fetches actually performed (NETWORK — a resumed source adds 0)
    cancelled: bool                   # STOP / kill-switch halted the refresh mid-run
    last_seq: int                     # next free seq after the refresh (monotonic)
    refused: dict = field(default_factory=dict)   # source name -> reason the egress gate refused it
    resumed_from_seq: int = -1        # cursor value a re-pull resumed from (-1 = fresh full refresh / no store)
    skipped_by_source: dict = field(default_factory=dict)  # source name -> seqs skipped (already durable)


# Attribute this feed's outbound requests to the "vulnfeed" token budget (the shared transport charges
# the current tool, whose default is "recon"). Guarded: a missing vigil_core never affects the pull.
try:                                                       # pragma: no cover - import guard
    from vigil_core import token_budget as _token_budget
except Exception:                                          # noqa: BLE001
    _token_budget = None


def _tb_vulnfeed_enter():
    if _token_budget is None:
        return None
    try:
        ctx = _token_budget.using_tool("vulnfeed")
        ctx.__enter__()
        return ctx
    except Exception:                                      # noqa: BLE001
        return None


def _tb_vulnfeed_exit(ctx) -> None:
    if ctx is not None:
        try:
            ctx.__exit__(None, None, None)
        except Exception:                                  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Durable ingest cursor (resume checkpoint).
#
# ``refresh_vulnintel`` used to fetch EVERY source then ingest ONCE at the very end, so a crash before
# that end-ingest lost every fetched observation and the recovery pull re-fetched the whole catalog. The
# fix has two halves: (1) ingest INCREMENTALLY per source (so each source's leads are durable the moment
# it finishes), and (2) persist a small JSON checkpoint — a PER-SOURCE map of the last seq each source
# durably ingested (plus a scalar high-water mark used only for local re-projection), per engagement-slug
# and per plan-fingerprint, next to the intel store — advanced ONLY for a source that genuinely fetched-
# AND-ingested durable rows. Because the plan is deterministic and ``IntelIngest`` is seq-keyed idempotent,
# the seq a given fetch consumes is stable across pulls, so the recovery pull SKIPS a source ONLY when that
# source is recorded as durable in the per-source map (no network) and re-projects those durable leads
# locally to keep the belief graph coherent. A source that produced ZERO durable rows — a failed / rate-
# limited fetch (a routine NVD 503 makes ``GuardedHttpTransport`` set ``ok=False``; ``live_cve_observations``
# then yields [] WITHOUT raising) or a genuinely empty advisory — is NOT recorded, so resume RE-FETCHES it
# rather than silently dropping its leads. The skip decision trusts the per-source map, NEVER the scalar
# high-water mark alone (which may have holes below it: an earlier source can have failed while a later one
# succeeded, so "everything ``<= cursor`` is durable" is FALSE).
#
# The checkpoint is a CRASH-RECOVERY marker, not a permanent skip-list: a pull that runs to completion
# DELETES it, so the next scheduled/manual pull does a fresh full refresh and the auto-updating feed keeps
# catching newly-published CVEs / KEV entries. A surviving cursor therefore always means an interrupted
# (crashed / STOPped) pull — exactly the pull that should resume.
#
# STATE, never a finding: the cursor only records how far ingest got; nothing here promotes a lead to a
# fact. FAIL-OPEN: every cursor read/write/reload/delete is wrapped so a failure degrades to the old
# full-refresh behaviour and NEVER raises — a broken cursor can at worst cause a redundant (idempotent) pull.
# ---------------------------------------------------------------------------


def _cursor_dir(ingest) -> Path | None:
    """The directory the cursor file lives in — the intel store dir (parent of the memory DB), or None
    for an ephemeral (store-less) run where there is nothing durable to resume from."""
    store = getattr(ingest, "store", None)
    if store is None:
        return None
    try:
        db_path = getattr(getattr(store, "_s", None), "path", None)
        if db_path is None:
            return None
        return Path(db_path).parent / "vulnfeed_cursors"
    except Exception:                                     # noqa: BLE001 - fail-open
        return None


def _plan_fingerprint(plan, base_seq: int) -> str:
    """A stable hash of the plan (source names/modes/kinds + exact query order) and the base seq. Two
    refreshes share a cursor only if their plan AND base seq match — a different query set is a different
    cursor, so a narrower re-pull never wrongly skips a source it did not run before."""
    canon = [[s.name, s.mode, s.source_kind.value, [str(q) for q in queries]] for s, queries in plan]
    blob = json.dumps({"base_seq": int(base_seq), "plan": canon}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cursor_path(ingest, plan, base_seq: int):
    """(cursor Path | None, plan_fingerprint). None when there is no durable store."""
    d = _cursor_dir(ingest)
    fp = _plan_fingerprint(plan, base_seq)
    if d is None:
        return None, fp
    slug = getattr(ingest, "engagement_slug", "") or "ephemeral"
    safe_slug = re.sub(r"[^A-Za-z0-9_.-]", "_", slug)[:64]
    return d / f"{safe_slug}__{fp[:16]}.json", fp


def _read_cursor(path, fp: str):
    """Return ``(done_through, per_source)`` from the cursor file. ``done_through`` is the highest seq
    reached by ANY durably-ingested source — a high-water mark used ONLY for local re-projection, which
    may have holes below it (an earlier source can have failed while a later one succeeded); it is the
    ``per_source`` map, NOT this scalar, that decides whether a source is skippable on resume. ``-1`` =
    nothing / no reusable cursor. Fail-open: any error, a mismatched plan fingerprint, or a malformed
    file yields ``(-1, {})`` so the refresh degrades to a full pull."""
    if path is None:
        return -1, {}
    try:
        if not path.exists():
            return -1, {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("plan_fp") != fp:
            return -1, {}
        v = int(data.get("last_ingested_seq", -1))
        per = data.get("per_source", {})
        if not isinstance(per, dict):
            per = {}
        return (v if v >= 0 else -1), {str(k): int(x) for k, x in per.items()}
    except Exception:                                     # noqa: BLE001 - fail-open
        return -1, {}


def _write_cursor(path, fp: str, slug: str, base_seq: int,
                  last_ingested_seq: int, per_source: dict) -> None:
    """Persist the cursor atomically (temp file + ``os.replace``) with owner-only perms. Never raises —
    a persist failure is a recorded no-op that simply leaves the next re-pull to re-fetch."""
    if path is None:
        return
    tmp = None
    try:
        payload = json.dumps({
            "version": 1, "plan_fp": fp, "slug": slug, "base_seq": int(base_seq),
            "last_ingested_seq": int(last_ingested_seq),
            "per_source": {str(k): int(v) for k, v in per_source.items()},
        }, sort_keys=True, separators=(",", ":"))
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, path)                            # atomic swap → no torn cursor on crash
    except Exception:                                    # noqa: BLE001 - fail-open
        try:
            if tmp is not None and tmp.exists():         # best-effort cleanup of a partial temp
                tmp.unlink()
        except Exception:                                # noqa: BLE001
            pass


def _delete_cursor(path) -> None:
    """Clear the checkpoint once a pull runs to completion. Never raises. A surviving cursor therefore
    ALWAYS means an interrupted pull (crash / STOP) — so the next pull RESUMES it — while a completed pull
    leaves nothing behind, so the next scheduled/manual pull does a fresh full refresh and the
    auto-updating feed keeps catching newly-published CVEs / KEV entries."""
    if path is None:
        return
    try:
        if path.exists():
            path.unlink()
    except Exception:                                    # noqa: BLE001 - fail-open
        pass


def _reload_prior(ingest, plan, done_through: int) -> int:
    """Re-project the already-durable leads (seq <= cursor) from the store into this run's fresh
    world-model, so a resumed pull's resolve/entity-sync sees the COMPLETE observation set and never GCs a
    previously-persisted entity. Local + idempotent (obs_id-keyed) — it does NO network. Returns the count
    reloaded (0 also flags an orphaned cursor whose backing rows are gone → caller degrades to full pull)."""
    store = getattr(ingest, "store", None)
    if store is None or done_through < 0:
        return 0
    try:
        slug = getattr(ingest, "engagement_slug", "") or ""
        kinds: list[str] = []
        for s, _q in plan:
            k = s.source_kind.value
            if k not in kinds:
                kinds.append(k)
        prior = []
        seen: set[str] = set()
        for k in kinds:
            for obs in store.observations(engagement_slug=slug, source_kind=k):
                if obs.seq <= done_through and obs.obs_id not in seen:
                    seen.add(obs.obs_id)
                    prior.append(obs)
        if prior:
            ingest.ingest(prior)                         # re-project durable leads (applied not counted)
        return len(prior)
    except Exception:                                    # noqa: BLE001 - fail-open
        return 0


def refresh_vulnintel(plan, *, transport_for, ingest, seq: int = 0, cancel=None) -> VulnfeedResult:
    """Pull each planned source through its gated transport and ingest the (lead-only) observations.

    ``plan`` is a list of ``(VulnSource, [cve_query, ...])``. ``transport_for(source)`` returns the gated
    transport for a source (in production ``build_vulnintel_transport``; in tests a ``FixtureTransport``).
    ``ingest`` is an ``IntelIngest``. ``seq`` is the base of the monotonic clock — every fetch consumes one
    tick, so ids stay deterministic and idempotent across re-pulls. ``cancel()`` is honoured before each
    source AND each per-CVE fetch: a tripped STOP / kill-switch halts the refresh and is reported, not
    swallowed. Nothing minted is ever promoted to a fact.

    Ingest is INCREMENTAL (one ingest per source, durable before the checkpoint advances), so a crash keeps
    every already-finished source's leads. When ``ingest`` carries a durable store, a per-plan checkpoint
    (see the cursor section above) lets an interrupted pull RESUME: the recovery pull re-projects the
    already-durable leads locally and skips their NETWORK fetch, pulling only the sources that did not
    durably ingest — a source whose fetch failed or returned zero obs is RE-FETCHED, never skipped. A pull
    that completes clears its checkpoint so the next pull refreshes in full. All checkpoint
    IO is fail-open — a read/write/delete failure degrades to the pre-existing full-refresh, never raises.
    """
    cancel = cancel or (lambda: False)
    minted: dict = {}
    refused: dict = {}
    skipped: dict = {}
    cur = int(seq)
    qrun = 0
    applied = 0
    cancelled = False

    # -- resume checkpoint: read the durable cursor, then re-project what is already durable so a
    #    resumed pull's resolve/entity-sync sees the full observation set (all fail-open) --------------
    cpath, fp = _cursor_path(ingest, plan, seq)
    slug = getattr(ingest, "engagement_slug", "") or "ephemeral"
    done_through, per_source_cursor = _read_cursor(cpath, fp)
    if done_through >= 0:
        loaded = _reload_prior(ingest, plan, done_through)
        if loaded == 0:
            # a surviving cursor whose backing rows are gone (store reset) — do not skip un-backed work.
            done_through, per_source_cursor = -1, {}
    resumed_from = done_through

    _tb_ctx = _tb_vulnfeed_enter()          # transport fetches below charge the "vulnfeed" budget
    for source, queries in plan:
        if cancel():
            cancelled = True
            break
        try:
            transport = transport_for(source)
        except CollectorEgressRefused as exc:
            # the gate refused this source (e.g. it overlaps target scope) — record it and move on,
            # fail-closed per source. No seq is consumed and no bytes left for this source. (Resolved
            # BEFORE the resume-skip so seq alignment matches the run that wrote the cursor.)
            refused[source.name] = str(exc)
            continue
        n = 1 if source.mode == "bulk" else len(queries)
        last_seq_for_source = cur + n - 1
        if n > 0 and per_source_cursor.get(source.name, -1) >= last_seq_for_source:
            # THIS source genuinely fetched-AND-ingested durable rows in the interrupted run — its
            # per-source high-water covers every seq it would consume now (re-projected locally above) —
            # so skip the NETWORK fetch and just advance the deterministic clock. This is the resume win.
            # A source that failed or returned ZERO obs has NO per-source entry, so it is RE-FETCHED, not
            # skipped: resume NEVER skips a source whose rows are not durable. (The scalar high-water mark
            # is deliberately NOT consulted here — it can sit above a lower-seq source that never ingested.)
            cur += n
            skipped[source.name] = n
            continue
        got = 0
        src_obs: list = []
        if source.mode == "bulk":
            fetch_seq = cur
            cur += 1
            rec = transport.fetch(source.source_kind, "", seq=fetch_seq)
            qrun += 1
            if rec.ok:
                obs = observations_from_kev(rec.payload, seq=fetch_seq)
                src_obs.extend(obs)
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
                src_obs.extend(obs)
                got += len(obs)
        minted[source.name] = minted.get(source.name, 0) + got
        # INCREMENTAL ingest of just this source, THEN advance the cursor — durable-BEFORE-cursor, so a
        # crash between the two only ever re-fetches (idempotent), never skips un-ingested leads.
        durable = False
        if src_obs:
            res = ingest.ingest(src_obs)
            applied += res.applied
            durable = res.persisted > 0      # rows ACTUALLY landed in the durable store (reloadable on resume)
        # Advance the cursor ONLY for a source that ACTUALLY produced durable rows (fetched-AND-ingested),
        # NOT merely "not cancelled". A source that returned zero obs — a failed / rate-limited fetch
        # (GuardedHttpTransport sets ok=False on any non-2xx / network error; live_cve_observations then
        # yields [] WITHOUT raising) OR a genuinely empty advisory — is left UN-recorded, so resume
        # re-fetches it instead of silently dropping its leads.
        if cpath is not None and durable and n > 0 and not cancelled:
            per_source_cursor[source.name] = cur - 1
            done_through = max(done_through, cur - 1)
            _write_cursor(cpath, fp, slug, seq, done_through, per_source_cursor)
        if cancelled:
            break
    _tb_vulnfeed_exit(_tb_ctx)              # stop attributing to "vulnfeed" before returning

    if cpath is not None and not cancelled:
        # the pull ran to completion (no crash — a raised fetch never reaches here — and no STOP): clear
        # the checkpoint so the NEXT pull re-fetches. A crash/STOP leaves the cursor so the following
        # pull RESUMES the interrupted work instead of losing it.
        _delete_cursor(cpath)
    return VulnfeedResult(minted_by_source=minted, applied=applied, queries_run=qrun,
                          cancelled=cancelled, last_seq=cur, refused=refused,
                          resumed_from_seq=resumed_from, skipped_by_source=skipped)
