"""monitoring_spool — the SOVEREIGN drain of the AEGIS-SaaS monitoring-report seam (AE-4b).

A tenant-bound AEGIS gateway (``framework.v2.aegis.monitoring_report``, AE-4a) spools one inert envelope per
confirmed/lead verdict: ``{schema, body, mac}`` where ``body`` is canonical JSON of verdict METADATA and ``mac`` is
HMAC-SHA256 under that deployment's per-(tenant, host) REPORT secret. The bytes sit unauthenticated at rest, so
this drain trusts NOTHING until:

  1. the envelope is a bounded regular UTF-8 file of the right schema (hostile-file-hardened, like billing_spool);
  2. the MAC verifies (constant-time) under the secret provisioned for the (org_id, host) the body names — a
     gateway for tenant A cannot forge a report for tenant B, and the secret never comes from the spool;
  3. the report is FRESH (``ts`` within ``max_age_s`` in the past and ``future_skew_s`` ahead);
  4. the tenant holds an ACTIVE monitoring authority for that exact host AT RECEIPT
     (``MonitoringAuthorityRegistry.active_at``) — a revoked/expired/ownership-lapsed grant drops its reports.

Only then is ONE spine event appended (signal ``aegis.monitoring_event``), carrying the metadata fields alone. It
is labelled honestly: these are GATEWAY-REPORTED detections (authenticated to the deployment), not owner-re-verified
FACTs — the sovereign plane does not re-run engine oracles (FATAL-2). Each confirmed report keeps its certificate
SHA-256 so it can be matched against the offline-re-runnable certificate the gateway retains.

IDEMPOTENT: content-addressed ``processed/<sha256>`` dedup + read-time ``report_id`` dedup. FAIL-CLOSED: any
failure moves the file to ``rejected/`` with a ``.reason`` sidecar and appends nothing; ``drain()`` never raises on
one bad file. SOVEREIGN-only (``assert_no_offense``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.fold_read import UNCACHED as _UNCACHED, cached_unsigned_read  # noqa: E402
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)

REPORT_SCHEMA = "vigil.aegis.monitoring.v1"                 # MUST match framework.v2.aegis.monitoring_report
REPORT_DOMAIN = b"vigil.aegis.monitoring-report.v1\x00"     # MUST match (pinned by a cross-plane round-trip test)
DOMAIN_SLUG_PREFIX = b"vigil.aegis.monitoring-domain.v1\x00"  # MUST match (AS-3a strict-domain slug; pinned)
EVENT_SIGNAL = "aegis.monitoring_event"
DRAIN_ALERT_SIGNAL = "aegis.monitoring_drain_alert"          # AS-3a: a strictness quarantine fired an alert
_MAX_BYTES = 16 * 1024
_DECISIONS = frozenset({"confirmed", "lead"})
_FIELDS = ("org_id", "host", "ts", "decision", "attack_class", "action", "confidence", "provenance_tier",
           "certificate_sha256", "report_id")
_OFF_DOMAIN_SWEEP_CAP = 4096       # AS-3a: a single strict drain quarantines at most this many off-domain items
_PER_DOMAIN_DRAIN_CAP = 1024       # AS-3a red-pen #3: the BOUNDED SAFE DEFAULT per-domain per-pass cost. A
#                                    declared tenant drains at most this many reports per pass, so a flooded
#                                    tenant whose slug sorts first can NEVER consume the whole pass and starve
#                                    the next declared tenant — fairness is the DEFAULT, not opt-in.


def domain_slug(org_id: str, host: str) -> str:
    """A path-safe, collision-resistant slug for the (org_id, host) MONITORING DOMAIN (AS-3a).

    MIRRORS ``framework.v2.aegis.monitoring_report.domain_slug`` byte-for-byte — a shared CONTRACT
    (not shared code: FATAL-2 forbids the sovereign plane importing the engine), pinned equal by a
    cross-plane test exactly as ``REPORT_SCHEMA`` / ``REPORT_DOMAIN`` are. A strict drain processes
    each DECLARED domain's own ``incoming/<slug>/`` subtree in isolation and quarantines everything
    else by LOCATION, so one tenant's volume/poison never enters another tenant's drain path. The key
    is LENGTH-PREFIXED and domain-separated so distinct (org, host) pairs can never alias. PURE."""
    key = f"{len(org_id)}:{org_id}\x1f{len(host)}:{host}".encode("utf-8")
    return hashlib.sha256(DOMAIN_SLUG_PREFIX + key).hexdigest()[:32]


class MonitoringSpoolError(RuntimeError):
    """A fail-closed refusal while draining one monitoring report (nothing was spined)."""


SecretResolver = Callable[[str, str], Optional[bytes]]


class MonitoringSpoolWatcher:
    def __init__(self, store, *, spool_dir: "str | os.PathLike", secret_for: SecretResolver, authority,
                 now_fn: Callable[[], float] = time.time, max_age_s: float = 7 * 24 * 3600.0,
                 future_skew_s: float = 300.0,
                 domains: "Optional[Iterable[tuple[str, str]]]" = None,
                 per_domain_limit: Optional[int] = None,
                 off_domain_limit: int = _OFF_DOMAIN_SWEEP_CAP) -> None:
        if not callable(secret_for):
            raise ValueError("secret_for (the per-(tenant, host) report-secret resolver) is required")
        if authority is None or not hasattr(authority, "active_at"):
            raise ValueError("a MonitoringAuthorityRegistry is required to re-bind every report")
        self.store = store
        self.secret_for = secret_for
        self.authority = authority
        self._now = now_fn
        self.max_age_s = float(max_age_s)
        self.future_skew_s = float(future_skew_s)
        # AS-3a STRICT-DOMAIN mode (opt-in, DEFAULT-OFF). ``domains=None`` ⇒ the unchanged GLOBAL drain
        # (byte-for-byte). A declared set ⇒ the strict drain: process each declared domain's OWN
        # ``incoming/<slug>/`` subtree in isolation, quarantine everything else off-domain by LOCATION
        # (never scanning its content), and fire one coalesced alert per pass. ``per_domain_limit`` bounds
        # the reports one domain drains per pass (fairness) — ``None`` means the BOUNDED SAFE DEFAULT
        # (``_PER_DOMAIN_DRAIN_CAP``), NOT unbounded, so a flooded tenant can never starve another (red-pen #3);
        # ``off_domain_limit`` bounds the off-domain / in-domain-foreign sweeps so even a flood of junk cannot
        # blow up a drain pass. Both bounds also bound the ENUMERATION itself (scandir early-stop), not just the
        # processed slice (red-pen #1).
        self._domains: "Optional[dict[str, tuple[str, str]]]" = (
            None if domains is None else {domain_slug(str(o), str(h)): (str(o), str(h)) for o, h in domains})
        self.per_domain_limit = (_PER_DOMAIN_DRAIN_CAP if per_domain_limit is None else max(0, int(per_domain_limit)))
        self.off_domain_limit = max(0, int(off_domain_limit))
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"
        self.processed = self.spool / "processed"
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    # -- one envelope ---------------------------------------------------------------------------------
    def _verify(self, text: str) -> dict:
        try:
            env = json.loads(text)
        except ValueError as exc:
            raise MonitoringSpoolError(f"not valid JSON: {exc}") from exc
        if not isinstance(env, dict) or env.get("schema") != REPORT_SCHEMA:
            raise MonitoringSpoolError("not a monitoring-report envelope of the expected schema")
        body, mac = env.get("body"), env.get("mac")
        if not isinstance(body, str) or not isinstance(mac, str) or not body or not mac:
            raise MonitoringSpoolError("envelope missing body/mac")
        try:
            rep = json.loads(body)
        except ValueError as exc:
            raise MonitoringSpoolError(f"body is not valid JSON: {exc}") from exc
        if not isinstance(rep, dict) or rep.get("schema") != REPORT_SCHEMA:
            raise MonitoringSpoolError("body schema mismatch")
        org, host = rep.get("org_id"), rep.get("host")
        if not isinstance(org, str) or not org or not isinstance(host, str) or not host:
            raise MonitoringSpoolError("report names no tenant/host")
        secret = self.secret_for(org, host)
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
            raise MonitoringSpoolError("no report secret provisioned for this tenant/host")
        want = hmac.new(bytes(secret), REPORT_DOMAIN + body.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, mac):
            raise MonitoringSpoolError("report MAC does not verify under the tenant's report secret")
        if rep.get("decision") not in _DECISIONS:
            raise MonitoringSpoolError("report decision is not reportable")
        try:
            ts = float(rep["ts"])
        except (KeyError, TypeError, ValueError) as exc:
            raise MonitoringSpoolError("report timestamp unreadable") from exc
        now = float(self._now())
        if not (now - self.max_age_s <= ts <= now + self.future_skew_s):
            raise MonitoringSpoolError("report is stale or from the future")
        if self.authority.active_at(org, host, now=now) is None:
            raise MonitoringSpoolError("tenant holds no active monitoring authority for this host")
        return rep

    def _record(self, rep: dict) -> int:
        payload: dict[str, object] = {"signal": EVENT_SIGNAL, "source_class": "gateway_reported"}
        for k in _FIELDS:
            payload[k] = rep.get(k)
        return self.store.append(kind="event", source="aegis", actor="AEGIS", payload=payload)

    # -- hostile-file hardened I/O (mirrors billing_spool) -------------------------------------------------
    @staticmethod
    def _read_regular(path: Path) -> str:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file (symlink/FIFO/device refused)")
            if st.st_size > _MAX_BYTES:
                raise OSError(f"file exceeds {_MAX_BYTES} bytes")
            data = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > _MAX_BYTES:
            raise OSError(f"file exceeds {_MAX_BYTES} bytes")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OSError(f"not valid UTF-8: {exc}") from exc

    def _quarantine(self, path: Path, reason: str) -> None:
        dest = self.rejected / path.name
        try:
            os.replace(path, dest)
        except OSError:
            dest = self.rejected / (path.name + ".orphan")
        try:
            (self.rejected / (dest.name + ".reason")).write_text(reason[:2000], encoding="utf-8")
        except OSError:
            pass

    def _process_one(self, src: Path) -> "tuple[str, int]":
        """Claim ONE incoming file out of ``incoming/`` and drain it: returns ``(status, seq)`` where status is
        ``recorded`` | ``deduped`` | ``rejected`` | ``gone`` and ``seq`` is the spined event seq (``-1`` unless
        recorded). Shared by the global and strict drains so the per-file contract (atomic claim, bounded
        regular-UTF-8 read, content-addressed dedup, fail-closed verify, nothing-appended-on-refusal) lives in
        exactly one place. Never raises."""
        claimed = self.working / src.name
        try:
            os.replace(src, claimed)   # atomic CLAIM: the file leaves incoming/ before we act on it
        except OSError:
            return ("gone", -1)        # raced away — nothing to do
        try:
            text = self._read_regular(claimed)
        except OSError as exc:
            self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
            return ("rejected", -1)
        marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
        if marker.exists():
            try:
                os.replace(claimed, marker)
            except OSError:
                pass
            return ("deduped", -1)
        try:
            rep = self._verify(text)
            seq = self._record(rep)
            os.replace(claimed, marker)
            return ("recorded", seq)
        except Exception as exc:  # noqa: BLE001 — any failure is a refusal; nothing appended
            self._quarantine(claimed, f"{type(exc).__name__}: {exc}")
            return ("rejected", -1)

    def drain(self) -> dict:
        """Drain the spool once. DEFAULT (``domains=None``): the unchanged GLOBAL drain — process every file in
        ``incoming/`` in one pass. STRICT (AS-3a, ``domains`` declared): process ONLY each declared domain's own
        ``incoming/<slug>/`` subtree, quarantine everything else OFF-DOMAIN by location (never scanning it), and
        fire one coalesced alert per pass. Returns ``{recorded, rejected, deduped, seqs}`` and, in strict mode,
        also ``{off_domain, in_domain_foreign, alert_seq}``. Never raises on one bad file."""
        if self._domains is None:
            return self._drain_global()
        return self._drain_strict()

    def _drain_global(self) -> dict:
        """The default drain: one pass over every ``incoming/*.json`` (byte-for-byte the pre-AS-3a behavior)."""
        recorded, rejected, deduped, seqs = 0, 0, 0, []
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue
            status, seq = self._process_one(src)
            if status == "recorded":
                recorded += 1
                seqs.append(seq)
            elif status == "deduped":
                deduped += 1
            elif status == "rejected":
                rejected += 1
        return {"recorded": recorded, "rejected": rejected, "deduped": deduped, "seqs": seqs}

    def _drain_strict(self) -> dict:
        """STRICT-DOMAIN drain (AS-3a). Process each DECLARED domain's own ``incoming/<slug>/`` subtree in
        isolation — so a given tenant's cost depends ONLY on its own subtree, never on another tenant's volume
        or poison (TT-A's p95 holds while TT-B is flooded). Then a BOUNDED off-domain sweep quarantines, by
        LOCATION alone (no content read, no MAC/authority check — i.e. NO GLOBAL SCAN), anything that is not
        under a declared domain: flat files in ``incoming/`` and whole undeclared ``incoming/<x>/`` subtrees.
        One coalesced alert per pass fires when any strictness quarantine happened.

        THREE red-pen bounds hold every pass (AS-3a follow-up): (1) the ENUMERATION itself is bounded — each
        declared subtree and the off-domain sweep read via ``os.scandir`` and EARLY-STOP at their caps, so a
        sustained flood is read only up to the cap, never materialized/sorted in full; (2) every subtree entry
        that is NOT a flat ``*.json`` report (a non-``.json`` file, a nested path) is swept BY LOCATION into
        ``rejected/`` — never scanned as input and never silently retained; (3) ``per_domain_limit`` carries a
        BOUNDED SAFE DEFAULT, so a flooded tenant drains at most that many reports per pass and the next declared
        tenant is always served in the SAME pass (no starvation)."""
        declared = self._domains or {}
        recorded, rejected, deduped = 0, 0, 0
        in_domain_foreign = 0
        seqs: "list[int]" = []
        # 1) DECLARED domains first (so a declared tenant is always served before any off-domain work). Each is
        #    read from its OWN subtree via a SINGLE bounded scandir pass: up to per_domain_limit flat *.json to
        #    drain + up to off_domain_limit OTHER entries (non-.json, nested dirs) to quarantine by location.
        for slug in sorted(declared):
            ddir = self.incoming / slug
            if not ddir.is_dir():
                continue
            picked, foreign = self._scan_declared_subtree(ddir, self.per_domain_limit, self.off_domain_limit)
            for name in sorted(picked):                # determinism over the BOUNDED slice (signed-path order)
                status, seq = self._process_one(ddir / name)
                if status == "recorded":
                    recorded += 1
                    seqs.append(seq)
                elif status == "deduped":
                    deduped += 1
                elif status == "rejected":
                    rejected += 1
            swept_foreign = 0                          # per-subtree AGGREGATE: bound the TOTAL in-domain-foreign
            for entry in foreign:                      # sweep by off_domain_limit (not off_domain_limit PER entry).
                if swept_foreign >= self.off_domain_limit:  # `foreign` can hold up to off_domain_limit DIRECTORY
                    break                              # entries, each of which _sweep_entry drains up to its budget
                got = self._sweep_entry(               # of children — so a full off_domain_limit per entry would do
                    entry, f"in-domain foreign: not a flat *.json report under declared domain '{slug}'",
                    self.off_domain_limit - swept_foreign)  # off_domain_limit**2 moves. A DECREMENTING budget, exactly
                swept_foreign += got                   # like _sweep_off_domain, caps the whole subtree's foreign
                in_domain_foreign += got               # work at off_domain_limit and keeps the reported count honest.
        # 2) BOUNDED off-domain sweep — quarantine by location, never scanning content.
        off_domain = self._sweep_off_domain(set(declared))
        # 3) ONE coalesced alert per pass when strictness quarantined anything (off-domain, an in-domain foreign
        #    entry, OR a poisoned in-domain report). Bounded to one spine event per drain so a flood can never
        #    amplify onto the spine.
        alert_seq = -1
        if off_domain or rejected or in_domain_foreign:
            alert_seq = self._emit_alert(off_domain=off_domain, poisoned=rejected,
                                         in_domain_foreign=in_domain_foreign)
        return {"recorded": recorded, "rejected": rejected, "deduped": deduped, "seqs": seqs,
                "off_domain": off_domain, "in_domain_foreign": in_domain_foreign, "alert_seq": alert_seq}

    def _scan_declared_subtree(self, ddir: Path, json_budget: int,
                               foreign_budget: int) -> "tuple[list[str], list[os.DirEntry[str]]]":
        """ONE bounded, UNSORTED ``os.scandir`` pass over a declared domain's OWN subtree (AS-3a red-pen #1/#2).
        Collect up to ``json_budget`` flat ``*.json`` report NAMES to drain, and up to ``foreign_budget`` OTHER
        entries (non-``.json`` files, nested dirs, a ``*.json`` that is not a regular file) to quarantine BY
        LOCATION. The ENUMERATION is bounded: at most ``json_budget + foreign_budget`` entries are ever examined,
        so a sustained flood is read only up to the caps, never the whole directory (across passes the claim-and-
        move drain chews the backlog down bounded-per-pass). ``.tmp-`` producer temps are skipped. The caller
        SORTS the returned names so the signed drain order is deterministic over the bounded slice. Never raises."""
        picked: "list[str]" = []
        foreign: "list[os.DirEntry[str]]" = []
        examined = 0
        cap = json_budget + foreign_budget
        try:
            it = os.scandir(ddir)
        except OSError:
            return picked, foreign
        with it:
            for entry in it:
                if entry.name.startswith(".tmp-"):
                    continue                           # a producer's in-flight temp — leave it
                if len(picked) >= json_budget and len(foreign) >= foreign_budget:
                    break                              # both budgets met — stop early (bounded enumeration)
                examined += 1
                if examined > cap:
                    break                              # hard enumeration bound regardless of flood composition
                if entry.name.endswith(".json"):
                    try:
                        regular = entry.is_file(follow_symlinks=False)
                    except OSError:
                        regular = False
                    if regular:
                        if len(picked) < json_budget:
                            picked.append(entry.name)
                        continue                       # a flat *.json report — drained by the caller
                if len(foreign) < foreign_budget:
                    foreign.append(entry)              # non-.json / nested dir / non-regular .json -> quarantine
        return picked, foreign

    def _sweep_entry(self, entry: "os.DirEntry[str]", reason: str, budget: int) -> int:
        """Quarantine ONE off-/in-domain entry BY LOCATION (never reading file content), bounded by ``budget``.
        A regular file (or symlink / other non-dir) is moved as-is into ``rejected/``; a real sub-directory has
        its children moved (a BOUNDED scandir, early-stopping at ``budget``) and is then best-effort removed.
        Symlinks are NOT followed (a symlinked dir is moved as the link, never walked out of the spool). Returns
        the count quarantined (``<= budget``). Never raises."""
        if budget <= 0:
            return 0
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            is_dir = False
        if not is_dir:
            self._quarantine(Path(entry.path), reason)
            return 1
        swept = 0
        try:
            sub = os.scandir(entry.path)
        except OSError:
            return 0
        with sub:
            for child in sub:
                if swept >= budget:
                    break                              # bounded: never read the whole nested dir in one pass
                self._quarantine(Path(child.path), reason)
                swept += 1
        try:
            Path(entry.path).rmdir()                    # best-effort tidy of the now-(maybe-)empty dir
        except OSError:
            pass
        return swept

    def _sweep_off_domain(self, declared_slugs: "set[str]") -> int:
        """Quarantine, BY LOCATION only (no content read), everything in ``incoming/`` that is NOT a declared
        domain subtree: a flat file placed directly in ``incoming/``, or any UNDECLARED ``incoming/<x>/`` subtree.
        The ENUMERATION is bounded (AS-3a red-pen #1): ``incoming/`` is read via ``os.scandir`` and the sweep
        EARLY-STOPS at ``off_domain_limit``, so a flood of off-domain junk is read only up to the cap, never
        materialized/sorted in full. A declared domain's own subtree is NEVER swept (it was drained in step 1);
        an in-flight ``.tmp-`` file is left for the producer. Returns the number quarantined. Never raises."""
        if self.off_domain_limit <= 0:
            return 0
        swept = 0
        try:
            it = os.scandir(self.incoming)
        except OSError:
            return 0
        with it:
            for entry in it:
                if swept >= self.off_domain_limit:
                    break                              # bounded enumeration — stop at the cap, never read on
                name = entry.name
                if name.startswith(".tmp-"):
                    continue                           # a producer's in-flight temp — never quarantine mid-write
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                if is_dir and name in declared_slugs:
                    continue                           # a declared domain subtree — handled in step 1
                reason = (f"off-domain: '{name}' is not a declared monitoring domain" if is_dir
                          else "off-domain: file placed outside any declared domain subdir")
                swept += self._sweep_entry(entry, reason, self.off_domain_limit - swept)
        return swept

    def _emit_alert(self, *, off_domain: int, poisoned: int, in_domain_foreign: int = 0) -> int:
        """Append ONE coalesced strictness alert for this drain pass (signal ``aegis.monitoring_drain_alert``).
        METADATA-ONLY counts — off-domain and in-domain-foreign items are NEVER read, so there is no tenant
        content to leak. This surfaces the strictness breach on the owner's monitoring line; the standing
        ``quarantined_count`` dead-man also fires off ``rejected/`` so a buried quarantine keeps alarming until a
        human clears it."""
        payload: "dict[str, object]" = {
            "signal": DRAIN_ALERT_SIGNAL, "source_class": "drain_strictness",
            "off_domain": int(off_domain), "poisoned": int(poisoned),
            "in_domain_foreign": int(in_domain_foreign), "scope": "monitoring_spool",
        }
        return self.store.append(kind="event", source="aegis", actor="AEGIS", payload=payload)


# ================================================================================================================
# Front C S0d follow-up — the verified INCREMENTAL FOLD INDEX behind the bell poll.
#
# `monitoring_events` was the last hot per-customer read still doing a plain O(N) `iter_records()` scan of the
# whole spine on every poll. It now serves from a per-org fold of the monitoring line (exactly as the findings /
# wallet / customer reads do): the fold verifies/folds only the records appended since the last read (O(records
# since), not O(all)), and a poll reads O(its own events), not O(all monitoring records on the spine). It is an
# UNSIGNED, `live_window` fold — monitoring events carry no owner signature (the drain already authenticated them)
# and the scan loads no snapshot, so the full scan below answers whenever the cache declines. DEFAULT-OFF
# (`VIGIL_FOLD_CACHE_ENABLED`): with the cache off the unchanged scan runs, byte-identical. FATAL-2: sovereign-only.
# ================================================================================================================
class _MonitoringLine:
    """One org's drained monitoring events as the read projects them: ``events`` is the per-org list the scan
    builds (oldest-first, report_id-deduped first-wins) and ``seen`` its report_ids — exactly the scan's per-query
    ``out`` / ``seen`` for that org, built once and extended incrementally."""

    __slots__ = ("events", "seen")

    def __init__(self) -> None:
        self.events: "list[dict]" = []
        self.seen: set = set()


class _MonitoringView:
    """The per-org monitoring index ``monitoring_events`` reads instead of rescanning the whole spine per request.
    ``by_org[org]`` = that org's :class:`_MonitoringLine`, folded from EXACTLY the records the scan keeps (same
    signal / org / report_id checks; the projected row is the same pure expression). A record whose ``report_id``
    is unhashable (the scan's ``rid in seen`` would raise on it) POISONS the view, so every read falls back to the
    unchanged scan and raises exactly where it did."""

    __slots__ = ("by_org", "poisoned")

    def __init__(self) -> None:
        self.by_org: "dict[str, _MonitoringLine]" = {}
        self.poisoned = False

    def page(self, org_id: str, limit: int) -> "list[dict]":
        """The org's events newest-first, ``[:max(0, int(limit))]`` — IDENTICAL to the scan's
        ``out.reverse(); out[:max(0, int(limit))]`` — as fresh COPIES (never a reference into the fold state, which
        later reads extend in place). ``start = max(0, len-n)`` is the newest ``n`` oldest-first (``n==0`` -> [],
        ``n > len`` -> all); ``reversed`` makes it newest-first."""
        line = self.by_org.get(org_id)
        if line is None:
            return []
        n = max(0, int(limit))
        start = max(0, len(line.events) - n)
        return [dict(e) for e in reversed(line.events[start:])]


def _monitoring_step(view: "_MonitoringView", r, _ctx) -> None:
    """Fold ONE spine record into the per-org index — the scan's own filter / dedup / projection, record by record.
    No kind filter: the scan keys on the payload ``signal`` alone (a record of any kind), so this must too."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != EVENT_SIGNAL:
        return
    org = p.get("org_id")
    if not isinstance(org, str):
        return                                        # a str query can only equal a str org_id (the scan's `!=`)
    rid = p.get("report_id")
    try:
        hash(rid)
    except TypeError:
        view.poisoned = True                          # the scan's `rid in seen` would raise: decline to the scan
        return
    line = view.by_org.get(org)
    if line is None:
        line = _MonitoringLine()
        view.by_org[org] = line
    if rid in line.seen:
        return                                        # first occurrence (lowest seq) wins — exactly the scan
    line.seen.add(rid)
    line.events.append({k: p.get(k) for k in _FIELDS} | {"seq": r.seq, "source_class": p.get("source_class")})


_MONITORING_FOLD = FoldCache("inbound.monitoring_events", step=_monitoring_step)


def _monitoring_cached(store, reader: "Callable[[Any], Any]") -> Any:
    """``reader(view)`` over the verified incremental fold of the monitoring line, or ``_UNCACHED`` (the flag is
    off, the view is poisoned, or the rebuild's read was not contiguous). A ``live_window`` fold: the scan loads no
    snapshot, so a snapshot that cannot be loaded declines rather than raises (the full scan still answers)."""
    return cached_unsigned_read(_MONITORING_FOLD, store, seed=lambda snap: (_MonitoringView(), -1),
                                live_window=True, reader=reader)


def monitoring_events(store, org_id: str, *, limit: int = 200) -> list[dict]:
    """The tenant's monitoring events, newest first, STRICTLY scoped to ``org_id`` (report_id-deduped).

    Served from a verified incremental per-org fold (Front C S0d; ``VIGIL_FOLD_CACHE_ENABLED``) so a bell poll
    reads O(its own events), not the whole spine. With the cache off — or on any doubt (``_UNCACHED``) — the
    unchanged O(N) scan below answers, byte-identical."""
    if not isinstance(org_id, str) or not org_id:
        return []
    hit = _monitoring_cached(store, lambda v: v.page(org_id, limit))
    if hit is not _UNCACHED:
        return hit
    out, seen = [], set()
    for r in store.iter_records():
        p = r.payload
        if not isinstance(p, dict) or p.get("signal") != EVENT_SIGNAL or p.get("org_id") != org_id:
            continue
        rid = p.get("report_id")
        if rid in seen:
            continue
        seen.add(rid)
        out.append({k: p.get(k) for k in _FIELDS} | {"seq": r.seq, "source_class": p.get("source_class")})
    out.reverse()
    return out[: max(0, int(limit))]
