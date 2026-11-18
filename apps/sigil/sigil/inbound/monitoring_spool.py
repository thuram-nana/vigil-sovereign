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
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.fold_read import UNCACHED as _UNCACHED, cached_unsigned_read  # noqa: E402
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)

REPORT_SCHEMA = "vigil.aegis.monitoring.v1"                 # MUST match framework.v2.aegis.monitoring_report
REPORT_DOMAIN = b"vigil.aegis.monitoring-report.v1\x00"     # MUST match (pinned by a cross-plane round-trip test)
EVENT_SIGNAL = "aegis.monitoring_event"
_MAX_BYTES = 16 * 1024
_DECISIONS = frozenset({"confirmed", "lead"})
_FIELDS = ("org_id", "host", "ts", "decision", "attack_class", "action", "confidence", "provenance_tier",
           "certificate_sha256", "report_id")


class MonitoringSpoolError(RuntimeError):
    """A fail-closed refusal while draining one monitoring report (nothing was spined)."""


SecretResolver = Callable[[str, str], Optional[bytes]]


class MonitoringSpoolWatcher:
    def __init__(self, store, *, spool_dir: "str | os.PathLike", secret_for: SecretResolver, authority,
                 now_fn: Callable[[], float] = time.time, max_age_s: float = 7 * 24 * 3600.0,
                 future_skew_s: float = 300.0) -> None:
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

    def drain(self) -> dict:
        """Process every file in ``incoming/`` once: {recorded, rejected, deduped, seqs}. Never raises on one file."""
        recorded, rejected, deduped, seqs = 0, 0, 0, []
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)
            except OSError:
                continue
            try:
                text = self._read_regular(claimed)
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
                rejected += 1
                continue
            marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
            if marker.exists():
                try:
                    os.replace(claimed, marker)
                except OSError:
                    pass
                deduped += 1
                continue
            try:
                rep = self._verify(text)
                seqs.append(self._record(rep))
                recorded += 1
                os.replace(claimed, marker)
            except Exception as exc:  # noqa: BLE001 — any failure is a refusal; nothing appended
                self._quarantine(claimed, f"{type(exc).__name__}: {exc}")
                rejected += 1
        return {"recorded": recorded, "rejected": rejected, "deduped": deduped, "seqs": seqs}


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
