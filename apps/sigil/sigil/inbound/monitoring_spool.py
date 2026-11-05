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
from typing import Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

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


def monitoring_events(store, org_id: str, *, limit: int = 200) -> list[dict]:
    """The tenant's monitoring events, newest first, STRICTLY scoped to ``org_id`` (report_id-deduped)."""
    if not isinstance(org_id, str) or not org_id:
        return []
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
