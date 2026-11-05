"""AEGIS-SaaS AE-4 (data-plane half) — seal each tenant verdict as an INERT, metadata-only monitoring report and
spool it for the sovereign plane.

The gateway holds NO signing key. A report is authenticated with a dedicated per-(tenant, host) REPORT secret
(HMAC-SHA256, domain-separated), provisioned per deployment — distinct from ``AegisConfig.deployment_secret``
(the actor-pseudonymization key, which must never reach the sovereign plane). The sovereign drainer
(``sigil.inbound.monitoring_spool``) verifies the MAC with THAT tenant's secret, re-checks that the tenant holds an
active monitoring authority for the host, and only then records the event — so the spool is fail-closed even
though the bytes sit unauthenticated at rest.

PRIVACY BY CONSTRUCTION: a report carries verdict METADATA only — decision, attack class, action, a rounded
confidence, the provenance tier, and (for a confirmed verdict) the SHA-256 of its certificate. Never the request
path, query, headers, body, client address or actor identity.

TOTAL: the reporter never raises into the gateway (a monitoring-pipeline fault must not affect traffic), never
blocks, and drops (counting) anything over its per-minute cap.

FATAL-2: engine-side; imports nothing from ``sigil``. The envelope contract is mirrored in the sovereign drainer
and pinned by a cross-plane round-trip test.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as _secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

__all__ = ["REPORT_SCHEMA", "REPORT_DOMAIN", "build_report", "seal_report", "SpoolReporter"]

REPORT_SCHEMA = "vigil.aegis.monitoring.v1"
REPORT_DOMAIN = b"vigil.aegis.monitoring-report.v1\x00"
_MAX_ENVELOPE_BYTES = 16 * 1024
_REPORTED_DECISIONS = frozenset({"confirmed", "lead"})


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _cert_digest(verdict: Any) -> str:
    cert = getattr(verdict, "certificate", None)
    if cert is None:
        return ""
    try:
        raw = cert.model_dump_json() if hasattr(cert, "model_dump_json") else json.dumps(cert, default=str)
    except Exception:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_report(verdict: Any, *, org_id: str, host: str, ts: float) -> dict:
    """Verdict METADATA only (see module doc). No request content, no actor."""
    return {
        "schema": REPORT_SCHEMA,
        "org_id": str(org_id),
        "host": str(host),
        "ts": float(ts),
        "decision": str(getattr(verdict, "decision", "")),
        "attack_class": str(getattr(verdict, "attack_class", "")),
        "action": str(getattr(verdict, "action", "")),
        "confidence": round(float(getattr(verdict, "confidence", 0.0) or 0.0), 3),
        "provenance_tier": str(getattr(verdict, "provenance", "") or "").split(":", 1)[0],
        "certificate_sha256": _cert_digest(verdict),
        "report_id": _secrets.token_hex(16),
    }


def seal_report(report: dict, secret: bytes) -> dict:
    """``{schema, body, mac}`` where ``mac = HMAC-SHA256(secret, REPORT_DOMAIN || body)`` and ``body`` is the
    canonical JSON of the report (so the verifier MACs the exact bytes it parses)."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise ValueError("a monitoring report secret of at least 16 bytes is required")
    body = _canonical(report)
    mac = hmac.new(bytes(secret), REPORT_DOMAIN + body.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"schema": REPORT_SCHEMA, "body": body, "mac": mac}


class SpoolReporter:
    """An ``on_verdict`` sink for a tenant gateway: seal + atomically spool each confirmed/lead verdict."""

    def __init__(self, spool_dir: "str | Path", *, org_id: str, host: str, secret: bytes,
                 max_per_minute: int = 600, now_fn: Callable[[], float] = time.time) -> None:
        if not org_id or not host:
            raise ValueError("a monitoring reporter is bound to one tenant and one host")
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
            raise ValueError("a monitoring report secret of at least 16 bytes is required")
        self._incoming = Path(spool_dir) / "incoming"
        self._org, self._host, self._secret = str(org_id), str(host), bytes(secret)
        self._cap = max(1, int(max_per_minute))
        self._now = now_fn
        self._lock = threading.Lock()
        self._window = (0, 0)          # (minute bucket, count)
        self.dropped = 0
        self.written = 0
        self.errors = 0

    def _admit(self) -> bool:
        with self._lock:
            bucket = int(self._now() // 60)
            b, n = self._window
            if b != bucket:
                b, n = bucket, 0
            if n >= self._cap:
                self.dropped += 1
                self._window = (b, n)
                return False
            self._window = (b, n + 1)
            return True

    def __call__(self, verdict: Any) -> None:
        try:
            if verdict is None or getattr(verdict, "decision", None) not in _REPORTED_DECISIONS:
                return
            if not self._admit():
                return
            env = seal_report(build_report(verdict, org_id=self._org, host=self._host, ts=self._now()),
                              self._secret)
            data = _canonical(env).encode("utf-8")
            if len(data) > _MAX_ENVELOPE_BYTES:
                self.errors += 1
                return
            self._write(data)
            self.written += 1
        except Exception:
            self.errors += 1          # never raise into the gateway

    def _write(self, data: bytes) -> None:
        self._incoming.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self._incoming, 0o700)
        except OSError:
            pass
        final = self._incoming / (hashlib.sha256(data).hexdigest()[:32] + ".json")
        if final.exists():
            return
        tmp = self._incoming / (".tmp-" + _secrets.token_hex(8))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, final)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise


def compose_sinks(*sinks: Optional[Callable[[Any], None]]) -> Optional[Callable[[Any], None]]:
    """Fan a verdict out to several sinks, each isolated (one failing never affects another or the gateway)."""
    live = [s for s in sinks if s is not None]
    if not live:
        return None

    def _fan(v: Any) -> None:
        for s in live:
            try:
                s(v)
            except Exception:
                pass
    return _fan
