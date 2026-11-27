"""framework.v2.aegis.receiver — AS-9b: the per-tenant ingest RECEIVER (hot SPOOL) engine core.

An external sensor/provider PUSHes ONE inert, metadata-only finding per request. The receiver treats
every byte as hostile, authenticates the transport (HMAC body signature and/or mTLS client), enforces
caps (bounded body + per-minute rate, DROP-and-COUNT over cap, NEVER raising into the request path),
and — only on an authenticated, in-bounds, well-formed, SAME-TENANT record — seals it as the AS-2b
``{schema, body, mac}`` monitoring envelope and lands it in the hot SPOOL the AS-3c-hardened sovereign
drain consumes.

WHAT IT WRITES — the SPOOL FORMAT (do NOT invent a format). The record the sovereign drain
(``sigil.inbound.monitoring_spool.MonitoringSpoolWatcher``) actually consumes is the v1 monitoring
envelope ``{schema: "vigil.aegis.monitoring.v1", body, mac}`` where ``body`` is canonical JSON of verdict
METADATA and ``mac = HMAC-SHA256(report_secret, REPORT_DOMAIN || body)``, filed into the STRICT per-domain
subtree ``<spool>/incoming/<domain_slug(org,host)>/`` via the shared content-addressed, append-only,
atomic :func:`~framework.v2.aegis.monitoring_report.atomic_spool_write`. The receiver reuses
``monitoring_report.{REPORT_SCHEMA, REPORT_DOMAIN, domain_slug, seal_report, atomic_spool_write}`` verbatim
so a landed record is byte-for-byte what the drain's ``_verify`` + ACCEPT-SET + DEDUP accept. (See the
module note below on why v1, not the v2 ``incoming_v2`` emission seam.)

DEDUP ID. The report carries a STABLE ``report_id`` = a content digest of the record's own metadata, so a
re-POST of the SAME record mints the SAME ``report_id`` and the drain's bounded ``(org_id, report_id)``
window dedups it at-most-once — AND the whole sealed envelope (hence its content-addressed filename) is a
pure function of the record (DETERMINISM: no wall-clock, no RNG in the body or its id).

DEFAULT-OFF (``VIGIL_AEGIS_RECEIVER``, strict / fail-closed, mirrors ``broker.BROKER_ENV`` /
``job_runner.JOBS_ENV``): off ⇒ the receiver is INERT — :func:`serve_receiver` binds NO socket and
:meth:`IngestReceiver.ingest` accepts nothing. ``enforce_capable=False`` (the fleet contract): the receiver
never blocks/enforces; it only accepts + spools.

SECRETS ARE SSM-DELIVERED, NEVER env (AS-2h). The inbound HMAC verify opens a SEALED ingest secret through
:class:`~framework.v2.aegis.connector_secrets.InboundConnectorVerifier` (the net-new AS-9b verify peer,
reusing ``open_secret`` / ``connector_aad``); the per-(tenant, host) REPORT secret that seals the spooled
envelope is the same SSM-delivered report secret the gateway holds (``report-secret``), passed in as bytes
— never read from the environment here.

FATAL-2: engine leg — imports only ``vigil_core``, the stdlib, and
``framework.v2.aegis.{boundary, monitoring_report, connector_secrets}``. NEVER ``sigil``.

 --------------------------------------------------------------------------------------------------------
MODULE NOTE — v1 spool, not the v2 ``incoming_v2`` seam (resolved ambiguity, flagged for red-pen):
The AS-9b plan names the v2 ``AegisEventV2`` / ``incoming_v2`` emission helpers, but the SHIPPED sovereign
drain (``MonitoringSpoolWatcher``) consumes ONLY the v1 ``incoming/<slug>/`` monitoring envelope — the v2
``incoming_v2/`` subtree "the v1 drain never reads" has no consumer anywhere in the tree
(``monitoring_event_v2`` is a WRITER; no v2 drain exists). The load-bearing acceptance is that a landed
record is drained end-to-end by the REAL MonitoringSpoolWatcher, so the receiver writes the v1 envelope the
drain actually accepts. The envelope SHAPE (``{schema, body, mac}``), the content-addressed/append-only
``atomic_spool_write``, the ``domain_slug`` subtree, and the ``(org, report_id)`` dedup id are shared
between the seams, so this is the same contract minus the (unconsumed) v2 body.
"""
from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from vigil_core.canonical import canonical_json, sha256_hex

from . import boundary as _boundary
from .boundary import BoundaryError, normalize_text, redact_text
from .connector_secrets import (
    ConnectorBrokerDisabled,
    ConnectorBrokerRefused,
    InboundConnectorVerifier,
)
from .monitoring_report import (
    _MAX_ENVELOPE_BYTES,          # the SHARED spool-envelope byte cap — the drain refuses a larger file
    REPORT_DOMAIN,
    REPORT_SCHEMA,
    atomic_spool_write,
    domain_slug,
    seal_report,
)

__all__ = [
    "INGEST_FINDING_SCHEMA",
    "RECEIVER_ENV",
    "INGEST_HMAC_HEADER",
    "IngestOutcome",
    "IngestResult",
    "IngestReceiver",
    "ReceiverDisabled",
    "ReceiverServer",
    "receiver_enabled",
    "serve_receiver",
]

# The inbound WIRE schema a sensor/provider stamps on the pushed finding. Distinct from the SPOOL schema
# (``REPORT_SCHEMA``): the receiver TRANSLATES the inbound finding into the spool envelope the drain reads.
INGEST_FINDING_SCHEMA = "vigil.aegis.ingest.finding.v1"
INGEST_HMAC_HEADER = "X-Vigil-Ingest-Auth"      # ``v1=<hmac-sha256 over the raw body>`` (mirrors connector HMAC)

# The DEFAULT-OFF switch (strict, fail-closed; mirrors ``broker.BROKER_ENV`` / ``job_runner.JOBS_ENV``).
RECEIVER_ENV = "VIGIL_AEGIS_RECEIVER"

_MAX_BODY_BYTES = 16 * 1024          # the hot-path body cap (the drain itself refuses > 16 KiB files)
_MAX_PER_MINUTE = 600                # default per-minute accept cap (over-cap => DROP-and-count, never block)
_REPORTED_DECISIONS = frozenset({"confirmed", "lead"})
# The verdict-metadata fields the drain's ``_verify`` reads; the receiver fills exactly these + report_id.
_SPOOL_FIELDS = ("decision", "attack_class", "action", "confidence", "provenance_tier", "certificate_sha256")


def receiver_enabled() -> bool:
    """Is the receiver ARMED? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative token arms it."""
    return (os.environ.get(RECEIVER_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class ReceiverDisabled(RuntimeError):
    """The receiver was asked to serve while DEFAULT-OFF (``VIGIL_AEGIS_RECEIVER`` unset). Raised before any
    socket is bound, so a disabled receiver is fully inert."""


class IngestOutcome:
    """The disposition of one inbound request. A string enum (plain constants) so the result is trivially
    serialisable and the HTTP status maps cleanly. NONE of these raise into the request path."""

    SPOOLED = "spooled"                 # authenticated, in-bounds, landed in the hot spool            -> 202
    DEDUP_NOOP = "dedup_noop"           # byte-identical content already spooled (idempotent re-POST)  -> 202
    DROPPED_OVERSIZE = "dropped_oversize"   # body over the size cap — DROP-and-count                  -> 413
    DROPPED_ENVELOPE = "dropped_envelope"   # the SEALED envelope exceeds the spool/drain file cap     -> 413
    DROPPED_RATE = "dropped_rate"       # per-minute accept cap exceeded — DROP-and-count              -> 429
    REJECTED_AUTH = "rejected_auth"     # no/invalid HMAC and no verified mTLS client                  -> 401
    REJECTED_MALFORMED = "rejected_malformed"   # unparseable / schema-invalid / wrong-tenant finding  -> 400
    SPOOL_FAULT = "spool_fault"         # transient seal/spool I/O fault (SERVER-side) — retryable      -> 503
    DISABLED = "disabled"               # receiver is DEFAULT-OFF                                       -> 503

    _HTTP = {
        SPOOLED: 202, DEDUP_NOOP: 202, DROPPED_OVERSIZE: 413, DROPPED_ENVELOPE: 413, DROPPED_RATE: 429,
        REJECTED_AUTH: 401, REJECTED_MALFORMED: 400, SPOOL_FAULT: 503, DISABLED: 503,
    }

    @classmethod
    def http_status(cls, outcome: str) -> int:
        return cls._HTTP.get(outcome, 400)


@dataclass(frozen=True)
class IngestResult:
    """The value-free result of one ingest. ``report_id`` + ``filename`` are present only when SPOOLED/DEDUP;
    ``detail`` is a short, PII-free reason. Never carries the request body or any secret."""

    outcome: str
    http_status: int
    report_id: str = ""
    filename: str = ""
    detail: str = ""


def _coerce_ts(value: Any) -> float:
    ts = float(value)                 # raises TypeError/ValueError on a non-number
    if not math.isfinite(ts):
        raise ValueError("ts is not finite")
    return ts


class IngestReceiver:
    """The per-tenant ingest receiver core — PURE of any socket, so it is deterministic and unit-testable. One
    receiver is bound to exactly ONE tenant ``(org_id, host)`` (the systemd ``aegis-receiver@<instance>``
    model); a pushed finding naming any other tenant is rejected (a pusher authenticated for tenant A can
    never land tenant B's record). TOTAL: :meth:`ingest` never raises; a fault is a counted drop/reject."""

    def __init__(self, spool_dir: "str | os.PathLike", *, org_id: str, host: str, report_secret: bytes,
                 verifier: Optional[InboundConnectorVerifier] = None, ingest_connector_id: str = "ingest-hmac",
                 require_mtls_or_hmac: bool = True, max_body_bytes: int = _MAX_BODY_BYTES,
                 max_per_minute: int = _MAX_PER_MINUTE, max_depth: int = 16, max_field_chars: int = 2048,
                 now_fn: Callable[[], float] = time.time, enabled: Optional[bool] = None) -> None:
        if not org_id or not host:
            raise ValueError("a receiver is bound to exactly one tenant (org_id, host)")
        if not isinstance(report_secret, (bytes, bytearray)) or len(report_secret) < 16:
            raise ValueError("a per-(tenant, host) report secret of at least 16 bytes is required (SSM-delivered)")
        self.org_id = str(org_id)
        self.host = str(host)
        self._report_secret = bytes(report_secret)
        self._verifier = verifier
        self._ingest_connector_id = str(ingest_connector_id)
        self._require_auth = bool(require_mtls_or_hmac)
        self._max_body = max(1, int(max_body_bytes))
        self._max_depth = max(1, int(max_depth))
        self._max_field_chars = max(1, int(max_field_chars))
        self._cap = max(1, int(max_per_minute))
        self._now = now_fn
        self._enabled = receiver_enabled() if enabled is None else bool(enabled)
        self._slug = domain_slug(self.org_id, self.host)
        self._incoming = Path(spool_dir) / "incoming" / self._slug
        self._lock = threading.Lock()
        self._window = (0, 0)             # (minute bucket, count) — the per-minute admission cap state
        # Counters (operational only; never on the spine). Read by the health/metrics probe + tests.
        self.spooled = 0
        self.deduped = 0
        self.dropped_oversize = 0
        self.dropped_envelope = 0
        self.dropped_rate = 0
        self.rejected_auth = 0
        self.rejected_malformed = 0
        self.spool_faults = 0
        self.disabled_hits = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    # -- caps / back-pressure (DROP-and-COUNT; NEVER raises; enforce_capable=False => never blocks) ----------
    def _admit_rate(self) -> bool:
        """Per-minute token bucket (mirrors ``monitoring_report.SpoolReporter._admit``). Over cap ⇒ False
        (the caller DROPS-and-counts). Never blocks and never raises — the receiver only accepts + spools."""
        with self._lock:
            bucket = int(self._now() // 60)
            b, n = self._window
            if b != bucket:
                b, n = bucket, 0
            if n >= self._cap:
                self._window = (b, n)
                return False
            self._window = (b, n + 1)
            return True

    # -- auth (fail-closed) --------------------------------------------------------------------------------
    def _authenticate(self, body: bytes, hmac_header: str, mtls_client_verified: bool) -> bool:
        """True iff the inbound request authenticates: a verified mTLS client OR a valid HMAC body signature.
        Fail-closed — any verifier fault, a disabled verifier, or neither credential ⇒ False (never raises;
        the open-plaintext DEFAULT-OFF refusal from the verifier is caught and treated as a non-auth)."""
        if not self._require_auth:
            return True
        if mtls_client_verified and self._verifier is not None:
            try:
                return self._verifier.verify_mtls(
                    org=self.org_id, connector_id="ingest-mtls",
                    mtls_client_verified=True).ok
            except ConnectorBrokerRefused:
                return False
        if mtls_client_verified and self._verifier is None:
            # No verifier wired but the transport asserts a verified client cert: trust the TLS terminator.
            return True
        if hmac_header and self._verifier is not None:
            try:
                return self._verifier.verify_hmac(
                    org=self.org_id, connector_id=self._ingest_connector_id,
                    body=body, presented=hmac_header).ok
            except (ConnectorBrokerDisabled, ConnectorBrokerRefused):
                return False
        return False

    # -- the bounded, hostile-input parse (reuses aegis.boundary) ------------------------------------------
    def _parse_finding(self, body: bytes) -> dict:
        """Strict, bounded, hostile-input parse of the pushed finding into the drain-ready report fields.
        Reuses ``aegis.boundary`` (size/depth bound, strict ``json.loads`` — never eval/pickle, hidden-unicode
        normalisation, ReDoS-safe PII redaction). Raises :class:`BoundaryError`/``ValueError`` on anything
        malformed / schema-invalid / wrong-tenant (the caller maps that to a counted REJECT, never a raise)."""
        import json

        if len(body) > self._max_body:        # defense-in-depth; the hot-path size gate already dropped this
            raise BoundaryError("finding exceeds size cap")
        try:
            data = json.loads(body.decode("utf-8"))          # STRICT safe parse — never eval/pickle
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BoundaryError(f"finding is not valid UTF-8 JSON: {exc}") from None
        if not isinstance(data, dict):
            raise BoundaryError("finding must decode to a JSON object")
        _boundary._check_depth(data, max_depth=self._max_depth)   # bounded nesting (shared boundary primitive)
        if data.get("schema") != INGEST_FINDING_SCHEMA:
            raise BoundaryError("finding is not an ingest-finding envelope of the expected schema")
        org = data.get("org_id")
        host = data.get("host")
        if not isinstance(org, str) or not org or not isinstance(host, str) or not host:
            raise BoundaryError("finding names no tenant/host")
        # TENANT ISOLATION: the pushed finding must name THIS receiver's bound tenant (a pusher authenticated
        # for this tenant cannot land another tenant's record — and the accept-set would reject it anyway).
        if org != self.org_id or host != self.host:
            raise BoundaryError("finding names a different tenant than this receiver is bound to")
        decision = data.get("decision")
        if decision not in _REPORTED_DECISIONS:
            raise BoundaryError("finding decision is not reportable (want confirmed|lead)")
        try:
            ts = _coerce_ts(data.get("ts"))   # float(None|list|dict) raises TypeError, not ValueError
        except (TypeError, ValueError):
            raise BoundaryError("finding ts is missing or not a number") from None
        try:
            confidence = float(data.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            raise BoundaryError("finding confidence is not a number") from None
        if not (math.isfinite(confidence) and 0.0 <= confidence <= 1.0):
            raise BoundaryError("finding confidence must be within [0, 1]")
        cert = data.get("certificate_sha256", "")
        if cert is None:
            cert = ""
        if not isinstance(cert, str):
            raise BoundaryError("finding certificate_sha256 must be a string")
        # Free-text fields are hostile: normalise + length-cap + PII-redact via the boundary (defensive hygiene).
        attack_class = redact_text(str(data.get("attack_class", "")), max_chars=self._max_field_chars)
        provenance = redact_text(str(data.get("provenance_tier", "")), max_chars=self._max_field_chars)
        action = normalize_text(str(data.get("action", "observe") or "observe"), max_chars=self._max_field_chars)
        return {
            "org_id": org, "host": host, "ts": ts, "decision": decision,
            "attack_class": attack_class, "action": action,
            "confidence": round(confidence, 3), "provenance_tier": provenance,
            "certificate_sha256": normalize_text(cert, max_chars=self._max_field_chars),
        }

    def _build_report(self, fields: dict) -> dict:
        """Translate the parsed finding into the v1 monitoring report dict the drain accepts. The ``report_id``
        is a STABLE content digest of the record's own metadata (NOT an RNG token), so a re-POST of the same
        record mints the same id (drain dedup at-most-once) and the sealed envelope is a pure function of the
        record (determinism)."""
        report: dict[str, Any] = {"schema": REPORT_SCHEMA, "org_id": fields["org_id"], "host": fields["host"],
                                  "ts": fields["ts"]}
        for k in _SPOOL_FIELDS:
            report[k] = fields[k]
        report["report_id"] = sha256_hex(canonical_json(report))[:32]   # digest over every field but report_id
        return report

    # -- the one entry point -------------------------------------------------------------------------------
    def ingest(self, body: bytes, *, hmac_header: str = "", mtls_client_verified: bool = False) -> IngestResult:
        """Accept ONE pushed finding. Order: DEFAULT-OFF gate → size cap → rate cap → auth → bounded parse →
        seal → sealed-envelope cap → atomic spool. Every rejection path DROPS-and-COUNTS and returns a
        value-free :class:`IngestResult`; this method NEVER raises into the request path
        (``enforce_capable=False`` — accept + spool only)."""
        if not self._enabled:
            self.disabled_hits += 1
            return IngestResult(IngestOutcome.DISABLED, IngestOutcome.http_status(IngestOutcome.DISABLED),
                                detail="receiver is default-off")
        if not isinstance(body, (bytes, bytearray)):
            self.rejected_malformed += 1
            return IngestResult(IngestOutcome.REJECTED_MALFORMED,
                                IngestOutcome.http_status(IngestOutcome.REJECTED_MALFORMED), detail="body not bytes")
        body = bytes(body)
        if len(body) > self._max_body:
            self.dropped_oversize += 1
            return IngestResult(IngestOutcome.DROPPED_OVERSIZE,
                                IngestOutcome.http_status(IngestOutcome.DROPPED_OVERSIZE), detail="body over size cap")
        if not self._admit_rate():
            self.dropped_rate += 1
            return IngestResult(IngestOutcome.DROPPED_RATE,
                                IngestOutcome.http_status(IngestOutcome.DROPPED_RATE), detail="per-minute cap")
        try:
            authed = self._authenticate(body, hmac_header, mtls_client_verified)
        except Exception:        # noqa: BLE001 — auth must never raise into the request path (fail-closed)
            authed = False
        if not authed:
            self.rejected_auth += 1
            return IngestResult(IngestOutcome.REJECTED_AUTH,
                                IngestOutcome.http_status(IngestOutcome.REJECTED_AUTH), detail="unauthenticated")
        try:
            fields = self._parse_finding(body)
            report = self._build_report(fields)
            env = seal_report(report, self._report_secret)
            data = canonical_json(env)                        # bytes — exactly what lands on disk
        except (BoundaryError, ValueError) as exc:
            self.rejected_malformed += 1
            return IngestResult(IngestOutcome.REJECTED_MALFORMED,
                                IngestOutcome.http_status(IngestOutcome.REJECTED_MALFORMED),
                                detail=f"malformed: {type(exc).__name__}")
        except Exception:        # noqa: BLE001 — a seal/serialise fault is a SERVER fault, never malformed input
            self.spool_faults += 1
            return IngestResult(IngestOutcome.SPOOL_FAULT,
                                IngestOutcome.http_status(IngestOutcome.SPOOL_FAULT), detail="seal fault")
        # The SEALED envelope must fit the drain's file cap. ``seal_report`` canonicalises with
        # ``ensure_ascii=True``, so a body within ``_max_body`` whose free-text fields hold non-ASCII can
        # expand PAST the cap once sealed — and the AS-3c drain permanently QUARANTINES any file over
        # ``_MAX_ENVELOPE_BYTES``. DROP-and-count it here (visible 413) rather than black-holing a record the
        # receiver reported as accepted (mirrors ``monitoring_report.SpoolReporter``'s own envelope guard).
        if len(data) > _MAX_ENVELOPE_BYTES:
            self.dropped_envelope += 1
            return IngestResult(IngestOutcome.DROPPED_ENVELOPE,
                                IngestOutcome.http_status(IngestOutcome.DROPPED_ENVELOPE),
                                detail="sealed envelope over spool cap")
        filename = sha256_hex(data)[:32] + ".json"           # the content-addressed spool name (determinism)
        # A byte-identical re-POST already landed under this content-addressed name — report it as an
        # idempotent no-op (and ``atomic_spool_write`` below leaves the existing file untouched anyway).
        already = (self._incoming / filename).exists()
        try:
            atomic_spool_write(self._incoming, data)         # idempotent: skips if the final name already exists
        except Exception:        # noqa: BLE001 — a spool I/O fault is a transient SERVER fault (retryable), never malformed
            self.spool_faults += 1
            return IngestResult(IngestOutcome.SPOOL_FAULT,
                                IngestOutcome.http_status(IngestOutcome.SPOOL_FAULT), detail="spool fault")
        if already:
            self.deduped += 1
            return IngestResult(IngestOutcome.DEDUP_NOOP, IngestOutcome.http_status(IngestOutcome.DEDUP_NOOP),
                                report_id=report["report_id"], filename=filename)
        self.spooled += 1
        return IngestResult(IngestOutcome.SPOOLED, IngestOutcome.http_status(IngestOutcome.SPOOLED),
                            report_id=report["report_id"], filename=filename)

    def metrics(self) -> dict:
        """A value-free operational snapshot (for the health probe). No tenant content, no secret."""
        return {"org_id": self.org_id, "host": self.host, "enabled": self._enabled, "spooled": self.spooled,
                "deduped": self.deduped, "dropped_oversize": self.dropped_oversize,
                "dropped_envelope": self.dropped_envelope, "dropped_rate": self.dropped_rate,
                "rejected_auth": self.rejected_auth, "rejected_malformed": self.rejected_malformed,
                "spool_faults": self.spool_faults}


# ======================================================================================================
# The thin UNIX-socket HTTP wiring (DEFAULT-OFF: inert, binds no socket). The health probe contract is
# ``unix:/run/aegis-receiver/%i/ingest.sock health`` (GET /health -> 200). POST /ingest -> IngestReceiver.
# The receiver core above is where the logic + tests live; this is runtime glue only.
# ======================================================================================================
class ReceiverServer:
    """A bound UNIX-socket HTTP server in front of an :class:`IngestReceiver`, or (DEFAULT-OFF) an INERT
    object that bound nothing. Kept tiny — correctness of the ingest path is proven against ``IngestReceiver``
    directly, without a socket."""

    def __init__(self, receiver: Optional[IngestReceiver], socket_path: Optional[str], *, bound: bool,
                 httpd: Any = None) -> None:
        self.receiver = receiver
        self.socket_path = socket_path
        self.bound = bound
        self._httpd = httpd

    def serve_forever(self) -> None:
        if self._httpd is None:
            raise ReceiverDisabled("receiver is default-off: no socket bound, nothing to serve")
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()

    def close(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.server_close()
            finally:
                try:
                    if self.socket_path and os.path.exists(self.socket_path):
                        os.unlink(self.socket_path)
                except OSError:
                    pass


def serve_receiver(spool_dir: "str | os.PathLike", *, org_id: str, host: str, report_secret: bytes,
                   socket_path: str, verifier: Optional[InboundConnectorVerifier] = None,
                   enabled: Optional[bool] = None, **receiver_kw: Any) -> ReceiverServer:
    """Build the receiver and, when ARMED, bind a UNIX-socket HTTP front over it. DEFAULT-OFF
    (``VIGIL_AEGIS_RECEIVER`` unset ⇒ ``enabled`` False): bind NO socket and return an INERT
    :class:`ReceiverServer` (``bound=False``) — a disabled receiver never opens a listening socket.

    The HTTP surface: ``GET /health`` → 200 ``ok`` (the fleet health probe), ``POST /ingest`` → the
    :class:`IngestReceiver` (202/4xx per :class:`IngestOutcome`). The HMAC header is read from
    ``INGEST_HMAC_HEADER``; mTLS verification is a transport concern surfaced to the receiver by the TLS
    terminator (not re-implemented here)."""
    armed = receiver_enabled() if enabled is None else bool(enabled)
    receiver = IngestReceiver(spool_dir, org_id=org_id, host=host, report_secret=report_secret,
                              verifier=verifier, enabled=armed, **receiver_kw)
    if not armed:
        return ReceiverServer(receiver, socket_path, bound=False)

    import http.server
    import socketserver

    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 30          # per-connection read timeout: a slow/stalled client cannot pin a thread forever

        def log_message(self, *args: Any) -> None:   # noqa: ARG002 — silence default stderr access log
            pass

        def _send(self, status: int, body: bytes, ctype: str = "text/plain") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def do_GET(self) -> None:          # noqa: N802 — BaseHTTPRequestHandler dispatch name
            if self.path.rstrip("/") in ("/health", "/healthz", "/readyz") or self.path == "health":
                self._send(200, b"ok")
            else:
                self._send(404, b"not found")

        def do_POST(self) -> None:         # noqa: N802
            if self.path.rstrip("/") != "/ingest":
                self._send(404, b"not found")
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            # Read at most max_body + 1 so an over-size body is DROPPED by the receiver's cap (not read whole).
            to_read = min(max(0, length), receiver._max_body + 1)   # noqa: SLF001 — same-module glue
            body = self.rfile.read(to_read) if to_read else b""
            mtls = (self.headers.get("X-Vigil-MTLS-Verified") or "").strip().lower() in ("1", "true", "yes", "on")
            result = receiver.ingest(body, hmac_header=self.headers.get(INGEST_HMAC_HEADER, ""),
                                     mtls_client_verified=mtls)
            self._send(result.http_status, (result.outcome + "\n").encode("utf-8"))

    class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        allow_reuse_address = True

        def get_request(self):            # a UNIX socket has no peer address; synthesise one for the handler
            request, _ = super().get_request()
            return request, ("unix", 0)

    try:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    except OSError:
        pass
    httpd = _UnixHTTPServer(socket_path, _Handler)
    try:
        os.chmod(socket_path, 0o600)
    except OSError:
        pass
    return ReceiverServer(receiver, socket_path, bound=True, httpd=httpd)


# A tiny driver so the cross-plane round-trip can LAND a record via the REAL receiver in a SEPARATE process
# (the two-env boundary: a process that imports BOTH framework.aegis AND sigil.inbound trips the sovereign
# ``assert_no_offense``). Reads one JSON job from argv[1] and prints the IngestResult as JSON.
def _spool_one_cli(argv: "list[str]") -> int:
    """``python -m framework.v2.aegis.receiver <job.json>`` — engine-leg driver for the round-trip test's write leg.
    The job JSON: ``{spool, org_id, host, report_secret_hex, finding, hmac_header?, mtls?}``. Builds a receiver
    (auth OFF unless an hmac/mtls path is exercised by the caller sealing a secret) and lands one finding."""
    import json

    if len(argv) < 2:
        print(json.dumps({"outcome": "error", "detail": "usage: receiver <job.json>"}))
        return 2
    with open(argv[1], "rb") as fh:
        job = json.loads(fh.read().decode("utf-8"))
    rcv = IngestReceiver(job["spool"], org_id=job["org_id"], host=job["host"],
                         report_secret=bytes.fromhex(job["report_secret_hex"]),
                         require_mtls_or_hmac=bool(job.get("require_auth", False)), enabled=True)
    body = json.dumps(job["finding"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    res = rcv.ingest(body, hmac_header=job.get("hmac_header", ""),
                     mtls_client_verified=bool(job.get("mtls", False)))
    print(json.dumps({"outcome": res.outcome, "http_status": res.http_status,
                      "report_id": res.report_id, "filename": res.filename, "detail": res.detail}))
    return 0


if __name__ == "__main__":        # pragma: no cover — exercised as a subprocess by the round-trip test
    import sys

    raise SystemExit(_spool_one_cli(sys.argv))
