"""aegis-ingest — the AEGIS AS-9b ingest RECEIVER distribution (hot SPOOL).

The per-tenant inbound endpoint external sensors/providers PUSH inert, metadata-only findings into
(behind caps + authenticated transport), landing each in the hot monitoring SPOOL the AS-3c-hardened
sovereign drain (``sigil.inbound.monitoring_spool.MonitoringSpoolWatcher``) consumes.

This package is the DISTRIBUTION (own packaging / console entrypoint, per FORGE-DOMAIN-MAP: "AEGIS ingest
service — own distribution; caps; HMAC/mTLS"). The engine-plane receiver CORE lives in
``framework.v2.aegis.receiver`` so the AS-28 SaaS-closure deny-list gate (which walks ``framework.v2.aegis``
first-party modules) covers it; this package re-exports it unchanged.

ENGINE LEG (FATAL-2): the core imports ONLY ``vigil_core``, the stdlib, and
``framework.v2.aegis.{boundary, monitoring_report, connector_secrets}`` — NEVER ``sigil``. It is off the
``make gate`` scan/engage/gate path (nothing on that path imports it).
"""
from __future__ import annotations

from framework.v2.aegis.receiver import (
    INGEST_FINDING_SCHEMA,
    INGEST_HMAC_HEADER,
    RECEIVER_ENV,
    IngestOutcome,
    IngestReceiver,
    IngestResult,
    ReceiverDisabled,
    ReceiverServer,
    receiver_enabled,
    serve_receiver,
)

__all__ = [
    "INGEST_FINDING_SCHEMA",
    "INGEST_HMAC_HEADER",
    "RECEIVER_ENV",
    "IngestOutcome",
    "IngestReceiver",
    "IngestResult",
    "ReceiverDisabled",
    "ReceiverServer",
    "receiver_enabled",
    "serve_receiver",
]
