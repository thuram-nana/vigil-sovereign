"""aegis.notify — AS-20 (Wave 7): the OUTBOUND notify / SIEM EMITTER (Domain 5, the connector CONSUMER side).

A tenant's managed defence emits each confirmed/lead verdict to an operator-configured SIEM / notification
channel (Splunk HEC, an API-key SIEM, a signed webhook, a Slack hook). This slice is the OUTBOUND emitter
that CONSUMES the AS-9a connector-secrets broker — it is NOT a detector, adds NO ``OracleKind``, opens NO
customer-facing serve route. It upgrades the crude ``cli._make_webhook_verdict_sink`` precursor (whose auth
was a raw ``AEGIS_VERDICT_WEBHOOK_AUTHORIZATION`` env header) to a BROKER-SEALED credential path.

"Wire, don't rebuild" (plan §9.1 rule 10) — the notifier is GLUE over shipped substrate; no credential
custody, crypto, egress or payload shaping is reinvented here:

  * PAYLOAD — a METADATA-ONLY, HYGIENE-CLEAN notification is built by :func:`.monitoring_event_v2.build_event_v2`
    (deterministic, content-addressed; the AS-2e scrub of raw IP -> ``<ip>`` and canary/secret literal ->
    ``<redacted>`` is applied to every free-text field) and passed through the fail-closed
    :func:`.monitoring_event_v2.is_hygiene_clean` gate before egress — so NO certificate ``oracle_context`` /
    sentinel / raw client IP / actor identity ever leaves the host.
  * AUTH — the outbound POST is authenticated by STAMPING a sealed, rotated, registered connector credential
    via :meth:`.connector_secrets.ConnectorSecretBroker.stamp` (``HMAC_SIGNATURE`` preferred — the secret
    never leaves the broker, only a ``v1=<tag>`` signature over the exact body; ``BEARER`` for Splunk HEC;
    ``HEADER_KEY`` for an API-key SIEM). The notifier holds only a value-free :class:`.connector_secrets.ConnectorHandle`
    issued under an active :class:`~vigil_core.authority_v2.MonitoringAuthorityV2` grant (tenant isolation +
    lease window), NEVER a secret.
  * EGRESS — the sole egress is :func:`.report.push.push_via_urllib`: a bounded, http(s)-only POST with
    redirects DISABLED (no redirect-to-internal SSRF) and a hard timeout, to EXACTLY the operator URL.

TOTAL / FAIL-OPEN on delivery — any build / stamp / push fault (including a notify endpoint 5xx or timeout)
is swallowed and COUNTED (``dropped`` / ``errors`` / ``leaked_dropped``), NEVER raised into the gateway or
data plane. FAIL-CLOSED on every security guard, though: the hygiene gate, the 16 KiB envelope cap, the
broker's CR/LF header-injection guard, a stale/rotated/expired handle, and the SSRF/redirect/non-http(s)
refusal each DROP the notification (no POST) rather than emit something unsafe.

DEFAULT-OFF (strict, fail-closed) behind ``VIGIL_AEGIS_NOTIFY`` (the ``_saas_enforce_flag`` discipline —
only ``1|true|yes|on`` arms it). OFF ⇒ the notifier is INERT: it builds nothing, opens no secret, sends no
outbound request. The credential-materialisation step is ADDITIONALLY gated by the broker's own
``VIGIL_AEGIS_CONNECTOR_BROKER`` (``broker.authorize`` refuses fail-closed BEFORE opening any plaintext when
unset), so an un-armed build never touches a sealed secret.

DETERMINISM — the SIGNED body is a pure function of the verdict + its ``(org, host, instance, epoch, seq)``;
no wall-clock and no global RNG touch the body. The injected ``now`` is used ONLY for lease liveness in
``issue`` / ``stamp``, never in the signed bytes, so the same verdict yields a byte-identical body and a
byte-identical ``v1=<tag>``.

Nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (it is off the gate path,
like ``connector_secrets`` / ``job_runner`` / ``aegis_fleet``), so ``make gate`` stays byte-identical. The
gateway reaches it only via a LAZY import inside ``serve_gateway`` (the AS-3b ``emit_v2`` default-OFF
pattern); its tests import it directly.

FATAL-2: engine plane only — imports ``vigil_core`` (the authority + schema contracts, transitively via the
sibling AEGIS modules), the stdlib, and sibling ``framework.v2`` packages (``.connector_secrets``,
``.monitoring_event_v2``, ``..report.push``). Nothing from ``sigil`` / ``governor``.
"""
from __future__ import annotations

import functools
import itertools
import json
import os
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping, MutableMapping, Optional

from .connector_secrets import (
    ConnectorBrokerRefused,
    ConnectorHandle,
    ConnectorSecretBroker,
)
from .monitoring_event_v2 import build_event_v2, is_hygiene_clean

__all__ = [
    "NOTIFY_ENV",
    "notify_enabled",
    "NOTIFY_SCHEMA",
    "NotifyFormat",
    "notification_body_bytes",
    "build_notification",
    "ConnectorNotifier",
]

# The DEFAULT-OFF arm (strict, fail-closed, DEFAULT OFF — the ``_saas_enforce_flag`` discipline, mirroring
# VIGIL_AEGIS_{FLEET,JOBS,RECEIVER,CONNECTOR_BROKER,BROKER,EDGE}). Only an explicit affirmative token arms the
# notifier; unset / typo / empty keeps it INERT.
NOTIFY_ENV = "VIGIL_AEGIS_NOTIFY"

# The outbound notification envelope schema (metadata-only; see build_notification).
NOTIFY_SCHEMA = "vigil.aegis.notify.v1"

_MAX_ENVELOPE_BYTES = 16 * 1024

# Only confirmed/lead verdicts are notified — the SAME policy as monitoring_report / monitoring_event_v2 (a
# "clear" verdict is "no oracle fired", NOT a monitoring event, and emits NOTHING). Kept in lockstep with the
# emission policy by test_notify.py::test_reported_decisions_match_emission_policy.
_REPORTED_DECISIONS = frozenset({"confirmed", "lead"})


def notify_enabled() -> bool:
    """Is the notify emitter ARMED? Strict, fail-closed, DEFAULT OFF — only ``1|true|yes|on`` arms it. Read
    per construction (tests pin both legs). OFF ⇒ the notifier is inert (builds nothing, opens no secret,
    sends no outbound request)."""
    return (os.environ.get(NOTIFY_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class NotifyFormat(str, Enum):
    """How the operator's channel wants the metadata-only notification shaped.

    * ``WEBHOOK`` — the universal primitive a SIEM / Jira / DefectDojo / custom endpoint accepts: the full
      metadata-only event JSON under a stable envelope.
    * ``SLACK`` — a compact ``{"text": ...}`` message (the same metadata, one human-readable line)."""

    WEBHOOK = "webhook"
    SLACK = "slack"


def _coerce_format(fmt: "NotifyFormat | str") -> NotifyFormat:
    if isinstance(fmt, NotifyFormat):
        return fmt
    try:
        return NotifyFormat(str(fmt).strip().lower())
    except ValueError:
        return NotifyFormat.WEBHOOK


def _decision(verdict: Any) -> str:
    value = getattr(verdict, "decision", "")
    return str(getattr(value, "value", value) or "")


def notification_body_bytes(payload: Mapping[str, Any]) -> bytes:
    """The exact bytes that are both SIGNED (HMAC body) and SENT. This MUST match the serialisation
    :func:`.report.push.push_via_urllib` applies to the payload (``json.dumps(body).encode("utf-8")`` — the
    default separators, ``ensure_ascii=True``), so the ``v1=<tag>`` the broker stamps is a signature over the
    identical bytes the SIEM receives. Deterministic: the payload dict carries a fixed key order (the
    pydantic event field order under a stable envelope), and no sort/RNG is applied. Pinned equal to the
    sender by test_notify.py::test_signed_body_equals_sent_bytes."""
    return json.dumps(dict(payload)).encode("utf-8")


def _slack_text(event_json: Mapping[str, Any]) -> str:
    """A compact, metadata-only Slack line built from the already-scrubbed event fields (no raw content)."""
    return (f"AEGIS verdict: {event_json.get('decision', '?')} / {event_json.get('attack_class', '?')} "
            f"(action={event_json.get('action', '?')}, confidence={event_json.get('confidence', '?')}, "
            f"host={event_json.get('host', '?')})")


def build_notification(verdict: Any, *, org: str, host: str, instance_id: str, epoch: int, seq: int,
                       fmt: "NotifyFormat | str" = NotifyFormat.WEBHOOK,
                       redact_literals: "tuple[str, ...]" = ()) -> dict:
    """Build the METADATA-ONLY, HYGIENE-CLEAN notification payload for a verdict. PURE + DETERMINISTIC — no
    wall-clock, no RNG: the event id is the content digest of the record and ``seq`` is caller-supplied, so
    the same ``(verdict, org, host, instance_id, epoch, seq, fmt)`` yields a byte-identical payload (hence a
    byte-identical signed body). Reuses :func:`.monitoring_event_v2.build_event_v2` (the AS-2b v2 record +
    the AS-2e scrub of raw IP / canary / secret literals), so NO raw oracle_context / sentinel / client IP /
    actor identity is ever shaped into the payload."""
    event = build_event_v2(verdict, org_id=org, host=host, instance_id=instance_id, epoch=max(0, int(epoch)),
                           seq=max(0, int(seq)), redact_literals=redact_literals)
    event_json = event.model_dump(mode="json", by_alias=True)
    if _coerce_format(fmt) is NotifyFormat.SLACK:
        return {"text": _slack_text(event_json)}
    return {"schema": NOTIFY_SCHEMA, "kind": "aegis.verdict", "event": event_json}


class ConnectorNotifier:
    """An ``on_verdict`` sink (same shape as ``monitoring_report.SpoolReporter`` /
    ``monitoring_event_v2.EventV2Reporter``) that pushes each confirmed/lead verdict to an operator SIEM /
    notification channel, authenticated by a broker-sealed connector credential.

    It holds the AS-9a broker, the tenant-bound grant, and the connector id — and, transiently, a value-free
    :class:`~.connector_secrets.ConnectorHandle` it issues under the grant (re-issued when absent or its lease
    has lapsed, and dropped on any broker refusal so the next emit re-issues). It NEVER holds a credential
    value: the broker opens the sealed secret only inside ``stamp`` and clears it onto the outbound headers.

    TOTAL / FAIL-OPEN — ``__call__`` never raises into the gateway: a build / stamp / push fault (a disabled
    broker, a stale handle, a CR/LF credential, a non-http(s) URL, a 5xx, a timeout) is swallowed and COUNTED.
    FAIL-CLOSED on every guard — a "clear" verdict, an un-armed notifier, a hygiene-leaking or oversize
    payload, and any broker refusal each DROP the notification with NO outbound POST."""

    def __init__(self, broker: ConnectorSecretBroker, grant: Any, *, org: str, connector_id: str, host: str,
                 url: str, instance_id: str = "gw", fmt: "NotifyFormat | str" = NotifyFormat.WEBHOOK,
                 epoch_fn: "Callable[[], int]" = lambda: 0, redact_literals: "tuple[str, ...]" = (),
                 send: "Optional[Callable[..., dict]]" = None,
                 now_fn: "Optional[Callable[[], datetime]]" = None,
                 monotonic_fn: Callable[[], float] = time.monotonic,
                 enabled: Optional[bool] = None, lease_seconds: Optional[float] = None,
                 max_per_minute: int = 600, start_seq: int = 1,
                 max_envelope_bytes: int = _MAX_ENVELOPE_BYTES) -> None:
        if not isinstance(broker, ConnectorSecretBroker):
            raise ValueError("ConnectorNotifier requires a ConnectorSecretBroker")
        if not (isinstance(org, str) and org) or not (isinstance(connector_id, str) and connector_id):
            raise ValueError("a notifier is bound to one tenant org and one connector id")
        if not (isinstance(host, str) and host):
            raise ValueError("a notifier is bound to one protected host")
        if not (isinstance(url, str) and url):
            raise ValueError("a notifier needs an operator-configured sink URL")
        self._broker = broker
        self._grant = grant
        self._org = str(org)
        self._conn = str(connector_id)
        self._host = str(host)
        self._instance = str(instance_id)
        self._url = str(url)
        self._fmt = _coerce_format(fmt)
        self._epoch_fn = epoch_fn
        self._redact = tuple(lit for lit in redact_literals if lit)
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic_fn
        self._lease_seconds = lease_seconds
        self._cap = max(1, int(max_per_minute))
        self._max_bytes = max(1, int(max_envelope_bytes))
        # Read the arm ONCE at construction unless pinned (tests pin both legs). OFF ⇒ inert for life.
        self._enabled = notify_enabled() if enabled is None else bool(enabled)
        # Lazy-bind the egress so importing notify.py does not eagerly pull the report stack, and so the FATAL-2
        # AST leg sees only sibling/relative imports. push_via_urllib is the bounded, redirects-disabled, http(s)
        # -only sender — the SSRF/redirect/internal-destination guard lives there (single source of truth).
        if send is not None:
            self._send = send                            # injected test/custom sender — left as-is
        else:
            from ..report.push import push_via_urllib
            # block_internal=True ARMS the fail-closed internal-destination guard for the TENANT egress: a
            # tenant-configured notify-url that points at the shared gateway's own loopback / RFC-1918 / cloud
            # metadata (169.254.169.254) is refused before any POST. The operator report-push path keeps the
            # default (block_internal=False) so it is UNCHANGED.
            self._send = functools.partial(push_via_urllib, block_internal=True)
        # FAIL-CLOSED at construction: a statically-configured sink whose host is an INTERNAL IP LITERAL never
        # arms (a blind-SSRF notify-url like http://169.254.169.254/ or http://127.0.0.1:<port>/ stays inert,
        # it is not even reached). The residual sub-second DNS-REBIND TOCTOU for a *hostname* sink is accepted:
        # the egress guard re-resolves at send, the notify is blind + POST-only, and the HTTP status is counted
        # internally and never reflected to the tenant, so a rebind wins nothing observable.
        if self._enabled:
            from ..report.push import url_host_is_internal_literal
            if url_host_is_internal_literal(self._url):
                self._enabled = False
        self._seq = itertools.count(int(start_seq))
        self._handle: Optional[ConnectorHandle] = None
        self._lock = threading.Lock()
        self._window = (0, 0)          # (minute bucket, count) — operational cap only, never in the body
        self.written = 0               # delivered (2xx)
        self.dropped = 0               # rate-capped
        self.errors = 0                # build/stamp/push faults + non-2xx (fail-open, counted)
        self.leaked_dropped = 0        # dropped by the fail-closed hygiene gate (a raw IP / secret slipped)

    # --- rate cap (operational only) -------------------------------------------------------------
    def _admit(self) -> bool:
        with self._lock:
            bucket = int(self._monotonic() // 60)
            b, n = self._window
            if b != bucket:
                b, n = bucket, 0
            if n >= self._cap:
                self.dropped += 1
                self._window = (b, n)
                return False
            self._window = (b, n + 1)
            return True

    # --- atomic fan-out counters -----------------------------------------------------------------
    def _bump(self, field: str) -> None:
        """Atomically increment one fan-out counter. ``serve_gateway`` fans this sink across threads, so a
        bare ``self.<counter> += 1`` (read-add-write) can lose updates under concurrency. The critical section
        is BRIEF — a single increment — and is NEVER held across the network POST (``self._send``), which would
        serialise the gateway's sink fan-out."""
        with self._lock:
            setattr(self, field, getattr(self, field) + 1)

    # --- value-free handle custody ---------------------------------------------------------------
    def _ensure_handle(self, now: datetime) -> ConnectorHandle:
        """Return a live, value-free handle, issuing a fresh one (pure reference plane) when none is cached or
        the cached lease has lapsed. ``issue`` re-checks the grant (tenant isolation + active window) every
        time it runs, so a revoked/expired grant is refused here, before any secret is touched."""
        handle = self._handle
        if handle is not None and handle.lease_live(now):
            return handle
        lease_not_after = None
        if self._lease_seconds is not None:
            from datetime import timedelta
            lease_not_after = now + timedelta(seconds=float(self._lease_seconds))
        handle = self._broker.issue(self._grant, org=self._org, connector_id=self._conn, now=now,
                                    lease_not_after=lease_not_after)
        self._handle = handle
        return handle

    # --- the on_verdict sink ---------------------------------------------------------------------
    def __call__(self, verdict: Any) -> None:
        try:
            if not self._enabled:
                return                                   # INERT: build nothing, open no secret, no POST
            if verdict is None or _decision(verdict) not in _REPORTED_DECISIONS:
                return                                   # a "clear" verdict emits NOTHING (near-zero spurious)
            if not self._admit():
                return                                   # rate-capped (counted in _admit)
            with self._lock:
                seq = next(self._seq)
            try:
                epoch = int(self._epoch_fn())
            except Exception:                            # noqa: BLE001 — a bad epoch_fn never sinks a notify
                epoch = 0
            payload = build_notification(verdict, org=self._org, host=self._host, instance_id=self._instance,
                                         epoch=max(0, epoch), seq=seq, fmt=self._fmt,
                                         redact_literals=self._redact)
            body = notification_body_bytes(payload)
            # FAIL-CLOSED hygiene gate — DROP (never emit) a body that still carries a raw IP / secret literal.
            # Runs BEFORE any secret is opened, so a leaking payload never touches a sealed credential.
            if not is_hygiene_clean(body.decode("utf-8", "replace"), redact_literals=self._redact):
                with self._lock:                         # atomic pair-bump (brief; never across the POST)
                    self.leaked_dropped += 1
                    self.errors += 1
                return
            # FAIL-CLOSED 16 KiB envelope cap — a runaway payload is dropped, not sent (also pre-secret).
            if len(body) > self._max_bytes:
                self._bump("errors")
                return
            # AUTH — stamp a broker-sealed credential onto the outbound headers (the ONLY place a secret is
            # opened; DEFAULT-OFF via VIGIL_AEGIS_CONNECTOR_BROKER refuses before plaintext when unarmed). A
            # broker refusal (disabled / stale-rotated / expired / CR-LF credential / cross-tenant) drops the
            # cached handle and is counted — no POST.
            headers: MutableMapping[str, str] = {"Content-Type": "application/json"}
            try:
                handle = self._ensure_handle(self._now())
                self._broker.stamp(handle, headers, now=self._now(), body=body)
            except ConnectorBrokerRefused:
                self._handle = None                      # drop a stale/expired/disabled handle -> re-issue next
                self._bump("errors")
                return
            # EGRESS — the sole egress: a bounded, redirects-disabled, http(s)-only POST to EXACTLY self._url.
            res = self._send(self._url, dict(headers), payload)
            status = int(res.get("status", 0)) if isinstance(res, dict) else 0
            if 200 <= status < 300:
                self._bump("written")
            else:
                self._bump("errors")                     # 4xx/5xx — FAIL-OPEN (data plane untouched), counted
        except Exception:                                # noqa: BLE001 — TOTAL: never raise into the data plane
            self._bump("errors")
