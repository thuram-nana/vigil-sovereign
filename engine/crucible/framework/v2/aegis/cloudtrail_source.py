"""framework.v2.aegis.cloudtrail_source — AS-17b: the AWS CloudTrail telemetry SOURCE (provider reader).

AS-17b is a LOG-INGEST / TELEMETRY provider leg, NOT a detection-rule source. It is the ENGINE-leg
reader that stands over the shipped machinery and, when armed, turns a tenant's AWS CloudTrail delivery
into INERT, metadata-only LEAD findings spooled through the AS-9b ingest receiver — observe/LEAD only,
never a block (``enforce_capable=False``, exactly like the receiver it pushes through).

WIRE, DON'T REBUILD — this module COMPOSES merged slices and mints almost nothing of its own:

  * NORMALIZE (the ingest half, PURE/OFFLINE, no flag) — ``defender.logsource.parse_cloudtrail`` turns the
    CloudTrail ``{"Records":[...]}`` envelope (also a single-record object / NDJSON) into normalized
    ``LogEvent``s under AWS' own field names. The normalizer + its gated ``detect_format`` branch are
    additive (byte-identical default path), so they live in ``logsource`` and need NO flag.
  * DETECT (optional) — ``defender.sigma.evaluate_events`` (AS-17a, UNCHANGED) evaluates a CloudTrail
    Sigma ruleset over those events, with the opt-in CloudTrail rows of ``sigma.default_field_map``.
  * AUTHENTICATE the pull (optional, DEFAULT-OFF) — the AS-9a ``ConnectorSecretBroker`` issues a value-free
    handle (reference plane, always safe) and, only when the broker is armed, stamps the per-(org,
    connector) sealed credential onto the OUTBOUND pull request. The AS-17b consumer row is the
    "CloudTrail/provider reader" named in ``connector_secrets``.
  * PUSH — each LEAD finding (the ``receiver.INGEST_FINDING_SCHEMA`` wire shape) is handed to the AS-9b
    ``IngestReceiver.ingest``, which seals + spools the v1 ``{schema, body, mac}`` monitoring envelope the
    sovereign drain consumes. No new spool format is invented.
  * TAMPER-EVIDENCE — the ingested provider record is bound to AS-9c's anchor-1 (producer HMAC keyed by
    the AS-9a per-(org, connector) sealed secret, over the record's canonical bytes); anchor-2 (owner
    spine) is added sovereign-side when the record is appended to the owner-signed chain.

DEFAULT-OFF + FAIL-CLOSED (``VIGIL_AEGIS_CLOUDTRAIL``, strict, mirrors ``VIGIL_AEGIS_RECEIVER`` /
``VIGIL_AEGIS_CONNECTOR_BROKER`` / ``broker.BROKER_ENV`` / ``job_runner.JOBS_ENV``). OFF ⇒ the ACTIVE reader
is INERT: :meth:`CloudTrailSource.ingest_text` / :meth:`ingest_file` pull nothing, read no credential, mint
no anchor, and push NOTHING into the receiver/spool (they return an inert, zero-count result). Credential
materialisation (opening the sealed connector secret — for the outbound pull auth AND for minting anchor-1)
stays INDEPENDENTLY gated by ``VIGIL_AEGIS_CONNECTOR_BROKER``, so an un-armed broker mints no anchor and
reads no credential even when the CloudTrail flag is on. Hostile / oversize input fails closed: the
normalizer is a TOTAL parser (a bad record is skipped, never raised) and the receiver DROPS-and-counts an
over-size / malformed / over-rate push, so :meth:`ingest_text` never raises into its caller.

DETERMINISM on the signed path — every byte the anchor/spool covers is a pure function of the record: the
finding's ``ts`` is derived from the CloudTrail ``eventTime`` (NOT a wall-clock), the ``report_id`` is the
receiver's content digest, the per-record ``seq`` is the input index, and the anchor is HMAC-SHA256 over the
AegisEventV2 canonical bytes. The same CloudTrail bytes map to a byte-identical sealed envelope + anchor.

GATE-INVARIANCE: nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (off the
scan/engage/make-gate path, exactly like ``receiver`` / ``broker`` / ``job_runner``); its tests import it
directly, so ``make gate`` stays byte-identical and no OracleKind/class is added.

FATAL-2: engine leg — imports only ``vigil_core`` (anchors/schemas/sealing), the stdlib, and the sibling
``framework.v2.{defender, aegis}`` DEFENSIVE modules. NEVER ``sigil`` and never an offense/SDK module, so the
module carries zero denied imports and is clean against the AS-28 closure deny-list if it is ever served.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from vigil_core.aegis_anchors import ProducerAnchor, produce_producer_anchor
from vigil_core.aegis_schemas import AegisEventV2
from vigil_core.aegis_sealing import open_secret

from ..defender.logsource import LogEvent, load_log_file, parse_cloudtrail
from ..defender.sigma import SigmaEvalResult, SigmaRule, evaluate_events
from .connector_secrets import (
    ConnectorHandle,
    ConnectorReceipt,
    ConnectorSecretBroker,
    KekSource,
    SealedConnectorStore,
    connector_broker_enabled,
)
from .receiver import INGEST_FINDING_SCHEMA, IngestOutcome, IngestReceiver

__all__ = [
    "CLOUDTRAIL_ENV",
    "CLOUDTRAIL_CONNECTOR_ID",
    "cloudtrail_source_enabled",
    "CloudTrailSourceRefused",
    "CloudTrailLead",
    "CloudTrailIngestResult",
    "CloudTrailSource",
]

# The DEFAULT-OFF switch that ARMS the ACTIVE reader (strict, fail-closed; mirrors ``RECEIVER_ENV`` /
# ``CONNECTOR_BROKER_ENV``). OFF ⇒ the reader pulls nothing, opens no credential, pushes nothing.
CLOUDTRAIL_ENV = "VIGIL_AEGIS_CLOUDTRAIL"

# The AS-9a connector consumer row AS-17b authenticates as (the "CloudTrail/provider reader").
CLOUDTRAIL_CONNECTOR_ID = "cloudtrail-reader"

# The finding carries verdict METADATA only (receiver schema); a CloudTrail record is a LEAD, never a block.
# Typed as the exact ``AegisEventV2`` literals so the anchored record (a signed value object) type-checks.
_LEAD_DECISION: Literal["lead"] = "lead"
_OBSERVE: Literal["observe"] = "observe"
_PROVENANCE_TIER = "intel"            # the AEGIS LEAD-tier provenance (metadata only)
_BASE_CONFIDENCE = 0.2               # a normalized record on its own is a weak LEAD
_SIGMA_CONFIDENCE = 0.5             # a CloudTrail Sigma rule firing raises the LEAD (still not a FACT)
_CLASS_MAX = 80                     # cap the attack-class token length (a clean, bounded metadata token)


def cloudtrail_source_enabled() -> bool:
    """Is the ACTIVE CloudTrail reader ARMED? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative
    token arms it. The PURE offline normalize/evaluate helpers do NOT consult this flag (they open nothing and
    push nothing); only the active pull + receiver-push path does."""
    return (os.environ.get(CLOUDTRAIL_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class CloudTrailSourceRefused(RuntimeError):
    """A fail-closed refusal on the ACTIVE reader path (e.g. an outbound pull/stamp was asked for without a
    wired broker, or while the reader is DEFAULT-OFF). Names no secret bytes and no record content."""


@dataclass(frozen=True)
class CloudTrailLead:
    """The value-free result of ONE normalized CloudTrail record's ingest — safe for a log/report. Carries no
    record content and no secret: only the event index, the receiver ``report_id`` + outcome, the LEAD
    metadata, the firing ATT&CK techniques, and the anchor's non-reversible ``secret_ref`` (or '')."""

    event_index: int
    outcome: str
    report_id: str
    attack_class: str
    confidence: float
    techniques: tuple[str, ...] = ()
    anchor_secret_ref: str = ""


@dataclass
class CloudTrailIngestResult:
    """The outcome of ingesting a CloudTrail delivery. ``enabled`` is False (and every count 0) when the reader
    is DEFAULT-OFF — INERT. ``anchors`` holds the AS-9c producer anchors minted for the spooled records (only
    when the credential-materialisation broker is armed); never carries a credential value."""

    enabled: bool
    normalized: int = 0
    spooled: int = 0
    deduped: int = 0
    rejected: int = 0
    dropped: int = 0
    anchor_errors: int = 0
    leads: list[CloudTrailLead] = field(default_factory=list)
    anchors: list[ProducerAnchor] = field(default_factory=list)
    note: str = ""


def _event_time_to_ts(event: LogEvent) -> float:
    """Derive the finding's ``ts`` from the record's own ``eventTime`` (ISO-8601, e.g.
    ``2024-05-01T12:00:00Z``) — NOT a wall-clock — so the sealed envelope is a PURE function of the record
    (the determinism the signed/spooled path requires). An absent / unparseable time yields ``0.0`` (still a
    pure function of the record). Total: never raises."""
    raw = event.get("eventTime")
    if not isinstance(raw, str) or not raw:
        return 0.0
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return float(dt.timestamp())
    except (OverflowError, OSError, ValueError):
        return 0.0


def _safe_token(value: object, *, max_len: int = _CLASS_MAX) -> str:
    """Reduce an arbitrary (hostile) record value to a bounded, control-free metadata token safe for both the
    receiver finding and the AegisEventV2 ``attack_class`` validator (which rejects any control/format char).
    Keeps only ``[A-Za-z0-9._:/-]`` and bounds the length. Deterministic + total."""
    s = str(value or "")
    out = [c for c in s if c.isalnum() or c in "._:/-"]
    return "".join(out)[:max_len]


class CloudTrailSource:
    """The AS-17b CloudTrail provider reader (engine leg). Bound to exactly ONE tenant via the
    :class:`IngestReceiver` it pushes through (``org_id``/``host``). Composes the shipped slices; mints only
    the LEAD findings and the AS-9c producer anchors.

    Wiring (all optional except ``receiver``):
      * ``broker`` — the AS-9a :class:`ConnectorSecretBroker` for the OUTBOUND CloudTrail pull auth.
      * ``anchor_store`` + ``anchor_kek_source`` — the sealed per-(org, connector) credential custody used to
        open the connector secret and mint anchor-1 (independently gated by ``VIGIL_AEGIS_CONNECTOR_BROKER``).
      * ``sigma_rules`` + ``field_map`` — an optional CloudTrail Sigma ruleset to raise matching records to a
        stronger LEAD (AS-17a ``evaluate_events``; UNCHANGED).
      * ``ingest_hmac_secret`` — when set, the reader signs each push body with the ``INGEST_HMAC_HEADER``
        ``v1=<hmac>`` the receiver verifies (the authenticated-producer path); omit for a receiver wired
        ``require_mtls_or_hmac=False`` (trusted in-process producer)."""

    __slots__ = ("_rcv", "_connector_id", "_broker", "_anchor_store", "_anchor_kek", "_rules", "_field_map",
                 "_ingest_hmac_secret", "_enabled", "_anchor_armed", "org_id", "host")

    def __init__(self, receiver: IngestReceiver, *, connector_id: str = CLOUDTRAIL_CONNECTOR_ID,
                 broker: Optional[ConnectorSecretBroker] = None,
                 anchor_store: Optional[SealedConnectorStore] = None,
                 anchor_kek_source: Optional[KekSource] = None,
                 sigma_rules: Optional[list[SigmaRule]] = None,
                 field_map: Optional[Any] = None,
                 ingest_hmac_secret: Optional[bytes] = None,
                 enabled: Optional[bool] = None,
                 anchor_enabled: Optional[bool] = None) -> None:
        if not isinstance(receiver, IngestReceiver):
            raise CloudTrailSourceRefused("CloudTrailSource requires an IngestReceiver push target")
        self._rcv = receiver
        self.org_id = receiver.org_id
        self.host = receiver.host
        self._connector_id = str(connector_id)
        self._broker = broker
        self._anchor_store = anchor_store
        self._anchor_kek = anchor_kek_source
        self._rules = list(sigma_rules) if sigma_rules else None
        self._field_map = field_map
        self._ingest_hmac_secret = bytes(ingest_hmac_secret) if ingest_hmac_secret else None
        # Read the arm flags ONCE at construction unless pinned (tests pin both legs).
        self._enabled = cloudtrail_source_enabled() if enabled is None else bool(enabled)
        # Credential materialisation (opening the sealed connector secret, for anchor-1 / pull auth) is
        # INDEPENDENTLY gated — the same switch the broker/verifier use. An un-armed broker mints no anchor.
        self._anchor_armed = connector_broker_enabled() if anchor_enabled is None else bool(anchor_enabled)

    @property
    def enabled(self) -> bool:
        return self._enabled

    # --- PURE offline half (always safe; opens nothing; consults no flag) ----------------------------------
    def normalize(self, text: str) -> list[LogEvent]:
        """Normalize a CloudTrail delivery into ``LogEvent``s (``defender.logsource.parse_cloudtrail``). PURE /
        OFFLINE / TOTAL — reaches no network, opens no credential, needs no flag. The additive ingest half."""
        return parse_cloudtrail(text)

    def evaluate(self, events: list[LogEvent]) -> Optional[SigmaEvalResult]:
        """Evaluate the wired CloudTrail Sigma ruleset over ``events`` (AS-17a, UNCHANGED), or None when no
        ruleset is wired. PURE: no network, no flag. The opt-in field map resolves standard CloudTrail Sigma
        field names against the normalized event."""
        if not self._rules:
            return None
        return evaluate_events(self._rules, events, field_map=self._field_map)

    # --- OUTBOUND pull auth (AS-9a broker; reference plane always safe, stamp gated) -----------------------
    def authenticate_pull(self, grant: Any, *, now: datetime,
                          lease_not_after: Optional[datetime] = None) -> ConnectorHandle:
        """Issue a value-FREE :class:`ConnectorHandle` for the outbound CloudTrail pull (the AS-9a broker's
        PURE reference plane — opens no secret, always safe). Fail-closed if no broker is wired."""
        if self._broker is None:
            raise CloudTrailSourceRefused("no connector broker wired for the CloudTrail pull (fail-closed)")
        return self._broker.issue(grant, org=self.org_id, connector_id=self._connector_id, now=now,
                                  lease_not_after=lease_not_after)

    def stamp_pull(self, handle: ConnectorHandle, headers: dict, *, now: datetime,
                   body: bytes = b"") -> ConnectorReceipt:
        """Stamp the sealed CloudTrail credential onto an outbound pull request's ``headers`` (single-use,
        value-free receipt). DEFAULT-OFF: refuses before opening anything when the reader is off OR the broker
        is un-armed — the reader reads NO credential when inert. The broker's own materialisation gate
        (``VIGIL_AEGIS_CONNECTOR_BROKER``) is the independent second lock."""
        if not self._enabled:
            raise CloudTrailSourceRefused(
                f"CloudTrail reader is DEFAULT-OFF ({CLOUDTRAIL_ENV} unset): refusing to read a credential")
        if self._broker is None:
            raise CloudTrailSourceRefused("no connector broker wired for the CloudTrail pull (fail-closed)")
        return self._broker.stamp(handle, headers, now=now, body=body)

    # --- the ACTIVE ingest path (DEFAULT-OFF; the only path that pushes / opens) ----------------------------
    def ingest_text(self, text: str) -> CloudTrailIngestResult:
        """Normalize a CloudTrail delivery, (optionally) Sigma-evaluate it, build INERT LEAD findings and push
        them through the AS-9b receiver (seal + spool), minting AS-9c anchor-1 for each spooled record when the
        credential broker is armed. DEFAULT-OFF ⇒ INERT: returns a zero-count result and pushes nothing. TOTAL:
        a hostile/oversize record is DROPPED-and-counted by the receiver; this method never raises."""
        if not self._enabled:
            return CloudTrailIngestResult(enabled=False, note="cloudtrail reader is default-off")
        return self._ingest_events(self.normalize(text))

    def ingest_file(self, path: str) -> CloudTrailIngestResult:
        """As :meth:`ingest_text`, reading an operator-supplied CloudTrail file through the bounded, graceful
        ``defender.logsource.load_log_file`` (missing/oversized/unreadable ⇒ a clean 'no events' skip, never a
        crash). DEFAULT-OFF ⇒ INERT."""
        if not self._enabled:
            return CloudTrailIngestResult(enabled=False, note="cloudtrail reader is default-off")
        load = load_log_file(path, "cloudtrail")
        if not load.ok:
            return CloudTrailIngestResult(enabled=True, note=load.note)
        return self._ingest_events(load.events)

    def _ingest_events(self, events: list[LogEvent]) -> CloudTrailIngestResult:
        result = CloudTrailIngestResult(enabled=True, normalized=len(events))
        sigma = self.evaluate(events)
        tech_by_index = self._techniques_by_index(sigma)
        for idx, ev in enumerate(events):
            techniques = tech_by_index.get(idx, ())
            attack_class, confidence = self._classify(techniques, matched=idx in tech_by_index)
            finding = self._build_finding(ev, attack_class, confidence, idx)
            body = json.dumps(finding, sort_keys=True, separators=(",", ":")).encode("utf-8")
            hmac_header = ""
            if self._ingest_hmac_secret is not None:
                hmac_header = "v1=" + hmac.new(self._ingest_hmac_secret, body, hashlib.sha256).hexdigest()
            res = self._rcv.ingest(body, hmac_header=hmac_header)
            self._tally(result, res.outcome)
            anchor_ref = ""
            if res.outcome in (IngestOutcome.SPOOLED, IngestOutcome.DEDUP_NOOP):
                anchor = self._mint_anchor(res.report_id, idx, attack_class, confidence)
                if anchor is not None:
                    result.anchors.append(anchor)
                    anchor_ref = anchor.secret_ref
                elif self._anchor_wanted():
                    result.anchor_errors += 1
            result.leads.append(CloudTrailLead(
                event_index=idx, outcome=res.outcome, report_id=res.report_id,
                attack_class=attack_class, confidence=confidence, techniques=tuple(techniques),
                anchor_secret_ref=anchor_ref))
        return result

    # --- helpers -------------------------------------------------------------------------------------------
    @staticmethod
    def _techniques_by_index(sigma: Optional[SigmaEvalResult]) -> dict[int, tuple[str, ...]]:
        """Map each matched event index -> the ATT&CK techniques the firing rule carried (a per-record LEAD
        signal). ``evaluate_events`` records the FIRST event each rule fires on, so a record can accumulate
        techniques from several rules. Deterministic."""
        out: dict[int, list[str]] = {}
        if sigma is None:
            return {}
        for m in sigma.matches:
            bucket = out.setdefault(m.event_index, [])
            for t in m.attack_techniques:
                if t not in bucket:
                    bucket.append(t)
        return {i: tuple(v) for i, v in out.items()}

    def _classify(self, techniques: tuple[str, ...], *, matched: bool) -> tuple[str, float]:
        """The LEAD metadata for one record: a bounded ``attack_class`` token + a confidence. A Sigma hit
        raises the confidence and labels the class with the first ATT&CK technique (else ``cloudtrail-sigma``
        for a technique-less rule); an un-matched record is the weak baseline ``cloudtrail`` LEAD. Always a
        clean, bounded token. ``matched``/``techniques`` come straight from the authoritative
        ``evaluate_events`` match map (a technique-less rule still records a match), so no rule is re-run."""
        if techniques:
            return _safe_token(techniques[0]) or "cloudtrail-sigma", _SIGMA_CONFIDENCE
        if matched:
            return "cloudtrail-sigma", _SIGMA_CONFIDENCE
        return "cloudtrail", _BASE_CONFIDENCE

    @staticmethod
    def _record_identity(ev: LogEvent, seq: int) -> str:
        """A STABLE per-record discriminator so two DISTINCT CloudTrail records never collapse to one spool
        record. Without it the finding body is metadata-only, so two records sharing ``eventTime`` + class
        mint the SAME receiver ``report_id`` (content digest) and the second is silently DEDUP_NOOP'd — and
        records with no parseable ``eventTime`` all carry ``ts=0.0``, so EVERY baseline-class record in a file
        collapses to one. The identity is the record's unique ``eventID`` (when present) PLUS the monotonic
        delivery index as a tiebreaker: the index alone already distinguishes two records (covering a missing
        ``eventID`` AND the ``ts=0.0`` case), while ``eventID`` keeps the id meaningful. PURE/DETERMINISTIC:
        a function of the record's own bytes + its position — the SAME delivery bytes yield the SAME identity,
        so an idempotent re-delivery STILL dedups. ``_safe_token`` bounds it to a clean metadata token."""
        return f"{seq}:{_safe_token(ev.get('eventID'))}"

    def _build_finding(self, ev: LogEvent, attack_class: str, confidence: float, seq: int) -> dict:
        """One INERT, metadata-only LEAD finding in the receiver ``INGEST_FINDING_SCHEMA`` wire shape. PRIVACY
        BY CONSTRUCTION: verdict metadata only — never a record body, path, header, or raw identifier (the
        receiver additionally redacts the free-text fields). ``ts`` is derived from the record (determinism).
        ``record_id`` is the stable per-record discriminator (see :meth:`_record_identity`) the receiver folds
        into ``report_id`` so distinct records produce distinct spool records (no dedup collapse)."""
        return {
            "schema": INGEST_FINDING_SCHEMA,
            "org_id": self.org_id,
            "host": self.host,
            "ts": _event_time_to_ts(ev),
            "decision": _LEAD_DECISION,
            "attack_class": attack_class,
            "action": _OBSERVE,
            "confidence": round(float(confidence), 3),
            "provenance_tier": _PROVENANCE_TIER,
            "certificate_sha256": "",
            "record_id": self._record_identity(ev, seq),
        }

    def _anchor_wanted(self) -> bool:
        """True iff anchor-1 production is both WIRED (store + kek) and ARMED (credential broker on)."""
        return bool(self._anchor_armed and self._anchor_store is not None and self._anchor_kek is not None)

    def _mint_anchor(self, report_id: str, seq: int, attack_class: str,
                     confidence: float) -> Optional[ProducerAnchor]:
        """Mint AS-9c anchor-1 (producer HMAC) for the spooled record, keyed by the opened per-(org, connector)
        sealed secret. Requires the credential broker to be ARMED AND the sealed custody wired — else returns
        None (the finding still spooled; the anchor is the sovereign-side tamper-evidence layer). TOTAL:
        any malformed input / seal fault yields None, never a raise. The opened secret is dropped immediately
        after the HMAC is computed (Python cannot zeroise an immutable ``bytes``; mirrors the broker's noted
        limitation)."""
        if not self._anchor_wanted() or not report_id:
            return None
        try:
            sealed = self._anchor_store.current(self.org_id, self._connector_id)  # type: ignore[union-attr]
            kek = self._anchor_kek.kek_for(self.org_id)                           # type: ignore[union-attr]
            secret = open_secret(kek, sealed)
            record = AegisEventV2(
                org_id=self.org_id, host=self.host, instance_id=self._connector_id,
                epoch=sealed.epoch, seq=seq, decision=_LEAD_DECISION, attack_class=attack_class,
                action=_OBSERVE, confidence=round(float(confidence), 3), provenance_tier=_PROVENANCE_TIER,
                certificate_sha256="", event_id=report_id)
            anchor = produce_producer_anchor(record, org=self.org_id, connector_id=self._connector_id,
                                             epoch=sealed.epoch, secret=secret)
            del secret
            return anchor
        except Exception:        # noqa: BLE001 — anchor minting is best-effort tamper-evidence; never raise
            return None

    @staticmethod
    def _tally(result: CloudTrailIngestResult, outcome: str) -> None:
        if outcome == IngestOutcome.SPOOLED:
            result.spooled += 1
        elif outcome == IngestOutcome.DEDUP_NOOP:
            result.deduped += 1
        elif outcome in (IngestOutcome.DROPPED_OVERSIZE, IngestOutcome.DROPPED_ENVELOPE,
                         IngestOutcome.DROPPED_RATE):
            result.dropped += 1
        else:
            result.rejected += 1
