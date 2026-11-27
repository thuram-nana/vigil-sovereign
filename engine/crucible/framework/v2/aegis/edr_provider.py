"""aegis.edr_provider — AS-10b: the EDR telemetry PROVIDER / ingest SOURCE (engine plane).

A per-tenant, DEFAULT-OFF defensive worker that PULLs endpoint-detection-&-response (EDR) alerts from a
vendor API (via an AS-9a OUTBOUND connector credential), MAPs each genuine detection into the AS-9b wire
finding ``vigil.aegis.ingest.finding.v1``, mints an AS-9c :class:`~vigil_core.aegis_anchors.ProducerAnchor`
over the canonical AS-2b record for sovereign-side tamper-evidence, PUSHes the finding to the merged AS-9b
:class:`~framework.v2.aegis.receiver.IngestReceiver` over its authenticated transport, and APPENDs an EDR
:class:`~vigil_core.protection_contract.ProviderDescriptor` to the append-only provider registry.

WHY THIS IS A SOURCE, NOT A DETECTOR — the honest floor. EDR is an INTEL-TIER source: it observes/alerts on
an endpoint, it never *prevents*, and it can never mint a re-runnable certificate. So every EDR finding is
``decision="lead"`` with ``certificate_sha256=""`` — NEVER ``"confirmed"`` (no oracle-confirmed certificate
exists). The registered capability is ``outcome_class=detected_without_enforcement`` (class 5) with
``effect_verification=reported`` (K17 — provider-REPORTED, never independently verified). An info / heartbeat
/ benign EDR event maps to NO finding and triggers NO push (the near-zero-FP guarantee for a non-detector).

"Wire, don't rebuild": this slice composes merged machinery and writes little net-new code —
  * AS-9b receiver (``receiver``): the wire schema + HMAC header + ``IngestReceiver.ingest`` push target.
  * AS-9a broker (``connector_secrets``): ``ConnectorSecretBroker.issue``/``stamp`` for the OUTBOUND vendor
    credential and the OUTBOUND ingest-HMAC stamp; ``SealedConnectorStore`` / ``KekSource`` custody for the
    connector secret that keys anchor-1. ``connector_secrets.py`` literally names "an EDR provider (AS-10b)".
  * AS-30 runner (``job_runner``): the per-tenant, fault-isolated ``PerTenantRunner.run_job`` substrate the
    poll rides (deps=[AS-9b, AS-30] — it uses the EXISTING jobs worker-kind; it adds NO fleet WorkerKind).
  * AS-9c anchors (``vigil_core.aegis_anchors``): ``produce_producer_anchor`` mints anchor-1 over the
    canonical bytes of the AS-2b :class:`~vigil_core.aegis_schemas.AegisEventV2` it produces.
  * AS-2b (``vigil_core.aegis_schemas`` / ``vigil_core.protection_contract``): the deterministic metadata
    record + the append-only provider registry (later slices "extend it by APPENDING").
  * ``aegis.boundary``: the hostile-input parse (bounded size/depth, strict ``json.loads`` — never
    eval/pickle), hidden-unicode normalisation, and ReDoS-safe PII/IP redaction.

THREE independent DEFAULT-OFF gates cover the live path (belt-and-suspenders):
  1. ``VIGIL_AEGIS_EDR_PROVIDER`` (:func:`edr_provider_enabled`) — this provider's own gate. OFF ⇒ the poll
     is INERT: it polls nothing, pushes nothing, and opens NO connector secret.
  2. ``VIGIL_AEGIS_JOBS`` — the AS-30 runner the poll executes inside (a disabled runner runs nothing).
  3. ``VIGIL_AEGIS_CONNECTOR_BROKER`` — the AS-9a materialisation gate: a down broker refuses to open any
     plaintext (the vendor stamp, the ingest stamp, AND the anchor-secret open) BEFORE touching a secret.

Nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (it is off the make-gate
path, like ``receiver`` / ``job_runner`` / ``connector_secrets``), so ``make gate`` stays byte-identical and
this slice adds NO OracleKind to ``verify/verifier.py::_ALL_ORACLES``.

FATAL-2: engine leg — imports only ``vigil_core``, the stdlib, and ``framework.v2.aegis`` siblings
(``boundary`` / ``connector_secrets`` / ``job_runner`` / ``receiver``) + ``..common``. NEVER ``sigil``.
"""
from __future__ import annotations

import json
import math
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Protocol, runtime_checkable

from vigil_core.aegis_anchors import ProducerAnchor, produce_producer_anchor, verify_producer_anchor
from vigil_core.aegis_schemas import AegisEventV2, OutcomeClass
from vigil_core.aegis_sealing import SealedSecret, open_secret
from vigil_core.canonical import canonical_json, sha256_hex
from vigil_core.protection_contract import (
    AdapterCapability,
    EffectVerification,
    ProviderDescriptor,
    ProviderRegistry,
)

from ..common.logging import get_logger
from .boundary import BoundaryError, _check_depth, redact_text
from .connector_secrets import (
    CONNECTOR_BROKER_ENV,
    ConnectorBrokerDisabled,
    ConnectorBrokerRefused,
    ConnectorConsumer,
    ConnectorHandle,
    ConnectorScheme,
    ConnectorSecretBroker,
    ConsumerRegistry,
    KekSource,
    SealedConnectorStore,
    connector_broker_enabled,
)
from .job_runner import Job
from .receiver import INGEST_FINDING_SCHEMA, INGEST_HMAC_HEADER, IngestReceiver, IngestResult

_log = get_logger("aegis.edr_provider")

__all__ = [
    "EDR_PROVIDER_ENV",
    "EDR_PROVIDER_ID",
    "EDR_CHANNEL",
    "EDR_DECISION",
    "EDR_PROVENANCE_TIER",
    "edr_provider_enabled",
    "EdrProviderError",
    "EdrProviderDisabled",
    "parse_edr_alert",
    "is_reportable",
    "map_edr_alert",
    "build_canonical_record",
    "EdrAnchorMinter",
    "VendorFetch",
    "StaticVendorFetch",
    "BrokeredVendorFetch",
    "EdrPushClient",
    "receiver_sender",
    "unix_socket_sender",
    "EdrPush",
    "EdrPollResult",
    "EdrPollConfig",
    "EdrPollJob",
    "EDR_PROVIDER",
    "register_edr_provider",
    "edr_vendor_consumer",
    "edr_ingest_consumer",
]

# ==================================================================================================
# DEFAULT-OFF flag (strict, fail-closed; mirrors ``receiver.RECEIVER_ENV`` / ``job_runner.JOBS_ENV`` /
# ``connector_secrets.CONNECTOR_BROKER_ENV``).
# ==================================================================================================
EDR_PROVIDER_ENV = "VIGIL_AEGIS_EDR_PROVIDER"

#: Stable provider id in the AS-2b registry (a safe path component; appended, never a central-enum edit).
EDR_PROVIDER_ID = "edr"
#: The existing defender EDR channel token (``defender.models`` Channel literal) the capability aligns to.
EDR_CHANNEL = "edr_process"
#: EDR findings are ALWAYS leads — EDR is intel-tier and can never mint a re-runnable certificate, so it
#: can never produce a CONFIRMED verdict. This constant IS the decision clamp (see ``map_edr_alert``).
EDR_DECISION = "lead"
#: The provenance tier EDR telemetry carries (intel-tier, never grounded/oracle-confirmed).
EDR_PROVENANCE_TIER = "intel"

_MAX_ALERT_BYTES = 16 * 1024          # the hostile-input vendor-alert size cap (mirrors the receiver body cap)
_MAX_ALERT_DEPTH = 16                 # bounded nesting (shared boundary primitive)
_MAX_LABEL_CHARS = 128                # attack_class label cap (AegisEventV2.clean_token refuses > 128 chars)
_SCORE_REPORTABLE_THRESHOLD = 0.5     # a numeric detection score at/above this is reportable (no severity needed)

# An endpoint/alert event that is TELEMETRY, not a detection — never maps to a finding (near-zero-FP floor).
_NON_DETECTION_TYPES = frozenset({
    "heartbeat", "keepalive", "keep_alive", "status", "health", "healthcheck", "ping",
    "info", "informational", "telemetry", "audit", "inventory",
})
# Severities that are NOT actionable — a benign/info-level alert never maps to a finding. An ABSENT severity
# ("") is deliberately NOT here: it falls through to the score check (whose safe default is "not reportable"),
# so a genuine high-score detection that carries no severity field is not silently dropped.
_BENIGN_SEVERITIES = frozenset({"info", "informational", "benign", "none", "audit", "notice", "debug"})
# Severities that ARE actionable (map straight to a finding).
_ACTIONABLE_SEVERITIES = frozenset({"low", "medium", "moderate", "high", "critical", "severe", "warning"})
# A coarse severity -> confidence floor when the alert carries no numeric score.
_SEVERITY_CONFIDENCE: Mapping[str, float] = {
    "low": 0.4, "warning": 0.5, "medium": 0.6, "moderate": 0.6, "high": 0.85, "critical": 0.95, "severe": 0.95,
}

# Bounded, non-backtracking IP literal matchers (ReDoS-safe: applied only AFTER the label is length-capped).
# The label is hostile free text; an endpoint IP must never survive into the pushed finding (privacy / K-hygiene).
_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")


def edr_provider_enabled() -> bool:
    """Is the EDR provider ARMED? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative token arms
    it. OFF ⇒ the provider is INERT (polls nothing, pushes nothing, opens no connector secret)."""
    return (os.environ.get(EDR_PROVIDER_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class EdrProviderError(ValueError):
    """A fail-closed refusal by the EDR provider (a malformed map/record build, a bad config)."""


class EdrProviderDisabled(RuntimeError):
    """A live EDR action was asked for while the provider is DEFAULT-OFF (``VIGIL_AEGIS_EDR_PROVIDER`` unset).
    Raised before any poll / push / secret-open, so a disabled provider is fully inert."""


# ==================================================================================================
# NORMALIZE + MAP — hostile-input parse (aegis.boundary) then EDR alert -> vigil.aegis.ingest.finding.v1.
# ==================================================================================================
def parse_edr_alert(raw: Any, *, max_bytes: int = _MAX_ALERT_BYTES, max_depth: int = _MAX_ALERT_DEPTH) -> dict:
    """Strict, bounded, hostile-input parse of ONE raw vendor alert into a dict. Reuses ``aegis.boundary``
    discipline (size cap, STRICT ``json.loads`` — never eval/pickle, bounded nesting). Fails closed
    (:class:`BoundaryError`) on oversize / over-depth / malformed / non-object input; the poll DROPS-and-counts
    that, never raising it into the runner's hot path for a single bad alert."""
    if isinstance(raw, (bytes, bytearray)):
        b = bytes(raw)
        if len(b) > max_bytes:
            raise BoundaryError(f"edr alert exceeds size cap ({max_bytes} bytes)")
        try:
            data = json.loads(b.decode("utf-8"))        # STRICT safe parse — never eval/pickle
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BoundaryError(f"edr alert is not valid UTF-8 JSON: {exc}") from None
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > max_bytes:
            raise BoundaryError(f"edr alert exceeds size cap ({max_bytes} bytes)")
        try:
            data = json.loads(raw)                       # STRICT safe parse — never eval/pickle
        except json.JSONDecodeError as exc:
            raise BoundaryError(f"edr alert is not valid JSON: {exc}") from None
    elif isinstance(raw, dict):
        data = raw
        try:
            if len(json.dumps(data).encode("utf-8")) > max_bytes:
                raise BoundaryError(f"edr alert exceeds size cap ({max_bytes} bytes)")
        except (TypeError, ValueError) as exc:
            raise BoundaryError(f"edr alert is not JSON-serialisable: {exc}") from None
    else:
        raise BoundaryError(f"edr alert must be dict / str / bytes, got {type(raw).__name__}")
    if not isinstance(data, dict):
        raise BoundaryError("edr alert must decode to a JSON object")
    _check_depth(data, max_depth=max_depth)              # bounded nesting (shared boundary primitive)
    return data


def _alert_str(alert: Mapping[str, Any], *keys: str) -> str:
    """The first present string-ish value among ``keys`` (lower-cased, stripped), or ''."""
    for k in keys:
        v = alert.get(k)
        if v is not None and not isinstance(v, (dict, list, bool)):
            return str(v).strip().lower()
    return ""


def _coerce_score(alert: Mapping[str, Any]) -> Optional[float]:
    """The alert's detection score coerced to [0, 1], or None if absent/non-numeric. A score > 1 is read as a
    0-100 scale (``/100``). PURE — no clock, no RNG."""
    for k in ("confidence", "score", "risk_score", "severity_score", "detection_score"):
        v = alert.get(k)
        if isinstance(v, bool) or v is None:
            continue
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(f):
            continue
        if f > 1.0:
            f = f / 100.0
        return min(1.0, max(0.0, f))
    return None


def is_reportable(alert: Mapping[str, Any]) -> bool:
    """True iff this EDR event is a GENUINE detection worth a finding. A heartbeat/status/info TYPE or a
    benign/info-level SEVERITY is NOT reportable (maps to no finding / no push — the near-zero-FP guarantee for
    a SOURCE slice). An actionable severity OR a numeric score at/above the threshold is reportable. Fail
    toward NOT pushing on ambiguity. PURE."""
    etype = _alert_str(alert, "type", "event_type", "kind", "category", "class")
    if etype in _NON_DETECTION_TYPES:
        return False
    if alert.get("benign") is True or alert.get("suppressed") is True:
        return False
    sev = _alert_str(alert, "severity", "sev", "level", "priority")
    if sev in _ACTIONABLE_SEVERITIES:
        return True
    if sev in _BENIGN_SEVERITIES:
        return False
    score = _coerce_score(alert)
    return score is not None and score >= _SCORE_REPORTABLE_THRESHOLD


def _sanitize_label(text: str, *, max_chars: int = _MAX_LABEL_CHARS) -> str:
    """Normalise + length-cap + PII/IP-redact a hostile EDR label so it is safe to carry in a finding / record.
    Reuses ``boundary.redact_text`` (hidden-unicode/NFKC normalise + email + long-digit redaction), then
    redacts IP literals and strips any residual control / format / line-separator char (so the token also
    satisfies ``AegisEventV2``'s ``clean_token``). PURE / deterministic — the hygiene guard the negative
    control mutates: SKIP this and a raw IP/PII reaches the pushed finding."""
    s = redact_text(str(text), max_chars=max_chars)
    s = _IPV4.sub("<ip>", s)
    s = _IPV6.sub("<ip>", s)
    cleaned = []
    for ch in s:
        cat = unicodedata.category(ch)
        cleaned.append(" " if (cat[0] == "C" or cat in ("Zl", "Zp")) else ch)
    return "".join(cleaned)[:max_chars]


def _coerce_alert_ts(alert: Mapping[str, Any]) -> float:
    """The event's OWN timestamp as a finite float epoch-seconds — NEVER wallclock (determinism). Accepts a
    numeric epoch, a numeric string, or an ISO-8601 string (a naive datetime is read as UTC, a trailing ``Z``
    honoured). Fails closed (:class:`BoundaryError`) when no coercible timestamp is present — an un-timestamped
    alert is DROPPED rather than stamped with a clock."""
    raw: Any = None
    for k in ("timestamp", "ts", "detected_at", "detection_time", "time", "event_time", "created_at"):
        if alert.get(k) is not None:
            raw = alert.get(k)
            break
    if isinstance(raw, bool) or raw is None:
        raise BoundaryError("edr alert has no coercible timestamp (refusing to stamp with wallclock)")
    if isinstance(raw, (int, float)):
        ts = float(raw)
    elif isinstance(raw, str):
        s = raw.strip()
        try:
            ts = float(s)
        except ValueError:
            try:
                iso = s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s
                dt = datetime.fromisoformat(iso)
            except ValueError:
                raise BoundaryError("edr alert timestamp is not a number or ISO-8601 string") from None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()
    else:
        raise BoundaryError(f"edr alert timestamp must be a number or string, got {type(raw).__name__}")
    if not math.isfinite(ts):
        raise BoundaryError("edr alert timestamp is not finite")
    return ts


def _edr_label(alert: Mapping[str, Any]) -> str:
    """The raw EDR detection label (e.g. 'Ransomware.Encryptor'), from the alert's own naming fields."""
    for k in ("detection_name", "detection", "threat_name", "rule_name", "signature", "name", "title", "category"):
        v = alert.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return "unknown"


def _confidence(alert: Mapping[str, Any]) -> float:
    """The finding confidence in [0, 1], rounded to 3 places (matching the receiver's own rounding so the wire
    finding and the anchored record agree). A numeric score is used directly; else the severity's floor; else a
    conservative 0.5."""
    score = _coerce_score(alert)
    if score is not None:
        return round(score, 3)
    sev = _alert_str(alert, "severity", "sev", "level", "priority")
    return round(_SEVERITY_CONFIDENCE.get(sev, 0.5), 3)


def map_edr_alert(alert: Mapping[str, Any], *, org: str, host: str,
                  max_label_chars: int = _MAX_LABEL_CHARS) -> Optional[dict]:
    """Map one PARSED EDR alert to the AS-9b wire finding ``vigil.aegis.ingest.finding.v1``, or ``None`` when
    the event is not a genuine detection (info / heartbeat / benign ⇒ NO finding). ``org`` / ``host`` are the
    TENANT's managed-monitoring identity (the receiver's bound tenant), NOT the alert's endpoint hostname —
    the endpoint identity is dropped by construction (privacy, and the receiver only accepts its own tenant).

    The decision is ALWAYS :data:`EDR_DECISION` (``"lead"``) with ``certificate_sha256=""`` — EDR is intel-tier
    and can never produce a CONFIRMED verdict (the near-zero-FP clamp the negative control mutates). ``ts`` is
    the alert's OWN timestamp, coerced — never wallclock. PURE / deterministic."""
    if not is_reportable(alert):
        return None
    ts = _coerce_alert_ts(alert)
    attack_class = _sanitize_label(f"edr/{_edr_label(alert)}", max_chars=max_label_chars)
    return {
        "schema": INGEST_FINDING_SCHEMA,
        "org_id": org,
        "host": host,
        "ts": ts,
        "decision": EDR_DECISION,                   # the clamp: EDR is a lead, never a confirmed certificate
        "attack_class": attack_class,
        "action": "observe",                        # EDR observes/alerts; it never enforces
        "confidence": _confidence(alert),
        "certificate_sha256": "",                   # EDR carries no re-runnable certificate
        "provenance_tier": EDR_PROVENANCE_TIER,     # intel-tier
    }


# ==================================================================================================
# ANCHOR — build the canonical AS-2b record + mint the AS-9c anchor-1 over its canonical bytes.
# ==================================================================================================
def _seq_from_ts(ts: float) -> int:
    """A deterministic, non-negative, monotonic-in-time sequence derived from the alert's own epoch seconds —
    NOT a wallclock read and NOT a global RNG/counter (so the same alert yields byte-identical record bytes)."""
    return max(0, int(ts))


def build_canonical_record(finding: Mapping[str, Any], *, instance_id: str, epoch: int) -> AegisEventV2:
    """Build the metadata-only AS-2b :class:`AegisEventV2` the anchor signs, from a mapped EDR finding. The
    ``event_id`` is a DETERMINISTIC content digest of the record's own identifying metadata (``"edr-" +
    sha256(core)[:32]``), so the same EDR alert yields byte-identical record bytes + anchor tag. The honest
    §11.6 label is ``detected_without_enforcement`` (class 5) and the decision is clamped to a lead. PURE."""
    org = str(finding["org_id"])
    host = str(finding["host"])
    attack_class = str(finding.get("attack_class", ""))
    provenance = str(finding.get("provenance_tier", EDR_PROVENANCE_TIER))
    confidence = float(finding.get("confidence", 0.0) or 0.0)
    seq = _seq_from_ts(float(finding["ts"]))
    core = {
        "org_id": org, "host": host, "instance_id": instance_id, "epoch": int(epoch), "seq": seq,
        "decision": EDR_DECISION, "attack_class": attack_class, "action": "observe",
        "confidence": confidence, "provenance_tier": provenance,
        "outcome_class": OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT.value,
    }
    event_id = "edr-" + sha256_hex(canonical_json(core))[:32]
    try:
        return AegisEventV2(
            org_id=org, host=host, instance_id=instance_id, epoch=int(epoch), seq=seq,
            decision=EDR_DECISION, attack_class=attack_class, action="observe", confidence=confidence,
            provenance_tier=provenance, certificate_sha256="",
            outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT, rule_refs=[], event_id=event_id,
        )
    except Exception as exc:  # noqa: BLE001 — a schema-invalid record is a fail-closed refusal, never a crash
        raise EdrProviderError(f"could not build the canonical EDR record: {exc}") from exc


class EdrAnchorMinter:
    """Mints AS-9c anchor-1 over the canonical bytes of an EDR record, keyed by the AS-9a sealed CONNECTOR
    secret for the anchor connector. It OPENS the sealed secret transiently under the org KEK (the AS-2h
    custody the broker uses), mints via :func:`produce_producer_anchor`, and ZEROISES the plaintext — the
    anchor it returns is value-free (just the one-way HMAC tag). DEFAULT-OFF + fail-closed on the open path,
    sharing the broker's ``VIGIL_AEGIS_CONNECTOR_BROKER`` gate (opening a sealed secret to anchor is the same
    plaintext-touching act the broker gates): un-armed, it refuses BEFORE any open."""

    __slots__ = ("_store", "_kek", "_enabled")

    def __init__(self, store: SealedConnectorStore, kek_source: KekSource, *,
                 enabled: Optional[bool] = None) -> None:
        if not isinstance(store, SealedConnectorStore):
            raise EdrProviderError("store must be a SealedConnectorStore")
        if not isinstance(kek_source, KekSource):
            raise EdrProviderError("kek_source must implement the KekSource protocol")
        self._store = store
        self._kek = kek_source
        self._enabled = connector_broker_enabled() if enabled is None else bool(enabled)

    def current_epoch(self, org: str, connector_id: str) -> int:
        """The current sealed epoch for the anchor connector (reads no plaintext; fail-closed if none sealed)."""
        return self._store.current(org, connector_id).epoch

    def mint(self, record: AegisEventV2, *, org: str, connector_id: str) -> ProducerAnchor:
        """Open the current sealed connector secret transiently, mint anchor-1 over ``record``'s canonical
        bytes, zeroise the plaintext, and return the value-free :class:`ProducerAnchor`. Fail-closed: refuse
        BEFORE any open when un-armed (``ConnectorBrokerDisabled``)."""
        if not self._enabled:
            raise ConnectorBrokerDisabled(
                f"EDR anchor minter is DEFAULT-OFF ({CONNECTOR_BROKER_ENV} unset): refusing to open the anchor "
                f"secret for {connector_id!r} (no plaintext touched)")
        sealed = self._store.current(org, connector_id)
        kek = self._kek.kek_for(org)
        plain = bytearray()
        try:
            plain += open_secret(kek, sealed)
            anchor = produce_producer_anchor(record, org=org, connector_id=connector_id,
                                             epoch=sealed.epoch, secret=bytes(plain))
        finally:
            for i in range(len(plain)):
                plain[i] = 0
            del plain
        return anchor


# ==================================================================================================
# POLL — the vendor fetch (OUTBOUND connector) and the PUSH (OUTBOUND ingest HMAC -> IngestReceiver).
# ==================================================================================================
@runtime_checkable
class VendorFetch(Protocol):
    """The seam that fetches raw EDR vendor alerts for one tenant. Injected so the poll is tested offline with
    a canned source and run in production against a BROKERED outbound credential."""

    def fetch(self) -> list[Any]: ...


@dataclass(frozen=True)
class StaticVendorFetch:
    """A fixed, offline vendor source (test / replay): returns a pre-supplied list of raw alerts. Opens no
    connector and touches no network — the no-op floor."""

    alerts: list[Any]

    def fetch(self) -> list[Any]:
        return list(self.alerts)


class BrokeredVendorFetch:
    """Fetch EDR vendor alerts over an AS-9a OUTBOUND connector credential. Each fetch STAMPs the vendor
    connector's auth (BEARER / HEADER_KEY / HMAC_SIGNATURE) onto a fresh outbound header map via
    ``ConnectorSecretBroker.stamp`` — which opens plaintext ONLY when the broker is armed
    (``VIGIL_AEGIS_CONNECTOR_BROKER``), refusing with :class:`ConnectorBrokerDisabled` BEFORE any open when it
    is not — then calls the injected ``transport`` with the stamped headers. ``transport`` performs the actual
    (gated-egress) HTTP GET and returns the raw alert list; it is injected so no socket lives in this core."""

    __slots__ = ("_broker", "_handle", "_now", "_transport", "_body")

    def __init__(self, *, broker: ConnectorSecretBroker, handle: ConnectorHandle, now: datetime,
                 transport: Callable[[Mapping[str, str]], list[Any]], body: bytes = b"") -> None:
        self._broker = broker
        self._handle = handle
        self._now = now
        self._transport = transport
        self._body = body

    def fetch(self) -> list[Any]:
        headers: dict[str, str] = {}
        self._broker.stamp(self._handle, headers, now=self._now, body=self._body)
        return self._transport(headers)


@dataclass(frozen=True)
class EdrPush:
    """The record of one mapped+anchored+pushed EDR detection (value-free w.r.t. secrets)."""

    finding: dict
    record: AegisEventV2
    anchor: ProducerAnchor
    result: Any                      # the transport result (an IngestResult for the direct-receiver sender)


class EdrPushClient:
    """Pushes a mapped finding to the AS-9b receiver over its authenticated transport. It stamps the ingest
    HMAC header (``receiver.INGEST_HMAC_HEADER`` = ``v1=<hmac-sha256 over the raw body>``) via the broker's
    OUTBOUND ``ConnectorAuth.apply`` over the EXACT canonical body bytes, then delivers those same bytes +
    headers through the injected ``sender``. Correctness is proven against ``IngestReceiver.ingest`` directly
    (``receiver_sender``); production uses ``unix_socket_sender``."""

    __slots__ = ("_broker", "_handle", "_now", "_sender")

    def __init__(self, *, broker: ConnectorSecretBroker, handle: ConnectorHandle, now: datetime,
                 sender: Callable[[bytes, Mapping[str, str]], Any]) -> None:
        self._broker = broker
        self._handle = handle
        self._now = now
        self._sender = sender

    @staticmethod
    def wire_bytes(finding: Mapping[str, Any]) -> bytes:
        """The canonical wire bytes of a finding — deterministic (sorted keys, compact), so the stamped HMAC is
        over EXACTLY the bytes the receiver verifies + seals, and the content-addressed spool name is stable."""
        return json.dumps(finding, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def push(self, finding: Mapping[str, Any]) -> Any:
        """Serialise ``finding`` canonically, stamp the ingest HMAC over those exact bytes, and deliver. The
        credential value touches only the outbound header map and is cleared immediately (single-use
        ``ConnectorAuth``). Returns the sender's result (an :class:`IngestResult` for the direct sender)."""
        body = self.wire_bytes(finding)
        headers: dict[str, str] = {}
        self._broker.stamp(self._handle, headers, now=self._now, body=body)
        return self._sender(body, headers)


def receiver_sender(receiver: IngestReceiver) -> Callable[[bytes, Mapping[str, str]], IngestResult]:
    """A :class:`EdrPushClient` sender that drives a local :class:`IngestReceiver.ingest` directly (no socket) —
    the exact correctness-proof seam the receiver's own tests use."""

    def _send(body: bytes, headers: Mapping[str, str]) -> IngestResult:
        return receiver.ingest(bytes(body), hmac_header=headers.get(INGEST_HMAC_HEADER, ""))

    return _send


def unix_socket_sender(socket_path: str, *, path: str = "/ingest",
                       timeout: float = 30.0) -> Callable[[bytes, Mapping[str, str]], int]:
    """A production :class:`EdrPushClient` sender that POSTs the finding to the receiver's UNIX-socket
    ``/ingest`` and returns the HTTP status. Kept thin — correctness is proven against the receiver core via
    :func:`receiver_sender`; this is runtime glue only."""

    def _send(body: bytes, headers: Mapping[str, str]) -> int:
        import socket

        payload = bytes(body)
        head = [f"POST {path} HTTP/1.1", "Host: unix", "Connection: close",
                "Content-Type: application/json", f"Content-Length: {len(payload)}"]
        for name, value in headers.items():
            head.append(f"{name}: {value}")
        raw = ("\r\n".join(head) + "\r\n\r\n").encode("utf-8") + payload
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(socket_path)
            sock.sendall(raw)
            first = sock.recv(4096)
        finally:
            sock.close()
        try:
            return int(first.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return 0

    return _send


# ==================================================================================================
# The AS-30 poll JOB body — runs inside ``PerTenantRunner.run_job``; fault-contained per tenant.
# ==================================================================================================
@dataclass(frozen=True)
class EdrPollConfig:
    """Per-tenant poll configuration. ``anchor_connector_id`` names the AS-9a connector whose sealed secret
    keys anchor-1; ``instance_id`` is the emitting instance id (a safe path component)."""

    org: str
    host: str
    instance_id: str
    anchor_connector_id: str


@dataclass
class EdrPollResult:
    """The accumulated outcome of one poll run — value-free w.r.t. secrets. ``pushed`` is the mapped+anchored+
    delivered detections; ``skipped`` counts benign/heartbeat events that produced no finding; ``dropped``
    counts drop-class records (hostile/oversize input the boundary parse rejected, OR a reportable alert that
    carries no coercible timestamp / sanitisable label — a data fault the map path refuses to stamp); ``errors``
    counts genuine per-record faults that were contained so the batch continued (never a systemic fault, which
    fails the whole job). ``dropped``/``errors`` are the batch-resilience counters: a single bad record is
    counted here and the loop moves on — it is NEVER allowed to abort the batch."""

    tenant: str
    enabled: bool = True
    pushed: list[EdrPush] = field(default_factory=list)
    skipped: int = 0
    dropped: int = 0
    errors: int = 0

    @property
    def push_count(self) -> int:
        return len(self.pushed)


class EdrPollJob:
    """The ``EdrPollJob`` body that runs inside :meth:`PerTenantRunner.run_job`. It fetches EDR vendor alerts,
    parses each through the boundary (drop-and-count hostile input), maps genuine detections to findings (skip
    benign/heartbeat), builds the canonical record, mints anchor-1, and pushes to the receiver.

    BATCH-RESILIENT: every record is processed under a per-record guard — a single malformed / un-stampable /
    faulting alert is dropped-or-errored-and-counted and the loop CONTINUES, so one bad record never loses the
    genuine detections ordered after it in the same batch (the map-path guarantee "a single bad alert never
    raises into the runner's hot path" holds end-to-end, not just at the parse boundary).

    DEFAULT-OFF: with the provider flag off the job is INERT — :meth:`execute` fetches nothing, pushes nothing,
    and opens no connector secret (the vendor fetch and the anchor minter are never touched). A SYSTEMIC fault
    (the vendor fetch, or a down broker / ingest transport that fails every record this cycle) PROPAGATES to the
    runner, which CONTAINS it (that tenant's job goes FAILED, degrading no other tenant) — the poll never has to
    catch it itself."""

    __slots__ = ("_fetch", "_push", "_minter", "_cfg", "_enabled", "_result")

    def __init__(self, *, fetch: VendorFetch, push: EdrPushClient, minter: EdrAnchorMinter,
                 config: EdrPollConfig, enabled: Optional[bool] = None) -> None:
        self._fetch = fetch
        self._push = push
        self._minter = minter
        self._cfg = config
        self._enabled = edr_provider_enabled() if enabled is None else bool(enabled)
        self._result = EdrPollResult(tenant=config.org, enabled=self._enabled)

    @property
    def result(self) -> EdrPollResult:
        """The accumulated result of the last :meth:`execute` (readable even after a contained vendor fault)."""
        return self._result

    def execute(self, job: Job) -> EdrPollResult:  # noqa: ARG002 — the runner passes the Job; the poll is tenant-driven
        """The ``execute`` callable :meth:`PerTenantRunner.run_job` drives. INERT when the provider flag is off
        (no fetch, no push, no secret open). Accumulates results on :attr:`result`. Per-record RESILIENT: a
        single malformed / un-stampable / faulting alert is dropped-or-errored-and-counted and the batch goes
        on — one bad record NEVER aborts the others. May raise a SYSTEMIC fault (the vendor fetch, or a down
        broker / ingest transport that fails every record), which the runner contains (degrading ONLY this
        tenant); a single record's DATA fault is never allowed to raise into that hot path."""
        res = EdrPollResult(tenant=self._cfg.org, enabled=self._enabled)
        self._result = res
        if not self._enabled:
            return res                                   # DEFAULT-OFF: fully inert
        epoch = self._minter.current_epoch(self._cfg.org, self._cfg.anchor_connector_id)
        for raw in self._fetch.fetch():                  # a vendor fault here propagates -> runner contains it
            try:
                alert = parse_edr_alert(raw)
            except BoundaryError:
                res.dropped += 1                         # hostile/oversize alert — drop-and-count, never raise
                continue
            # Per-record processing is RESILIENT: the map / build / mint / push of ONE record is guarded so a
            # single malformed or un-stampable alert is dropped-or-errored-and-counted and the loop CONTINUES —
            # a single record's data fault NEVER aborts the batch (honours the map-path guarantee "a single bad
            # alert never raises into the runner's hot path"). Only a SYSTEMIC fault (broker/custody or ingest
            # transport down — the same for every record this cycle) propagates, failing ONLY this tenant's job.
            try:
                finding = map_edr_alert(alert, org=self._cfg.org, host=self._cfg.host)
                if finding is None:
                    res.skipped += 1                     # benign / heartbeat / info — NO finding, NO push
                    continue
                record = build_canonical_record(finding, instance_id=self._cfg.instance_id, epoch=epoch)
                anchor = self._minter.mint(record, org=self._cfg.org, connector_id=self._cfg.anchor_connector_id)
                result = self._push.push(finding)
            except BoundaryError:
                res.dropped += 1                         # reportable but un-stampable (no coercible ts) / un-sanitisable label — DROP, never abort
                continue
            except (ConnectorBrokerRefused, OSError):
                raise                                    # SYSTEMIC (broker/custody or ingest transport down) — fail THIS tenant's job, don't mask per-record
            except Exception:  # noqa: BLE001 — a single record's data fault must NEVER raise into the runner's hot path
                res.errors += 1                          # genuine per-record fault — count and CONTINUE to the next record
                continue
            res.pushed.append(EdrPush(finding=finding, record=record, anchor=anchor, result=result))
        return res

    def as_execute(self) -> Callable[[Job], object]:
        """The bound ``execute`` callable, typed for :meth:`PerTenantRunner.run_job`."""
        return self.execute


# ==================================================================================================
# REGISTER — the append-only EDR ProviderDescriptor + the EDR ConnectorConsumer factories.
# ==================================================================================================
#: The EDR provider descriptor appended to the AS-2b registry: an endpoint-detection telemetry SOURCE that
#: OBSERVES/ALERTS only (``detected_without_enforcement`` — class 5), and whose effect is provider-REPORTED
#: (K17), never independently verified. The honest floor for a telemetry source — it never prevents.
EDR_PROVIDER: ProviderDescriptor = ProviderDescriptor(
    provider_id=EDR_PROVIDER_ID,
    title="EDR endpoint-detection telemetry",
    capabilities=[
        AdapterCapability(kind=EDR_CHANNEL, outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
                          effect_verification=EffectVerification.REPORTED),
    ],
)


def register_edr_provider(registry: ProviderRegistry) -> ProviderRegistry:
    """APPEND the EDR provider to ``registry`` (returns a NEW registry; the baseline is never edited). This is
    the append-only extension doctrine — ``baseline_provider_registry().register(EDR_PROVIDER)`` — not a
    central-enum edit of ``protection_contract.py``."""
    return registry.register(EDR_PROVIDER)


def edr_vendor_consumer(org: str, connector_id: str, scheme: ConnectorScheme,
                        header_name: str) -> ConnectorConsumer:
    """The OUTBOUND vendor-API connector consumer to register in a :class:`ConsumerRegistry` (runtime config,
    not a central-enum edit). ``connector_id`` is e.g. ``"edr-<vendor>"``; ``scheme`` is how the vendor API
    authenticates the outbound pull (BEARER / HEADER_KEY / HMAC_SIGNATURE)."""
    return ConnectorConsumer(org=org, connector_id=connector_id, scheme=scheme, header_name=header_name)


def edr_ingest_consumer(org: str, *, connector_id: str = "ingest-hmac") -> ConnectorConsumer:
    """The OUTBOUND ingest-push connector consumer (HMAC_SIGNATURE over the body into the receiver's ingest
    HMAC header). The SAME ``(org, connector_id)`` sealed secret the AS-9b receiver's verifier holds, so the
    stamped tag verifies at the receiver."""
    return ConnectorConsumer(org=org, connector_id=connector_id, scheme=ConnectorScheme.HMAC_SIGNATURE,
                             header_name=INGEST_HMAC_HEADER)


# ==================================================================================================
# The ``python -m framework.v2.aegis.edr_provider`` entrypoint — the SEPARATE-PROCESS write leg of the
# cross-plane round-trip (mirrors ``receiver._spool_one_cli``). A process that imports BOTH framework.aegis
# AND sigil.inbound trips the sovereign ``assert_no_offense``, so the engine write leg runs standalone here.
# It maps ONE alert, builds the record, mints anchor-1 over the raw anchor secret, and lands the finding via
# the REAL receiver, printing a value-free result (incl. the anchor tag so the caller can re-verify it).
# ==================================================================================================
def _run_cli(argv: "list[str]") -> int:
    """``python -m framework.v2.aegis.edr_provider <job.json>`` — the engine-leg driver for the round-trip
    write leg. Job JSON: ``{spool, org_id, host, instance_id, report_secret_hex, anchor_connector_id,
    anchor_secret_hex, anchor_epoch, alert}``. Builds an armed receiver (auth OFF — the HMAC path is covered
    in-process), maps+anchors+lands one alert, and prints the result as JSON on the last line."""
    if len(argv) < 2:
        print(json.dumps({"outcome": "error", "detail": "usage: edr_provider <job.json>"}))
        return 2
    with open(argv[1], "rb") as fh:
        job = json.loads(fh.read().decode("utf-8"))
    org, host = job["org_id"], job["host"]
    alert = parse_edr_alert(job["alert"])
    finding = map_edr_alert(alert, org=org, host=host)
    if finding is None:
        print(json.dumps({"outcome": "no_finding", "detail": "alert is benign/heartbeat — no finding mapped"}))
        return 0
    epoch = int(job.get("anchor_epoch", 1))
    record = build_canonical_record(finding, instance_id=job["instance_id"], epoch=epoch)
    anchor_secret = bytes.fromhex(job["anchor_secret_hex"])
    anchor = produce_producer_anchor(record, org=org, connector_id=job["anchor_connector_id"], epoch=epoch,
                                     secret=anchor_secret)
    # Self-verify the anchor in THIS engine-leg process; the secret and the anchor tag never leave it. The
    # caller re-derives the anchor itself from the known secret, so stdout carries no secret-derived material.
    anchor_ok, _ = verify_producer_anchor(record, anchor, secret=anchor_secret)
    receiver = IngestReceiver(job["spool"], org_id=org, host=host,
                              report_secret=bytes.fromhex(job["report_secret_hex"]),
                              require_mtls_or_hmac=False, enabled=True)
    body = EdrPushClient.wire_bytes(finding)
    res = receiver.ingest(body)
    print(json.dumps({
        "outcome": res.outcome, "http_status": res.http_status, "report_id": res.report_id,
        "filename": res.filename, "detail": res.detail, "event_id": record.event_id,
        "record_digest": record.digest(), "anchor_verified": bool(anchor_ok),
        "anchor_connector_id": anchor.connector_id, "anchor_epoch": anchor.epoch,
    }))
    return 0


if __name__ == "__main__":        # pragma: no cover — exercised as a subprocess by the round-trip test
    import sys

    raise SystemExit(_run_cli(sys.argv))
