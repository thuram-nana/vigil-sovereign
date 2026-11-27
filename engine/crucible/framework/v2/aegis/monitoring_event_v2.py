"""AEGIS AS-3b — v2 EMISSION.

A tenant gateway emits each inspection verdict as an AS-2b ``aegis_event`` **v2** record
(:class:`vigil_core.aegis_schemas.AegisEventV2` — the v2 successor to
:mod:`.monitoring_report`'s ``vigil.aegis.monitoring.v1``), sealed under the same per-(tenant,
host) REPORT secret and spooled for a v2-aware sovereign drain to consume. Three doctrines are
enforced here, not merely documented:

  * **AS-2e OUTPUT HYGIENE** — a raw client IP or a seeded secret (the LLM canary / OOB canary
    sentinels) NEVER reaches an emitted record. Every free-text field (``attack_class``,
    ``provenance_tier``, ``rule_refs``) is scrubbed (IP → ``<ip>``, secret literal →
    ``<redacted>``, email/long-digit PII via :mod:`.boundary`), and a FINAL fail-closed
    assertion over the sealed body DROPS any record that still carries a raw IP or a secret —
    so a leak is never emitted, even if a future field slips the pre-scrub. The record is, as
    in v1, verdict METADATA only: never the path, query, headers, body, client address or actor.

  * **DETERMINISM** — no wall-clock and no RNG in the event BODY or its ORDERING. v1's random
    ``report_id`` + wall-clock ``ts`` are gone: ``seq`` is a caller-supplied MONOTONIC counter
    and ``event_id`` is the content digest of the record, so the same logical event has a stable
    id and two emitters over the same evidence produce byte-identical records.

  * **FAIL-CLOSED** — a malformed / over-size / schema-invalid / hygiene-leaking event is DROPPED
    (counted), never emitted raw; the reporter never raises into the gateway; and the spool write
    is atomic + APPEND-ONLY (content-addressed, never overwriting) via the shared
    :func:`.monitoring_report.atomic_spool_write`.

ADDITIVE + DEFAULT-OFF: nothing here runs unless a tenant gateway opts in (``serve_gateway``'s
``emit_v2`` / ``aegis gateway --emit-v2``). v2 records land in a DISTINCT ``incoming_v2/`` subtree
that the v1 drain (which globs ``incoming/*.json`` / scans ``incoming/<slug>/``) never reads, so
enabling v2 can never regress the v1 drain, and the gate/observe path is byte-unaffected.

FATAL-2: engine plane only — imports ``vigil_core`` (the shared integrity core: the AS-2b schemas
+ canonical bytes) + stdlib + sibling AEGIS modules. No ``sigil``, no governor.
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import ipaddress
import itertools
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from vigil_core.aegis_schemas import EVENT_V2_SCHEMA, AegisEventV2, OutcomeClass, clean_token
from vigil_core.canonical import canonical_json, sha256_hex

from .boundary import redact_text
from .monitoring_report import atomic_spool_write, domain_slug

__all__ = [
    "EVENT_V2_SCHEMA", "EVENT_V2_DOMAIN", "V2_INCOMING",
    "scrub_token", "default_outcome_class", "build_event_v2", "seal_event_v2",
    "is_hygiene_clean", "contains_raw_ip", "EventV2Reporter",
]

# Domain-separation tag for the v2 event MAC. DISTINCT from v1's ``REPORT_DOMAIN`` so a v1 verifier
# can never accept a v2 body (nor the reverse) even if a stray record reaches the wrong drain.
EVENT_V2_DOMAIN = b"vigil.aegis.event.v2\x00"
# The v2 spool subtree. A SIBLING of the v1 ``incoming/`` (NOT under it), so the v1 drain never sees it.
V2_INCOMING = "incoming_v2"
_MAX_ENVELOPE_BYTES = 16 * 1024
# Only confirmed/lead verdicts are reported (same policy as v1 ``monitoring_report``); a ``clear`` verdict is
# "no oracle fired", not a monitoring event. The AegisEventV2 schema itself permits "clear"; we choose not to emit it.
_REPORTED_DECISIONS = frozenset({"confirmed", "lead"})
_MAX_RULE_REFS = 64          # bound the emitted rule-ref set (the schema also caps at 256); DoS-safe.
_TOKEN_CHARS = 128


# --- AS-2e hygiene: IP + secret redaction (ReDoS-safe, bounded) ------------------------------------------
# BOUNDED candidate matchers (fixed, tiny repetition — no backtracking). A candidate is only redacted once it
# PARSES as a real IP, so a benign token like "v1.2.3.4-rule" (not an address) and "2024.11.27" are left intact
# only when they are not valid addresses; a valid dotted-quad / RFC-5952 IPv6 is always caught.
_IPV4_CAND = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IPV6_CAND = re.compile(r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}")


def _iter_ip_spans(s: str) -> "Iterator[tuple[int, int]]":
    """Yield ``(start, end)`` for every substring of ``s`` that PARSES as an IPv4/IPv6 address. The candidate
    regexes are bounded (ReDoS-safe); ``ipaddress`` is the ground truth, so no false positive on a dotted token
    that is not actually an address."""
    for m in _IPV4_CAND.finditer(s):
        try:
            ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        yield m.start(), m.end()
    for m in _IPV6_CAND.finditer(s):
        try:
            ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        yield m.start(), m.end()


def _redact_ips(s: str) -> str:
    spans = sorted(set(_iter_ip_spans(s)))
    if not spans:
        return s
    # Replace right-to-left so earlier offsets stay valid; overlapping/nested spans (an IPv4-mapped IPv6) collapse.
    out = s
    last = len(out)
    for start, end in sorted(spans, reverse=True):
        if end > last:          # skip a span already inside one we replaced (IPv4 tail of an IPv6)
            continue
        out = out[:start] + "<ip>" + out[end:]
        last = start
    return out


def contains_raw_ip(s: str) -> bool:
    """Does ``s`` contain a substring that parses as a raw IPv4/IPv6 address? The fail-closed hygiene check."""
    for _ in _iter_ip_spans(s):
        return True
    return False


def scrub_token(value: Any, *, redact_literals: "tuple[str, ...]" = (), max_len: int = _TOKEN_CHARS) -> str:
    """Hygiene-scrub one free-text token for emission (AS-2e). Normalise + length-cap + redact in-band PII
    (email/long-digit via :func:`.boundary.redact_text`), then redact raw IPs (``<ip>``) and every configured
    secret literal (``<redacted>``). Pure + deterministic."""
    s = redact_text("" if value is None else str(value), max_chars=max_len)   # normalises, strips control chars
    s = _redact_ips(s)
    for lit in redact_literals:
        if lit:
            s = s.replace(lit, "<redacted>")
    return s


def is_hygiene_clean(text: str, *, redact_literals: "tuple[str, ...]" = ()) -> bool:
    """Fail-closed hygiene gate over an about-to-be-emitted record body: True iff it carries NO raw IP and NONE
    of the configured secret literals. The reporter DROPS a record this rejects — a leak is never emitted."""
    for lit in redact_literals:
        if lit and lit in text:
            return False
    return not contains_raw_ip(text)


# --- verdict -> v2 event --------------------------------------------------------------------------------
def _sv(value: Any) -> str:
    """Coerce an enum / str / None to its string VALUE (``KnownBugClass.SQLI`` -> its value), never a repr."""
    if isinstance(value, enum.Enum):
        return str(value.value)
    return "" if value is None else str(value)


def _cert_digest(verdict: Any) -> str:
    """sha256 hex of the verdict's certificate (for a confirmed verdict), else "" — the SAME content id the v1
    report carries, so a v1 and a v2 record of one verdict reference the identical offline-re-runnable proof."""
    cert = getattr(verdict, "certificate", None)
    if cert is None:
        return ""
    try:
        import json
        raw = cert.model_dump_json() if hasattr(cert, "model_dump_json") else json.dumps(cert, default=str)
    except Exception:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def default_outcome_class(verdict: Any) -> "Optional[OutcomeClass]":
    """The HONEST §11.6 outcome label for a verdict, derived from its action — never over-claiming (the §2 K-C13
    overclaim is precisely a response WITHHELD-after-execution relabelled as PREVENTED-before-execution):

      * ``allow`` / ``observe``  -> ``None`` (read-only: no enforcement action was taken — AEGIS's default).
      * ``challenge`` / ``throttle`` -> ``detected_without_enforcement`` (a soft, RETRYABLE signal; nothing was
        hard-stopped, so it is honestly class 5, never a prevention).
      * ``block`` -> ``response_withheld_after_execution`` — the HONEST FLOOR for an inline block. The emission
        sink sees only the ``Verdict`` (not whether the gateway blocked request-side (class 1,
        prevented_before_execution) or withheld response-side (class 3)), so it claims the WEAKER class 3 and
        NEVER the stronger "prevented_before_execution" it cannot verify."""
    action = _sv(getattr(verdict, "action", "observe"))
    if action in ("allow", "observe"):
        return None
    if action in ("challenge", "throttle"):
        return OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT
    if action == "block":
        return OutcomeClass.RESPONSE_WITHHELD_AFTER_EXECUTION
    return None


def _scrub_rule_refs(verdict: Any, *, redact_literals: "tuple[str, ...]") -> "list[str]":
    """The detection rule refs that fired (AS-3b), drawn from the verdict's ``contributing`` oracle/rule names,
    each hygiene-scrubbed. Empty-after-scrub tokens are dropped; the set is bounded. The schema's validator then
    sorts + de-duplicates for a stable digest, so ordering never depends on the verdict's internal list order."""
    raw = getattr(verdict, "contributing", None)
    if not isinstance(raw, (list, tuple)):
        return []
    out: "list[str]" = []
    for item in list(raw)[: _MAX_RULE_REFS * 4]:          # bound the input scan regardless of verdict shape
        tok = scrub_token(item, redact_literals=redact_literals, max_len=64)
        if tok:
            out.append(tok)
        if len(out) >= _MAX_RULE_REFS:
            break
    return out


def build_event_v2(verdict: Any, *, org_id: str, host: str, instance_id: str, epoch: int, seq: int,
                   redact_literals: "tuple[str, ...]" = ()) -> AegisEventV2:
    """Build the AS-2b ``aegis_event`` v2 record for a verdict — METADATA ONLY, HYGIENE-CLEAN, DETERMINISTIC.

    ``event_id`` is the content digest of the record (every field but ``event_id`` itself), so it is caller-
    supplied yet reproducible with no RNG: two emitters over the same ``(verdict, org, host, instance, epoch,
    seq)`` mint the identical id. Every free-text field is scrubbed; the schema's own fail-closed validators
    (``extra='forbid'``, ``clean_token``, closed ``decision``/``action`` literals) reject anything malformed."""
    fields: "dict[str, Any]" = {
        "schema": EVENT_V2_SCHEMA,
        "org_id": str(org_id),
        "host": str(host),
        "instance_id": str(instance_id),
        "epoch": max(0, int(epoch)),
        "seq": max(0, int(seq)),
        "decision": _sv(getattr(verdict, "decision", "")),
        "attack_class": scrub_token(_sv(getattr(verdict, "attack_class", "")), redact_literals=redact_literals),
        "action": _sv(getattr(verdict, "action", "observe")) or "observe",
        "confidence": round(float(getattr(verdict, "confidence", 0.0) or 0.0), 3),
        "provenance_tier": scrub_token(_sv(getattr(verdict, "provenance", "")).split(":", 1)[0],
                                       redact_literals=redact_literals),
        "certificate_sha256": _cert_digest(verdict),
        "rule_refs": _scrub_rule_refs(verdict, redact_literals=redact_literals),
    }
    oc = default_outcome_class(verdict)
    if oc is not None:
        fields["outcome_class"] = oc.value
    # event_id = the content digest of the record (sans event_id). DETERMINISTIC (no RNG, no clock). The AS-2b
    # validators sort/normalise rule_refs + outcome_class, so digest over the normalised fields for stability.
    normalised = AegisEventV2(event_id="placeholderid", **fields).model_dump(mode="json", by_alias=True)
    normalised.pop("event_id", None)
    event_id = sha256_hex(canonical_json(normalised))[:32]
    return AegisEventV2(event_id=event_id, **fields)


def seal_event_v2(event: AegisEventV2, secret: bytes) -> dict:
    """``{schema, body, mac}`` where ``body`` is the event's canonical JSON and
    ``mac = HMAC-SHA256(secret, EVENT_V2_DOMAIN || body)`` — the verifier MACs the exact bytes it parses. The
    secret is the per-(tenant, host) REPORT secret (NOT the deployment/pseudonymisation secret)."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise ValueError("a monitoring report secret of at least 16 bytes is required")
    body = event.canonical_bytes()
    mac = hmac.new(bytes(secret), EVENT_V2_DOMAIN + body, hashlib.sha256).hexdigest()
    return {"schema": EVENT_V2_SCHEMA, "body": body.decode("utf-8"), "mac": mac}


class EventV2Reporter:
    """An ``on_verdict`` sink for a tenant gateway: build + hygiene-scrub + seal + atomically spool each
    confirmed/lead verdict as an AS-2b v2 ``aegis_event`` into ``<spool>/incoming_v2/`` (or, with
    ``strict_domain``, ``<spool>/incoming_v2/<domain_slug>/``). TOTAL — never raises into the gateway; a
    malformed / over-size / HYGIENE-LEAKING event is DROPPED (counted), never emitted raw."""

    def __init__(self, spool_dir: "str | Path", *, org_id: str, host: str, instance_id: str, secret: bytes,
                 epoch_fn: "Callable[[], int]" = lambda: 0, redact_literals: "tuple[str, ...]" = (),
                 max_per_minute: int = 600, now_fn: Callable[[], float] = time.monotonic,
                 strict_domain: bool = False, start_seq: int = 1) -> None:
        if not org_id or not host:
            raise ValueError("a v2 event reporter is bound to one tenant and one host")
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
            raise ValueError("a monitoring report secret of at least 16 bytes is required")
        self.strict_domain = bool(strict_domain)
        base = Path(spool_dir) / V2_INCOMING
        self._incoming = (base / domain_slug(str(org_id), str(host))) if self.strict_domain else base
        self._org, self._host, self._instance = str(org_id), str(host), str(instance_id)
        self._secret = bytes(secret)
        self._epoch_fn = epoch_fn
        self._redact = tuple(lit for lit in redact_literals if lit)
        self._cap = max(1, int(max_per_minute))
        self._now = now_fn
        self._lock = threading.Lock()
        self._window = (0, 0)              # (minute bucket, count) — operational cap only, never in the event body
        self._seq = itertools.count(int(start_seq))
        self.dropped = 0                   # rate-capped
        self.written = 0
        self.errors = 0                    # build/seal/write faults (fail-closed, counted)
        self.leaked_dropped = 0            # records dropped by the final hygiene gate (a raw IP / secret slipped)

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
            if verdict is None or _sv(getattr(verdict, "decision", None)) not in _REPORTED_DECISIONS:
                return
            if not self._admit():
                return
            with self._lock:
                seq = next(self._seq)
            try:
                epoch = int(self._epoch_fn())
            except Exception:
                epoch = 0
            event = build_event_v2(verdict, org_id=self._org, host=self._host, instance_id=self._instance,
                                   epoch=max(0, epoch), seq=seq, redact_literals=self._redact)
            env = seal_event_v2(event, self._secret)
            # FAIL-CLOSED final hygiene gate: assert NO raw IP / secret in the sealed body before it is written.
            if not is_hygiene_clean(env["body"], redact_literals=self._redact):
                self.leaked_dropped += 1
                self.errors += 1
                return
            data = canonical_json(env)
            if len(data) > _MAX_ENVELOPE_BYTES:
                self.errors += 1
                return
            atomic_spool_write(self._incoming, data)
            self.written += 1
        except Exception:
            self.errors += 1          # never raise into the gateway
