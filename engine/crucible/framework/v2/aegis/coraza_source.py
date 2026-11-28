"""aegis.coraza_source — AS-7b: the Coraza/CRS front-WAF supply-chain attestation + typed ``rule_refs`` lead admission.

The deployed AEGIS edge runs a **Caddy front + Coraza v3 in DetectionOnly mode** over the OWASP Core Rule Set
(CRS 4.x). Per doctrine (ADR 0003, plan §9.4): *a CRS hit is recorded as a LEAD in typed ``rule_refs``, never as a
standalone block* — the leads-not-blocks stance that keeps a third-party rule engine inside prove-don't-guess, so a
CRS or Sigma hit raises suspicion but NEVER alone produces a block. Only a fired AEGIS oracle blocks.

Coraza + CRS are THIRD-PARTY detection content, so admitting their hits is a SUPPLY-CHAIN concern, which is exactly
what AS-7b adds and nothing more. It composes the two SC gates already in the tree:

  * AS-7a LICENCE GATE (``license_gate.LicenseGate`` / §7 ``license_policy``) — is the front-WAF detection stack
    (the ``coraza-v3`` engine + the ``coreruleset-crs-4x`` rule corpus) LICENCE-ADMITTED for SERVICE use? A missing,
    inconsistent or policy-denied §7 record fails closed (``licensed = False``). AS-7b reaches this gate by RELATIVE
    import and NEVER re-implements it (it is the chain verifier analog here).
  * AS-28-style CORPUS PIN — is the CRS rule corpus PINNED to a known digest? ``corpus_pin`` is a deterministic
    sha256 over the corpus's canonical pin-bearing fields (version · paranoia · the sorted rule-id set). If a rule
    is added, removed or re-tagged, the pin moves and ``pinned`` goes False — tamper-evidence for the rule content,
    the same shrink-only discipline AS-28 applies to the import closure, computed with the STDLIB only (a separate
    corpus pin, not the AS-7a ledger digest and not the AS-28 import graph).

``admissible = licensed AND pinned``. A Coraza DetectionOnly hit's ``rule_refs`` are admitted as LEADS only when the
corpus is admissible; over an UNLICENSED or UNPINNED corpus the refs are DROPPED (fail closed) — untrusted or
unverified third-party rule content can never raise belief. Admitted refs are a LEAD only (the pipeline seeds the
benign-twin SCE weakly and keeps it live); AS-7b mints NO certificate, NO verdict, and takes NO response action.

Doctrine (non-negotiable, enforced here and tested — the identical bar as AS-5d/5e/5b):
  * AN ATTESTATION MEASURES, IT NEVER ACTS. The meter reports whether the front-WAF rule content is supply-chain
    admissible; it NEVER mutates the licence ledger, the corpus, or any state, and is NEVER a cause of, nor an input
    to, any admit/shed/allow/block decision. Only a fired oracle blocks. A CRS ``rule_ref`` is a LEAD, never a block.
  * READ-ONLY OVER ITS SOURCES. ``summary`` only READS the injected ledger records + the corpus manifest and runs
    the AS-7a gate over them; it writes nothing back. Any number of snapshots leave every §7 record and every admit
    decision byte-identical.
  * DETERMINISM. Pure functions of (ledger, policy, corpus): no wall-clock and no RNG anywhere — the corpus pin and
    the licence verdict are byte-identical under identical inputs, so a corpus can be pinned and re-verified offline.
  * ADDRESS-FREE + BOUNDED. ``normalize_rule_refs`` emits ONLY scrubbed, bounded, de-duplicated CRS rule-id tokens —
    NEVER a client address, a request URI/body, or the matched data a WAF audit record carries. The attestation
    surface carries counts + a digest, never request bytes and never a secret.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_CORAZA`` flag is set. Its structural
dependency is a CONFIGURED CRS corpus manifest (mirroring AS-5a's configured budget); its AS-7a/AS-28 gates are
flagless standalone gates, so there is no further dep flag to arm. OFF (or no corpus configured) ⇒ the gateway
builds no meter, computes nothing, and its data path AND the AS-5c probe snapshot are byte-identical.

FATAL-2: engine leg — imports ONLY the stdlib at module scope. It reaches the AS-7a licence gate (and the §7
``UseMode``) by RELATIVE import, consuming the ledger records by injection, so it NEVER re-implements the §7 check.
No ``vigil_core``, no ``sigil``/``governor``/``strix``/``apps`` — nothing on the scan/engage/benchmark gate path. It
adds NO OracleKind and registers NO vocabulary, so the make-gate byte-identity is structurally untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # relative, type-only — never executed at runtime (keeps the module stdlib-only at import)
    from .license_gate import LicenseRecord

__all__ = [
    "CORAZA_ENV",
    "WAF_ENGINE_ARTEFACT",
    "CRS_CORPUS_ARTEFACT",
    "CorazaCorpus",
    "CorazaAttestation",
    "CorazaAttestationMeter",
    "admit_rule_refs",
    "coraza_enabled",
    "corpus_pin",
    "normalize_rule_refs",
]

# The default-OFF switch for the Coraza/CRS front-WAF supply-chain attestation — strict, fail-closed, read when the
# gateway is built and re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit
# affirmative token turns it on; anything else (unset, typo, "0", "false") keeps it OFF — mirrors
# ``capacity.capacity_enabled`` / ``impact_budget.impact_budget_enabled`` / ``attribution.attribution_enabled`` exactly.
CORAZA_ENV = "VIGIL_AEGIS_CORAZA"

# The front-WAF detection stack whose §7 licence posture AS-7b attests: the DetectionOnly engine + its CRS rule
# corpus (the ``Coraza`` of the slice name). Both are ledgered Apache-2.0 service-use artefacts in engine-pins.json.
WAF_ENGINE_ARTEFACT = "coraza-v3"
CRS_CORPUS_ARTEFACT = "coreruleset-crs-4x"

# Bound the normalized rule-ref set so a flood of distinct rule ids in one audit record cannot bloat the lead.
_MAX_RULE_REFS = 32
# A CRS rule id is a short numeric token (e.g. "942100"); keep a conservative bound and an address-free charset so a
# matched-data / URI string smuggled into the id field is scrubbed to a safe token, never surfaced verbatim.
_RULE_ID_MAXLEN = 20
_RULE_ID_SCRUB = re.compile(r"[^0-9A-Za-z:_.-]")


def coraza_enabled() -> bool:
    """Is the Coraza/CRS front-WAF supply-chain attestation armed? Strict, fail-closed, DEFAULT OFF — only an
    explicit affirmative token arms it (mirrors ``capacity.capacity_enabled`` / ``attribution.attribution_enabled``).
    The gateway still builds a meter only when this is True AND its dependency (a configured CRS corpus) exists."""
    return (os.environ.get(CORAZA_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _canonical(obj: Any) -> str:
    """A deterministic canonical JSON encoding (sorted keys, no insignificant whitespace, ASCII). The byte basis for
    the corpus pin — stdlib only, no wall-clock, no RNG, so the same corpus always pins to the same digest."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _clean_rule_id(raw: Any) -> str:
    """Scrub one rule-id token to an address-free, bounded form: digits/letters/``:_.-`` only, length-capped. A
    non-conforming or empty token scrubs to ``""`` and is dropped by the caller (never surfaced verbatim)."""
    try:
        text = str(raw).strip()
    except Exception:
        return ""
    return _RULE_ID_SCRUB.sub("", text)[:_RULE_ID_MAXLEN]


def _normalized_rule_ids(rule_ids: Sequence[str]) -> tuple[str, ...]:
    """The canonical rule-id set a corpus pins over / a lead admits: scrubbed, de-duplicated, sorted and bounded, so
    the pin and the admitted leads never depend on input ordering or carry an unbounded/raw token."""
    seen: set[str] = set()
    for rid in rule_ids:
        tok = _clean_rule_id(rid)
        if tok:
            seen.add(tok)
    return tuple(sorted(seen))


def corpus_pin(version: str, paranoia: int, rule_ids: Sequence[str]) -> str:
    """A deterministic sha256 over the CRS corpus's pin-bearing fields (version · paranoia · the normalized rule-id
    set). Pure — stdlib only, no wall-clock, no RNG. A rule added/removed/re-tagged, a version or paranoia change,
    moves the pin: the AS-28-style tamper-evidence for the front-WAF rule content."""
    payload = {
        "artefact": CRS_CORPUS_ARTEFACT,
        "version": str(version),
        "paranoia": int(paranoia),
        "rule_ids": list(_normalized_rule_ids(rule_ids)),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def normalize_rule_refs(audit_event: Any) -> tuple[str, ...]:
    """Normalize a Coraza v3 / ModSecurity DetectionOnly audit record into typed, address-free ``rule_refs``.

    Accepts a dict (or JSON str/bytes) in the shapes Coraza emits: a top-level ``messages`` list of
    ``{"id"|"ruleId": ..., ...}`` entries, or a flat ``{"rule_ids": [...]}``. Returns the scrubbed, de-duplicated,
    sorted, bounded CRS rule-id tokens — NEVER the client address, the request URI/body, or the matched ``data`` the
    audit record carries. Total: a malformed record yields ``()`` (no lead), never an error."""
    data = audit_event
    if isinstance(data, (bytes, bytearray)):
        try:
            data = data.decode("utf-8", "replace")
        except Exception:
            return ()
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return ()
    if not isinstance(data, dict):
        return ()

    raw_ids: list[Any] = []
    messages = data.get("messages")
    if isinstance(messages, (list, tuple)):
        for msg in list(messages)[: _MAX_RULE_REFS * 8]:  # bound the scan regardless of record shape
            if isinstance(msg, dict):
                rid = msg.get("id", msg.get("ruleId"))
                if rid is not None:
                    raw_ids.append(rid)
            elif isinstance(msg, (str, int)):
                raw_ids.append(msg)
    flat = data.get("rule_ids")
    if isinstance(flat, (list, tuple)):
        raw_ids.extend(list(flat)[: _MAX_RULE_REFS * 8])

    return _normalized_rule_ids(raw_ids)[:_MAX_RULE_REFS]


@dataclass(frozen=True)
class CorazaCorpus:
    """The pinned CRS rule corpus a tenant's front WAF runs. Metadata only — rule IDS and a PIN, never rule bodies.

    * ``version``      — the CRS corpus version (e.g. ``"4.3.0"``).
    * ``paranoia``     — the CRS paranoia level the corpus is gated at (1-4).
    * ``rule_ids``     — the enforced CRS rule ids (normalized on construction: scrubbed, de-duplicated, sorted).
    * ``expected_pin`` — the digest this corpus is pinned to. ``pin`` recomputes it from the content; a mismatch is
      an unpinned (tampered / drifted) corpus. Defaults to the content pin (a self-consistent corpus)."""

    version: str
    paranoia: int
    rule_ids: tuple[str, ...]
    expected_pin: str

    @classmethod
    def build(cls, *, version: str, paranoia: int, rule_ids: Sequence[str],
              expected_pin: str | None = None) -> "CorazaCorpus":
        """Construct a corpus with a normalized rule-id set and a content pin. ``expected_pin`` defaults to the
        corpus's own content pin (a self-consistent corpus); pass a DIFFERENT value to model a drifted/tampered
        corpus whose live content no longer matches the digest it is pinned to."""
        ids = _normalized_rule_ids(rule_ids)
        pin = corpus_pin(version, paranoia, ids)
        return cls(version=str(version), paranoia=int(paranoia), rule_ids=ids,
                   expected_pin=expected_pin if expected_pin is not None else pin)

    @property
    def pin(self) -> str:
        """The LIVE content pin of this corpus (recomputed from version · paranoia · rule_ids)."""
        return corpus_pin(self.version, self.paranoia, self.rule_ids)

    @property
    def pinned(self) -> bool:
        """Does the live content pin match the digest this corpus is pinned to? False ⇒ drifted/tampered content."""
        return self.pin == self.expected_pin


@dataclass(frozen=True)
class CorazaAttestation:
    """ONE immutable, read-only front-WAF supply-chain attestation. Metadata only — counts + a digest, no secret.

    * ``licensed``     — the §7 licence gate (AS-7a) passes for the WAF detection stack (``coraza-v3`` engine +
      ``coreruleset-crs-4x`` corpus) under SERVICE use: complete, consistent, policy-clean. False ⇒ a missing /
      inconsistent / denied §7 record.
    * ``pinned``       — the CRS corpus's live content pin matches the digest it is pinned to (AS-28-style).
    * ``admissible``   — ``licensed AND pinned``: a Coraza hit's ``rule_refs`` may be admitted as a LEAD only when
      this is True; otherwise they are dropped (fail closed). ``admissible`` is NEVER a block — only a fired oracle
      blocks; it gates whether a CRS hit may raise belief AT ALL.
    * ``engine`` / ``artefact`` / ``version`` / ``paranoia`` — the attested stack's identity.
    * ``rules``        — the number of enforced CRS rule ids in the pinned corpus.
    * ``corpus_digest``— the live corpus pin (the AS-28-style content digest).
    * ``blocking``     — count of AS-7a BLOCKING licence findings over the WAF stack (0 when licensed).
    * ``advisories``   — count of AS-7a non-blocking findings (obligations / advisory records)."""

    licensed: bool
    pinned: bool
    admissible: bool
    engine: str
    artefact: str
    version: str
    paranoia: int
    rules: int
    corpus_digest: str
    blocking: int
    advisories: int

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        return {
            "licensed": self.licensed,
            "pinned": self.pinned,
            "admissible": self.admissible,
            "engine": self.engine,
            "artefact": self.artefact,
            "version": self.version,
            "paranoia": self.paranoia,
            "rules": self.rules,
            "corpus_digest": self.corpus_digest,
            "blocking": self.blocking,
            "advisories": self.advisories,
        }


class CorazaAttestationMeter:
    """The read-only Coraza/CRS front-WAF supply-chain attestation, bound to a CRS corpus manifest and the §7 licence
    ledger (the AS-7a records, injected). Holds NO mutable state — it only READS its ledger + corpus and runs the
    AS-7a gate over them, so it is inherently thread-safe and NEVER mutates a §7 record, the corpus, or any state.

    The meter MEASURES; it never acts: :meth:`summary` reports whether the front-WAF detection content a tenant runs
    is supply-chain admissible (licence-admitted AND pinned), paired with the corpus identity. It is surfaced
    read-only on the AS-5c probe snapshot and never touches the gateway data path or any admit/shed/allow/block
    decision. A CRS ``rule_ref`` admitted on the strength of this attestation is a LEAD, never a block."""

    def __init__(self, corpus: CorazaCorpus, *, ledger: "Sequence[LicenseRecord]") -> None:
        self._corpus = corpus
        self._ledger = tuple(ledger)  # a defensive copy of the injected records; never written back

    def summary(self) -> CorazaAttestation:
        """Compute the current attestation. Reads the injected §7 ledger (read-only; the AS-7a gate is a pure
        function of the records + policy) and the corpus pin. Read-only throughout; never mutates a source.

        Reaches the AS-7a licence gate by a LAZY RELATIVE import (keeping it off this module's import-time plane and
        the eager __init__/__main__ path) and NEVER re-implements the §7 check — ``licensed`` is the gate's verdict."""
        from .license_gate import DeployItem, LicenseGate  # relative, lazy — off the eager import plane (FATAL-2)
        from .license_policy import UseMode

        gate = LicenseGate()
        deploy = [
            DeployItem(artefact=WAF_ENGINE_ARTEFACT, use_mode=UseMode.SERVICE),
            DeployItem(artefact=CRS_CORPUS_ARTEFACT, use_mode=UseMode.SERVICE),
        ]
        result = gate.check(self._ledger, deploy)
        licensed = bool(result.passed)
        pinned = self._corpus.pinned
        return CorazaAttestation(
            licensed=licensed,
            pinned=pinned,
            admissible=licensed and pinned,
            engine=WAF_ENGINE_ARTEFACT,
            artefact=CRS_CORPUS_ARTEFACT,
            version=self._corpus.version,
            paranoia=self._corpus.paranoia,
            rules=len(self._corpus.rule_ids),
            corpus_digest=self._corpus.pin,
            blocking=len(result.blocking),
            advisories=len(result.advisories),
        )

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the front-WAF supply-chain attestation for the AS-5c probe
        surface. Carries counts + a digest, NO request bytes and NO secret — mirroring the AS-5a/5d/5e/5b snapshots."""
        return self.summary().to_dict()


def admit_rule_refs(rule_refs: Sequence[str], attestation: CorazaAttestation) -> tuple[str, ...]:
    """The supply-chain admission gate for Coraza DetectionOnly ``rule_refs``. Returns the (normalized) refs as
    admitted LEADS only when the corpus is ``admissible`` (licence-admitted AND pinned); over an unlicensed or
    unpinned corpus it returns ``()`` — untrusted/unverified third-party rule content raises NO belief (fail closed).

    This gates whether a CRS hit may raise belief AT ALL; it is NEVER a block (only a fired oracle blocks) and takes
    no response action. Pure + read-only: a function of its inputs, mutating nothing."""
    if not attestation.admissible:
        return ()
    return _normalized_rule_ids(rule_refs)[:_MAX_RULE_REFS]
