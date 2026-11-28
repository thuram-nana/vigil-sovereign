"""aegis.detection_kit — AS-10c: the detection-content KIT (supply-chain packaging attestation over CRS + Sigma).

A tenant's defensive deployment does not only RUN detection content (the Coraza/CRS front WAF, AS-7b) — it also
PACKAGES detection content to PUSH to customers: CRS-derived WAF rules and Sigma-derived SIEM rules, shipped as one
"kit". Shipping third-party detection content is a SUPPLY-CHAIN concern twice over: the content must be (a) LICENCE-
ADMITTED for *distribution* (CRS carries its NOTICE; SigmaHQ rules are DRL-1.1 and require author attribution — plan
§4.7), and (b) PINNED, so the exact rule content a customer receives is the content that was attested. AS-10c is the
read-only "kit" that composes those two guarantees into ONE bundled, tamper-evident attestation — and nothing more.

It composes, by RELATIVE import, the primitives three merged slices already expose (it re-implements none of them):

  * AS-7a §7 LICENCE GATE (``license_gate.LicenseGate`` / ``license_policy.UseMode``) — are the KIT's distributed
    artefacts (the ``pushed-rules`` bundle: ``pushed-crs-rules`` + ``pushed-sigma-rules``) LICENCE-ADMITTED under
    *distribution* use? A missing / inconsistent / policy-denied §7 record fails closed (``licensed = False``);
    attribution/NOTICE obligations are TRACKED as advisories, never blocking. Reached by relative import; never re-run
    by hand.
  * AS-7b CRS CORPUS PIN (``coraza_source.CorazaCorpus`` / ``corpus_pin``) — the CRS leg of the kit is pinned by the
    very same AS-28-style stdlib digest AS-7b mints for the running WAF corpus. AS-10c consumes AS-7b's
    ``normalize_rule_refs`` / ``admit_rule_refs`` address-free discipline for the kit's leads; it adds no CRS pin of
    its own.
  * AS-17a SIGMA (``..defender.sigma.SigmaRule``) — the Sigma leg. ``SigmaCorpus.from_rules`` reads the AS-17a parsed
    rules' identity + DEPLOYABILITY (``.id`` / ``.author`` / ``.license`` / ``.deployable``) — only the rules AS-17a
    deems DEPLOYABLE (supported + carrying their attribution) are packed into the kit — and pins them AS-28-style with
    the SAME normalize discipline AS-7b uses for CRS (reused, not re-implemented). AS-10c parses no Sigma itself.

``admissible = licensed AND crs_pinned AND sigma_pinned``. The ``kit_digest`` is a deterministic sha256 that BINDS
both corpus pins + the §7 licence-ledger digest + the kit identity into ONE seal — a drift in either corpus, in the
licence posture, or in the identity moves it, so a kit can be pinned once and re-verified offline byte-for-byte. A
detection hit's refs (CRS or Sigma) are admitted as LEADS only over an ADMISSIBLE kit; over an unlicensed or
unpinned (drifted/tampered) kit they are DROPPED (fail closed) — untrusted or unverified third-party rule content
can never raise belief. The kit mints NO certificate, NO verdict, and takes NO response action.

Doctrine (non-negotiable, enforced here and tested — the identical bar as AS-5d/5e/5b/7b):
  * AN ATTESTATION MEASURES, IT NEVER ACTS. The kit meter reports whether the detection content a tenant would ship
    is supply-chain admissible; it NEVER mutates the licence ledger, the corpora, or any state, and is NEVER a cause
    of, nor an input to, any admit/shed/allow/block decision. Only a fired oracle blocks. A CRS/Sigma ref is a LEAD.
  * READ-ONLY OVER ITS SOURCES. ``summary`` only READS the injected ledger + the two corpora and runs the AS-7a gate
    over them; it writes nothing back. Any number of snapshots leave every §7 record and every corpus byte-identical.
  * DETERMINISM. Pure functions of (ledger, policy, corpora): no wall-clock and no RNG anywhere — the corpus pins,
    the licence verdict and the kit digest are byte-identical under identical inputs, so a kit re-verifies offline.
  * ADDRESS-FREE + BOUNDED. The kit's lead admission reuses AS-7b's ``normalize_rule_refs`` discipline — ONLY
    scrubbed, bounded, de-duplicated rule-id tokens, NEVER a client address, a request URI/body, or matched data.
    The attestation surface carries counts + digests, never request bytes and never a secret.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_KIT`` flag is set. Its structural
dependency is a CONFIGURED kit (a CRS corpus + a Sigma corpus), mirroring AS-7b's configured-corpus dependency; its
AS-7a licence gate and the AS-7b/AS-17a pin/normalize primitives are flagless standalone gates/libraries, so — as
with AS-7b over AS-7a/AS-28 — there is no further dep flag to arm. OFF (or no kit configured) ⇒ the gateway builds
no meter, computes nothing, and its data path AND the AS-5c probe snapshot are byte-identical. (The AS-9b receiver is
a build/merge dependency — the ingest counterpart the kit is pushed through — and is deliberately NOT imported here:
a read-only packaging attestation pulls in no ingest service, keeping this module stdlib-only.)

FATAL-2: engine leg — imports ONLY the stdlib at module scope. It reaches the AS-7a licence gate, the AS-7b CRS
primitives and the AS-17a Sigma rules by RELATIVE import only (lazily, off the eager __init__/__main__ plane), so it
NEVER re-implements the §7 check, the corpus pin, or the Sigma parser. No ``vigil_core``, no ``sigil`` /
``governor`` / ``strix`` / ``apps`` — nothing on the scan/engage/benchmark gate path. It adds NO OracleKind and
registers NO vocabulary, so the make-gate byte-identity is structurally untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # relative, type-only — never executed at runtime (keeps the module stdlib-only at import)
    from ..defender.sigma import SigmaRule
    from .license_gate import LicenseRecord

__all__ = [
    "KIT_ENV",
    "KIT_NAME",
    "KIT_BUNDLE",
    "PUSHED_CRS_ARTEFACT",
    "PUSHED_SIGMA_ARTEFACT",
    "SigmaCorpus",
    "DetectionKit",
    "DetectionKitAttestation",
    "DetectionKitMeter",
    "admit_kit_leads",
    "kit_digest",
    "kit_enabled",
    "sigma_corpus_pin",
]

# The default-OFF switch for the detection-content kit supply-chain attestation — strict, fail-closed, read when the
# gateway is built and re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit
# affirmative token turns it on; anything else (unset, typo, "0", "false") keeps it OFF — mirrors
# ``coraza_source.coraza_enabled`` / ``capacity.capacity_enabled`` / ``attribution.attribution_enabled`` exactly.
KIT_ENV = "VIGIL_AEGIS_KIT"

# The kit's identity (what the kit digest is anchored to) and the §7 DISTRIBUTION bundle it attests: the
# SigmaHQ-derived + CRS-derived rule content pushed to customers (both ledgered under the ``pushed-rules`` bundle,
# use_mode=distribution, in engine-pins.json).
KIT_NAME = "aegis-detection-kit"
KIT_BUNDLE = "pushed-rules"
PUSHED_CRS_ARTEFACT = "pushed-crs-rules"
PUSHED_SIGMA_ARTEFACT = "pushed-sigma-rules"


def kit_enabled() -> bool:
    """Is the AS-10c detection-content kit supply-chain attestation armed? Strict, fail-closed, DEFAULT OFF — only an
    explicit affirmative token arms it (mirrors ``coraza_source.coraza_enabled``). The gateway still builds a meter
    only when this is True AND its dependency (a configured kit: a CRS corpus + a Sigma corpus) exists."""
    return (os.environ.get(KIT_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _canonical(obj: Any) -> str:
    """A deterministic canonical JSON encoding (sorted keys, no insignificant whitespace, ASCII). The byte basis for
    the Sigma corpus pin and the kit digest — stdlib only, no wall-clock, no RNG, so the same kit always digests the
    same way (the identical canonical form AS-7b's ``corpus_pin`` uses, so the two corpora pin consistently)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _normalized_ids(rule_ids: Sequence[str]) -> tuple[str, ...]:
    """Scrub / de-duplicate / sort a rule-id set with AS-7b's EXACT discipline (reused, not re-implemented), so the
    Sigma corpus pin and a kit lead never depend on input ordering or carry an unbounded/raw/address-bearing token.
    Reaches AS-7b's normalize primitive by a lazy RELATIVE import (keeping this module stdlib-only at import)."""
    from .coraza_source import _normalized_rule_ids  # AS-7b's address-free scrub/sort/dedup (relative, lazy)
    return _normalized_rule_ids(rule_ids)


def sigma_corpus_pin(version: str, author: str, license_: str, rule_ids: Sequence[str]) -> str:
    """A deterministic sha256 over a Sigma corpus's pin-bearing fields (version · author · licence · the normalized
    rule-id set). Pure — stdlib only, no wall-clock, no RNG. A rule added/removed/re-tagged, or a version/author/
    licence change, moves the pin: the AS-28-style tamper-evidence for the Sigma leg, parallel to AS-7b's CRS
    ``corpus_pin`` (a separate corpus pin — not the AS-7a ledger digest and not the AS-28 import graph)."""
    payload = {
        "artefact": PUSHED_SIGMA_ARTEFACT,
        "version": str(version),
        "author": str(author),
        "license": str(license_),
        "rule_ids": list(_normalized_ids(rule_ids)),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SigmaCorpus:
    """The pinned Sigma rule corpus a kit ships. Metadata only — rule IDS, attribution + a PIN, never rule bodies.

    * ``version``      — the Sigma corpus version (e.g. ``"2024.11"``).
    * ``author``       — the attribution the DRL-1.1 distribution obligation requires (plan §4.7).
    * ``license``      — the licence the rule content is distributed under (e.g. ``"DRL-1.1"``).
    * ``rule_ids``     — the DEPLOYABLE Sigma rule ids packed into the kit (normalized on construction: scrubbed,
      de-duplicated, sorted). Non-deployable rules (unsupported, or missing attribution) are NOT shipped.
    * ``nondeployable``— how many candidate rules were EXCLUDED as non-deployable (honest accounting, not shipped).
    * ``expected_pin`` — the digest this corpus is pinned to. ``pin`` recomputes it from the content; a mismatch is
      an unpinned (tampered / drifted) corpus. Defaults to the content pin (a self-consistent corpus)."""

    version: str
    author: str
    license: str
    rule_ids: tuple[str, ...]
    nondeployable: int
    expected_pin: str

    @classmethod
    def build(cls, *, version: str, author: str, license: str, rule_ids: Sequence[str],
              nondeployable: int = 0, expected_pin: str | None = None) -> "SigmaCorpus":
        """Construct a corpus with a normalized rule-id set and a content pin. ``expected_pin`` defaults to the
        corpus's own content pin (a self-consistent corpus); pass a DIFFERENT value to model a drifted/tampered
        corpus whose live content no longer matches the digest it is pinned to."""
        ids = _normalized_ids(rule_ids)
        pin = sigma_corpus_pin(version, author, license, ids)
        return cls(version=str(version), author=str(author), license=str(license), rule_ids=ids,
                   nondeployable=int(nondeployable),
                   expected_pin=expected_pin if expected_pin is not None else pin)

    @classmethod
    def from_rules(cls, rules: "Sequence[SigmaRule]", *, version: str,
                   author: str | None = None, license: str | None = None,
                   expected_pin: str | None = None) -> "SigmaCorpus":
        """Build a Sigma corpus from AS-17a parsed rules (reached by relative import). ONLY the rules AS-17a deems
        DEPLOYABLE (supported + carrying the author/licence attribution distribution requires) are packed into the
        kit; the rest are counted in ``nondeployable`` and dropped. ``author`` / ``license`` default to the first
        deployable rule's attribution, so the kit carries the attribution AS-17a parsed off the rule content."""
        from ..defender.sigma import SigmaRule  # AS-17a Sigma (relative, lazy — off the eager import plane, FATAL-2)

        deployable_ids: list[str] = []
        nondeployable = 0
        derived_author = ""
        derived_license = ""
        for rule in rules:
            if not isinstance(rule, SigmaRule):  # narrows to AS-17a's SigmaRule; a non-rule is not shippable content
                nondeployable += 1
                continue
            if rule.deployable:
                deployable_ids.append(str(rule.id or ""))
                if not derived_author and rule.author:
                    derived_author = str(rule.author)
                if not derived_license and rule.license:
                    derived_license = str(rule.license)
            else:
                nondeployable += 1
        return cls.build(
            version=version,
            author=author if author is not None else derived_author,
            license=license if license is not None else derived_license,
            rule_ids=deployable_ids,
            nondeployable=nondeployable,
            expected_pin=expected_pin,
        )

    @property
    def pin(self) -> str:
        """The LIVE content pin of this corpus (recomputed from version · author · licence · rule_ids)."""
        return sigma_corpus_pin(self.version, self.author, self.license, self.rule_ids)

    @property
    def pinned(self) -> bool:
        """Does the live content pin match the digest this corpus is pinned to? False ⇒ drifted/tampered content."""
        return self.pin == self.expected_pin


def kit_digest(*, name: str, crs_digest: str, sigma_digest: str, ledger_digest: str,
               crs: "dict[str, object]", sigma: "dict[str, object]") -> str:
    """A deterministic sha256 that BINDS a kit's two corpus pins + its §7 licence-ledger digest + its identity into
    ONE tamper-evident seal. Pure — stdlib only, no wall-clock, no RNG. A drift in either corpus (moves its digest),
    in the licence posture (moves ``ledger_digest``), or in the kit identity moves the kit digest, so a kit can be
    pinned once and re-verified offline byte-for-byte."""
    payload = {
        "kit": str(name),
        "crs": {**crs, "digest": crs_digest},
        "sigma": {**sigma, "digest": sigma_digest},
        "ledger_digest": str(ledger_digest),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DetectionKit:
    """ONE configured detection-content kit: a CRS corpus (AS-7b ``CorazaCorpus``) + a Sigma corpus (``SigmaCorpus``),
    packaged under ``name``. Metadata only — rule ids + pins, never rule bodies."""

    name: str
    crs: Any  # CorazaCorpus (AS-7b) — typed Any to keep this module stdlib-only at import (no eager coraza import)
    sigma: SigmaCorpus

    @classmethod
    def build(cls, *, crs: Any, sigma: SigmaCorpus, name: str = KIT_NAME) -> "DetectionKit":
        return cls(name=str(name), crs=crs, sigma=sigma)


@dataclass(frozen=True)
class DetectionKitAttestation:
    """ONE immutable, read-only detection-content kit supply-chain attestation. Metadata only — counts + digests.

    * ``licensed``      — the §7 licence gate (AS-7a) passes for the kit's DISTRIBUTION bundle (``pushed-crs-rules`` +
      ``pushed-sigma-rules``): complete, consistent, policy-clean. False ⇒ a missing / inconsistent / denied record.
    * ``crs_pinned`` / ``sigma_pinned`` — each corpus's live content pin matches the digest it is pinned to.
    * ``admissible``    — ``licensed AND crs_pinned AND sigma_pinned``: a kit hit's refs may be admitted as a LEAD
      only when this is True; otherwise they are dropped (fail closed). NEVER a block — only a fired oracle blocks.
    * ``kit_digest``    — the tamper-evident seal binding both corpus pins + the licence digest + the kit identity.
    * ``crs_digest`` / ``sigma_digest`` — the two AS-28-style corpus content pins the kit seal binds.
    * ``ledger_digest`` — the §7 licence-ledger digest (the pinnable licence posture).
    * identity fields   — the attested content's identity (crs version/paranoia/rules; sigma version/author/licence/
      rules/nondeployable).
    * ``blocking``      — count of AS-7a BLOCKING licence findings over the kit bundle (0 when licensed).
    * ``advisories``    — count of AS-7a non-blocking findings (NOTICE / attribution obligations the kit must carry)."""

    name: str
    licensed: bool
    crs_pinned: bool
    sigma_pinned: bool
    admissible: bool
    kit_digest: str
    crs_digest: str
    sigma_digest: str
    ledger_digest: str
    crs_version: str
    crs_paranoia: int
    crs_rules: int
    sigma_version: str
    sigma_author: str
    sigma_license: str
    sigma_rules: int
    sigma_nondeployable: int
    blocking: int
    advisories: int

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only (counts + digests,
        never a rule body, never a client address, never a secret)."""
        return {
            "name": self.name,
            "licensed": self.licensed,
            "crs_pinned": self.crs_pinned,
            "sigma_pinned": self.sigma_pinned,
            "admissible": self.admissible,
            "kit_digest": self.kit_digest,
            "crs_digest": self.crs_digest,
            "sigma_digest": self.sigma_digest,
            "ledger_digest": self.ledger_digest,
            "crs_version": self.crs_version,
            "crs_paranoia": self.crs_paranoia,
            "crs_rules": self.crs_rules,
            "sigma_version": self.sigma_version,
            "sigma_author": self.sigma_author,
            "sigma_license": self.sigma_license,
            "sigma_rules": self.sigma_rules,
            "sigma_nondeployable": self.sigma_nondeployable,
            "blocking": self.blocking,
            "advisories": self.advisories,
        }


class DetectionKitMeter:
    """The read-only detection-content kit supply-chain attestation, bound to a configured ``DetectionKit`` and the §7
    licence ledger (the AS-7a records, injected). Holds NO mutable state — it only READS its ledger + corpora and runs
    the AS-7a gate over them, so it is inherently thread-safe and NEVER mutates a §7 record, the corpora, or any state.

    The meter MEASURES; it never acts: :meth:`summary` reports whether the detection content a tenant would SHIP is
    supply-chain admissible (licence-admitted for distribution AND both corpora pinned), sealed by the kit digest. It
    is surfaced read-only on the AS-5c probe snapshot and never touches the gateway data path or any admit/shed/allow/
    block decision. A ref admitted on the strength of this attestation is a LEAD, never a block."""

    def __init__(self, kit: DetectionKit, *, ledger: "Sequence[LicenseRecord]") -> None:
        self._kit = kit
        self._ledger = tuple(ledger)  # a defensive copy of the injected records; never written back

    def summary(self) -> DetectionKitAttestation:
        """Compute the current attestation. Reads the injected §7 ledger (read-only; the AS-7a gate is a pure function
        of the records + policy) and the two corpus pins. Read-only throughout; never mutates a source.

        Reaches the AS-7a licence gate and the AS-7b CRS primitive by LAZY RELATIVE import (keeping them off this
        module's import-time plane and the eager __init__/__main__ path) and NEVER re-implements the §7 check or the
        CRS pin — ``licensed`` is the gate's verdict and ``crs_digest`` is AS-7b's corpus pin."""
        from .coraza_source import CRS_CORPUS_ARTEFACT  # AS-7b CRS identity (relative, lazy)
        from .license_gate import DeployItem, LicenseGate, ledger_digest  # AS-7a §7 gate (relative, lazy)
        from .license_policy import UseMode

        gate = LicenseGate()
        deploy = [
            DeployItem(artefact=PUSHED_CRS_ARTEFACT, use_mode=UseMode.DISTRIBUTION),
            DeployItem(artefact=PUSHED_SIGMA_ARTEFACT, use_mode=UseMode.DISTRIBUTION),
        ]
        result = gate.check(self._ledger, deploy)
        licensed = bool(result.passed)
        crs = self._kit.crs
        sigma = self._kit.sigma
        crs_pinned = bool(crs.pinned)
        sigma_pinned = bool(sigma.pinned)
        crs_digest = str(crs.pin)
        sigma_digest = str(sigma.pin)
        led_digest = ledger_digest(self._ledger)
        crs_identity: "dict[str, object]" = {
            "artefact": CRS_CORPUS_ARTEFACT,
            "version": str(crs.version),
            "paranoia": int(crs.paranoia),
            "rules": len(crs.rule_ids),
        }
        sigma_identity: "dict[str, object]" = {
            "artefact": PUSHED_SIGMA_ARTEFACT,
            "version": str(sigma.version),
            "author": str(sigma.author),
            "license": str(sigma.license),
            "rules": len(sigma.rule_ids),
        }
        seal = kit_digest(name=self._kit.name, crs_digest=crs_digest, sigma_digest=sigma_digest,
                          ledger_digest=led_digest, crs=crs_identity, sigma=sigma_identity)
        return DetectionKitAttestation(
            name=self._kit.name,
            licensed=licensed,
            crs_pinned=crs_pinned,
            sigma_pinned=sigma_pinned,
            admissible=licensed and crs_pinned and sigma_pinned,
            kit_digest=seal,
            crs_digest=crs_digest,
            sigma_digest=sigma_digest,
            ledger_digest=led_digest,
            crs_version=str(crs.version),
            crs_paranoia=int(crs.paranoia),
            crs_rules=len(crs.rule_ids),
            sigma_version=str(sigma.version),
            sigma_author=str(sigma.author),
            sigma_license=str(sigma.license),
            sigma_rules=len(sigma.rule_ids),
            sigma_nondeployable=int(sigma.nondeployable),
            blocking=len(result.blocking),
            advisories=len(result.advisories),
        )

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the kit supply-chain attestation for the AS-5c probe surface.
        Carries counts + digests, NO request bytes and NO secret — mirroring the AS-5a/5d/5e/5b/7b snapshots."""
        return self.summary().to_dict()


def admit_kit_leads(rule_refs: Sequence[str], attestation: DetectionKitAttestation) -> tuple[str, ...]:
    """The supply-chain admission gate for a detection hit's (CRS or Sigma) ``rule_refs`` against a KIT. Returns the
    (normalized) refs as admitted LEADS only when the kit is ``admissible`` (licence-admitted AND both corpora
    pinned); over an unlicensed or unpinned kit it returns ``()`` — untrusted/unverified third-party rule content
    raises NO belief (fail closed).

    Reuses AS-7b's ``normalize_rule_refs`` address-free discipline (scrubbed, bounded, sorted, de-duplicated — never a
    client address/URI/matched data) by relative import. This gates whether a kit hit may raise belief AT ALL; it is
    NEVER a block (only a fired oracle blocks) and takes no response action. Pure + read-only."""
    if not attestation.admissible:
        return ()
    from .coraza_source import normalize_rule_refs  # AS-7b's address-free, bounded normalize (relative, lazy)
    return normalize_rule_refs({"rule_ids": list(rule_refs)})
