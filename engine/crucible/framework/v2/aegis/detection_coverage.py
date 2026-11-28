"""aegis.detection_coverage, AS-8: the deterministic read-only DETECTION-CONTENT COVERAGE measure.

AS-7b attests WHETHER the front-WAF detection content a tenant runs is supply-chain admissible (licence-admitted
AND pinned), and admits a Coraza DetectionOnly hit's ``rule_refs`` as a LEAD only over that admissible content. An
operator who has an admissible corpus then has one honest question no single slice answers: *of the detection
content I am actually allowed to run, WHAT does it cover, which attack techniques / rule-classes does the
admissible, hygiene-clean content detect, and how much of the known technique taxonomy is that, surfaced
read-only, as a measurement I can read and attest, never as something that acts?*

AS-8 answers exactly that, and NOTHING more. It is a deterministic, READ-ONLY COVERAGE measure: over the AS-7b
CRS attestation's ADMISSIBLE content (the enforced CRS rule-ids admitted through the AS-7b gate, reached by a
LAZY RELATIVE import, never re-implemented) it classifies each rule-id into its canonical CRS DETECTION TECHNIQUE
by the well-known CRS rule-id banding (the thousands band of a CRS id names its rule file / technique, e.g.
``942xxx`` is SQLi, ``941xxx`` is XSS), and reports which techniques the admissible content covers, how many rules
back each, how much of the known technique taxonomy is covered, and a deterministic posture digest.

The classifiable detection content is the AS-7b CRS corpus: the CRS rule-id → technique banding is a fixed,
deterministic, address-free taxonomy, and AS-7b's admissible CRS rule-ids ARE that classifiable content. (AS-10c's
kit CRS leg is the same corpus AS-7b attests; its Sigma leg carries opaque UUID ids that the CRS-band taxonomy does
not classify, so the CRS-technique coverage measure is correctly and completely sourced from the AS-7b CRS
content, the AS-8 engine-plane dependency.)

Doctrine (non-negotiable, enforced here and tested, the identical bar as AS-5d/5e/5b/7b/10c/31):
  * A COVERAGE MEASURE MEASURES, IT NEVER ACTS. It reports which techniques the admissible content covers; it NEVER
    mutates the licence ledger, the corpus, or any state, and is NEVER a cause of, nor an input to, any
    admit/shed/allow/block decision. A classified technique is a LEAD, never a block, only a fired oracle blocks.
  * READ-ONLY OVER ITS SOURCES. :meth:`summary` only READS the AS-7b meter (which itself only reads its ledger +
    corpus); it writes nothing back. Any number of measurements leave every source byte-identical.
  * DETERMINISM. Pure functions of (attestation, content): no wall-clock and no RNG, the coverage digest and the
    covered-technique set are byte-identical under identical inputs, so a coverage posture re-verifies offline.
  * FAIL-CLOSED. Over INADMISSIBLE (unlicensed / unpinned / drifted) content the measure covers NOTHING (``()``):
    unverified detection content is credited with NO coverage.
  * ADDRESS-FREE + BOUNDED + NO-LEAK. Every surfaced token is a fixed technique label or a scrubbed CRS rule-count,
    NEVER a client address, a request URI/body, or matched data. The admitted rule-ids reuse AS-7b's normalize
    discipline (bounded, sorted, de-duplicated) AND pass the AS-2e hygiene gate (a dotted-quad that survives the
    AS-7b charset scrub is DROPPED before it is ever classified). The measure carries counts + a digest, never
    request bytes and never a secret.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_COVERAGE`` flag is set AND its
dependency, the AS-7b Coraza attestation (``VIGIL_AEGIS_CORAZA``, which itself needs a configured CRS corpus), is
armed (there is no admissible content to measure otherwise). OFF (or the AS-7b dep off) ⇒ the gateway builds no
meter, computes nothing, and its data path AND the AS-5c probe snapshot are byte-identical.

FATAL-2: engine leg, imports ONLY the stdlib at module scope. It reaches the AS-7b admit gate and the AS-2e
hygiene gate by LAZY RELATIVE import, consuming their results by composition, so it NEVER re-implements either. No
``vigil_core``, no ``sigil``/``governor``/``strix``/``apps``: nothing on the scan/engage/benchmark gate path. It
adds NO OracleKind, NO fleet WorkerKind, and registers NO vocabulary, so the make-gate byte-identity is
structurally untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # relative, type-only, never executed at runtime (keeps the module stdlib-only at import)
    from .coraza_source import CorazaAttestationMeter

__all__ = [
    "COVERAGE_ENV",
    "CRS_TECHNIQUES",
    "KNOWN_TECHNIQUES",
    "UNCLASSIFIED",
    "DetectionCoverage",
    "DetectionCoverageMeter",
    "coverage_digest",
    "coverage_enabled",
    "crs_technique",
]

# The default-OFF switch for the detection-content coverage measure, strict, fail-closed, read when the gateway is
# built and re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit affirmative token
# turns it on; anything else (unset, typo, "0", "false") keeps it OFF, mirrors ``coraza_source.coraza_enabled`` /
# ``detection_mirror.detection_mirror_enabled`` / ``detection_kit.kit_enabled`` exactly.
COVERAGE_ENV = "VIGIL_AEGIS_COVERAGE"

# The canonical CRS 4.x rule-id → DETECTION TECHNIQUE taxonomy. A CRS rule id is a 6-digit token whose thousands
# band (its first three digits) names the rule file it belongs to and thus the attack technique it detects. This is
# a fixed, address-free, deterministic map, the classifiable basis for the coverage measure. The operational
# scoring bands (``949`` anomaly / blocking-evaluation, ``980`` correlation) are NOT attack-detection techniques, so
# they are deliberately omitted from the taxonomy and fall through to ``UNCLASSIFIED`` (counted honestly, but never
# credited as technique coverage).
CRS_TECHNIQUES: "dict[str, str]" = {
    "911": "method-enforcement",
    "913": "scanner-detection",
    "920": "protocol-enforcement",
    "921": "protocol-attack",
    "922": "multipart-attack",
    "930": "lfi",
    "931": "rfi",
    "932": "rce",
    "933": "php-injection",
    "934": "generic-attack",
    "941": "xss",
    "942": "sqli",
    "943": "session-fixation",
    "944": "java-attack",
    "951": "data-leakage-sql",
    "952": "data-leakage-java",
    "953": "data-leakage-php",
    "954": "data-leakage-iis",
}

# The label a rule-id whose band is outside the named taxonomy carries (an operational-scoring band, or an id shape
# the CRS banding does not name). It is surfaced + counted for honest accounting, but is NOT a named technique: it
# never inflates the covered-technique numerator or the known-technique denominator.
UNCLASSIFIED = "unclassified"

# The known attack-technique catalogue: the sorted distinct technique labels the taxonomy names. This is the
# coverage DENOMINATOR, "how much of the known technique taxonomy does the admissible content cover?".
KNOWN_TECHNIQUES: "tuple[str, ...]" = tuple(sorted(set(CRS_TECHNIQUES.values())))

# Bound the surfaced technique set and the per-technique breakdown so neither a flood of distinct rule-ids nor a
# malformed corpus can bloat the read-only coverage surface. (AS-7b's admit already bounds the rule-ref set, so
# these are belt-and-suspenders upper limits.)
_MAX_TECHNIQUES = 64
_MAX_RULES = 256


def coverage_enabled() -> bool:
    """Is the AS-8 detection-content coverage measure armed? Strict, fail-closed, DEFAULT OFF, only an explicit
    affirmative token arms it (mirrors ``coraza_source.coraza_enabled`` / ``detection_mirror.detection_mirror_enabled``).
    The gateway still builds a meter only when this is True AND the AS-7b Coraza attestation (its dependency) was
    itself built."""
    return (os.environ.get(COVERAGE_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _canonical(obj: Any) -> str:
    """A deterministic canonical JSON encoding (sorted keys, no insignificant whitespace, ASCII). The byte basis for
    the coverage digest, stdlib only, no wall-clock, no RNG, so the same coverage posture always digests the same
    way (the identical canonical form AS-7b / AS-31 use for their pins)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def crs_technique(rule_id: str) -> str:
    """Classify ONE CRS rule-id into its detection TECHNIQUE by the canonical CRS thousands-band taxonomy. A 6-digit
    CRS id's first three digits name its rule file / technique (``942100`` -> ``sqli``). An id whose band is outside
    the named taxonomy (an operational-scoring band, or a shape the banding does not name) classifies to
    :data:`UNCLASSIFIED`. Pure, a total function of the token, never an error."""
    try:
        text = str(rule_id).strip()
    except Exception:
        return UNCLASSIFIED
    band = text[:3]
    if len(band) == 3 and band.isdigit():
        return CRS_TECHNIQUES.get(band, UNCLASSIFIED)
    return UNCLASSIFIED


def coverage_digest(admissible: bool, per_technique: "dict[str, int]", rules: int) -> str:
    """A deterministic sha256 over the measured coverage posture (the content-admissibility bit · the sorted
    per-technique rule-count breakdown · the total classified rule count). Pure, stdlib only, no wall-clock, no
    RNG. The content flipping (in)admissible, a technique gained/lost, or a per-technique count changing moves the
    digest: the tamper/drift-evidence for the measured coverage posture."""
    payload = {
        "admissible": bool(admissible),
        "per_technique": {str(k): int(v) for k, v in sorted(per_technique.items())},
        "rules": int(rules),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DetectionCoverage:
    """ONE immutable, read-only measure of the detection-content coverage. Metadata only, counts + labels + a
    digest, never a client address, request bytes, or a secret.

    * ``admissible``: the AS-7b verdict: the front-WAF detection content is licence-admitted AND pinned. False ⇒
      inadmissible content (unlicensed / unpinned / drifted), NOTHING is credited as covered (fail closed).
    * ``techniques``: the sorted, de-duplicated, bounded set of DETECTION TECHNIQUES the admissible content
      covers (fixed address-free labels from the CRS taxonomy; may include :data:`UNCLASSIFIED` for operational
      bands). ``()`` over inadmissible content.
    * ``technique_count``: the number of distinct techniques surfaced (includes ``unclassified`` when present).
    * ``covered``: the number of distinct NAMED attack techniques covered (excludes ``unclassified``). The
      coverage numerator.
    * ``known``: the size of the known attack-technique taxonomy (:data:`KNOWN_TECHNIQUES`). The denominator.
    * ``coverage_bps``: ``covered`` as basis points of ``known`` (``covered * 10000 // known``, integer floor,
      no float, fully deterministic). 0 over inadmissible content.
    * ``per_technique``: a bounded, sorted mapping technique -> count of admissible rules backing it (honest
      accounting; the counts sum to ``rules``).
    * ``rules``: the total count of admissible, hygiene-clean CRS rule-ids classified. 0 when inadmissible.
    * ``digest``: the deterministic content digest of the measured coverage posture (:func:`coverage_digest`).
    * ``clean``: the AS-2e hygiene verdict over the surfaced body: True ⇒ it carries no raw IP and no
      configured secret literal. A measurement only, it NEVER drives a decision."""

    admissible: bool
    techniques: tuple[str, ...]
    technique_count: int
    covered: int
    known: int
    coverage_bps: int
    per_technique: "dict[str, int]"
    rules: int
    digest: str
    clean: bool

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        return {
            "admissible": self.admissible,
            "techniques": list(self.techniques),
            "technique_count": self.technique_count,
            "covered": self.covered,
            "known": self.known,
            "coverage_bps": self.coverage_bps,
            "per_technique": dict(sorted(self.per_technique.items())),
            "rules": self.rules,
            "digest": self.digest,
            "clean": self.clean,
        }


class DetectionCoverageMeter:
    """The read-only detection-content coverage measure, bound to the AS-7b Coraza attestation meter (the detection
    CONTENT admissibility gate) and the enforced detection content (the CRS rule-ids). Holds NO mutable state, it
    reads the (immutable) injected content refs once at construction and, per :meth:`summary`, reads the AS-7b meter
    (which itself only reads its ledger + corpus), so it is inherently thread-safe and NEVER mutates the licence
    ledger, the corpus, or any state.

    The meter MEASURES; it never acts: :meth:`summary` reports the detection coverage (which techniques the
    admissible content covers · how much of the known taxonomy · a posture digest), :meth:`classify` measures one
    observed detection hit's techniques (admitted only over admissible content, else ``()``). It is surfaced
    read-only on the AS-5c probe snapshot and never touches the gateway data path or any admit/shed/allow/block
    decision. A classified technique is a LEAD, never a block."""

    __slots__ = ("_coraza", "_content_refs", "_redact")

    def __init__(self, coraza_meter: "CorazaAttestationMeter", content_refs: Sequence[str], *,
                 redact_literals: "tuple[str, ...]" = ()) -> None:
        self._coraza = coraza_meter
        self._content_refs = tuple(str(r) for r in content_refs)
        self._redact = tuple(lit for lit in redact_literals if lit)

    def _hygienic(self, refs: Sequence[str]) -> tuple[str, ...]:
        """The AS-2e fail-closed LEAK gate: DROP any token that still carries a raw IP (AS-7b's address-free charset
        keeps digits and ``.``, so a dotted-quad survives its scrub) or a configured secret literal. Reaches the
        AS-2e hygiene primitive by a LAZY RELATIVE import, never re-implemented."""
        from .monitoring_event_v2 import contains_raw_ip  # relative, lazy, off the eager import plane (FATAL-2)
        out: list[str] = []
        for tok in refs:
            if contains_raw_ip(tok):
                continue
            if any(lit in tok for lit in self._redact):
                continue
            out.append(tok)
        return tuple(out[:_MAX_RULES])

    def _coverage(self, refs: Sequence[str], admissible: bool) -> DetectionCoverage:
        """Classify a set of admissible, hygiene-clean CRS rule-ids into the coverage posture. Pure, a function of
        the refs + the admissibility bit, mutating nothing."""
        per: "dict[str, int]" = {}
        for rid in refs:
            tech = crs_technique(rid)
            per[tech] = per.get(tech, 0) + 1
        techniques = tuple(sorted(per)[:_MAX_TECHNIQUES])
        covered = sum(1 for t in techniques if t != UNCLASSIFIED)
        known = len(KNOWN_TECHNIQUES)
        rules = sum(per.values())
        coverage_bps = (covered * 10000 // known) if known else 0
        clean = (not refs) or self._is_clean(refs)
        return DetectionCoverage(
            admissible=admissible,
            techniques=techniques,
            technique_count=len(techniques),
            covered=covered,
            known=known,
            coverage_bps=coverage_bps,
            per_technique=dict(sorted(per.items())),
            rules=rules,
            digest=coverage_digest(admissible, per, rules),
            clean=clean,
        )

    def classify(self, rule_refs: Sequence[str]) -> tuple[str, ...]:
        """Measure ONE observed detection hit (a set of ``rule_refs``) into the DETECTION TECHNIQUES it exercises.
        Fail-closed: returns ``()`` unless the detection content is ADMISSIBLE (AS-7b); each ref is first normalized
        address-free / bounded / sorted / de-duplicated (AS-7b) and passed through the AS-2e hygiene gate (a
        dotted-quad is dropped), then classified by the CRS-band taxonomy. The result is the sorted, de-duplicated
        technique labels, pure + read-only, a function of its inputs and the current attestation.

        This is a LEAD, never a block (only a fired oracle blocks) and takes no response action: it measures which
        techniques a detection hit touches."""
        from .coraza_source import admit_rule_refs           # relative, lazy, off the eager import plane (FATAL-2)
        att = self._coraza.summary()
        admitted = self._hygienic(admit_rule_refs(rule_refs, att))  # () over inadmissible content; else normalized
        techs = sorted({crs_technique(rid) for rid in admitted})
        return tuple(techs[:_MAX_TECHNIQUES])

    def summary(self) -> DetectionCoverage:
        """Compute the current coverage measure. Reads the AS-7b attestation (read-only; a pure function of the
        injected ledger + corpus) and classifies the admissible detection CONTENT (the enforced CRS rule-ids admitted
        through the AS-7b gate) by the CRS-band technique taxonomy. Read-only throughout; never mutates a source.

        Reaches the AS-7b admit gate by a LAZY RELATIVE import (keeping it off this module's import-time plane and
        the eager __init__/__main__ path) and NEVER re-implements it, ``admissible`` is the attestation's own
        verdict, the classified rules are its own admit gate's output."""
        from .coraza_source import admit_rule_refs           # relative, lazy, off the eager import plane (FATAL-2)
        att = self._coraza.summary()
        admissible = bool(att.admissible)
        refs = self._hygienic(admit_rule_refs(self._content_refs, att))
        return self._coverage(refs, admissible)

    def _is_clean(self, refs: Sequence[str]) -> bool:
        """The AS-2e hygiene VERDICT over the classified rule-ids (True ⇒ no raw IP, no configured secret literal).
        Reaches the AS-2e gate by a LAZY RELATIVE import, never re-implemented."""
        from .monitoring_event_v2 import is_hygiene_clean   # relative, lazy, off the eager import plane (FATAL-2)
        return is_hygiene_clean(_canonical(sorted(set(refs))), redact_literals=self._redact)

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the detection-content coverage measure for the AS-5c probe surface:
        the content-admissibility bit, the covered techniques, the per-technique breakdown, the coverage ratio (in
        basis points), the posture digest and the hygiene verdict. Carries counts + labels + a digest, NO request
        bytes and NO secret, mirroring the AS-5a/5d/5e/5b/7b/10c/31 snapshots."""
        return self.summary().to_dict()
