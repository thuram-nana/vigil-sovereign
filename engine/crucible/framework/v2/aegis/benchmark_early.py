"""aegis.benchmark_early, AS-23a: the deterministic read-only EARLY DETECTION-POSTURE BENCHMARK.

AEGIS now carries three read-only measures over its front-WAF detection content: AS-7b attests WHETHER that
content is supply-chain admissible (licence-admitted AND pinned), AS-8 measures WHAT the admissible content
COVERS (which CRS detection techniques, how much of the known taxonomy), and AS-31 REFLECTS the detection
posture (the cataloged sources, the admissible content leads). A defender preparing a comparative claim then
has one honest question none of those three answers on its own: *against a fixed reference set of attack
techniques I care about, how much of that reference does the detection content I am actually allowed to run
cover, and is the posture reflected live, surfaced read-only as a bounded efficacy measurement I can read and
re-verify offline, never as something that acts?*

AS-23a answers exactly that, and NOTHING more. It is the EARLY benchmark: a deterministic, READ-ONLY efficacy
MEASUREMENT that COMPOSES its three merged dependencies against a small, fixed, in-repo reference set.

  * AS-8 detection-content coverage (``DetectionCoverageMeter.summary``). The covered CRS detection techniques
    the admissible content classifies to, and the AS-7b admissibility bit it carries. Reached by a LAZY
    RELATIVE import, consumed by composition, never re-implemented.
  * AS-7b Coraza/CRS admissibility. ``admissible = licensed AND pinned`` enters the benchmark through BOTH
    composed meters; the benchmark cross-checks that the two agree (``consistent``) and credits coverage only
    over admissible content. Over inadmissible (unlicensed / unpinned / drifted) content the benchmark covers
    NOTHING of the reference set (fail closed).
  * AS-31 detection mirror (``DetectionMirrorMeter.summary``). The cataloged detection-source count and the
    admissible content lead count, reflected as a live-posture cross-check alongside the coverage efficacy.
    Reached by a LAZY RELATIVE import, consumed by composition, never re-implemented.

The REFERENCE SET is :data:`REFERENCE_TECHNIQUES`, a small, FIXED, address-free, in-repo fixture of canonical
CRS attack-technique labels (the benchmark denominator). It is a code constant, never fetched and never read
from the network. The efficacy metric is ``covered_reference / reference`` in integer basis points: of the
reference techniques, how many the admissible content actually covers.

Doctrine (non-negotiable, enforced here and tested, the identical bar as AS-5d/5e/5b/7b/8/31):
  * A BENCHMARK MEASURES, IT NEVER ACTS. It reports the efficacy of the admissible content against a fixed
    reference; it NEVER mutates the licence ledger, the corpus, the provider inventory, or any state, and is
    NEVER a cause of, nor an input to, any admit/shed/allow/block decision. A covered technique is a LEAD,
    never a block, only a fired oracle blocks. It asserts nothing about live traffic.
  * READ-ONLY OVER ITS SOURCES. :meth:`summary` only READS the composed AS-8 / AS-31 meters (which themselves
    only read their ledger + corpus + inventory); it writes nothing back. Any number of measurements leave
    every source byte-identical.
  * DETERMINISM. Pure functions of (coverage summary, mirror summary, reference set): no wall-clock and no RNG,
    the benchmark digest and the covered/missing sets are byte-identical under identical inputs, so a benchmark
    posture re-verifies offline.
  * FAIL-CLOSED. Over INADMISSIBLE content, or an EMPTY reference set, the benchmark credits NO reference
    coverage (efficacy 0, the whole reference ``missing``). Unverified detection content earns no efficacy.
  * ADDRESS-FREE + BOUNDED + NO-LEAK. Every surfaced token is a fixed CRS technique label or a scrubbed count,
    NEVER a client address, a request URI/body, or matched data. The composed coverage/mirror hygiene verdicts
    are carried through AND the surfaced body passes the AS-2e hygiene gate (a token that still carries a raw
    IP or a configured secret literal is caught). The benchmark carries counts + labels + a digest, never
    request bytes and never a secret.

DEFAULT-OFF: nothing here is armed unless the strict, fail-closed ``VIGIL_AEGIS_BENCHMARK`` flag is set AND
every dependency flag is armed, the AS-7b Coraza attestation (``VIGIL_AEGIS_CORAZA``, which itself needs a
configured CRS corpus), the AS-8 coverage measure (``VIGIL_AEGIS_COVERAGE``), and the AS-31 detection mirror
(``VIGIL_AEGIS_DETECTION_MIRROR``). OFF (or any dep off) ⇒ :func:`benchmark_early_snapshot` returns a
byte-identical inert no-op (``{}``) and the composed meters are never consulted. The arming gate is the ONLY
environment read; the measurement itself (:meth:`summary`) is a pure function of its injected inputs.

FATAL-2: engine leg, imports ONLY the stdlib at module scope. It reaches the AS-8 coverage meter, the AS-31
mirror meter, the AS-7b flag predicate, and the AS-2e hygiene gate by LAZY RELATIVE import, consuming their
results by composition, so it NEVER re-implements any of them. No ``vigil_core``, no
``sigil``/``governor``/``strix``/``apps``, nothing on the scan/engage/benchmark gate path. It adds NO
OracleKind, NO fleet WorkerKind, and registers NO vocabulary, and stays OFF the eager
``aegis/__init__`` / ``__main__`` import path (lazy relative imports), so the make-gate byte-identity and the
SaaS import closure are structurally untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # relative, type-only, never executed at runtime (keeps the module stdlib-only at import)
    from .detection_coverage import DetectionCoverageMeter
    from .detection_mirror import DetectionMirrorMeter

__all__ = [
    "BENCHMARK_ENV",
    "REFERENCE_TECHNIQUES",
    "BenchmarkEarly",
    "BenchmarkEarlyMeter",
    "benchmark_armed",
    "benchmark_deps_armed",
    "benchmark_digest",
    "benchmark_early_enabled",
    "benchmark_early_snapshot",
]

# The default-OFF switch for the AS-23a early benchmark, strict, fail-closed, read only in the arming gate (so
# the measurement itself stays a pure function of its injected inputs). Only an explicit affirmative token arms
# it; anything else (unset, typo, "0", "false") keeps it OFF, mirrors ``coraza_source.coraza_enabled`` /
# ``detection_coverage.coverage_enabled`` / ``detection_mirror.detection_mirror_enabled`` exactly.
BENCHMARK_ENV = "VIGIL_AEGIS_BENCHMARK"

# The fixed, in-repo REFERENCE SET: the canonical CRS attack-technique labels this early benchmark scores the
# admissible detection content against (the efficacy denominator). A small, address-free, deterministic code
# constant, never fetched and never read from the network. Each label is a named technique in the AS-8 CRS
# taxonomy (``detection_coverage.KNOWN_TECHNIQUES``), so a reference technique is classifiable and can be
# covered. Kept sorted so the surfaced reference is representation-stable.
REFERENCE_TECHNIQUES: "tuple[str, ...]" = (
    "lfi",
    "php-injection",
    "protocol-attack",
    "rce",
    "rfi",
    "scanner-detection",
    "sqli",
    "xss",
)

# Bound the reference set and the covered/missing breakdowns so neither an oversized fixture nor a flood of
# distinct technique labels can bloat the read-only benchmark surface. (The composed AS-8 measure already
# bounds its technique set, so these are belt-and-suspenders upper limits.)
_MAX_REFERENCE = 64


def benchmark_early_enabled() -> bool:
    """Is the AS-23a early benchmark's OWN flag armed? Strict, fail-closed, DEFAULT OFF, only an explicit
    affirmative token arms it (mirrors ``coverage_enabled`` / ``detection_mirror_enabled``). This is only the
    benchmark's own switch; :func:`benchmark_armed` additionally requires every dependency flag."""
    return (os.environ.get(BENCHMARK_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def benchmark_deps_armed() -> bool:
    """Are the benchmark's dependency flags all armed? The early benchmark composes AS-8 coverage and AS-31
    reflection, each over the AS-7b attestation, so it is inert unless the AS-7b Coraza
    (``VIGIL_AEGIS_CORAZA``), the AS-8 coverage (``VIGIL_AEGIS_COVERAGE``) AND the AS-31 mirror
    (``VIGIL_AEGIS_DETECTION_MIRROR``) flags are each armed. Reaches each dependency's flag predicate by a LAZY
    RELATIVE import, never re-implementing the parse."""
    from .coraza_source import coraza_enabled            # relative, lazy, off the eager import plane (FATAL-2)
    from .detection_coverage import coverage_enabled      # relative, lazy, off the eager import plane (FATAL-2)
    from .detection_mirror import detection_mirror_enabled  # relative, lazy, off the eager import plane
    return coraza_enabled() and coverage_enabled() and detection_mirror_enabled()


def benchmark_armed() -> bool:
    """Is the early benchmark fully armed? True only when its own ``VIGIL_AEGIS_BENCHMARK`` flag AND every
    dependency flag are armed. Strict, fail-closed, DEFAULT OFF. This is the ONLY environment read on the
    benchmark path; the measurement itself is a pure function of its injected inputs."""
    return benchmark_early_enabled() and benchmark_deps_armed()


def _canonical(obj: Any) -> str:
    """A deterministic canonical JSON encoding (sorted keys, no insignificant whitespace, ASCII). The byte
    basis for the benchmark digest, stdlib only, no wall-clock, no RNG, so the same benchmark posture always
    digests the same way (the identical canonical form AS-7b / AS-8 / AS-31 use for their pins)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def benchmark_digest(admissible: bool, reference: Sequence[str], covered: Sequence[str],
                     efficacy_bps: int, reflected_leads: int, sources: int) -> str:
    """A deterministic sha256 over the measured benchmark posture (the content-admissibility bit, the sorted
    reference set, the sorted covered-reference set, the integer efficacy, the reflected-lead count, the
    detection-source count). Pure, stdlib only, no wall-clock, no RNG. The content flipping (in)admissible, a
    reference technique gained or lost from coverage, the efficacy moving, or the reflected posture changing
    moves the digest: the tamper/drift-evidence for the measured benchmark posture."""
    payload = {
        "admissible": bool(admissible),
        "reference": sorted({str(t) for t in reference}),
        "covered": sorted({str(t) for t in covered}),
        "efficacy_bps": int(efficacy_bps),
        "reflected_leads": int(reflected_leads),
        "sources": int(sources),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BenchmarkEarly:
    """ONE immutable, read-only early-benchmark measurement. Metadata only, counts + fixed labels + a digest,
    never a client address, request bytes, or a secret.

    * ``admissible``       the AS-7b verdict carried by the AS-8 coverage measure: the front-WAF detection
      content is licence-admitted AND pinned. False ⇒ inadmissible content, NO reference coverage is credited
      (fail closed).
    * ``consistent``       the two composed meters agree on the admissibility bit (AS-8 coverage vs AS-31
      mirror). False flags a composition divergence (meters built over different corpora). A measurement only.
    * ``reference``        the fixed reference attack-technique set scored against (sorted, address-free). The
      efficacy denominator.
    * ``reference_count``  the size of the reference set.
    * ``covered``          the reference techniques the admissible content covers (sorted intersection of the
      AS-8 covered techniques with the reference set, bounded). ``()`` over inadmissible content.
    * ``covered_count``    the number of reference techniques covered. The efficacy numerator.
    * ``missing``          the reference techniques NOT covered (sorted, bounded). The whole reference set over
      inadmissible content.
    * ``missing_count``    the number of reference techniques not covered.
    * ``efficacy_bps``     ``covered_count`` as basis points of ``reference_count``
      (``covered_count * 10000 // reference_count``, integer floor, no float, fully deterministic). 0 over
      inadmissible content or an empty reference set.
    * ``sources``          the AS-31 cataloged detection-source count (live-posture context).
    * ``reflected_leads``  the AS-31 admissible content lead count (a live-posture reflection cross-check).
    * ``digest``           the deterministic content digest of the measured benchmark posture.
    * ``clean``            the composed hygiene verdict: the AS-8 and AS-31 verdicts AND the AS-2e verdict over
      the surfaced body. True ⇒ it carries no raw IP and no configured secret literal. A measurement only, it
      NEVER drives a decision."""

    admissible: bool
    consistent: bool
    reference: tuple[str, ...]
    reference_count: int
    covered: tuple[str, ...]
    covered_count: int
    missing: tuple[str, ...]
    missing_count: int
    efficacy_bps: int
    sources: int
    reflected_leads: int
    digest: str
    clean: bool

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        return {
            "admissible": self.admissible,
            "consistent": self.consistent,
            "reference": list(self.reference),
            "reference_count": self.reference_count,
            "covered": list(self.covered),
            "covered_count": self.covered_count,
            "missing": list(self.missing),
            "missing_count": self.missing_count,
            "efficacy_bps": self.efficacy_bps,
            "sources": self.sources,
            "reflected_leads": self.reflected_leads,
            "digest": self.digest,
            "clean": self.clean,
        }


class BenchmarkEarlyMeter:
    """The read-only early detection-posture benchmark, bound to the AS-8 coverage meter (the detection-content
    coverage measure) and the AS-31 detection mirror meter (the reflected posture), each of which composes the
    AS-7b attestation. Holds NO mutable state, it reads the (immutable) injected reference set once at
    construction and, per :meth:`summary`, reads the two composed meters (which themselves only read their
    ledger + corpus + inventory), so it is inherently thread-safe and NEVER mutates the licence ledger, the
    corpus, the provider inventory, or any state.

    The meter MEASURES; it never acts: :meth:`summary` reports the efficacy of the admissible content against
    the fixed reference set (covered vs reference techniques, an integer efficacy, a posture digest) paired
    with the AS-31 live-posture cross-check. It never touches any gateway data path or any admit/shed/allow/
    block decision, and asserts nothing about live traffic. A covered reference technique is a LEAD, never a
    block."""

    __slots__ = ("_coverage", "_mirror", "_reference", "_redact")

    def __init__(self, coverage_meter: "DetectionCoverageMeter", mirror_meter: "DetectionMirrorMeter", *,
                 reference: Sequence[str] = REFERENCE_TECHNIQUES,
                 redact_literals: "tuple[str, ...]" = ()) -> None:
        self._coverage = coverage_meter
        self._mirror = mirror_meter
        # the reference set, read ONCE at construction into an immutable, sorted, de-duplicated, bounded tuple
        # (the meter holds no mutable state).
        self._reference = tuple(sorted({str(t) for t in reference}))[:_MAX_REFERENCE]
        self._redact = tuple(lit for lit in redact_literals if lit)

    def _is_clean(self, tokens: Sequence[str]) -> bool:
        """The AS-2e hygiene VERDICT over the surfaced labels (True ⇒ no raw IP, no configured secret literal).
        Reaches the AS-2e gate by a LAZY RELATIVE import, never re-implemented. The reference / covered /
        missing labels are fixed address-free technique names, so this is a belt over the composed verdicts."""
        from .monitoring_event_v2 import is_hygiene_clean  # relative, lazy, off the eager import plane (FATAL-2)
        return is_hygiene_clean(_canonical(sorted(set(tokens))), redact_literals=self._redact)

    def summary(self) -> BenchmarkEarly:
        """Compute the current early-benchmark measurement. Reads the AS-8 coverage summary and the AS-31 mirror
        summary (both read-only, pure functions of their injected ledger + corpus + inventory) and scores the
        admissible covered techniques against the fixed reference set. Read-only throughout; never mutates a
        source.

        Credits reference coverage ONLY over admissible content (``admissible`` is the AS-8 measure's own AS-7b
        verdict); over inadmissible content it covers nothing of the reference (fail closed). The efficacy is
        integer basis points, floor, no float. Pure: a function of the two summaries and the reference set,
        mutating nothing."""
        cov = self._coverage.summary()   # AS-8 coverage (embeds the AS-7b admissibility verdict)
        mir = self._mirror.summary()     # AS-31 reflection (embeds the AS-7b admissibility verdict + AS-30)
        admissible = bool(cov.admissible)
        consistent = admissible == bool(mir.content_admissible)

        covered_all: "set[str]" = set(cov.techniques) if admissible else set()
        reference = self._reference
        covered = tuple(t for t in reference if t in covered_all)       # reference is sorted ⇒ covered is sorted
        missing = tuple(t for t in reference if t not in covered_all)
        ref_n = len(reference)
        covered_n = len(covered)
        efficacy_bps = (covered_n * 10000 // ref_n) if ref_n else 0
        reflected_leads = int(mir.lead_count)
        sources = int(mir.source_count)
        clean = (bool(cov.clean) and bool(mir.clean)
                 and self._is_clean(tuple(reference) + covered + missing))
        return BenchmarkEarly(
            admissible=admissible,
            consistent=consistent,
            reference=reference,
            reference_count=ref_n,
            covered=covered,
            covered_count=covered_n,
            missing=missing,
            missing_count=len(missing),
            efficacy_bps=efficacy_bps,
            sources=sources,
            reflected_leads=reflected_leads,
            digest=benchmark_digest(admissible, reference, covered, efficacy_bps, reflected_leads, sources),
            clean=clean,
        )

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the early-benchmark measurement for an offline consumer: the
        content-admissibility bit, the reference set, the covered / missing reference techniques, the integer
        efficacy, the AS-31 live-posture cross-check, the posture digest and the hygiene verdict. Carries counts
        + labels + a digest, NO request bytes and NO secret, mirroring the AS-5a/5d/5e/5b/7b/8/31 snapshots."""
        return self.summary().to_dict()


def benchmark_early_snapshot(meter: "BenchmarkEarlyMeter") -> "dict[str, object]":
    """The armed-gated read-only snapshot. Returns a byte-identical inert no-op (``{}``) UNLESS the early
    benchmark's own ``VIGIL_AEGIS_BENCHMARK`` flag AND every dependency flag are armed (see
    :func:`benchmark_armed`); only then does it read the composed meters and return the measurement. OFF (or any
    dep off) ⇒ the composed meters are never consulted and the result is ``{}`` regardless of configuration, so
    an unarmed benchmark is structurally a no-op. The arming gate is the ONLY environment read on this path."""
    if not benchmark_armed():
        return {}
    return meter.snapshot()
