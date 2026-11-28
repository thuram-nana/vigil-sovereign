"""aegis.incidents, AS-11a: the deterministic read-only DETECTION-LEAD CORRELATION into INCIDENT records.

AS-31 reflects the detection posture (which detection sources are cataloged, whether the detection content is
supply-chain admissible, and which detection LEADS that content raises); AS-8 classifies each admissible lead into
its canonical CRS detection TECHNIQUE; AS-5b rolls the gateway's denied-enforcement load up by SOURCE. An operator
reading those three has one honest question no single slice answers: *of the admissible detection leads my content
raises, which ones CORRELATE, how do they group into a small, bounded set of INCIDENT records by the technique they
exercise, how much recurrence backs each, and under what denial-source pressure are they observed, surfaced
read-only, as a correlation I can read and attest, never as something that acts?*

AS-11a answers exactly that, and NOTHING more. It is a deterministic, READ-ONLY CORRELATION: over the AS-31 mirror's
admissible reflected leads (reached by COMPOSITION, never re-reflected), it groups correlated leads, keyed by their
AS-8 detection TECHNIQUE (reached by a LAZY RELATIVE import of the AS-8 band classifier, never re-implemented), into
a bounded, address-free, de-duplicated set of INCIDENT records over a recency WINDOW, each carrying its distinct
leads, its contributing detection sources, a recurrence weight, and a deterministic incident id, with a
deterministic posture digest over the whole set. When an AS-5b denial-source rollup is also armed, its aggregate
denial pressure is carried beside the incidents as read-only CONTEXT.

HONEST LIMIT (stated plainly, not papered over): an AS-5d receipt carries no caller key and a detection lead carries
no caller, so there is NO join key between the AS-5b per-source denial pressure and a correlated incident. AS-11a
therefore carries the AS-5b pressure as an AGGREGATE context annotation BESIDE the incident set (the denial pressure
under which these incidents were observed), never joined to a specific incident. It is the most the chain's data
honestly supports: a correlation of leads by technique, paired with the denied-load pressure as context, not a
per-incident denial attribution.

Doctrine (non-negotiable, enforced here and tested, the identical bar as AS-5d/5e/5b/7b/8/31):
  * A CORRELATION CORRELATES, IT NEVER ACTS. An incident is a correlated GROUPING of detection LEADS; it is NEVER a
    block, a verdict, a certificate, or a response action. Grouping leads into an incident NEVER mutates any
    ledger / inventory / corpus, and is NEVER a cause of, nor an input to, any admit/shed/allow/block decision. A
    correlated incident is a LEAD, never a block, only a fired oracle blocks.
  * READ-ONLY OVER ITS SOURCES. :meth:`summary` only READS the injected AS-31 mirror (which itself only reads the
    AS-30 inventory + the AS-7b meter) and, when present, the AS-5b rollup; it writes nothing back. Any number of
    correlations leave every source byte-identical.
  * DETERMINISM. The correlation is a pure function of (the admissible reflected leads, their AS-8 technique, the
    window bound): no wall-clock and no RNG, the incident set and the posture digest are byte-identical under
    identical inputs, so a correlation re-verifies offline. (The optional AS-5b pressure is live CONTEXT and is
    kept OUT of the digest, so the content-addressed digest stays deterministic.)
  * FAIL-CLOSED. Over INADMISSIBLE (unlicensed / unpinned / drifted) content the mirror reflects NO leads, so
    AS-11a correlates NOTHING (no incidents). An empty intake, or an UNARMED dependency (the mirror inert), yields
    an empty incident set. Unverified detection content raises no incident.
  * ADDRESS-FREE + BOUNDED + NO-LEAK. Every surfaced token is a fixed technique label, a scrubbed CRS rule-id, an
    opaque AS-30 source id, or a count, NEVER a client address, a request URI/body, or matched data. The leads
    reuse the AS-7b normalize discipline (bounded, sorted, de-duplicated, via the mirror) AND pass the AS-2e
    hygiene gate (a dotted-quad that survives the AS-7b charset scrub is DROPPED before it is ever correlated). The
    incident set is bounded (the recency window, the incident count, and the per-incident lead/source counts), so
    neither a flood of distinct leads nor a malformed corpus can bloat the read-only surface.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_INCIDENTS`` flag is set AND its
dependency, the AS-31 detection mirror (``VIGIL_AEGIS_DETECTION_MIRROR``, which itself needs the AS-7b Coraza
attestation armed over a configured CRS corpus), is armed (there are no admissible reflected leads to correlate
otherwise). The AS-8 band classifier is a flagless pure function, so there is no further hard dep flag to arm; the
AS-5b rollup is an OPTIONAL enrichment, surfaced only when it is itself armed. OFF (or the AS-31 dep off) => the
gateway builds no meter, computes nothing, and its data path AND the AS-5c probe snapshot are byte-identical.

FATAL-2: engine leg, imports ONLY the stdlib at module scope. It reaches the AS-8 technique classifier and the
AS-2e hygiene gate by LAZY RELATIVE import, consuming their results by composition, and reaches the AS-31 mirror
and the AS-5b rollup by INJECTION (type-only relative imports under ``TYPE_CHECKING``), so it NEVER re-implements
any of them. No ``vigil_core``, no ``sigil``/``governor``/``strix``/``apps``: nothing on the scan/engage/benchmark
gate path. It adds NO OracleKind, NO fleet WorkerKind, and registers NO vocabulary, so the make-gate byte-identity
is structurally untouched. Kept OFF the eager ``aegis/__init__`` / ``__main__`` import plane by a lazy relative
import at the gateway (mirroring ``detection_mirror`` / ``detection_coverage``), so ``make gate`` / closure stays
byte-identical.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # relative, type-only, never executed at runtime (keeps the module stdlib-only at import)
    from .attribution import AttributionMeter
    from .detection_mirror import DetectionMirrorMeter

__all__ = [
    "INCIDENTS_ENV",
    "Incident",
    "IncidentMeter",
    "IncidentPosture",
    "incidents_enabled",
    "posture_digest",
]

# The default-OFF switch for the detection-lead correlation, strict, fail-closed, read when the gateway is built and
# re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit affirmative token turns it
# on; anything else (unset, typo, "0", "false") keeps it OFF, mirrors ``detection_mirror.detection_mirror_enabled``
# / ``detection_coverage.coverage_enabled`` / ``attribution.attribution_enabled`` exactly.
INCIDENTS_ENV = "VIGIL_AEGIS_INCIDENTS"

# Bound the recency WINDOW (how many correlation observations are retained), the surfaced INCIDENT set, and the
# per-incident lead / source lists so neither a flood of distinct leads nor a malformed corpus can bloat the
# read-only correlation surface. (The AS-31 mirror already bounds the reflected lead set, so these are
# belt-and-suspenders upper limits.)
_MAX_WINDOW = 256
_MAX_INCIDENTS = 64
_MAX_LEADS = 64
_MAX_SOURCES = 64


def incidents_enabled() -> bool:
    """Is the AS-11a detection-lead correlation armed? Strict, fail-closed, DEFAULT OFF, only an explicit affirmative
    token arms it (mirrors ``detection_mirror.detection_mirror_enabled`` / ``detection_coverage.coverage_enabled``).
    The gateway still builds a meter only when this is True AND the AS-31 detection mirror (its dependency) was
    itself built."""
    return (os.environ.get(INCIDENTS_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _canonical(obj: Any) -> str:
    """A deterministic canonical JSON encoding (sorted keys, no insignificant whitespace, ASCII). The byte basis for
    the posture digest, stdlib only, no wall-clock, no RNG, so the same correlation posture always digests the same
    way (the identical canonical form AS-7b / AS-8 / AS-31 use for their pins / digests)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _technique(lead: str) -> str:
    """Classify ONE admissible lead into its detection TECHNIQUE by the AS-8 canonical CRS band taxonomy. Reaches the
    AS-8 classifier by a LAZY RELATIVE import (off this module's import-time plane, FATAL-2) and NEVER
    re-implements the banding, the technique is AS-8's own ``crs_technique`` verdict."""
    from .detection_coverage import crs_technique  # relative, lazy, off the eager import plane (FATAL-2)
    return crs_technique(lead)


def posture_digest(admissible: bool, incidents: "Sequence[Incident]") -> str:
    """A deterministic sha256 over the correlated incident posture (the content-admissibility bit, and the sorted
    per-incident correlation key / distinct leads / contributing sources / recurrence weight). Pure, stdlib only, no
    wall-clock, no RNG. The content flipping (in)admissible, an incident gained/lost, a lead or source changing, or
    a recurrence weight moving changes the digest: the tamper/drift-evidence for the correlation posture. The
    optional AS-5b denial pressure is live CONTEXT and is deliberately OUT of this digest."""
    payload = {
        "admissible": bool(admissible),
        "incidents": [
            {
                "key": inc.key,
                "leads": sorted({str(x) for x in inc.leads}),
                "sources": sorted({str(x) for x in inc.sources}),
                "weight": int(inc.weight),
            }
            for inc in sorted(incidents, key=lambda i: i.key)
        ],
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _incident_digest(key: str, leads: "Sequence[str]", sources: "Sequence[str]") -> str:
    """A deterministic sha256 incident id over the correlated grouping (the technique key, the distinct leads, the
    contributing sources). Pure, stdlib only, no wall-clock, no RNG, so the SAME correlated grouping always carries
    the SAME id across consecutive snapshots (stable cross-snapshot correlation without an address)."""
    payload = {
        "key": str(key),
        "leads": sorted({str(x) for x in leads}),
        "sources": sorted({str(x) for x in sources}),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Incident:
    """ONE immutable, read-only correlated incident, a deduplicated grouping of detection LEADS that share a
    correlation KEY. Metadata only, labels + scrubbed ids + counts + a digest, never a client address, request
    bytes, or a secret.

    * ``key``        the correlation key: the AS-8 detection TECHNIQUE the grouped leads exercise (a fixed,
      address-free label from the CRS band taxonomy, may be ``unclassified`` for an operational band).
    * ``leads``      the sorted, de-duplicated, bounded CRS rule-ids correlated into this incident (address-free,
      AS-7b-normalized through the mirror, AS-2e hygiene-clean).
    * ``lead_count`` the number of distinct leads in this incident.
    * ``sources``    the sorted, de-duplicated, bounded detection SOURCE ids (AS-30 provider ids) that raised these
      leads, ``()`` for a content-derived correlation (a content lead is tied to no observed source).
    * ``weight``     the recurrence weight: how many correlation observations (source x lead) backed this incident
      over the window (distinct-lead count for a content-derived correlation; >= lead_count when leads recur).
    * ``digest``     the deterministic incident id over (key, leads, sources) (see :func:`_incident_digest`)."""

    key: str
    leads: tuple[str, ...]
    lead_count: int
    sources: tuple[str, ...]
    weight: int
    digest: str

    def to_dict(self) -> "dict[str, object]":
        return {
            "key": self.key,
            "leads": list(self.leads),
            "lead_count": self.lead_count,
            "sources": list(self.sources),
            "weight": self.weight,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class IncidentPosture:
    """ONE immutable, read-only correlation posture, the bounded, de-duplicated set of correlated incidents over the
    window. Metadata only, no client address, no secret.

    * ``admissible``       the AS-31 / AS-7b verdict: the detection content is licence-admitted AND pinned. False =>
      the mirror reflects no leads => NO incidents (fail closed).
    * ``incidents``        the bounded (top-``_MAX_INCIDENTS``), de-duplicated incidents, sorted by key.
    * ``incident_count``   the number of correlated incidents surfaced.
    * ``lead_count``       the total distinct leads correlated across all incidents.
    * ``observations``     the total correlation observations in the window (the sum of the incident weights).
    * ``window``           the recency-window bound applied to the correlation (a flood of observations cannot
      bloat the surface past this many).
    * ``sources``          the detection SOURCE context: the cataloged AS-30 provider ids a content-derived
      correlation reflects, or the union of observed sources, sorted / de-duplicated / bounded.
    * ``pressure``         the OPTIONAL AS-5b denial-source context (concentration, constrained, tracked, verified),
      or ``None`` when no AS-5b rollup is armed. An AGGREGATE annotation BESIDE the incidents, never joined to one
      (an incident carries no caller key, see the module HONEST LIMIT). Live CONTEXT, kept OUT of ``digest``.
    * ``digest``           the deterministic content digest of the correlation posture (:func:`posture_digest`).
    * ``clean``            the AS-2e hygiene verdict over the surfaced body: True => it carries no raw IP and no
      configured secret literal. A measurement only, it NEVER drives a decision."""

    admissible: bool
    incidents: tuple[Incident, ...]
    incident_count: int
    lead_count: int
    observations: int
    window: int
    sources: tuple[str, ...]
    digest: str
    clean: bool
    pressure: "dict[str, object] | None" = field(default=None)

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        out: "dict[str, object]" = {
            "admissible": self.admissible,
            "incidents": [inc.to_dict() for inc in self.incidents],
            "incident_count": self.incident_count,
            "lead_count": self.lead_count,
            "observations": self.observations,
            "window": self.window,
            "sources": list(self.sources),
            "digest": self.digest,
            "clean": self.clean,
        }
        if self.pressure is not None:
            out["pressure"] = dict(self.pressure)
        return out


class IncidentMeter:
    """The read-only detection-lead correlation, bound to an AS-31 detection mirror (the admissible reflected LEADS)
    and, optionally, an AS-5b denial-source rollup (aggregate denial pressure CONTEXT). Holds NO mutable state, it
    reads the (immutable) injected sources per :meth:`summary` / :meth:`correlate` (the mirror itself only reads the
    AS-30 inventory + the AS-7b ledger + corpus), so it is inherently thread-safe and NEVER mutates the inventory,
    the licence ledger, or the corpus.

    The meter CORRELATES; it never acts: :meth:`summary` groups the mirror's admissible reflected content leads into
    incidents by their AS-8 technique, :meth:`correlate` groups a window of OBSERVED detection hits the same way
    (reflecting each hit through the AS-31 gate, fail-closed). It is surfaced read-only on the AS-5c probe snapshot
    and never touches the gateway data path or any admit/shed/allow/block decision. A correlated incident is a LEAD,
    never a block."""

    __slots__ = ("_attribution", "_mirror", "_redact", "_window")

    def __init__(self, mirror_meter: "DetectionMirrorMeter", *,
                 attribution_meter: "AttributionMeter | None" = None,
                 redact_literals: "tuple[str, ...]" = (), window: int = _MAX_WINDOW) -> None:
        self._mirror = mirror_meter
        self._attribution = attribution_meter
        self._redact = tuple(lit for lit in redact_literals if lit)
        # Clamp the recency-window bound to a sane positive upper limit (a caller cannot widen it past the
        # structural cap, nor make it non-positive).
        self._window = max(1, min(int(window), _MAX_WINDOW))

    # ----------------------------------------------------------------------------------------------
    # The AS-2e fail-closed leak gate, reused (never re-implemented) exactly as the siblings do.
    # ----------------------------------------------------------------------------------------------
    def _drop_leaky(self, lead: str) -> bool:
        """True IFF a token must be DROPPED by the AS-2e leak gate: it still carries a raw IP (the AS-7b
        address-free charset keeps digits and ``.``, so a dotted-quad survives its scrub) or a configured secret
        literal. Reaches the AS-2e hygiene primitive by a LAZY RELATIVE import, never re-implemented."""
        from .monitoring_event_v2 import contains_raw_ip  # relative, lazy, off the eager import plane (FATAL-2)
        if contains_raw_ip(lead):
            return True
        return any(lit in lead for lit in self._redact)

    def _is_clean(self, body: str) -> bool:
        """The AS-2e hygiene VERDICT over the surfaced correlation body (True => no raw IP, no configured secret
        literal). Reaches the AS-2e gate by a LAZY RELATIVE import, never re-implemented."""
        from .monitoring_event_v2 import is_hygiene_clean  # relative, lazy, off the eager import plane (FATAL-2)
        return is_hygiene_clean(body, redact_literals=self._redact)

    def _pressure(self) -> "dict[str, object] | None":
        """The OPTIONAL AS-5b denial-source CONTEXT: the aggregate concentration / constrained / tracked / verified
        the AS-5b rollup reports, read-only. ``None`` when no AS-5b rollup is injected. An aggregate annotation
        BESIDE the incidents, never joined to one (an incident carries no caller key). Total / fail-safe: a rollup
        read fault degrades this one annotation to ``None``, never the correlation."""
        attrib = self._attribution
        if attrib is None:
            return None
        try:
            s = attrib.summary()
            return {
                "concentration": s.concentration,
                "constrained": int(s.constrained),
                "tracked": int(s.tracked),
                "verified": bool(s.verified),
            }
        except Exception:
            return None

    # ----------------------------------------------------------------------------------------------
    # The pure correlation core. A function of (pairs, admissibility, catalog, window) only.
    # ----------------------------------------------------------------------------------------------
    def _correlate(self, pairs: "Sequence[tuple[str, str]]", *, admissible: bool,
                   catalog: "Sequence[str]") -> IncidentPosture:
        """Group correlation observations (source, lead) pairs into a bounded, de-duplicated INCIDENT set keyed by
        the AS-8 technique. PURE, a function of its inputs, mutating nothing. Fail-closed: over inadmissible content
        (``admissible`` False) the pairs are ignored and the incident set is empty.

        The correlation CORRELATES; it never acts. Each incident is a grouping of LEADS, never a block or a verdict."""
        catalog_ids = tuple(sorted({str(c) for c in catalog if c})[:_MAX_SOURCES])
        if not admissible:
            # Inadmissible content raises no leads => no incidents (fail closed), but a well-formed empty posture.
            digest = posture_digest(False, ())
            return IncidentPosture(
                admissible=False, incidents=(), incident_count=0, lead_count=0, observations=0,
                window=self._window, sources=catalog_ids, digest=digest, clean=True, pressure=self._pressure(),
            )
        # The recency WINDOW: retain only the last ``self._window`` observations (a flood cannot bloat the surface).
        windowed = list(pairs)[-self._window:]
        # Group by the AS-8 technique: distinct leads, distinct sources, and a recurrence weight per technique.
        leads_by_key: "dict[str, set[str]]" = {}
        sources_by_key: "dict[str, set[str]]" = {}
        weight_by_key: "dict[str, int]" = {}
        for source, lead in windowed:
            tok = str(lead)
            if not tok or self._drop_leaky(tok):          # the AS-2e leak gate, drop a leaky/empty lead
                continue
            key = _technique(tok)                         # the AS-8 correlation key, never re-implemented
            leads_by_key.setdefault(key, set()).add(tok)
            src = str(source)
            if src:
                sources_by_key.setdefault(key, set()).add(src)
            weight_by_key[key] = weight_by_key.get(key, 0) + 1
        incidents: list[Incident] = []
        for key in sorted(leads_by_key):
            leads = tuple(sorted(leads_by_key[key])[:_MAX_LEADS])
            srcs = tuple(sorted(sources_by_key.get(key, set()))[:_MAX_SOURCES])
            incidents.append(Incident(
                key=key, leads=leads, lead_count=len(leads), sources=srcs,
                weight=int(weight_by_key.get(key, 0)), digest=_incident_digest(key, leads, srcs),
            ))
        incidents = incidents[:_MAX_INCIDENTS]
        inc_tuple = tuple(incidents)
        lead_total = len({lead for inc in inc_tuple for lead in inc.leads})
        obs_total = sum(inc.weight for inc in inc_tuple)
        digest = posture_digest(True, inc_tuple)
        body = _canonical([inc.to_dict() for inc in inc_tuple] + [list(catalog_ids)])
        clean = self._is_clean(body)
        return IncidentPosture(
            admissible=True, incidents=inc_tuple, incident_count=len(inc_tuple), lead_count=lead_total,
            observations=obs_total, window=self._window, sources=catalog_ids, digest=digest, clean=clean,
            pressure=self._pressure(),
        )

    # ----------------------------------------------------------------------------------------------
    # The two correlation entrypoints: content-derived (the probe surface) and observed-window.
    # ----------------------------------------------------------------------------------------------
    def summary(self) -> IncidentPosture:
        """Correlate the AS-31 mirror's admissible reflected CONTENT leads (the enforced CRS rule-ids admitted
        through the AS-7b gate) into incidents keyed by their AS-8 technique. Read-only throughout: it READS the
        mirror's reflection (a pure function of the injected inventory + ledger + corpus) and groups it, never
        mutates a source. Fail-closed: over inadmissible content the mirror reflects no leads => no incidents.

        This is the probe surface. A content lead is tied to no observed source, so each incident's ``sources`` is
        ``()`` and the posture ``sources`` carries the cataloged AS-30 detection sources the mirror reflects."""
        mir = self._mirror.summary()
        admissible = bool(getattr(mir, "content_admissible", False))
        leads = tuple(getattr(mir, "leads", ()) or ())
        catalog = tuple(getattr(mir, "sources", ()) or ())
        pairs = [("", lead) for lead in leads]
        return self._correlate(pairs, admissible=admissible, catalog=catalog)

    def correlate(self, observations: "Sequence[tuple[str, Sequence[str]]]") -> IncidentPosture:
        """Correlate a WINDOW of OBSERVED detection hits into incidents. Each observation is a ``(source,
        rule_refs)`` hit; it is reflected through the AS-31 mirror (fail-closed: an uncataloged source or
        inadmissible content yields no leads, so it contributes no correlation), and the admitted leads are grouped
        by their AS-8 technique, WITH their observed source attributed per incident. Pure + read-only, a function of
        its inputs and the current attestation, mutating nothing.

        Only the last ``window`` observations are retained (the recency bound). A correlated incident is a LEAD,
        never a block (only a fired oracle blocks) and takes no response action."""
        obs = list(observations)[-self._window:]
        admissible = bool(getattr(self._mirror.summary(), "content_admissible", False))
        pairs: list[tuple[str, str]] = []
        observed_sources: set[str] = set()
        for source, rule_refs in obs:
            src = str(source)
            leads = self._mirror.reflect(src, list(rule_refs))   # the AS-31 fail-closed admission gate
            if not leads:
                continue
            observed_sources.add(src)
            for lead in leads:
                pairs.append((src, lead))
        return self._correlate(pairs, admissible=admissible, catalog=tuple(sorted(observed_sources)))

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the detection-lead correlation for the AS-5c probe surface: the
        content-admissibility bit, the bounded de-duplicated incident set (each with its correlation key, distinct
        leads, contributing sources, recurrence weight and incident id), the detection source context, the optional
        AS-5b denial-pressure context, the posture digest and the hygiene verdict. Carries labels + scrubbed ids +
        counts + a digest, NO request bytes and NO secret, mirroring the AS-5a/5d/5e/5b/7b/8/31 snapshots."""
        return self.summary().to_dict()
