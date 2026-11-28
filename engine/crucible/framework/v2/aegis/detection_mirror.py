"""aegis.detection_mirror — AS-31: the deterministic read-only DETECTION MIRROR.

AEGIS runs several DETECTION surfaces, each merged separately: the AS-30 telemetry-provider runtime catalogs the
detection SOURCES (the EDR / CloudTrail / IdP providers, each class-5 ``detected_without_enforcement`` / ``reported``
— they OBSERVE and ALERT, they never prevent), and the AS-7b Coraza/CRS front-WAF supply-chain attestation gates
whether the detection CONTENT those sources reference (the ``coreruleset-crs-4x`` rule corpus, over the ``coraza-v3``
engine) is admissible — licence-admitted AND pinned. An operator running a firewall in front of their own app has
one honest question no single slice answers: *what is my detection posture right now — which detection sources are
cataloged, is the detection content I run supply-chain admissible, and which detection leads would that content
raise — surfaced read-only, as a reflected view I can read and attest, never as something that acts?*

AS-31 answers exactly that, and NOTHING more. It is a deterministic, READ-ONLY DETECTION MIRROR: a reflected,
metadata-only view that UNIFIES its three merged dependencies —

  * AS-30 provider runtime (the detection SOURCE catalog). ``build_provider_runtime_registry`` is the PURE,
    append-only inventory of telemetry-detection providers; the mirror reflects its sorted, bounded provider-id
    catalog as the admissible detection SOURCES. It is the gate for :meth:`reflect`: a detection hit whose source
    is NOT a cataloged provider is DROPPED (an uncataloged source raises no belief). Reached by a LAZY RELATIVE
    import, never re-implemented.
  * AS-7b Coraza/CRS attestation (the detection CONTENT admissibility). ``CorazaAttestation.admissible`` says
    whether the front-WAF detection content is licence-admitted AND pinned; ``admit_rule_refs`` admits a Coraza
    DetectionOnly hit's ``rule_refs`` as a LEAD only over an admissible corpus (address-free, bounded, sorted,
    de-duplicated), and DROPS them fail-closed otherwise. The mirror reflects the admissible detection CONTENT
    (the enforced CRS rule-ids admitted through that gate) and uses the gate for every lead it reflects. Reached
    by a LAZY RELATIVE import, never re-implemented.
  * AS-3b v2 emission (the AS-2e OUTPUT HYGIENE). ``is_hygiene_clean`` / ``contains_raw_ip`` is the fail-closed
    leak gate the v2 emitter runs over an about-to-be-emitted body: a token that still carries a raw IP (AS-7b's
    address-free charset keeps ``0-9`` and ``.`` — a dotted-quad survives its scrub) or a configured secret literal
    is DROPPED, so a leak is never mirrored. Reached by a LAZY RELATIVE import, never re-implemented.

Doctrine (non-negotiable, enforced here and tested — the identical bar as AS-5d/5e/5b/7b):
  * A MIRROR REFLECTS, IT NEVER ACTS. The mirror reports the detection posture (sources · content admissibility ·
    the admissible leads); it NEVER mutates the provider inventory, the licence ledger, the corpus, or any state,
    and is NEVER a cause of, nor an input to, any admit/shed/allow/block decision. A mirrored detection hit is a
    LEAD, never a block — only a fired oracle blocks.
  * READ-ONLY OVER ITS SOURCES. :meth:`summary` only READS the injected inventory + the AS-7b meter (which itself
    only reads its ledger + corpus); it writes nothing back. Any number of reflections leave every source
    byte-identical.
  * DETERMINISM. Pure functions of (inventory, attestation, content, reflected refs): no wall-clock and no RNG —
    the mirror digest and the reflected leads are byte-identical under identical inputs, so a posture can be
    attested and re-verified offline.
  * FAIL-CLOSED. A detection hit from an UNCATALOGED source, or over INADMISSIBLE (unlicensed / unpinned / drifted)
    content, raises NO lead (``()``). Unverified detection content never raises belief.
  * ADDRESS-FREE + BOUNDED + NO-LEAK. Every surfaced token is a scrubbed provider-id or CRS rule-id — NEVER a
    client address, a request URI/body, or matched data. The leads reuse AS-7b's normalize discipline (bounded,
    sorted, de-duplicated) AND pass AS-3b's hygiene gate (a dotted-quad that survives the charset scrub is DROPPED).
    The mirror carries counts + a digest, never request bytes and never a secret.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_DETECTION_MIRROR`` flag is set AND its
underlying dependency — the AS-7b Coraza attestation (``VIGIL_AEGIS_CORAZA``, which itself needs a configured CRS
corpus) — is armed (there is no detection content to mirror otherwise; the AS-30 inventory and the AS-3b hygiene
gate are flagless pure functions, so there is no further dep flag to arm). OFF (or the AS-7b dep off) ⇒ the gateway
builds no meter, computes nothing, and its data path AND the AS-5c probe snapshot are byte-identical.

FATAL-2: engine leg — imports ONLY the stdlib at module scope. It reaches the AS-30 provider inventory, the AS-7b
Coraza admit gate, and the AS-3b hygiene gate by LAZY RELATIVE import, consuming their results by composition, so it
NEVER re-implements any of them. No ``vigil_core``, no ``sigil``/``governor``/``strix``/``apps`` — nothing on the
scan/engage/benchmark gate path. It adds NO OracleKind, NO fleet WorkerKind, and registers NO vocabulary, so the
make-gate byte-identity is structurally untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # relative, type-only — never executed at runtime (keeps the module stdlib-only at import)
    from .coraza_source import CorazaAttestationMeter

__all__ = [
    "DETECTION_MIRROR_ENV",
    "DetectionMirror",
    "DetectionMirrorMeter",
    "detection_mirror_enabled",
    "mirror_digest",
]

# The default-OFF switch for the detection-mirror reflection — strict, fail-closed, read when the gateway is built
# and re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit affirmative token turns
# it on; anything else (unset, typo, "0", "false") keeps it OFF — mirrors ``coraza_source.coraza_enabled`` /
# ``impact_budget.impact_budget_enabled`` / ``attribution.attribution_enabled`` exactly.
DETECTION_MIRROR_ENV = "VIGIL_AEGIS_DETECTION_MIRROR"

# Bound the reflected detection SOURCE catalog and the reflected LEAD set so neither the (append-only) provider
# inventory nor a flood of distinct rule-ids can bloat the read-only mirror surface.
_MAX_SOURCES = 64
_MAX_LEADS = 64


def detection_mirror_enabled() -> bool:
    """Is the detection mirror armed? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative token arms it
    (mirrors ``coraza_source.coraza_enabled`` / ``attribution.attribution_enabled``). The gateway still builds a
    meter only when this is True AND the AS-7b Coraza attestation (its dependency) was itself built."""
    return (os.environ.get(DETECTION_MIRROR_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _canonical(obj: Any) -> str:
    """A deterministic canonical JSON encoding (sorted keys, no insignificant whitespace, ASCII). The byte basis
    for the mirror digest — stdlib only, no wall-clock, no RNG, so the same posture always reflects to the same
    digest."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def mirror_digest(sources: Sequence[str], content_admissible: bool, leads: Sequence[str]) -> str:
    """A deterministic sha256 over the reflected detection posture (the sorted/de-duplicated source catalog · the
    content-admissibility bit · the sorted/de-duplicated admissible leads). Pure — stdlib only, no wall-clock, no
    RNG. A source added/removed, the content flipping (in)admissible, or a lead changing moves the digest: the
    tamper/drift-evidence for the reflected posture."""
    payload = {
        "sources": sorted({str(s) for s in sources}),
        "content_admissible": bool(content_admissible),
        "leads": sorted({str(r) for r in leads}),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DetectionMirror:
    """ONE immutable, read-only reflection of the detection posture. Metadata only — counts + tokens + a digest,
    never a client address, request bytes, or a secret.

    * ``sources``            — the cataloged detection SOURCE ids (the AS-30 provider inventory), sorted,
      de-duplicated and bounded. Address-free opaque catalog names (``edr`` / ``cloudtrail`` / ``idp`` / ...).
    * ``source_count``       — the number of cataloged detection sources.
    * ``content_admissible`` — the AS-7b verdict: the front-WAF detection content is licence-admitted AND pinned.
      False ⇒ inadmissible content (unlicensed / unpinned / drifted) — NO leads are reflected (fail closed).
    * ``leads``              — the admissible detection CONTENT leads (the enforced CRS rule-ids admitted through
      the AS-7b gate), address-free, bounded, sorted, de-duplicated, AND hygiene-clean (a dotted-quad that survives
      the AS-7b charset scrub is DROPPED by the AS-3b gate). ``()`` over inadmissible content.
    * ``lead_count``         — the number of admissible detection leads reflected.
    * ``digest``             — the deterministic content digest of the reflected posture (see :func:`mirror_digest`).
    * ``clean``              — the AS-3b hygiene verdict over the reflected body: True ⇒ it carries no raw IP and no
      configured secret literal. A measurement only — it NEVER drives a decision."""

    sources: tuple[str, ...]
    source_count: int
    content_admissible: bool
    leads: tuple[str, ...]
    lead_count: int
    digest: str
    clean: bool

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        return {
            "sources": list(self.sources),
            "source_count": self.source_count,
            "content_admissible": self.content_admissible,
            "leads": list(self.leads),
            "lead_count": self.lead_count,
            "digest": self.digest,
            "clean": self.clean,
        }


class DetectionMirrorMeter:
    """The read-only detection mirror, bound to the AS-30 provider inventory (the detection SOURCE catalog), the
    AS-7b Coraza attestation meter (the detection CONTENT admissibility gate), and the enforced detection content
    (the CRS rule-ids). Holds NO mutable state — it reads the (immutable) injected inventory ids once at
    construction and, per :meth:`summary`, reads the AS-7b meter (which itself only reads its ledger + corpus), so
    it is inherently thread-safe and NEVER mutates the inventory, the licence ledger, the corpus, or any state.

    The meter REFLECTS; it never acts: :meth:`summary` reports the detection posture, :meth:`reflect` admits one
    observed detection hit into a mirrored LEAD (source-cataloged AND content-admissible, else ``()``). It is
    surfaced read-only on the AS-5c probe snapshot and never touches the gateway data path or any
    admit/shed/allow/block decision. A mirrored detection hit is a LEAD, never a block."""

    __slots__ = ("_coraza", "_content_refs", "_redact", "_source_ids")

    def __init__(self, coraza_meter: "CorazaAttestationMeter", content_refs: Sequence[str], *,
                 inventory: Any = None, redact_literals: "tuple[str, ...]" = ()) -> None:
        self._coraza = coraza_meter
        self._content_refs = tuple(str(r) for r in content_refs)
        self._redact = tuple(lit for lit in redact_literals if lit)
        # The detection SOURCE catalog — read ONCE at construction into an immutable tuple (the mirror holds no
        # mutable state). ``inventory`` is an injected AS-30 ``ProviderRegistry`` (tested offline); default: the
        # PURE append-only runtime inventory, reached by a LAZY RELATIVE import (off the eager __init__/__main__
        # import plane — FATAL-2). Building a catalog opens nothing and needs no flag (AS-30 doctrine).
        reg = inventory
        if reg is None:
            from .provider_runtime import build_provider_runtime_registry  # relative, lazy — off the eager plane
            reg = build_provider_runtime_registry()
        ids = sorted({str(pid) for pid in getattr(reg, "provider_ids", ())})
        self._source_ids = tuple(ids[:_MAX_SOURCES])

    def _hygienic(self, refs: Sequence[str]) -> tuple[str, ...]:
        """The AS-3b fail-closed LEAK gate: DROP any token that still carries a raw IP (AS-7b's address-free charset
        keeps digits and ``.``, so a dotted-quad survives its scrub) or a configured secret literal. Reaches the
        AS-2e hygiene primitive by a LAZY RELATIVE import, never re-implemented."""
        from .monitoring_event_v2 import contains_raw_ip  # relative, lazy — off the eager import plane (FATAL-2)
        out: list[str] = []
        for tok in refs:
            if contains_raw_ip(tok):
                continue
            if any(lit in tok for lit in self._redact):
                continue
            out.append(tok)
        return tuple(out[:_MAX_LEADS])

    def reflect(self, source: str, rule_refs: Sequence[str]) -> tuple[str, ...]:
        """Reflect ONE observed detection hit — a set of ``rule_refs`` from a named detection ``source`` — into a
        mirrored LEAD. Fail-closed: returns ``()`` unless the ``source`` is a CATALOGED detection provider (AS-30)
        AND the detection content is ADMISSIBLE (AS-7b); each surviving ref is normalized address-free / bounded /
        sorted / de-duplicated (AS-7b) and passed through the AS-3b hygiene gate (a dotted-quad is dropped). Pure +
        read-only: a function of its inputs and the current attestation, mutating nothing.

        This is a LEAD, never a block (only a fired oracle blocks) and takes no response action: it gates whether a
        detection hit may be MIRRORED at all."""
        if str(source) not in self._source_ids:            # an uncataloged source raises no belief (fail closed)
            return ()
        from .coraza_source import admit_rule_refs           # relative, lazy — off the eager import plane (FATAL-2)
        att = self._coraza.summary()
        admitted = admit_rule_refs(rule_refs, att)          # () over inadmissible content; else normalized refs
        return self._hygienic(admitted)

    def summary(self) -> DetectionMirror:
        """Compute the current detection-posture reflection. Reads the AS-7b attestation (read-only; a pure function
        of the injected ledger + corpus) and reflects the admissible detection CONTENT (the enforced CRS rule-ids
        admitted through the AS-7b gate) over the AS-30 source catalog. Read-only throughout; never mutates a
        source.

        Reaches the AS-7b admit gate by a LAZY RELATIVE import (keeping it off this module's import-time plane and
        the eager __init__/__main__ path) and NEVER re-implements it — ``content_admissible`` is the attestation's
        own verdict, the leads are its own admit gate's output."""
        from .coraza_source import admit_rule_refs           # relative, lazy — off the eager import plane (FATAL-2)
        att = self._coraza.summary()
        admissible = bool(att.admissible)
        leads = self._hygienic(admit_rule_refs(self._content_refs, att))
        sources = self._source_ids
        clean = (not leads) or self._is_clean(leads)
        return DetectionMirror(
            sources=sources,
            source_count=len(sources),
            content_admissible=admissible,
            leads=leads,
            lead_count=len(leads),
            digest=mirror_digest(sources, admissible, leads),
            clean=clean,
        )

    def _is_clean(self, leads: Sequence[str]) -> bool:
        """The AS-3b hygiene VERDICT over the reflected leads (True ⇒ no raw IP, no configured secret literal).
        Reaches the AS-2e gate by a LAZY RELATIVE import, never re-implemented."""
        from .monitoring_event_v2 import is_hygiene_clean   # relative, lazy — off the eager import plane (FATAL-2)
        return is_hygiene_clean(_canonical(sorted(set(leads))), redact_literals=self._redact)

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the detection-posture reflection for the AS-5c probe surface: the
        cataloged detection sources, the content-admissibility bit, the admissible leads, the posture digest and the
        hygiene verdict. Carries counts + tokens + a digest, NO request bytes and NO secret — mirroring the
        AS-5a/5d/5e/5b/7b snapshots."""
        return self.summary().to_dict()
