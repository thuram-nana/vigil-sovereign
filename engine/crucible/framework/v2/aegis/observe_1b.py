"""aegis.observe_1b — AS-18a: the deterministic read-only 1b OBSERVE view.

AEGIS runs two deployment paths (CHARTER-TEMPLATE.md §3). Path 1a is the managed keyless gateway AEGIS
places inline. Path 1b is different: AEGIS consumes the tenant's OWN existing CDN/WAF (Cloudflare/CRS)
telemetry — the enforcement point stays at the tenant's edge, and AEGIS says so honestly (ADR 0004). An
operator running path 1b has one honest question: *over the findings my existing edge PUSHED me, what is
my OBSERVE posture right now — which of them raise an admissible detection lead, and how strong a claim can
I make — surfaced read-only, as a view I can read and attest, never as something that blocks?*

AS-18a is the OBSERVE leg that answers exactly that, and NOTHING more. It is a deterministic, READ-ONLY
OBSERVE-mode VIEW: it DETECTS (which received edge findings become admissible leads) and REPORTS (the
graded observe posture), and it NEVER blocks or enforces (the 1b ENFORCE leg is the separate AS-18b slice,
a later wave). It UNIFIES its three merged dependencies —

  * AS-9b receiver (the RECEIVED EVENTS). The AS-9b per-tenant ingest receiver is where a path-1b edge
    PUSHes its inert, metadata-only findings. This view reflects over those received events, reduced to the
    two opaque tokens it reflects — the detection ``source`` (an AS-30 provider id) and the edge
    ``rule_refs`` (the CRS rule-ids the tenant's edge raised). The receiver already bounds + redacts a
    finding, so the view consumes only this metadata, never a request body. An absent/empty intake raises no
    belief (fail closed).
  * AS-31 detection mirror (the REFLECTION). The AS-31 ``DetectionMirrorMeter`` is the read-only reflection
    of the detection posture (the AS-30 detection SOURCE catalog × the AS-7b detection CONTENT
    admissibility). This view reflects each received event through the injected mirror: ``reflect(source,
    refs)`` admits a hit as a LEAD only over a CATALOGED source AND ADMISSIBLE content, address-free /
    bounded / sorted / de-duplicated / hygiene-clean, and DROPS it fail-closed otherwise. The mirror is
    reached by COMPOSITION (injected), never re-implemented.
  * AS-4b contract evaluator (the GRADE). The AS-4b ``headline_floor`` is the §4.5 fail-closed grader: the
    headline is the FLOOR of its posture axes (the weakest axis caps the claim), over the Headline ladder
    unsupported < inactive < degraded < unverified < observing < enforcing. This view grades its observe
    posture through that SAME floor grader, reached by a LAZY import and never re-implemented, so the honest
    headline is AS-4b's own computation. The observe leg passes no ``enforcing`` axis, so the floor is
    STRUCTURALLY capped at ``observing`` — it can never claim enforce.

Doctrine (non-negotiable, enforced here and tested — the identical bar as AS-31/AS-7b):
  * A VIEW REFLECTS + GRADES, IT NEVER ACTS. The view reports the observe posture (the admissible leads · the
    graded headline); it NEVER mutates the inventory, the licence ledger, the corpus, the spool, or any
    state, and is NEVER a cause of, nor an input to, any admit/shed/allow/block decision. A reflected finding
    is a LEAD, never a block — only a fired oracle blocks.
  * OBSERVE ONLY. The graded headline is capped at ``observing``; the view carries no enforce/block/response
    semantics. Detect + report is the whole contract; the 1b ENFORCE leg is AS-18b.
  * READ-ONLY OVER ITS SOURCES. The view only READS the injected mirror (which itself only reads its
    inventory + its AS-7b meter) and the supplied events; it writes nothing back. Any number of views leave
    every source byte-identical.
  * DETERMINISM. Pure functions of (mirror posture, received events): no wall-clock and no RNG — the view
    digest is byte-identical under identical inputs, so a posture can be attested and re-verified offline.
  * FAIL-CLOSED. An UNCATALOGED source, INADMISSIBLE content, or an EMPTY intake raises NO lead (``()``) and
    caps the headline honestly (``degraded`` over inadmissible content, ``unsupported`` over an empty source
    catalog). Unverified detection content never raises belief.
  * ADDRESS-FREE + BOUNDED + NO-LEAK. Every surfaced token is a scrubbed CRS rule-id the AS-31 mirror already
    passed through the AS-7b normalize discipline and the AS-3b hygiene gate — NEVER a client address, a
    request URI/body, or matched data. The view carries counts + a digest, never request bytes and never a
    secret.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_OBSERVE_1B`` flag is set AND its
dependency — the AS-31 detection mirror (``VIGIL_AEGIS_DETECTION_MIRROR``, which itself needs the AS-7b
Coraza attestation + a configured CRS corpus) — is armed (there is no detection posture to observe through
otherwise; AS-4b is a flagless pure grader, so there is no further dep flag to arm). OFF (or the AS-31 dep
off) ⇒ the gateway builds no meter, computes nothing, and its data path AND the AS-5c probe snapshot are
byte-identical.

FATAL-2: engine leg — imports ONLY the stdlib at module scope. It reaches the AS-31 mirror by COMPOSITION
(an injected meter) and the AS-4b grader by a LAZY import, consuming their results, so it NEVER
re-implements either. No ``sigil``/``governor``/``strix``/``apps`` — nothing on the scan/engage/benchmark
gate path. It adds NO OracleKind, NO fleet WorkerKind, and registers NO vocabulary, so the make-gate
byte-identity is structurally untouched; it stays OFF the eager ``aegis/__init__`` / ``__main__`` import
path (reached only by a lazy import in the gateway constructor), mirroring AS-31.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Sequence

if TYPE_CHECKING:  # type-only — never executed at runtime (keeps the module stdlib-only at import)
    from .detection_mirror import DetectionMirrorMeter

__all__ = [
    "OBSERVE_1B_ENV",
    "Observe1bMeter",
    "Observe1bView",
    "ReceivedEvent",
    "observe_1b_digest",
    "observe_1b_enabled",
]

# The default-OFF switch for the 1b observe view — strict, fail-closed, read when the gateway is built and
# re-read per snapshot (so a live flip-OFF stops surfacing it at once). Only an explicit affirmative token
# turns it on; anything else (unset, typo, "0", "false") keeps it OFF — mirrors
# ``detection_mirror.detection_mirror_enabled`` exactly.
OBSERVE_1B_ENV = "VIGIL_AEGIS_OBSERVE_1B"

# Bound the reflected LEAD set and the per-view event fan-in so neither a flood of distinct rule-ids nor a
# flood of received events can bloat the read-only observe surface.
_MAX_LEADS = 64
_MAX_EVENTS = 4096


def observe_1b_enabled() -> bool:
    """Is the 1b observe view armed? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative token
    arms it (mirrors ``detection_mirror.detection_mirror_enabled``). The gateway still builds a meter only
    when this is True AND the AS-31 detection mirror (its dependency) was itself built."""
    return (os.environ.get(OBSERVE_1B_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _canonical(obj: Any) -> str:
    """A deterministic canonical JSON encoding (sorted keys, no insignificant whitespace, ASCII). The byte
    basis for the view digest — stdlib only, no wall-clock, no RNG, so the same posture always reflects to
    the same digest."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def observe_1b_digest(headline: str, source_count: int, content_admissible: bool,
                      leads: Sequence[str], events_observed: int, lead_events: int) -> str:
    """A deterministic sha256 over the graded observe posture (the headline · the source count · the
    content-admissibility bit · the sorted/de-duplicated admissible leads · the event tallies). Pure —
    stdlib only, no wall-clock, no RNG. Any posture change (a different headline, a source added/removed, the
    content flipping (in)admissible, a lead changing, a different intake) moves the digest: the tamper/drift
    evidence for the reflected posture."""
    payload = {
        "headline": str(headline),
        "source_count": int(source_count),
        "content_admissible": bool(content_admissible),
        "leads": sorted({str(r) for r in leads}),
        "events_observed": int(events_observed),
        "lead_events": int(lead_events),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ReceivedEvent:
    """ONE path-1b received event (the AS-9b ingest shape), reduced to the metadata the OBSERVE view
    reflects: the detection ``source`` (an AS-30 provider id) and the edge ``rule_refs`` (the CRS rule-ids
    the tenant's existing edge raised). Address-free + metadata-only — it carries NO client address, request
    URI/body, or matched data (the AS-9b receiver already bounds + redacts a finding; the view reflects only
    these two opaque tokens through the AS-31 mirror, which drops anything address-shaped)."""

    source: str
    rule_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Observe1bView:
    """ONE immutable, read-only 1b OBSERVE view. Metadata only — counts + tokens + a digest, never a client
    address, request bytes, or a secret.

    * ``headline``           — the AS-4b-graded observe headline (the FLOOR of the posture axes, over the
      Headline ladder). STRUCTURALLY capped at ``observing``: the observe leg never claims ``enforcing``.
    * ``source_count``       — the number of cataloged detection sources (the AS-30 provider inventory,
      reflected through the AS-31 mirror).
    * ``content_admissible`` — the AS-7b verdict reflected by the mirror: the edge detection content is
      licence-admitted AND pinned. False ⇒ inadmissible content — NO leads are reflected (fail closed) and
      the headline is capped at ``degraded``.
    * ``events_observed``    — the number of received events (AS-9b) reflected into this view.
    * ``lead_events``        — the number of those events that raised at least one admissible lead.
    * ``leads``              — the admissible detection leads (the CRS rule-ids admitted through the AS-31
      mirror), address-free, bounded, sorted, de-duplicated, AND hygiene-clean. ``()`` over inadmissible
      content, an uncataloged source, or an empty intake.
    * ``lead_count``         — the number of admissible detection leads reflected.
    * ``digest``             — the deterministic content digest of the graded posture (see
      :func:`observe_1b_digest`).
    * ``clean``              — the AS-3b hygiene verdict reflected by the mirror: True ⇒ the reflected body
      carries no raw IP and no configured secret literal. A measurement only — it NEVER drives a decision."""

    headline: str
    source_count: int
    content_admissible: bool
    events_observed: int
    lead_events: int
    leads: tuple[str, ...]
    lead_count: int
    digest: str
    clean: bool

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view for the read-only probe surface / an offline consumer. Metadata only."""
        return {
            "headline": self.headline,
            "source_count": self.source_count,
            "content_admissible": self.content_admissible,
            "events_observed": self.events_observed,
            "lead_events": self.lead_events,
            "leads": list(self.leads),
            "lead_count": self.lead_count,
            "digest": self.digest,
            "clean": self.clean,
        }


def _event_fields(event: "ReceivedEvent | Mapping[str, Any]") -> "tuple[str, tuple[str, ...]]":
    """Reduce one received event — a :class:`ReceivedEvent` or a plain mapping (the AS-9b finding metadata) —
    to the two opaque tokens the view reflects: ``(source, rule_refs)``. TOTAL: a malformed/empty event
    yields ``("", ())``, which the AS-31 mirror drops fail-closed (an uncataloged source raises no belief).
    Carries no address: ``rule_refs`` is passed straight into the mirror, which scrubs + hygiene-gates it."""
    if isinstance(event, ReceivedEvent):
        return str(event.source), tuple(str(r) for r in event.rule_refs)
    if isinstance(event, Mapping):
        source = event.get("source", "")
        refs = event.get("rule_refs", ())
        if not isinstance(refs, (list, tuple)):
            refs = ()
        return str(source or ""), tuple(str(r) for r in refs)
    return "", ()


class Observe1bMeter:
    """The read-only 1b OBSERVE view builder, bound to the AS-31 detection mirror (the reflection of the
    AS-30 source catalog × the AS-7b content admissibility). Holds NO mutable state — it reads the injected
    mirror (which itself only reads its inventory + its AS-7b meter) per view, so it is inherently
    thread-safe and NEVER mutates the inventory, the licence ledger, the corpus, the spool, or any state.

    The meter REFLECTS + GRADES; it never acts: :meth:`observe` reflects a batch of received events (AS-9b)
    into admissible leads and grades the observe posture (AS-4b), :meth:`snapshot` surfaces the standing
    observe posture read-only. It is surfaced read-only on the AS-5c probe snapshot and never touches the
    gateway data path or any admit/shed/allow/block decision. A reflected finding is a LEAD, never a block;
    the graded headline is capped at ``observing`` (the 1b ENFORCE leg is AS-18b)."""

    __slots__ = ("_mirror",)

    def __init__(self, mirror_meter: "DetectionMirrorMeter") -> None:
        self._mirror = mirror_meter

    def _grade_headline(self, *, sources: Sequence[str], content_admissible: bool,
                        events_observed: int, lead_events: int) -> str:
        """Grade the observe posture into an honest headline by composing AS-4b's OWN floor grader (never
        re-implemented): the FLOOR of the posture axes, over the §4.5 Headline ladder. The observe leg passes
        no ``enforcing`` axis, so the floor is STRUCTURALLY capped at ``observing``. Reached by a LAZY import,
        off the eager import plane (FATAL-2); the headline is AS-4b's own computation.

        Axes (each a Headline rung, weakest caps the claim):
          * SOURCES  — ``observing`` when the AS-30 source catalog is non-empty, else ``unsupported`` (no
            detection sources ⇒ the surface is not covered).
          * CONTENT  — ``observing`` when the AS-7b content is admissible, else ``degraded`` (the plane is
            active but its detection content is impaired: unlicensed/unpinned/drifted).
          * INTAKE   — only when received events are in hand: ``observing`` when at least one raised an
            admissible lead, else ``unverified`` (telemetry arrived but nothing corroborated through
            admissible content). A standing posture view (no intake) grades the plane only."""
        from vigil_core.contract_eval import headline_floor  # lazy, absolute — off the eager import plane
        from vigil_core.protection_contract import Headline   # lazy, absolute — off the eager import plane

        axes: list[Headline] = [
            Headline.OBSERVING if sources else Headline.UNSUPPORTED,
            Headline.OBSERVING if content_admissible else Headline.DEGRADED,
        ]
        if events_observed > 0:
            axes.append(Headline.OBSERVING if lead_events > 0 else Headline.UNVERIFIED)
        floor = headline_floor(axes)
        # Observe-leg STRUCTURAL cap: never claim ``enforcing`` (belt-and-braces — no axis above is
        # ``enforcing``, so the floor cannot reach it; the 1b ENFORCE leg is the separate AS-18b slice).
        if floor is Headline.ENFORCING:
            floor = Headline.OBSERVING
        return str(floor.value)

    def observe(self, events: "Sequence[ReceivedEvent | Mapping[str, Any]]" = ()) -> Observe1bView:
        """Reflect a batch of received events (AS-9b) into a read-only OBSERVE view. Each event's ``(source,
        rule_refs)`` is reflected through the AS-31 mirror into admissible leads (fail-closed: () unless the
        source is CATALOGED and the content ADMISSIBLE; each surviving ref is normalized address-free /
        bounded / sorted / de-duplicated and hygiene-clean). The observe posture is then graded through the
        AS-4b floor grader. Pure + read-only: a function of its inputs and the current mirror posture,
        mutating nothing.

        This REFLECTS + GRADES, it never acts: the view takes no response action and is never an input to any
        admit/shed/allow/block decision. A reflected finding is a LEAD, never a block (only a fired oracle
        blocks)."""
        evs = list(events)[:_MAX_EVENTS]
        mir = self._mirror.summary()                 # AS-31: sources × content admissibility (read-only)
        leads: set[str] = set()
        lead_events = 0
        for ev in evs:
            source, refs = _event_fields(ev)
            admitted = self._mirror.reflect(source, refs)   # AS-31 fail-closed admit (address-free/hygiene)
            if admitted:
                lead_events += 1
                leads.update(admitted)
        events_observed = len(evs)
        leads_sorted = tuple(sorted(leads)[:_MAX_LEADS])
        headline = self._grade_headline(sources=mir.sources, content_admissible=mir.content_admissible,
                                        events_observed=events_observed, lead_events=lead_events)
        return Observe1bView(
            headline=headline,
            source_count=mir.source_count,
            content_admissible=mir.content_admissible,
            events_observed=events_observed,
            lead_events=lead_events,
            leads=leads_sorted,
            lead_count=len(leads_sorted),
            digest=observe_1b_digest(headline, mir.source_count, mir.content_admissible,
                                     leads_sorted, events_observed, lead_events),
            clean=bool(mir.clean),
        )

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the STANDING 1b observe posture for the AS-5c probe
        surface: the graded headline over the AS-30 source catalog × the AS-7b content admissibility (no
        received events in hand), the admissible-lead count (0 in the standing view), the posture digest and
        the hygiene verdict. Carries counts + a digest, NO request bytes and NO secret — mirroring the
        AS-31/AS-7b snapshots. A reflected finding is a LEAD, never a block; the headline is capped at
        ``observing``."""
        return self.observe(()).to_dict()
