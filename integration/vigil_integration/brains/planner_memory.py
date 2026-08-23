"""planner_memory — H9 bounded adaptive re-planning: the deterministic, propose-only knowledge the
hexstrike planner UPDATES on new observations and RE-PLANS from.

WHAT THIS CLOSES. Before H9, ``engine_think.BrainThink`` built its chain ONCE and thereafter only advanced
an index; ``state`` was read a single time and ignored. So a run that discovered a new surface, wasted a
step on a tool that returned nothing, or had a step denied at the gate learned NOTHING — it kept walking a
plan built against a blank slate. This module is the memory that makes the planner adaptive within a run:

  * TOOL-EFFECTIVENESS STATISTICS — per tool: proposed / ran / facts / leads / no-progress / denied.
  * FAILED-PATH MEMORY — a tool that ran and produced no facts AND no leads, or was denied at the gate, is
    remembered and DEPRIORITIZED (moved to the end of the plan; not re-proposed once already emitted).
  * DISCOVERED SURFACES / TECHNOLOGY PROFILE — new open ports, services, technologies, a CMS fingerprint,
    a target-type signal observed DURING the run re-shape the profile the next plan is built from.
  * ORACLE-CONFIRMED RELATIONSHIPS + TESTED INSERTION POINTS — recorded from the engagement's FACTs/LEADs.

THE LOAD-BEARING HONESTY INVARIANT (the reason this module carries an admission gate at all):

    **Unverified model prose NEVER enters durable knowledge as a FACT.**

A :class:`KnowledgeEntry` is the durable, append-only unit. Its ``verdict`` is ``FACT`` ONLY when it was
minted from an oracle-confirmed :class:`~vigil_integration.agent.state.Finding` (``status == "fact"``) that
carries a signed evidence reference — which becomes the entry's ``certificate_digest``. Everything else — a
LEAD (a tool's or the model's say-so), a sensor observation, operator prose — is admitted as ``LEAD`` or
``ADVISORY`` and can NEVER become a ``FACT``. The gate is enforced in :meth:`KnowledgeEntry.__post_init__`:
a ``FACT`` verdict with no certificate digest RAISES. This mirrors the existing type-level invariant on
``Finding`` (a FACT requires a signed evidence ref) at the planner's knowledge layer.

An unverified observation may still SHAPE THE PLAN — that is the point of adaptive re-planning — but only as
a PRIOR. The profile a plan is built from carries no authority (the same doctrine ``profile_observations``
already states: "An observation is a PRIOR for the planner — never a fact"). The gate authorizes; the oracle
confirms. Nothing here mints, promotes, grants a tier, or widens scope.

IMMUTABILITY. The ledger is append-only. An entry is NEVER edited. A changed belief is recorded by APPENDING
a superseding entry that names (by ``entry_id``) the one it supersedes; both remain in the ledger forever, so
the historical evidence stays immutable and the supersession history is reconstructable. Staleness is a
QUERY-TIME view (:meth:`current`), never a mutation — the graph accretes knowledge, it does not forget it.

DETERMINISM (the metacognition/RL determinism rule). No wallclock and no rng anywhere. Every sequence number
is an internal monotonic counter incremented per ingest; every digest is a SHA-256 over a canonical
(sorted-key, tight-separator) JSON encoding. Two identical sequences of ``ingest_state`` calls produce
byte-identical ledgers, digests and plans.

FATAL-2. stdlib + the brain's own stdlib modules only (``hexstrike_brain``, ``profile_observations``); no
``framework.*`` / ``strix.*`` / ``sigil.*`` / network. So it imports at module scope in ``engine_think``
without pulling any offense engine, and it loads in the sovereign leg.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

from .hexstrike_brain import AttackStep
from .profile_observations import (
    ObsKind,
    ProfileObservation,
    make_observation,
    reduce_to_profile_kwargs,
)

#: The knowledge schema this module writes. Bumped only on a breaking change to :class:`KnowledgeEntry`'s
#: fields, so a persisted/queried entry always states the schema it was minted under.
SCHEMA_VERSION = "h9-planner-knowledge/1"

#: Default staleness horizon (in monotonic ingest-seq units) for a LEAD/ADVISORY entry — after this many
#: further ingests without corroboration, :meth:`PlannerMemory.current` no longer surfaces it. A FACT never
#: staleness-expires by default (a signed, oracle-confirmed relationship stands until it is SUPERSEDED, not
#: until a timer elapses). 0 means "never expires".
_DEFAULT_LEAD_TTL = 8

#: The CMS fingerprints the surface reducer recognises (the closed set ``create_attack_chain`` branches on).
_CMS_NAMES = frozenset({"wordpress", "drupal", "joomla"})

#: A "<port>/tcp" or "<port>/udp" token, and a "port: <n>" / "port=<n>" form — deterministic, conservative
#: port extraction from a finding's structured-ish text. An out-of-range number is dropped by ``_as_port``.
_PORT_SLASH = re.compile(r"(?<!\d)(\d{1,5})/(?:tcp|udp)\b", re.IGNORECASE)
_PORT_KV = re.compile(r"\bport[\s:=]+(\d{1,5})\b", re.IGNORECASE)
#: Tokeniser for whole-word technology/CMS matching (so "node" never matches inside "nodeadbeef").
_TOKENS = re.compile(r"[a-z0-9.#+-]+")


class Verdict(str, Enum):
    """The veracity of a durable knowledge entry. Only ``FACT`` is authoritative, and only the admission
    gate (an oracle-confirmed finding carrying a certificate digest) can produce it."""

    FACT = "fact"          # oracle-confirmed; carries a signed certificate digest
    LEAD = "lead"          # a tool's/model's proposal — a prior; NEVER a fact
    ADVISORY = "advisory"  # sensor/operator prose — a prior; NEVER a fact


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _as_port(tok: Any) -> Optional[int]:
    try:
        p = int(str(tok).strip())
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


@dataclass(frozen=True)
class KnowledgeEntry:
    """One durable, IMMUTABLE knowledge-graph entry the planner learned.

    Carries its full provenance so a reader can tell WHERE it came from and WHETHER to trust it:
      * ``source_engagement`` — the engagement slug that produced it.
      * ``observation_digest`` — a digest of the exact observation (e.g. the finding) that minted it.
      * ``verdict`` — FACT / LEAD / ADVISORY (see :class:`Verdict`).
      * ``certificate_digest`` — the oracle-confirmed finding's signed evidence reference; REQUIRED for a
        FACT, empty for anything else (this is the admission gate).
      * ``schema_version`` — the schema this entry was minted under.
      * ``confidence`` — a prior in [0,1]; never upgraded to certainty by anything here.
      * ``asserted_seq`` — the monotonic ingest sequence at which it was asserted (deterministic; no clock).
      * ``stale_after_seq`` — the seq beyond which :meth:`PlannerMemory.current` stops surfacing it; 0 =
        never (a FACT). Staleness is a VIEW, never a mutation — the entry stays in the ledger forever.
      * ``supersedes`` — the ``entry_id`` of a prior entry this one replaces ("" if it supersedes nothing).
    """

    subject: str
    predicate: str
    obj: str
    verdict: str
    source_engagement: str
    observation_digest: str
    certificate_digest: str
    schema_version: str
    confidence: float
    asserted_seq: int
    stale_after_seq: int
    supersedes: str = ""

    def __post_init__(self) -> None:
        # ADMISSION GATE — the whole reason this class validates. Unverified knowledge is NEVER a FACT.
        if self.verdict == Verdict.FACT.value and not (self.certificate_digest or "").strip():
            raise ValueError(
                "H9 admission: a FACT knowledge entry requires an oracle certificate digest — unverified "
                "prose/leads may be recorded only as LEAD or ADVISORY, never as FACT."
            )
        if self.verdict not in {v.value for v in Verdict}:
            raise ValueError(f"unknown knowledge verdict {self.verdict!r}")
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError(f"confidence out of range: {self.confidence!r}")

    @property
    def entry_id(self) -> str:
        """A content-address over every field — so the same asserted knowledge has the same id, and a
        superseding entry can name exactly what it replaced."""
        return _digest({
            "subject": self.subject, "predicate": self.predicate, "obj": self.obj,
            "verdict": self.verdict, "source_engagement": self.source_engagement,
            "observation_digest": self.observation_digest, "certificate_digest": self.certificate_digest,
            "schema_version": self.schema_version, "confidence": self.confidence,
            "asserted_seq": self.asserted_seq, "stale_after_seq": self.stale_after_seq,
            "supersedes": self.supersedes,
        })

    def is_stale(self, current_seq: int) -> bool:
        return self.stale_after_seq > 0 and current_seq > self.stale_after_seq

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id, "subject": self.subject, "predicate": self.predicate,
            "obj": self.obj, "verdict": self.verdict, "source_engagement": self.source_engagement,
            "observation_digest": self.observation_digest, "certificate_digest": self.certificate_digest,
            "schema_version": self.schema_version, "confidence": self.confidence,
            "asserted_seq": self.asserted_seq, "stale_after_seq": self.stale_after_seq,
            "supersedes": self.supersedes,
        }


@dataclass
class ToolStat:
    """Per-tool effectiveness statistics accumulated from the engagement's execution trace."""

    proposed: int = 0
    ran: int = 0
    facts: int = 0
    leads: int = 0
    no_progress: int = 0   # ran but produced 0 facts AND 0 leads
    denied: int = 0        # refused at the gate / executor (never ran)

    def to_dict(self) -> dict:
        return {"proposed": self.proposed, "ran": self.ran, "facts": self.facts, "leads": self.leads,
                "no_progress": self.no_progress, "denied": self.denied}


# ---- deterministic surface derivation ------------------------------------------------------------

def observations_from_finding(finding: Any, *, oracle_confirmed: bool) -> list[ProfileObservation]:
    """Derive discovered-surface :class:`ProfileObservation`s from a finding's structured text.

    Conservative and total: only RECOGNISED tokens (a known technology/CMS name, a well-formed port) yield
    an observation — an unrecognised fingerprint is dropped, never guessed (the ``profile_observations``
    doctrine). Never raises. Confidence reflects veracity: an oracle-confirmed FACT contributes a strong
    prior, a LEAD a weak one — but NEITHER is a fact here; both only shape the profile the planner reasons
    from, which itself carries no authority."""
    conf = 0.9 if oracle_confirmed else 0.4
    prov = ("oracle-fact:" if oracle_confirmed else "lead:") + str(getattr(finding, "source", "") or "?")
    text = " ".join(str(getattr(finding, k, "") or "") for k in ("bug_class", "title", "ref"))
    tokens = set(_TOKENS.findall(text.lower()))
    out: list[ProfileObservation] = []

    def _add(kind: ObsKind, value: str) -> None:
        obs = make_observation(kind.value, value, prov, conf)
        if obs is not None:
            out.append(obs)

    # technologies / CMS (whole-word matches only)
    for name in _CMS_NAMES:
        if name in tokens:
            _add(ObsKind.CMS, name)
    # a technology alias present as a whole token -> a technology observation (reduce maps/drops it)
    from .profile_observations import _TECH_ALIASES  # local: the alias table is the single source of truth
    for alias in _TECH_ALIASES:
        if alias in tokens:
            _add(ObsKind.TECHNOLOGY, alias)
    # ports: "<n>/tcp", "<n>/udp", "port: <n>"
    seen_ports: set[int] = set()
    for m in list(_PORT_SLASH.finditer(text)) + list(_PORT_KV.finditer(text)):
        p = _as_port(m.group(1))
        if p is not None and p not in seen_ports:
            seen_ports.add(p)
            _add(ObsKind.OPEN_PORT, str(p))
    return out


def _rows_to_observations(rows: Any) -> list[ProfileObservation]:
    """Coerce an explicit structured observation channel (a list of ``{kind,value,provenance,confidence}``
    rows a sensor/console may put on the state) into :class:`ProfileObservation`s. Total; a malformed row is
    dropped by ``make_observation``."""
    out: list[ProfileObservation] = []
    if not isinstance(rows, (list, tuple)):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        obs = make_observation(row.get("kind"), row.get("value"),
                               row.get("provenance"), row.get("confidence"))
        if obs is not None:
            out.append(obs)
    return out


# ---- the memory ----------------------------------------------------------------------------------

@dataclass
class PlannerMemory:
    """The deterministic, propose-only memory the planner updates on new observations and re-plans from."""

    engagement_slug: str = ""
    lead_ttl: int = _DEFAULT_LEAD_TTL
    schema_version: str = SCHEMA_VERSION

    # the append-only, immutable knowledge ledger (never edited; supersede by APPENDING)
    ledger: list[KnowledgeEntry] = field(default_factory=list)
    # derived planning indices
    tool_stats: dict[str, ToolStat] = field(default_factory=dict)
    failed_paths: dict[str, str] = field(default_factory=dict)   # tool -> reason (deprioritized)
    # accumulated discovered-surface priors (ProfileObservation), used to augment the profile
    surface_obs: list = field(default_factory=list)

    # cursors / dedupe (internal; never part of any digest of the observed WORLD)
    _seq: int = 0
    _seen_findings: set = field(default_factory=set)
    _trace_cursor: int = 0
    _obs_cursor: int = 0

    # ------------------------------------------------------------------ deterministic seq
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # ------------------------------------------------------------------ admission
    def _admit(self, *, subject: str, predicate: str, obj: str, verdict: Verdict,
               observation_digest: str, certificate_digest: str, confidence: float,
               seq: int) -> KnowledgeEntry:
        """Append one entry to the immutable ledger through the admission gate. A FACT with no certificate
        digest raises inside :class:`KnowledgeEntry` — the gate cannot be bypassed by calling this."""
        stale_after = 0 if verdict is Verdict.FACT or self.lead_ttl <= 0 else seq + self.lead_ttl
        entry = KnowledgeEntry(
            subject=subject, predicate=predicate, obj=obj, verdict=verdict.value,
            source_engagement=self.engagement_slug, observation_digest=observation_digest,
            certificate_digest=certificate_digest, schema_version=self.schema_version,
            confidence=confidence, asserted_seq=seq, stale_after_seq=stale_after,
        )
        self.ledger.append(entry)
        return entry

    def _finding_key(self, finding: Any, *, kind: str) -> tuple:
        return (kind, str(getattr(finding, "ref", "") or ""),
                str(getattr(finding, "evidence_ref", "") or ""),
                str(getattr(finding, "title", "") or ""))

    def _finding_digest(self, finding: Any) -> str:
        return _digest({k: str(getattr(finding, k, "") or "")
                        for k in ("ref", "bug_class", "title", "severity", "status",
                                  "evidence_ref", "source")})

    # ------------------------------------------------------------------ ingest
    def ingest_state(self, state: Any, *, engagement_slug: str = "") -> None:
        """Fold the CURRENT engagement observations into memory. Idempotent per observation: a finding or a
        trace row already consumed is never double-counted, so calling this on every think cycle (as the
        engine does) accretes only what is NEW. Reads three channels off the state, each via ``getattr`` so
        a bare ``SimpleNamespace`` (carrying only ``objective``) is handled with all-empty defaults:

          * ``facts``  — oracle-confirmed :class:`Finding`s -> a FACT knowledge entry (certificate digest =
            the finding's signed ``evidence_ref``) + strong surface priors.
          * ``leads``  — proposals -> a LEAD knowledge entry (NEVER a fact) + weak surface priors.
          * ``execution_trace`` — per-iteration outcomes -> tool-effectiveness stats + failed-path memory.
          * ``observations`` (optional) — an explicit structured surface channel a sensor/console may write.
        """
        if engagement_slug:
            self.engagement_slug = engagement_slug

        for finding in list(getattr(state, "facts", None) or []):
            if str(getattr(finding, "status", "") or "") != "fact":
                continue  # a non-fact in the facts store is not admitted as a fact (defence in depth)
            key = self._finding_key(finding, kind="fact")
            if key in self._seen_findings:
                continue
            self._seen_findings.add(key)
            cert = str(getattr(finding, "evidence_ref", "") or "")
            if not cert.strip():
                # A fact without a signed evidence ref cannot be admitted as a FACT — record it honestly as
                # a LEAD instead of fabricating a certificate. (Finding's own type-validator already forbids
                # this shape; this is belt-and-braces so a duck-typed input cannot slip past the gate.)
                verdict, cert_arg = Verdict.LEAD, ""
            else:
                verdict, cert_arg = Verdict.FACT, cert
            seq = self._next_seq()
            self._admit(subject=f"finding:{getattr(finding, 'ref', '') or seq}",
                        predicate=str(getattr(finding, "bug_class", "") or "finding"),
                        obj=str(getattr(finding, "title", "") or getattr(finding, "ref", "") or ""),
                        verdict=verdict, observation_digest=self._finding_digest(finding),
                        certificate_digest=cert_arg,
                        confidence=0.9 if verdict is Verdict.FACT else 0.4, seq=seq)
            self._absorb_surface(observations_from_finding(finding, oracle_confirmed=verdict is Verdict.FACT))

        for finding in list(getattr(state, "leads", None) or []):
            key = self._finding_key(finding, kind="lead")
            if key in self._seen_findings:
                continue
            self._seen_findings.add(key)
            seq = self._next_seq()
            # A LEAD — unverified prose. It shapes the plan as a PRIOR but is NEVER a fact (no cert digest).
            self._admit(subject=f"finding:{getattr(finding, 'ref', '') or seq}",
                        predicate=str(getattr(finding, "bug_class", "") or "finding"),
                        obj=str(getattr(finding, "title", "") or getattr(finding, "ref", "") or ""),
                        verdict=Verdict.LEAD, observation_digest=self._finding_digest(finding),
                        certificate_digest="", confidence=0.4, seq=seq)
            self._absorb_surface(observations_from_finding(finding, oracle_confirmed=False))

        # execution trace -> tool-effectiveness statistics + failed-path memory (consume only NEW rows)
        trace = list(getattr(state, "execution_trace", None) or [])
        for row in trace[self._trace_cursor:]:
            self._ingest_trace_row(row)
        self._trace_cursor = len(trace)

        # optional explicit structured surface channel (advisory priors + ADVISORY ledger entries)
        rows = getattr(state, "observations", None)
        if isinstance(rows, (list, tuple)):
            for obs in _rows_to_observations(rows[self._obs_cursor:]):
                self._absorb_surface([obs])
                seq = self._next_seq()
                self._admit(subject=f"surface:{obs.kind.value}:{obs.value}", predicate="observed",
                            obj=obs.value, verdict=Verdict.ADVISORY,
                            observation_digest=_digest(obs.to_dict()), certificate_digest="",
                            confidence=float(obs.confidence), seq=seq)
            self._obs_cursor = len(rows)

    def _ingest_trace_row(self, row: Any) -> None:
        if not isinstance(row, dict):
            return
        if str(row.get("action", "")) != "use_tool":
            return
        tool = str(row.get("tool", "") or "").strip()
        if not tool:
            return
        stat = self.tool_stats.setdefault(tool, ToolStat())
        outcome = str(row.get("outcome", "") or "")
        if outcome == "ran":
            stat.ran += 1
            f = int(row.get("facts", 0) or 0)
            ld = int(row.get("leads", 0) or 0)
            stat.facts += f
            stat.leads += ld
            if f == 0 and ld == 0:
                stat.no_progress += 1
                self.failed_paths[tool] = "ran but produced no facts and no leads"
            else:
                # real progress supersedes an earlier failed-path verdict for this tool
                self.failed_paths.pop(tool, None)
        elif outcome == "deny":
            stat.denied += 1
            self.failed_paths[tool] = f"denied at the gate: {row.get('reason', '') or 'not authorized'}"

    def _absorb_surface(self, observations: Iterable[ProfileObservation]) -> None:
        """Accrete discovered-surface priors. De-duplicated on (kind, value) so re-observing a surface does
        not inflate the profile; the graph accretes, it does not double-count."""
        have = {(o.kind, o.value) for o in self.surface_obs}
        for obs in observations:
            if (obs.kind, obs.value) not in have:
                have.add((obs.kind, obs.value))
                self.surface_obs.append(obs)

    # ------------------------------------------------------------------ supersession (append-only)
    def supersede(self, old: KnowledgeEntry, *, obj: str, verdict: Optional[Verdict] = None,
                  certificate_digest: str = "", confidence: Optional[float] = None,
                  observation_digest: str = "") -> KnowledgeEntry:
        """Record a changed belief by APPENDING a new entry that names ``old`` — never by editing ``old``.
        Both entries remain in the ledger, so the historical evidence is immutable and the supersession
        chain is reconstructable. The admission gate still applies (a FACT still needs a certificate)."""
        v = verdict if verdict is not None else Verdict(old.verdict)
        seq = self._next_seq()
        stale_after = 0 if v is Verdict.FACT or self.lead_ttl <= 0 else seq + self.lead_ttl
        entry = KnowledgeEntry(
            subject=old.subject, predicate=old.predicate, obj=obj, verdict=v.value,
            source_engagement=self.engagement_slug or old.source_engagement,
            observation_digest=observation_digest or old.observation_digest,
            certificate_digest=certificate_digest, schema_version=self.schema_version,
            confidence=old.confidence if confidence is None else float(confidence),
            asserted_seq=seq, stale_after_seq=stale_after, supersedes=old.entry_id,
        )
        self.ledger.append(entry)
        return entry

    def current(self, *, at_seq: Optional[int] = None) -> list[KnowledgeEntry]:
        """The live view: entries that are neither superseded nor stale at ``at_seq`` (defaults to the
        current seq). A pure QUERY — it never mutates the ledger, so historical evidence is untouched."""
        seq = self._seq if at_seq is None else at_seq
        superseded = {e.supersedes for e in self.ledger if e.supersedes}
        return [e for e in self.ledger
                if e.entry_id not in superseded and not e.is_stale(seq)]

    def facts(self) -> list[KnowledgeEntry]:
        """Only the oracle-confirmed FACT entries (each carries a certificate digest)."""
        return [e for e in self.ledger if e.verdict == Verdict.FACT.value]

    # ------------------------------------------------------------------ re-planning
    def augment(self, seed: dict) -> dict:
        """Merge the caller's SEED observation kwargs with the surfaces discovered during the run.

        List fields (open_ports / ip_addresses / technologies) become the DISTINCT UNION; scalar fields
        (target_type / cms_type / cloud_provider) keep the SEED's value when it set one, else adopt the
        discovered value. With no discovered surfaces the result equals ``seed`` (so a run with no new
        observation re-plans to the identical chain — the build-once behaviour is preserved as a special
        case, not a hard-coded branch)."""
        out = dict(seed or {})
        discovered = reduce_to_profile_kwargs(self.surface_obs)
        # list unions
        for key in ("open_ports", "ip_addresses"):
            merged = list(out.get(key) or [])
            for v in discovered.get(key) or []:
                if v not in merged:
                    merged.append(v)
            if merged:
                out[key] = sorted(merged) if key == "open_ports" else merged
        # technologies: union preserving order, de-dup on value
        techs = list(out.get("technologies") or [])
        seen_t = {getattr(t, "value", t) for t in techs}
        for t in discovered.get("technologies") or []:
            tv = getattr(t, "value", t)
            if tv not in seen_t:
                seen_t.add(tv)
                techs.append(t)
        if techs:
            out["technologies"] = techs
        # services: fill gaps only (seed wins on a port already known)
        services = dict(out.get("services") or {})
        for port, name in (discovered.get("services") or {}).items():
            services.setdefault(port, name)
        if services:
            out["services"] = services
        # scalars: seed wins if it set one, else adopt the discovered value
        for key in ("target_type", "cms_type", "cloud_provider"):
            if not out.get(key) and discovered.get(key):
                out[key] = discovered[key]
        return out

    def replan(self, base_steps: list) -> list:
        """Return the ordered plan for the current world: the base chain with FAILED-PATH tools DEPRIORITIZED
        (moved to the end), each partition keeping its base order. Stable — with no failed paths it returns
        ``base_steps`` unchanged. The caller (``BrainThink``) additionally skips tools already emitted, so a
        deprioritized-and-already-tried tool is simply never re-proposed."""
        keep: list = []
        deferred: list = []
        for step in base_steps:
            tool = getattr(step, "tool", None) if not isinstance(step, dict) else step.get("tool")
            (deferred if tool in self.failed_paths else keep).append(step)
        return keep + deferred

    # ------------------------------------------------------------------ digests / snapshot
    def world_digest(self) -> str:
        """A deterministic digest of the OBSERVED WORLD that drives re-planning: the durable knowledge
        (every ledger entry, by content-addressed id), the discovered surfaces, the failed-path set, and the
        tool-effectiveness stats. It changes exactly when a NEW observation has arrived — a new finding
        (fact or lead) appends a ledger entry, a new trace row updates the failed-path/stat channel — so
        ``BrainThink`` re-plans then and only then. It deliberately EXCLUDES the internal ``_seq`` counter
        and is computed over de-duplicated, idempotent state, so RE-INGESTING the same static state leaves it
        unchanged (a plain run with no new observation is not rebuilt on every idle cycle)."""
        return _digest({
            "knowledge": [e.entry_id for e in self.ledger],
            "surfaces": sorted(f"{o.kind.value}={o.value}@{o.confidence}" for o in self.surface_obs),
            "failed": sorted(self.failed_paths),
            "stats": {t: s.to_dict() for t, s in sorted(self.tool_stats.items())},
        })

    def snapshot(self) -> dict:
        """A JSON-safe, deterministic view for persistence/telemetry (e.g. the replanning-history block of
        ``brain-proposal.json``). Pure — invents nothing, mints nothing."""
        return {
            "schema_version": self.schema_version,
            "engagement": self.engagement_slug,
            "world_digest": self.world_digest(),
            "n_facts": len(self.facts()),
            "n_leads": sum(1 for e in self.ledger if e.verdict == Verdict.LEAD.value),
            "deprioritized": sorted(self.failed_paths),
            "discovered": {k: v for k, v in reduce_to_profile_kwargs(self.surface_obs).items()
                           if v not in (None, [], {}, "")},
            "tool_stats": {t: s.to_dict() for t, s in sorted(self.tool_stats.items())},
        }
