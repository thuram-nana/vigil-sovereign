"""
sensors.base — the Universal Sensor/Producer abstraction (Wave 2.1).

A SENSOR is the universal producer: it turns some source of facts — a native probe, an integrated
CLI (Nmap, a packet engine, Nuclei), or a cloud API — into the ONE evidence model. It reuses,
unchanged, everything the OSINT collector pipeline already built (``intel.Observation`` +
``intel.project.project_observation`` + ``intel.IntelIngest``) and everything the W1.4 tool seam
already built (a Sensor IS a gated ``agents.tools.Tool``: kill-switch / entitlement / scope /
destructive-confirm / egress gate it before it runs). What a Sensor adds is a ``normalize`` step:
its raw tool output → provenance-labelled ``Observation``s.

Doctrine, by construction:
  * PROVE-DON'T-GUESS. A sensor mints OBSERVATIONS, never facts. They enter the world-model as
    ``GROUNDING_INTEL`` (the ``intel:`` provenance tier) — real but not oracle-proof — and become a
    FACT only if a deterministic oracle later re-verifies them (Wave 2.3+). A Sensor never writes a
    Finding.
  * GATED. Every sensor invocation runs through the W1.4 fail-closed chain (via ``sensors.pipeline
    .run_sensor`` → ``agents.tools.invoke_tool``). A refused/failed sensor mints nothing.
  * DETERMINISM. The tool OUTPUT reflects the live world, but ``normalize → Observation → project →
    Beta belief`` is a PURE, replayable function of that output (caller-supplied ``seq``, no
    wallclock, no rng). ``obs_id`` is deterministic so re-ingest is idempotent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, runtime_checkable

from ..agents.tools import ToolContext, ToolResult
from ..intel.from_scan import host_ref
from ..intel.models import IntelSourceKind, Observation, SourceReliability
from ..intel.refs import EntityRef, canonicalize
from ..worldmodel.models import EdgeKind, NodeKind


# ---------------------------------------------------------------------------
# INCONCLUSIVE outcome — a missing prerequisite is NEVER a clean negative
# ---------------------------------------------------------------------------
#
# A live cloud/K8s sensor cannot assess a target it could not reach. Its prerequisites are AMBIENT
# read-only credentials (the host's own identity) and a provisioned egress scope
# (``targets/<slug>/collector-hosts.txt``). When one is MISSING the sensor has assessed NOTHING — and
# for a product whose thesis is a SOUND NEGATIVE, reporting "assessed nothing" as "found nothing" is
# the worst failure mode: a silent CLEAN. So a missing prerequisite mints a structured, machine-
# readable INCONCLUSIVE outcome that NAMES the prerequisite, which ``engage_fusion.fuse_sensors``
# CONSUMES (via ``SensorResult.inconclusive`` -> ``_surface_inconclusive``) to emit a distinct
# ``source='sensor:inconclusive'`` spine event — so a FUSION run's missing-prerequisite outcome is
# visibly distinct from an assessed run, never a clean negative.

INCONCLUSIVE = "inconclusive"


def inconclusive_result(sensor: str, *, missing: str, detail: str) -> ToolResult:
    """Mint a MISSING-PREREQUISITE sensor outcome as an explicit, machine-readable INCONCLUSIVE
    verdict — NEVER a clean negative.

    A live cloud/K8s sensor that lacks a prerequisite (AMBIENT read-only credentials, or a provisioned
    egress scope — ``targets/<slug>/collector-hosts.txt``) has assessed NOTHING. Reporting that as
    "found nothing" is a silent CLEAN — the worst failure mode for a sound-negative product. So the
    outcome is ``ok=False`` (nothing ran to completion) carrying a TYPED marker in ``output`` —
    ``status='inconclusive'``, ``assessed=False``, ``missing_prerequisite=<name>`` — that
    ``engage_fusion.fuse_sensors`` keys on (via ``SensorResult.inconclusive``) to emit a distinct
    ``sensor:inconclusive`` spine event, keeping a not-assessed surface OUT of any clean negative, plus a
    loud ``note`` that leads with INCONCLUSIVE and names what was not assessed. The marker rides in
    ``output`` because a failed ToolResult carries no facts, so that field is free for the reason (the
    fusion consumer keys on the TYPED marker, not on the free-text note). Total."""
    return ToolResult(
        ok=False,
        note=(f"{sensor}: INCONCLUSIVE — a missing prerequisite means NOTHING was assessed; this is "
              f"NOT a clean result. {detail}"),
        output={"status": INCONCLUSIVE, "assessed": False, "missing_prerequisite": missing,
                "sensor": sensor},
    )


def is_inconclusive(result: Any) -> bool:
    """True iff ``result`` is a structured INCONCLUSIVE sensor outcome (a missing prerequisite meant
    NOTHING was assessed) — the signal ``engage_fusion.fuse_sensors`` keys on (via
    ``SensorResult.inconclusive``) to surface the not-assessed surface as a distinct spine event rather
    than a clean negative. Total: a plain failure, an assessed ``ok=True`` result, or ``None`` is NOT
    inconclusive."""
    out = getattr(result, "output", None)
    return isinstance(out, dict) and out.get("status") == INCONCLUSIVE and out.get("assessed") is False


@runtime_checkable
class Sensor(Protocol):
    """A gated tool that also knows how to NORMALIZE its output into world-model observations.

    ``name`` + ``run`` is the ``agents.tools.Tool`` contract, so a Sensor registers in a
    ``ToolRegistry`` and is gated by ``invoke_tool``; the optional gating metadata (``tier`` /
    ``capability`` / ``destructive`` / ``egress_hosts``) is read defensively by the invoker.
    ``normalize`` turns the ``ToolResult`` into ``Observation``s to project into the world-model."""

    name: str

    def run(self, args: dict, ctx: ToolContext) -> ToolResult: ...

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]: ...


@dataclass
class SensorResult:
    """The outcome of running a sensor through the gated pipeline: the raw gated ``ToolResult``, the
    ``Observation``s it normalized, and (if any were ingested) the projection tally."""

    result: ToolResult
    observations: list[Observation] = field(default_factory=list)
    applied: int = 0          # observations that projected new/updated world-model state
    dropped: int = 0          # observations the projector declined (unknown/no-reliability)

    @property
    def ok(self) -> bool:
        return self.result.ok and not self.result.refused

    @property
    def inconclusive(self) -> bool:
        """True iff a prerequisite was missing so NOTHING was assessed — a not-assessed outcome that
        ``engage_fusion.fuse_sensors`` reads and surfaces as a distinct ``sensor:inconclusive`` spine
        event, so it is never folded into a clean negative (see ``inconclusive_result``)."""
        return is_inconclusive(self.result)

    @property
    def missing_prerequisite(self) -> str:
        """The prerequisite whose absence made the run inconclusive ('' when the run was assessed)."""
        out = getattr(self.result, "output", None)
        if self.inconclusive and isinstance(out, dict):
            return str(out.get("missing_prerequisite") or "")
        return ""


def service_observations(
    host: str,
    services: Iterable[dict],
    *,
    seq: int,
    source: str,
    source_kind: IntelSourceKind,
    reliability: SourceReliability,
    open_confidence: float = 0.9,
) -> list[Observation]:
    """Mint the canonical HOST + per-SERVICE nodes + ``HOST --HOSTS--> SERVICE`` edges (+ an
    ``APPLICATION`` + ``SERVICE --RUNS--> APPLICATION`` when a product is known) from a normalized
    ``(host, services)`` structure — the SHARED minter every network-service sensor (the declared
    reference sensor here, the Nmap sensor in W2.2, masscan later) reuses, so the SERVICE/HOSTS
    schema is produced ONE way.

    Each ``services`` item is a dict with at least ``port``; optional ``protocol`` (default 'tcp'),
    ``state`` (default 'open'), ``service``, ``product``, ``version``. Only OPEN services mint a
    SERVICE node; a non-dict item is skipped (this is the shared minter, so it stays robust for the
    less-clean producers to come). Pure: no wallclock, no rng, no positional counter — ``obs_id`` IS
    the ``(source, seq, claim)`` key, so re-ingest / reordering / an intra-batch duplicate collapse
    to one observation (idempotent; belief never inflates from input ordering)."""
    out: list[Observation] = []
    subj = host_ref(host)

    def _mint(subject: EntityRef, *, rel: EdgeKind | None = None, obj: EntityRef | None = None,
              conf: float, attrs: dict | None = None) -> Observation:
        # obs_id IS the claim key at this (source, seq): DISTINCT claims get distinct ids, and the
        # SAME claim — re-declared, reordered, or duplicated within one batch — gets the SAME id, so
        # IntelIngest dedups it and the Beta belief is not double-counted. No positional index (which
        # would make the id order-dependent), no clock, no rng: a PURE replayable function.
        r = rel.value if rel else ""
        o = obj.node_id if obj else ""
        return Observation(
            obs_id=f"{source}:{seq}:{subject.node_id}|{r}|{o}",
            source=source, source_kind=source_kind, collector=source,
            subject=subject, relation=rel, object=obj, attrs=attrs or {},
            source_reliability=reliability, confidence=conf, seq=seq)

    out.append(_mint(subj, conf=1.0))    # the HOST/DOMAIN is observed (up), at self-reliability
    # HOSTS is a host/netblock -> service edge (worldmodel schema): only a true HOST may host a
    # service. host_ref maps an IP literal to a HOST but a hostname to a DOMAIN; for a DOMAIN-declared
    # host we still record the SERVICE and its APPLICATION (both tier-valid), but NOT a wrong-tier
    # DOMAIN--HOSTS-->SERVICE edge that would corrupt path-search / co-hosting reasoning downstream.
    host_hosts = subj.kind in (NodeKind.HOST, NodeKind.NETBLOCK)
    for svc in services:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        if port is None or str(svc.get("state", "open")).lower() != "open":
            continue
        proto = str(svc.get("protocol") or "tcp").lower()
        svc_ref = canonicalize(NodeKind.SERVICE, f"{subj.key}:{port}/{proto}")
        # The service descriptor lives on the SERVICE node's OWN subject-claim, not on the HOSTS
        # edge: project_observation copies a node-claim's attrs onto its SUBJECT, so putting them on
        # the HOSTS edge would land the port/product on the HOST (order-dependently, last-service-
        # wins) and leave the SERVICE node bare. Edges stay bare; the node carries its metadata.
        svc_attrs = {k: v for k, v in {
            "port": port, "protocol": proto, "service": svc.get("service"),
            "product": svc.get("product"), "version": svc.get("version"),
        }.items() if v is not None}
        out.append(_mint(svc_ref, conf=open_confidence, attrs=svc_attrs))
        if host_hosts:
            out.append(_mint(subj, rel=EdgeKind.HOSTS, obj=svc_ref, conf=open_confidence))
        product = svc.get("product")
        if product:
            app_ref = canonicalize(NodeKind.APPLICATION, str(product))
            version = svc.get("version")
            out.append(_mint(app_ref, conf=open_confidence,
                             attrs={"version": version} if version else None))
            out.append(_mint(svc_ref, rel=EdgeKind.RUNS, obj=app_ref, conf=open_confidence))
    return out


# ---------------------------------------------------------------------------
# evidence_observations — the SHARED minter for external-MCP EVIDENCE leads
# ---------------------------------------------------------------------------
#
# The CONSUME-direction evidence connector (``mcp.evidence.MCPEvidenceSensor``) turns an operator's
# EXTERNAL MCP server's say-so about a subject's internals — a DB schema (tables/columns), an env
# keyset, a log stream — into world-model observations. That remote content is a THIRD PARTY's claim,
# so, exactly like the ``service_observations`` leads a consumed MCP TOOL mints, every entry enters as
# a LEAD (``IntelSourceKind.MCP_EVIDENCE``, projecting as ``GROUNDING_INTEL`` / the ``intel:`` tier),
# NEVER a fact: this minter sets ONLY ``source_kind`` for provenance (never an ``oracle:``/``cert:``
# grounding), writes no Finding, and never promotes. A deterministic CRUCIBLE oracle must later re-fire
# over a trusted-channel capture to turn a "the schema has table X" lead into a fact.

# The four evidence facets an external-MCP server reports about a subject's internals. An entry whose
# ``kind`` is not one of these is DROPPED — the untrusted remote cannot invent a new claim kind.
_EVIDENCE_KINDS = frozenset({"schema_table", "schema_column", "env_key", "log_event"})
_MAX_EVIDENCE_ENTRIES = 1024   # bound an untrusted remote payload so a giant schema cannot flood intake
_MAX_EVIDENCE_STR = 256        # bound every string field an untrusted remote supplies
_EVIDENCE_LEAD_CONFIDENCE = 0.6  # a modest per-datum confidence — a lead to RE-VERIFY, never proof


def evidence_observations(
    subject: EntityRef,
    entries: Iterable[dict],
    *,
    seq: int,
    source: str,
    source_kind: IntelSourceKind,
    reliability: SourceReliability,
) -> list[Observation]:
    """Mint one LEAD ``Observation`` per sanitized EVIDENCE entry ABOUT ``subject`` — the SHARED
    minter the external-MCP evidence connector reuses, so the DB-schema / env / log evidence schema is
    produced ONE way, exactly as ``service_observations`` is the one way a network-service sensor mints
    SERVICE leads.

    ``subject`` is the ``EntityRef`` the INTEGRATOR (the gated sensor) resolved for the surface its
    operator pointed the external MCP at (e.g. a ``DATASTORE`` / ``WEBAPP`` / ``APPLICATION``). Every
    entry is a node-claim about THAT one subject: the untrusted remote supplies only the per-entry
    ``(kind, name, detail)`` facet, never a node id — so, mirroring the consumed-tool sensor's
    scope-tight invariant, a remote payload can NEVER plant a new or off-scope node in the graph, only
    attach bounded evidence leads under the subject the integrator already gate-validated.

    Each ``entries`` item is a dict ``{"kind": one of "schema_table" | "schema_column" | "env_key" |
    "log_event", "name": str, "detail": optional str}``. The per-entry ``(evidence_kind, name, detail)``
    rides in the Observation's ``attrs`` (the authoritative, per-lead structured payload an oracle
    re-verifies one lead at a time).

    UNTRUSTED INPUT. ``entries`` is a remote third party's say-so, so it is sanitized HERE (this is the
    shared minter, kept robust for the untrusted CONSUME path): the number of entries examined is
    bounded (``_MAX_EVIDENCE_ENTRIES``), every string is length-bounded (``_MAX_EVIDENCE_STR``), only
    the four known evidence kinds survive, and any malformed entry — not a dict, an unknown ``kind``, or
    a missing/blank/non-str ``name`` — is DROPPED, never raised. A wholly malformed batch degrades to
    zero leads (no crash, no guess).

    LEAD, NEVER A FACT. Provenance is carried ONLY by ``source_kind`` (the caller passes
    ``IntelSourceKind.MCP_EVIDENCE``) at the caller's lead ``reliability`` (Admiralty C3 for an external
    MCP). This mints no oracle/cert grounding and no Finding; promotion to a fact is a later oracle's job.

    PURE / IDEMPOTENT. No wallclock, no rng, no positional counter: ``obs_id`` IS the
    ``(source, seq, kind, name)`` claim-key under the fixed ``subject`` (``source:seq:subject|kind|name``),
    so re-ingest, reordering, or an intra-batch duplicate collapse to ONE observation — the Beta belief
    never inflates from input ordering or duplication, exactly like ``service_observations``.

    NODE REPRESENTATION. Every entry is a claim about the SAME ``subject`` (relation/object ``None``), so
    the authoritative, complete, order-invariant per-lead record is the SET of claim-keyed Observations
    this returns — what an oracle re-verifies one lead at a time. When those project onto the shared
    subject GRAPH node, the projector merges their attrs LAST-WRITE-WINS, so ``node.attrs`` reflects one
    representative facet (the last processed) and is order-sensitive across differing remote orderings;
    the Beta belief and the obs_id set stay order-invariant. A consumer that needs every facet reads the
    Observation stream, not the single node's attrs."""
    out: list[Observation] = []
    for idx, entry in enumerate(entries):
        if idx >= _MAX_EVIDENCE_ENTRIES:        # bound the UNTRUSTED input (examined, not just minted)
            break
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        # Guard the membership test against an UNHASHABLE / non-str remote value: a list/dict ``kind``
        # would raise ``TypeError: unhashable type`` on the frozenset lookup and void the WHOLE batch.
        # A non-str kind is simply DROPPED, never raised — the shared firewall's drop-malformed /
        # never-raise contract must hold for EVERY caller, not only one that wraps it in try/except.
        if not isinstance(kind, str) or kind not in _EVIDENCE_KINDS:
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        name = name.strip()[:_MAX_EVIDENCE_STR]
        if not name:                            # a blank name is not a claim
            continue
        attrs: dict[str, Any] = {"evidence_kind": kind, "name": name}
        detail = entry.get("detail")
        if isinstance(detail, str):
            detail = detail.strip()[:_MAX_EVIDENCE_STR]
            if detail:
                attrs["detail"] = detail
        # obs_id IS the claim key at this (source, seq): the (kind, name) pair distinguishes the entry
        # under the fixed subject, so a DISTINCT (kind, name) gets a distinct id and the SAME one —
        # re-declared, reordered, or duplicated within one batch — gets the SAME id, so IntelIngest
        # dedups it and the Beta belief is not double-counted. No positional index, no clock, no rng.
        out.append(Observation(
            obs_id=f"{source}:{seq}:{subject.node_id}|{kind}|{name}",
            source=source, source_kind=source_kind, collector=source,
            subject=subject, relation=None, object=None, attrs=attrs,
            source_reliability=reliability, confidence=_EVIDENCE_LEAD_CONFIDENCE, seq=seq))
    return out
