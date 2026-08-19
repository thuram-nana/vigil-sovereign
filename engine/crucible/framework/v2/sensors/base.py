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
# readable INCONCLUSIVE outcome that NAMES the prerequisite and is visibly distinct from an assessed
# run — never a clean negative.

INCONCLUSIVE = "inconclusive"


def inconclusive_result(sensor: str, *, missing: str, detail: str) -> ToolResult:
    """Mint a MISSING-PREREQUISITE sensor outcome as an explicit, machine-readable INCONCLUSIVE
    verdict — NEVER a clean negative.

    A live cloud/K8s sensor that lacks a prerequisite (AMBIENT read-only credentials, or a provisioned
    egress scope — ``targets/<slug>/collector-hosts.txt``) has assessed NOTHING. Reporting that as
    "found nothing" is a silent CLEAN — the worst failure mode for a sound-negative product. So the
    outcome is ``ok=False`` (nothing ran to completion) carrying a TYPED marker in ``output`` —
    ``status='inconclusive'``, ``assessed=False``, ``missing_prerequisite=<name>`` — that a report/
    verdict layer keys on to keep a not-assessed surface OUT of any clean negative, plus a loud
    ``note`` that leads with INCONCLUSIVE and names what was not assessed. The marker rides in
    ``output`` because a failed ToolResult carries no facts, so that field is free for the reason
    (a report keys on the TYPED marker, not on the free-text note). Total."""
    return ToolResult(
        ok=False,
        note=(f"{sensor}: INCONCLUSIVE — a missing prerequisite means NOTHING was assessed; this is "
              f"NOT a clean result. {detail}"),
        output={"status": INCONCLUSIVE, "assessed": False, "missing_prerequisite": missing,
                "sensor": sensor},
    )


def is_inconclusive(result: Any) -> bool:
    """True iff ``result`` is a structured INCONCLUSIVE sensor outcome (a missing prerequisite meant
    NOTHING was assessed) — the signal a verdict/report layer keys on to keep a not-assessed surface
    out of a clean negative. Total: a plain failure, an assessed ``ok=True`` result, or ``None`` is
    NOT inconclusive."""
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
        """True iff a prerequisite was missing so NOTHING was assessed — a not-assessed outcome the
        caller must keep OUT of any clean negative (see ``inconclusive_result``)."""
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
