"""
mcp.evidence_sensor — CONSUME an operator's external MCP EVIDENCE server AS A GATED, LEAD-ONLY SENSOR
(the CONSUME-direction evidence connector — the glue over Modules A/B/C).

Where :class:`mcp.sensor.MCPSensor` consumes an external RECON tool driven against a charter-scoped
ATTACK host (minting SERVICE leads), this consumes an operator's OWN evidence infrastructure — a
DB-schema server, a logs/env server — that DESCRIBES a subject's internals. Same machinery (a gated
``agents.tools.Tool`` + a ``normalize`` step), the same one world-model, the same LEAD-not-FACT firewall;
a DIFFERENT, deliberately disjoint axis::

    load_evidence_servers(slug)       (Module B: operator-only allowlist, DISJOINT from attack scope)
      -> FloorPinnedHttpTransport     (Module C: egress through the never-liftable L3/L4 floor) | or Stdio
      -> MCPClient.call_tool          (mcp.client: untrusted JSON-RPC, normalised, never trusted)
      -> MCPEvidenceSensor.run        (sanitise the remote's say-so, under invoke_tool's gate chain)
      -> MCPEvidenceSensor.normalize  (evidence_observations: Module A's shared minter)
      -> IntelIngest                  (the one world-model; GROUNDING_INTEL, NEVER a fact)

Doctrine, by construction:
  * THIRD-PARTY SAY-SO -> LEAD, NEVER A FACT. Everything an external evidence server returns is one
    remote party's claim. It enters as an ``IntelSourceKind.MCP_EVIDENCE`` observation (Admiralty C3, a
    ``GROUNDING_INTEL`` lead); the sensor writes no Finding and never promotes. A deterministic CRUCIBLE
    oracle must re-fire over a TRUSTED-channel capture to turn "the schema has column users.ssn" into a
    fact — so there is DELIBERATELY NO ``_reverify`` on this axis (promotion is a downstream oracle's
    job over a channel we trust, never the evidence server's own say-so).
  * SUBJECT FIXED BY THE INTEGRATOR. The subject (the surface the operator pointed the external MCP at)
    is resolved by the INTEGRATOR and fixed on the sensor; the untrusted remote supplies only the
    per-entry ``(kind, name, detail)`` facet and can NEVER plant or redirect to another node — Module A
    (``evidence_observations``) enforces this.
  * DISJOINT EGRESS AXIS, DOUBLY GATED. An evidence server is the operator's OWN infra, provisioned on a
    SEPARATE axis from the charter target scope and DROPPED if it overlaps it
    (``egress_guard.collector_scope_conflicts``) — a recon/evidence source must be a third party disjoint
    from what we attack. An http server's host is (a) pinned to the never-liftable floor by Module C's
    transport AND (b) declared in the sensor's ``egress_hosts`` so ``invoke_tool``'s egress gate refuses
    it unless the operator also listed it in ``targets/<slug>/collector-hosts.txt`` (exactly like a live
    collector) — the ONE exemption is the loopback family (``127.0.0.1``/``::1``/``localhost``), which the
    engine's egress baseline always permits (it is the operator's own box and adds no new network reach),
    so a loopback evidence server is reachable on the config file alone. A stdio server spawns a local
    subprocess — no egress host, so that gate is skipped.
  * UNTRUSTED INPUT, ONE FIREWALL. The remote structured content is read defensively into a bounded
    candidate list here; every sanitising DECISION (known kinds only, bounded strings, drop-malformed)
    lives in ``evidence_observations`` — the single shared firewall, never duplicated.

Pure stdlib + framework only; no ``sigil`` import, no integration-layer import.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from ..agents.egress_guard import (
    EgressAllowlist,
    build_engagement_allowlist,
    collector_scope_conflicts,
)
from ..agents.tools import ToolContext, ToolRegistry, ToolResult
from ..intel.ingest import IntelIngest
from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from ..intel.refs import EntityRef
from ..sensors.base import _MAX_EVIDENCE_ENTRIES, evidence_observations
from ..sensors.pipeline import run_sensor
from .client import MCPClient, StdioSubprocessTransport
from .evidence_config import EvidenceServer, evidence_egress_hosts, load_evidence_servers
from .evidence_transport import FloorPinnedHttpTransport

__all__ = [
    "MCPEvidenceSensor",
    "build_evidence_sensors",
    "fuse_evidence_sensors",
]

# An external MCP evidence server is a MODERATE-trust source: generally reliable (C) but its specific
# datum is only possibly-true (C3) — a lead to RE-VERIFY over a trusted channel, never an oracle proof.
# Exactly the rating a consumed MCP tool's leads carry (``mcp.sensor._MCP_LEAD_RELIABILITY``).
_MCP_EVIDENCE_LEAD_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)

# The convenience arrays an evidence server MAY return instead of a flat ``entries`` list — each maps to
# one of the four evidence kinds. An item is a bare name string or a ``{"name", "detail"?}`` object; the
# minter (``evidence_observations``) is the authoritative firewall for every one.
_KIND_ARRAYS: tuple[tuple[str, str], ...] = (
    ("tables", "schema_table"),
    ("columns", "schema_column"),
    ("env_keys", "env_key"),
    ("log_events", "log_event"),
)


def _safe_entries(structured: Any) -> list[dict]:
    """Assemble a BOUNDED list of candidate evidence entries from an UNTRUSTED remote structured content.

    Two accepted shapes (both pass through the minter's firewall unchanged):
      * a flat ``structured["entries"]`` list of ``{"kind", "name", "detail"?}`` objects, or
      * the per-kind convenience arrays (``tables``/``columns``/``env_keys``/``log_events``), each item a
        bare name string or a ``{"name", "detail"?}`` object.

    This NEVER validates a claim (``evidence_observations`` does — one firewall); it only bounds how many
    candidates are assembled so a giant remote payload cannot build an unbounded intermediate list. A
    non-dict ``structured``, or neither shape, yields ``[]``."""
    if not isinstance(structured, dict):
        return []
    out: list[dict] = []
    flat = structured.get("entries")
    if isinstance(flat, list):
        for item in flat:
            if isinstance(item, dict):
                # Copy ONLY the three fields the minter reads — never the raw remote dict (defence-in-depth,
                # mirroring the sibling mcp.sensor._safe_services allowlist; the minter stays the firewall).
                out.append({k: item[k] for k in ("kind", "name", "detail") if k in item})
            if len(out) >= _MAX_EVIDENCE_ENTRIES:
                return out
    for key, kind in _KIND_ARRAYS:
        arr = structured.get(key)
        if not isinstance(arr, list):
            continue
        for item in arr:
            if isinstance(item, str):
                out.append({"kind": kind, "name": item})
            elif isinstance(item, dict):
                entry: dict[str, Any] = {"kind": kind}
                if "name" in item:
                    entry["name"] = item.get("name")
                if "detail" in item:
                    entry["detail"] = item.get("detail")
                out.append(entry)
            # a non-str / non-dict array item is skipped (the minter would drop it anyway)
            if len(out) >= _MAX_EVIDENCE_ENTRIES:
                return out
    return out


class MCPEvidenceSensor:
    """Wrap one external MCP evidence tool as a gated, LEAD-ONLY CRUCIBLE sensor bound to a FIXED subject.

    The subject (an :class:`intel.refs.EntityRef`) is the surface the operator pointed the external MCP at
    — resolved by the INTEGRATOR, never by the untrusted remote. ``run`` calls the remote evidence tool
    (optionally with operator-supplied ``args['remote_args']`` filters) and sanitises its say-so into a
    bounded entries list; ``normalize`` mints one ``MCP_EVIDENCE`` lead per entry ABOUT that subject. No
    host is ever forced from the remote payload (unlike ``MCPSensor``, whose attack-host IS the scope
    gate) — here the subject is the operator's own infra and the remote can only attach bounded leads
    under it.

    Gating metadata is DECLARED at construction (default-conservative Tier-1, no capability, no egress —
    a stdio evidence server). For an http evidence server the builder passes its host in ``egress_hosts``
    so ``invoke_tool`` egress-gates it against ``targets/<slug>/collector-hosts.txt`` just like a live
    collector. ``destructive`` is ALWAYS False — reading evidence never mutates a target."""

    def __init__(
        self,
        name: str,
        client: Any,
        remote_tool: str,
        subject: EntityRef,
        *,
        tier: str = "T1",
        capability: Any = None,
        egress_hosts: tuple = (),
        reliability: SourceReliability | None = None,
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("MCPEvidenceSensor requires a non-empty name")
        if not isinstance(remote_tool, str) or not remote_tool.strip():
            raise ValueError("MCPEvidenceSensor requires a non-empty remote_tool name")
        if not callable(getattr(client, "call_tool", None)):
            raise ValueError("MCPEvidenceSensor requires an mcp.client.MCPClient (with call_tool)")
        if not isinstance(subject, EntityRef):
            raise ValueError("MCPEvidenceSensor requires an EntityRef subject (resolved by the integrator)")
        self.name = name.strip()
        self._client = client
        self._remote_tool = remote_tool.strip()
        self._subject = subject
        self.tier = str(tier)
        self.capability = capability
        self.destructive = False            # reading evidence is never destructive — fixed, not a knob
        self.egress_hosts = tuple(egress_hosts) if egress_hosts else ()
        self._reliability = reliability if reliability is not None else _MCP_EVIDENCE_LEAD_RELIABILITY

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        remote_args = args.get("remote_args") if isinstance(args, dict) else None
        if remote_args is not None and not isinstance(remote_args, dict):
            return ToolResult(ok=False, note=f"{self.name} args['remote_args'] must be an object")
        # Dry-run exercises the gate chain without any external call (byte-safe rehearsal).
        if getattr(ctx, "dry_run", False):
            return ToolResult(ok=True, summary=f"[dry-run] {self.name} on {self._subject.node_id}",
                              output={"entries": [], "remote_tool": self._remote_tool})
        try:
            res = self._client.call_tool(self._remote_tool, dict(remote_args or {}))
        except Exception as e:
            return ToolResult(ok=False,
                              note=f"{self.name} external MCP call failed: {type(e).__name__}: {e}")
        if not isinstance(res, dict) or not res.get("ok"):
            reason = ""
            if isinstance(res, dict) and isinstance(res.get("error"), dict):
                reason = str(res["error"].get("message", ""))
            return ToolResult(
                ok=False,
                note=f"{self.name} external evidence tool returned no usable result"
                     f"{': ' + reason if reason else ''}")
        structured = res.get("structured") if isinstance(res.get("structured"), dict) else None
        entries = _safe_entries(structured)
        return ToolResult(
            ok=True,
            summary=f"{self.name}: {len(entries)} evidence lead(s) on {self._subject.node_id} "
                    f"(via {self._remote_tool})",
            output={"entries": entries, "remote_tool": self._remote_tool})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        entries = out.get("entries")
        if not isinstance(entries, list):
            return []
        # Mint ONLY under the integrator-fixed subject — never a node the untrusted remote supplied.
        return evidence_observations(
            self._subject, entries, seq=seq, source=f"mcp:{self.name}",
            source_kind=IntelSourceKind.MCP_EVIDENCE, reliability=self._reliability)


# =============================================================================
# BUILDER — turn provisioned evidence servers (Module B) into gated, floor-pinned sensors
# =============================================================================


def _default_client_factory(
    allowlist: EgressAllowlist, slug: str, token_resolver: Callable[[str], "str | None"],
) -> Callable[[EvidenceServer], MCPClient]:
    """The PRODUCTION client factory: an http server dials through Module C's floor-pinned transport
    (name allowlist + never-liftable L3/L4 floor); a stdio server spawns a local subprocess (no egress).
    A bearer token is resolved OUT-OF-BAND from the env var NAMED by ``auth_env`` (never from the config
    file, never logged) at build time."""
    def factory(server: EvidenceServer) -> MCPClient:
        if server.transport == "http":
            token = token_resolver(server.auth_env) if server.auth_env else None
            transport: Any = FloorPinnedHttpTransport(
                str(server.url), allowlist, slug=slug, token=token)
        else:  # "stdio" — a local subprocess, no egress host
            transport = StdioSubprocessTransport([str(server.command), *server.args])
        return MCPClient(transport, name=f"mcp-evidence:{server.id}")
    return factory


def build_evidence_sensors(
    slug: str,
    subject: EntityRef,
    *,
    allowlist: "EgressAllowlist | None" = None,
    reliability: "SourceReliability | None" = None,
    token_resolver: Callable[[str], "str | None"] = os.environ.get,
    client_factory: "Callable[[EvidenceServer], Any] | None" = None,
    root: "str | None" = None,
) -> tuple[list[MCPEvidenceSensor], list[str]]:
    """Turn the operator's provisioned external-MCP evidence servers (``targets/<slug>/
    mcp-evidence-servers.json``, Module B) into gated, floor-pinned, LEAD-ONLY :class:`MCPEvidenceSensor`
    instances bound to ``subject``. Returns ``(sensors, skipped)`` where ``skipped`` is a list of
    NON-SECRET reasons a server produced no sensor (for an operator UI).

    DEFAULT-EMPTY + fail-closed: no provisioning file ⇒ ``([], [])`` (the connector is OFF until the
    operator provisions it). A server is turned into sensors ONLY if it declares ``allowed_tools`` — one
    sensor per declared tool — so the builder never has to egress to enumerate tools; a server with none
    is skipped with an issue. An http server whose host OVERLAPS the charter target scope is DROPPED
    (``collector_scope_conflicts`` — the disjointness doctrine). Each http sensor's host rides in
    ``egress_hosts`` so ``invoke_tool`` egress-gates it (the operator must also list it in
    ``collector-hosts.txt``); a stdio sensor needs no egress.

    ``allowlist``      the engagement :class:`EgressAllowlist` the http transport dials through; defaults
                       to ``build_engagement_allowlist(slug, collector_hosts=<the evidence hosts>)`` so the
                       transport permits exactly the provisioned evidence hosts (conflicts/over-broad
                       already dropped by that builder).
    ``token_resolver`` resolves ``auth_env`` (an env-var NAME) to the bearer VALUE out-of-band; defaults
                       to ``os.environ.get``.
    ``client_factory`` TEST SEAM — ``(EvidenceServer) -> client``; defaults to the production factory
                       (floor-pinned http / stdio subprocess).
    ``root``           deployment/test override for the crucible root the config is read from (threaded
                       to :func:`load_evidence_servers`); ``None`` uses the real repo layout."""
    servers = load_evidence_servers(slug, root=root)
    if not servers:
        return [], []

    target_hosts: tuple[str, ...] = ()
    if allowlist is None:
        allowlist = build_engagement_allowlist(
            slug=slug, collector_hosts=evidence_egress_hosts(servers))
    target_hosts = tuple(allowlist.target_hosts)
    factory = client_factory or _default_client_factory(allowlist, slug, token_resolver)
    rel = reliability if reliability is not None else _MCP_EVIDENCE_LEAD_RELIABILITY

    sensors: list[MCPEvidenceSensor] = []
    skipped: list[str] = []
    for server in servers:
        if not server.allowed_tools:
            skipped.append(f"{server.id}: declares no 'allowed_tools' (cannot enumerate without egress)")
            continue
        egress_hosts: tuple[str, ...] = ()
        if server.transport == "http":
            host = server.host or ""
            # Disjointness doctrine: an evidence host that overlaps the attack scope is DROPPED.
            if host and collector_scope_conflicts([host], target_hosts):
                skipped.append(f"{server.id}: host overlaps the charter target scope (dropped — an "
                               f"evidence source must be disjoint from the attack target)")
                continue
            egress_hosts = (host,) if host else ("<malformed-evidence-host>",)
        try:
            client = factory(server)
        except Exception as e:   # a transport that refuses to construct (e.g. a bad URL) drops the server
            skipped.append(f"{server.id}: transport could not be constructed ({type(e).__name__})")
            continue
        for tool in server.allowed_tools:
            sensors.append(MCPEvidenceSensor(
                name=f"mcp_evidence:{server.id}:{tool}",
                client=client,
                remote_tool=tool,
                subject=subject,
                tier="T1",
                capability=None,
                egress_hosts=egress_hosts,
                reliability=rel))
    return sensors, skipped


def fuse_evidence_sensors(
    world: Any,
    slug: str,
    ctx: ToolContext,
    *,
    subject: EntityRef,
    seq: int,
    reliability: "SourceReliability | None" = None,
    token_resolver: Callable[[str], "str | None"] = os.environ.get,
    client_factory: "Callable[[EvidenceServer], Any] | None" = None,
    root: "str | None" = None,
    sink: Any = None,
) -> int:
    """Run every provisioned evidence sensor through the SAME gated pipeline the attack-surface sensors
    use (``run_sensor``: ``invoke_tool`` gate chain → ``normalize`` → ``IntelIngest``), ingesting the
    results into ``world`` as ``MCP_EVIDENCE`` LEADS. Returns the number of observations that projected
    new/updated world state.

    LEAD-ONLY, by design: there is deliberately NO re-verification / promotion step here — an evidence
    server's say-so is a lead a downstream deterministic oracle must re-fire over a trusted channel to
    turn into a fact. OFF BY DEFAULT: with nothing provisioned this ingests nothing (fail-closed). ``seq``
    stamps the batch on the run's monotonic clock; within ONE pass, reordered or duplicated entries
    collapse (claim-keyed ``obs_id``). NOTE: a fresh ``IntelIngest`` is built per call, so this is NOT
    re-run-idempotent on the SAME world at the SAME ``seq`` — a replay at an unchanged ``seq`` re-projects
    and the subject's Beta belief grows (the same semantics as ``engage_fusion.fuse_sensors``). Callers
    ADVANCE ``seq`` across passes, so each pass is a genuine, distinct observation."""
    sensors, _skipped = build_evidence_sensors(
        slug, subject, reliability=reliability, token_resolver=token_resolver,
        client_factory=client_factory, root=root)
    if not sensors:
        return 0
    reg = ToolRegistry()
    for sensor in sensors:
        reg.register(sensor)
    ingest = IntelIngest(world, engagement_slug=slug)
    applied = 0
    for i, sensor in enumerate(sensors):
        res = run_sensor(reg, sensor.name, {}, ctx, ingest=ingest, seq=seq + i, sink=sink)
        applied += res.applied
    return applied
