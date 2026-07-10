"""
mcp.sensor — CONSUME an external MCP tool AS A GATED SENSOR (W6b, CONSUME direction).

This is literally the Wave-2 sensor interface over MCP: an external MCP tool becomes a first-class
CRUCIBLE :class:`sensors.base.Sensor` (a gated ``agents.tools.Tool`` + a ``normalize`` step), so it
runs through the SAME machinery every other producer does —

    run_sensor  ->  invoke_tool (kill-switch / entitlement / scope / destructive / egress)
                ->  MCPSensor.run (call the external tool via mcp.client)
                ->  MCPSensor.normalize (raw output -> Observations)  ->  IntelIngest -> world-model

Doctrine, by construction:
  * PROVE-DON'T-GUESS. The external tool's output is a THIRD PARTY's say-so. It enters the ONE
    world-model as a provenance-labelled OBSERVATION (``IntelSourceKind.MCP_TOOL``) at MODERATE
    reliability (Admiralty C3) — a LEAD, projecting as ``GROUNDING_INTEL``, NEVER a fact. The sensor
    never writes a Finding and never promotes; a deterministic CRUCIBLE oracle re-verifies the lead
    (e.g. a real service-reachability handshake) to turn an "open port" claim into a fact.
  * GATED / SCOPE-TIGHT. The sensor acts on ``args['host']`` — the invoker charter-scope-gates it, so
    the external tool is only ever driven against an in-scope host. And normalization mints leads ONLY
    under that gate-validated host (a service the remote CLAIMS for another host is attributed to the
    scoped host or dropped) — an untrusted remote payload can NEVER plant an off-scope asset.
  * UNTRUSTED INPUT. The remote structured content is sanitized: only known service fields survive,
    string lengths and list size are bounded, and anything malformed degrades to zero leads (no crash,
    no guess).
  * DETERMINISM. The remote OUTPUT reflects the live world, but ``normalize -> Observation -> project``
    is a PURE, replayable function of that output (caller ``seq``, no wallclock, no rng); claim-keyed
    ``obs_id`` makes re-ingest idempotent.
"""

from __future__ import annotations

from typing import Any

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from ..sensors.base import service_observations

# An external MCP tool is a source of MODERATE trust: the tool is generally reliable (C) but its
# specific datum is only possibly-true (C3) — a heuristic report, not an oracle proof. weight() ≈ 0.65,
# so a lead enters the graph (reliability > 0) but moves belief only modestly, exactly like a
# third-party web-scanner match. The whole point is that this is a lead to re-verify, not proof.
_MCP_LEAD_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)

# Bounds on untrusted remote structured content.
_MAX_SERVICES = 256
_MAX_STR = 256
_SERVICE_FIELDS = ("port", "protocol", "state", "service", "product", "version")


def _clip(value: Any) -> Any:
    """Keep only a scalar string/number field (never a bool masquerading as a number), string-length
    bounded — so a giant or structured value from an untrusted remote cannot enter the world-model."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return value[:_MAX_STR]
    if isinstance(value, (int, float)):
        return value
    return None


def _safe_services(value: Any) -> list[dict]:
    """Sanitize an untrusted remote ``services`` list into the shape ``service_observations`` expects:
    a bounded list of dicts carrying ONLY known service fields (no ``host``/``subject``/arbitrary attrs
    that could redirect or pollute the graph). A non-list, or an item without a usable ``port``, is
    dropped. This is the untrusted-input firewall for the CONSUME path."""
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value[:_MAX_SERVICES]:
        if not isinstance(item, dict):
            continue
        svc: dict[str, Any] = {}
        for k in _SERVICE_FIELDS:
            if k in item:
                clipped = _clip(item[k])
                if clipped is not None:
                    svc[k] = clipped
        if "port" in svc:            # only a port-bearing entry can mint a SERVICE lead
            out.append(svc)
    return out


class MCPSensor:
    """Wrap one external MCP tool as a gated, lead-producing CRUCIBLE sensor.

    Gating metadata is DECLARED by the operator at construction (default-conservative): an external
    tool that actively probes should be given ``capability=Capability.ACTIVE_RECON`` and, if it is a
    remote server, its host in ``egress_hosts`` — the invoker then entitlement/egress-gates it just
    like a first-party active sensor. The default (Tier-1, no capability, no egress) suits a passive
    external producer. Either way the charter-scope gate on ``args['host']`` always applies."""

    def __init__(
        self,
        name: str,
        client: Any,
        remote_tool: str,
        *,
        capability: Any = None,
        tier: str = "T1",
        destructive: bool = False,
        egress_hosts: tuple = (),
        reliability: SourceReliability | None = None,
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("MCPSensor requires a non-empty name")
        if not isinstance(remote_tool, str) or not remote_tool.strip():
            raise ValueError("MCPSensor requires a non-empty remote_tool name")
        if not callable(getattr(client, "call_tool", None)):
            raise ValueError("MCPSensor requires an mcp.client.MCPClient (with call_tool)")
        self.name = name.strip()
        self._client = client
        self._remote_tool = remote_tool.strip()
        self.tier = str(tier)
        self.capability = capability
        self.destructive = bool(destructive)
        self.egress_hosts = tuple(egress_hosts) if egress_hosts else ()
        self._reliability = reliability if reliability is not None else _MCP_LEAD_RELIABILITY

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        host = args.get("host") if isinstance(args, dict) else None
        if not host or not isinstance(host, str):
            return ToolResult(ok=False, note=f"{self.name} requires args['host'] (a scoped string)")
        remote_args = args.get("remote_args") if isinstance(args, dict) else None
        if remote_args is not None and not isinstance(remote_args, dict):
            return ToolResult(ok=False, note=f"{self.name} args['remote_args'] must be an object")
        # Dry-run exercises the gate chain without any external call (byte-safe rehearsal).
        if getattr(ctx, "dry_run", False):
            return ToolResult(ok=True, summary=f"[dry-run] {self.name} on {host}",
                              output={"host": host, "services": []})
        payload = dict(remote_args or {})
        payload.setdefault("host", host)   # default the remote tool onto the SCOPED host
        try:
            res = self._client.call_tool(self._remote_tool, payload)
        except Exception as e:
            return ToolResult(ok=False, note=f"{self.name} external MCP call failed: {type(e).__name__}: {e}")
        if not isinstance(res, dict) or not res.get("ok"):
            reason = ""
            if isinstance(res, dict) and isinstance(res.get("error"), dict):
                reason = str(res["error"].get("message", ""))
            return ToolResult(ok=False, note=f"{self.name} external tool returned no usable result{': ' + reason if reason else ''}")
        services = _safe_services(res.get("structured", {}).get("services") if isinstance(res.get("structured"), dict) else None)
        return ToolResult(
            ok=True,
            summary=f"{self.name}: {len(services)} service lead(s) on {host} (via {self._remote_tool})",
            output={"host": host, "services": services, "remote_tool": self._remote_tool})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        host = out.get("host")
        if not isinstance(host, str) or not host:
            return []
        # Mint ONLY under the gate-validated scoped host — never a host the untrusted remote supplied.
        return service_observations(
            host, out.get("services") or [], seq=seq, source=f"mcp:{self.name}",
            source_kind=IntelSourceKind.MCP_TOOL, reliability=self._reliability)
