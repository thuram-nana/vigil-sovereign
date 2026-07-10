"""
sensors.builtin — the built-in reference sensor (Wave 2.1).

``DeclaredServiceSensor`` is a SAFE, no-egress reference producer: the operator declares a host and
its listening services (from prior knowledge / an out-of-band inventory), and the sensor mints them
into the ONE world-model as HOST + SERVICE + ``HOSTS`` edges. It is the FIRST producer of the
port-bearing SERVICE / HOSTS structure the schema has always modelled but nothing produced. It needs
no network access (the operator supplies the data), so it is Tier 1, no entitlement, no egress — and
its output is a provenance-labelled OBSERVATION, never a fact (Wave 2.2 produces the same shape from a
real Nmap scan; Wave 2.3 re-verifies "open" to a fact via a handshake oracle).
"""

from __future__ import annotations

from ..agents.tools import ToolContext, ToolResult
from ..agents.tools.base import ToolRegistry
from ..intel.models import Credibility, IntelSourceKind, Reliability, SourceReliability
from .base import Sensor, service_observations

# Operator-declared inventory: reliable but not first-hand confirmed (Admiralty B2).
_DECLARED_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)


class DeclaredServiceSensor:
    """Mint operator-declared host services into the world-model. args:
    ``{"host": "10.0.0.5", "services": [{"port": 443, "protocol": "tcp", "service": "https",
    "product": "nginx", "version": "1.18.0"}]}``. Safe: no egress, no entitlement, deterministic."""

    name = "declared_service"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        host = args.get("host") if isinstance(args, dict) else None
        if not host or not isinstance(host, str):
            return ToolResult(ok=False, note="declared_service requires args['host'] (a string)")
        services = args.get("services") or []
        if not isinstance(services, list):
            return ToolResult(ok=False, note="declared_service args['services'] must be a list of dicts")
        return ToolResult(
            ok=True,
            summary=f"declared {host}: {len(services)} service(s)",
            output={"host": host, "services": [s for s in services if isinstance(s, dict)]})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        host = out.get("host")
        if not isinstance(host, str) or not host:
            return []
        return service_observations(
            host, out.get("services") or [], seq=seq, source="declared",
            source_kind=IntelSourceKind.OPERATOR_INGEST, reliability=_DECLARED_RELIABILITY)


def register_builtin_sensors(registry: ToolRegistry) -> ToolRegistry:
    """Register the built-in reference sensors onto ``registry`` and return it. Registration is not
    invocation — every sensor is still gated at ``run_sensor`` time, so registering the active Nmap
    sensor here is safe: it cannot run without its ``ACTIVE_RECON`` entitlement + charter scope."""
    from .nmap import NmapServiceSensor
    from .tshark import TsharkFlowSensor
    registry.register(DeclaredServiceSensor())
    registry.register(NmapServiceSensor())
    registry.register(TsharkFlowSensor())
    return registry


def default_registry() -> ToolRegistry:
    """A fresh registry pre-loaded with the built-in reference sensors."""
    return register_builtin_sensors(ToolRegistry())
