"""
agents.tools.base — the gated tool/sensor abstraction (W1.4).

The reasoning core needs a uniform, SAFE way to invoke capabilities — today internal ones
(re-verify a finding, query the world-model), and in Wave 2 the integrated sensors (Nmap, a
packet engine, Nuclei, a cloud API). This module is that seam: a ``Tool`` protocol + a
``ToolRegistry`` (mirroring ``scanner.checks.Check`` / ``agents.executor_proto.Executor`` and
their rosters), plus the typed ``ToolResult`` / ``ToolContext`` a gated invoker threads through.

The doctrine the invoker enforces (see ``agents.tools.invoker``):

  * FAIL-CLOSED gating. Every invocation passes the same fail-closed checks the HTTP path does —
    kill-switch, entitlement (per the tool's declared ``capability``), charter scope (if the tool
    acts on a host), destructive-confirm, and the egress allowlist (if the tool reaches hosts) —
    before ``run`` is ever called. A refused invocation NEVER runs the tool.
  * PROVE-DON'T-GUESS. A tool's output is a PROVENANCE-LABELLED OBSERVATION, not a fact. It
    becomes a fact only if a deterministic oracle later re-verifies it (Wave 2). ``ToolResult``
    is deliberately not a ``Finding``.
  * DETERMINISM. The invoker machinery (registry lookup, gate composition, event emission) is a
    pure function of ``(tool, args, gates, ctx)``. A tool's OUTPUT may reflect the live world, but
    nothing here reads the wallclock or a global rng.

A tool declares how it must be gated via optional metadata attributes (read defensively by the
invoker, safest-default when absent): ``tier`` ('T1'/'T2'/'T3'), ``capability`` (an entitlement
``Capability`` or None), ``destructive`` (bool), ``egress_hosts`` (tuple of hosts it reaches).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ...common.errors import CrucibleError


class ToolError(CrucibleError):
    """A recoverable tool-layer error — a duplicate/empty tool name, or an unknown tool. The
    tool layer records and gates; it makes no trust decision, so this is a plain CrucibleError."""


@dataclass
class ToolContext:
    """What a gated tool invocation is given. ``slug`` binds the run to its charter/scope/
    kill-switch. ``world`` is the optional shared world-model for read-only internal query tools.
    ``prompt_callback`` (``(question, timeout_s) -> bool``, default-deny) backs destructive-confirm.
    ``dry_run`` lets a tool short-circuit any real effect while still exercising the gates."""

    slug: str
    world: Any = None
    prompt_callback: Any = None
    dry_run: bool = False


@dataclass
class ToolResult:
    """The outcome of a gated tool invocation — a provenance-labelled observation, never a fact.

    ``ok`` is True iff the tool ran and produced a result. ``refused`` (with ``gate``) marks a
    fail-closed gate declining the invocation before the tool ran. ``summary`` is a short human/
    log line; ``output`` is the tool's structured result the caller may normalise into the world-
    model (Wave 2). ``note`` carries an error or refusal reason."""

    ok: bool
    summary: str = ""
    output: dict = field(default_factory=dict)
    refused: bool = False
    gate: str = ""
    note: str = ""


@runtime_checkable
class Tool(Protocol):
    """A named, gated capability the reasoning core can invoke. Minimally a stable ``name`` and a
    ``run`` — the gating metadata (``tier`` / ``capability`` / ``destructive`` / ``egress_hosts``)
    is optional and read defensively by the invoker. ``run`` returns a :class:`ToolResult`;
    raising is tolerated (the invoker turns it into a failed result, never a crash)."""

    name: str

    def run(self, args: dict, ctx: ToolContext) -> ToolResult: ...


class ToolRegistry:
    """A deterministic registry of tools by unique name. Registration is fail-loud on a duplicate
    or empty name; lookups and listings are stable (sorted), so a run over the registry never
    depends on insertion order."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        name = getattr(tool, "name", "")
        if not isinstance(name, str) or not name.strip():
            raise ToolError("a tool must have a non-empty string name")
        if not callable(getattr(tool, "run", None)):
            raise ToolError(f"tool {name!r} must expose a callable run(args, ctx)")
        if name in self._tools:
            raise ToolError(f"tool {name!r} is already registered")
        self._tools[name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)
