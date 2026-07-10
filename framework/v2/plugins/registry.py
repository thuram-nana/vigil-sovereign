"""
plugins.registry — the UNIFIED, read-only capability catalog (Wave 6a).

CRUCIBLE grew several independent rosters: the SENSOR registry
(``sensors.builtin.default_registry`` — auto-populated by imports), the internal
TOOL registry (``agents.tools.builtin.default_registry``), the ORACLE catalog
(``verify.verifier.BUG_CLASS_ORACLES``), the OPERATOR catalog
(``knowledge.catalog`` + ``knowledge.catalog_ext``), and the CLI subcommand
table (``__main__._DISPATCH``). Each is the source of truth for its own kind,
and each is discovered — never re-typed — here.

``capability_registry()`` is the single, deterministic, READ-ONLY view over all
of them: "what sensors / tools / oracles / operators / commands exist, what each
produces, its gating tier / entitlement, its graceful-absent behaviour." It is
the substrate a Wave-6 MCP server or HTTP API enumerates. It is the discovery
surface the SDK's plugin authors publish into via :class:`PluginRegistry`.

Doctrine, by construction:

  * READ-ONLY METADATA. The catalog is derived by INTROSPECTING declared
    attributes (``name`` / ``tier`` / ``capability`` / ``destructive`` /
    ``egress_hosts`` / optional ``produces``) and static catalog data. It NEVER
    calls a sensor's ``run`` / ``normalize``, an oracle, or an operator's
    ``apply``. Registration is not invocation — every capability stays gated at
    run time exactly as before; nothing here changes how any of them execute.

  * DISCOVERY, NOT DUPLICATION. Sensors/tools are read out of the LIVE
    ``ToolRegistry`` (so a sensor Wave 5 adds to ``register_builtin_sensors``
    auto-appears — no hardcoded roster). Oracle bug_classes are inverted from
    ``BUG_CLASS_ORACLES``; operator production is read off ``Operator.effects``.
    The catalog holds no independent copy of any registry's state.

  * DETERMINISM. The catalog is a pure, sorted, reproducible function of what is
    installed + what plugins registered. No wallclock, no rng — two calls over
    the same inputs yield byte-identical output.

  * EXTENSIBLE. A plugin adds a sensor/tool/oracle/operator through
    :class:`PluginRegistry` (mirroring ``ToolRegistry.register`` — fail-loud on a
    duplicate/empty name) WITHOUT editing core files, and it appears in the
    catalog. Wiring a plugin capability into a live execution path (the invoker,
    the verifier) is a SEPARATE, still-gated step this metadata layer never takes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..common.errors import CrucibleError


class PluginError(CrucibleError):
    """A plugin-registration fault — a duplicate/empty capability name, or an
    oracle mapping naming an OracleKind the deterministic substrate does not
    know. The registry records and describes; it makes no trust decision, so
    this is a plain CrucibleError, never an EthicsViolation."""


# ---------------------------------------------------------------------------
# Descriptor — one capability's read-only metadata row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityDescriptor:
    """A single capability described as pure metadata — enough for a third party
    (or an MCP/API layer) to reason about it WITHOUT running it.

    ``kind`` is one of ``sensor`` / ``tool`` / ``oracle`` / ``operator`` /
    ``command``. ``name`` is the capability's stable identifier within its kind.
    The gating fields (``tier`` / ``entitlement`` / ``destructive`` /
    ``egress_hosts``) mirror what the invoker reads to gate the capability — so
    the catalog shows exactly the clearance a run would require, never a run.
    ``produces`` is what the capability yields (bug_classes for an oracle,
    world-model edges/attrs for an operator, declared outputs for a sensor).
    ``degrades_cleanly`` reflects the sensor/tool contract (a missing binary /
    backend yields a failed result, never a crash or a fabricated fact)."""

    kind: str
    name: str
    summary: str = ""
    tier: str = ""
    entitlement: str | None = None
    destructive: bool = False
    egress_hosts: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    provable_by: tuple[str, ...] = ()
    intel_refs: tuple[str, ...] = ()
    degrades_cleanly: bool | None = None
    origin: str = "builtin"

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.kind, self.name)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-ready view. Optional/empty fields are omitted so the shape is
        compact; a caller that wants a fixed schema can default the absentees.
        Deterministic — the same descriptor always renders the same dict."""
        d: dict[str, Any] = {
            "kind": self.kind,
            "name": self.name,
            "origin": self.origin,
            "destructive": self.destructive,
        }
        if self.summary:
            d["summary"] = self.summary
        if self.tier:
            d["tier"] = self.tier
        # entitlement is meaningful even when None (== ungated), so always emit it.
        d["entitlement"] = self.entitlement
        if self.egress_hosts:
            d["egress_hosts"] = list(self.egress_hosts)
        if self.produces:
            d["produces"] = list(self.produces)
        if self.provable_by:
            d["provable_by"] = list(self.provable_by)
        if self.intel_refs:
            d["intel_refs"] = list(self.intel_refs)
        if self.degrades_cleanly is not None:
            d["degrades_cleanly"] = self.degrades_cleanly
        return d


# ---------------------------------------------------------------------------
# Catalog — the grouped, sorted view over all kinds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityCatalog:
    """The unified, read-only capability catalog, grouped by kind. Every group is
    already sorted by name, so the whole structure is a deterministic function of
    what is installed."""

    sensors: tuple[CapabilityDescriptor, ...] = ()
    tools: tuple[CapabilityDescriptor, ...] = ()
    oracles: tuple[CapabilityDescriptor, ...] = ()
    operators: tuple[CapabilityDescriptor, ...] = ()
    commands: tuple[CapabilityDescriptor, ...] = ()

    def groups(self) -> tuple[tuple[str, tuple[CapabilityDescriptor, ...]], ...]:
        """(group-name, descriptors) pairs in a fixed order — the CLI/JSON layout."""
        return (
            ("sensors", self.sensors),
            ("tools", self.tools),
            ("oracles", self.oracles),
            ("operators", self.operators),
            ("commands", self.commands),
        )

    def all(self) -> tuple[CapabilityDescriptor, ...]:
        """Every descriptor, flattened and sorted by ``(kind, name)``."""
        merged = [d for _, group in self.groups() for d in group]
        return tuple(sorted(merged, key=lambda d: d.sort_key))

    def get(self, kind: str, name: str) -> CapabilityDescriptor | None:
        for _, group in self.groups():
            for d in group:
                if d.kind == kind and d.name == name:
                    return d
        return None

    def counts(self) -> dict[str, int]:
        return {name: len(group) for name, group in self.groups()}

    def to_dict(self) -> dict[str, Any]:
        """A JSON-ready mapping ``{group: [descriptor, ...]}`` plus a ``counts``
        summary. Deterministic — safe to hash / diff across runs."""
        out: dict[str, Any] = {name: [d.to_dict() for d in group] for name, group in self.groups()}
        out["counts"] = self.counts()
        return out


# ---------------------------------------------------------------------------
# Plugin registration API — the extension seam (mirrors ToolRegistry.register)
# ---------------------------------------------------------------------------


class PluginRegistry:
    """A deterministic hold for capabilities a plugin contributes WITHOUT editing
    core files. Sensors and internal tools are held in real ``ToolRegistry``
    instances (so they inherit the exact fail-loud-on-duplicate/empty-name and
    sorted-listing semantics core sensors have); oracle bug_class→kind mappings
    and operators are held in name-keyed dicts with the same fail-loud contract.

    Holding a plugin sensor here makes it DISCOVERABLE (it shows in the catalog)
    and, separately and still fully gated, INVOKABLE by a caller that threads it
    through ``agents.tools.invoke_tool``. This registry itself never invokes
    anything — registration is not invocation."""

    def __init__(self) -> None:
        # imported lazily to keep this module import-light for the metadata path
        from ..agents.tools.base import ToolRegistry

        self._sensors: ToolRegistry = ToolRegistry()
        self._tools: ToolRegistry = ToolRegistry()
        self._oracles: dict[str, tuple[Any, ...]] = {}
        self._operators: dict[str, Any] = {}

    # -- register -----------------------------------------------------------

    def register_sensor(self, sensor: Any) -> None:
        """Contribute a sensor (a gated ``Tool`` that also ``normalize``s). Fails
        loud on a duplicate/empty name via ``ToolRegistry.register``."""
        self._sensors.register(sensor)

    def register_tool(self, tool: Any) -> None:
        """Contribute an internal (no-egress) tool. Fails loud like a sensor."""
        self._tools.register(tool)

    def register_oracle(self, bug_class: str, kinds: Iterable[Any]) -> None:
        """Declare that ``bug_class`` is confirmable by one or more EXISTING
        ``OracleKind``s. A plugin may map a NEW bug_class onto known oracle kinds
        (that is honest — those kinds already adjudicate); it may NOT invent a
        new oracle KIND, since only the verifier's fixed dispatch can run one.
        The mapping is discoverable metadata; it does not mutate the verifier."""
        from ..verify.verifier import normalize_bug_class

        key = normalize_bug_class(bug_class)
        if not key:
            raise PluginError("register_oracle requires a non-empty bug_class")
        coerced = tuple(_coerce_oracle_kind(k) for k in kinds)
        if not coerced:
            raise PluginError(f"register_oracle({bug_class!r}) requires at least one OracleKind")
        if key in self._oracles:
            raise PluginError(f"oracle bug_class {key!r} is already registered")
        self._oracles[key] = coerced

    def register_operator(self, operator: Any) -> None:
        """Contribute a technique ``Operator``. Fails loud on a duplicate/empty id."""
        op_id = str(getattr(operator, "id", "") or "")
        if not op_id.strip():
            raise PluginError("an operator must have a non-empty string id")
        if op_id in self._operators:
            raise PluginError(f"operator {op_id!r} is already registered")
        self._operators[op_id] = operator

    # -- read (deterministic, sorted) --------------------------------------

    def sensor_names(self) -> list[str]:
        return self._sensors.names()

    def get_sensor(self, name: str) -> Any:
        return self._sensors.get(name)

    def tool_names(self) -> list[str]:
        return self._tools.names()

    def get_tool(self, name: str) -> Any:
        return self._tools.get(name)

    def oracle_items(self) -> list[tuple[str, tuple[Any, ...]]]:
        return sorted(self._oracles.items())

    def operators(self) -> list[Any]:
        return [self._operators[k] for k in sorted(self._operators)]


def _coerce_oracle_kind(kind: Any) -> Any:
    """Normalise a plugin-declared oracle kind to a real ``OracleKind`` enum
    member — a str must name an existing member. An invented kind fails loud
    (the deterministic substrate can only run kinds it dispatches on)."""
    from ..verify.models import OracleKind

    if isinstance(kind, OracleKind):
        return kind
    try:
        return OracleKind(str(kind))
    except ValueError as e:
        raise PluginError(
            f"unknown OracleKind {kind!r} — a plugin may only map onto existing "
            f"oracle kinds, not invent one"
        ) from e


# A process-wide default plugin registry. A plugin imports this module and calls
# the module-level convenience functions (or default_plugins()) at import time to
# publish itself, exactly as one would call ToolRegistry.register.
_DEFAULT_PLUGINS = PluginRegistry()


def default_plugins() -> PluginRegistry:
    """The process-wide plugin registry ``capability_registry()`` reads by default.
    Tests should pass an explicit ``PluginRegistry`` to ``capability_registry`` to
    stay hermetic rather than mutating this global."""
    return _DEFAULT_PLUGINS


def register_sensor(sensor: Any) -> None:
    """Publish a sensor into the process-wide plugin registry."""
    _DEFAULT_PLUGINS.register_sensor(sensor)


def register_tool(tool: Any) -> None:
    """Publish an internal tool into the process-wide plugin registry."""
    _DEFAULT_PLUGINS.register_tool(tool)


def register_oracle(bug_class: str, kinds: Iterable[Any]) -> None:
    """Publish an oracle bug_class→kind mapping into the process-wide registry."""
    _DEFAULT_PLUGINS.register_oracle(bug_class, kinds)


def register_operator(operator: Any) -> None:
    """Publish a technique operator into the process-wide plugin registry."""
    _DEFAULT_PLUGINS.register_operator(operator)


# ---------------------------------------------------------------------------
# Introspection helpers (pure — read declared metadata, never run anything)
# ---------------------------------------------------------------------------


def _first_sentence(doc: str | None, *, limit: int = 200) -> str:
    """The first sentence of a class/function docstring, whitespace-collapsed and
    length-capped — a stable one-line human summary. Pure text, no side effects."""
    if not doc:
        return ""
    text = " ".join(doc.split())
    dot = text.find(". ")
    if 0 <= dot < limit:
        return text[: dot + 1]
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _str_tuple(value: Any) -> tuple[str, ...]:
    """Normalise a declared string-list attribute (``produces`` / refs) to a tuple
    of strings, defensively — a str becomes a 1-tuple (never char-iterated), a
    non-iterable / falsy value becomes ``()``. Never raises."""
    try:
        if not value:
            return ()
        if isinstance(value, (str, bytes)):
            s = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
            return (s,)
        return tuple(str(v) for v in value)
    except Exception:
        return ()


def _normalize_hosts(value: Any) -> tuple[str, ...]:
    """Normalise a declared ``egress_hosts`` for DISPLAY — the same shape the
    invoker gates on (falsy→(), str→1-tuple, iterable→tuple), so the catalog's
    egress view matches what a run would be gated against. Never raises."""
    return _str_tuple(value)


def _descriptor_from_tool(tool: Any, *, kind: str, origin: str) -> CapabilityDescriptor:
    """Build a descriptor from a gated ``Tool``/``Sensor`` by reading its DECLARED
    metadata attributes only (the same ones the invoker reads to gate it). Never
    calls ``run`` / ``normalize`` — pure introspection."""
    name = str(getattr(tool, "name", "") or "")
    tier = str(getattr(tool, "tier", "") or "")
    cap = getattr(tool, "capability", None)
    entitlement = str(getattr(cap, "value", cap)) if cap is not None else None
    destructive = bool(getattr(tool, "destructive", False))
    egress = _normalize_hosts(getattr(tool, "egress_hosts", ()))
    produces = _str_tuple(getattr(tool, "produces", ()))
    # The sensor/tool contract is degrade-cleanly (a missing binary/backend yields
    # a failed ToolResult, never a crash). Default True; a capability that does NOT
    # degrade cleanly declares ``graceful_absent = False`` to say so honestly.
    degrades = bool(getattr(tool, "graceful_absent", True))
    summary = _first_sentence(type(tool).__doc__)
    return CapabilityDescriptor(
        kind=kind,
        name=name,
        summary=summary,
        tier=tier,
        entitlement=entitlement,
        destructive=destructive,
        egress_hosts=egress,
        produces=produces,
        degrades_cleanly=degrades,
        origin=origin,
    )


def _tool_descriptors(
    registry: Any, *, kind: str, plugin_names: list[str], plugin_get: Any
) -> tuple[CapabilityDescriptor, ...]:
    """Discover descriptors for one ToolRegistry-backed kind (sensors or internal
    tools): the built-ins from ``registry`` then the plugin-contributed ones. A
    plugin name that collides with a built-in fails loud — a plugin may not
    silently shadow a core capability."""
    out: list[CapabilityDescriptor] = []
    builtin_names: set[str] = set()
    for name in registry.names():  # sorted, deterministic
        out.append(_descriptor_from_tool(registry.get(name), kind=kind, origin="builtin"))
        builtin_names.add(name)
    for name in plugin_names:  # sorted, deterministic
        if name in builtin_names:
            raise PluginError(f"plugin {kind} {name!r} collides with a built-in of the same name")
        out.append(_descriptor_from_tool(plugin_get(name), kind=kind, origin="plugin"))
    return tuple(sorted(out, key=lambda d: d.sort_key))


# Human summaries for the oracle KINDS (mirrors the OracleKind enum's own inline
# notes). A kind absent here falls back to a humanised value, so a new OracleKind
# is still described — never silently blank.
def _oracle_summaries() -> dict[Any, str]:
    from ..verify.models import OracleKind

    return {
        OracleKind.DIFFERENTIAL_RESPONSE: "A mutated request diverged from baseline on a chosen discriminator (boolean/time-based blind).",
        OracleKind.ACHIEVED_STATE: "An unauthorized state was actually reached — a predicate over observed evidence, no rubber-stamp.",
        OracleKind.SIDE_EFFECT: "A unique injected marker reached an observed sink.",
        OracleKind.OOB_CALLBACK: "A blind out-of-band interaction (DNS/HTTP) fired to a minted correlation token.",
        OracleKind.SANITIZER_SIGNAL: "An ASAN/UBSAN/panic/traceback appeared in process output.",
        OracleKind.TIMING: "A statistical time-based signal separated treatment from baseline latencies.",
        OracleKind.BOOLEAN_INFERENCE: "An SPRT over repeated true/false probes reached a decision.",
        OracleKind.REFLECTION_CONTEXT: "A marker reached an executable HTML/JS context.",
        OracleKind.EVALUATION: "The server evaluated an injected expression (SSTI/EL).",
        OracleKind.ERROR_SIGNATURE: "A datastore/parser error signature a payload provoked (error-based).",
        OracleKind.DOM_EXECUTION: "Injected JS actually executed in a real DOM (DOM-XSS).",
        OracleKind.SERVICE_REACHABILITY: "A real transport handshake reproduced (port open).",
        OracleKind.TLS_WEAKNESS: "A real TLS handshake negotiated a weak protocol/cipher.",
    }


def _oracle_descriptors(plugins: PluginRegistry) -> tuple[CapabilityDescriptor, ...]:
    """Discover the oracle catalog: each ``OracleKind`` and the bug_classes it can
    confirm, INVERTED from ``verify.verifier.BUG_CLASS_ORACLES`` (plus any plugin
    bug_class→kind mappings). The oracle KINDS are the fixed enum — a plugin can
    only widen the bug_classes an existing kind confirms, never add a kind."""
    from ..verify.models import OracleKind
    from ..verify.verifier import BUG_CLASS_ORACLES

    summaries = _oracle_summaries()
    by_kind: dict[OracleKind, set[str]] = {k: set() for k in OracleKind}
    for bug_class, kinds in BUG_CLASS_ORACLES.items():
        for k in kinds:
            by_kind[k].add(bug_class)
    for bug_class, kinds in plugins.oracle_items():
        for k in kinds:
            by_kind.setdefault(k, set()).add(bug_class)

    out: list[CapabilityDescriptor] = []
    for kind in sorted(by_kind, key=lambda k: k.value):
        produces = tuple(sorted(by_kind[kind]))
        out.append(
            CapabilityDescriptor(
                kind="oracle",
                name=kind.value,
                summary=summaries.get(kind, kind.value.replace("_", " ")),
                produces=produces,
                origin="builtin",
            )
        )
    return tuple(sorted(out, key=lambda d: d.sort_key))


def _operator_production(operator: Any) -> tuple[str, ...]:
    """What an operator ASSERTS if it fires — the edge kinds it adds and the node
    attrs it sets — read off ``Operator.effects``. Deterministic (sorted, unique).
    Reads declared structure only; never applies the operator."""
    from ..knowledge.models import EffectKind

    produced: set[str] = set()
    for effect in getattr(operator, "effects", ()) or ():
        if getattr(effect, "kind", None) is EffectKind.ASSERT_EDGE and effect.edge_kind is not None:
            produced.add(effect.edge_kind.value)
        elif getattr(effect, "attr", None):
            produced.add(f"attr:{effect.attr}")
    return tuple(sorted(produced))


def _descriptor_from_operator(operator: Any, origin: str) -> CapabilityDescriptor:
    """Build a descriptor from a technique ``Operator`` — its human name (+ tactic),
    the world-model facts it produces, the oracle that would confirm it, and its
    intel provenance. Pure introspection over the operator's declared fields."""
    name = str(getattr(operator, "id", "") or "")
    human = str(getattr(operator, "name", "") or "")
    tactic = getattr(operator, "tactic", None)
    summary = f"{human} [{tactic}]" if tactic else human
    oracle_kind = getattr(operator, "oracle_kind", None)
    provable_by = (str(getattr(oracle_kind, "value", oracle_kind)),) if oracle_kind is not None else ()
    intel_refs = _str_tuple(getattr(operator, "technique_ref", ()))
    return CapabilityDescriptor(
        kind="operator",
        name=name,
        summary=summary,
        produces=_operator_production(operator),
        provable_by=provable_by,
        intel_refs=intel_refs,
        origin=origin,
    )


def _operator_descriptors(plugins: PluginRegistry) -> tuple[CapabilityDescriptor, ...]:
    """Discover the operator catalog: the seed + extended technique catalogs, then
    plugin-contributed operators. A plugin id that collides with a built-in fails
    loud."""
    from ..knowledge.catalog import CATALOG
    from ..knowledge.catalog_ext import EXTENDED_CATALOG

    out: list[CapabilityDescriptor] = []
    builtin_ids: set[str] = set()
    for op in (*CATALOG, *EXTENDED_CATALOG):
        out.append(_descriptor_from_operator(op, "builtin"))
        builtin_ids.add(str(getattr(op, "id", "")))
    for op in plugins.operators():  # sorted by id
        op_id = str(getattr(op, "id", ""))
        if op_id in builtin_ids:
            raise PluginError(f"plugin operator {op_id!r} collides with a built-in of the same id")
        out.append(_descriptor_from_operator(op, "plugin"))
    return tuple(sorted(out, key=lambda d: d.sort_key))


def _command_descriptors() -> tuple[CapabilityDescriptor, ...]:
    """Discover the CLI subcommand surface from ``__main__._DISPATCH`` (names only —
    never the handler functions). Read defensively: any failure yields ``()`` so a
    command-table quirk can never destabilise the catalog."""
    try:
        import importlib

        main_mod = importlib.import_module("framework.v2.__main__")
        dispatch = getattr(main_mod, "_DISPATCH", {}) or {}
        out: list[CapabilityDescriptor] = []
        for name in sorted(dispatch):
            fn = dispatch.get(name)
            out.append(
                CapabilityDescriptor(
                    kind="command",
                    name=str(name),
                    summary=_first_sentence(getattr(fn, "__doc__", None)),
                    origin="builtin",
                )
            )
        return tuple(out)
    except Exception:
        return ()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def capability_registry(
    *,
    sensor_registry: Any = None,
    tool_registry: Any = None,
    plugins: PluginRegistry | None = None,
    include_commands: bool = True,
) -> CapabilityCatalog:
    """Build the unified, read-only :class:`CapabilityCatalog`.

    With no arguments it discovers the LIVE built-in rosters (a fresh sensor
    registry, a fresh internal-tool registry, the oracle + operator catalogs, the
    CLI table) plus whatever the process-wide plugin registry holds. Callers
    (tests, an MCP layer wanting a hermetic view) may inject their own
    ``sensor_registry`` / ``tool_registry`` / ``plugins`` instead.

    Pure and deterministic: it only reads declared metadata and static catalog
    data, sorts every group, and returns. It never runs a capability."""
    if plugins is None:
        plugins = default_plugins()

    if sensor_registry is None:
        from ..sensors.builtin import default_registry as sensor_default

        sensor_registry = sensor_default()
    if tool_registry is None:
        from ..agents.tools.builtin import default_registry as tool_default

        tool_registry = tool_default()

    sensors = _tool_descriptors(
        sensor_registry, kind="sensor",
        plugin_names=plugins.sensor_names(), plugin_get=plugins.get_sensor,
    )
    tools = _tool_descriptors(
        tool_registry, kind="tool",
        plugin_names=plugins.tool_names(), plugin_get=plugins.get_tool,
    )
    oracles = _oracle_descriptors(plugins)
    operators = _operator_descriptors(plugins)
    commands = _command_descriptors() if include_commands else ()

    return CapabilityCatalog(
        sensors=sensors,
        tools=tools,
        oracles=oracles,
        operators=operators,
        commands=commands,
    )
