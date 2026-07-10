"""
imports.tool — ``ImportFindingsTool``, the importer as a GATED tool.

Wrapping the importer as an ``agents.tools.Tool`` means an import driven over the
external API runs through the EXACT SAME fail-closed gate chain as any other action:
``agents.tools.invoke_tool`` runs the kill-switch gate (fail-closed), the entitlement
gate (this tool declares the baseline ``PASSIVE_INTAKE`` capability), and — because
the import reaches NO host and declares no egress — nothing else. A tripped
kill-switch refuses the import before it runs, exactly as it would locally.

The import is PASSIVE by design: it reaches no target, sends nothing, and mints only
GROUNDING_INTEL leads (never facts). It therefore declares no ``target``/``host`` arg,
so the charter-scope gate is skipped — a third-party report legitimately references
many hosts, and a lead about a host is informational; ACTING on that lead (re-verify /
scan) is a separate, scope-gated action. This keeps the intel doctrine: leads are
never auto-scanned; the oracle stays the sole authority on what is real.
"""

from __future__ import annotations

import json

from ..agents.tools.base import ToolContext, ToolResult
from ..entitlement import Capability
from .importer import import_report
from .models import ImportAdapterError
from .parsers import detect_format

# request-body bound (defense in depth; the API server also bounds the raw body).
_MAX_REPORT_BYTES = 8 * 1024 * 1024


def default_intel_store():
    """Build the durable intel store (over the standard memory db) so an imported
    batch persists and the API's ``/imports`` read can enumerate it. Best-effort:
    returns None if the store cannot be opened, and the import still ingests into the
    in-memory world-model."""
    from ..intel.store import IntelStore
    from ..memory.store import Store

    return IntelStore(Store())


class ImportFindingsTool:
    """Ingest a third-party tool export into the world-model as leads — as a gated,
    passive, no-egress tool. ``args``:

        format      : one of ``imports.available_formats()`` (or omitted to auto-detect)
        report      : the raw export text (or a JSON-serializable object)
        source_tool : optional provenance label (defaults to the format)
        seq         : optional monotonic batch seq (default 0)

    Returns a ``ToolResult`` whose ``output`` is the ``ImportResult`` — the parsed
    leads plus the ingest roll-up. Never raises to the invoker (an error becomes a
    failed result)."""

    name = "import_findings"
    tier = "T1"
    capability = Capability.PASSIVE_INTAKE  # passive: through the entitlement gate, baseline-granted
    destructive = False
    egress_hosts: tuple = ()

    def __init__(self, *, store_factory=default_intel_store) -> None:
        # store_factory: () -> IntelStore | None. None disables persistence (ingest
        # into ctx.world only) — used by tests to stay hermetic.
        self._store_factory = store_factory

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not isinstance(args, dict):
            return ToolResult(ok=False, note="import_findings requires a dict of args")

        report = args.get("report", "")
        if not isinstance(report, str):
            # tolerate a pre-parsed dict/list (the generic path re-serializes to JSON)
            try:
                report = json.dumps(report)
            except (TypeError, ValueError):
                return ToolResult(
                    ok=False, note="import_findings 'report' must be a string or JSON-serializable")
        if len(report.encode("utf-8", "replace")) > _MAX_REPORT_BYTES:
            return ToolResult(ok=False, note="import_findings 'report' exceeds the size bound")

        fmt = str(args.get("format", "") or "").strip().lower()
        if not fmt:
            fmt = detect_format(report) or ""
        if not fmt:
            return ToolResult(
                ok=False, note="import_findings needs a 'format' (auto-detect was inconclusive)")

        source_tool = str(args.get("source_tool", "") or "").strip() or None
        try:
            seq = int(args.get("seq", 0) or 0)
        except (TypeError, ValueError):
            seq = 0
        if seq < 0:
            seq = 0

        store = None
        if self._store_factory is not None:
            try:
                store = self._store_factory()
            except Exception:  # noqa: BLE001 — persistence is best-effort; still ingest in-memory
                store = None

        try:
            result = import_report(
                fmt, report, world=ctx.world, store=store,
                engagement_slug=ctx.slug, source_tool=source_tool, seq=seq)
        except ImportAdapterError as e:
            return ToolResult(ok=False, note=f"import parse error: {e}")
        except Exception as e:  # noqa: BLE001 — never crash the invoker
            return ToolResult(ok=False, note=f"import error: {type(e).__name__}: {e}")

        return ToolResult(
            ok=True,
            summary=f"imported {len(result.leads)} lead(s) from {result.source_tool} "
                    f"({result.format}); applied {result.applied}, dropped {result.dropped}",
            output=result.model_dump())
