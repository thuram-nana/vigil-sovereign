"""
imports.importer — the orchestrator: parse -> mint leads -> ingest into the world-model.

``import_report`` is the one entry point. It parses a third-party export into
``ImportedFinding``s (``parsers``), mints them as intel Observations (``to_observations``),
and ingests them through ``IntelIngest`` — the SAME single-writer seam the intel
collectors use — so the leads land in the shared world-model exactly like any other
intelligence, tagged GROUNDING_INTEL, never as facts.

It is pure of wallclock/rng and idempotent: re-importing the same export mints the
same claim-keyed ``obs_id``s, which the ingest de-dups.
"""

from __future__ import annotations

from ..intel.ingest import IntelIngest
from ..intel.models import IntelSourceKind
from ..intel.store import IntelStore
from ..worldmodel.graph import WorldModel
from .models import ImportResult
from .parsers import parse_export
from .to_observations import observations_from_imported

# Heuristic third-party scanners -> a LEAD (WEB_SCANNER). The tool-neutral escape hatch
# is operator-provided -> OPERATOR_INGEST. Both classify GROUNDING_INTEL once projected.
_SOURCE_KIND = {
    "nuclei": IntelSourceKind.WEB_SCANNER,
    "zap": IntelSourceKind.WEB_SCANNER,
    "burp": IntelSourceKind.WEB_SCANNER,
    "sqlmap": IntelSourceKind.WEB_SCANNER,
    "nikto": IntelSourceKind.WEB_SCANNER,
    "wapiti": IntelSourceKind.WEB_SCANNER,
    # SARIF is a neutral interchange format from ANY tool (DAST or SAST) — an operator-supplied export.
    "sarif": IntelSourceKind.OPERATOR_INGEST,
    "generic": IntelSourceKind.OPERATOR_INGEST,
}


def import_report(
    fmt: str,
    output: str,
    *,
    world: WorldModel | None = None,
    store: IntelStore | None = None,
    engagement_slug: str = "",
    source_tool: str | None = None,
    seq: int = 0,
    max_findings: int = 5000,
) -> ImportResult:
    """Parse ``output`` (format ``fmt``) into leads and ingest them into ``world``.

    ``world`` defaults to a fresh in-memory :class:`WorldModel` (the caller can pass
    a shared one to accumulate). ``store`` (optional) persists the observations so a
    later reader (the API ``/imports`` endpoint) can enumerate them. Returns an
    :class:`ImportResult` — the parsed leads plus the ingest roll-up.

    Deterministic + idempotent: pure of wallclock/rng; re-importing the same export
    is a no-op on belief (claim-keyed obs_ids de-dup)."""
    findings, default_tool = parse_export(fmt, output)
    warnings: list[str] = []

    if len(findings) > max_findings:
        warnings.append(
            f"export carried {len(findings)} findings; import bounded to {max_findings} "
            f"(remaining dropped)")
        findings = findings[:max_findings]

    tool = (source_tool or default_tool or fmt).strip() or "import"
    source_kind = _SOURCE_KIND.get((fmt or "").strip().lower(), IntelSourceKind.WEB_SCANNER)

    observations = observations_from_imported(
        findings, source_tool=tool, source_kind=source_kind, seq=seq)

    wm = world if world is not None else WorldModel()
    ingest = IntelIngest(wm, store=store, engagement_slug=engagement_slug)
    ingest_result = ingest.ingest(observations, seq=seq)

    return ImportResult(
        source_tool=tool,
        format=(fmt or "").strip().lower(),
        leads=findings,
        observations=len(observations),
        applied=ingest_result.applied,
        dropped=ingest_result.dropped,
        persisted=ingest_result.persisted,
        warnings=warnings,
    )
