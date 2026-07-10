"""
api.reads — the READ-first core of the external API (the safe majority of the surface).

Enumerate engagements, read the world-model / findings / governance state, list the
gated action surface, and enumerate imported leads. Every provider is PURE and
RESILIENT and issues NO traffic — it reads an artifact/store on demand and returns a
plain JSON-serializable dict, never raising on a fresh/half-initialised tree.

Most providers DELEGATE to ``console.api`` (the already-audited read layer) rather than
re-implement it — the external API is a programmatic view over the SAME reads the
console renders. Two providers are new: ``tools`` (enumerate the gated tool registry —
the action surface, described but not invoked) and ``imports`` (enumerate the leads a
prior import minted into the intel store).
"""

from __future__ import annotations

from typing import Any

from ..console import api as console_api


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


# --- delegated reads (the console's audited providers, surfaced programmatically) ---

def status() -> dict[str, Any]:
    return console_api.status_data()


def engagements() -> dict[str, Any]:
    return console_api.list_engagements()


def engagement(slug: str) -> dict[str, Any]:
    return console_api.engagement_detail(slug)


def authority(slug: str) -> dict[str, Any]:
    return console_api.authority_full(slug)


def runs() -> dict[str, Any]:
    return console_api.list_runs()


def report(run_id: str) -> dict[str, Any]:
    return console_api.run_report(run_id)


def worldmodel(run_id: str) -> dict[str, Any]:
    return console_api.worldmodel(run_id)


def evidence(run_id: str) -> dict[str, Any]:
    return console_api.evidence(run_id)


def intel(slug: str) -> dict[str, Any]:
    return console_api.intel_data(slug)


# --- new reads --------------------------------------------------------------

def tools(registry) -> dict[str, Any]:
    """Enumerate the gated tool registry — the ACTION surface, DESCRIBED not invoked.
    For each registered tool: its name and gating metadata (tier / capability /
    destructive / whether it reaches hosts). Read-only: listing a tool runs nothing
    and passes no gate. An operator uses this to discover what ``POST /tool/invoke``
    could drive — every one of which still runs through the full gate chain."""
    out = []
    for name in _safe(registry.names, default=[]) or []:
        tool = registry.get(name)
        cap = getattr(tool, "capability", None)
        out.append({
            "name": name,
            "tier": str(getattr(tool, "tier", "T1")),
            "capability": getattr(cap, "value", None) if cap is not None else None,
            "destructive": bool(getattr(tool, "destructive", False)),
            "reaches_hosts": bool(getattr(tool, "egress_hosts", ()) or ()),
        })
    return {"tools": out,
            "doctrine": "Every tool here is invoked through the SAME fail-closed gate chain "
                        "(kill-switch, entitlement, scope, destructive-confirm, egress) as a "
                        "local action. Enumeration is read-only and gates nothing."}


_LEAD_SOURCE_KINDS = ("web_scanner", "operator_ingest")


def imports(slug: str, *, store_factory=None) -> dict[str, Any]:
    """Enumerate the LEADS a prior import minted into the intel store for ``slug`` —
    every observation whose source_kind marks it as an imported third-party finding
    (WEB_SCANNER / OPERATOR_INGEST). Read-only over the durable store; safe on a fresh
    tree (no rows yet). Each row surfaces the claimed bug class and the honest label
    that it is an UNVERIFIED lead, not a fact."""
    if not slug:
        return {"slug": None, "note": "select an engagement"}

    def _build_store():
        if store_factory is not None:
            return store_factory()
        from ..intel.store import IntelStore
        from ..memory.store import Store
        return IntelStore(Store())

    def _read() -> dict[str, Any]:
        istore = _build_store()
        rows: list[dict[str, Any]] = []
        for sk in _LEAD_SOURCE_KINDS:
            for obs in _safe(lambda sk=sk: istore.observations(engagement_slug=slug, source_kind=sk),
                             default=[]) or []:
                attrs = obs.attrs or {}
                if not attrs.get("lead"):
                    continue  # skip the asset/edge plumbing — surface only vuln leads
                rows.append({
                    "obs_id": obs.obs_id,
                    "source_tool": obs.source,
                    "source_kind": obs.source_kind.value,
                    "subject": obs.subject.node_id,
                    "bug_class": attrs.get("bug_class"),
                    "severity": attrs.get("severity"),
                    "tool_confirmed": attrs.get("tool_confirmed"),
                    "location": attrs.get("location"),
                    "is_lead": bool(attrs.get("lead")),
                    "unverified": bool(attrs.get("unverified", True)),
                    "confidence": round(obs.confidence, 3),
                    "reliability": round(obs.reliability(), 3),
                })
        return {"slug": slug, "leads": rows, "count": len(rows),
                "doctrine": "Imported findings are UNVERIFIED leads (GROUNDING_INTEL). A CRUCIBLE "
                            "oracle re-verifies where possible; the rest stay labelled leads."}

    return _safe(_read, default={"slug": slug, "leads": [], "count": 0,
                                 "note": "no intel store yet"})
