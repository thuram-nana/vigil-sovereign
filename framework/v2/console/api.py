"""
console.api — read-only data providers for the Ops Console.

Every function here is PURE and RESILIENT: it reads an artifact/store on demand and
returns a plain JSON-serializable dict, and it never raises on a missing/fresh tree
(a brand-new checkout has no `.memory/`, `.authority/`, or `targets/*` yet). It
reuses the framework's own read helpers (`common.paths`, `authority.killswitch`,
`memory.store`, `kernel.backends`) — it does not re-implement them, and it imports
nothing from the scan/engage hot path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import paths


def _safe(fn, default=None):
    """Call a zero-arg read and swallow any error into ``default`` — the console
    must render a partial view of a half-initialised tree, never 500 on it."""
    try:
        return fn()
    except Exception:
        return default


# ---------------------------------------------------------------------------
# status / health
# ---------------------------------------------------------------------------


def status_data() -> dict[str, Any]:
    """Environment + backend health — the data behind the `status` CLI, as JSON."""
    from ..kernel import backends as backends_pkg

    def _paths() -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for label, fn in (
            ("crucible_root", paths.crucible_root),
            ("v2_root", paths.v2_root),
            ("memory_db", paths.memory_db),
            ("dryrun_dir", paths.dryrun_dir),
            ("targets_root", paths.targets_root),
        ):
            p = _safe(fn)
            out[label] = str(p) if p is not None else None
        return out

    backends = _safe(
        lambda: [
            {"name": name, "available": bool(avail), "note": note}
            for name, avail, note in backends_pkg.probe_all()
        ],
        default=[],
    )
    return {"paths": _paths(), "backends": backends}


# ---------------------------------------------------------------------------
# engagements
# ---------------------------------------------------------------------------


def _killswitch_state(slug: str) -> dict[str, Any]:
    from ..authority.killswitch import KillSwitch

    def _read() -> dict[str, Any]:
        ks = KillSwitch(slug)
        tripped = ks.is_tripped()
        return {"tripped": bool(tripped), "reason": ks.reason() if tripped else None}

    # is_tripped fails CLOSED (ambiguous stat -> tripped); mirror that honestly.
    return _safe(_read, default={"tripped": True, "reason": "state unreadable (fail-closed)"})


def _authority_state(slug: str) -> dict[str, Any] | None:
    def _read() -> dict[str, Any] | None:
        p = paths.authority_path(slug)
        if not Path(p).is_file():
            return None
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        # SignedAuthority wraps an authority payload; surface the operator-relevant bits.
        auth = doc.get("authority", doc)
        return {
            "environment": auth.get("environment"),
            "scope": auth.get("scope", []),
            "not_before": auth.get("not_before"),
            "not_after": auth.get("not_after"),
            "allow_destructive": auth.get("allow_destructive"),
            "max_actions": auth.get("max_actions"),
            "issued_by": auth.get("issued_by"),
        }

    return _safe(_read, default=None)


def _engagement_row(slug: str) -> dict[str, Any]:
    td = _safe(lambda: Path(paths.target_dir(slug)))
    has_charter = _safe(lambda: Path(paths.charter_path(slug)).is_file(), default=False)
    log = _safe(lambda: Path(paths.crucible_v2_log(slug)))
    return {
        "slug": slug,
        "has_charter": bool(has_charter),
        "killswitch": _killswitch_state(slug),
        "authority": _authority_state(slug),
        "log_exists": bool(log and log.is_file()),
        "log_size": _safe(lambda: log.stat().st_size, default=0) if log else 0,
        "evidence_count": _safe(
            lambda: sum(1 for _ in (td / "evidence").iterdir()) if (td / "evidence").is_dir() else 0,
            default=0,
        ),
    }


def list_engagements() -> dict[str, Any]:
    """Every engagement (a slug = a directory under ``targets/``), with its
    safety/charter state. Skips the `_template` scaffold and hidden dirs."""
    def _list() -> list[str]:
        root = Path(paths.targets_root())
        if not root.is_dir():
            return []
        return sorted(
            p.name for p in root.iterdir()
            if p.is_dir() and not p.name.startswith((".", "_"))
        )

    slugs = _safe(_list, default=[])
    return {"engagements": [_engagement_row(s) for s in slugs]}


def engagement_detail(slug: str) -> dict[str, Any]:
    """One engagement's full at-a-glance state (charter presence, safety, logs)."""
    row = _engagement_row(slug)
    row["charter_present"] = row["has_charter"]
    row["memory"] = _safe(_memory_summary, default={})
    return row


def _memory_summary() -> dict[str, int]:
    from ..memory.store import Store

    return Store().engagement_summary()


# ---------------------------------------------------------------------------
# console runs + reports (populated by the launch action)
# ---------------------------------------------------------------------------


def list_runs() -> dict[str, Any]:
    """Console-launched scan runs, newest first, with their meta + finding count."""
    from . import actions

    def _list() -> list[dict[str, Any]]:
        runs_root = actions.console_dir() / "runs"
        if not runs_root.is_dir():
            return []
        out: list[dict[str, Any]] = []
        for d in sorted(runs_root.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            meta = _safe(lambda p=d: json.loads((p / "meta.json").read_text(encoding="utf-8")), default={})
            report = _safe(lambda p=d: json.loads((p / "report.json").read_text(encoding="utf-8")), default=None)
            out.append({
                "run_id": d.name,
                "target": meta.get("target"),
                "status": meta.get("status", "unknown"),
                "started": meta.get("started"),
                "findings": len((report or {}).get("findings", [])) if report else None,
                "has_report": report is not None,
            })
        return out

    return {"runs": _safe(_list, default=[])}


def run_report(run_id: str) -> dict[str, Any]:
    """The saved `build_report` document for a console run (findings + attack_paths +
    summary), or an error marker if it has not finished yet."""
    from . import actions

    rep = actions.run_dir(run_id) / "report.json"
    doc = _safe(lambda: json.loads(rep.read_text(encoding="utf-8")), default=None)
    if doc is None:
        meta = _safe(lambda: json.loads((actions.run_dir(run_id) / "meta.json").read_text(encoding="utf-8")), default={})
        return {"run_id": run_id, "pending": True, "status": meta.get("status", "unknown")}
    doc["run_id"] = run_id
    return doc


def _no_send(_request):  # pragma: no cover - chaining is pure reasoning, never sends
    raise RuntimeError("world-model reconstruction must not issue traffic")


def worldmodel(run_id: str) -> dict[str, Any]:
    """Reconstruct the world-model attack graph for a saved run — a PURE re-run of
    the chaining over the retained ScanReport (no traffic). Returns typed nodes,
    belief-weighted edges, attacker→crown-jewel paths, and choke-points."""
    from . import actions

    rj = actions.run_dir(run_id) / "reverifiable.json"
    doc = _safe(lambda: json.loads(rj.read_text(encoding="utf-8")), default=None)
    if doc is None:
        return {"run_id": run_id, "pending": True, "nodes": [], "edges": [], "paths": [], "chokes": []}

    def _build() -> dict[str, Any]:
        from ..scanner.campaign import ScanReport
        from ..scanner.orchestrator import _CROWN_KINDS, _TRAVERSABLE, AutonomousCampaign
        from ..worldmodel.attacker import ATTACKER_ID
        from ..worldmodel.pathsearch import choke_points

        report = ScanReport.model_validate(doc)
        auto = AutonomousCampaign(_no_send).chain_findings(report)
        world = auto.world
        nodes = [{
            "id": n.id, "kind": getattr(n.kind, "value", str(n.kind)),
            "belief": round(n.belief_mean, 3), "confidence": round(n.confidence, 3),
            "provenance": n.provenance, "detail": n.attrs.get("detail") or n.attrs.get("bug_class") or "",
        } for n in world.all_nodes()]
        edges = [{
            "src": e.src, "dst": e.dst, "kind": getattr(e.kind, "value", str(e.kind)),
            "technique": str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])),
            "belief": round(e.belief_mean, 3), "provenance": e.provenance,
        } for e in world.all_edges()]
        paths = [{
            "description": p.describe(), "detection_cost": p.detection_cost, "hops": p.hops,
            "destination": p.destination,
            "steps": [{"src": s.src, "edge": s.edge, "dst": s.dst, "technique": s.technique} for s in p.steps],
        } for p in auto.attack_paths]
        chokes: list[dict[str, Any]] = []
        if world.get_node(ATTACKER_ID) is not None:
            for c in _safe(lambda: choke_points(world, ATTACKER_ID, _CROWN_KINDS, edge_kinds=_TRAVERSABLE), default=[]) or []:
                chokes.append({"src": c.edge.src, "dst": c.edge.dst,
                               "kind": getattr(c.edge.kind, "value", str(c.edge.kind)),
                               "betweenness": c.betweenness, "disconnects": c.disconnects, "is_bridge": c.is_bridge})
        return {"run_id": run_id, "nodes": nodes, "edges": edges, "paths": paths, "chokes": chokes,
                "node_count": world.node_count, "edge_count": world.edge_count}

    return _safe(_build, default={"run_id": run_id, "error": "could not reconstruct world-model",
                                  "nodes": [], "edges": [], "paths": [], "chokes": []})


# ---------------------------------------------------------------------------
# benchmark + coverage
# ---------------------------------------------------------------------------


def benchmark_data() -> dict[str, Any]:
    """The committed benchmark scoreboard + the regression baseline — reused as-is
    (no run needed). These are committed PACKAGE data, so read them relative to this
    file (the installed framework), not the runtime CRUCIBLE_ROOT."""
    v2 = Path(__file__).resolve().parents[1]  # .../framework/v2
    results = _safe(lambda: json.loads((v2 / "docs" / "benchmark-results.json").read_text(encoding="utf-8")), default=None)
    baseline = _safe(lambda: json.loads((v2 / "eval" / "baselines" / "benchmark-app.json").read_text(encoding="utf-8")), default=None)
    return {"results": results, "baseline": baseline}


def coverage_data(run_id: str) -> dict[str, Any]:
    """Surface-coverage view of a saved run: detected stack, discovered endpoints,
    passive hygiene, DOM-XSS leads (all from the build_report document)."""
    doc = run_report(run_id)
    if doc.get("pending"):
        return {"run_id": run_id, "pending": True}
    findings = doc.get("findings", [])
    return {
        "run_id": run_id,
        "target": doc.get("target"),
        "fingerprint": doc.get("fingerprint", []),
        "discovered_endpoints": doc.get("discovered_endpoints", []),
        "summary": doc.get("summary", {}),
        "passive": [f for f in findings if f.get("kind") == "passive"],
        "dom_xss": [f for f in findings if f.get("kind") == "dom_xss_candidate"],
    }
