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
                # P2 assessment-run fields (absent for legacy loopback scans → sensible defaults):
                "mode": meta.get("mode", "url"),
                "slug": meta.get("slug"),
                "objective": meta.get("objective", ""),
                # how the Live view should tail this run: 'blackboard' (engage --spine), 'progress'
                # (loopback scan --progress-log), or 'none' (strix/aegis — status only).
                "stream": meta.get("stream", "progress"),
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

        from ..worldmodel.impact import ImpactModel, rank_choke_points

        report = ScanReport.model_validate(doc)
        auto = AutonomousCampaign(_no_send).chain_findings(report)
        world = auto.world
        # first_seen/last_seen drive the Timeline-replay screen (monotonic graph growth).
        nodes = [{
            "id": n.id, "kind": getattr(n.kind, "value", str(n.kind)),
            "belief": round(n.belief_mean, 3), "confidence": round(n.confidence, 3),
            "provenance": n.provenance, "detail": n.attrs.get("detail") or n.attrs.get("bug_class") or "",
            "first_seen": n.first_seen, "last_seen": n.last_seen,
            "grounding": getattr(n, "grounding", "unclassified"),   # anti-hallucination tier
        } for n in world.all_nodes()]
        edges = [{
            "src": e.src, "dst": e.dst, "kind": getattr(e.kind, "value", str(e.kind)),
            "technique": str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])),
            "belief": round(e.belief_mean, 3), "provenance": e.provenance,
            "first_seen": e.first_seen, "last_seen": e.last_seen,
            "grounding": getattr(e, "grounding", "unclassified"),
        } for e in world.all_edges()]
        paths = [{
            "description": p.describe(), "detection_cost": p.detection_cost, "hops": p.hops,
            "destination": p.destination, "value": getattr(p, "value", 1.0),
            "steps": [{"src": s.src, "edge": s.edge, "dst": s.dst, "technique": s.technique} for s in p.steps],
        } for p in auto.attack_paths]
        # impact-ranked remediation levers (P2): weighted by the crown-jewel worth each severs
        chokes: list[dict[str, Any]] = []
        if world.get_node(ATTACKER_ID) is not None:
            impact = ImpactModel.uniform()
            for c in _safe(lambda: rank_choke_points(world, ATTACKER_ID, _CROWN_KINDS, impact,
                                                     edge_kinds=_TRAVERSABLE), default=[]) or []:
                chokes.append({"src": c.edge.src, "dst": c.edge.dst,
                               "kind": getattr(c.edge.kind, "value", str(c.edge.kind)),
                               "betweenness": c.betweenness, "disconnects": c.disconnects,
                               "is_bridge": c.is_bridge, "impact_disconnected": c.impact_disconnected})
        return {"run_id": run_id, "nodes": nodes, "edges": edges, "paths": paths, "chokes": chokes,
                "node_count": world.node_count, "edge_count": world.edge_count}

    return _safe(_build, default={"run_id": run_id, "error": "could not reconstruct world-model",
                                  "nodes": [], "edges": [], "paths": [], "chokes": []})


def evidence(run_id: str) -> dict[str, Any]:
    """The Evidence Browser: every confirmed finding's certificate, INDEPENDENTLY
    re-verified offline (pure oracle re-run over the retained oracle_context) so the
    operator sees which findings are provable — reproduced + matches-claim — and which
    carry a re-runnable certificate at all. Read-only; sends no traffic."""
    from . import actions

    rj = actions.run_dir(run_id) / "reverifiable.json"
    doc = _safe(lambda: json.loads(rj.read_text(encoding="utf-8")), default=None)
    if doc is None:
        return {"run_id": run_id, "pending": True, "findings": []}

    def _build() -> dict[str, Any]:
        from ..evidence.canonical import digest_payload
        from ..verify.reverify import reverify_document
        results = reverify_document(doc)
        findings = doc.get("active_findings") or []
        out = []
        for i, r in enumerate(results):
            f = findings[i] if i < len(findings) else {}
            oc = f.get("oracle_context")
            # cert id = a REAL content address of the retained certificate: sha256 over the
            # canonical bytes of the oracle_context (the same digest the signed EvidenceCertificate
            # binds as `oracle_context_digest`). "" when the finding carries no re-runnable proof —
            # never fabricated. Two byte-identical certificates share an id; a tampered one does not.
            cert_id = ""
            if isinstance(oc, dict) and oc:
                cert_id = _safe(lambda oc=oc: "sha256:" + digest_payload(oc), default="")
            out.append({
                "ref": r.finding_ref,
                "bug_class": f.get("bug_class", ""),
                "surface": f.get("insertion_point") or f.get("param") or "",
                "confirmed_by": r.confirmed_by or f.get("confirmed_by", ""),
                "confidence": round(r.confidence, 3),
                "has_certificate": bool(oc),
                "cert_id": cert_id,
                "reproduced": r.reproduced,
                "matches_claim": r.matches_claim,
                "sound": r.ok,
                "note": r.note,
            })
        n_ok = sum(1 for x in out if x["sound"])
        return {"run_id": run_id, "findings": out,
                "reproduced": n_ok, "total": len(out),
                "doctrine": "Each certificate re-verifies OFFLINE with no target and no trust "
                            "in the tool that produced it — prove-don't-guess, made checkable."}

    return _safe(_build, default={"run_id": run_id, "findings": [], "error": "could not re-verify"})


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


# ---------------------------------------------------------------------------
# memory / kernel / authority / planner / reports (Phase 3-4)
# ---------------------------------------------------------------------------


def memory_data() -> dict[str, Any]:
    """The learning store: engagement roll-up + per-archetype Beta priors."""
    def _read() -> dict[str, Any]:
        from ..memory.priors import all_priors
        from ..memory.store import Store

        st = Store()
        summary = _safe(st.engagement_summary, default={})
        priors = _safe(lambda: [{
            "archetype": p.archetype, "bug_class": p.bug_class, "surface": p.surface_pattern,
            "successes": p.successes, "attempts": p.attempts,
            "mean": round(p.mean, 3), "lower_bound": round(p.lower_bound, 3),
        } for p in all_priors(st)], default=[])
        return {"summary": summary, "priors": sorted(priors, key=lambda x: -x["mean"])}

    return _safe(_read, default={"summary": {}, "priors": [], "note": "no memory store yet"})


def kernel_data() -> dict[str, Any]:
    """The URK cognitive layer: LLM backends (live/dryrun) + the cognitive docs the
    kernel produces structured outputs for."""
    from ..kernel import backends as backends_pkg

    backends = _safe(lambda: [
        {"name": n, "available": bool(a), "note": note} for n, a, note in backends_pkg.probe_all()
    ], default=[])
    docs = ["hypothesize", "critique", "pivot", "decide (CVSS severity)", "opsec", "threat-model"]
    return {"backends": backends, "cognitive_docs": docs,
            "dryrun_default": True,
            "note": "Kernel outputs are produced on demand via `kernel <verb>`; every call "
                    "returns a CallTrace (backend, dryrun, tokens, latency)."}


def authority_full(slug: str) -> dict[str, Any]:
    """The governance state for an engagement: kill-switch, authority window/scope,
    charter presence — the fail-closed safety picture."""
    if not slug:
        return {"slug": None, "note": "select an engagement"}
    return {
        "slug": slug,
        "killswitch": _killswitch_state(slug),
        "authority": _authority_state(slug),
        "charter_present": _safe(lambda: __import__("pathlib").Path(paths.charter_path(slug)).is_file(), default=False),
        "gates": ["authority/kill-switch", "scope", "destructive-confirm", "budget", "rate-limit", "egress"],
    }


def planner_data(slug: str) -> dict[str, Any]:
    """The goal-tree/plan state for an engagement, if a planner ran (planner-state.json)."""
    def _read() -> dict[str, Any]:
        p = Path(paths.planner_state(slug))
        if not p.is_file():
            return {"slug": slug, "present": False}
        doc = json.loads(p.read_text(encoding="utf-8"))
        return {"slug": slug, "present": True, "state": doc}

    return _safe(_read, default={"slug": slug, "present": False})


def reports_data(slug: str) -> dict[str, Any]:
    """Generated reports on disk for an engagement (targets/<slug>/reports/)."""
    def _read() -> dict[str, Any]:
        rd = Path(paths.target_dir(slug)) / "reports"
        if not rd.is_dir():
            return {"slug": slug, "reports": []}
        files = [{"name": f.name, "size": f.stat().st_size} for f in rd.iterdir() if f.is_file()]
        return {"slug": slug, "reports": sorted(files, key=lambda x: x["name"])}

    return _safe(_read, default={"slug": slug, "reports": []})


# ---------------------------------------------------------------------------
# external host tools (WS-TOOLS)
# ---------------------------------------------------------------------------


def tools_data() -> dict[str, Any]:
    """The offense engine's external host CLIs, probed LIVE (WS-TOOLS): for every tool —
    installed / missing / failed, its resolved path + a cheap version, its purpose, and a
    copyable install hint; plus the informational Strix-sandbox roster and the host platform.

    Real data only: :func:`..tools.registry.probe_tools` resolves PATH at call time and never
    invents a status; 'failed' is layered from the installer's optional hint file and the live
    probe always overrides it. Safe on any box (a non-Linux host reports every tool
    ``unsupported``). Read-only — issues no traffic and installs nothing."""
    def _read() -> dict[str, Any]:
        from ..tools.registry import probe_tools
        return probe_tools()

    return _safe(_read, default={
        "platform": {"system": None, "supported": False, "debian_family": False},
        "tools": [],
        "summary": {"total": 0, "installed": 0, "missing": 0, "failed": 0,
                    "unsupported": 0, "required_missing": 0},
        "sandbox": {"image": None, "tools": []},
        "error": "could not probe host tools",
    })


def capabilities_data() -> dict[str, Any]:
    """The ENGAGE capability packs the New-Assessment wizard offers under 'pick tools' — the SINGLE
    source of truth (``actions.ENGAGE_CAPABILITIES``) that a launch maps a picked id onto a real,
    already-gated ``engage`` flag. Real config data (not invented), so the UI never hardcodes it and
    a picked capability can never widen authority beyond the charter/scope/kill-switch/egress stack.
    The ``flag`` is intentionally NOT exposed — the id is the contract; the mapping lives server-side."""
    from . import actions
    return {
        "capabilities": [
            {"id": c["id"], "label": c["label"], "tier": c["tier"], "purpose": c["purpose"]}
            for c in actions.ENGAGE_CAPABILITIES
        ],
        "scan_modes": [
            {"id": "quick", "label": "Quick", "purpose": "Fast, targeted, bounded pages/budget."},
            {"id": "standard", "label": "Standard", "purpose": "Balanced coverage (default)."},
            {"id": "deep", "label": "Deep", "purpose": "Widest coverage; more pages/budget/cycles."},
        ],
        "note": "Capabilities map to already-gated engage flags. Offensive steps still QUEUE for "
                "owner approval — nothing fires automatically.",
    }


# ---------------------------------------------------------------------------
# AEGIS Defense (P5a) — the managed gateway's live status
# ---------------------------------------------------------------------------


def aegis_status() -> dict[str, Any]:
    """The managed AEGIS gateway's live status for the Defense dashboard: whether it is running, its
    EFFECTIVE mode (enforce may downgrade to observe without the AEGIS_RESPOND entitlement), the target,
    and the per-actor Beta beliefs snapshotted by the gateway. Read-only + resilient (never raises;
    _safe-wrapped by the router). NO gateway launched yet → an honest empty state, not fabricated data."""
    from . import actions
    cur = _safe(actions._read_aegis_current, {}) or {}
    if not cur:
        return {"running": False, "gateway": None, "actors": [], "actor_count": 0,
                "note": "No AEGIS gateway is running. Start one from the Defense screen to watch it live."}
    alive = bool(_safe(lambda: actions._pid_alive(cur.get("pid")), False))
    snap: dict[str, Any] = {}
    sp = cur.get("status_file")
    if sp and Path(sp).is_file():
        snap = _safe(lambda: json.loads(Path(sp).read_text(encoding="utf-8")), {}) or {}
    return {
        "running": alive,
        "gateway": {"upstream": cur.get("upstream"), "bind": f"{cur.get('host')}:{cur.get('port')}",
                    "requested_mode": cur.get("mode"), "slug": cur.get("slug"),
                    "pid": cur.get("pid"), "started": cur.get("started"), "run_id": cur.get("run_id")},
        "effective_mode": snap.get("effective_mode") if alive else None,
        "requested_mode": cur.get("mode"),
        "actors": snap.get("actors", []) if alive else [],
        "actor_count": snap.get("actor_count", 0) if alive else 0,
        "note": None if alive else "The last gateway is no longer running — start a new one.",
    }


# ---------------------------------------------------------------------------
# intelligence & reconnaissance (Intelligence Engine)
# ---------------------------------------------------------------------------


def intel_data(slug: str) -> dict[str, Any]:
    """The Intelligence Engine's picture for an engagement: resolved entities (with
    merge explanations), source-yield learning with calibrated priors, and the gated
    prediction queue (never facts). Read-only over the durable intel store; safe on a
    fresh tree (no intel rows yet)."""
    if not slug:
        return {"slug": None, "note": "select an engagement"}

    def _read() -> dict[str, Any]:
        from ..intel import learn
        from ..intel.models import IntelSourceKind
        from ..intel.predict import AssetPredictor, assess_prediction
        from ..intel.store import IntelStore
        from ..memory.store import Store
        from ..worldmodel.models import NodeKind

        istore = IntelStore(Store())
        ents = _safe(lambda: istore.entities(engagement_slug=slug), default=[]) or []
        entities = [{
            "id": e.canonical_id, "kind": e.primary_kind.value, "confidence": e.confidence,
            "members": [m.node_id for m in e.members], "owned_by": e.owned_by,
            "why": e.explain(),
        } for e in ents]

        source_kinds = [IntelSourceKind.DNS, IntelSourceKind.CERT_TRANSPARENCY,
                        IntelSourceKind.RDAP_WHOIS, IntelSourceKind.ASN_BGP]
        yields = _safe(lambda: [{
            **row, "calibrated_prior": learn.source_prior(istore, row["source_kind"],
                                                          archetype=row["archetype"]),
        } for row in istore.all_source_yield()], default=[])

        domains = sorted({m.key for e in ents for m in e.members if m.kind is NodeKind.DOMAIN})
        preds = _safe(lambda: [assess_prediction(p)
                               for p in AssetPredictor().predict(observed_domains=domains)[:12]],
                      default=[])

        return {"slug": slug, "observations": _safe(
                    lambda: istore.observation_count(engagement_slug=slug), default=0),
                "entities": entities, "source_yield": yields, "predictions": preds,
                "doctrine": "Predictions are gated hypotheses — never facts, never auto-scanned. "
                            "Oracle/verify stays the sole authority on what is real."}

    return _safe(_read, default={"slug": slug, "entities": [], "source_yield": [],
                                 "predictions": [], "note": "no intel store yet"})
