"""
worldmodel.attack_paths — the graph-theoretic remediation-triage surface (P4).

This is the decisive national-infrastructure triage output: over the asset topology
projected from the signed spine (:mod:`worldmodel.spine_projector`), it answers the
three questions a government defender actually acts on —

  1. **Shortest / highest-confidence attack path** — from a foothold to any crown
     jewel (``pathsearch.best_paths`` / ``shortest_paths``). *How does the attacker
     get in, and by the most credible route?*
  2. **Chokepoint ranking** — *which single remediation breaks the most attack
     paths?* (``impact.rank_choke_points``: exact 1-cut / bridge detection weighted
     by the business impact each edge severs). The one lever to pull first.
  3. **Reachability-bounded blast radius** — the crown jewels (and their worth) an
     attacker at the foothold can reach, and the counterfactual reduction from
     cutting the top chokepoint (``impact.what_if_remediate``).

Everything is **read-only** over the WorldModel and **deterministic** — the same
projected graph yields byte-identical Markdown + JSON, so the report is a
reproducible artifact, not a one-off. Business impact is **optional**: with a
``targets/<slug>/impact.yaml`` the levers rank by value severed; without one the
model degrades gracefully to a UNIFORM weighting (every crown jewel worth 1.0), so
the ranking becomes an honest attack-path COUNT.

CLI::

    python3 -m framework.v2 attack-paths <slug> --spine spine.json --source host:foothold
    python3 -m framework.v2 attack-paths --spine spine.json --source host:foothold --stdout

The projector treats its input as records off an ALREADY-VERIFIED signed spine
(signature / hash-chain audit is the spine loader's job — ``VigilCoreSpine.verify``
/ the evidence verifier); this surface reasons over the projection.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, Optional

from .graph import WorldModel
from .impact import ImpactModel, RankedChoke, rank_choke_points, what_if_remediate
from .models import EdgeKind, NodeKind, Path as WMPath
from .pathsearch import best_paths, default_weight, lcb_weight
from .spine_projector import _to_edge_kind, _to_node_kind, project_spine, records_from_dicts

# The attack-MOVEMENT edge kinds a path may traverse by default. Deliberately EXCLUDES
# annotation edges (EVIDENCES), the recon asset-graph (RESOLVES_TO / PRESENTS_CERT /
# HOSTS-of-netblock / …) and threat-intel leads (AFFECTS) — traversing those would
# manufacture attacker reach. Callers can override with --edge-kind.
DEFAULT_ATTACK_EDGE_KINDS: tuple[EdgeKind, ...] = (
    EdgeKind.REACHABLE_FROM,
    EdgeKind.TRUSTS_FOR,
    EdgeKind.HAS_GRANT,
    EdgeKind.MEMBER_OF,
    EdgeKind.CAN_ASSUME,
    EdgeKind.VALID_ON,
    EdgeKind.AUTHENTICATES_TO,
    EdgeKind.SESSION_ON,
    EdgeKind.OWNS,
    EdgeKind.HOLDS,
    EdgeKind.REACHED,
    EdgeKind.HOSTS,
    EdgeKind.RUNS,
)

# Crown jewels by default: the datastores and cloud resources a mission cares about.
DEFAULT_OBJECTIVE_KINDS: tuple[NodeKind, ...] = (NodeKind.DATASTORE, NodeKind.CLOUD_RESOURCE)


def _edge_dict(edge) -> dict:
    return {"src": edge.src, "dst": edge.dst, "kind": edge.kind.value,
            "confidence": round(edge.confidence, 6),
            "belief_mean": round(edge.belief_mean, 6),
            "belief_lcb": round(edge.belief_lcb(), 6),
            "provenance": edge.provenance, "grounding": edge.grounding}


def _path_dict(world: WorldModel, path: WMPath, impact: ImpactModel) -> dict:
    terminal = path.nodes[-1]
    tnode = world.get_node(terminal)
    return {
        "nodes": path.nodes,
        "hops": path.hops,
        "min_confidence": round(path.min_confidence, 6),
        "belief_mean": round(path.belief_mean, 6),
        "belief_lcb": round(path.belief_lcb(), 6),
        "objective": terminal,
        "objective_kind": tnode.kind.value if tnode else None,
        "objective_impact": round(impact.impact_of(tnode), 6),
        "provenance_chain": path.provenance_chain,
        "edges": [_edge_dict(e) for e in path.edges],
    }


def _choke_dict(choke: RankedChoke) -> dict:
    return {
        "edge": _edge_dict(choke.edge),
        "is_bridge": choke.is_bridge,
        "betweenness": choke.betweenness,
        "disconnects": sorted(choke.disconnects),
        "disconnect_count": len(choke.disconnects),
        "impact_disconnected": round(choke.impact_disconnected, 6),
    }


def build_report(
    world: WorldModel,
    *,
    source: str,
    objective_kinds: Iterable[NodeKind],
    edge_kinds: Iterable[EdgeKind],
    impact: ImpactModel,
    k: int = 5,
    risk_averse: bool = False,
    impact_source: str = "uniform (no impact.yaml)",
) -> dict:
    """Compute the deterministic attack-path triage report as a JSON-able dict.

    ``risk_averse`` swaps the route weight from ``-log(confidence)`` (point estimate)
    to ``-log(belief_lcb)`` (evidence-discounted), so a thinly-evidenced high-mean hop
    ranks below a proven one. Read-only; no traffic; no mutation of ``world``."""
    objective_kinds = list(objective_kinds)
    edge_kinds = list(edge_kinds)

    # crown jewels present in the graph (deterministic id order)
    jewels: list[str] = []
    for nk in objective_kinds:
        for node in world.nodes_of_kind(nk):
            if node.id != source and node.id not in jewels:
                jewels.append(node.id)
    jewels.sort()

    source_present = world.has_node(source)

    weight_fn = lcb_weight() if risk_averse else default_weight
    paths = (best_paths(world, source, objective_kinds, weight_fn=weight_fn, k=k, edge_kinds=edge_kinds)
             if source_present else [])
    chokes = (rank_choke_points(world, source, objective_kinds, impact, edge_kinds=edge_kinds, k=max(k, 8))
              if source_present else [])

    # reachability-bounded blast radius
    reachable = world.reachable(source, edge_kinds) if source_present else set()
    reachable_jewels = sorted(j for j in jewels if j in reachable)
    impact_reachable = round(sum(impact.impact_of_id(world, j) for j in reachable_jewels), 6)
    impact_total = round(sum(impact.impact_of_id(world, j) for j in jewels), 6)

    # top-lever counterfactual: cut the #1 chokepoint, what falls off?
    what_if = None
    if chokes:
        top_key = chokes[0].edge.key
        wi = what_if_remediate(world, source, objective_kinds, {top_key},
                               edge_kinds=edge_kinds, impact=impact)
        what_if = {
            "remediated_edge": chokes[0].edge.key,
            "now_unreachable": sorted(wi.now_unreachable),
            "still_reachable": sorted(wi.still_reachable),
            "impact_removed": round(wi.impact_removed, 6),
            "impact_remaining": round(wi.impact_remaining, 6),
        }

    return {
        "schema": "vigil.attack-paths/1",
        "source": source,
        "source_present": source_present,
        "objective_kinds": sorted(nk.value for nk in objective_kinds),
        "edge_kinds": sorted(ek.value for ek in edge_kinds),
        "impact_source": impact_source,
        "risk_averse": risk_averse,
        "graph": {"nodes": world.node_count, "edges": world.edge_count},
        "crown_jewels": {
            "total": len(jewels),
            "ids": jewels,
            "reachable": reachable_jewels,
            "reachable_count": len(reachable_jewels),
            "impact_reachable": impact_reachable,
            "impact_total": impact_total,
        },
        "blast_radius": {
            "reachable_node_count": len(reachable),
            "reachable_nodes": sorted(reachable),
        },
        "shortest_attack_paths": [_path_dict(world, p, impact) for p in paths],
        "chokepoints": [_choke_dict(c) for c in chokes],
        "top_remediation": what_if,
    }


def to_json(report: dict) -> str:
    """Deterministic JSON (sorted keys, UTF-8) — byte-identical for the same report."""
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)


def _fmt_route(p: dict) -> str:
    return " -> ".join(p["nodes"])


def render_markdown(report: dict) -> str:
    """Deterministic Markdown rendering of the report — the operator-facing triage doc."""
    r = report
    L: list[str] = []
    L.append("# Attack-path triage")
    L.append("")
    L.append(f"- **Foothold (source):** `{r['source']}`"
             + ("" if r["source_present"] else "  ⚠ NOT PRESENT in the projected graph"))
    L.append(f"- **Crown-jewel kinds:** {', '.join(r['objective_kinds']) or '(none)'}")
    L.append(f"- **Traversable edge kinds:** {', '.join(r['edge_kinds'])}")
    L.append(f"- **Business impact:** {r['impact_source']}")
    L.append(f"- **Route ranking:** {'risk-averse (belief LCB)' if r['risk_averse'] else 'confidence point-estimate'}")
    L.append(f"- **Graph:** {r['graph']['nodes']} nodes / {r['graph']['edges']} edges")
    L.append("")

    cj = r["crown_jewels"]
    L.append("## Blast radius")
    L.append("")
    L.append(f"An attacker at `{r['source']}` reaches **{cj['reachable_count']} of {cj['total']}** "
             f"crown jewels ({len(r['blast_radius']['reachable_nodes'])} nodes total in reach), "
             f"exposing **{cj['impact_reachable']} of {cj['impact_total']}** total business impact.")
    if cj["reachable"]:
        L.append("")
        L.append("Reachable crown jewels: " + ", ".join(f"`{j}`" for j in cj["reachable"]))
    L.append("")

    L.append("## Shortest / highest-confidence attack paths")
    L.append("")
    if not r["shortest_attack_paths"]:
        L.append("_No path from the foothold to any crown jewel._")
    else:
        for i, p in enumerate(r["shortest_attack_paths"], 1):
            L.append(f"{i}. **{_fmt_route(p)}**  ")
            L.append(f"   {p['hops']} hop(s) · min-confidence {p['min_confidence']} · "
                     f"belief {p['belief_mean']} (LCB {p['belief_lcb']}) · "
                     f"reaches `{p['objective']}` (impact {p['objective_impact']})")
    L.append("")

    L.append("## Chokepoint ranking — the single most valuable remediation first")
    L.append("")
    if not r["chokepoints"]:
        L.append("_No chokepoints (no crown jewel is reachable)._")
    else:
        L.append("| # | Edge | Bridge? | Severs | Impact severed | Betweenness |")
        L.append("|---|------|---------|--------|----------------|-------------|")
        for i, c in enumerate(r["chokepoints"], 1):
            e = c["edge"]
            edge_lbl = f"`{e['src']}` --{e['kind']}--> `{e['dst']}`"
            L.append(f"| {i} | {edge_lbl} | {'YES' if c['is_bridge'] else '—'} | "
                     f"{c['disconnect_count']} | {c['impact_disconnected']} | {c['betweenness']} |")
    L.append("")

    wi = r["top_remediation"]
    L.append("## Top remediation — counterfactual")
    L.append("")
    if not wi:
        L.append("_Nothing to remediate (no reachable crown jewel)._")
    else:
        e = wi["remediated_edge"]
        L.append(f"Cutting the #1 chokepoint `{e[0]}` --{e[2]}--> `{e[1]}` severs "
                 f"**{len(wi['now_unreachable'])}** crown jewel(s) and removes "
                 f"**{wi['impact_removed']}** impact "
                 f"(**{wi['impact_remaining']}** would remain reachable).")
        if wi["now_unreachable"]:
            L.append("")
            L.append("Now unreachable: " + ", ".join(f"`{j}`" for j in wi["now_unreachable"]))
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_spine(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        for key in ("records", "spine", "rows"):
            if isinstance(doc.get(key), list):
                return list(doc[key])
        raise ValueError("spine JSON object must carry a 'records' (or 'spine'/'rows') array")
    if isinstance(doc, list):
        return list(doc)
    raise ValueError("spine JSON must be a list of records or a {records:[...]} object")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 attack-paths",
        description="Graph-theoretic attack-path + chokepoint triage over the asset topology "
                    "projected from the signed spine. Deterministic; read-only; no traffic.",
    )
    parser.add_argument("slug", nargs="?",
                        help="Engagement slug — loads targets/<slug>/impact.yaml for business "
                             "impact and, absent --spine, defaults the spine + output paths.")
    parser.add_argument("--spine", metavar="PATH",
                        help="JSON spine document (a list of records, or {records:[...]}). "
                             "Default in slug mode: targets/<slug>/worldmodel-spine.json.")
    parser.add_argument("--source", required=True, metavar="NODE_ID",
                        help="The foothold node id the attacker starts from (e.g. host:foothold).")
    parser.add_argument("--objective-kind", action="append", default=[], metavar="KIND",
                        help="A crown-jewel node kind (repeatable). Default: datastore, cloud_resource.")
    parser.add_argument("--edge-kind", action="append", default=[], metavar="KIND",
                        help="An attack-movement edge kind a path may traverse (repeatable). "
                             "Default: the reachability/trust/identity movement set.")
    parser.add_argument("-k", type=int, default=5, help="How many top paths to report (default 5).")
    parser.add_argument("--risk-averse", action="store_true",
                        help="Rank routes by evidence-discounted belief (LCB) instead of the "
                             "confidence point estimate.")
    parser.add_argument("--strict-grounding", action="store_true",
                        help="Seed an UNGROUNDED (LLM/assumption-provenance) spine write at a low "
                             "belief floor rather than its asserted confidence.")
    parser.add_argument("--no-impact", action="store_true",
                        help="Ignore any impact.yaml; use a uniform (unweighted) model.")
    parser.add_argument("--out", metavar="DIR",
                        help="Output directory (default: targets/<slug>/reports/ in slug mode).")
    parser.add_argument("--stdout", action="store_true", help="Print the report; write no files.")
    args = parser.parse_args(argv)

    if args.k < 1:
        print("error: -k must be >= 1", flush=True)
        return 2

    # resolve the spine path
    spine_path: Optional[Path] = None
    if args.spine:
        spine_path = Path(args.spine)
    elif args.slug:
        from ..common import paths as _paths
        spine_path = Path(_paths.target_dir(args.slug)) / "worldmodel-spine.json"
    if spine_path is None:
        print("error: give --spine PATH (or a slug with targets/<slug>/worldmodel-spine.json)", flush=True)
        return 2
    if not spine_path.is_file():
        print(f"error: no spine file at {spine_path}", flush=True)
        return 2
    try:
        rows = _load_spine(spine_path)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: cannot read spine {spine_path}: {e}", flush=True)
        return 2

    # objective + edge kinds (canonical values or recon aliases)
    obj_kinds: list[NodeKind] = []
    for raw in (args.objective_kind or []):
        nk = _to_node_kind(raw)
        if nk is None:
            print(f"error: unknown objective kind {raw!r}", flush=True)
            return 2
        if nk not in obj_kinds:
            obj_kinds.append(nk)
    if not obj_kinds:
        obj_kinds = list(DEFAULT_OBJECTIVE_KINDS)

    edge_kinds: list[EdgeKind] = []
    for raw in (args.edge_kind or []):
        ek = _to_edge_kind(raw)
        if ek is None:
            print(f"error: unknown edge kind {raw!r}", flush=True)
            return 2
        if ek not in edge_kinds:
            edge_kinds.append(ek)
    if not edge_kinds:
        edge_kinds = list(DEFAULT_ATTACK_EDGE_KINDS)

    # business impact (optional; graceful uniform degrade)
    impact_source = "uniform (no impact.yaml)"
    if args.no_impact or not args.slug:
        impact = ImpactModel.uniform()
        if args.no_impact:
            impact_source = "uniform (--no-impact)"
    else:
        from ..common import paths as _paths
        yaml_fp = Path(_paths.target_dir(args.slug)) / "impact.yaml"
        impact = ImpactModel.from_slug(args.slug)
        impact_source = str(yaml_fp) if yaml_fp.is_file() else "uniform (no impact.yaml)"

    records = records_from_dicts(rows)
    world = project_spine(records, strict_grounding=args.strict_grounding)
    report = build_report(
        world, source=args.source, objective_kinds=obj_kinds, edge_kinds=edge_kinds,
        impact=impact, k=args.k, risk_averse=args.risk_averse, impact_source=impact_source,
    )

    md = render_markdown(report)
    js = to_json(report)

    if args.stdout:
        print(md)
        return 0

    if args.out:
        out_dir = Path(args.out)
    elif args.slug:
        from ..common import paths as _paths
        out_dir = Path(_paths.target_dir(args.slug)) / "reports"
    else:
        # no slug, no --out → print (nowhere canonical to write)
        print(md)
        return 0

    from ..common import paths as _paths
    _paths.secure_write(out_dir / "attack-paths.md", md)
    _paths.secure_write(out_dir / "attack-paths.json", js)
    print(f"wrote {out_dir / 'attack-paths.md'}")
    print(f"wrote {out_dir / 'attack-paths.json'}")
    # a terse operator summary to stdout
    cj = report["crown_jewels"]
    print(f"source={report['source']} reaches {cj['reachable_count']}/{cj['total']} crown jewels "
          f"(impact {cj['impact_reachable']}/{cj['impact_total']}); "
          f"{len(report['chokepoints'])} chokepoint(s), "
          f"{len(report['shortest_attack_paths'])} path(s).")
    return 0
