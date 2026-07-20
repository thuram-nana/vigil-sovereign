"""
intel.cli — `python3 -m framework.v2 intel <subcommand>`.

The operator's window onto the Intelligence Engine. Everything runs offline by
default (bundled fixtures); durable state lives in the memory DB under a `--slug`.

    ingest    --seed DOMAIN [--fixtures DIR] [--slug S] [--max-depth N] [--archetype A]
                run the passive collectors offline and ingest (project + resolve +
                persist); credits source-yield learning
    resolve   [--slug S]                     resolved entities, with merge explanations
    plan      --seed DOMAIN [--slug S] [--archetype A]
                the recon plan, ranked by value-of-information (learned priors)
    predict   [--slug S | --domains a,b]     gated asset predictions + SCE posteriors
    timeline  --node NODE_ID [--slug S]      an asset's first-seen / reaffirmed / refuted history
    delta     --from A --to B [--slug S]     surface change between two seqs (disappearance-honest)
    yield     [--archetype A]                source-yield learning table + calibrated priors

Predictions are shown as HYPOTHESES with priors — never facts, never auto-verified.
Live collection is deliberately absent from the CLI's happy path: gated egress is a
code-level opt-in (GuardedHttpTransport), not a flag that fires traffic by surprise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..worldmodel.graph import WorldModel
from ..worldmodel.models import NodeKind
from . import learn
from .collectors import DEFAULT_COLLECTORS
from .ingest import RECON_MAX_WORKERS, IntelIngest
from .models import IntelSourceKind
from .planner import ReconPlanner
from .predict import AssetPredictor, assess_prediction
from .refs import canonicalize
from .store import IntelStore
from .temporal import TemporalIndex
from .transport import FixtureTransport

_BUNDLED_FIXTURES = Path(__file__).resolve().parent / "collectors" / "fixtures"
_SOURCE_KINDS = [IntelSourceKind.DNS, IntelSourceKind.CERT_TRANSPARENCY,
                 IntelSourceKind.RDAP_WHOIS, IntelSourceKind.ASN_BGP]


def _open(slug: str | None):
    """Open (memory Store, IntelStore) for a slug, or (None, None) for ephemeral runs."""
    if not slug:
        return None, None
    from ..memory.store import open_store
    store = open_store()
    return store, IntelStore(store)


def _emit(obj) -> int:
    print(json.dumps(obj, indent=2, default=str))
    return 0


# ---- ingest ------------------------------------------------------------------


def _ingest(args: argparse.Namespace) -> int:
    if getattr(args, "live", False):
        # GATED live recon against third-party sources (never the target). Egress is an
        # explicit opt-in; the allowlist is disjoint from the seed by construction.
        from .live import DEFAULT_COLLECTOR_HOSTS, build_live_transport
        hosts = tuple(h.strip() for h in (args.collector_hosts or "").split(",") if h.strip())
        transport = build_live_transport(
            collector_hosts=hosts or DEFAULT_COLLECTOR_HOSTS,
            target_hosts=(args.seed,),
            capture_dir=Path(args.capture) if args.capture else None)
    else:
        fixtures = Path(args.fixtures) if args.fixtures else _BUNDLED_FIXTURES
        transport = FixtureTransport(fixtures)
    store, istore = _open(args.slug)
    world = WorldModel()
    ing = IntelIngest(world, store=istore, engagement_slug=args.slug or "")
    seed = canonicalize(NodeKind.DOMAIN, args.seed)
    res = ing.run_collectors([seed], list(DEFAULT_COLLECTORS), transport,
                             seq=0, max_depth=args.max_depth,
                             max_workers=RECON_MAX_WORKERS)
    if istore is not None:
        learn.credit_discovery(istore, res, archetype=args.archetype)
    owned = [{"id": e.canonical_id, "members": [m.node_id for m in e.members],
              "confidence": e.confidence, "owned_by": e.owned_by} for e in res.entities if e.owned_by]
    out = {"seed": seed.node_id, "applied": res.applied, "dropped": res.dropped,
           "persisted": res.persisted, "per_source": res.per_source,
           "entities": len(res.entities), "owned_entities": owned,
           "slug": args.slug or "(ephemeral)"}
    if store is not None:
        store.close()
    return _emit(out)


# ---- resolve -----------------------------------------------------------------


def _ingest_offline(args: argparse.Namespace, adapter) -> int:
    """Ingest an operator-provided offline inventory (cloud/IAM or SBOM) into the graph."""
    doc = json.loads(Path(args.file).read_text(encoding="utf-8"))
    obs = adapter(doc, seq=0)
    store, istore = _open(args.slug)
    world = WorldModel()
    ing = IntelIngest(world, store=istore, engagement_slug=args.slug or "")
    res = ing.ingest(obs)
    out = {"observations": len(obs), "applied": res.applied,
           "nodes": world.node_count, "edges": world.edge_count,
           "entities": len(res.entities)}
    if store is not None:
        store.close()
    return _emit(out)


def _ingest_cloud(args: argparse.Namespace) -> int:
    from .from_cloud import observations_from_cloud
    return _ingest_offline(args, observations_from_cloud)


def _ingest_sbom(args: argparse.Namespace) -> int:
    from .from_sbom import observations_from_sbom
    return _ingest_offline(args, observations_from_sbom)


def _ingest_intel(args: argparse.Namespace) -> int:
    """Ingest an operator-supplied threat-intel feed (MISP / STIX / NVD / OSV) OFFLINE →
    IOC + CVE observations projected onto the world-model.

    Fail-closed + gated: when run under an engagement ``--slug`` whose kill-switch is tripped,
    it refuses before reading anything. Graceful absence: a missing feed file is a clean skip
    (exit 0), not a crash. Live pulls are a deliberate code-level opt-in, never a CLI flag that
    fires egress by surprise (see build_threatintel_live_transport)."""
    from .from_threatintel import detect_format, observations_from_threat_feed

    if args.slug:
        from ..authority.killswitch import KillSwitch
        if KillSwitch(args.slug).is_tripped():
            print(f"refused: kill-switch tripped for engagement {args.slug!r}", file=sys.stderr)
            return 3

    path = Path(args.file)
    if not path.is_file():
        # graceful absence — no feed supplied is a normal, non-error state.
        return _emit({"feed": str(path), "present": False, "observations": 0,
                      "note": "feed file absent; nothing ingested"})

    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read feed {path}: {e}", file=sys.stderr)
        return 2

    fmt = args.format or "auto"
    obs = observations_from_threat_feed(doc, seq=0, fmt=fmt)
    store, istore = _open(args.slug)
    world = WorldModel()
    ing = IntelIngest(world, store=istore, engagement_slug=args.slug or "")
    res = ing.ingest(obs)
    iocs = sum(1 for o in obs if o.source_kind in (IntelSourceKind.MISP, IntelSourceKind.STIX))
    cves = sum(1 for o in obs if o.source_kind is IntelSourceKind.VULN_DB and o.relation is None)
    out = {"feed": str(path), "present": True, "format": fmt if fmt != "auto" else detect_format(doc),
           "observations": len(obs), "iocs": iocs, "cve_advisories": cves,
           "applied": res.applied, "dropped": res.dropped,
           "nodes": world.node_count, "edges": world.edge_count,
           "slug": args.slug or "(ephemeral)"}
    if store is not None:
        store.close()
    return _emit(out)


def _resolve(args: argparse.Namespace) -> int:
    store, istore = _open(args.slug)
    if istore is None:
        print("error: resolve reads persisted state; pass --slug", file=sys.stderr)
        return 2
    ents = istore.entities(engagement_slug=args.slug)
    out = [{"id": e.canonical_id, "kind": e.primary_kind.value, "confidence": e.confidence,
            "members": [m.node_id for m in e.members], "owned_by": e.owned_by,
            "why": e.explain()} for e in ents]
    store.close()
    return _emit(out)


# ---- plan --------------------------------------------------------------------


def _plan(args: argparse.Namespace) -> int:
    store, istore = _open(args.slug)
    subjects = [canonicalize(NodeKind.DOMAIN, args.seed)]
    if istore is not None:
        for e in istore.entities(engagement_slug=args.slug):
            for m in e.members:
                if m.kind in (NodeKind.DOMAIN, NodeKind.HOST):
                    subjects.append(m)
    # de-dup, deterministic
    subjects = list({s.node_id: s for s in subjects}.values())
    priors = (learn.planner_priors(istore, _SOURCE_KINDS, archetype=args.archetype)
              if istore is not None else None)
    plan = ReconPlanner(list(DEFAULT_COLLECTORS)).plan(subjects, priors=priors)
    out = {"priors": priors or "default 0.5",
           "tasks": [{"collector": t.collector, "subject": t.subject.node_id,
                      "prior": t.prior, "eig_bits": t.eig_bits, "eig_per_cost": t.eig_per_cost,
                      "rationale": t.rationale} for t in plan.next_n(args.top)]}
    if store is not None:
        store.close()
    return _emit(out)


# ---- predict -----------------------------------------------------------------


def _predict(args: argparse.Namespace) -> int:
    store, istore = _open(args.slug)
    domains: list[str] = []
    if args.domains:
        domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    elif istore is not None:
        for e in istore.entities(engagement_slug=args.slug):
            domains += [m.key for m in e.members if m.kind is NodeKind.DOMAIN]
    if not domains:
        print("error: no observed domains; pass --domains a,b or --slug with ingested data",
              file=sys.stderr)
        if store is not None:
            store.close()
        return 2
    preds = AssetPredictor().predict(observed_domains=domains)[: args.top]
    out = [assess_prediction(p) for p in preds]
    if store is not None:
        store.close()
    return _emit(out)


# ---- timeline ----------------------------------------------------------------


def _timeline(args: argparse.Namespace) -> int:
    store, istore = _open(args.slug)
    if istore is None:
        print("error: timeline reads persisted observations; pass --slug", file=sys.stderr)
        return 2
    idx = TemporalIndex.from_observations(istore.observations(engagement_slug=args.slug))
    out = [{"seq": e.seq, "event": e.kind, "source": e.source,
            "truth": e.truth_confidence} for e in idx.timeline(args.node)]
    store.close()
    return _emit({"node": args.node, "timeline": out})


# ---- delta -------------------------------------------------------------------


def _delta(args: argparse.Namespace) -> int:
    store, istore = _open(args.slug)
    if istore is None:
        print("error: delta reads persisted observations; pass --slug", file=sys.stderr)
        return 2
    idx = TemporalIndex.from_observations(istore.observations(engagement_slug=args.slug))
    d = idx.delta(args.from_seq, args.to_seq)
    store.close()
    return _emit(d.model_dump())


# ---- yield -------------------------------------------------------------------


def _yield(args: argparse.Namespace) -> int:
    store, istore = _open(args.slug or "_")   # any slug opens the shared DB
    rows = istore.all_source_yield()
    out = []
    for r in rows:
        prior = learn.source_prior(istore, r["source_kind"], archetype=r["archetype"])
        out.append({**r, "calibrated_prior": prior})
    store.close()
    return _emit(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 intel",
        description="Intelligence & Reconnaissance Engine — reason over intel, offline by default.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="run passive collectors (offline by default) and ingest")
    p.add_argument("--seed", required=True, help="apex domain to seed recon from")
    p.add_argument("--fixtures", default="", help="fixtures dir (default: bundled)")
    p.add_argument("--slug", default="", help="persist under this engagement slug")
    p.add_argument("--archetype", default="", help="target archetype for source-yield learning")
    p.add_argument("--max-depth", type=int, default=2, dest="max_depth")
    p.add_argument("--live", action="store_true",
                   help="GATED live recon against public third-party sources "
                        "(DoH / crt.sh / RDAP / RIPEstat — never the target). Opt-in egress.")
    p.add_argument("--collector-hosts", default="", dest="collector_hosts",
                   help="comma-separated source allowlist for --live (default: the four public sources)")
    p.add_argument("--capture", default="", help="mirror live responses to this dir to seed offline fixtures")
    p.set_defaults(fn=_ingest)

    p = sub.add_parser("ingest-cloud", help="ingest an operator cloud/IAM inventory (offline) → PRINCIPAL/resource + IAM edges")
    p.add_argument("--file", required=True, help="cloud inventory JSON (principals + resources)")
    p.add_argument("--slug", default="")
    p.set_defaults(fn=_ingest_cloud)

    p = sub.add_parser("ingest-sbom", help="ingest an operator SBOM (offline) → PACKAGE nodes + DEPENDS_ON edges")
    p.add_argument("--file", required=True, help="SBOM JSON (normalized or CycloneDX)")
    p.add_argument("--slug", default="")
    p.set_defaults(fn=_ingest_sbom)

    p = sub.add_parser("ingest-intel",
                       help="ingest a threat-intel feed (offline) → IOC + CVE/advisory observations "
                            "(MISP / STIX 2.x / NVD / OSV). LEADS, never facts.")
    p.add_argument("--file", required=True, help="threat-intel feed JSON export")
    p.add_argument("--format", default="auto", choices=["auto", "misp", "stix", "cve", "nvd", "osv"],
                   help="feed format (default: auto-detect)")
    p.add_argument("--slug", default="", help="persist under this engagement slug (kill-switch honored)")
    p.set_defaults(fn=_ingest_intel)

    p = sub.add_parser("resolve", help="resolved entities with merge explanations")
    p.add_argument("--slug", required=True)
    p.set_defaults(fn=_resolve)

    p = sub.add_parser("plan", help="recon plan ranked by value-of-information")
    p.add_argument("--seed", required=True)
    p.add_argument("--slug", default="")
    p.add_argument("--archetype", default="")
    p.add_argument("--top", type=int, default=10)
    p.set_defaults(fn=_plan)

    p = sub.add_parser("predict", help="gated asset predictions + confidence posteriors")
    p.add_argument("--slug", default="")
    p.add_argument("--domains", default="", help="comma-separated observed domains")
    p.add_argument("--top", type=int, default=10)
    p.set_defaults(fn=_predict)

    p = sub.add_parser("timeline", help="an asset's learning history")
    p.add_argument("--node", required=True, help="world-model node id, e.g. domain:api.company.com")
    p.add_argument("--slug", required=True)
    p.set_defaults(fn=_timeline)

    p = sub.add_parser("delta", help="surface change between two seqs (disappearance-honest)")
    p.add_argument("--from", type=int, required=True, dest="from_seq")
    p.add_argument("--to", type=int, required=True, dest="to_seq")
    p.add_argument("--slug", required=True)
    p.set_defaults(fn=_delta)

    p = sub.add_parser("yield", help="source-yield learning table + calibrated priors")
    p.add_argument("--slug", default="")
    p.add_argument("--archetype", default="")
    p.set_defaults(fn=_yield)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
