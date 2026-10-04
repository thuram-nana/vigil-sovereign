"""
worldmodel.twin_refresh — the STANDING TWIN: a thin, pure refresh of the asset
topology from the latest signed spine into a STORED, advisory snapshot (M4.5).

The world model (:mod:`worldmodel.spine_projector`) is rebuilt per CLI invocation
by every reader that needs it — ``attack-paths`` re-projects the spine on every
run. That makes the topology a one-off: nothing on disk says *"this is the asset
topology as of the current signed spine head"* that a dashboard, a drift check, or
the next engagement can read without re-projecting. This module closes that gap
with the SMALLEST possible surface: one pure projection into one deterministic
JSON snapshot, which a systemd timer (``infra/systemd/vigil-twin.{service,timer}``)
re-fires on a cadence so the stored twin tracks the spine head over time.

What it is, precisely:

  * **A pure re-projection, no new writer of the graph.** It reuses
    :func:`attack_paths._load_spine` and :func:`spine_projector.project_spine`
    VERBATIM — the projector stays the sole writer of the ``WorldModel`` and the
    sovereign projection rules (confirmed ⇔ oracle-signed, grounded belief,
    grounded-only refutation) are inherited unchanged. The snapshot is then just
    :func:`store.to_dict` over that projection, with a thin envelope.
  * **Deterministic + offline.** The projection reads only the spine (no network,
    no target), the temporal coordinate is the spine ``seq`` (never a wallclock /
    RNG), and ``store.to_dict`` sorts nodes by id and edges by ``(src, dst, kind)``.
    So the same spine yields a BYTE-IDENTICAL snapshot on re-run. The only clock is
    the OPTIONAL envelope ``generated_at``, which is PASSED IN by the caller (the
    unit's ``ExecStart`` may inject one, or omit it) — it never comes from
    ``time``/``datetime`` inside the projection, so a snapshot built with
    ``generated_at=None`` is a pure function of the spine alone.
  * **Advisory ONLY — never an oracle input, never mints a FACT.** The twin
    snapshot is a convenience projection for triage/dashboards. It reaches the
    oracle suite by no path: this module imports no verifier and registers no
    ``OracleKind`` (``_ALL_ORACLES`` stays 15), the envelope carries no signature
    and no evidence ref, and its ``advisory`` / ``mints_fact`` markers say so
    in-band. A FACT is minted ONLY by the oracle via ``certify_admitted`` over a
    signed spine record; a stored twin can never launder a claim into one.

The cadence PATTERN (a bounded re-fire that each cycle re-reads its source and
re-derives a pure result) mirrors :func:`verify.drift.watch`; here the systemd
timer owns the cadence and the CLI is a single ``--once`` cycle (the same shape as
``vigil reprove --once``), so the refresh itself stays pure and side-effect-bounded
to the one snapshot file it writes.

Import-clean & framework-side: the sibling ``worldmodel`` modules + ``common.paths``
+ stdlib only (no integration / sovereign import), so the offense-engine CLI can
refresh the twin without crossing the two-env boundary.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable, Optional

from ..common import paths as _paths
from . import store
from .attack_paths import (
    DEFAULT_ATTACK_EDGE_KINDS,
    DEFAULT_OBJECTIVE_KINDS,
    _load_spine,
    build_report,
)
from .impact import ImpactModel
from .models import EdgeKind, NodeKind
from .spine_projector import _to_edge_kind, _to_node_kind, project_spine, records_from_dicts

# The snapshot schema id. Bumped only on a breaking envelope change.
SNAPSHOT_SCHEMA = "vigil.twin-snapshot/1"

# The default basename the snapshot is written under in ``--out DIR`` mode.
SNAPSHOT_BASENAME = "worldmodel-twin.json"


def build_twin_snapshot(
    records: Any,
    *,
    strict_grounding: bool = False,
    spine_ref: str = "",
    generated_at: Optional[str] = None,
    footholds: Optional[Iterable[str]] = None,
    objective_kinds: Optional[Iterable[NodeKind]] = None,
    edge_kinds: Optional[Iterable[EdgeKind]] = None,
    k: int = 5,
    risk_averse: bool = False,
) -> dict:
    """Re-project ``records`` (an already-verified signed spine) into an advisory
    worldmodel snapshot dict.

    PURE + deterministic: the projection reuses :func:`project_spine` verbatim (spine
    ``seq`` is the only temporal coordinate) and the serialised body is
    :func:`store.to_dict`, which sorts nodes/edges. With ``generated_at=None`` and no
    ``footholds`` the result is a pure function of the spine, so a re-run is
    byte-identical.

    ``footholds`` optionally re-runs :func:`attack_paths.build_report` per foothold
    node id (uniform business impact — the advisory twin never reads an
    ``impact.yaml``), stored under ``attack_paths`` keyed by foothold id in sorted
    order. Those reports are themselves read-only + deterministic.

    The snapshot is ADVISORY: it carries no signature and no evidence ref, and the
    ``advisory`` / ``mints_fact`` markers record that it is never an oracle input."""
    recs = records_from_dicts(records)
    world = project_spine(recs, strict_grounding=strict_grounding)

    snapshot: dict[str, Any] = {
        "schema": SNAPSHOT_SCHEMA,
        # In-band honesty markers: the twin is a convenience projection, never a FACT
        # source and never an oracle input. (Enforced structurally: this module imports
        # no verifier and defines no OracleKind — _ALL_ORACLES stays 15.)
        "advisory": True,
        "mints_fact": False,
        "strict_grounding": bool(strict_grounding),
        "spine_ref": spine_ref,
        "graph": {"nodes": world.node_count, "edges": world.edge_count},
        "worldmodel": store.to_dict(world),
    }
    if generated_at is not None:
        # The ONLY clock, and it is injected by the caller — never read here — so the
        # projection stays pure and a generated_at=None snapshot is spine-only.
        snapshot["generated_at"] = str(generated_at)

    foot = sorted({str(f).strip() for f in (footholds or []) if str(f).strip()})
    if foot:
        obj_kinds = list(objective_kinds) if objective_kinds is not None else list(DEFAULT_OBJECTIVE_KINDS)
        e_kinds = list(edge_kinds) if edge_kinds is not None else list(DEFAULT_ATTACK_EDGE_KINDS)
        impact = ImpactModel.uniform()
        reports: dict[str, Any] = {}
        for src in foot:
            reports[src] = build_report(
                world, source=src, objective_kinds=obj_kinds, edge_kinds=e_kinds,
                impact=impact, k=k, risk_averse=risk_averse,
                impact_source="uniform (advisory twin)",
            )
        snapshot["attack_paths"] = reports
    return snapshot


def to_json(snapshot: dict) -> str:
    """Deterministic JSON (sorted keys, UTF-8) — byte-identical for the same snapshot."""
    return json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 twin",
        description="The STANDING TWIN: re-project the latest signed spine into a stored, "
                    "ADVISORY worldmodel snapshot. Deterministic; read-only; no traffic; "
                    "never an oracle input (never mints a FACT).",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    rp = sub.add_parser(
        "refresh",
        help="Do one refresh cycle: re-project the spine into a stored advisory snapshot.",
    )
    rp.add_argument("--once", action="store_true",
                    help="Do exactly one refresh cycle (the systemd timer owns the cadence). "
                         "Accepted for symmetry with `vigil reprove --once`; the refresh is "
                         "single-shot regardless.")
    rp.add_argument("--spine", required=True, metavar="PATH",
                    help="JSON spine document (a list of records, or {records:[...]}). The "
                         "signature / hash-chain audit is the spine loader's job; this surface "
                         "re-projects the already-verified records.")
    rp.add_argument("--source", action="append", default=[], metavar="NODE_ID",
                    help="A foothold node id to ALSO compute an advisory attack-path report for "
                         "(repeatable). Omit for a topology-only snapshot.")
    rp.add_argument("--objective-kind", action="append", default=[], metavar="KIND",
                    help="A crown-jewel node kind for the attack-path reports (repeatable). "
                         "Default: datastore, cloud_resource.")
    rp.add_argument("--edge-kind", action="append", default=[], metavar="KIND",
                    help="An attack-movement edge kind a path may traverse (repeatable). "
                         "Default: the reachability/trust/identity movement set.")
    rp.add_argument("-k", type=int, default=5, help="How many top paths per foothold (default 5).")
    rp.add_argument("--risk-averse", action="store_true",
                    help="Rank attack-path routes by evidence-discounted belief (LCB).")
    rp.add_argument("--strict-grounding", action="store_true",
                    help="Seed an UNGROUNDED (LLM/assumption-provenance) spine write at a low "
                         "belief floor rather than its asserted confidence.")
    rp.add_argument("--generated-at", default=None, metavar="ISO",
                    help="An explicit timestamp for the snapshot envelope. DETERMINISM: it is the "
                         "only clock and is caller-supplied; omit it for a spine-only, "
                         "byte-identical snapshot.")
    rp.add_argument("--out", metavar="DIR",
                    help=f"Output directory — writes DIR/{SNAPSHOT_BASENAME} (owner-only at rest).")
    rp.add_argument("--stdout", action="store_true", help="Print the snapshot JSON; write no files.")
    return parser


def _resolve_kinds(args) -> tuple[list[NodeKind], list[EdgeKind]] | None:
    """Resolve the (objective, edge) kind lists from the CLI; print + return None on a bad kind."""
    obj_kinds: list[NodeKind] = []
    for raw in (args.objective_kind or []):
        nk = _to_node_kind(raw)
        if nk is None:
            print(f"error: unknown objective kind {raw!r}", flush=True)
            return None
        if nk not in obj_kinds:
            obj_kinds.append(nk)
    if not obj_kinds:
        obj_kinds = list(DEFAULT_OBJECTIVE_KINDS)

    edge_kinds: list[EdgeKind] = []
    for raw in (args.edge_kind or []):
        ek = _to_edge_kind(raw)
        if ek is None:
            print(f"error: unknown edge kind {raw!r}", flush=True)
            return None
        if ek not in edge_kinds:
            edge_kinds.append(ek)
    if not edge_kinds:
        edge_kinds = list(DEFAULT_ATTACK_EDGE_KINDS)
    return obj_kinds, edge_kinds


def _do_refresh(args) -> int:
    if args.k < 1:
        print("error: -k must be >= 1", flush=True)
        return 2

    spine_path = Path(args.spine)
    if not spine_path.is_file():
        print(f"error: no spine file at {spine_path}", flush=True)
        return 2
    try:
        rows = _load_spine(spine_path)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: cannot read spine {spine_path}: {e}", flush=True)
        return 2

    kinds = _resolve_kinds(args)
    if kinds is None:
        return 2
    obj_kinds, edge_kinds = kinds

    snapshot = build_twin_snapshot(
        rows,
        strict_grounding=args.strict_grounding,
        spine_ref=str(spine_path),
        generated_at=args.generated_at,
        footholds=args.source,
        objective_kinds=obj_kinds,
        edge_kinds=edge_kinds,
        k=args.k,
        risk_averse=args.risk_averse,
    )
    js = to_json(snapshot)

    if args.stdout:
        print(js)
        return 0
    if not args.out:
        # No sink given → print (nowhere canonical to write).
        print(js)
        return 0

    out_path = Path(args.out) / SNAPSHOT_BASENAME
    _paths.secure_write(out_path, js)   # owner-only at rest (may hold intel-derived topology)
    g = snapshot["graph"]
    foot = snapshot.get("attack_paths", {})
    print(f"wrote {out_path}")
    print(f"twin: {g['nodes']} node(s) / {g['edges']} edge(s) projected from {spine_path}"
          + (f"; {len(foot)} foothold report(s)" if foot else ""))
    return 0


def main(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.action == "refresh":
        return _do_refresh(args)
    parser.print_help()
    return 2
