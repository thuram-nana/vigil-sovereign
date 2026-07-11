"""
engage_fusion — fuse GATED sensors into a live engagement's world-model (Workstream B, slice 1).

Sensors (``DeclaredServiceSensor``, ``SbomVulnSensor``, Nmap, Nuclei, cloud …) already exist and
already know how to normalise their output into ``intel.Observation``s, but in a live run their
observations never flow into THAT engagement's world-model — the sensor framework was built and
tested in isolation. This module is the missing seam: given a run's ``WorldModel`` and slug, it runs
a small set of SAFE, OFFLINE sensors through the existing gated pipeline, folds their observations
into the world-model, and lets the existing oracles re-verify in-run where applicable.

    resolve fusion plan  ->  run_sensor (W1.4 fail-closed gate chain)  ->  normalize -> Observation
                          ->  IntelIngest.ingest -> project_observation (LEAD, ``intel:`` provenance)
                          ->  oracle re-verify (version-range) -> ORACLE-GROUNDED fact (``oracle:``)

``fuse_sensors(world, slug, ctx)`` is the hook Workstream-A's ``_run_autonomous`` calls (with a
graceful fallback when this module is absent), so the signature is fixed and load-bearing.

Doctrine, by construction:
  * PROVE-DON'T-GUESS. A sensor mints OBSERVATIONS, never facts. They enter the world-model as
    ``GROUNDING_INTEL`` LEADS (the ``intel:`` provenance tier). A LEAD becomes a FACT only when a
    deterministic oracle re-fires over the sensor's OWN retained evidence — here the version-range
    oracle over SBOM advisories, written back with ``oracle:`` provenance (``GROUNDING_GROUNDED``).
    Nothing else promotes a claim. ``declared_service`` 'open' stays a LEAD until a live
    service-reachability handshake oracle confirms it (roadmap).
  * GATED, FAIL-CLOSED. Every sensor runs through ``sensors.pipeline.run_sensor`` ->
    ``agents.tools.invoke_tool``'s chain (kill-switch / entitlement / scope / destructive / egress).
    A refused/failed sensor mints nothing. The first slice's allowlist is OFFLINE-only producers
    (no live binary, no egress); the active/live sensors are the roadmap below.
  * DETERMINISM. ``normalize -> Observation -> project -> Beta belief`` is a pure, replayable
    function of the caller-supplied ``seq`` — no wallclock, no global rng. ``obs_id`` is stable so
    re-ingest is idempotent (belief never inflates from re-running the fusion pass).
  * ADDITIVE / OFF BY DEFAULT. Nothing on the default scan/engage/benchmark path imports this
    module; only WS-A's opt-in autonomous loop calls ``fuse_sensors``. The gate benchmark is
    therefore byte-identical.

ROADMAP — fusing the ACTIVE sensors into the loop (slice 2+):
  * ``nmap`` (``NmapServiceSensor``): ACTIVE_RECON entitlement + charter scope + the service-
    reachability handshake oracle (``verify.reachability``) to promote 'open' LEADS to FACTS in-run.
  * ``nuclei`` / ``zap`` / ``burp`` (``web_scanner``): gated web LEADS re-verified by the matching
    CRUCIBLE oracle (``sensors.confirm_web_lead`` -> the bug-class oracle) before promotion.
  * ``cloud`` (``CloudInventoryPullSensor`` / posture import): IAM topology LEADS whose privilege
    PATHS become FACTS only when the policy-path oracle (``confirm_cloud_privilege_path``) re-derives
    them over the retained graph.
  * ``tshark`` packet flows, once a capture is supplied.
  These add to ``_SAFE_SENSORS`` only alongside their promotion oracle, and each stays gated at
  ``run_sensor`` time; the fusion loop itself does not change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .agents.tools import ToolContext
from .agents.tools.base import ToolRegistry
from .intel.ingest import IntelIngest
from .intel.models import Observation
from .intel.refs import EntityRef, canonicalize
from .sensors.builtin import DeclaredServiceSensor
from .sensors.pipeline import run_sensor
from .sensors.sbom import SbomVulnSensor
from .worldmodel.models import Edge, EdgeKind, Node, NodeKind

# The SAFE, OFFLINE sensor allowlist for the first fusion slice: producers that need no live
# external binary and no egress (Tier-1, no entitlement). An active/live sensor task is dropped
# in _resolve_tasks (roadmap) rather than invoked — the gate chain would refuse it anyway, but the
# allowlist keeps the first slice's behaviour predictable and its imports minimal.
_SAFE_SENSORS = ("declared_service", "sbom_vuln")

# The confidence an oracle-confirmed vulnerable-dependency FACT enters at. It is a fact because the
# version-range oracle deterministically re-derived membership over the retained advisory, not
# because of this scalar; belief stays a Beta posterior in the graph.
_ORACLE_FACT_CONFIDENCE = 0.99


@dataclass(frozen=True)
class FusionTask:
    """One sensor to fuse: a registered sensor ``name`` and its ``args`` (e.g.
    ``{"host": ..., "services": [...]}`` for declared_service, ``{"report": "/path"}`` for
    sbom_vuln). The plan is an ordered list of these — deterministic, caller-supplied."""

    sensor: str
    args: dict = field(default_factory=dict)


# ---- fusion plan resolution -------------------------------------------------


def _coerce_task(raw: Any) -> FusionTask | None:
    """Coerce one plan entry (a ``FusionTask`` or a ``{"sensor"/"name", "args"}`` dict) into a
    ``FusionTask`` — defensively, never raising. A malformed entry returns None (it is skipped,
    not fatal), so a partly-bad plan still fuses its good tasks."""
    if isinstance(raw, FusionTask):
        sensor, args = raw.sensor, raw.args
    elif isinstance(raw, dict):
        sensor = raw.get("sensor") or raw.get("name")
        args = raw.get("args")
    else:
        return None
    if not isinstance(sensor, str) or not sensor.strip():
        return None
    return FusionTask(sensor=sensor.strip(), args=dict(args) if isinstance(args, dict) else {})


def _plan_from_ctx(ctx: Any) -> list | None:
    """An explicit fusion plan carried on the caller's ``ctx`` — the path WS-A's autonomous loop
    uses. Read defensively from a few conventional attrs (or a mapping). None means 'no plan on
    ctx', which falls through to the operator manifest."""
    for attr in ("fusion_tasks", "sensor_tasks", "fusion_plan"):
        v = getattr(ctx, attr, None)
        if isinstance(v, (list, tuple)):
            return list(v)
    if isinstance(ctx, dict):
        for key in ("fusion_tasks", "sensor_tasks", "fusion_plan"):
            v = ctx.get(key)
            if isinstance(v, (list, tuple)):
                return list(v)
    return None


def _plan_from_manifest(slug: str) -> list:
    """The operator's declared fusion plan at ``targets/<slug>/fusion.json`` — a JSON list of task
    dicts, or ``{"tasks": [...]}``. This makes a real engagement fuse its declared inventory /
    SBOM report with zero WS-A wiring. Total: a missing/malformed manifest yields ``[]``."""
    if not slug:
        return []
    try:
        from .common.paths import target_dir

        path = target_dir(slug) / "fusion.json"
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if isinstance(data, dict):
        data = data.get("tasks")
    return data if isinstance(data, list) else []


def _resolve_tasks(slug: str, ctx: Any) -> list[FusionTask]:
    """The ordered fusion plan. Priority: an explicit plan on ``ctx`` first, else the operator
    manifest. Only SAFE (offline) sensors survive in the first slice — an active-sensor task is
    dropped here (roadmap), never invoked. Deterministic: plan/manifest order is preserved."""
    raw = _plan_from_ctx(ctx)
    if raw is None:
        raw = _plan_from_manifest(slug)
    tasks: list[FusionTask] = []
    for item in raw or []:
        t = _coerce_task(item)
        if t is not None and t.sensor in _SAFE_SENSORS:
            tasks.append(t)
    return tasks


# ---- run context / clock ----------------------------------------------------


def _fusion_registry() -> ToolRegistry:
    """A registry holding ONLY the first-slice safe/offline sensors. Registration is not
    invocation (each is still gated at ``run_sensor`` time), but keeping the registry minimal
    keeps the fusion path's scope and imports tight — active sensors are added with slice 2."""
    reg = ToolRegistry()
    reg.register(DeclaredServiceSensor())
    reg.register(SbomVulnSensor())
    return reg


def _tool_context(world: Any, slug: str, ctx: Any) -> ToolContext:
    """A ``ToolContext`` bound to THIS run's slug (authoritative for gating) and world. Any
    ``dry_run`` / ``prompt_callback`` on the caller's ctx is inherited so fusion runs under the
    engagement's posture; a plain ctx yields safe defaults (dry_run False, default-deny prompt)."""
    if isinstance(ctx, ToolContext):
        return ToolContext(slug=slug or ctx.slug, world=world,
                           prompt_callback=ctx.prompt_callback, dry_run=ctx.dry_run)
    return ToolContext(
        slug=slug, world=world,
        prompt_callback=getattr(ctx, "prompt_callback", None),
        dry_run=bool(getattr(ctx, "dry_run", False)))


def _sink_of(ctx: Any) -> Any:
    """The optional spine sink for best-effort event emission (duck-typed; None => no events)."""
    return getattr(ctx, "sink", None) or getattr(ctx, "spine_sink", None)


def _world_high_water(world: Any) -> int:
    """The world-model's current monotonic high-water (max ``last_seen`` over nodes), so fusion's
    clock continues AFTER the run's recon/scan state instead of inverting it. Defensive: 0 on any
    trouble (a fresh world) so the base falls to 1."""
    try:
        return max((int(getattr(n, "last_seen", 0) or 0) for n in world.all_nodes()), default=0)
    except Exception:
        return 0


def _base_seq(world: Any, ctx: Any) -> int:
    """The seq the fusion batch starts at. A caller-supplied ``base_seq`` (WS-A passing the run's
    high-water) wins; otherwise continue after the world's own high-water; otherwise 1. Each task
    then takes ``base + i`` so distinct tasks get distinct ``obs_id``s and the clock is monotonic."""
    for attr in ("base_seq", "fusion_seq"):
        v = getattr(ctx, attr, None)
        if isinstance(v, int) and v >= 0:
            return v
    if isinstance(ctx, dict) and isinstance(ctx.get("base_seq"), int) and ctx["base_seq"] >= 0:
        return int(ctx["base_seq"])
    return _world_high_water(world) + 1


# ---- oracle re-verification (LEAD -> FACT, where applicable) -----------------


def _project_vuln_fact(world: Any, adv: dict, *, seq: int) -> None:
    """Write the version-range oracle's confirmed vulnerable-dependency FACT: a ``VULNERABILITY``
    node + an ``AFFECTS`` edge (vulnerability -> package), both with ``oracle:`` provenance so the
    world-model's ``classify_provenance`` grounds them (``GROUNDING_GROUNDED``). The ``PACKAGE``
    endpoint is the same LEAD node the sensor minted — the AFFECTS edge is the grounded fact; the
    package stays intel-grounded. Idempotent (stable ids); pure over ``seq``."""
    vuln_id = str(adv.get("vuln_id") or "").strip()
    name = str(adv.get("package") or "").strip()
    version = str(adv.get("version") or "").strip()
    if not vuln_id or not name:
        return
    vuln = canonicalize(NodeKind.VULNERABILITY, vuln_id)
    pkg = EntityRef(kind=NodeKind.PACKAGE, key=f"{name}@{version}".lower())
    prov = "oracle:version_range"
    world.add_node(Node(
        id=vuln.node_id, kind=NodeKind.VULNERABILITY,
        attrs={k: v for k, v in {"vuln_id": vuln_id, "ecosystem": adv.get("ecosystem") or None,
                                 "confirmed_by": "version_range_oracle"}.items() if v},
        provenance=prov, confidence=_ORACLE_FACT_CONFIDENCE, first_seen=seq, last_seen=seq))
    # The edge needs both endpoints. The sensor already minted the PACKAGE LEAD, but mint a bare
    # intel-grounded fallback if it is somehow absent (defensive) so the grounded edge never fails.
    if not world.has_node(pkg.node_id):
        world.add_node(Node(
            id=pkg.node_id, kind=NodeKind.PACKAGE, attrs={"name": name, "version": version},
            provenance=f"intel:sbom:{pkg.node_id}", confidence=0.85, first_seen=seq, last_seen=seq))
    world.add_edge(Edge(
        src=vuln.node_id, dst=pkg.node_id, kind=EdgeKind.AFFECTS, attrs={},
        provenance=prov, confidence=_ORACLE_FACT_CONFIDENCE, first_seen=seq, last_seen=seq))


def _reverify(world: Any, task: FusionTask, res: Any, *, seq: int) -> int:
    """Let the existing oracles re-fire over the sensor's OWN retained evidence, in-run. The only
    offline-firing oracle in the first slice is the version-range oracle over SBOM advisories: a
    confirmed advisory writes an oracle-grounded vuln fact; the sensor's LEADS are untouched.
    Returns the number of facts promoted. Best-effort and deterministic — advisories are re-verified
    in report order, and the oracle is a pure function of the retained advisory."""
    if task.sensor != "sbom_vuln" or not getattr(res, "ok", False):
        return 0
    try:
        from .verify import confirm_vulnerable_dependency
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    advisories = output.get("advisories")
    if not isinstance(advisories, list):
        return 0
    promoted = 0
    for adv in advisories:
        if not isinstance(adv, dict):
            continue
        try:
            confirmed = bool(confirm_vulnerable_dependency(adv).confirmed)
        except Exception:
            confirmed = False
        if confirmed:
            _project_vuln_fact(world, adv, seq=seq)
            promoted += 1
    return promoted


# ---- the hook WS-A calls -----------------------------------------------------


def fuse_sensors(world: Any, slug: str, ctx: Any) -> list:
    """Fuse the run's SAFE sensors into ``world`` and return the LEAD ``Observation``s minted.

    Runs each task in the resolved fusion plan through ``sensors.pipeline.run_sensor`` — which gates
    it (kill-switch / entitlement / scope / destructive / egress) and, only if it ran, normalises its
    output into ``intel.Observation``s and folds them into ``world`` via ``IntelIngest`` /
    ``project_observation`` (as ``GROUNDING_INTEL`` LEADS). Then lets the existing oracles re-verify
    in-run where applicable (the version-range oracle over SBOM advisories), promoting a confirmed
    LEAD to an ``oracle:``-grounded FACT in ``world``. Returns the observations minted (the LEADS).

    Fail-closed and total: a refused/failed sensor mints nothing; an empty plan returns ``[]``; a
    sensor that raises is skipped rather than sinking the pass. Deterministic: the caller-supplied
    seq (``base + task index``) stamps each batch, no wallclock/rng. This is WS-A's ``_run_autonomous``
    hook — it is only reached on the opt-in autonomous path, so the default gate stays byte-identical."""
    tasks = _resolve_tasks(slug, ctx)
    if not tasks:
        return []

    registry = _fusion_registry()
    tool_ctx = _tool_context(world, slug, ctx)
    ingest = IntelIngest(world, engagement_slug=slug or "")
    sink = _sink_of(ctx)
    base = _base_seq(world, ctx)

    minted: list[Observation] = []
    for i, task in enumerate(tasks):
        seq = base + i
        try:
            res = run_sensor(registry, task.sensor, task.args, tool_ctx,
                             ingest=ingest, seq=seq, sink=sink)
        except Exception:
            continue   # a sensor blowing up never sinks the whole fusion pass
        minted.extend(res.observations)
        _reverify(world, task, res, seq=seq)   # LEAD -> FACT, where an oracle re-fires
    return minted
