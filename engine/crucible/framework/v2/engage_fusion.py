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
    deterministic oracle re-fires over the sensor's OWN retained evidence — the version-range oracle
    over SBOM advisories, the k8s-posture oracle over each retained kube-bench control (WS-3a), and the
    policy-path oracle over each oracle-provable cloud posture lead (WS-3b) — written back with
    ``oracle:`` provenance (``GROUNDING_GROUNDED``). Nothing else promotes a claim. A ``declared_service``
    'open' LEAD stays a LEAD unless the OPT-IN, GATED live service-reachability handshake confirms it
    (WS-3c: only through the fail-closed capture, never on the default path).
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

WIRED (Workstream-3) — the dormant OFFLINE producers now fuse alongside their promotion oracle:
  * ``kube_bench`` (``KubeBenchSensor``): CIS-control-failure LEADS whose CONCRETE insecure settings
    become FACTS when the k8s-posture oracle (``verify.k8s_posture``) re-derives them over the retained
    control (3a).
  * ``cloud_import`` (``CloudPostureImportSensor``): IAM topology + posture LEADS whose privilege PATHS
    become FACTS when the policy-path oracle (``sensors.cloud.confirm_cloud_posture_facts``) re-derives
    them over the retained graph, and whose ACHIEVED-STATE misconfiguration LEAD (encryption-at-rest
    disabled on a sensitive datastore) becomes a FACT when the cloud-posture oracle
    (``verify.cloud_posture.confirm_cloud_posture``) re-derives it over the retained achieved state — no
    live cloud calls (3b).
  * ``declared_service`` 'open' LEADS become reachability FACTS ONLY via an OPT-IN, GATED live handshake
    (``verify.reachability``: ACTIVE_RECON + charter scope, fail-closed) — never on the default path (3c).

ROADMAP — the remaining ACTIVE sensors:
  * ``nmap`` (``NmapServiceSensor``): the SAME reachability handshake oracle over a real scan's 'open'.
  * ``nuclei`` / ``zap`` / ``burp`` (``web_scanner``): gated web LEADS re-verified by the matching
    CRUCIBLE oracle (``sensors.confirm_web_lead`` -> the bug-class oracle) before promotion.
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

# The SAFE, OFFLINE sensor allowlist: producers that need no live external binary and no egress
# (Tier-1, no entitlement). An active/live sensor task is dropped in _resolve_tasks rather than
# invoked — the gate chain would refuse it anyway, but the allowlist keeps behaviour predictable.
# Workstream-3 wires the dormant OFFLINE producers (kube_bench, cloud_import) in alongside their
# promotion oracle (k8s-posture, policy-path) — each still gated at run_sensor time. (declared_service
# stays offline; its LEADS can be promoted by a GATED, opt-in LIVE reachability handshake — see
# _reverify_reachability — which fires only through the fail-closed capture, never by default.)
_SAFE_SENSORS = ("declared_service", "sbom_vuln", "kube_bench", "cloud_import", "cicd_workflows",
                 "mobsf_static", "tls_cert", "android_manifest", "mesh_config", "email_auth", "identity")

# The LIVE-collector allowlist (Phase C2): Tier-2 sensors that call a third-party control plane
# read-only AT RUN TIME. Unlike the offline _SAFE_SENSORS these make network calls in their own
# ``run`` (not merely in an opt-in re-verify handshake), so they are admitted to the fusion plan as a
# SEPARATE, explicit, auditable set — and remain fully gated at ``run_sensor`` time: each declares an
# ``ACTIVE_RECON`` capability (the engagement must be entitled) and its control-plane ``egress_hosts``
# (the egress gate REFUSES it unless the operator provisioned them in ``targets/<slug>/collector-hosts.txt``
# — C1). With no entitlement, no provisioned egress, or no ambient credentials the live collector
# refuses / no-ops (fail-closed, default-off). Their leads are promoted by the SAME oracles as the
# offline importers (``cloud_live`` reuses ``_reverify_cloud``), so no new promotion path is trusted.
_LIVE_SENSORS = ("cloud_live", "gcp_live", "azure_live", "k8s_live")

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
        if t is not None and (t.sensor in _SAFE_SENSORS or t.sensor in _LIVE_SENSORS):
            tasks.append(t)
    return tasks


# ---- run context / clock ----------------------------------------------------


def _fusion_registry() -> ToolRegistry:
    """A registry holding ONLY the safe/offline fusion sensors. Registration is not invocation (each is
    still gated at ``run_sensor`` time), but keeping the registry minimal keeps the fusion path's scope
    and imports tight. Workstream-3 adds the offline kube-bench + cloud-posture importers alongside
    their promotion oracles."""
    from .sensors.cicd import WorkflowScanSensor
    from .sensors.cloud import CloudPostureImportSensor
    from .sensors.azure_live import AzureLiveSensor
    from .sensors.cloud_live import CloudLiveSensor
    from .sensors.gcp_live import GcpLiveSensor
    from .sensors.k8s_live import K8sLiveSensor
    from .sensors.k8s_runtime import KubeBenchSensor
    from .sensors.mobile import MobsfSensor
    from .sensors.tls_cert import CertScanSensor
    from .sensors.android_manifest import AndroidManifestSensor
    from .sensors.mesh import MeshConfigSensor
    from .sensors.email_auth import EmailAuthSensor
    from .sensors.identity import IdentitySensor

    reg = ToolRegistry()
    reg.register(DeclaredServiceSensor())
    reg.register(SbomVulnSensor())
    reg.register(KubeBenchSensor())          # offline kube-bench --json ingest (Tier-1)
    reg.register(K8sLiveSensor())            # LIVE read-only K8s workload/RBAC posture (Tier-2, gated; C2·K8s)
    reg.register(CloudPostureImportSensor())  # offline cloud/CSPM export ingest (Tier-1)
    reg.register(CloudLiveSensor())           # LIVE read-only AWS posture pull (Tier-2, gated; C2)
    reg.register(GcpLiveSensor())             # LIVE read-only GCP posture pull (Tier-2, gated; C2·GCP)
    reg.register(AzureLiveSensor())           # LIVE read-only Azure posture pull (Tier-2, gated; C2·Azure)
    reg.register(WorkflowScanSensor())        # offline GitHub-Actions workflow ingest (Tier-1)
    reg.register(MobsfSensor())               # offline MobSF static-report ingest (Tier-1)
    reg.register(CertScanSensor())            # offline X.509 certificate ingest (Tier-1)
    reg.register(AndroidManifestSensor())     # offline decoded-AndroidManifest.xml ingest (Tier-1)
    reg.register(MeshConfigSensor())          # offline Istio/Linkerd config ingest (Tier-1)
    reg.register(EmailAuthSensor())           # offline DNS email-auth policy ingest (Tier-1, Domain 10)
    reg.register(IdentitySensor())            # offline IdP-export identity-posture ingest (Tier-1, Domain 7)
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


def _project_oracle_fact(world: Any, subject: EntityRef, *, oracle_kind: str, bug_class: str,
                         evidence: str, seq: int, detail: dict | None = None) -> None:
    """Write an oracle-grounded FACT about ``subject`` (a sensor lead): a ``FINDING`` node + an
    ``EVIDENCES`` edge (finding -> subject), both ``oracle:<kind>`` provenance so the world-model's
    ``classify_provenance`` grounds them (``GROUNDING_GROUNDED``). The subject node stays whatever tier
    the sensor minted it at (a LEAD); the EVIDENCES edge is the grounded fact attached to it — exactly
    the shape ``_project_vuln_fact`` uses for the version-range promotion. Idempotent (stable ids), pure
    over ``seq``. The GENERIC WS-3 promotion projector (k8s-posture / policy-path / reachability)."""
    prov = f"oracle:{oracle_kind}"
    finding = EntityRef(kind=NodeKind.FINDING, key=f"{oracle_kind}:{subject.key}")
    attrs: dict = {"bug_class": bug_class, "confirmed_by": oracle_kind, "evidence": (evidence or "")[:400]}
    if detail:
        attrs.update({k: v for k, v in detail.items() if v is not None})
    world.add_node(Node(
        id=finding.node_id, kind=NodeKind.FINDING, attrs=attrs,
        provenance=prov, confidence=_ORACLE_FACT_CONFIDENCE, first_seen=seq, last_seen=seq))
    if not world.has_node(subject.node_id):
        # defensive: the sensor lead usually already minted the subject; mint an intel-grounded
        # fallback so the grounded edge never dangles (subject stays a lead; the edge is the fact).
        world.add_node(Node(
            id=subject.node_id, kind=subject.kind, attrs={},
            provenance=f"intel:fusion:{subject.node_id}", confidence=0.6, first_seen=seq, last_seen=seq))
    world.add_edge(Edge(
        src=finding.node_id, dst=subject.node_id, kind=EdgeKind.EVIDENCES, attrs={},
        provenance=prov, confidence=_ORACLE_FACT_CONFIDENCE, first_seen=seq, last_seen=seq))


def _reverify_sbom(world: Any, res: Any, *, seq: int) -> int:
    """version-range oracle over SBOM advisories -> an oracle-grounded vuln fact per confirmed advisory."""
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


def _reverify_k8s(world: Any, res: Any, *, seq: int) -> int:
    """3a promotion: the k8s-posture oracle over each RETAINED kube-bench control. A control that hard-
    FAILED with a concrete observed insecure setting is promoted to an oracle-grounded FACT on its
    CONTROL node; a passing/benign control (or a FAIL with no proof) is left an honest LEAD."""
    try:
        from .verify.k8s_posture import confirm_k8s_posture
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    controls = output.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            if not confirm_k8s_posture(c).confirmed:
                continue
        except Exception:
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"cis-k8s:{check_id}".lower())
        _project_oracle_fact(
            world, subject, oracle_kind="k8s_posture", bug_class="k8s_misconfiguration",
            evidence=f"kube-bench CIS control {check_id} FAILED with a concrete observed insecure setting",
            seq=seq, detail={"check_id": check_id, "status": str(c.get("status") or "")})
        promoted += 1
    return promoted


def _reverify_k8s_live(world: Any, res: Any, *, seq: int) -> int:
    """C2·K8s promotion: the LIVE k8s-RBAC achieved-state oracle over each RETAINED binding control. A binding
    whose retained raw subjects + role re-derive a concrete critical fact (an ANONYMOUS subject bound to a
    dangerous built-in role — cluster-admin/admin/edit) is promoted to an oracle-grounded FACT on its CONTROL
    node; anything else (the benign public-info-viewer default, an anonymous binding to a non-dangerous role)
    is left an honest LEAD. NO cluster calls — a pure re-derivation over the retained control (mirrors
    :func:`_reverify_k8s`; the oracle ``k8s_workload_posture_oracle`` is called directly like
    :func:`_reverify_crypto`)."""
    try:
        from .verify.oracles import k8s_workload_posture_oracle
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    controls = output.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            sig = k8s_workload_posture_oracle(c)
        except Exception:
            continue
        if not getattr(sig, "fired", False):
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"k8s-workload:{check_id}".lower())
        _project_oracle_fact(
            world, subject, oracle_kind="k8s_workload", bug_class="k8s_workload_misconfiguration",
            evidence=f"live k8s control {check_id} re-derives a concrete insecure achieved state",
            seq=seq, detail={"check_id": check_id, "resource_kind": str(c.get("resource_kind") or ""),
                             "rule": (getattr(sig, "observed", None) or {}).get("rule")})
        promoted += 1
    return promoted


def _reverify_cicd(world: Any, res: Any, *, seq: int) -> int:
    """CI/CD promotion: the CI/CD-posture oracle over each RETAINED workflow control. A control that
    re-derives a concrete dangerous construct (an unpinned third-party action / pwn-request checkout /
    script-injection sink) is promoted to an oracle-grounded FACT on its CONTROL node; anything the
    oracle cannot re-confirm is left an honest LEAD. Mirrors :func:`_reverify_k8s`."""
    try:
        from .verify.cicd_posture import confirm_cicd_posture
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    controls = output.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            if not confirm_cicd_posture(c).confirmed:
                continue
        except Exception:
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"cicd:{check_id}".lower())
        _project_oracle_fact(
            world, subject, oracle_kind="cicd_posture", bug_class="cicd_misconfiguration",
            evidence=f"CI/CD workflow control '{c.get('rule')}' re-derives a concrete dangerous construct",
            seq=seq, detail={"check_id": check_id, "rule": str(c.get("rule") or "")})
        promoted += 1
    return promoted


def _reverify_mesh(world: Any, res: Any, *, seq: int) -> int:
    """Service-mesh promotion: the mesh-posture oracle over each RETAINED mesh-config control. A control
    whose achieved state re-derives a concrete insecure fact (permissive/disabled mTLS, an allow-everyone
    AuthorizationPolicy, an unauthenticated Linkerd inbound policy) is promoted to an oracle-grounded FACT
    on its CONTROL node; a STRICT/scoped/deny config is left an honest LEAD. Mirrors :func:`_reverify_cicd`."""
    try:
        from .verify.mesh_posture import confirm_mesh_posture
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    controls = output.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            if not confirm_mesh_posture(c).confirmed:
                continue
        except Exception:
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"mesh:{check_id}")
        _project_oracle_fact(
            world, subject, oracle_kind="mesh_posture", bug_class="mesh_misconfiguration",
            evidence=f"mesh {c.get('resource_kind')} '{check_id}' re-derives a concrete insecure achieved state",
            seq=seq, detail={"check_id": check_id, "resource_kind": str(c.get("resource_kind") or "")})
        promoted += 1
    return promoted


def _reverify_email_auth(world: Any, res: Any, *, seq: int) -> int:
    """Email-auth promotion (FORGE Domain 10): the email-auth-posture oracle over each RETAINED DNS policy
    control. A control whose PUBLISHED policy re-derives a concrete spoofing weakness (no DMARC anywhere in
    the RFC 7489 §6.6.3 chain, ``p=none``, or SPF ``+all``) is promoted to an oracle-grounded FACT on its
    CONTROL node; a hardened domain (``p=reject``/``sp=reject``/``-all``) is left an honest LEAD. NO DNS is
    queried, NO mail is sent — a pure re-derivation over the operator's retained records. Mirrors
    :func:`_reverify_mesh`; the lead and its FACT share the ``email:<check_id>`` node (lowercased, exactly as
    ``sensors.email_auth.email_auth_observations`` keys it)."""
    try:
        from .verify.email_auth import confirm_email_auth_posture
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    controls = output.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            if not confirm_email_auth_posture(c).confirmed:
                continue
        except Exception:
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"email:{check_id}".lower())
        _project_oracle_fact(
            world, subject, oracle_kind="email_auth_posture", bug_class="email_auth_misconfiguration",
            evidence=(f"the published email-auth policy for '{c.get('domain')}' ({c.get('rule')}) "
                      "re-derives a concrete spoofing weakness"),
            seq=seq, detail={"check_id": check_id, "rule": str(c.get("rule") or ""),
                             "domain": str(c.get("domain") or "")})
        promoted += 1
    return promoted


def _reverify_identity(world: Any, res: Any, *, seq: int) -> int:
    """Identity promotion (FORGE Domain 7): the identity-posture oracle over each RETAINED IdP-export
    control. A control whose STRICT-TYPED fields re-derive a concrete weakness (a privileged identity with
    MFA provably off, or a credential past its rotation policy) is promoted to an oracle-grounded FACT on its
    CONTROL node; a compliant identity is left an honest LEAD. NO IdP is queried, NO authentication is
    attempted — a pure re-derivation over the operator's retained export. Mirrors :func:`_reverify_email_auth`;
    the lead and its FACT share the ``identity:<check_id>`` node (lowercased, exactly as
    ``sensors.identity.identity_observations`` keys it)."""
    try:
        from .verify.identity_posture import confirm_identity_posture
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    controls = output.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            if not confirm_identity_posture(c).confirmed:
                continue
        except Exception:
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"identity:{check_id}".lower())
        _project_oracle_fact(
            world, subject, oracle_kind="identity_posture", bug_class="identity_misconfiguration",
            evidence=(f"the retained identity control for '{c.get('subject')}' ({c.get('rule')}) "
                      "re-derives a concrete identity-posture weakness"),
            seq=seq, detail={"check_id": check_id, "rule": str(c.get("rule") or ""),
                             "subject": str(c.get("subject") or "")})
        promoted += 1
    return promoted


def _reverify_mobile(world: Any, res: Any, *, seq: int) -> int:
    """Mobile promotion: the mobile-posture oracle over each RETAINED MobSF control. A control the oracle
    RE-DERIVES a concrete weakness for (this slice: an embedded PEM private key that loads as an
    unencrypted key) is promoted to an oracle-grounded FACT on its CONTROL node; anything the oracle
    cannot re-confirm (a lead-only rule, an encrypted/masked/unparseable key) is left an honest LEAD.
    Mirrors :func:`_reverify_cicd`; the sensor output nests the controls under ``parsed``."""
    try:
        from .verify.mobile_posture import confirm_mobile_posture
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    parsed = output.get("parsed")
    if not isinstance(parsed, dict):
        return 0
    # the sensor mints NO lead (mobsf_observations short-circuits) when the report has no app identity;
    # mirror that guard here so a fact is never promoted onto a control the sensor never minted as a lead.
    app = parsed.get("app") or {}
    app_key = (app.get("package") or app.get("name") or "").strip().lower()
    if not app_key:
        return 0
    controls = parsed.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            if not confirm_mobile_posture(c).confirmed:
                continue
        except Exception:
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"mobile:{check_id}")
        _project_oracle_fact(
            world, subject, oracle_kind="mobile_posture", bug_class="mobile_misconfiguration",
            evidence=f"mobile control '{c.get('rule')}' re-derives a concrete offline-provable weakness",
            seq=seq, detail={"check_id": check_id, "rule": str(c.get("rule") or "")})
        promoted += 1
    return promoted


def _reverify_crypto(world: Any, res: Any, *, seq: int) -> int:
    """Weak-crypto promotion: the weak-crypto-artifact oracle over each RETAINED certificate descriptor. A
    cert signed with a BROKEN hash (MD5/SHA-1 — collision-forgeable) is promoted to an oracle-grounded FACT
    on its CONTROL node; a modern SHA-256+ cert is left an honest LEAD. Mirrors :func:`_reverify_cicd`; the
    oracle re-derives from the retained signatureAlgorithm OID name (a pure re-verifiable classification)."""
    try:
        from .verify.weak_crypto import crypto_descriptor_verdict
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    controls = output.get("controls")
    if not isinstance(controls, list):
        return 0
    promoted = 0
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        try:
            ok, evidence, reason = crypto_descriptor_verdict(c)
        except Exception:
            continue
        if not ok:
            continue
        subject = EntityRef(kind=NodeKind.CONTROL, key=f"crypto:{check_id}")
        _project_oracle_fact(
            world, subject, oracle_kind="tls_weakness", bug_class="weak_crypto_artifact",
            evidence=evidence or "certificate carries a weak-crypto property",
            seq=seq, detail={"check_id": check_id, "reason": reason,
                             "signature_algorithm": str(c.get("signature_algorithm") or ""),
                             "key_bits": c.get("key_bits")})
        promoted += 1
    return promoted


def _reverify_cloud(world: Any, res: Any, *, seq: int) -> int:
    """3b promotion: TWO cloud oracles re-fire over the RETAINED export — NO live cloud calls. The
    EXISTING policy-path oracle re-derives each REACHABILITY-provable posture LEAD (public exposure /
    over-broad trust) over the retained policy graph; the cloud-posture oracle re-derives each
    ACHIEVED-STATE MISCONFIGURATION LEAD (encryption-at-rest disabled on a sensitive datastore — the lead
    the policy-path oracle STRUCTURALLY cannot prove) over the retained achieved state. Each confirmed
    weakness is projected as an oracle-grounded FACT on the SAME cloud-resource node the topology minter
    created; a benign/compliant control stays an honest LEAD."""
    try:
        import json as _json

        from .intel.from_cloud import _resource as _resource_ref
        from .sensors.cloud import confirm_cloud_posture_facts, normalize_cloud_export
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    text, fmt = output.get("export"), output.get("format", "auto")
    if not isinstance(text, str) or not text.strip():
        return 0
    try:
        inventory = normalize_cloud_export(_json.loads(text), fmt if isinstance(fmt, str) else "auto")
        facts = confirm_cloud_posture_facts(inventory)
    except Exception:
        return 0
    promoted = 0
    for f in facts:
        resource = str(f.get("resource") or "")
        if not resource:
            continue
        subject = _resource_ref(resource, str(f.get("resource_kind") or ""))
        _project_oracle_fact(
            world, subject, oracle_kind="policy_path", bug_class="privilege_path",
            evidence=(f"cloud {f.get('lead_class')} confirmed: principal {f.get('principal')!r} reaches "
                      f"resource {resource!r} via a real IAM grant path"),
            seq=seq, detail={"principal": f.get("principal"), "access": f.get("access") or None,
                             "lead_class": f.get("lead_class")})
        promoted += 1
    # The un-reachability-provable MISCONFIGURATION lead (encryption-at-rest disabled on a sensitive
    # datastore) — promoted over the RETAINED achieved state by the cloud-posture oracle, offline.
    promoted += _reverify_cloud_misconfig(world, inventory, seq=seq)
    return promoted


def _reverify_cloud_misconfig(world: Any, inventory: dict, *, seq: int) -> int:
    """cloud-posture oracle over each retained MISCONFIGURATION lead: a sensitive datastore with
    encryption-at-rest DISABLED — the exact ``cloud_posture_leads`` ``misconfiguration`` condition
    (``sensitive`` and ``encrypted is False``), the lead the policy-path oracle STRUCTURALLY cannot
    prove (no reachability path proves an at-rest-encryption gap). Mirrors that lead condition-for-
    condition so exactly the leads the sensor minted are re-verified here, then judges each with the
    deterministic ``confirm_cloud_posture`` seam (``FindingContext.from_cloud_control`` -> the
    ``cloud_posture_oracle``). On a FIRED signal the achieved-state weakness is projected as an
    oracle-grounded FACT on the SAME resource node the topology minter created; a compliant/unknown
    control is NOT confirmed (it stays an honest LEAD). Pure re-derivation over the already-parsed
    inventory — NO live cloud call. Best-effort + deterministic; idempotent (stable finding id)."""
    try:
        from .intel.from_cloud import _resource as _resource_ref
        from .verify.cloud_posture import confirm_cloud_posture
    except Exception:
        return 0
    promoted = 0
    seen: set = set()
    for r in inventory.get("resources", []) or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        # mirror cloud_posture_leads' `misconfiguration` lead condition exactly — only the leads the
        # sensor actually minted are re-verified (never a laundered live re-derivation).
        if not (bool(r.get("sensitive")) and r.get("encrypted") is False):
            continue
        rid = str(r["id"])
        if rid in seen:
            continue
        seen.add(rid)
        try:
            result = confirm_cloud_posture(r)            # the cloud-posture oracle must FIRE
        except Exception:
            continue
        # Promote ONLY when the ENCRYPTION-AT-REST rule specifically fired. The oracle also fires on
        # public_exposure / wildcard_principal, but those are promoted by the policy-path seam — so
        # accepting a bare `.confirmed` here would DOUBLE-count them AND mislabel a public/wildcard fact
        # as `encryption_at_rest_disabled` with a fabricated "encrypted=false, sensitive=true" achieved
        # state (the review's mislabel FP). Gate on the actual fired proof, not the aggregate verdict.
        if not (result.confirmed and any(
                getattr(s, "fired", False)
                and (getattr(s, "observed", None) or {}).get("rule") == "encryption_at_rest_disabled"
                for s in (result.signals or []))):
            continue
        subject = _resource_ref(rid, str(r.get("kind") or ""))
        _project_oracle_fact(
            world, subject, oracle_kind="cloud_posture", bug_class="cloud_misconfiguration",
            evidence=(f"cloud posture fact: sensitive resource {rid} has encryption-at-rest DISABLED "
                      f"(achieved state: encrypted=false, sensitive=true) — the un-reachability-provable "
                      f"misconfiguration lead, promoted over the retained achieved state"),
            seq=seq, detail={"resource_id": rid, "rule": "encryption_at_rest_disabled"})
        promoted += 1
    return promoted


def _reverify_reachability(world: Any, task: FusionTask, res: Any, *, seq: int, slug: str,
                           connect: Any = None) -> int:
    """3c promotion (OPT-IN, GATED, LIVE): confirm a declared_service 'open' LEAD with a REAL transport
    handshake. Fires ONLY when the task explicitly opts in (``args['confirm_reachable']`` truthy) AND the
    live connect passes the fail-closed gate (``verify.reachability.capture_handshake``: kill-switch ->
    single-host -> ACTIVE_RECON entitlement -> charter scope). A refused/failed handshake promotes
    NOTHING (the lead stays a lead). Never on the default/gate path — only under the opt-in fusion flag
    AND an explicit per-task opt-in. ``connect`` is injectable so the path is testable offline."""
    if not (isinstance(task.args, dict) and task.args.get("confirm_reachable")):
        return 0
    try:
        from .intel.from_scan import host_ref
        from .intel.refs import canonicalize
        from .verify.reachability import capture_handshake, confirm_reachable
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    host = output.get("host")
    services = output.get("services")
    if not isinstance(host, str) or not host or not isinstance(services, list):
        return 0
    host_key = host_ref(host).key
    promoted = 0
    for svc in services:
        if not isinstance(svc, dict) or svc.get("port") is None:
            continue
        if str(svc.get("state", "open")).lower() != "open":
            continue
        proto = str(svc.get("protocol") or "tcp").lower()
        try:
            port = int(svc["port"])
        except (TypeError, ValueError):
            continue
        try:
            hs = capture_handshake(host, port, slug=slug, protocol=proto, connect=connect)
            if not confirm_reachable(hs).confirmed:
                continue
        except Exception:
            continue
        subject = canonicalize(NodeKind.SERVICE, f"{host_key}:{port}/{proto}")
        _project_oracle_fact(
            world, subject, oracle_kind="service_reachability", bug_class="service_reachable",
            evidence=f"{proto} handshake reproduced to {host}:{port} — 'open' LEAD confirmed reachable",
            seq=seq, detail={"host": host, "port": port, "protocol": proto})
        promoted += 1
    return promoted


# Ports on which a TLS handshake is worth attempting when the operator opts in (a handshake to a non-TLS
# port just fails and promotes nothing — this only avoids blindly TLS-probing every open port).
_TLS_PORTS = frozenset({443, 465, 636, 989, 990, 993, 995, 4433, 5061, 8443, 8883})


def _reverify_tls_live(world: Any, task: FusionTask, res: Any, *, seq: int, slug: str,
                       connect: Any = None) -> int:
    """OPT-IN, GATED, LIVE TLS posture: for a declared_service 'open' TLS service, reproduce ONE real,
    fail-closed-gated TLS handshake (``verify.tls.capture_tls_handshake``: kill-switch -> single-host ->
    ACTIVE_RECON entitlement -> charter scope) and promote, over the SAME retained evidence, TWO already-
    built oracles: a weak negotiated PROTOCOL/CIPHER (``confirm_weak_tls``) AND a leaf certificate signed
    with a BROKEN hash (``confirm_crypto_descriptor`` over the captured cert). Fires ONLY when the task
    opts in (``args['confirm_tls']`` truthy) AND the gate passes; a refused/failed handshake promotes
    NOTHING. Never on the default/gate path. ``connect`` is injectable so the path is testable offline.
    Mirrors :func:`_reverify_reachability`."""
    if not (isinstance(task.args, dict) and task.args.get("confirm_tls")):
        return 0
    try:
        import base64
        from .intel.from_scan import host_ref
        from .intel.refs import canonicalize
        from .verify.tls import capture_tls_handshake, confirm_weak_tls
        from .verify.weak_crypto import crypto_descriptor_verdict, signature_descriptors
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    host = output.get("host")
    services = output.get("services")
    if not isinstance(host, str) or not host or not isinstance(services, list):
        return 0
    host_key = host_ref(host).key
    promoted = 0
    for svc in services:
        if not isinstance(svc, dict) or svc.get("port") is None:
            continue
        if str(svc.get("state", "open")).lower() != "open":
            continue
        try:
            port = int(svc["port"])
        except (TypeError, ValueError):
            continue
        # attempt TLS only where the operator flagged it, or on a well-known TLS port
        if not (svc.get("tls") or port in _TLS_PORTS):
            continue
        proto = str(svc.get("protocol") or "tcp").lower()
        try:
            hs = capture_tls_handshake(host, port, slug=slug, connect=connect)
        except Exception:
            continue
        if not hs.get("connected"):
            continue
        subject = canonicalize(NodeKind.SERVICE, f"{host_key}:{port}/{proto}")
        # (a) weak negotiated protocol/cipher
        try:
            if confirm_weak_tls(hs).confirmed:
                _project_oracle_fact(
                    world, subject, oracle_kind="tls_weakness", bug_class="weak_tls",
                    evidence=(f"{host}:{port} negotiated a weak TLS protocol/cipher "
                              f"({hs.get('tls_version')}/{hs.get('cipher')}) in a real gated handshake"),
                    seq=seq, detail={"host": host, "port": port,
                                     "tls_version": str(hs.get("tls_version") or ""),
                                     "cipher": str(hs.get("cipher") or "")})
                promoted += 1
        except Exception:
            pass
        # (b) leaf certificate with a weak-crypto property (a broken signature hash OR an undersized key) —
        # a DISTINCT oracle_kind label so the two facts do not collide on the shared finding-key
        # `{oracle_kind}:{subject}` (both are TLS_WEAKNESS-kind). The FACT is labelled with the oracle's OWN
        # per-reason evidence (broken hash vs short key), never a hardcoded string.
        cert_b64 = hs.get("cert_der_b64")
        if isinstance(cert_b64, str) and cert_b64:
            try:
                cert = base64.b64decode(cert_b64)
                for desc in signature_descriptors(cert):
                    ok, evidence, reason = crypto_descriptor_verdict(desc)
                    if ok:
                        _project_oracle_fact(
                            world, subject, oracle_kind="weak_crypto_artifact",
                            bug_class="weak_crypto_artifact",
                            evidence=f"{host}:{port} — {evidence}" if evidence else f"{host}:{port} presents a weak-crypto certificate",
                            seq=seq, detail={"host": host, "port": port, "reason": reason,
                                             "signature_algorithm": str(desc.get("signature_algorithm") or ""),
                                             "key_bits": desc.get("key_bits")})
                        promoted += 1
                        break
            except Exception:
                pass
    return promoted


# The provider aliases we can turn into an anonymous public-read URL (C3). An unknown/empty provider
# is fail-closed: we cannot infer the endpoint, so we do NOT probe (no fact).
_AWS_PROVIDERS = frozenset({"aws", "amazon", "amazon_web_services", "s3"})
_GCP_PROVIDERS = frozenset({"gcp", "gcs", "google", "google_cloud", "googlecloud"})
_AZURE_PROVIDERS = frozenset({"azure", "az", "microsoft", "azure_blob"})


def _exposure_url(provider: str, resource: str) -> str:
    """Construct the anonymous public-read URL for a confirmed-public resource, per provider (C3). The
    resource id is exactly what the cloud collectors emit: an S3/GCS bucket NAME, or ``<account>/
    <container>`` for Azure Blob. Pure/total: an unknown provider or a malformed id yields ``""`` (no
    probe, no fact) — fail-closed. NOTE: S3/Azure carry the bucket/account in the HOST (per-resource charter
    scoping); GCS path-style scopes only the shared ``storage.googleapis.com`` host — per-resource safety
    then rests on the export being the operator's own inventory + the opt-in flag (C3 red-pen LOW-2)."""
    from .verify.reachability_cloud import azure_blob_url, gcs_public_url, s3_public_url

    p = str(provider or "").strip().lower().replace("-", "_")
    r = str(resource or "").strip()
    if not r:
        return ""
    if p in _AWS_PROVIDERS:
        return s3_public_url(r)
    if p in _GCP_PROVIDERS:
        return gcs_public_url(r)
    if p in _AZURE_PROVIDERS:
        account, sep, container = r.partition("/")
        return azure_blob_url(account, container) if sep else ""
    return ""


def _reverify_active_exposure(world: Any, task: FusionTask, res: Any, *, seq: int, slug: str,
                              connect: Any = None) -> int:
    """C3 promotion (OPT-IN, GATED, LIVE, UNAUTHENTICATED): turn a cloud resource a POSTURE already
    re-derived as PUBLIC into a PROVEN anonymously-reachable FACT with ONE gated, credential-free HTTP
    GET. Fires ONLY when the task explicitly opts in (``args['confirm_exposure']`` truthy) AND the live
    GET passes the fail-closed gate (``verify.reachability_cloud.capture_anonymous_get``: kill-switch ->
    single-host -> ACTIVE_RECON entitlement -> charter scope on the URL host, no credentials). A refused/
    failed capture or any non-2xx (401/403/404/redirect) promotes NOTHING (the posture fact stays a
    posture fact). Never on the default/gate path — only under the opt-in fusion flag AND an explicit
    per-task opt-in. ``connect`` is injectable so the path is testable offline. Mirrors
    :func:`_reverify_reachability` / :func:`_reverify_tls_live`.

    The set of resources probed is EXACTLY the ORACLE-confirmed public ones: ``confirm_cloud_posture_facts``
    re-derives each anonymous grant path over the RETAINED export, and only its ``public_exposure`` facts
    are eligible — so the active GET only ever tests what the deterministic posture oracle already proved
    public over the operator's own evidence (posture-proven -> reachability-proven, never a raw guess)."""
    if not (isinstance(task.args, dict) and task.args.get("confirm_exposure")):
        return 0
    try:
        import json as _json

        from .intel.from_cloud import _resource as _resource_ref
        from .sensors.cloud import confirm_cloud_posture_facts, normalize_cloud_export
        from .verify.reachability_cloud import capture_anonymous_get, confirm_anonymous_reachable
    except Exception:
        return 0
    output = getattr(res.result, "output", None) or {}
    text, fmt = output.get("export"), output.get("format", "auto")
    if not isinstance(text, str) or not text.strip():
        return 0
    try:
        inventory = normalize_cloud_export(_json.loads(text), fmt if isinstance(fmt, str) else "auto")
        facts = confirm_cloud_posture_facts(inventory)
    except Exception:
        return 0
    provider = str(inventory.get("provider") or "").strip().lower()
    promoted = 0
    seen: set = set()
    for f in facts:
        if not isinstance(f, dict) or f.get("lead_class") != "public_exposure":
            continue
        resource = str(f.get("resource") or "")
        if not resource or resource in seen:
            continue
        seen.add(resource)
        url = _exposure_url(provider, resource)
        if not url:
            continue
        try:
            capture = capture_anonymous_get(url, slug=slug, connect=connect)
            if not confirm_anonymous_reachable(capture).confirmed:
                continue
        except Exception:
            continue
        subject = _resource_ref(resource, str(f.get("resource_kind") or ""))
        _project_oracle_fact(
            world, subject, oracle_kind="active_exposure", bug_class="anonymous_reachable",
            evidence=(f"unauthenticated HTTP GET to {url} returned HTTP {capture.get('status')} with a "
                      f"{capture.get('body_len')}-byte body — public {provider or 'cloud'} resource "
                      f"{resource!r} PROVEN anonymously reachable"),
            seq=seq, detail={"url": url, "status": capture.get("status"),
                             "body_len": capture.get("body_len"), "provider": provider or None,
                             "content_type": capture.get("content_type") or None})
        promoted += 1
    return promoted


def _reverify(world: Any, task: FusionTask, res: Any, *, seq: int, slug: str = "",
              connect: Any = None, tls_connect: Any = None, exposure_connect: Any = None) -> int:
    """Let the existing oracles re-fire over the sensor's OWN retained evidence, in-run — the LEAD ->
    FACT bridge. Each promotion is a deterministic oracle over the sensor's retained evidence; the
    sensor's LEADS are untouched. Returns the number of facts promoted. Best-effort and deterministic.
    A refused/failed sensor promotes nothing.

      * sbom_vuln       -> version-range oracle over SBOM advisories
      * kube_bench      -> k8s-posture oracle over each retained CIS control (3a)
      * k8s_live        -> the LIVE k8s-RBAC achieved-state oracle over each retained binding control
                           (an anonymous subject bound to a dangerous built-in role; C2·K8s)
      * cicd_workflows  -> CI/CD-posture oracle over each retained workflow control
      * mesh_config     -> mesh-posture oracle over each retained Istio/Linkerd control
      * email_auth      -> email-auth-posture oracle over each retained DNS policy control (Domain 10)
      * identity        -> identity-posture oracle over each retained IdP-export control (Domain 7)
      * mobsf_static    -> mobile-posture oracle over each retained MobSF control
      * android_manifest-> mobile-posture oracle over each retained AndroidManifest provider control
      * tls_cert        -> weak-crypto-artifact oracle over each retained certificate descriptor
      * cloud_import    -> policy-path oracle over each reachability-provable posture lead + cloud-posture
                           oracle over each achieved-state misconfiguration lead (3b)
      * cloud_live      -> the SAME two cloud oracles over the LIVE read-only pull's retained export (C2:
                           gated ACTIVE_RECON + egress; ambient creds; no new promotion path)
      * gcp_live        -> the SAME two cloud oracles over the LIVE GCP pull (provider-agnostic; a public
                           GCS bucket / project-IAM binding promotes exactly as AWS does)
      * azure_live      -> the SAME two cloud oracles over the LIVE Azure pull (a public blob container —
                           container publicAccess + account allowBlobPublicAccess + network internet-open
                           three-scope — promotes as AWS)
      * declared_service-> service-reachability oracle over a GATED, OPT-IN live handshake (3c), PLUS the
                           weak-TLS + weak-crypto oracles over a GATED, OPT-IN live TLS handshake
    """
    if not getattr(res, "ok", False):
        return 0
    if task.sensor == "sbom_vuln":
        return _reverify_sbom(world, res, seq=seq)
    if task.sensor == "kube_bench":
        return _reverify_k8s(world, res, seq=seq)
    if task.sensor == "k8s_live":
        return _reverify_k8s_live(world, res, seq=seq)
    if task.sensor == "cicd_workflows":
        return _reverify_cicd(world, res, seq=seq)
    if task.sensor == "mesh_config":
        return _reverify_mesh(world, res, seq=seq)
    if task.sensor == "email_auth":
        return _reverify_email_auth(world, res, seq=seq)
    if task.sensor == "identity":
        return _reverify_identity(world, res, seq=seq)
    if task.sensor in ("mobsf_static", "android_manifest"):
        return _reverify_mobile(world, res, seq=seq)
    if task.sensor == "tls_cert":
        return _reverify_crypto(world, res, seq=seq)
    if task.sensor in ("cloud_import", "cloud_live", "gcp_live", "azure_live"):
        n = _reverify_cloud(world, res, seq=seq)
        # C3: PLUS an OPT-IN, GATED, UNAUTHENTICATED live GET that proves a confirmed-public resource is
        # anonymously reachable (fires only under args['confirm_exposure'] AND the fail-closed gate).
        n += _reverify_active_exposure(world, task, res, seq=seq, slug=slug, connect=exposure_connect)
        return n
    if task.sensor == "declared_service":
        n = _reverify_reachability(world, task, res, seq=seq, slug=slug, connect=connect)
        n += _reverify_tls_live(world, task, res, seq=seq, slug=slug, connect=tls_connect)
        return n
    return 0


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
    # Injectable connectors for the OPT-IN, GATED live handshakes — None => the real bounded socket
    # connect (still fail-closed inside capture_handshake / capture_tls_handshake). Tests pass a fake.
    reach_connect = getattr(ctx, "reach_connect", None)
    tls_connect = getattr(ctx, "tls_connect", None)
    exposure_connect = getattr(ctx, "exposure_connect", None)   # C3 anonymous-GET connector (None => real)

    minted: list[Observation] = []
    for i, task in enumerate(tasks):
        seq = base + i
        try:
            res = run_sensor(registry, task.sensor, task.args, tool_ctx,
                             ingest=ingest, seq=seq, sink=sink)
        except Exception:
            continue   # a sensor blowing up never sinks the whole fusion pass
        minted.extend(res.observations)
        # LEAD -> FACT, where an oracle re-fires over the sensor's OWN retained evidence.
        _reverify(world, task, res, seq=seq, slug=slug or "", connect=reach_connect,
                  tls_connect=tls_connect, exposure_connect=exposure_connect)
    return minted
