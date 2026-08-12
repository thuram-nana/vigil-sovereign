"""
scanner.orchestrator — the self-directed autonomous engagement.

The scanner is the hands; ``worldmodel`` is the head's memory; ``knowledge`` holds
the moves. This ties them together so a run does not stop at a list of findings —
it *reasons forward* from them, and reports the multi-hop ATTACK PATHS that the
confirmed facts unlock, not just isolated escalations.

:class:`AutonomousCampaign` runs the loop:

  1. crawl + scan (the oracle-anchored WebScanCampaign),
  2. write each oracle-confirmed finding into a world-model attack graph and
     establish the topology + precondition it implies — an SSRF endpoint
     ``fetches_url`` and the attacker has REACHED it; an IDOR endpoint has broken
     ``auth`` and fronts a DATASTORE; a deserialization endpoint runs on a HOST —
  3. seed the internal resources a real engagement pivots toward, and the attacker
     principal,
  4. run the technique operators to a fixpoint (``knowledge.saturate``) so every
     chain the confirmed facts unlock is derived, and
  5. search the resulting graph for paths from the attacker to crown-jewel nodes
     (``worldmodel.pathsearch``) — the ranked, technique-annotated attack paths.

Every raw finding stays oracle-confirmed; the paths are sound derivations over
those confirmed facts, each hop carrying the technique that produced it.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..knowledge import CATALOG, EXTENDED_CATALOG, saturate
from ..worldmodel.attacker import ATTACKER_ID, AttackerState
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind
from ..worldmodel.pathsearch import best_paths
from .campaign import ScanReport, WebScanCampaign, populate_worldmodel
from .checks import DEFAULT_CHECKS, Check, Send
from .detection_cost import path_detection_cost
from .insertion import InsertionKind
from .quantum_era import anneal_path_portfolio

DEFAULT_INTERNAL_RESOURCES: tuple[tuple[str, dict[str, object]], ...] = (
    ("internal:cloud-metadata", {"internal": True, "detail": "169.254.169.254 instance metadata"}),
    ("internal:admin-host", {"internal": True, "detail": "internal admin service"}),
)

# crown-jewel node kinds an attack path aims for.
_CROWN_KINDS = (NodeKind.CLOUD_RESOURCE, NodeKind.DATASTORE, NodeKind.HOST)

# edge kinds an attacker can traverse when we search for a path.
_TRAVERSABLE = (
    EdgeKind.REACHED, EdgeKind.REACHABLE_FROM, EdgeKind.CAN_ASSUME, EdgeKind.HAS_GRANT,
    EdgeKind.SESSION_ON, EdgeKind.OWNS, EdgeKind.AUTHENTICATES_TO, EdgeKind.TRUSTS_FOR,
    EdgeKind.VALID_ON,
)

# operator ids that must be seeded with the attacker as their acting principal
# (base catalog + the extended catalog's attacker-acting operators). saturate
# RAISES if a seed-requiring operator matches without its seed, so every such
# operator whose preconditions the graph can satisfy must be listed.
_ACTOR_SEEDED = (
    "credential-reuse", "token-replay", "deserialization-to-code-exec",
    "credential-leak-capture", "datastore-secret-extraction", "token-leak-capture",
)


@dataclass
class ChainedConclusion:
    src: str
    edge: str
    dst: str
    technique: str

    def describe(self) -> str:
        return f"{self.src} --{self.edge}--> {self.dst}  (via {self.technique})"


@dataclass
class AttackPath:
    """A multi-hop route from the attacker to a crown-jewel node, each hop tagged
    with the technique (operator) that established it, or the finding for observed
    hops."""

    steps: list[ChainedConclusion]
    detection_cost: float = 0.0  # 0 = stealthy, 1 = loud (DEL telemetry accounting)
    value: float = 1.0           # reaching one crown jewel = 1 unit (portfolio value)

    @property
    def destination(self) -> str:
        return self.steps[-1].dst if self.steps else ""

    @property
    def hops(self) -> int:
        return len(self.steps)

    def describe(self) -> str:
        chain = " -> ".join([self.steps[0].src, *[s.dst for s in self.steps]]) if self.steps else ""
        techs = ", ".join(dict.fromkeys(s.technique for s in self.steps))
        return f"{chain}   [{techs}]"


@dataclass
class AutonomousResult:
    scan_report: ScanReport
    chained_conclusions: list[ChainedConclusion] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    # the quantum-inspired optimizer's pick: the most valuable set of paths whose
    # total detection cost fits the budget — the stealthiest way to the crown jewels.
    path_portfolio: list[AttackPath] = field(default_factory=list)
    world: WorldModel | None = None

    @property
    def confirmed_findings(self) -> int:
        return len(self.scan_report.active_findings)


class AutonomousCampaign:
    """Self-directed engagement: crawl → scan → chain → attack paths."""

    def __init__(
        self,
        send: Send,
        *,
        checks: tuple[Check, ...] = DEFAULT_CHECKS,
        insertion_kinds: tuple[InsertionKind, ...] | None = None,
        internal_resources: tuple[tuple[str, dict[str, object]], ...] = DEFAULT_INTERNAL_RESOURCES,
        max_pages: int = 100,
        max_depth: int = 6,
        max_audit_requests: int = 0,
        detection_budget: float = 2.0,
        impact_model: object | None = None,
    ) -> None:
        from ..worldmodel.impact import ImpactModel
        self._send = send
        self.detection_budget = detection_budget
        # Business-impact model — mission-aware path/portfolio value. Uniform by default
        # (every crown jewel worth 1.0), so the default behaviour is byte-identical.
        self.impact_model = impact_model or ImpactModel.uniform()
        self.checks = checks
        self.insertion_kinds = insertion_kinds
        self.internal_resources = internal_resources
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_audit_requests = max_audit_requests

    def run(self, seed_url: str) -> AutonomousResult:
        report = WebScanCampaign(
            self._send, checks=self.checks, insertion_kinds=self.insertion_kinds,
            enable_oob=True, targeted=True, max_pages=self.max_pages,
            max_depth=self.max_depth, max_audit_requests=self.max_audit_requests,
        ).run(seed_url)
        return self.chain_findings(report)

    def chain_findings(
        self, report: ScanReport, *,
        world: WorldModel | None = None, seq_base: int = 1, verify: bool = False,
    ) -> AutonomousResult:
        """Turn a scan report into an attack graph, chain the operators over the
        confirmed facts, and extract the attacker→crown-jewel paths. Split out from
        :meth:`run` so the reasoning is testable without a live scan.

        ``world`` lets the caller pass a PRE-POPULATED graph — e.g. one an intel recon
        pass already projected assets onto — so findings accrete onto the SAME
        substrate rather than a fresh graph (attack-tier ids ``endpoint:*``/``finding:*``
        are disjoint from intel-tier ids ``domain:*``/``host:*``, so they coexist).
        ``seq_base`` is where finding projection starts on the monotonic clock; a caller
        that already spent seqs ``0..N`` on recon passes ``N+1`` so the clock never
        inverts. Defaults (``None``/``1``) reproduce the standalone behaviour exactly.

        ``verify`` (TRUTHENOVATION T1 — the veracity choke point for STORED projections).
        This method is PURE reasoning over the findings it is given; by default it trusts
        them (correct for a LIVE scan, whose findings just fired, and for unit tests that
        feed synthetic facts). A caller that re-projects a STORED, possibly-stale report —
        the console ``/api/worldmodel/<run_id>`` handler rebuilding from a saved
        ``reverifiable.json`` — passes ``verify=True`` to RE-EXECUTE each finding's retained
        proof and grant an attacker capability (the ``finding:``-provenance reach edge, the
        topology nodes/edges, and the attack paths they feed) ONLY to a finding that
        RE-FIRES NOW. A recorded-``confirmed`` finding whose proof no longer reproduces then
        grants NOTHING — so the attack graph can never render a grounded reach/topology/path
        built on an unproven finding (the demoted finding is still recorded, as an
        UNGROUNDED node, by ``populate_worldmodel``). Verification is a boundary concern, so
        it lives here as an opt-in rather than in the pure reasoning core."""
        world = world if world is not None else WorldModel()
        populate_worldmodel(report, world, seq=seq_base)
        seq = _Seq(seq_base + 1)

        attacker = AttackerState(world)
        attacker.ensure(seq=seq.next())

        for res_id, attrs in self.internal_resources:
            world.add_node(Node(id=res_id, kind=NodeKind.CLOUD_RESOURCE, attrs=dict(attrs),
                                provenance="orchestrator:seed", confidence=1.0,
                                first_seen=seq.peek(), last_seen=seq.next()))

        for f in report.active_findings:
            ep_id = f"endpoint:{f.param}"
            if world.get_node(ep_id) is None:
                continue
            # T1 veracity choke point for STORED projections: when re-projecting a possibly-stale
            # report (``verify=True``, set by the console /api/worldmodel handler), an attacker
            # CAPABILITY grounded on a finding — the `finding:`-provenance reach edge, the topology
            # nodes/edges, and the attack paths they feed — is minted ONLY if the finding's retained
            # proof RE-FIRES NOW (the same admit() gate populate_worldmodel + the dossier use). A
            # recorded-confirmed finding whose proof no longer reproduces grants the attacker NOTHING
            # (its derivatives are skipped; the demoted finding is still recorded as an UNGROUNDED
            # node by populate_worldmodel). Default ``verify=False`` = pure reasoning over given facts
            # (a LIVE scan's findings just fired; unit tests feed synthetic facts).
            if verify and not _finding_refires(f):
                continue
            # the attacker has reached this confirmed-vulnerable surface
            attacker.reach(ep_id, seq=seq.next(), provenance=f"finding:{f.bug_class}", confidence=f.confidence)
            self._establish_topology(world, ep_id, f.bug_class, f.confidence, seq)
            if f.bug_class == "imds_credential_capture":
                # E1 achieved effect: a confirmed metadata credential capture — the attacker HOLDS a valid
                # cloud credential, which chains (OWN_VIA_HELD_CREDENTIAL) to account takeover.
                self._establish_imds_capture(world, attacker, ep_id, f.confidence, seq)
            if f.bug_class == "secret_credential_validity":
                # E5 achieved effect: an exposed secret proven VALID — the attacker HOLDS a confirmed-valid
                # leaked credential, which chains (OWN_VIA_HELD_CREDENTIAL) to account takeover.
                self._establish_secret_validity(world, attacker, ep_id, f.confidence, seq)
            if f.bug_class == "gcp_sa_impersonation":
                # E3 achieved effect: a minted impersonation token proven VALID as the target SA — the
                # attacker HOLDS a confirmed-valid token that is VALID_ON the target principal B, which chains
                # (OWN_VIA_HELD_CREDENTIAL) to ownership of B.
                self._establish_gcp_impersonation(world, attacker, ep_id, f.confidence, seq)
            if f.bug_class == "k8s_workload_misconfiguration":
                # E4 achieved effect: a confirmed anonymous-privileged RBAC binding — an UNAUTHENTICATED
                # subject is bound to cluster-admin, so merely REACHING the kube-apiserver hands over the
                # cluster control-plane and, through it, every secret (no credential held — see the method).
                self._establish_k8s_rbac_capture(world, ep_id, f.confidence, seq)
            if f.bug_class == "iam_escalation_primitive":
                # E2 achieved effect: the retained IAM config PERMITS the base principal an unconditional
                # strict-gain escalation primitive. A credential MINTED for the target (create_access_key)
                # uses the HELD-credential chain; a role/permission gain uses HAS_GRANT + OWNS over the
                # escalated resource (see the method — the primitive family is read from the finding).
                self._establish_iam_escalation(world, attacker, ep_id, f, seq)

        # passive findings feed chains too: a disclosed private key IS a credential
        # the attacker can capture, which the extended operators turn into account
        # takeover / a grant over a crown jewel.
        for pf in report.passive_findings:
            if pf.check_id == "info-private-key":
                self._establish_credential_exposure(world, pf.url, seq)

        # chain: run the base + extended technique operators over the confirmed
        # facts to a fixpoint. role-assumption grants over a caller-supplied crown
        # jewel; seed it with an internal resource so it can fire without raising.
        seeds: dict[str, dict[str, str]] = {op_id: {"actor": ATTACKER_ID} for op_id in _ACTOR_SEEDED}
        if self.internal_resources:
            seeds["role-assumption"] = {"resource": self.internal_resources[0][0]}
        saturate([*CATALOG, *EXTENDED_CATALOG], world, seq_start=seq.next(), seeds=seeds)

        conclusions = [
            ChainedConclusion(src=e.src, edge=e.kind.value, dst=e.dst,
                              technique=str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])))
            for e in world.all_edges() if e.provenance.startswith("operator:")
        ]

        paths = self._extract_paths(world)
        # pick the most valuable path set within the detection budget (exact 0/1
        # knapsack over the path portfolio).
        portfolio: list[AttackPath] = []
        if paths:
            sel = anneal_path_portfolio(paths, budget=self.detection_budget, rng=random.Random(0))
            portfolio = list(sel.chosen)
        return AutonomousResult(scan_report=report, chained_conclusions=conclusions,
                                attack_paths=paths, path_portfolio=portfolio, world=world)

    # -- topology per finding class ---------------------------------------

    def _establish_topology(self, world: WorldModel, ep_id: str, bug_class: str, conf: float, seq: "_Seq") -> None:
        prov = f"finding:{bug_class}"
        if bug_class == "ssrf":
            _set_attr(world, ep_id, {"fetches_url": True}, prov, conf, seq)
        elif bug_class in ("idor", "bola", "broken_access_control"):
            _set_attr(world, ep_id, {"auth": False}, prov, conf, seq)
            ds = f"datastore:{ep_id}"
            world.add_node(Node(id=ds, kind=NodeKind.DATASTORE, attrs={"detail": "backing store"},
                                provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
            _edge(world, ep_id, ds, EdgeKind.TRUSTS_FOR, prov, conf, seq)
        elif bug_class == "deserialization":
            _set_attr(world, ep_id, {"deserializes_untrusted": True}, prov, conf, seq)
            host = f"host:{ep_id}"
            world.add_node(Node(id=host, kind=NodeKind.HOST, attrs={"detail": "service host"},
                                provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
            # the operator wants an incoming REACHABLE_FROM(host -> endpoint)
            _edge(world, host, ep_id, EdgeKind.REACHABLE_FROM, prov, conf, seq)

    def _establish_credential_exposure(self, world: WorldModel, url: str, seq: "_Seq") -> None:
        """A disclosed credential valid on a principal — the topology the
        credential-leak-capture → role-assumption chain consumes."""
        slug = ("".join(c for c in url if c.isalnum())[-16:]) or "x"
        cred, principal = f"credential:leaked:{slug}", f"principal:leaked:{slug}"
        prov = "finding:info-private-key"
        world.add_node(Node(id=cred, kind=NodeKind.CREDENTIAL, attrs={"exposed": True},
                            provenance=prov, confidence=0.9, first_seen=seq.peek(), last_seen=seq.next()))
        world.add_node(Node(id=principal, kind=NodeKind.PRINCIPAL, attrs={},
                            provenance=prov, confidence=0.9, first_seen=seq.peek(), last_seen=seq.next()))
        _edge(world, cred, principal, EdgeKind.VALID_ON, prov, 0.9, seq)

    def _establish_imds_capture(self, world: WorldModel, attacker: "AttackerState", ep_id: str,
                                conf: float, seq: "_Seq") -> None:
        """A confirmed IMDS/metadata credential capture (E1 achieved effect): the attacker HOLDS a cloud
        credential proven valid by a confirming call. Mint the credential + its principal + a VALID_ON edge
        and record the attacker's HOLD, so the graph chains via OWN_VIA_HELD_CREDENTIAL (HOLDS(cred) +
        VALID_ON(cred->principal) => OWNS(principal)) to account takeover — the same achieved-effect topology
        the leaked-key capture chain consumes, but seeded by a confirmed live capture rather than a leak."""
        prov = "finding:imds_credential_capture"
        cred, principal = f"credential:imds:{ep_id}", f"principal:imds:{ep_id}"
        world.add_node(Node(id=cred, kind=NodeKind.CREDENTIAL,
                            attrs={"source": "instance-metadata", "confirmed": True},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        world.add_node(Node(id=principal, kind=NodeKind.PRINCIPAL, attrs={},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        _edge(world, cred, principal, EdgeKind.VALID_ON, prov, conf, seq)
        attacker.hold(cred, seq=seq.next(), provenance=prov, confidence=conf)

    def _establish_secret_validity(self, world: WorldModel, attacker: "AttackerState", ep_id: str,
                                   conf: float, seq: "_Seq") -> None:
        """A confirmed exposed-secret VALIDITY (E5 achieved effect): the attacker HOLDS a leaked credential
        proven VALID by a confirming call. Mint the credential + its principal + a VALID_ON edge and record
        the attacker's HOLD, so the graph chains via OWN_VIA_HELD_CREDENTIAL (HOLDS(cred) +
        VALID_ON(cred->principal) => OWNS(principal)) to account takeover — the same achieved-effect topology
        as an IMDS capture, seeded by a confirmed-valid leaked secret rather than a metadata credential."""
        prov = "finding:secret_credential_validity"
        cred, principal = f"credential:secret:{ep_id}", f"principal:secret:{ep_id}"
        world.add_node(Node(id=cred, kind=NodeKind.CREDENTIAL,
                            attrs={"source": "exposed-secret", "confirmed": True},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        world.add_node(Node(id=principal, kind=NodeKind.PRINCIPAL, attrs={},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        _edge(world, cred, principal, EdgeKind.VALID_ON, prov, conf, seq)
        attacker.hold(cred, seq=seq.next(), provenance=prov, confidence=conf)

    def _establish_gcp_impersonation(self, world: WorldModel, attacker: "AttackerState", ep_id: str,
                                     conf: float, seq: "_Seq") -> None:
        """A confirmed GCP service-account impersonation (E3 achieved effect): the attacker HOLDS a minted
        short-lived token proven VALID as the target service-account B by a confirming identity echo. Mint the
        credential + its principal (B) + a VALID_ON edge and record the attacker's HOLD, so the graph chains
        via OWN_VIA_HELD_CREDENTIAL (HOLDS(cred) + VALID_ON(cred->principal) => OWNS(principal)) to ownership
        of B — the same achieved-effect topology as an IMDS/secret capture, seeded by a confirmed impersonation
        token rather than a metadata credential or a leaked secret."""
        prov = "finding:gcp_sa_impersonation"
        cred, principal = f"credential:gcp-impersonation:{ep_id}", f"principal:gcp-impersonation:{ep_id}"
        world.add_node(Node(id=cred, kind=NodeKind.CREDENTIAL,
                            attrs={"source": "gcp-impersonation", "confirmed": True},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        world.add_node(Node(id=principal, kind=NodeKind.PRINCIPAL, attrs={},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        _edge(world, cred, principal, EdgeKind.VALID_ON, prov, conf, seq)
        attacker.hold(cred, seq=seq.next(), provenance=prov, confidence=conf)

    def _establish_k8s_rbac_capture(self, world: WorldModel, ep_id: str, conf: float, seq: "_Seq") -> None:
        """A confirmed anonymous-privileged K8s-RBAC binding (E4 achieved effect): system:anonymous /
        system:unauthenticated is bound to a dangerous BUILT-IN ClusterRole (cluster-admin / admin / edit).
        Unlike an IMDS/secret capture, NO credential is HELD — the binding grants privilege to an
        UNAUTHENTICATED subject, so an attacker who merely REACHES the kube-apiserver (ep_id, already reached
        above) IS cluster-admin. Mint the cluster control-plane (a crown CLOUD_RESOURCE) + the secret store
        (a crown DATASTORE) and TRUSTS_FOR edges ep->cluster->secrets, so best_paths yields the crown-jewel
        route the achieved effect proves — the idor/bola datastore topology (reaching the surface hands over
        the resource behind it), NOT the credential-HOLD chain of E1/E5."""
        prov = "finding:k8s_workload_misconfiguration"
        cluster, secrets = f"cluster:{ep_id}", f"secrets:{ep_id}"
        world.add_node(Node(id=cluster, kind=NodeKind.CLOUD_RESOURCE,
                            attrs={"detail": "kube-apiserver control-plane", "anonymous_cluster_admin": True},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        world.add_node(Node(id=secrets, kind=NodeKind.DATASTORE, attrs={"detail": "cluster secret store"},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        # reaching the anonymous-bound API server IS cluster-admin (no credential); cluster-admin reads all secrets
        _edge(world, ep_id, cluster, EdgeKind.TRUSTS_FOR, prov, conf, seq)
        _edge(world, cluster, secrets, EdgeKind.TRUSTS_FOR, prov, conf, seq)

    def _establish_iam_escalation(self, world: WorldModel, attacker: "AttackerState", ep_id: str,
                                  finding: Any, seq: "_Seq") -> None:
        """A confirmed IAM privilege-escalation PRIMITIVE (E2 achieved effect): the RETAINED IAM config PERMITS
        the base principal (which the attacker reached at ep_id) an UNCONDITIONAL strict-gain escalation
        primitive. The projection branches on the primitive FAMILY (read from the finding's retained capture):

          * credential_mint (iam:CreateAccessKey / iam:CreateLoginProfile) — the attacker MINTS a credential
            FOR the escalated principal, so use the HELD-credential chain (mirrors _establish_secret_validity):
            CREDENTIAL + PRINCIPAL + VALID_ON + attacker.HOLDS(cred) => OWN_VIA_HELD_CREDENTIAL => OWNS.

          * grant_gain (trust-rewrite / PassRole / attach-policy / add-to-group) — the base principal GAINS a
            grant over / control of the escalated RESOURCE, so mint the base PRINCIPAL + the escalated
            CLOUD_RESOURCE, a HAS_GRANT(base->resource) strict-gain edge, and record the attacker's OWNS over
            the resource (reaching the escalation-capable base principal + the unconditional primitive = the
            achieved gain). A capture with no readable primitive falls back to grant_gain (the general case)."""
        from ..verify.oracles import _IAM_CREDENTIAL_MINT_PRIMITIVES  # authoritative primitive-family set

        conf = float(getattr(finding, "confidence", 0.9) or 0.9)
        octx = getattr(finding, "oracle_context", None) or {}
        cap = octx.get("iam_escalation_capture") if isinstance(octx, dict) else None
        esc = cap.get("escalation") if isinstance(cap, dict) and isinstance(cap.get("escalation"), dict) else {}
        primitive = str(esc.get("primitive", "") or "").strip().lower()
        prov = "finding:iam_escalation_primitive"

        # credential_mint family — a credential minted FOR the target (the HELD-credential chain).
        if primitive in _IAM_CREDENTIAL_MINT_PRIMITIVES:
            cred, principal = f"credential:iam-escalation:{ep_id}", f"principal:iam-escalation:{ep_id}"
            world.add_node(Node(id=cred, kind=NodeKind.CREDENTIAL,
                                attrs={"source": "iam-escalation-mint", "confirmed": True},
                                provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
            world.add_node(Node(id=principal, kind=NodeKind.PRINCIPAL, attrs={"escalated": True},
                                provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
            _edge(world, cred, principal, EdgeKind.VALID_ON, prov, conf, seq)
            attacker.hold(cred, seq=seq.next(), provenance=prov, confidence=conf)
            return

        # grant_gain family (or an unreadable primitive — the general case): a HAS_GRANT strict-gain edge over
        # the escalated resource, and the attacker OWNS it (reaching the base principal + the primitive = the
        # achieved gain).
        base, resource = f"principal:iam-esc-base:{ep_id}", f"resource:iam-esc-target:{ep_id}"
        world.add_node(Node(id=base, kind=NodeKind.PRINCIPAL, attrs={"escalation_capable": True},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        world.add_node(Node(id=resource, kind=NodeKind.CLOUD_RESOURCE, attrs={"escalated": True},
                            provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
        _edge(world, base, resource, EdgeKind.HAS_GRANT, prov, conf, seq)   # the strict-gain edge
        attacker.own(resource, seq=seq.next(), provenance=prov, confidence=conf)

    def _extract_paths(self, world: WorldModel) -> list[AttackPath]:
        if world.get_node(ATTACKER_ID) is None:
            return []
        paths: list[AttackPath] = []
        for p in best_paths(world, ATTACKER_ID, _CROWN_KINDS, k=8, edge_kinds=_TRAVERSABLE):
            steps = [
                ChainedConclusion(
                    src=e.src, edge=e.kind.value, dst=e.dst,
                    technique=str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])),
                )
                for e in p.edges
            ]
            if steps:
                cost = path_detection_cost([s.technique for s in steps])
                # business worth of THIS route = impact of the crown jewel it reaches
                # (feeds AttackPath.value → the portfolio optimiser's value_of).
                value = self.impact_model.impact_of(world.get_node(p.nodes[-1])) if p.nodes else 1.0
                paths.append(AttackPath(steps=steps, detection_cost=round(cost, 3),
                                        value=round(float(value), 4)))
        # stealthiest first — the DEL telemetry accounting lets the operator (or a
        # planner) prefer the least-detectable route to the same crown jewel.
        paths.sort(key=lambda ap: ap.detection_cost)
        return paths


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _Seq:
    """A tiny monotonic counter for the world-model's sequence ints."""

    def __init__(self, start: int) -> None:
        self._n = start

    def next(self) -> int:
        v = self._n
        self._n += 1
        return v

    def peek(self) -> int:
        return self._n


def _finding_refires(f: object) -> bool:
    """True IFF the active finding's retained ``oracle_context`` RE-FIRES NOW, graded through the
    shared veracity authority (``report.grounding.admit_for_report`` → ``veracity.admit`` →
    ``verify.reverify``) — the SAME gate ``populate_worldmodel`` and the dossier use (T1). A
    recorded-``confirmed`` finding whose proof no longer reproduces (tampered / relabelled /
    dry-run / absent) grades non-fact. Fail-closed: any error → False. Pure/read-only (oracle
    re-run over retained evidence, no traffic; memoized). Lazy import keeps it offense-side only
    (FATAL-2)."""
    try:
        from ..report.grounding import admit_for_report
        admitted = admit_for_report(f)
        return bool(admitted is not None and getattr(admitted, "is_fact", False))
    except Exception:
        return False


def _set_attr(world: WorldModel, node_id: str, attrs: dict[str, object], prov: str, conf: float, seq: "_Seq") -> None:
    node = world.get_node(node_id)
    if node is None:
        return
    world.add_node(Node(id=node_id, kind=node.kind, attrs=dict(attrs),
                        provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))


def _edge(world: WorldModel, src: str, dst: str, kind: EdgeKind, prov: str, conf: float, seq: "_Seq") -> None:
    world.add_edge(Edge(src=src, dst=dst, kind=kind, attrs={},
                        provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
