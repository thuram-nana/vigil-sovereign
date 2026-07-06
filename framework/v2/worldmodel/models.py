"""
worldmodel.models — typed schemas for the attack-graph world-model.

The world-model is a directed, typed multigraph of everything the
framework has *observed or inferred* about a target: hosts, services,
web surface, datastores, cloud resources, identities, credentials,
sessions, controls, and findings — plus the trust and reachability
edges that connect them.

Two rules make this substrate load-bearing rather than decorative:

  1. Every fact carries **provenance** — the id of the event or
     observation that asserted it — and a **confidence** in [0, 1].
     A path through the graph is only as trustworthy as its least
     confident edge, and every edge can be traced back to what made
     the framework believe it. This is what makes an attack path
     *explainable* to the operator instead of an oracle's say-so.

  2. Time is a **monotonic sequence int**, never a wallclock. Callers
     pass a sequence number (their own event counter); the graph never
     reads the clock. This keeps merges, ordering, and tests fully
     deterministic and replayable.

Nothing here performs graph algorithms or persistence — these are pure,
validated data shapes. The graph lives in graph.py, queries in
query.py, persistence in store.py.
"""

from __future__ import annotations

import enum
import math

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _belief_sd(alpha: float, beta: float) -> float:
    """Standard deviation of a Beta(alpha, beta) belief."""
    s = alpha + beta
    return math.sqrt((alpha * beta) / (s * s * (s + 1.0)))


# ---------------------------------------------------------------------------
# Kinds
# ---------------------------------------------------------------------------


class NodeKind(str, enum.Enum):
    """What a node *is*. The set spans the surfaces a modern engagement
    touches — web, identity, and cloud — under one schema, because an
    attack path routinely crosses all three (an ENDPOINT leaks a
    CREDENTIAL that is VALID_ON a PRINCIPAL that CAN_ASSUME a
    CLOUD_RESOURCE that fronts a DATASTORE)."""

    HOST = "host"                       # a machine / instance
    SERVICE = "service"                 # a listening service (host:port/proto)
    ENDPOINT = "endpoint"               # one HTTP route / RPC method
    WEBAPP = "webapp"                   # a browser-facing application
    DATASTORE = "datastore"             # a database / bucket / secret store
    CLOUD_RESOURCE = "cloud_resource"   # an IAM-governed cloud object
    NETWORK_SEGMENT = "network_segment"  # a subnet / VPC / trust zone
    PRINCIPAL = "principal"             # a user / role / service account
    CREDENTIAL = "credential"           # a secret proving a principal
    SESSION = "session"                 # a live authenticated session
    CONTROL = "control"                 # a defensive control (WAF, auth, MFA)
    FINDING = "finding"                 # a confirmed vulnerability

    # Intelligence / asset-graph kinds (scanner.intel) — the recon substrate. An
    # Observation projects onto one of these with a Beta belief, exactly like the
    # attack kinds above; pathsearch scopes the two apart via `edge_kinds`.
    DOMAIN = "domain"                   # a DNS name (apex or sub)
    CERTIFICATE = "certificate"         # an X.509 leaf (by sha256 fingerprint)
    ASN = "asn"                         # an autonomous system (AS<n>)
    NETBLOCK = "netblock"               # an announced/allocated CIDR
    ORGANIZATION = "organization"       # an owning org / registrant
    IDENTITY = "identity"               # an OSINT persona/email (NOT a PRINCIPAL auth actor)
    APPLICATION = "application"         # a non-web application (NOT a WEBAPP)


class EdgeKind(str, enum.Enum):
    """What one node asserts about another. Directed: `src` -> `dst`.

    REACHABLE_FROM  dst is reachable *from* src (network / call reach).
    TRUSTS_FOR      src trusts dst for some purpose (attrs['purpose']).
    HAS_GRANT       src (principal) holds a grant over dst (resource).
    MEMBER_OF       src (principal) is a member of dst (group/role).
    CAN_ASSUME      src (principal) can assume dst (role/identity).
    VALID_ON        src (credential) authenticates on dst (principal).
    AUTHENTICATES_TO src (principal/session) authenticates to dst.
    SESSION_ON      src (session) is established on dst (host/webapp).
    CONTROL_PROTECTS src (control) protects dst (any node).
    EVIDENCES       src (finding) evidences a fact about dst.

    Attacker-state edges (an achieved postcondition of a confirmed primitive,
    src is the attacker principal — see worldmodel.attacker):
    OWNS            src (attacker) controls dst (host/service/resource/principal).
    HOLDS           src (attacker) holds dst (credential/session/token).
    REACHED         src (attacker) has reached dst (service/endpoint/segment).

    Intelligence / asset-graph edges (scanner.intel — recon substrate):
    RESOLVES_TO     src (domain) resolves to dst (host/ip).
    PRESENTS_CERT   src (host/service/domain) presents dst (certificate).
    ANNOUNCES       src (asn) announces dst (netblock).
    HOSTS           src (host/netblock) hosts dst (service/application).
    RUNS            src (host/service) runs dst (application/webapp).
    OBSERVED_ON     src (asset) was observed on dst (source/time context).
    ASSET_OWNS      src (org/asn/netblock) owns dst (asset). NOTE: deliberately
                    distinct from OWNS above — OWNS is an ATTACKER-state postcondition
                    and a derivation rule keyed on OWNS would hallucinate attacker
                    reachability from mere asset ownership.
    SAME_AS         src (asset-ref) is believed the same asset as dst (entity resolution).
    """

    REACHABLE_FROM = "reachable_from"
    TRUSTS_FOR = "trusts_for"
    HAS_GRANT = "has_grant"
    MEMBER_OF = "member_of"
    CAN_ASSUME = "can_assume"
    VALID_ON = "valid_on"
    AUTHENTICATES_TO = "authenticates_to"
    SESSION_ON = "session_on"
    CONTROL_PROTECTS = "control_protects"
    EVIDENCES = "evidences"
    OWNS = "owns"
    HOLDS = "holds"
    REACHED = "reached"
    # intelligence / asset-graph edges
    RESOLVES_TO = "resolves_to"
    PRESENTS_CERT = "presents_cert"
    ANNOUNCES = "announces"
    HOSTS = "hosts"
    RUNS = "runs"
    OBSERVED_ON = "observed_on"
    ASSET_OWNS = "asset_owns"
    SAME_AS = "same_as"


# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------


class Node(BaseModel):
    """One typed entity in the world-model.

    `id` is caller-assigned and stable — re-asserting the same id upserts
    (see graph.WorldModel.add_node). `attrs` is an open bag of observed
    properties (ip, port, url, arn, ...). `provenance` names the event /
    observation that asserted this node; `confidence` is the framework's
    belief in [0, 1]. `first_seen` / `last_seen` are monotonic sequence
    ints supplied by the caller — never wallclock timestamps."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, description="Stable caller-assigned node id.")
    kind: NodeKind
    attrs: dict[str, object] = Field(default_factory=dict)
    provenance: str = Field(
        min_length=1,
        description="Id of the event/observation that asserted this node.",
    )
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    # Beta(alpha, beta) belief accumulated from re-observations: alpha = 1 +
    # corroboration weight, beta = 1 + refutation weight. `confidence` stays the
    # asserted point estimate (reconciled by max); this is the richer signal that
    # DROPS when a fact is re-observed and fails (max never can). Default Beta(1,1)
    # is the uniform prior. Maintained by worldmodel.graph on upsert.
    alpha: float = Field(default=1.0, gt=0.0, description="Beta belief: 1 + corroboration weight.")
    beta: float = Field(default=1.0, gt=0.0, description="Beta belief: 1 + refutation weight.")
    first_seen: int = Field(ge=0, description="Monotonic sequence int, not wallclock.")
    last_seen: int = Field(ge=0, description="Monotonic sequence int, not wallclock.")

    @model_validator(mode="after")
    def _check_seen(self) -> "Node":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self

    @property
    def belief_mean(self) -> float:
        """Posterior mean of the Beta belief, alpha / (alpha + beta)."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def belief_sd(self) -> float:
        return _belief_sd(self.alpha, self.beta)

    def belief_lcb(self, z: float = 1.0) -> float:
        """Lower credible bound: belief_mean - z * sd, floored at 0. A high-mean
        but high-variance (thinly-evidenced) belief scores below a proven one."""
        return max(0.0, self.belief_mean - z * self.belief_sd)


class Edge(BaseModel):
    """One typed, directed relationship between two nodes.

    Identity is the triple (src, dst, kind): the same triple upserts and
    merges (see graph.WorldModel.add_edge), so parallel edges of the same
    kind between the same pair collapse to one reconciled fact. Different
    kinds between the same pair coexist (this is a multigraph)."""

    model_config = ConfigDict(extra="forbid")

    src: str = Field(min_length=1, description="Source node id.")
    dst: str = Field(min_length=1, description="Destination node id.")
    kind: EdgeKind
    attrs: dict[str, object] = Field(default_factory=dict)
    provenance: str = Field(
        min_length=1,
        description="Id of the event/observation that asserted this edge.",
    )
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    # Beta belief (see Node.alpha/beta) — the uncertainty-aware companion to the
    # scalar confidence, maintained by worldmodel.graph on upsert.
    alpha: float = Field(default=1.0, gt=0.0, description="Beta belief: 1 + corroboration weight.")
    beta: float = Field(default=1.0, gt=0.0, description="Beta belief: 1 + refutation weight.")
    first_seen: int = Field(ge=0, description="Monotonic sequence int, not wallclock.")
    last_seen: int = Field(ge=0, description="Monotonic sequence int, not wallclock.")

    @model_validator(mode="after")
    def _check_seen(self) -> "Edge":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self

    @property
    def belief_mean(self) -> float:
        """Posterior mean of the Beta belief, alpha / (alpha + beta)."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def belief_sd(self) -> float:
        return _belief_sd(self.alpha, self.beta)

    def belief_lcb(self, z: float = 1.0) -> float:
        """Lower credible bound: belief_mean - z * sd, floored at 0."""
        return max(0.0, self.belief_mean - z * self.belief_sd)

    @property
    def key(self) -> tuple[str, str, str]:
        """The identity triple (src, dst, kind-value) used for upsert."""
        return (self.src, self.dst, self.kind.value)


# ---------------------------------------------------------------------------
# Paths (query results)
# ---------------------------------------------------------------------------


class Path(BaseModel):
    """An enumerated simple path through the world-model: an ordered list
    of the edges traversed. `min_confidence` is the weakest link — the
    honest confidence of the whole path — and `provenance_chain` lets the
    operator audit every hop back to what asserted it."""

    model_config = ConfigDict(extra="forbid")

    edges: list[Edge] = Field(min_length=1)

    @property
    def nodes(self) -> list[str]:
        """Ordered node ids along the path: src of each edge, then final dst."""
        return [self.edges[0].src] + [e.dst for e in self.edges]

    @property
    def min_confidence(self) -> float:
        """Confidence of the weakest edge — the path is no stronger."""
        return min(e.confidence for e in self.edges)

    @property
    def provenance_chain(self) -> list[str]:
        """The provenance id of each hop, in order."""
        return [e.provenance for e in self.edges]

    @property
    def hops(self) -> int:
        return len(self.edges)

    @property
    def belief_mean(self) -> float:
        """The path's success belief: the product of its edges' belief means
        (independent-hop assumption). The uncertainty-aware analogue of
        min_confidence."""
        p = 1.0
        for e in self.edges:
            p *= e.belief_mean
        return p

    def belief_lcb(self, z: float = 1.0) -> float:
        """A conservative lower credible bound on the path's success belief — the
        product of the edges' lower bounds. A path of thinly-evidenced hops scores
        below one of equally-mean but proven hops."""
        p = 1.0
        for e in self.edges:
            p *= e.belief_lcb(z)
        return p
