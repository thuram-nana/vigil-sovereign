"""
knowledge.catalog — a hand-authored seed of technique operators.

Six well-known techniques, spanning access, credential, identity, server-side,
and code-execution classes, each written as an abstract planning operator with
correct pre/post-conditions, intel refs (ATT&CK / CAPEC / CWE), detection
signals, and the verify oracle that would confirm it. These are NOT exploits —
each says *what must be true for the technique to apply here*, *what capability
it grants*, and *how a defender would see it*. No payloads.

The catalog is the join the gap analysis called out: ATT&CK gives loose prose,
this gives machine-checkable operators the path engine can chain. Two of these
(`credential-reuse` -> `role-assumption`) deliberately chain: the first asserts
a CAN_ASSUME edge that is the second's precondition, so forward-chaining
(operators.saturate) walks credential theft into cloud privilege the same way a
real operator would.

Look-ups:

    CATALOG                    -> tuple[Operator, ...]  (stable order)
    by_id(op_id)               -> Operator
    by_technique(ref)          -> list[Operator]        (any ATT&CK/CWE/CAPEC id)
"""

from __future__ import annotations

from ..verify.models import OracleKind
from ..worldmodel.models import EdgeKind, NodeKind
from .models import (
    AttrOp,
    Direction,
    Effect,
    EffectKind,
    Operator,
    Predicate,
    PredicateKind,
)

# ---------------------------------------------------------------------------
# 1. unauth-endpoint-read — IDOR / BOLA: a broken-object-authz endpoint that
#    fronts a datastore lets an attacker read records across the auth boundary.
# ---------------------------------------------------------------------------

UNAUTH_ENDPOINT_READ = Operator(
    id="unauth-endpoint-read",
    name="Unauthenticated object read (IDOR / BOLA)",
    technique_ref=["T1190", "CWE-639", "CWE-284", "CAPEC-1"],
    tactic="initial-access",
    description=(
        "An ENDPOINT that fronts a DATASTORE performs no (or broken) object-"
        "level authorization. Reaching it crosses the auth boundary and makes "
        "the backing datastore's records readable to the attacker."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.ENDPOINT,
                  note="the move is tried on an HTTP route"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="auth", op=AttrOp.FALSY,
                  note="no / broken object-level authz (auth=false or unset)"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.TRUSTS_FOR,
                  direction=Direction.OUT, other_kind=NodeKind.DATASTORE,
                  capture_as="store",
                  note="the endpoint queries a datastore (app-tier trust link)"),
    ],
    effects=[
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
               src_role="focus", dst_role="store", confidence=0.8,
               edge_attrs={"boundary": "object-authz"},
               note="datastore records become reachable through the broken endpoint"),
    ],
    detection_signals=[
        "200 OK for an object id the session does not own",
        "response body contains another tenant's / user's record",
        "sequential id enumeration returns distinct owners",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 2. credential-reuse — a recovered credential VALID_ON a principal lets the
#    acting attacker assume that principal (T1078 Valid Accounts).
# ---------------------------------------------------------------------------

CREDENTIAL_REUSE = Operator(
    id="credential-reuse",
    name="Credential reuse to account takeover",
    technique_ref=["T1078", "CWE-522", "CWE-287", "CAPEC-560"],
    tactic="credential-access",
    description=(
        "A CREDENTIAL the framework recovered is VALID_ON a PRINCIPAL. An "
        "attacker acting as some `actor` principal can present it and assume "
        "the target principal — the classic reused-secret account takeover."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.CREDENTIAL,
                  note="the move is tried on a recovered credential"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                  direction=Direction.OUT, other_kind=NodeKind.PRINCIPAL,
                  capture_as="principal",
                  note="the credential authenticates a principal"),
    ],
    effects=[
        # `actor` is caller-seeded: the identity the attacker already controls.
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
               src_role="actor", dst_role="principal", confidence=0.75,
               edge_attrs={"via": "reused-credential"},
               note="the actor can now assume the target principal"),
    ],
    detection_signals=[
        "identical password / key material across two accounts",
        "login success replaying a dumped credential",
        "auth log shows the same secret used from a new source",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 3. token-replay — an unbound SESSION token replayed authenticates the
#    attacker to the app it was minted for (T1550.001).
# ---------------------------------------------------------------------------

TOKEN_REPLAY = Operator(
    id="token-replay",
    name="Session/token replay",
    technique_ref=["T1550.001", "CWE-384", "CWE-613", "CAPEC-60"],
    tactic="lateral-movement",
    description=(
        "A SESSION token that is not bound to its client (no DPoP / mTLS / IP "
        "pinning) and has not expired can be replayed from anywhere, "
        "authenticating the actor to the webapp/host the session runs on."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.SESSION,
                  note="the move is tried on a captured session"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="client_bound", op=AttrOp.FALSY,
                  note="token not bound to the client -> replayable"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="expired", op=AttrOp.FALSY,
                  note="session still valid"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.SESSION_ON,
                  direction=Direction.OUT, other_kind=NodeKind.WEBAPP,
                  capture_as="app",
                  note="the session is established on a webapp"),
    ],
    effects=[
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.AUTHENTICATES_TO,
               src_role="actor", dst_role="app", confidence=0.7,
               edge_attrs={"via": "replayed-token"},
               note="replaying the token authenticates the actor to the app"),
    ],
    detection_signals=[
        "same bearer token accepted from a second IP / user-agent",
        "no token binding (DPoP / mTLS / cookie __Host- + SameSite)",
        "session cookie replay yields an authenticated response",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 4. ssrf-internal-reach — a URL-fetching endpoint reaches an internal-only
#    resource the attacker cannot address directly (CWE-918).
# ---------------------------------------------------------------------------

SSRF_INTERNAL_REACH = Operator(
    id="ssrf-internal-reach",
    name="SSRF to internal resource",
    technique_ref=["CWE-918", "CAPEC-664", "T1090"],
    tactic="discovery",
    description=(
        "An ENDPOINT fetches an attacker-supplied URL server-side with no "
        "egress allow-list. The server becomes a proxy into the internal "
        "network, making an internal-only CLOUD_RESOURCE (e.g. instance "
        "metadata) reachable through it."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.ENDPOINT,
                  note="the move is tried on an HTTP route"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="fetches_url", op=AttrOp.TRUTHY,
                  note="endpoint dereferences a user-controlled URL server-side"),
        Predicate(kind=PredicateKind.GRAPH_HAS_NODE, node_kind=NodeKind.CLOUD_RESOURCE,
                  attr="internal", op=AttrOp.TRUTHY, capture_as="internal",
                  note="an internal-only cloud resource exists to pivot to"),
    ],
    effects=[
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
               src_role="focus", dst_role="internal", confidence=0.7,
               edge_attrs={"pivot": "ssrf"},
               note="internal resource reachable via the server-side fetch"),
    ],
    detection_signals=[
        "server fetches an attacker-controlled URL",
        "response leaks 169.254.169.254 / metadata content",
        "internal-only host responds only via the proxy parameter",
        "out-of-band DNS/HTTP callback originating from the server IP",
    ],
    oracle_kind=OracleKind.OOB_CALLBACK,
)


# ---------------------------------------------------------------------------
# 5. role-assumption — a principal that CAN_ASSUME a role inherits that role's
#    grant over a resource (privilege escalation, T1548 / T1078.004).
# ---------------------------------------------------------------------------

ROLE_ASSUMPTION = Operator(
    id="role-assumption",
    name="Role assumption privilege inheritance",
    technique_ref=["T1548", "T1078.004", "CWE-269", "CAPEC-233"],
    tactic="privilege-escalation",
    description=(
        "A PRINCIPAL that can assume a role inherits that role's grants. If "
        "the assumable role HAS_GRANT over a resource, the principal gains the "
        "same grant — the step that turns a foothold identity into access to a "
        "crown-jewel resource."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.PRINCIPAL,
                  note="the move is tried on a principal the attacker controls"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
                  direction=Direction.OUT, other_kind=NodeKind.PRINCIPAL,
                  capture_as="role",
                  note="the principal can assume another principal/role"),
    ],
    effects=[
        # The grant target is caller-seeded (`resource`) — the resource the
        # assumable role already holds a grant over, resolved by the planner.
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.HAS_GRANT,
               src_role="focus", dst_role="resource", confidence=0.7,
               edge_attrs={"via": "assumed-role"},
               note="principal inherits the assumed role's grant over the resource"),
    ],
    detection_signals=[
        "principal can sts:AssumeRole a higher-privilege role",
        "wildcard iam:PassRole / trust policy with a broad Principal",
        "assumed role grants access to a crown-jewel resource",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 6. deserialization-to-code-exec — an endpoint that deserializes untrusted
#    input yields code execution on its host (CWE-502).
# ---------------------------------------------------------------------------

DESERIALIZATION_TO_CODE_EXEC = Operator(
    id="deserialization-to-code-exec",
    name="Insecure deserialization to code execution",
    technique_ref=["CWE-502", "T1059", "T1203", "CAPEC-586"],
    tactic="execution",
    description=(
        "An ENDPOINT deserializes untrusted input with a library that can "
        "instantiate arbitrary types (pickle / native-Java / YAML unsafe-load "
        "/ ObjectInputStream). A crafted object graph yields code execution on "
        "the HOST running the service, giving the attacker a foothold there."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.ENDPOINT,
                  note="the move is tried on an HTTP route"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="deserializes_untrusted",
                  op=AttrOp.TRUTHY,
                  note="endpoint deserializes attacker-controlled input"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
                  direction=Direction.IN, other_kind=NodeKind.HOST,
                  capture_as="host",
                  note="a host runs the service exposing this endpoint"),
    ],
    effects=[
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.SESSION_ON,
               src_role="actor", dst_role="host", confidence=0.7,
               edge_attrs={"via": "deserialization-rce"},
               note="code execution yields an interactive foothold on the host"),
        Effect(kind=EffectKind.SET_ATTR, target_role="host", attr="code_exec",
               value=True, confidence=0.7,
               note="mark the host as code-exec compromised"),
    ],
    detection_signals=[
        "serialized-object magic bytes in the body (\\xac\\xed / rO0AB / pickle opcodes)",
        "known gadget-chain class names in the request",
        "out-of-band callback triggered during deserialization",
        "unexpected child process / sanitizer traceback on the host",
    ],
    oracle_kind=OracleKind.OOB_CALLBACK,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CATALOG: tuple[Operator, ...] = (
    UNAUTH_ENDPOINT_READ,
    CREDENTIAL_REUSE,
    TOKEN_REPLAY,
    SSRF_INTERNAL_REACH,
    ROLE_ASSUMPTION,
    DESERIALIZATION_TO_CODE_EXEC,
)

_BY_ID = {op.id: op for op in CATALOG}


def by_id(op_id: str) -> Operator:
    """Look up a catalog operator by id. KeyError if absent (a typo in a
    planner wiring should fail loudly, not silently no-op)."""
    return _BY_ID[op_id]


def by_technique(ref: str) -> list[Operator]:
    """Every operator whose `technique_ref` contains `ref` (an ATT&CK / CWE /
    CAPEC id), in catalog order. Empty list if none match."""
    return [op for op in CATALOG if ref in op.technique_ref]
