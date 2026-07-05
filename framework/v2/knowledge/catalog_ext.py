"""
knowledge.catalog_ext — extended technique operators that deepen the chains.

The six seed operators in :mod:`knowledge.catalog` establish the *first* boundary
crossing of each class (broken authz, credential reuse, token replay, SSRF,
role assumption, deserialization RCE). This module adds six operators that pick
those effects up as *preconditions* and drive them one or two hops further —
turning a single confirmed primitive into a modelled multi-hop escalation the
path engine can walk to a crown jewel:

    unauth-endpoint-read ─▶ datastore-secret-extraction
        (REACHABLE_FROM ep→store)   (store reached + stores a cred ⇒ HOLDS cred)

    deserialization-to-code-exec ─▶ host-takeover ─▶ lateral-pivot
        (SESSION_ON + code_exec)      (⇒ OWNS host)   (OWNS + REACHABLE_FROM peer
                                                        ⇒ OWNS the peer host)

    credential-leak-capture ─▶ role-assumption
        (exposed cred VALID_ON P ⇒ CAN_ASSUME P)   (⇒ HAS_GRANT over the resource)

    token-leak-capture ─▶ session-theft-takeover
        (leaked SESSION ⇒ HOLDS)   (HOLDS + SESSION_ON app ⇒ AUTHENTICATES_TO app)

Every operator keeps the catalog's contract exactly: typed pre/post-conditions
over the world-model's own ``NodeKind`` / ``EdgeKind`` / attrs, intel refs
(ATT&CK / CAPEC / CWE), the observable detection signals, and the deterministic
``oracle_kind`` that would confirm the move fired. No payloads live here — an
operator says *what must be true, what becomes true, and how a defender sees it*.

Because effects are named by role and roles compose, ``[*CATALOG, *EXTENDED_CATALOG]``
forward-chains to a fixpoint under :func:`knowledge.operators.saturate`. Several
operators act *as* the attacker principal — they name a caller-seeded ``actor``
role (the identity the framework already controls), exactly like ``credential-reuse``
and ``token-replay`` in the base catalog; the rest capture their acting principal
straight off the edge that unlocked them (``owner`` / ``thief``), so no seed is
needed.

Look-ups:

    EXTENDED_CATALOG        -> tuple[Operator, ...]  (stable order)
    FINDING_PRECONDITIONS   -> dict[bug_class, dict[attr, value]]
    by_id_ext(op_id)        -> Operator
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
# 1. credential-leak-capture — a credential the framework observed *exposed*
#    (in a response body, repo, config, log) is now held by the attacker, and
#    if it is VALID_ON a principal the attacker can assume that principal.
#    This is the leak-side twin of `credential-reuse`: same CAN_ASSUME effect
#    (so it feeds `role-assumption`), but gated on an exposure the recon layer
#    saw and additionally recording the HOLDS attacker-state fact.
# ---------------------------------------------------------------------------

CREDENTIAL_LEAK_CAPTURE = Operator(
    id="credential-leak-capture",
    name="Leaked credential capture to account assumption",
    technique_ref=["T1552", "T1552.001", "CWE-522", "CWE-798", "CAPEC-545"],
    tactic="credential-access",
    description=(
        "A CREDENTIAL observed exposed (leaked in a response, repository, config "
        "or log — attr `exposed`) is taken into the attacker's possession. If it "
        "is VALID_ON a PRINCIPAL, the attacker can assume that principal — the "
        "same CAN_ASSUME capability `role-assumption` consumes, sourced from a "
        "leak rather than a reuse."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.CREDENTIAL,
                  note="the move is tried on a recovered credential"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="exposed", op=AttrOp.TRUTHY,
                  note="the credential was observed leaked, not merely present"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                  direction=Direction.OUT, other_kind=NodeKind.PRINCIPAL,
                  capture_as="principal",
                  note="the leaked credential authenticates a principal"),
    ],
    effects=[
        # `actor` is caller-seeded: the identity the attacker already controls.
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.HOLDS,
               src_role="actor", dst_role="focus", confidence=0.8,
               edge_attrs={"via": "leaked-credential"},
               note="the attacker now holds the leaked credential"),
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
               src_role="actor", dst_role="principal", confidence=0.75,
               edge_attrs={"via": "leaked-credential"},
               note="holding the credential lets the actor assume the principal"),
    ],
    detection_signals=[
        "secret material echoed in an HTTP response / error / debug page",
        "high-entropy token matching a known key format in a public artifact",
        "the same leaked secret subsequently used to authenticate successfully",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 2. datastore-secret-extraction — a DATASTORE the attacker reached (an
#    incoming REACHABLE_FROM edge, e.g. the one `unauth-endpoint-read` asserts)
#    that stores a CREDENTIAL yields that credential into the attacker's hands.
#    This is the hop that turns a *read* primitive into *credential access*,
#    feeding `credential-reuse` / worldmodel's OWN_VIA_HELD_CREDENTIAL rule.
# ---------------------------------------------------------------------------

DATASTORE_SECRET_EXTRACTION = Operator(
    id="datastore-secret-extraction",
    name="Reached datastore to credential extraction",
    technique_ref=["T1555", "T1213", "CWE-522", "CAPEC-639"],
    tactic="credential-access",
    description=(
        "A DATASTORE the attacker has reached (it has an incoming REACHABLE_FROM "
        "edge across some boundary) and that holds a CREDENTIAL — modelled as the "
        "credential being reachable from the store — gives up that credential. "
        "A read primitive (IDOR / SQLi / broken-authz endpoint) becomes credential "
        "access, the classic pivot from data exposure to identity compromise."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.DATASTORE,
                  note="the move is tried on a datastore"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
                  direction=Direction.IN,
                  note="the datastore is reachable — the attacker can read it"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
                  direction=Direction.OUT, other_kind=NodeKind.CREDENTIAL,
                  capture_as="cred",
                  note="a credential is obtainable from (stored in) the datastore"),
    ],
    effects=[
        # `actor` is caller-seeded: the attacker doing the reading.
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.HOLDS,
               src_role="actor", dst_role="cred", confidence=0.7,
               edge_attrs={"via": "datastore-read"},
               note="the credential read out of the store is now held"),
    ],
    detection_signals=[
        "a secrets table / bucket object returned by an over-broad query",
        "credential columns (password_hash, api_key, token) in a response body",
        "a datastore read whose result set includes another tenant's secrets",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 3. host-takeover — code execution on a HOST (attr `code_exec`, established by
#    e.g. `deserialization-to-code-exec`) is promoted to full attacker OWNShip
#    of that host. The acting principal is captured off the SESSION_ON foothold
#    the exec primitive left, so no seed is needed.
# ---------------------------------------------------------------------------

HOST_TAKEOVER = Operator(
    id="host-takeover",
    name="Code execution to host ownership",
    technique_ref=["T1059", "T1203", "CWE-94", "CAPEC-248"],
    tactic="execution",
    description=(
        "A HOST on which the attacker achieved code execution (attr `code_exec`) "
        "and holds an interactive foothold (an incoming SESSION_ON from the acting "
        "principal) is now fully controlled: the attacker OWNS it. This records the "
        "postcondition that the lateral-movement and attacker-state layers reason "
        "over."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.HOST,
                  note="the move is tried on a host"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="code_exec", op=AttrOp.TRUTHY,
                  note="code execution has been achieved on this host"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.SESSION_ON,
                  direction=Direction.IN, other_kind=NodeKind.PRINCIPAL,
                  capture_as="owner",
                  note="the acting principal holds a session/foothold on the host"),
    ],
    effects=[
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.OWNS,
               src_role="owner", dst_role="focus", confidence=0.8,
               edge_attrs={"via": "code-exec"},
               note="the acting principal now owns the compromised host"),
    ],
    detection_signals=[
        "post-exploitation commands run under the service account",
        "a reverse shell / implant beacon from the host",
        "persistence artifact (cron, unit, authorized_keys) newly written",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 4. lateral-pivot — from a HOST the attacker OWNS, a second HOST that is
#    REACHABLE_FROM it (an internal-only peer the attacker could not address
#    directly) is taken over too. Composes with `host-takeover`: OWN one box,
#    then walk the flat internal network to the next, hop by hop.
# ---------------------------------------------------------------------------

LATERAL_PIVOT = Operator(
    id="lateral-pivot",
    name="Lateral movement to an adjacent host",
    technique_ref=["T1021", "T1210", "CAPEC-555"],
    tactic="lateral-movement",
    description=(
        "A HOST the attacker OWNS can reach a peer HOST (a REACHABLE_FROM edge into "
        "the internal network). Owning the first box hands the attacker the second: "
        "the reused-foothold pivot that turns one compromised host into a chain "
        "across a flat internal segment. Re-applies to each newly owned host, so "
        "the pivot walks as far as the reachability graph allows."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.HOST,
                  note="the move is tried on an already-owned host"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.OWNS,
                  direction=Direction.IN, other_kind=NodeKind.PRINCIPAL,
                  capture_as="owner",
                  note="the attacker owns this host (the pivot origin)"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
                  direction=Direction.OUT, other_kind=NodeKind.HOST,
                  capture_as="peer",
                  note="a peer host is reachable from the owned host"),
    ],
    effects=[
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.OWNS,
               src_role="owner", dst_role="peer", confidence=0.65,
               edge_attrs={"via": "lateral-pivot"},
               note="the peer host is taken over from the owned foothold"),
    ],
    detection_signals=[
        "east-west connections from a workload that never initiates them",
        "SMB/SSH/WinRM auth to a peer using material lifted from the first host",
        "the same tool/implant hash appearing on a second internal host",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 5. token-leak-capture — a SESSION/token observed *leaked* (referrer leak,
#    log, mispiped cache, XSS exfil — attr `leaked`) is taken into the
#    attacker's possession as a HOLDS fact, priming `session-theft-takeover`.
# ---------------------------------------------------------------------------

TOKEN_LEAK_CAPTURE = Operator(
    id="token-leak-capture",
    name="Leaked session/token capture",
    technique_ref=["T1528", "T1539", "CWE-522", "CWE-384", "CAPEC-593"],
    tactic="credential-access",
    description=(
        "A SESSION or bearer token observed leaked (attr `leaked` — exfiltrated via "
        "XSS, a Referer leak, a shared log, or a cache mishap) is now held by the "
        "attacker. This records the HOLDS attacker-state fact that "
        "`session-theft-takeover` turns into authenticated access."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.SESSION,
                  note="the move is tried on a captured session/token"),
        Predicate(kind=PredicateKind.NODE_ATTR, attr="leaked", op=AttrOp.TRUTHY,
                  note="the session material was observed exfiltrated"),
    ],
    effects=[
        # `actor` is caller-seeded: the attacker who exfiltrated the token.
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.HOLDS,
               src_role="actor", dst_role="focus", confidence=0.75,
               edge_attrs={"via": "token-leak"},
               note="the attacker now holds the leaked session token"),
    ],
    detection_signals=[
        "session cookie / bearer token present in an outbound Referer or log",
        "an XSS payload observed exfiltrating document.cookie",
        "the same token later replayed from an unrelated client",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# 6. session-theft-takeover — a SESSION the attacker HOLDS that is SESSION_ON a
#    webapp authenticates the attacker to that app: account takeover. Consumes
#    the HOLDS that `token-leak-capture` (or any exfil primitive) produced.
# ---------------------------------------------------------------------------

SESSION_THEFT_TAKEOVER = Operator(
    id="session-theft-takeover",
    name="Stolen session to account takeover",
    technique_ref=["T1550.004", "T1539", "CWE-384", "CWE-613", "CAPEC-593"],
    tactic="lateral-movement",
    description=(
        "A SESSION the attacker HOLDS and that is established on a WEBAPP "
        "authenticates the holder to that app — account takeover with the victim's "
        "live session, no credential needed. The acting principal is captured off "
        "the HOLDS edge, so the takeover attributes to whoever stole the token."
    ),
    preconditions=[
        Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.SESSION,
                  note="the move is tried on a held session"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.HOLDS,
                  direction=Direction.IN, other_kind=NodeKind.PRINCIPAL,
                  capture_as="thief",
                  note="a principal holds this session (it was stolen)"),
        Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.SESSION_ON,
                  direction=Direction.OUT, other_kind=NodeKind.WEBAPP,
                  capture_as="app",
                  note="the session is established on a webapp"),
    ],
    effects=[
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.AUTHENTICATES_TO,
               src_role="thief", dst_role="app", confidence=0.7,
               edge_attrs={"via": "stolen-session"},
               note="the holder authenticates to the app as the victim"),
    ],
    detection_signals=[
        "one session id active from two divergent client fingerprints / geos",
        "an authenticated action from a session whose login it never issued",
        "concurrent use of a session cookie the legitimate user still holds",
    ],
    oracle_kind=OracleKind.ACHIEVED_STATE,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

EXTENDED_CATALOG: tuple[Operator, ...] = (
    CREDENTIAL_LEAK_CAPTURE,
    DATASTORE_SECRET_EXTRACTION,
    HOST_TAKEOVER,
    LATERAL_PIVOT,
    TOKEN_LEAK_CAPTURE,
    SESSION_THEFT_TAKEOVER,
)

_BY_ID = {op.id: op for op in EXTENDED_CATALOG}


def by_id_ext(op_id: str) -> Operator:
    """Look up an extended-catalog operator by id. KeyError if absent — a typo
    in planner wiring should fail loudly, not silently no-op."""
    return _BY_ID[op_id]


# ---------------------------------------------------------------------------
# Finding -> world-model precondition mapping
# ---------------------------------------------------------------------------
#
# When the orchestrator confirms a finding it creates a world-model node for
# the affected surface. FINDING_PRECONDITIONS says *what fact that confirmation
# establishes* so an EXTENDED_CATALOG operator becomes applicable — the bridge
# from "we proved bug X" to "these escalation operators can now fire".
#
# Two flavours of overlay, both expressed as {attr: value}:
#
#   * direct node-attr markers — `exposed`, `code_exec`, `leaked`,
#     `deserializes_untrusted`, `fetches_url` — are stamped straight onto the
#     finding's node and are read verbatim by a NODE_ATTR precondition
#     (credential-leak-capture, host-takeover, token-leak-capture, plus the
#     base catalog's deserialization / SSRF operators).
#
#   * edge-establishing markers — `reads_datastore`, `steals_session` — are a
#     signal to the orchestrator to ALSO assert the corresponding world-model
#     edge (a REACHABLE_FROM into the read DATASTORE / a HOLDS of the stolen
#     SESSION) so datastore-secret-extraction / session-theft-takeover engage.
#     They mirror the spec's illustrative {"sqli": {...}} / {"xss": {...}} form.
#
# The orchestrator merges this dict into its own bug_class mapping; it is data,
# not behaviour, so it can be extended without touching the operators.
FINDING_PRECONDITIONS: dict[str, dict[str, object]] = {
    # secrets / credential exposure -> exposed CREDENTIAL node
    "credential-leak": {"exposed": True},
    "secrets-exposure": {"exposed": True},
    "hardcoded-credentials": {"exposed": True},
    # datastore read primitives -> the attacker reached a DATASTORE
    "sqli": {"reads_datastore": True},
    "nosql-injection": {"reads_datastore": True},
    "idor": {"reads_datastore": True},
    # code execution -> code_exec on the HOST
    "rce": {"code_exec": True},
    "command-injection": {"code_exec": True},
    "deserialization": {"deserializes_untrusted": True},
    # session / token theft -> the attacker holds a SESSION
    "xss": {"steals_session": True},
    "session-fixation": {"leaked": True},
    "jwt-forgery": {"leaked": True},
    # ssrf keeps the base catalog's endpoint marker for ssrf-internal-reach
    "ssrf": {"fetches_url": True},
}
