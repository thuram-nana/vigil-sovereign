"""
live.graph_neo4j — the LIVE Neo4j binder for the F4 graph read-model (VIGIL-LIVE, WS1b).

This is the drop-in that replaces the deferred "Neo4j is the deferred live backend" thunk in
``vigil_integration.graph``. It mirrors the signed-spine projection into a real Neo4j database. Going
live changes NOTHING about the sovereign contract — the graph is still a PURE, ONE-WAY PROJECTION of the
signed spine, never a parallel source of truth, and nothing here makes anything true or authorizes
anything. The single most dangerous fusion (trust-laundering) is defended here exactly as it is in the
in-memory projector, deterministically:

  1. **Projection-only.** Neo4j is written ONLY by ``rebuild_from_spine`` over a list of ``SpineRecord``,
     via ``graph.project`` — the ONE writer. There is no independent Neo4j writer; nothing an LLM or a
     tool asserts reaches Neo4j except as a signed spine record whose veracity is re-derived by the
     projector, never trusted. ``rebuild_from_spine`` CLEARS the engagement partition and re-projects, so
     Neo4j equals ``graph.project`` for the same spine — it can never silently diverge.
  2. **Confirmed ⇔ a DISTINCT Neo4j label.** A finding projects to a ``:ChainFinding:Confirmed`` node
     ONLY if the projector marked it CONFIRMED (oracle-minted FACT carrying signed evidence). An
     unproven finding is a ``:ChainFinding:Lead`` node — a DIFFERENT label. ``query_confirmed`` and the
     F10 triage match ``:Confirmed``; a LEAD is physically unable to appear there. The confirmation
     label is derived from ``GraphNode.is_confirmed`` (the projector's oracle-grounded flag), NEVER from
     a finding field, so a record that merely *claims* it is a fact is still written as a Lead.
  3. **No authority is read FROM Neo4j.** The reads here return non-authoritative retrieval context
     (``FindingSummary`` / a ``RemediationDraft``), exactly like ``graph.query``. Nothing here grants a
     tier, promotes a finding, or authorizes an action; the conjunctive gate never consults Neo4j.
  4. **Cypher is PARAMETERIZED.** Every finding-derived value is passed as a query PARAMETER — never
     interpolated into the Cypher string — so a hostile finding field (a title of ``x'}) DETACH DELETE``)
     cannot inject Cypher. The only literals interpolated into a query are Neo4j LABELS / relationship
     TYPES, and those come from a fixed enum whitelist, never from record content.
  5. **Fail-closed + total.** No ``session_factory`` wired, a session error, a timeout, or a malformed
     record degrades to "no write" / "no rows" — never a partial-truth write and never a raise. A torn
     record is skipped by ``graph.project``; a torn row read back from Neo4j is skipped here.
  6. **Secret-free.** Finding-derived node properties are passed through the F3 redactor
     (``tools.redact_tool_args``, one vocabulary, one path) and coerced to Neo4j-safe scalars, so no
     credential/token is ever written into a node. Provenance references (spine hash, signature ref,
     SCITT/OpenVEX evidence id) are signed public references, not secrets, and are kept.
  7. **Deterministic + spine-safe.** No wallclock / RNG: the temporal coordinate is the spine ``seq``
     (carried as ``valid_from`` / ``invalid_from`` node properties). The write order is sorted, so two
     rebuilds of the same spine issue byte-identical Cypher + parameters.

The ``session_factory`` is an INJECTED zero-arg callable returning a Neo4j session (context-manager or
plain). Unit tests inject a fake in-memory session — the live ``neo4j`` driver is never required to test
the invariant. In production: ``Neo4jGraphWriter(lambda: driver.session(), group_id=...)``.

Import-clean: pydantic + stdlib + the F3/F4/F10 seams only (the ``neo4j`` driver is the injected caller's,
never imported here).
"""

from __future__ import annotations

import math
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from ..graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphView,
    NodeLabel,
    project,
)
from ..graph.query import FindingSummary
from ..remediation.triage import (
    RemediationDraft,
    TriageFinding,
    may_remediate,
    severity_rank,
)
from ..tools import redact_tool_args

# A zero-arg callable that yields a Neo4j session (context-manager or plain). Injected so the binder is
# testable with a fake; the live wiring is ``lambda: driver.session()``.
SessionFactory = Callable[[], Any]
ScopeGate = Callable[[str], bool]

# =============================================================================================
# Neo4j label / relationship-type whitelist — the ONLY literals interpolated into a Cypher string.
# Everything derived from a record is a bound PARAMETER; these come from the fixed enums, so a finding
# field can never contribute a label and inject Cypher.
# =============================================================================================

_COMMON_LABEL = "VigilNode"
_CONFIRMED_LABEL = "Confirmed"
_LEAD_LABEL = "Lead"
_CHAIN_FINDING_LABEL = NodeLabel.CHAIN_FINDING.value  # "ChainFinding"

_NODE_LABEL_WHITELIST: frozenset[str] = frozenset(
    {_COMMON_LABEL, _CONFIRMED_LABEL, _LEAD_LABEL} | {lab.value for lab in NodeLabel}
)
_EDGE_TYPE_WHITELIST: frozenset[str] = frozenset(e.value for e in EdgeType)

# Finding-derived property keys we mirror onto a node. A strict allowlist (never ``dict(node.props)``)
# so arbitrary attacker-influenced / nested / secret props never reach Neo4j; every value is redacted +
# scalar-coerced. NONE of these are system/provenance fields (those are set separately and always win).
_FINDING_PROP_KEYS: tuple[str, ...] = (
    "ref", "finding_ref", "title", "severity", "bug_class", "category", "source",
    "target", "host", "target_host", "url", "domain",
    "cisa_kev", "exploit_available", "cve_ids", "attack_chain_path",
    "target_repo", "target_branch",
)
# System / provenance property names — reserved so a hostile finding prop can never overwrite the
# derived confirmation, id, engagement partition, or signed provenance.
_RESERVED_PROP_KEYS: frozenset[str] = frozenset({
    "id", "engagement_id", "node_label", "confirmation", "spine_hash", "signature_ref",
    "evidence_ref", "valid_from", "invalid_from", "invalid_grounded",
})

_HIGH_SEVERITIES: tuple[str, ...] = ("high", "critical")


# =============================================================================================
# result shapes
# =============================================================================================


class MirrorResult(BaseModel):
    """The outcome of a ``rebuild_from_spine``. Pure counts — it authorizes nothing. ``ok=False`` with a
    reason on any fail-closed path (no session factory, a session error), never a raise."""

    ok: bool = False
    cleared: bool = False               # was the engagement partition cleared before the write?
    nodes_written: int = 0
    confirmed: int = 0                  # confirmed FACT finding nodes mirrored
    leads: int = 0                     # unproven LEAD finding nodes mirrored (distinct label)
    edges_written: int = 0
    error: str = ""


# =============================================================================================
# the 9 deterministic F10 triage queries, expressed as PARAMETERIZED Cypher over the Neo4j projection.
# Each matches ONLY ``:ChainFinding:Confirmed`` active nodes — a LEAD (a distinct label) can never be
# selected. Correlation signals (cve / asset / attack-chain) read the finding's projected scalar props
# (which the projector wrote from the same signed spine), so no relationship traversal is string-built.
# The Python correlate/dedup/prioritize pass mirrors ``remediation.triage.run_triage`` (F10 Phase-2).
# =============================================================================================


class TriageCypher(BaseModel):
    """One named F10 triage query. ``cypher`` is a parameterized string (the ``$engagement_id`` and any
    ``$severities`` are bound at run time); ``params_extra`` supplies the non-engagement bound params."""

    name: str
    phase: str
    description: str
    cypher: str
    params_extra: dict[str, Any] = Field(default_factory=dict)


def _confirmed_match(where_extra: str = "") -> str:
    """A confirmed-finding MATCH scoped to the engagement partition and to ACTIVE (non-retired) nodes.
    ``where_extra`` is a fixed, parameterized predicate (never record-derived)."""
    where = "n.engagement_id = $engagement_id AND n.invalid_from IS NULL"
    if where_extra:
        where += f" AND {where_extra}"
    return (f"MATCH (n:`{_CHAIN_FINDING_LABEL}`:`{_CONFIRMED_LABEL}`)\n"
            f"WHERE {where}\n"
            "RETURN properties(n) AS n\n"
            "ORDER BY n.id")


TRIAGE_CYPHER: tuple[TriageCypher, ...] = (
    TriageCypher(name="all_confirmed", phase="collect",
                 description="every oracle-confirmed finding",
                 cypher=_confirmed_match()),
    TriageCypher(name="critical", phase="collect",
                 description="confirmed findings at CRITICAL severity",
                 cypher=_confirmed_match("toLower(n.severity) IN $severities"),
                 params_extra={"severities": ["critical"]}),
    TriageCypher(name="high_or_critical", phase="collect",
                 description="confirmed findings at HIGH+ severity",
                 cypher=_confirmed_match("toLower(n.severity) IN $severities"),
                 params_extra={"severities": ["high", "critical"]}),
    TriageCypher(name="kev_or_exploitable", phase="prioritize",
                 description="KEV / public-exploit findings",
                 cypher=_confirmed_match("(n.cisa_kev = true OR n.exploit_available = true)")),
    TriageCypher(name="cve_correlated", phase="correlate",
                 description="findings correlated to a CVE",
                 cypher=_confirmed_match("n.cve_ids IS NOT NULL AND size(n.cve_ids) > 0")),
    TriageCypher(name="asset_affecting", phase="correlate",
                 description="findings affecting a concrete asset",
                 cypher=_confirmed_match("n.target IS NOT NULL AND n.target <> ''")),
    TriageCypher(name="attack_chain_member", phase="correlate",
                 description="findings on an attack chain",
                 cypher=_confirmed_match("n.attack_chain_path IS NOT NULL AND size(n.attack_chain_path) > 0")),
    TriageCypher(name="duplicate_class", phase="dedup",
                 description="duplicate (class,target) findings — deduped in the Python pass",
                 cypher=_confirmed_match()),
    TriageCypher(name="severity_prioritized", phase="prioritize",
                 description="all confirmed, severity-ranked",
                 cypher=_confirmed_match()),
)
assert len(TRIAGE_CYPHER) == 9, "the F10 triage runs exactly 9 deterministic queries"

# lead collection — a DISTINCT label; surfaced separately, never mixed with confirmed facts.
_LEAD_CYPHER = (f"MATCH (n:`{_CHAIN_FINDING_LABEL}`:`{_LEAD_LABEL}`)\n"
                "WHERE n.engagement_id = $engagement_id AND n.invalid_from IS NULL\n"
                "RETURN properties(n) AS n\n"
                "ORDER BY n.id")

# engagement-partition clear (scoped DETACH DELETE) — the first half of "clear + re-project".
_CLEAR_CYPHER = (f"MATCH (n:`{_COMMON_LABEL}` {{engagement_id: $engagement_id}})\n"
                 "DETACH DELETE n")


# =============================================================================================
# value coercion + secret-free node/edge property projection
# =============================================================================================


# Neo4j stores signed 64-bit integers; a value outside this range makes the driver reject the write.
_INT64_MIN: int = -(2 ** 63)
_INT64_MAX: int = 2 ** 63 - 1


def _coerce_scalar(v: Any) -> Any:
    """Coerce a value to a Neo4j-storable scalar (or list of scalars). A value Neo4j cannot store —
    a nested map, an integer outside the signed 64-bit range, or a non-finite float — degrades to
    ``None`` (the field is DROPPED → a smaller mirror) rather than reaching the driver and making it
    reject the WHOLE write (an availability-only, all-or-nothing denial of the engagement's mirror).
    ``bool`` is handled before ``int`` (it is an ``int`` subclass)."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        # out-of-64-bit int would make the real driver raise → _in_session denies the whole rebuild;
        # drop the single hostile field instead, so one poisoned prop degrades to a smaller mirror.
        return v if _INT64_MIN <= v <= _INT64_MAX else None
    if isinstance(v, float):
        return v if math.isfinite(v) else None      # NaN / ±inf are not Neo4j-storable → drop
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if isinstance(x, (str, int, float, bool))]
    return None


def _finding_scalar_props(props: Any) -> dict[str, Any]:
    """The allowlisted, scalar-coerced, F3-REDACTED finding properties. Total: a non-dict ``props`` or a
    per-key coercion failure yields an empty / smaller map, never a raise. Secret-free: the whole map is
    routed through ``redact_tool_args`` (the one F3 redaction path) so an inline ``Bearer <tok>`` /
    ``password=…`` in any free-text field is masked before it can reach a node."""
    if not isinstance(props, dict):
        return {}
    raw: dict[str, Any] = {}
    for k in _FINDING_PROP_KEYS:
        if k in _RESERVED_PROP_KEYS or k not in props:
            continue
        cv = _coerce_scalar(props.get(k))
        if cv is None:                       # complex / unstorable value dropped
            continue
        if isinstance(cv, str) and not cv:   # empty string carries no signal
            continue
        raw[k] = cv
    try:
        redacted = redact_tool_args(raw)     # F3 redaction — one vocabulary, one path
    except Exception:                        # noqa: BLE001 — redaction never crashes the projection
        return {}
    out: dict[str, Any] = {}
    for k, v in redacted.items():
        if k in _RESERVED_PROP_KEYS:         # a redacted map can never smuggle a system field
            continue
        cv = _coerce_scalar(v)               # re-coerce post-redaction (defensive)
        if cv is None or (isinstance(cv, str) and not cv):
            continue
        out[str(k)] = cv
    return out


def _node_labels(node: GraphNode) -> list[str]:
    """The Neo4j labels for a node: the common ``VigilNode`` + the typed label + (for a finding only) the
    DISTINCT confirmation label. The confirmation label comes from ``node.is_confirmed`` — the projector's
    oracle-grounded flag — NEVER from a finding field, so a lead can never be labelled Confirmed. Returns
    ``[]`` if any label is off the enum whitelist (defense-in-depth; the node is then skipped)."""
    labels = [_COMMON_LABEL, node.label.value]
    if node.label == NodeLabel.CHAIN_FINDING:
        labels.append(_CONFIRMED_LABEL if node.is_confirmed else _LEAD_LABEL)
    if any(lbl not in _NODE_LABEL_WHITELIST for lbl in labels):
        return []
    return labels


def _node_row(node: GraphNode, group_id: str) -> Optional[dict[str, Any]]:
    """Build the ``{id, props}`` row for one node. System/provenance props are set AFTER the redacted
    finding props so a hostile finding prop (e.g. ``confirmation=confirmed``) can never overwrite the
    derived confirmation, id, engagement partition, or signed provenance. A confirmed node carries the
    signed ``evidence_ref``; a lead carries none. Returns ``None`` if the node cannot be built."""
    try:
        props = _finding_scalar_props(node.props)
        sysprops: dict[str, Any] = {
            "id": node.id,
            "engagement_id": group_id,
            "node_label": node.label.value,
            "confirmation": node.provenance.confirmation.value,
            "spine_hash": node.provenance.spine_hash,
            "signature_ref": node.provenance.signature_ref,
            "valid_from": int(node.valid_from) if isinstance(node.valid_from, int)
            and not isinstance(node.valid_from, bool) else 0,
        }
        if node.invalid_from is not None and isinstance(node.invalid_from, int) \
                and not isinstance(node.invalid_from, bool):
            sysprops["invalid_from"] = int(node.invalid_from)
        # evidence_ref is written ONLY for a confirmed FACT (its presence ⇔ confirmed, mirroring the F2
        # Finding invariant); a lead node never carries a signed evidence reference.
        if node.is_confirmed and (node.provenance.evidence_ref or "").strip():
            sysprops["evidence_ref"] = node.provenance.evidence_ref
        props.update(sysprops)               # system fields always win
        return {"id": node.id, "props": props}
    except Exception:                        # noqa: BLE001 — a torn node is skipped, not fatal
        return None


def _edge_row(edge: GraphEdge) -> Optional[dict[str, Any]]:
    try:
        props: dict[str, Any] = {
            "type": edge.type.value,
            "confirmation": edge.provenance.confirmation.value,
            "spine_hash": edge.provenance.spine_hash,
            "valid_from": int(edge.valid_from) if isinstance(edge.valid_from, int)
            and not isinstance(edge.valid_from, bool) else 0,
        }
        if edge.invalid_from is not None and isinstance(edge.invalid_from, int) \
                and not isinstance(edge.invalid_from, bool):
            props["invalid_from"] = int(edge.invalid_from)
        return {"src": edge.src, "dst": edge.dst, "props": props}
    except Exception:                        # noqa: BLE001
        return None


def _node_write_cypher(extra_labels: list[str]) -> str:
    """A parameterized node-upsert. Values arrive via ``$rows`` (bound params); the only interpolation is
    the whitelisted extra LABELS.

    The MERGE identity is ENGAGEMENT-SCOPED — ``{id, engagement_id}``, not ``{id}`` — so a foreign
    engagement partition's node (same id like ``finding:F-1`` or a shared bridge ``host:127.0.0.1``, but
    a different ``engagement_id``) can NEVER alias into this write and have its confirmation / props
    flipped; each engagement owns its own copy of a shared id. The per-engagement clear only reaches this
    engagement's nodes, and this MERGE only matches within this engagement, so the two are consistent.

    The confirmation labels are RESET (``REMOVE n:Confirmed REMOVE n:Lead``) BEFORE the current label is
    set, so a stale ``:Confirmed`` can never survive a lead re-projection given the live backend's
    ADDITIVE ``SET n:<label>`` semantics (a bare ``SET`` unions labels, it does not replace them). For a
    non-finding node the REMOVE is a harmless no-op. ``$engagement_id`` is a bound param, never
    interpolated. ``extra_labels`` always has ≥1 element (the typed label), so ``SET n<suffix>`` is valid."""
    suffix = "".join(f":`{lbl}`" for lbl in extra_labels)
    return ("UNWIND $rows AS row\n"
            f"MERGE (n:`{_COMMON_LABEL}` {{id: row.id, engagement_id: $engagement_id}})\n"
            "SET n = row.props\n"
            f"REMOVE n:`{_CONFIRMED_LABEL}` REMOVE n:`{_LEAD_LABEL}`\n"
            f"SET n{suffix}")


def _edge_write_cypher(edge_type: str) -> str:
    """A parameterized edge-upsert. The relationship TYPE is a whitelisted enum literal; endpoints and
    props arrive via ``$rows``. The endpoint MATCH is ENGAGEMENT-SCOPED ``{id, engagement_id}`` — because
    a shared id (e.g. ``host:127.0.0.1``) now has one node copy PER engagement, an unscoped ``{id}`` match
    would fan an edge across engagement partitions; scoping keeps every edge strictly within its own
    engagement. ``$engagement_id`` is a bound param, never interpolated."""
    return ("UNWIND $rows AS row\n"
            f"MATCH (a:`{_COMMON_LABEL}` {{id: row.src, engagement_id: $engagement_id}})\n"
            f"MATCH (b:`{_COMMON_LABEL}` {{id: row.dst, engagement_id: $engagement_id}})\n"
            f"MERGE (a)-[r:`{edge_type}`]->(b)\n"
            "SET r = row.props")


# =============================================================================================
# reading rows back (total)
# =============================================================================================


def _record_props(record: Any) -> dict[str, Any]:
    """Pull the ``properties(n) AS n`` map from a Neo4j record, tolerant of the driver's Record shape or
    a plain dict / mapping. Total — an unreadable record degrades to ``{}``."""
    val: Any = None
    try:
        val = record["n"]
    except Exception:                        # noqa: BLE001
        try:
            val = record.get("n")            # type: ignore[union-attr]
        except Exception:                    # noqa: BLE001
            val = record if isinstance(record, dict) else None
    if isinstance(val, dict):
        return val
    if isinstance(record, dict):
        return record
    return {}


def _summary_from_props(props: dict[str, Any]) -> FindingSummary:
    return FindingSummary(
        ref=str(props.get("ref") or props.get("finding_ref") or props.get("id") or ""),
        title=str(props.get("title") or ""),
        severity=str(props.get("severity") or ""),
        bug_class=str(props.get("bug_class") or props.get("category") or ""),
        evidence_ref=str(props.get("evidence_ref") or ""),
        spine_hash=str(props.get("spine_hash") or ""),
    )


def _triage_finding_from_props(props: dict[str, Any], *, confirmed: bool) -> Optional[TriageFinding]:
    """Build an F10 ``TriageFinding`` from a Neo4j row. A confirmed row MUST carry a non-empty signed
    ``evidence_ref`` — the ``TriageFinding`` validator re-enforces the sovereign rule and REFUSES an
    evidence-less 'confirmed' row, so a mislabelled node can never spawn a codefix. Returns ``None`` on
    any construction failure (fail-closed)."""
    ev = str(props.get("evidence_ref") or "").strip()
    if confirmed and not ev:                 # confirmed label but no signed proof → drop (fail-closed)
        return None
    try:
        return TriageFinding(
            ref=str(props.get("ref") or props.get("finding_ref") or props.get("id") or ""),
            title=str(props.get("title") or ""),
            bug_class=str(props.get("bug_class") or props.get("category") or ""),
            severity=str(props.get("severity") or ""),
            target=str(props.get("target") or props.get("host") or props.get("url") or ""),
            confirmed=confirmed,
            evidence_ref=ev if confirmed else "",
            spine_hash=str(props.get("spine_hash") or ""),
            attack_chain_path=[str(x) for x in props.get("attack_chain_path") or []
                               if isinstance(x, (str, int, float))],
            cve_ids=[str(x) for x in props.get("cve_ids") or [] if isinstance(x, (str, int, float))],
            exploit_available=bool(props.get("exploit_available")),
            cisa_kev=bool(props.get("cisa_kev")),
            target_repo=str(props.get("target_repo") or ""),
            target_branch=str(props.get("target_branch") or ""),
        )
    except Exception:                        # noqa: BLE001 — a torn / invariant-violating row is dropped
        return None


def _priority_key(f: TriageFinding) -> tuple:
    """Deterministic F10 rank: severity desc, then KEV, then public-exploit, then chain depth, then ref
    asc — a total, stable tiebreak (no wallclock / RNG). Mirrors ``remediation.triage._priority_key``."""
    return (-severity_rank(f.severity), -int(f.cisa_kev), -int(f.exploit_available),
            -len(f.attack_chain_path), f.ref)


def _dedup_by_ref(findings: list[TriageFinding]) -> list[TriageFinding]:
    """Collapse findings sharing a ``ref`` — keep the highest-(severity, spine_hash) representative
    (deterministic). First-appearance order preserved (re-sorted by priority after)."""
    best: dict[str, TriageFinding] = {}
    order: list[str] = []
    for f in findings:
        cur = best.get(f.ref)
        if cur is None:
            best[f.ref] = f
            order.append(f.ref)
        elif (severity_rank(f.severity), f.spine_hash) > (severity_rank(cur.severity), cur.spine_hash):
            best[f.ref] = f
    return [best[r] for r in order]


# =============================================================================================
# the writer
# =============================================================================================


class Neo4jGraphWriter:
    """Mirrors the F4 signed-spine projection into a live Neo4j database and reads it back as
    non-authoritative retrieval context.

    ``session_factory`` is an injected zero-arg callable returning a Neo4j session (context-manager or
    plain). ``group_id`` is the engagement partition key — every node/edge and every query is scoped to
    it, so multiple engagements never bleed together. The writer is inert: it authorizes nothing, mints
    no fact, and is never consulted by the conjunctive gate."""

    def __init__(self, session_factory: Optional[SessionFactory], *, group_id: str = "") -> None:
        self._session_factory: Optional[SessionFactory] = (
            session_factory if callable(session_factory) else None)
        self.group_id: str = str(group_id or "")

    # -- session plumbing (total, fail-closed) --------------------------------------------------

    def _in_session(self, fn: Callable[[Any], Any]) -> Any:
        """Open a session (context-manager or plain), run ``fn(session)``, and always close. Returns
        ``fn``'s value, or ``None`` on ANY failure (no factory, factory raised, fn raised). Never raises —
        a live-backend hiccup degrades to no-signal, never a crash or a partial-truth commit."""
        factory = self._session_factory
        if factory is None:
            return None
        try:
            session = factory()
        except Exception:                    # noqa: BLE001 — a factory error is fail-closed
            return None
        is_cm = hasattr(session, "__enter__") and hasattr(session, "__exit__")
        try:
            active = session.__enter__() if is_cm else session
            try:
                return fn(active)
            finally:
                if is_cm:
                    session.__exit__(None, None, None)
                elif hasattr(session, "close"):
                    session.close()
        except Exception:                    # noqa: BLE001
            return None

    @staticmethod
    def _run(session: Any, cypher: str, params: dict[str, Any]) -> Any:
        return session.run(cypher, parameters=params)

    # -- the one writer: clear + re-project -----------------------------------------------------

    def rebuild_from_spine(self, records: Any, *, group_id: Optional[str] = None,
                           scope_gate: Optional[ScopeGate] = None) -> MirrorResult:
        """CLEAR the engagement partition, then re-project ``records`` into Neo4j via ``graph.project`` —
        the ONLY writer. Afterwards Neo4j equals the in-memory projection of the same spine (a pure,
        rebuildable projection; no independent truth). Confirmed FACT findings become ``:Confirmed``
        nodes, unproven findings ``:Lead`` nodes (a distinct label). Deterministic: the same spine issues
        byte-identical Cypher + params. Total: a malformed record list degrades to a smaller/empty
        mirror; no ``session_factory`` or a session error yields ``ok=False`` — never a raise."""
        eid = str(group_id) if group_id is not None else self.group_id
        self.group_id = eid
        if self._session_factory is None:
            return MirrorResult(ok=False, error="no session factory wired (fail-closed: no write)")

        view: GraphView = project(list(records) if isinstance(records, (list, tuple)) else [],
                                  group_id=eid, scope_gate=scope_gate)
        node_rows, confirmed, leads = self._node_write_batches(view, eid)
        edge_batches = self._edge_write_batches(view)
        result = MirrorResult(ok=False, confirmed=confirmed, leads=leads)

        def _do(session: Any) -> MirrorResult:
            self._run(session, _CLEAR_CYPHER, {"engagement_id": eid})
            result.cleared = True
            for suffix, rows in node_rows:
                if rows:
                    self._run(session, _node_write_cypher(suffix), {"rows": rows, "engagement_id": eid})
                    result.nodes_written += len(rows)
            for etype, rows in edge_batches:
                if rows:
                    self._run(session, _edge_write_cypher(etype), {"rows": rows, "engagement_id": eid})
                    result.edges_written += len(rows)
            result.ok = True
            return result

        out = self._in_session(_do)
        if out is None:                      # session failed AFTER we started — fail-closed report
            return MirrorResult(ok=False, confirmed=confirmed, leads=leads,
                                error="neo4j session error (fail-closed: mirror not committed)")
        return out

    def _node_write_batches(self, view: GraphView, eid: str) -> tuple[list, int, int]:
        """Group node rows by their (deterministic) extra-label tuple → one UNWIND write per group.
        Returns (batches, confirmed_count, lead_count). Deterministic node order (sorted id)."""
        by_labels: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        confirmed = leads = 0
        for nid in sorted(view.nodes.keys()):
            node = view.nodes[nid]
            labels = _node_labels(node)
            if not labels:                   # off-whitelist label → skip (defense-in-depth)
                continue
            row = _node_row(node, eid)
            if row is None:
                continue
            extra = tuple(labels[1:])        # everything beyond the common VigilNode label
            by_labels.setdefault(extra, []).append(row)
            if node.label == NodeLabel.CHAIN_FINDING:
                if node.is_confirmed:
                    confirmed += 1
                else:
                    leads += 1
        batches = [(list(extra), rows) for extra, rows in sorted(by_labels.items())]
        return batches, confirmed, leads

    def _edge_write_batches(self, view: GraphView) -> list[tuple[str, list[dict[str, Any]]]]:
        by_type: dict[str, list[dict[str, Any]]] = {}
        for edge in sorted(view.edges, key=lambda e: (e.src, e.dst, e.type.value)):
            if edge.type.value not in _EDGE_TYPE_WHITELIST:
                continue
            row = _edge_row(edge)
            if row is None:
                continue
            by_type.setdefault(edge.type.value, []).append(row)
        return sorted(by_type.items())

    # -- reads: non-authoritative retrieval context ---------------------------------------------

    def query_confirmed(self, *, target: Optional[str] = None, high_only: bool = False,
                        limit: int = 100, group_id: Optional[str] = None) -> list[FindingSummary]:
        """The confirmed facts, read back from Neo4j as NON-AUTHORITATIVE ``FindingSummary`` context. The
        parameterized Cypher matches ONLY ``:ChainFinding:Confirmed`` active nodes — a LEAD (a distinct
        label) is physically unable to be returned. ``target`` / ``high_only`` are bound as PARAMETERS
        (never string-built). Deterministic (id order). Total: any error yields ``[]``."""
        eid = str(group_id) if group_id is not None else self.group_id
        lim = max(0, int(limit)) if isinstance(limit, int) and not isinstance(limit, bool) else 100
        where_extra: list[str] = []
        params: dict[str, Any] = {"engagement_id": eid}
        if high_only:
            where_extra.append("toLower(n.severity) IN $severities")
            params["severities"] = list(_HIGH_SEVERITIES)
        if isinstance(target, str) and target:
            where_extra.append("n.target = $target")
            params["target"] = target
        cypher = _confirmed_match(" AND ".join(where_extra))
        rows = self._read_rows(cypher, params)
        return [_summary_from_props(p) for p in rows][:lim]

    def query_leads(self, *, limit: int = 100,
                    group_id: Optional[str] = None) -> list[FindingSummary]:
        """The unproven LEADS, read from the DISTINCT ``:Lead`` label and surfaced SEPARATELY — never
        mixed into ``query_confirmed``. Non-authoritative context; total (``[]`` on any error)."""
        eid = str(group_id) if group_id is not None else self.group_id
        lim = max(0, int(limit)) if isinstance(limit, int) and not isinstance(limit, bool) else 100
        rows = self._read_rows(_LEAD_CYPHER, {"engagement_id": eid})
        return [_summary_from_props(p) for p in rows][:lim]

    def retrieve_priors(self, *, group_id: Optional[str] = None, limit: int = 8,
                        extra_partitions: Any = ()) -> list[dict[str, Any]]:
        """NON-AUTHORITATIVE PRIOR context from the session's Neo4j partition(s), for the think step (F3).

        Returns bounded, deterministic advisory summaries — the confirmed facts + leads ALREADY projected
        into this session's partition (an earlier run's findings, or this run's so far). It is RETRIEVAL,
        never authority: a prior confirmed here is a LEAD in the current run — THIS run's oracle must
        re-fire over its own evidence to mint a fact. Each row is tagged with its ``origin`` partition so
        F4's cross-session union stays provenance-preserving; ``extra_partitions`` unions the operator's
        CONSENTED connected sessions (empty in F3 — a session reads only its own partition). Nothing here is
        read back by the gate. Total ([] on any error); no wallclock/rng (severity/confirmed/ref order)."""
        eid = str(group_id) if group_id is not None else self.group_id
        extra = [str(p) for p in extra_partitions] if isinstance(
            extra_partitions, (list, tuple, set, frozenset)) else []
        parts = sorted({eid, *extra})
        lim = max(0, int(limit)) if isinstance(limit, int) and not isinstance(limit, bool) else 8
        out: list[dict[str, Any]] = []
        for part in parts:
            for s in self.query_confirmed(group_id=part, limit=lim):
                out.append({"ref": s.ref, "title": s.title, "severity": s.severity,
                            "bug_class": s.bug_class, "confirmed": True, "origin": part})
            for s in self.query_leads(group_id=part, limit=lim):
                out.append({"ref": s.ref, "title": s.title, "severity": s.severity,
                            "bug_class": s.bug_class, "confirmed": False, "origin": part})
        # deterministic rank: confirmed first, then higher severity, then ref (a total, stable order)
        out.sort(key=lambda r: (0 if r["confirmed"] else 1, -severity_rank(r["severity"]), str(r["ref"])))
        return out[:lim]

    def run_triage(self, *, high_only: bool = False, existing_refs: Any = (),
                   group_id: Optional[str] = None) -> RemediationDraft:
        """Run the 9 deterministic F10 triage queries (``TRIAGE_CYPHER``) over the Neo4j projection and
        assemble a prioritized, deduped ``RemediationDraft`` — the F10 CypherFix Phase-1 (Cypher collect)
        + Phase-2 (Python correlate/dedup/prioritize), on Neo4j.

        Only oracle-CONFIRMED findings can enter ``findings`` (each may spawn a remediation — see
        ``may_remediate``); unproven leads are surfaced SEPARATELY in ``leads``. Every triage query
        matches ONLY ``:Confirmed`` nodes, so a LEAD can never trigger a codefix. ``existing_refs`` are
        excluded (only NEW findings drafted); ``high_only`` restricts to HIGH+ severity. This is
        RETRIEVAL, not authority — a returned finding still clears the oracle + gate before any action.
        Deterministic + total (a backend error yields an empty draft, never a raise)."""
        eid = str(group_id) if group_id is not None else self.group_id
        existing = frozenset(str(r) for r in existing_refs) if isinstance(
            existing_refs, (list, tuple, set, frozenset)) else frozenset()

        # Phase-1: collect the union of confirmed nodes across the 9 queries, first-seen (deterministic).
        seen: set[str] = set()
        collected: list[dict[str, Any]] = []
        for q in TRIAGE_CYPHER:
            params: dict[str, Any] = {"engagement_id": eid, **q.params_extra}
            for props in self._read_rows(q.cypher, params):
                nid = str(props.get("id") or "")
                if nid and nid not in seen:
                    seen.add(nid)
                    collected.append(props)

        # Phase-2: build confirmed TriageFindings (evidence re-required), filter, dedup, prioritize.
        findings: list[TriageFinding] = []
        for props in collected:
            tf = _triage_finding_from_props(props, confirmed=True)
            if tf is None or not tf.confirmed:
                continue
            if high_only and severity_rank(tf.severity) < 3:
                continue
            if tf.ref in existing:
                continue
            findings.append(tf)
        findings = _dedup_by_ref(findings)
        findings.sort(key=_priority_key)
        for i, tf in enumerate(findings):
            tf.priority = i + 1

        leads: list[TriageFinding] = []
        for props in self._read_rows(_LEAD_CYPHER, {"engagement_id": eid}):
            lf = _triage_finding_from_props(props, confirmed=False)
            if lf is not None:
                leads.append(lf)

        return RemediationDraft(
            findings=findings,
            leads=leads,
            summary=(f"{len(findings)} confirmed finding(s) eligible for remediation; "
                     f"{len(leads)} unconfirmed lead(s) surfaced (never spawn a codefix)"),
            by_severity=_count(findings, lambda f: (f.severity or "unknown").strip().lower() or "unknown"),
            by_type=_count(findings, lambda f: f.bug_class or "unknown"),
        )

    def _read_rows(self, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Run a read and materialize the ``properties(n)`` maps. Total: any session/iteration error
        yields ``[]`` (no-signal, never a raise)."""
        def _do(session: Any) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            result = self._run(session, cypher, params)
            for record in (result or []):
                props = _record_props(record)
                if props:
                    out.append(props)
            return out

        rows = self._in_session(_do)
        return rows if isinstance(rows, list) else []


def _count(findings: list[TriageFinding], key: Callable[[TriageFinding], str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        k = key(f)
        out[k] = out.get(k, 0) + 1
    return out


# Re-exported for callers so the sovereign remediation-spawn boundary is reachable from the live binder
# without reaching back into F10 internals: only an oracle-confirmed FACT may spawn a remediation.
__all__ = [
    "Neo4jGraphWriter",
    "MirrorResult",
    "TriageCypher",
    "TRIAGE_CYPHER",
    "SessionFactory",
    "may_remediate",
]
