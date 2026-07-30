"""
worldmodel.spine_projector — project the signed, append-only spine onto the RICH
``worldmodel.WorldModel`` asset topology (P4).

The chain-centric spine projector (``integration.graph.projector``) builds a
provenance DAG of ``AttackChain → ChainStep → {Finding | Failure | Decision}``
bridged to a thin recon graph (CVE/host/port/tech). That view answers *"how did
this engagement unfold?"* — but it is **not** the asset topology the
graph-theoretic planner needs. Shortest-attack-path, chokepoint ranking, and
blast-radius (``worldmodel.pathsearch`` / ``worldmodel.impact``) run over a
typed multigraph of hosts, services, credentials, principals and datastores wired
by *reachability* and *trust* edges — the ``worldmodel.WorldModel``.

This module is the missing bridge: a **pure, one-way projection** of the signed
spine into that asset topology. It carries the exact same sovereign rules as the
chain projector, enforced here deterministically:

  1. **Projection-only, no other writer.** The WorldModel is written ONLY by
     :func:`project_spine` over a list of :class:`AssetSpineRecord`. Nothing an LLM
     or a tool asserts reaches the graph except as a spine record; its veracity is
     re-derived, never trusted.
  2. **Confirmed ⇔ oracle-signed.** A finding projects as a CONFIRMED (grounded)
     ``FINDING`` node ONLY if the record is a FACT carrying BOTH a non-empty signed
     ``evidence_ref`` AND a ``signature_ref`` (:func:`_finding_confirmed`). A bare
     ``status="fact"`` with no signed evidence is a LEAD. The graph can never
     launder an unproven claim into a fact.
  3. **Belief is grounded, never manufactured.** An edge's / node's belief comes
     from the confidence the spine recorded (the oracle/sensor's grounded number).
     When a record omits it, the default is *conservative* — a grounded fact seeds
     at :data:`_CONFIRMED_DEFAULT` (``0.9``, never ``1.0``, mirroring the report
     layer's honesty), an ungrounded lead at :data:`_LEAD_DEFAULT` (``0.5``). We
     never invent certainty; an explicit spine-recorded confidence is passed
     through faithfully (clamped to ``[0, 1]``).
  4. **Provenance drives the grounding tier.** Each write's provenance string is
     derived so ``worldmodel.models.classify_provenance`` tags it GROUNDED (an
     ``oracle:`` fact), INTEL (an ``intel:`` recon lead) or UNGROUNDED — the same
     vocabulary the veracity firewall and console filter on. The WorldModel's Beta
     belief then seeds/updates automatically on upsert.
  5. **Deterministic + rebuildable.** Records are applied in a total
     ``(seq, hash, canonical-body)`` order (so ``attrs`` merges and provenance
     ties resolve identically every run), the temporal coordinate is the spine
     ``seq`` (never a wallclock / RNG), and the pass is idempotent — the same spine
     yields a byte-identical WorldModel. It can be rebuilt and independently
     verified against the spine and cannot silently diverge.
  6. **Grounded-only refutation.** A ``refute`` record DEMOTES belief (a Beta
     refutation that lowers ``belief_lcb``) only when it is itself oracle-grounded;
     a bare (unauthenticated) refute of a confirmed fact is ignored — an opinion
     cannot un-prove a proof (the mirror of anti-laundering).

The projector reads the spine and NOTHING else: it never reads a tier / grant /
sovereignty state back, and never mutates the spine.

Import-clean & framework-side: pydantic + the sibling ``worldmodel`` modules +
stdlib only (no dependency on the integration layer), so the offense-engine CLI
can project without crossing the two-env boundary.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from .graph import WorldModel
from .models import Edge, EdgeKind, Node, NodeKind

# Conservative belief defaults used ONLY when a record omits an explicit confidence.
# A grounded fact never defaults to 1.0 (certainty is never manufactured — 0.9 mirrors
# the report layer's "confirmed = 0.9, not 1.0" honesty); a lead defaults to a coin-flip.
_CONFIRMED_DEFAULT = 0.9
_LEAD_DEFAULT = 0.5

# Record kinds this projector understands. An unrecognised kind projects NOTHING
# (fail-closed), exactly like the chain projector.
KIND_ASSET = "asset"
KIND_RELATION = "relation"
KIND_FINDING = "finding"
KIND_REFUTE = "refute"


# ---------------------------------------------------------------------------
# Kind coercion (string → enum), total, with the common recon aliases.
# ---------------------------------------------------------------------------

# Aliases fold a raw recon/target vocabulary onto the canonical NodeKind set. A
# target's `type` from a finding bridge ("ip", "url", "arn", …) resolves the same
# way whether it arrives as an asset record or a finding target.
_NODE_ALIASES: dict[str, NodeKind] = {
    "host": NodeKind.HOST, "ip": NodeKind.HOST, "ipv4": NodeKind.HOST,
    "ipv6": NodeKind.HOST, "subdomain": NodeKind.HOST, "machine": NodeKind.HOST,
    "service": NodeKind.SERVICE, "port": NodeKind.SERVICE, "listener": NodeKind.SERVICE,
    "endpoint": NodeKind.ENDPOINT, "url": NodeKind.ENDPOINT, "route": NodeKind.ENDPOINT,
    "webapp": NodeKind.WEBAPP, "web": NodeKind.WEBAPP,
    "datastore": NodeKind.DATASTORE, "database": NodeKind.DATASTORE, "db": NodeKind.DATASTORE,
    "bucket": NodeKind.DATASTORE, "secretstore": NodeKind.DATASTORE,
    "cloud_resource": NodeKind.CLOUD_RESOURCE, "cloud": NodeKind.CLOUD_RESOURCE,
    "arn": NodeKind.CLOUD_RESOURCE, "resource": NodeKind.CLOUD_RESOURCE,
    "network_segment": NodeKind.NETWORK_SEGMENT, "segment": NodeKind.NETWORK_SEGMENT,
    "subnet": NodeKind.NETWORK_SEGMENT, "vpc": NodeKind.NETWORK_SEGMENT,
    "principal": NodeKind.PRINCIPAL, "role": NodeKind.PRINCIPAL, "user": NodeKind.PRINCIPAL,
    "serviceaccount": NodeKind.PRINCIPAL, "identity_actor": NodeKind.PRINCIPAL,
    "credential": NodeKind.CREDENTIAL, "secret": NodeKind.CREDENTIAL,
    "token": NodeKind.CREDENTIAL, "key": NodeKind.CREDENTIAL,
    "session": NodeKind.SESSION,
    "control": NodeKind.CONTROL, "waf": NodeKind.CONTROL, "mfa": NodeKind.CONTROL,
    "finding": NodeKind.FINDING, "vuln_finding": NodeKind.FINDING,
    "domain": NodeKind.DOMAIN, "certificate": NodeKind.CERTIFICATE, "cert": NodeKind.CERTIFICATE,
    "asn": NodeKind.ASN, "netblock": NodeKind.NETBLOCK, "cidr": NodeKind.NETBLOCK,
    "organization": NodeKind.ORGANIZATION, "org": NodeKind.ORGANIZATION,
    "identity": NodeKind.IDENTITY, "persona": NodeKind.IDENTITY,
    "application": NodeKind.APPLICATION, "app": NodeKind.APPLICATION,
    "package": NodeKind.PACKAGE, "dependency": NodeKind.PACKAGE, "technology": NodeKind.PACKAGE,
    "tech": NodeKind.PACKAGE,
    # A CVE is a threat-intel LEAD, never a confirmed FINDING (see models.NodeKind docs).
    "cve": NodeKind.VULNERABILITY, "vulnerability": NodeKind.VULNERABILITY, "advisory": NodeKind.VULNERABILITY,
    "indicator": NodeKind.INDICATOR, "ioc": NodeKind.INDICATOR,
}


def _to_node_kind(raw: Any) -> Optional[NodeKind]:
    """Coerce a raw string to a NodeKind (canonical value or a recon alias). Total —
    returns None for an unrecognised kind so the caller can fail-closed on it."""
    s = str(raw or "").strip().lower()
    if not s:
        return None
    if s in _NODE_ALIASES:
        return _NODE_ALIASES[s]
    try:
        return NodeKind(s)
    except ValueError:
        return None


def _to_edge_kind(raw: Any) -> Optional[EdgeKind]:
    """Coerce a raw string to an EdgeKind by its canonical value. Total (None on miss)."""
    s = str(raw or "").strip().lower()
    if not s:
        return None
    try:
        return EdgeKind(s)
    except ValueError:
        return None


# The default edge kind a finding uses to EVIDENCE a fact about an asset. EVIDENCES is
# an annotation edge — NOT a movement/reachability edge — so pathsearch (which scopes on
# an explicit attack-movement `edge_kinds` set) never traverses it. A finding cannot
# fabricate reach; the reach it enables must be recorded as its own `relation` record,
# belief-grounded by that finding's oracle evidence.
_FINDING_EVIDENCE_EDGE = EdgeKind.EVIDENCES


# ---------------------------------------------------------------------------
# The spine record contract
# ---------------------------------------------------------------------------


class AssetSpineRecord(BaseModel):
    """One signed spine record fed to the asset-topology projector.

    In production these are adapted from the CRUCIBLE signed offense spine (recon
    observations, oracle-confirmed findings, and the reachability they establish);
    the projector never trusts a field's *claim* of confirmation — it re-derives it
    from the signed evidence (:func:`_finding_confirmed`).

    Discriminated by ``kind``:

      * ``asset``    — assert one typed node. Needs ``node_id`` + ``node_kind``.
      * ``relation`` — assert one typed directed edge ``src -> dst`` of ``edge_kind``.
        May carry ``src_kind`` / ``dst_kind`` to mint an endpoint that no ``asset``
        record declared (else a relation whose endpoint is unknown is skipped).
      * ``finding``  — a vulnerability. Projects a ``FINDING`` node whose grounding is
        re-derived; ``targets`` (``[{type,value}]``) and ``affects`` (node ids) become
        the assets it EVIDENCES.
      * ``refute``   — a grounded Beta refutation of a prior node/edge (lowers belief).
    """

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0, description="Monotonic spine index — the deterministic temporal coordinate.")
    hash: str = Field(min_length=1, description="This record's signed hash (tiebreak + provenance).")
    kind: str = Field(description="asset | relation | finding | refute.")

    # signed-spine veracity (a finding is CONFIRMED only with BOTH of these)
    status: str = "lead"                 # lead | fact
    evidence_ref: str = ""               # signed oracle evidence cert id
    signature_ref: str = ""              # signed-head / signature reference

    # belief + provenance (both optional; conservative, grounded defaults when absent)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    provenance: str = ""                 # explicit spine provenance; else derived from grounding

    attrs: dict[str, Any] = Field(default_factory=dict)

    # asset
    node_id: str = ""
    node_kind: str = ""

    # relation
    src: str = ""
    dst: str = ""
    edge_kind: str = ""
    src_kind: str = ""                   # optional: mint src if no asset record declared it
    dst_kind: str = ""                   # optional: mint dst if no asset record declared it

    # finding
    finding_ref: str = ""
    targets: list[dict[str, Any]] = Field(default_factory=list)   # [{"type":..,"value":..}]
    affects: list[str] = Field(default_factory=list)              # node ids the finding evidences

    # refute
    refutes_id: str = ""                 # a node id, OR "src|edge_kind|dst" for an edge


def _finding_confirmed(rec: AssetSpineRecord) -> bool:
    """A finding is CONFIRMED iff it is an oracle-minted FACT carrying a non-empty signed
    ``evidence_ref`` AND ``signature_ref`` — mirrors the F2 Finding invariant and the
    chain projector. A bare ``status="fact"`` with no signed evidence is a LEAD."""
    return (rec.status == "fact"
            and bool((rec.evidence_ref or "").strip())
            and bool((rec.signature_ref or "").strip()))


def _grounded(rec: AssetSpineRecord) -> bool:
    """A non-finding record (asset/relation/refute) is oracle-grounded iff it carries BOTH
    a signed ``evidence_ref`` and ``signature_ref`` — e.g. a lateral-movement reach the
    oracle confirmed. Otherwise it is intel (a recon lead)."""
    return bool((rec.evidence_ref or "").strip()) and bool((rec.signature_ref or "").strip())


def _belief_and_prov(rec: AssetSpineRecord, *, grounded: bool, tag: str) -> tuple[float, str]:
    """The (confidence, provenance) a write asserts. Confidence: the explicit spine value
    if present (faithful, clamped in the model), else a conservative default keyed on
    grounding — never manufacturing certainty. Provenance: the explicit spine string if
    present, else derived with an ``oracle:`` / ``intel:`` prefix so
    ``classify_provenance`` tags the correct grounding tier."""
    if rec.confidence is not None:
        conf = rec.confidence
    else:
        conf = _CONFIRMED_DEFAULT if grounded else _LEAD_DEFAULT
    if rec.provenance.strip():
        prov = rec.provenance.strip()
    elif grounded:
        prov = f"oracle:{(rec.evidence_ref or rec.hash).strip()}"
    else:
        prov = f"intel:{tag}:{(rec.finding_ref or rec.hash).strip()}"
    return conf, prov


# ---------------------------------------------------------------------------
# Node application (pass A)
# ---------------------------------------------------------------------------


def _mint_node(world: WorldModel, nid: str, kind: NodeKind, conf: float, prov: str,
               seq: int, attrs: dict[str, Any] | None = None) -> None:
    world.add_node(Node(id=nid, kind=kind, attrs=dict(attrs or {}),
                        provenance=prov, confidence=conf, first_seen=seq, last_seen=seq))


def _apply_nodes(world: WorldModel, rec: AssetSpineRecord) -> None:
    kind = (rec.kind or "").lower()
    if kind == KIND_ASSET:
        nk = _to_node_kind(rec.node_kind)
        if nk is None or not rec.node_id.strip():
            return
        conf, prov = _belief_and_prov(rec, grounded=_grounded(rec), tag="asset")
        _mint_node(world, rec.node_id.strip(), nk, conf, prov, rec.seq, rec.attrs)
        return

    if kind == KIND_RELATION:
        # Mint endpoints ONLY when the relation names their kind (else they must be
        # declared by their own asset record — we never invent a node of unknown kind).
        conf, prov = _belief_and_prov(rec, grounded=_grounded(rec), tag="relation")
        for nid, nk_raw in ((rec.src, rec.src_kind), (rec.dst, rec.dst_kind)):
            nid = nid.strip()
            nk = _to_node_kind(nk_raw)
            if nid and nk is not None and not world.has_node(nid):
                _mint_node(world, nid, nk, conf, prov, rec.seq)
        return

    if kind == KIND_FINDING:
        fid = f"finding:{(rec.finding_ref or rec.hash).strip()}"
        confirmed = _finding_confirmed(rec)
        conf, prov = _belief_and_prov(rec, grounded=confirmed, tag="finding")
        f_attrs = dict(rec.attrs)
        f_attrs.setdefault("status", "fact" if confirmed else "lead")
        f_attrs.setdefault("confirmed", confirmed)
        _mint_node(world, fid, NodeKind.FINDING, conf, prov, rec.seq, f_attrs)
        # the assets a finding names (recon targets) become typed nodes too — a finding's
        # bridge target inherits INTEL grounding (the recon fact), not the finding's proof.
        for t in rec.targets:
            if not isinstance(t, dict):
                continue
            nk = _to_node_kind(t.get("type"))
            val = str(t.get("value", "")).strip()
            if nk is None or not val:
                continue
            tid = f"{nk.value}:{val}"
            if not world.has_node(tid):
                _mint_node(world, tid, nk, _LEAD_DEFAULT if rec.confidence is None else rec.confidence,
                           f"intel:target:{val}", rec.seq, {"value": val})
        return
    # asset placeholders for a refute's endpoints are NOT minted — a refute never creates.


# ---------------------------------------------------------------------------
# Edge application (pass B)
# ---------------------------------------------------------------------------


def _add_edge_if_endpoints(world: WorldModel, src: str, dst: str, ek: EdgeKind,
                           conf: float, prov: str, seq: int, attrs: dict[str, Any] | None = None) -> bool:
    """Add a typed edge only when BOTH endpoints already exist — never invent a node to
    carry an edge (that would fabricate topology). Returns True if the edge was written."""
    if not (world.has_node(src) and world.has_node(dst)):
        return False
    world.add_edge(Edge(src=src, dst=dst, kind=ek, attrs=dict(attrs or {}),
                        provenance=prov, confidence=conf, first_seen=seq, last_seen=seq))
    return True


def _apply_edges(world: WorldModel, rec: AssetSpineRecord) -> None:
    kind = (rec.kind or "").lower()
    if kind == KIND_RELATION:
        ek = _to_edge_kind(rec.edge_kind)
        if ek is None or not rec.src.strip() or not rec.dst.strip():
            return
        conf, prov = _belief_and_prov(rec, grounded=_grounded(rec), tag="relation")
        _add_edge_if_endpoints(world, rec.src.strip(), rec.dst.strip(), ek, conf, prov, rec.seq, rec.attrs)
        return

    if kind == KIND_FINDING:
        fid = f"finding:{(rec.finding_ref or rec.hash).strip()}"
        confirmed = _finding_confirmed(rec)
        conf, prov = _belief_and_prov(rec, grounded=confirmed, tag="finding")
        # EVIDENCES edges: finding -> each affected/target asset. Annotation, not reach.
        dsts: list[str] = [a.strip() for a in rec.affects if str(a).strip()]
        for t in rec.targets:
            if not isinstance(t, dict):
                continue
            nk = _to_node_kind(t.get("type"))
            val = str(t.get("value", "")).strip()
            if nk is not None and val:
                dsts.append(f"{nk.value}:{val}")
        for dst in dsts:
            _add_edge_if_endpoints(world, fid, dst, _FINDING_EVIDENCE_EDGE, conf, prov, rec.seq)
        return


# ---------------------------------------------------------------------------
# Refutation (pass B, grounded-only) — a Beta demotion, not a delete.
# ---------------------------------------------------------------------------


def _apply_refute(world: WorldModel, rec: AssetSpineRecord) -> None:
    """A grounded refutation re-observes the target node/edge with confidence 0.0, so the
    WorldModel's conjugate Beta update lowers ``belief_mean`` / ``belief_lcb`` (the signal a
    max-confidence scalar cannot express). Grounded-only: a bare (unauthenticated) refute is
    ignored — an opinion cannot demote a proof. Never deletes; the node/edge stays for audit,
    only its belief drops (so a risk-averse ``lcb_weight`` route ranking discounts it)."""
    if (rec.kind or "").lower() != KIND_REFUTE:
        return
    if not _grounded(rec):
        return
    target = (rec.refutes_id or "").strip()
    if not target:
        return
    prov = rec.provenance.strip() or f"oracle:{(rec.evidence_ref or rec.hash).strip()}"
    if "|" in target:   # an edge key "src|edge_kind|dst"
        parts = target.split("|")
        if len(parts) != 3:
            return
        src, ek_raw, dst = (p.strip() for p in parts)
        ek = _to_edge_kind(ek_raw)
        if ek is None:
            return
        existing = world.get_edge(src, dst, ek)
        if existing is None:
            return
        # re-observe as a refutation (confidence 0.0 → Beta beta bump); keep the max scalar
        # (upsert reconciles to max) but drop the belief mean/lcb.
        world.add_edge(Edge(src=src, dst=dst, kind=ek, provenance=prov, confidence=0.0,
                            first_seen=rec.seq, last_seen=rec.seq))
        return
    node = world.get_node(target)
    if node is None:
        return
    world.add_node(Node(id=target, kind=node.kind, provenance=prov, confidence=0.0,
                        first_seen=rec.seq, last_seen=rec.seq))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _sort_key(rec: AssetSpineRecord) -> tuple[int, str, str]:
    """Total order (seq, hash, canonical body) so two records sharing (seq, hash) still sort
    deterministically. The body is computed DEFENSIVELY — a record carrying a
    non-JSON-serialisable prop must not crash the sort (totality over the whole list)."""
    try:
        body = rec.model_dump_json()
    except Exception:   # noqa: BLE001
        body = repr(sorted(str(k) for k in (rec.attrs or {})))
    return (rec.seq, rec.hash, body)


def records_from_dicts(rows: Any) -> list[AssetSpineRecord]:
    """Parse a list of dicts (a JSON spine document) into AssetSpineRecords. Total on a lossy
    loader — a row that is not a valid record is skipped, never crashed on."""
    out: list[AssetSpineRecord] = []
    for row in (rows or []):
        if isinstance(row, AssetSpineRecord):
            out.append(row)
            continue
        if not isinstance(row, dict):
            continue
        try:
            out.append(AssetSpineRecord(**row))
        except Exception:   # noqa: BLE001 — one malformed row must not sink the projection
            continue
    return out


def project_spine(records: Any, *, strict_grounding: bool = False) -> WorldModel:
    """Project a list of signed spine records into a ``worldmodel.WorldModel`` asset topology —
    the ONLY writer. Deterministic: records are applied in ``(seq, hash, body)`` order in two
    passes (all nodes, then all edges + refutations), so an edge never races its endpoints and
    the same spine rebuilds a byte-identical WorldModel. A finding is CONFIRMED only when its
    record carries signed oracle evidence; everything else is a LEAD. Never raises on a
    malformed record LIST — a non-record / malformed element is skipped, not crashed on.

    ``strict_grounding`` forwards to the WorldModel: an UNGROUNDED (LLM/assumption-provenance)
    write is seeded at a low belief floor rather than its asserted confidence."""
    recs = records if (records and isinstance(records[0], AssetSpineRecord)) else records_from_dicts(records)
    recs = [r for r in recs if isinstance(r, AssetSpineRecord)]
    recs.sort(key=_sort_key)

    world = WorldModel(strict_grounding=strict_grounding)
    # Pass A — every node-producing effect (asset nodes, minted relation endpoints,
    # finding nodes + their target assets).
    for rec in recs:
        try:
            _apply_nodes(world, rec)
        except Exception:   # noqa: BLE001 — a malformed record must not abort the whole projection
            continue
    # Pass B — every edge-producing effect + grounded refutations.
    for rec in recs:
        try:
            _apply_edges(world, rec)
            _apply_refute(world, rec)
        except Exception:   # noqa: BLE001
            continue
    return world
