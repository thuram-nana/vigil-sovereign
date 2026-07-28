"""
WS1b — the LIVE Neo4j binder for the F4 graph read-model.

The through-line every test defends is the SOVEREIGN INVARIANT of the graph fusion, carried unchanged
into the live backend:

  * Only oracle-confirmed FACT spine records become ``:ChainFinding:Confirmed`` Neo4j nodes; a LEAD is a
    DISTINCT label (``:Lead``) and can NEVER be written as / queried as confirmed — not even a record
    that *claims* ``status="fact"`` with no signed evidence (the adversarial case), and not even a lead
    re-projection that collides with a foreign engagement's surviving confirmed node (the cross-partition
    aliasing case the red-pen found).
  * The Neo4j view is a PURE PROJECTION of the signed spine: ``rebuild_from_spine`` clears + re-projects
    via ``graph.project``, so the mirror equals the in-memory projection (no parallel truth) and is
    byte-identically rebuildable.
  * No authority is read FROM Neo4j — reads return non-authoritative retrieval context.
  * Cypher is PARAMETERIZED: a hostile finding field can never inject Cypher (it appears only in bound
    params, never in a query string).
  * Fail-closed + total: no session factory / a session error / a malformed record → no write, no rows,
    never a raise.
  * Secret-free: an inline credential in a finding field is F3-redacted before it reaches a node.

Everything runs against a FAKE in-memory Neo4j session — the live driver is never required. Crucially the
fake models the two live-backend semantics the sovereign invariant depends on FAITHFULLY: (1) ``MERGE``
matches by exactly the identity map written in the Cypher (so an engagement-scoped MERGE isolates and an
unscoped one aliases — the exact dimension the HIGH finding turned on); (2) ``SET n:<label>`` is ADDITIVE
(unions labels, never replaces), so a stale ``:Confirmed`` survives unless explicitly removed; (3) an
out-of-64-bit integer / non-finite float is rejected by the driver. A fake that fudged any of these would
green-wash the invariant while the real backend violated it.
"""

from __future__ import annotations

import json
import math
import re

import pytest

from vigil_integration.graph import SpineRecord, project
from vigil_integration.live.graph_neo4j import (
    TRIAGE_CYPHER,
    MirrorResult,
    Neo4jGraphWriter,
    may_remediate,
)
from vigil_integration.remediation.triage import TriageFinding


# =============================================================================================
# a Neo4j-FAITHFUL in-memory fake — it records every (cypher, params) and EXECUTES the writer's exact
# parameterized query shapes with real Neo4j semantics: MERGE matches by the identity map literally
# written in the query (engagement-scoped or not), ``SET n = row.props`` REPLACES properties, and
# ``SET n:<label>`` UNIONS labels (``REMOVE n:<label>`` removes them). Because the fake matches whatever
# identity the writer emits, an unscoped ``MERGE {id}`` would alias across engagements here (making the
# HIGH break observable) and the shipped engagement-scoped ``MERGE {id, engagement_id}`` isolates.
# =============================================================================================


def _backtick_labels(segment: str) -> set[str]:
    return set(re.findall(r"`([^`]+)`", segment))


def _prop_map(body: str) -> list[tuple[str, str]]:
    """Parse an inline Cypher property map body (``id: row.id, engagement_id: $engagement_id``) into
    (key, source) pairs, where source is ``row.<field>`` or ``$<param>``."""
    pairs: list[tuple[str, str]] = []
    for part in body.split(","):
        part = part.strip()
        if not part:
            continue
        k, _, v = part.partition(":")
        pairs.append((k.strip(), v.strip()))
    return pairs


def _resolve(src: str, row: dict, params: dict):
    """Resolve a MERGE/MATCH identity source against the current row / bound params (faithful to how the
    driver binds ``row.<field>`` and ``$<param>``)."""
    if src.startswith("row."):
        return row.get(src[4:])
    if src.startswith("$"):
        return params.get(src[1:])
    return src.strip("'\"")


def _neo4j_storable(value) -> bool:
    """Model the driver's storability check: integers must fit signed 64-bit, floats must be finite,
    lists must be storable element-wise. A non-storable value makes ``run`` raise (like the real driver)."""
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -(2 ** 63) <= value <= 2 ** 63 - 1
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, (list, tuple)):
        return all(_neo4j_storable(x) for x in value)
    return True


class _Store:
    """A small faithful property graph. Nodes are a LIST (a shared id can legitimately have one copy per
    engagement partition), edges reference node objects by identity so ``DETACH DELETE`` is faithful."""

    def __init__(self) -> None:
        self._nodes: list[dict] = []                     # each {"labels": set[str], "props": dict}
        self.edges: list[dict] = []                      # each {"a": node, "b": node, "type", "props"}
        self.calls: list[tuple[str, dict]] = []          # every (cypher, params) issued

    # -- faithful MERGE/MATCH: a node whose labels include ``label`` and whose props equal every
    #    identity pair. This is exactly Neo4j's MERGE-match semantics for the emitted patterns. --
    def match(self, label: str, ident: dict) -> dict | None:
        for n in self._nodes:
            if label in n["labels"] and all(n["props"].get(k) == v for k, v in ident.items()):
                return n
        return None

    # -- test-facing accessors (ids can collide across engagements, so eid disambiguates) --
    def all_nodes(self) -> list[dict]:
        return self._nodes

    def node_ids(self) -> set[str]:
        return {str(n["props"].get("id")) for n in self._nodes}

    def _find(self, nid: str, eid: str | None = None) -> dict | None:
        hits = [n for n in self._nodes if n["props"].get("id") == nid
                and (eid is None or n["props"].get("engagement_id") == eid)]
        assert len(hits) <= 1, f"ambiguous id {nid!r} across engagements — pass eid"
        return hits[0] if hits else None

    def has_node(self, nid: str, eid: str | None = None) -> bool:
        return self._find(nid, eid) is not None

    def node(self, nid: str, eid: str | None = None) -> dict:
        n = self._find(nid, eid)
        if n is None:
            raise KeyError(nid)
        return n

    def confirmed_ids(self, eid: str | None = None) -> set[str]:
        return {str(n["props"].get("id")) for n in self._nodes
                if {"ChainFinding", "Confirmed"} <= n["labels"]
                and (eid is None or n["props"].get("engagement_id") == eid)}

    def lead_ids(self, eid: str | None = None) -> set[str]:
        return {str(n["props"].get("id")) for n in self._nodes
                if {"ChainFinding", "Lead"} <= n["labels"]
                and (eid is None or n["props"].get("engagement_id") == eid)}

    def seed_node(self, *, id: str, engagement_id: str, labels: set[str], **props) -> None:
        self._nodes.append({"labels": set(labels),
                            "props": {"id": id, "engagement_id": engagement_id, **props}})


class FakeSession:
    def __init__(self, store: _Store, *, fail: bool = False) -> None:
        self._store = store
        self._fail = fail

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *_a) -> bool:
        return False

    def close(self) -> None:
        pass

    def run(self, cypher, parameters=None, **kw):
        if self._fail:
            raise RuntimeError("simulated neo4j failure")
        params = dict(parameters or {})
        params.update(kw)
        self._store.calls.append((cypher, params))
        if "DETACH DELETE" in cypher:
            self._clear(params)
            return None
        if cypher.startswith("UNWIND $rows") and "MERGE (n:" in cypher:
            self._write_nodes(cypher, params)
            return None
        if cypher.startswith("UNWIND $rows") and "MERGE (a)" in cypher:
            self._write_edges(cypher, params)
            return None
        if "RETURN properties(n)" in cypher:
            return self._read(cypher, params)
        return None

    # -- writes -------------------------------------------------------------------------------
    def _clear(self, params: dict) -> None:
        # MATCH (n:`VigilNode` {engagement_id: $engagement_id}) DETACH DELETE n
        eid = params.get("engagement_id")
        dead = {id(n) for n in self._store._nodes if n["props"].get("engagement_id") == eid}
        self._store._nodes = [n for n in self._store._nodes if id(n) not in dead]
        self._store.edges = [e for e in self._store.edges
                             if id(e["a"]) not in dead and id(e["b"]) not in dead]

    def _write_nodes(self, cypher: str, params: dict) -> None:
        m = re.search(r"MERGE \(n:`([^`]+)`\s*\{([^}]*)\}\)", cypher)
        merge_label, ident_spec = m.group(1), _prop_map(m.group(2))
        set_labels: set[str] = set()
        remove_labels: set[str] = set()
        for line in cypher.splitlines():
            s = line.strip()
            if s.startswith("SET n:"):
                set_labels |= _backtick_labels(s)
            elif s.startswith("REMOVE n:"):
                remove_labels |= _backtick_labels(s)
        for row in params.get("rows", []):
            ident = {k: _resolve(src, row, params) for k, src in ident_spec}
            props = dict(row["props"])
            # a real driver rejects an unstorable value → the run raises; the writer must coerce BEFORE
            # a value reaches $rows, so a poisoned field degrades to a smaller mirror, not a hard denial.
            for v in props.values():
                if not _neo4j_storable(v):
                    raise RuntimeError("neo4j: value not storable (out-of-64-bit / non-finite)")
            node = self._store.match(merge_label, ident)
            if node is None:                             # MERGE: no match → CREATE with identity + label
                node = {"labels": {merge_label}, "props": dict(ident)}
                self._store._nodes.append(node)
            node["props"] = props                        # SET n = row.props → wholesale property replace
            node["labels"].add(merge_label)              # MERGE label persists a property replace
            node["labels"] -= remove_labels              # REMOVE n:Confirmed REMOVE n:Lead
            node["labels"] |= set_labels                 # SET n:<current> → UNION (additive, like Neo4j)

    def _write_edges(self, cypher: str, params: dict) -> None:
        endpoints = re.findall(r"MATCH \((\w+):`([^`]+)`\s*\{([^}]*)\}\)", cypher)
        m = re.search(r"\[r:`([^`]+)`\]", cypher)
        etype = m.group(1) if m else ""
        for row in params.get("rows", []):
            matched: dict[str, dict] = {}
            ok = True
            for var, label, body in endpoints:
                ident = {k: _resolve(src, row, params) for k, src in _prop_map(body)}
                nd = self._store.match(label, ident)
                if nd is None:                           # an unmatched endpoint yields no row → no edge
                    ok = False
                    break
                matched[var] = nd
            if not ok:
                continue
            a, b = matched["a"], matched["b"]
            existing = next((e for e in self._store.edges
                             if e["a"] is a and e["b"] is b and e["type"] == etype), None)
            if existing is None:
                existing = {"a": a, "b": b, "type": etype, "props": {}}
                self._store.edges.append(existing)
            existing["props"] = dict(row["props"])

    # -- reads --------------------------------------------------------------------------------
    def _read(self, cypher: str, params: dict) -> list[dict]:
        first_line = cypher.split("\n", 1)[0]
        required = _backtick_labels(first_line)          # e.g. {ChainFinding, Confirmed} or {…, Lead}
        out = []
        for node in sorted(self._store._nodes, key=lambda nn: str(nn["props"].get("id"))):
            p = node["props"]
            if not required <= node["labels"]:
                continue
            if "n.engagement_id = $engagement_id" in cypher and p.get("engagement_id") != params.get(
                    "engagement_id"):
                continue
            if "n.invalid_from IS NULL" in cypher and p.get("invalid_from") is not None:
                continue
            if "severities" in params and str(p.get("severity", "")).lower() not in params["severities"]:
                continue
            if "n.target = $target" in cypher and p.get("target") != params.get("target"):
                continue
            if "n.cisa_kev = true OR n.exploit_available = true" in cypher and not (
                    p.get("cisa_kev") or p.get("exploit_available")):
                continue
            if "size(n.cve_ids) > 0" in cypher and not (p.get("cve_ids") or []):
                continue
            if "n.target <> ''" in cypher and not p.get("target"):
                continue
            if "size(n.attack_chain_path) > 0" in cypher and not (p.get("attack_chain_path") or []):
                continue
            out.append({"n": dict(p)})
        return out


def _factory(store: _Store, *, fail: bool = False):
    return lambda: FakeSession(store, fail=fail)


# =============================================================================================
# record builders
# =============================================================================================


def _confirmed(seq: int, ref: str, *, severity: str = "high", host: str | None = "127.0.0.1",
               **props) -> SpineRecord:
    base = {"ref": ref, "title": f"finding {ref}", "severity": severity, "bug_class": "sqli"}
    base.update(props)
    return SpineRecord(seq=seq, hash=f"h{seq}", kind="finding", engagement_id="eng-1",
                       signature_ref=f"sig{seq}", status="fact", evidence_ref=f"scitt:cert-{seq}",
                       finding_ref=ref, props=base,
                       targets=[{"type": "host", "value": host}] if host else [])


def _lead(seq: int, ref: str, *, claims_fact: bool = False, host: str | None = None,
          **props) -> SpineRecord:
    base = {"ref": ref, "title": f"lead {ref}", "severity": "medium", "bug_class": "xss"}
    base.update(props)
    # claims_fact=True is the adversarial case: status="fact" but NO signed evidence/signature → LEAD.
    return SpineRecord(seq=seq, hash=f"h{seq}", kind="finding", engagement_id="eng-1",
                       signature_ref="", status="fact" if claims_fact else "lead", evidence_ref="",
                       finding_ref=ref, props=base,
                       targets=[{"type": "host", "value": host}] if host else [])


# =============================================================================================
# tests
# =============================================================================================


def test_rebuild_writes_confirmed_and_lead_as_distinct_labels():
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    res = w.rebuild_from_spine([_confirmed(1, "F-1", severity="critical"), _lead(2, "F-2")])
    assert isinstance(res, MirrorResult) and res.ok and res.cleared
    assert res.confirmed == 1 and res.leads == 1
    assert store.confirmed_ids() == {"finding:F-1"}
    assert store.lead_ids() == {"finding:F-2"}
    # the confirmed node carries the signed evidence ref; the lead never does
    assert store.node("finding:F-1")["props"]["evidence_ref"] == "scitt:cert-1"
    assert "evidence_ref" not in store.node("finding:F-2")["props"]
    # a bridge (host) node + FOUND_ON edge were mirrored too
    assert store.has_node("host:127.0.0.1")
    assert any(e["type"] == "FOUND_ON" for e in store.edges)


def test_adversarial_lead_claiming_fact_never_becomes_confirmed():
    """THE sovereign invariant. A record that CLAIMS status='fact' but carries no signed evidence/
    signature is a LEAD — it must NEVER be written as, or queried as, confirmed."""
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    w.rebuild_from_spine([
        _confirmed(1, "REAL", severity="critical"),
        _lead(2, "FAKE", claims_fact=True),          # unauthenticated 'looks like a fact'
    ])
    # write side: FAKE never carries the Confirmed label
    assert "finding:FAKE" not in store.confirmed_ids()
    assert "finding:FAKE" in store.lead_ids()
    # query side: query_confirmed returns ONLY the oracle-confirmed fact
    confirmed = w.query_confirmed()
    assert [f.ref for f in confirmed] == ["REAL"]
    assert all(f.evidence_ref for f in confirmed)     # every confirmed row carries signed proof
    # the lead is surfaced only in the SEPARATE leads channel
    assert [f.ref for f in w.query_leads()] == ["FAKE"]
    # and the F10 triage over Neo4j can never draft the lead
    draft = w.run_triage()
    assert [f.ref for f in draft.findings] == ["REAL"]
    assert "FAKE" not in {f.ref for f in draft.findings}
    assert [f.ref for f in draft.leads] == ["FAKE"]
    ok, _ = may_remediate(draft.findings[0])
    assert ok is True
    lead_ok, _ = may_remediate(draft.leads[0])
    assert lead_ok is False                            # a lead can never spawn a remediation


def test_cross_engagement_isolation_lead_never_aliases_a_foreign_confirmed():
    """HIGH regression (+ the faithful-fake MEDIUM). Finding ``F-1`` is an oracle-CONFIRMED fact in
    engagement A and a bare LEAD in engagement B in the SAME database, sharing a bridge ``host:127.0.0.1``
    node. B's clear only reaches B's partition, so A's confirmed ``finding:F-1`` survives. With the
    engagement-scoped MERGE identity (``{id, engagement_id}``) + per-write ``REMOVE :Confirmed :Lead``,
    B's lead re-projection can NEVER alias A's surviving node, flip its engagement/props, and leave a
    stale ``:Confirmed`` on it. Driven through a Neo4j-FAITHFUL fake (MERGE matches the literal identity
    map, ``SET n:<label>`` is additive) so the exact live-backend break the red-pen found is observable
    rather than hidden — an unscoped ``MERGE {id}`` would alias here and fail this test."""
    store = _Store()
    w_a = Neo4jGraphWriter(_factory(store), group_id="eng-A")
    w_b = Neo4jGraphWriter(_factory(store), group_id="eng-B")

    # A: F-1 is a signed FACT on host 127.0.0.1
    assert w_a.rebuild_from_spine([_confirmed(1, "F-1", severity="critical", host="127.0.0.1")]).ok
    # B (same DB): the SAME finding_ref is only a LEAD, sharing the bridge host node
    assert w_b.rebuild_from_spine([_lead(2, "F-1", host="127.0.0.1")]).ok

    # two distinct nodes now share the id 'finding:F-1' — one per engagement partition, never aliased
    assert store.confirmed_ids(eid="eng-A") == {"finding:F-1"}
    assert store.confirmed_ids(eid="eng-B") == set()
    assert store.lead_ids(eid="eng-B") == {"finding:F-1"}
    # the shared bridge host id exists once PER engagement, isolated
    assert store.has_node("host:127.0.0.1", eid="eng-A")
    assert store.has_node("host:127.0.0.1", eid="eng-B")

    # THE sovereign assertion: B's lead is NEVER queryable as confirmed; A's fact is untouched
    assert w_b.query_confirmed() == []
    assert [f.ref for f in w_b.query_leads()] == ["F-1"]
    assert w_b.run_triage().findings == []                     # the lead can never spawn a codefix
    assert [f.ref for f in w_a.query_confirmed()] == ["F-1"]
    assert all(f.evidence_ref for f in w_a.query_confirmed())

    # A's node was NOT flipped: still confirmed-only, still carries its signed evidence, still eng-A
    a_node = store.node("finding:F-1", eid="eng-A")
    assert {"ChainFinding", "Confirmed"} <= a_node["labels"]
    assert "Lead" not in a_node["labels"]
    assert a_node["props"]["engagement_id"] == "eng-A"
    assert a_node["props"]["evidence_ref"] == "scitt:cert-1"
    # B's node is a lead-only, evidence-less copy
    b_node = store.node("finding:F-1", eid="eng-B")
    assert {"ChainFinding", "Lead"} <= b_node["labels"]
    assert "Confirmed" not in b_node["labels"]
    assert "evidence_ref" not in b_node["props"]


def test_lead_reprojection_in_same_engagement_removes_stale_confirmed_label():
    """The label-reset half of the HIGH fix, isolated. A ``finding:F-1`` that was CONFIRMED and, on a
    later spine, is only a LEAD must lose its ``:Confirmed`` label — the additive ``SET n:<label>`` must
    be preceded by ``REMOVE :Confirmed :Lead`` or a stale confirmation would persist and be queryable."""
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    assert w.rebuild_from_spine([_confirmed(1, "F-1", severity="critical", host="127.0.0.1")]).ok
    assert store.confirmed_ids() == {"finding:F-1"}
    # re-project the SAME engagement with F-1 now only a lead (a demotion / lost proof)
    assert w.rebuild_from_spine([_lead(2, "F-1", host="127.0.0.1")]).ok
    node = store.node("finding:F-1", eid="eng-1")
    assert "Confirmed" not in node["labels"]           # stale confirmation label reset, not unioned
    assert {"ChainFinding", "Lead"} <= node["labels"]
    assert w.query_confirmed() == []
    assert [f.ref for f in w.query_leads()] == ["F-1"]


def test_out_of_range_scalar_degrades_to_smaller_mirror_not_whole_denial():
    """LOW regression. A hostile allowlisted finding field set to an out-of-64-bit integer must be
    DROPPED at coercion (a smaller mirror) — it must never reach ``$rows`` where a real driver rejects
    the write and denies the ENTIRE engagement's mirror. The faithful fake rejects an out-of-range value
    exactly like the driver, so had the coercion regressed this rebuild would fail-closed to ok=False."""
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    res = w.rebuild_from_spine([_confirmed(1, "F-1", severity="high", url=10 ** 40)])
    assert res.ok is True                                  # smaller mirror, NOT a whole-rebuild denial
    node = store.node("finding:F-1")
    assert {"ChainFinding", "Confirmed"} <= node["labels"]  # the finding still mirrored + confirmed
    assert "url" not in node["props"]                      # the out-of-range field dropped
    assert node["props"]["severity"] == "high"             # other allowlisted fields survive
    # the poisoned value never reached a bound param
    blob = json.dumps([p for _, p in store.calls], default=str)
    assert str(10 ** 40) not in blob


def test_rebuild_is_pure_projection_and_byte_identically_rebuildable():
    records = [_confirmed(1, "F-1", severity="critical"), _confirmed(3, "F-3", severity="low"),
               _lead(2, "F-2"), _lead(4, "F-4", claims_fact=True)]
    view = project(records, group_id="eng-1")

    store_a, store_b = _Store(), _Store()
    Neo4jGraphWriter(_factory(store_a), group_id="eng-1").rebuild_from_spine(records)
    Neo4jGraphWriter(_factory(store_b), group_id="eng-1").rebuild_from_spine(records)

    # pure projection: the mirrored node set equals graph.project's node set, with the SAME confirmed/
    # lead partition (no parallel truth, nothing invented, nothing dropped)
    assert store_a.node_ids() == set(view.nodes)
    assert store_a.confirmed_ids() == {n.id for n in view.confirmed_findings()}
    assert store_a.lead_ids() == {n.id for n in view.lead_findings()}
    # deterministic: two rebuilds issue byte-identical Cypher + params
    assert store_a.calls == store_b.calls


def test_rebuild_clears_stale_engagement_partition():
    store = _Store()
    # a stale node from a prior run, in the same engagement partition
    store.seed_node(id="finding:STALE", engagement_id="eng-1",
                    labels={"VigilNode", "ChainFinding", "Confirmed"},
                    ref="STALE", evidence_ref="x", severity="high")
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    w.rebuild_from_spine([_confirmed(1, "F-1")])
    assert not store.has_node("finding:STALE")           # cleared before re-projection
    assert store.confirmed_ids() == {"finding:F-1"}


def test_cypher_is_parameterized_no_injection_via_finding_field():
    store = _Store()
    hostile = "x`}) DETACH DELETE n //"                 # a Cypher-injection attempt in a finding title
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    w.rebuild_from_spine([_confirmed(1, "F-1", title=hostile)])
    # the hostile value NEVER appears inside a Cypher STRING — only inside bound params
    for cypher, _params in store.calls:
        assert hostile not in cypher
    # it IS present as a parameter (so it round-trips as data)
    assert store.node("finding:F-1")["props"]["title"] == hostile
    # the ONLY DETACH DELETE issued is the scoped engagement clear, parameterized on engagement_id
    deletes = [(c, p) for c, p in store.calls if "DETACH DELETE" in c]
    assert len(deletes) == 1
    assert "$engagement_id" in deletes[0][0] and deletes[0][1] == {"engagement_id": "eng-1"}


def test_node_properties_are_secret_free():
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    # an inline bearer token in a free-text field + a secret-KEYED prop that is not even allowlisted
    w.rebuild_from_spine([_confirmed(1, "F-1", source="auth via Bearer sk-live-SECRET-abcdef123456",
                                     api_key="sk-KEYED-SECRET-987654")])
    props = store.node("finding:F-1")["props"]
    blob = json.dumps(store.all_nodes(), default=str) + json.dumps([c for c, _ in store.calls]) \
        + json.dumps([p for _, p in store.calls], default=str)
    assert "sk-live-SECRET-abcdef123456" not in blob    # inline secret F3-redacted
    assert "sk-KEYED-SECRET-987654" not in blob          # secret-keyed prop never mirrored
    assert "api_key" not in props                        # off the allowlist entirely
    assert "••••" in props["source"]                     # masked, not dropped


def test_run_triage_ranks_confirmed_and_honours_existing_refs():
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    w.rebuild_from_spine([
        _confirmed(1, "LOW", severity="low"),
        _confirmed(2, "CRIT", severity="critical", cisa_kev=True),
        _confirmed(3, "HIGH", severity="high"),
        _lead(4, "LEAD-1"),
    ])
    draft = w.run_triage()
    # confirmed only, deterministically severity-ranked (critical > high > low), priorities assigned
    assert [f.ref for f in draft.findings] == ["CRIT", "HIGH", "LOW"]
    assert [f.priority for f in draft.findings] == [1, 2, 3]
    assert all(isinstance(f, TriageFinding) and f.confirmed for f in draft.findings)
    assert [f.ref for f in draft.leads] == ["LEAD-1"]
    # high_only drops the low finding
    assert {f.ref for f in w.run_triage(high_only=True).findings} == {"CRIT", "HIGH"}
    # existing_refs excludes already-remediated findings (only NEW ones drafted)
    assert {f.ref for f in w.run_triage(existing_refs={"CRIT"}).findings} == {"HIGH", "LOW"}


def test_query_confirmed_filters_by_target_and_high_only():
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    w.rebuild_from_spine([
        _confirmed(1, "H", severity="high", target="127.0.0.1"),
        _confirmed(2, "M", severity="medium", target="127.0.0.1"),
        _confirmed(3, "OTHER", severity="high", target="10.0.0.5"),
    ])
    assert {f.ref for f in w.query_confirmed(high_only=True)} == {"H", "OTHER"}
    assert {f.ref for f in w.query_confirmed(target="127.0.0.1")} == {"H", "M"}
    assert {f.ref for f in w.query_confirmed(target="127.0.0.1", high_only=True)} == {"H"}
    assert w.query_confirmed(limit=1) and len(w.query_confirmed(limit=1)) == 1


def test_fail_closed_without_session_factory():
    w = Neo4jGraphWriter(None, group_id="eng-1")
    res = w.rebuild_from_spine([_confirmed(1, "F-1")])
    assert res.ok is False and "no session factory" in res.error
    assert w.query_confirmed() == [] and w.query_leads() == []
    draft = w.run_triage()
    assert draft.findings == [] and draft.leads == []


def test_fail_closed_on_session_error():
    store = _Store()
    w = Neo4jGraphWriter(_factory(store, fail=True), group_id="eng-1")
    res = w.rebuild_from_spine([_confirmed(1, "F-1")])
    assert res.ok is False and "session error" in res.error   # never a partial-truth commit, never raise
    assert w.query_confirmed() == []                          # a failing read → no-signal, not a crash
    assert w.run_triage().findings == []


def test_factory_that_raises_is_fail_closed():
    def boom():
        raise RuntimeError("cannot open session")

    w = Neo4jGraphWriter(boom, group_id="eng-1")
    assert w.rebuild_from_spine([_confirmed(1, "F-1")]).ok is False
    assert w.query_confirmed() == []


def test_total_on_malformed_records():
    store = _Store()
    w = Neo4jGraphWriter(_factory(store), group_id="eng-1")
    # garbage / torn rows interleaved with one good confirmed record must not raise
    res = w.rebuild_from_spine([None, 42, "not-a-record", {"seq": 1}, _confirmed(1, "GOOD")])
    assert res.ok is True
    assert store.confirmed_ids() == {"finding:GOOD"}
    # a non-list records argument also degrades cleanly
    assert w.rebuild_from_spine(None).ok is True


def test_triage_cypher_are_parameterized_and_confirmed_only():
    # the 9 F10 triage queries are the documented artifact — assert each is confirmed-scoped, engagement-
    # parameterized, and never selects a Lead
    assert len(TRIAGE_CYPHER) == 9
    for q in TRIAGE_CYPHER:
        assert "`ChainFinding`:`Confirmed`" in q.cypher
        assert "`Lead`" not in q.cypher
        assert "$engagement_id" in q.cypher
        # no record-derived value is interpolated — the only bound params are engagement_id + severities
        assert set(q.params_extra).issubset({"severities"})


# =============================================================================================
# F3 — per-session priors (retrieve_priors): partition-scoped, tagged, deterministic, non-authoritative
# =============================================================================================


def test_retrieve_priors_is_partition_scoped():
    # each session owns a disjoint partition; retrieve_priors(sess-A) never sees sess-B's findings.
    store = _Store()
    Neo4jGraphWriter(_factory(store), group_id="sess-A").rebuild_from_spine(
        [_confirmed(1, "F-1", severity="critical"), _lead(2, "F-2")])
    Neo4jGraphWriter(_factory(store), group_id="sess-B").rebuild_from_spine(
        [_confirmed(3, "F-3", severity="high")])
    priors_a = Neo4jGraphWriter(_factory(store), group_id="sess-A").retrieve_priors(limit=8)
    refs = {p["ref"] for p in priors_a}
    assert "F-1" in refs and "F-2" in refs and "F-3" not in refs        # sess-B is invisible to sess-A
    assert all(p["origin"] == "sess-A" for p in priors_a)               # every row provenance-tagged


def test_retrieve_priors_tags_confirmed_vs_lead_and_never_re_mints_a_fact():
    store = _Store()
    Neo4jGraphWriter(_factory(store), group_id="sess-A").rebuild_from_spine(
        [_confirmed(1, "F-1", severity="critical"), _lead(2, "F-2")])
    priors = Neo4jGraphWriter(_factory(store), group_id="sess-A").retrieve_priors(limit=8)
    by_ref = {p["ref"]: p for p in priors}
    assert by_ref["F-1"]["confirmed"] is True and by_ref["F-2"]["confirmed"] is False
    # retrieve_priors is RETRIEVAL, not authority — it returns plain summaries, mints nothing, and touches
    # no store node (the confirmed count in the graph is unchanged by a retrieval).
    assert store.confirmed_ids(eid="sess-A") == {"finding:F-1"}


def test_retrieve_priors_is_deterministic_confirmed_first_then_severity():
    store = _Store()
    Neo4jGraphWriter(_factory(store), group_id="sess-A").rebuild_from_spine([
        _lead(1, "L-low", severity="low"),
        _confirmed(2, "C-high", severity="high"),
        _confirmed(3, "C-crit", severity="critical"),
    ])
    w = Neo4jGraphWriter(_factory(store), group_id="sess-A")
    order1 = [p["ref"] for p in w.retrieve_priors(limit=8)]
    order2 = [p["ref"] for p in w.retrieve_priors(limit=8)]
    assert order1 == order2                                             # deterministic (no wallclock/rng)
    # confirmed before lead; within confirmed, higher severity first
    assert order1.index("C-crit") < order1.index("C-high") < order1.index("L-low")


def test_retrieve_priors_extra_partitions_unions_with_origin_tags():
    # F4 forward-compat: extra_partitions unions the (consented) connected sessions, each row origin-tagged.
    store = _Store()
    Neo4jGraphWriter(_factory(store), group_id="sess-A").rebuild_from_spine([_confirmed(1, "A-1")])
    Neo4jGraphWriter(_factory(store), group_id="sess-B").rebuild_from_spine([_confirmed(2, "B-1")])
    priors = Neo4jGraphWriter(_factory(store), group_id="sess-A").retrieve_priors(
        limit=8, extra_partitions=["sess-B"])
    origins = {p["ref"]: p["origin"] for p in priors}
    assert origins.get("A-1") == "sess-A" and origins.get("B-1") == "sess-B"


def test_retrieve_priors_is_bounded_and_total():
    store = _Store()
    recs = [_confirmed(i, f"F-{i}") for i in range(1, 20)]
    Neo4jGraphWriter(_factory(store), group_id="sess-A").rebuild_from_spine(recs)
    assert len(Neo4jGraphWriter(_factory(store), group_id="sess-A").retrieve_priors(limit=5)) == 5
    # no session factory → total, empty (never a raise)
    assert Neo4jGraphWriter(None, group_id="sess-A").retrieve_priors() == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
