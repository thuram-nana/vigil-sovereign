"""F4 slice S3 — charter objectives projected as INERT ``Goal`` read-model nodes (default-OFF behind
``VIGIL_GRAPH_OBJECTIVES``). One deterministic, offline test per acceptance item. The through-line every
test defends: a Goal is NEVER a FACT — it carries no evidence_ref, is never returned by
``confirmed_findings()``, authorizes nothing — and the projection is additive, flag-gated, scope-gated,
bi-temporal and byte-identically absent when the flag is off.

Framework-free (imports only ``vigil_integration``), so it runs in the sovereign CI leg exactly like
``test_graph_projection.py`` — no ``framework`` importorskip, no ci.yml offense-leg registration needed."""

from __future__ import annotations

import json

import pytest

from vigil_integration.graph import (
    ConfirmationStatus,
    EdgeType,
    NodeLabel,
    OBJECTIVES_ENV,
    ObjectiveContext,
    SpineRecord,
    objectives,
    objectives_enabled,
    project,
    query_prior_chains,
)
from vigil_integration.tools import redact_tool_args


# --- helpers ---------------------------------------------------------------------------------

def _chain(seq, h, cid="C", **props):
    return SpineRecord(seq=seq, hash=h, kind="chain", chain_id=cid, props=props)


def _step(seq, h, sid="S", cid="C", objective_id="", **props):
    return SpineRecord(seq=seq, hash=h, kind="step", step_id=sid, chain_id=cid,
                       objective_id=objective_id, props=props)


def _goal(seq, h, oid, *, status="lead", evidence_ref="", signature_ref="", **props):
    return SpineRecord(seq=seq, hash=h, kind="goal", objective_id=oid, status=status,
                       evidence_ref=evidence_ref, signature_ref=signature_ref, props=props)


def _reach(seq, h, oid, targets, *, status="lead", evidence_ref="", signature_ref=""):
    return SpineRecord(seq=seq, hash=h, kind="reach", objective_id=oid, status=status,
                       evidence_ref=evidence_ref, signature_ref=signature_ref, targets=targets)


# --- 1. Flag OFF: goal/reach are unknown kinds; view byte-identical to the pre-slice read-model ----

def test_flag_off_goal_record_ignored_view_byte_identical_to_preslice():
    pre = [_chain(1, "c"), _step(2, "s")]
    with_s3 = [
        _chain(1, "c"),
        _step(2, "s", objective_id="O1"),                       # step declares an objective id
        _goal(3, "g", "O1", title="exfil"),                     # a charter objective
        _reach(4, "r", "O1", [{"type": "host", "value": "in.tld"}],
               status="fact", evidence_ref="cert", signature_ref="sig"),
    ]
    off = project(with_s3, objectives=False)
    base = project(pre, objectives=False)
    # the S3 records project NOTHING with the flag off (goal/reach are unknown kinds, step.objective_id
    # adds no edge) → the view is byte-identical to the spine with the S3 records removed.
    assert off.model_dump() == base.model_dump()
    assert off.active_nodes(NodeLabel.OBJECTIVE) == []
    assert [e for e in off.edges if e.type in (EdgeType.REACHES, EdgeType.PURSUES)] == []


# --- 2. Flag ON: a 'goal' record → ONE OBJECTIVE node on a stable id; re-project MERGEs ------------

def test_flag_on_goal_projects_one_objective_node_and_merges_on_reproject():
    recs = [_goal(1, "g", "OBJ-1", title="exfil customer DB")]
    view = project(recs, objectives=True)
    objs = view.active_nodes(NodeLabel.OBJECTIVE)
    assert len(objs) == 1
    assert objs[0].id == "objective:OBJ-1" and objs[0].label == NodeLabel.OBJECTIVE
    assert objs[0].props.get("title") == "exfil customer DB"
    # re-projecting the SAME objective id MERGEs on the same node key, never duplicates
    view2 = project(recs + [_goal(2, "g2", "OBJ-1", title="exfil customer DB")], objectives=True)
    assert len(view2.active_nodes(NodeLabel.OBJECTIVE)) == 1
    # a different id is a distinct node
    view3 = project(recs + [_goal(2, "g2", "OBJ-2", title="other")], objectives=True)
    assert {n.id for n in view3.active_nodes(NodeLabel.OBJECTIVE)} == {"objective:OBJ-1", "objective:OBJ-2"}


# --- 3. Flag ON: a crown-jewel a PathCertificate reaches → Asset-[REACHES]->Goal, path's confirmation -

def test_flag_on_reach_projects_asset_reaches_goal_inheriting_path_confirmation():
    gate = lambda h: h == "jewel.in.tld"
    # a CONFIRMED (signed/verified) path → a confirmed REACHES edge
    v_fact = project([
        _goal(1, "g", "OBJ", title="own the datastore"),
        _reach(2, "r", "OBJ", [{"type": "host", "value": "jewel.in.tld"}],
               status="fact", evidence_ref="path-cert:9", signature_ref="sig:9"),
    ], objectives=True, scope_gate=gate)
    reaches = [e for e in v_fact.edges if e.type == EdgeType.REACHES]
    assert len(reaches) == 1
    assert reaches[0].src == "host:jewel.in.tld" and reaches[0].dst == "objective:OBJ"
    assert reaches[0].provenance.confirmation == ConfirmationStatus.CONFIRMED
    assert reaches[0].provenance.evidence_ref == "path-cert:9"       # edge carries the path's proof
    # the asset NODE is a plain recon node (never itself confirmed/evidenced)
    asset = v_fact.get("host:jewel.in.tld")
    assert asset.label == NodeLabel.HOST and asset.provenance.confirmation == ConfirmationStatus.LEAD

    # an UNPROVEN (lead) route → a LEAD edge carrying no evidence (a lead route is a lead edge)
    v_lead = project([
        _goal(1, "g", "OBJ", title="own the datastore"),
        _reach(2, "r", "OBJ", [{"type": "host", "value": "jewel.in.tld"}], status="lead"),
    ], objectives=True, scope_gate=gate)
    le = [e for e in v_lead.edges if e.type == EdgeType.REACHES][0]
    assert le.provenance.confirmation == ConfirmationStatus.LEAD and le.provenance.evidence_ref == ""


# --- 4. Flag ON: ChainStep-[PURSUES]->Goal from the step's objective id; none ⇒ NO edge -----------

def test_flag_on_step_pursues_goal_only_with_declared_objective_id():
    view = project([
        _step(1, "s1", sid="S1", objective_id="OBJ"),      # declares an objective id → PURSUES edge
        _step(2, "s2", sid="S2"),                          # NO objective id → no PURSUES edge
    ], objectives=True)
    pursues = [e for e in view.edges if e.type == EdgeType.PURSUES]
    assert len(pursues) == 1
    assert pursues[0].src == "step:S1" and pursues[0].dst == "objective:OBJ"
    # linkage is never fabricated: the step with no objective id produces no PURSUES edge at all
    assert all(e.src != "step:S2" for e in pursues)
    assert pursues[0].provenance.confirmation == ConfirmationStatus.LEAD   # a plan-intent link, never a proof


# --- 5. A Goal is INERT: no evidence_ref, never confirmed, never a FACT ----------------------------

def test_goal_is_inert_even_when_the_record_claims_fact_with_evidence():
    # a goal record that CLAIMS status=fact with a signed evidence+signature STILL projects LEAD with no
    # evidence_ref — a Goal can never launder itself into a FACT.
    view = project([_goal(1, "g", "OBJ", status="fact", evidence_ref="cert:1",
                          signature_ref="sig:1", title="t")], objectives=True)
    g = view.get("objective:OBJ")
    assert g.provenance.confirmation == ConfirmationStatus.LEAD
    assert g.provenance.evidence_ref == ""              # carries NO evidence ref
    assert g.is_confirmed is False                      # is_confirmed gates on CHAIN_FINDING only
    assert g not in view.confirmed_findings()           # never returned as a confirmed finding/FACT
    assert view.confirmed_findings() == []
    # and it is not a finding at all — lead_findings (ChainFinding leads) excludes it too
    assert view.lead_findings() == []


# --- 6. Flag ON: bi-temporal retirement applies to Goal nodes/edges (retire, never delete) ---------

def test_flag_on_withdrawn_objective_retires_never_deletes():
    view = project([
        _goal(1, "g", "OBJ", title="t"),
        _reach(2, "r", "OBJ", [{"type": "host", "value": "in.tld"}],
               status="fact", evidence_ref="c", signature_ref="s"),
        _step(3, "s", sid="S", objective_id="OBJ"),
        SpineRecord(seq=4, hash="x", kind="refute", refutes_id="objective:OBJ"),   # objective withdrawn
    ], objectives=True, scope_gate=lambda h: h == "in.tld")
    g = view.get("objective:OBJ")
    assert g is not None and g.invalid_from == 4 and not g.is_active   # retired, STILL PRESENT (audit)
    assert view.active_nodes(NodeLabel.OBJECTIVE) == []                # excluded from active queries
    # every edge touching the retired Goal (REACHES in, PURSUES in) is retired with it
    touching = [e for e in view.edges if e.dst == "objective:OBJ"]
    assert touching and all(not e.is_active for e in touching)
    assert objectives(view).objectives == []                          # and from the Goal read surface


# --- 7. Flag ON: a Goal/edge bridging to a host clears the EXISTING scope gate ---------------------

def test_flag_on_out_of_scope_host_cannot_enter_under_the_goal_path():
    recs = [
        _goal(1, "g", "OBJ", title="t"),
        _reach(2, "r", "OBJ", [{"type": "host", "value": "evil.tld"},
                               {"type": "endpoint", "value": "https://evil.tld/admin"},
                               {"type": "port", "value": "evil.tld:22"}],
               status="fact", evidence_ref="c", signature_ref="s"),
    ]
    # the SAME _host_in_scope gate the finding bridges use: a denied host enters under NO label
    denied = project(recs, objectives=True, scope_gate=lambda h: False)
    assert denied.active_nodes(NodeLabel.HOST) == []
    assert denied.active_nodes(NodeLabel.ENDPOINT) == []
    assert denied.active_nodes(NodeLabel.PORT) == []
    assert [e for e in denied.edges if e.type == EdgeType.REACHES] == []    # no asset → no REACHES
    assert denied.get("objective:OBJ") is not None                          # the Goal itself still projects
    # an in-scope host admits the reach
    allowed = project(recs, objectives=True, scope_gate=lambda h: h == "evil.tld")
    assert {e.src for e in allowed.edges if e.type == EdgeType.REACHES} >= {"host:evil.tld"}


# --- 8. Flag ON: a read surfacing a Goal stays retrieval_only / non-authoritative ----------------

def test_flag_on_goal_read_surface_is_non_authoritative_and_frozen():
    view = project([_goal(1, "g", "OBJ", title="exfil")], objectives=True)
    ctx = objectives(view)
    assert isinstance(ctx, ObjectiveContext)
    assert ctx.authoritative is False and ctx.retrieval_only is True      # grants nothing
    assert {o.objective_id for o in ctx.objectives} == {"OBJ"}
    # the context is FROZEN — a consumer cannot flip the flags to fabricate authority
    with pytest.raises(Exception):
        ctx.authoritative = True
    with pytest.raises(Exception):
        ctx.retrieval_only = False
    # the prior-chain retrieval surface is likewise unaffected: a Goal never becomes a confirmed finding
    pcc = query_prior_chains(view)
    assert pcc.authoritative is False and pcc.confirmed_findings == []


# --- 9. Additive-for-others: flag ON for a spine with NO goal records == flag OFF ------------------

def test_flag_on_is_byte_identical_to_off_for_a_spine_with_no_goal_records():
    spine = [
        _chain(1, "c", objective="o"),
        _step(2, "s1", sid="S1", tool="nmap"),
        SpineRecord(seq=3, hash="f1", kind="finding", finding_ref="F", status="fact",
                    evidence_ref="c", signature_ref="s", parent_step_id="S1", props={"ref": "F"}),
    ]
    on = project(spine, objectives=True)
    off = project(spine, objectives=False)
    assert on.model_dump() == off.model_dump()    # no goal/reach kinds, no step.objective_id → ON adds nothing


# --- 10. No secrets: a Goal's props pass the EXISTING F3 redactor before export/label -------------

def test_flag_on_goal_props_pass_the_existing_f3_redactor():
    # a charter objective is free text; it must not leak a credential/host-userinfo into a label on export.
    view = project([_goal(1, "g", "OBJ",
                          title="own the DB",
                          description="pivot via Authorization: Bearer sk-live-LEAK123 then dump",
                          password="hunter2secret",
                          note="reach https://admin:pw-LEAK@in.tld/db")], objectives=True)
    g = view.get("objective:OBJ")
    # reuse the ONE F3 redactor the Neo4j export path runs on node props (tools.redact_tool_args)
    redacted = redact_tool_args(g.props)
    blob = json.dumps(redacted)
    for leaked in ("sk-live-LEAK123", "hunter2secret", "pw-LEAK"):
        assert leaked not in blob, leaked                  # every secret is masked before it can be a label
    assert "pivot via" in blob and "own the DB" in blob    # non-secret free text survives (still useful)


# --- the flag wiring itself: DEFAULT-OFF behind VIGIL_GRAPH_OBJECTIVES ----------------------------

def test_env_flag_default_off_truth_table_and_env_driven_projection(monkeypatch):
    # affirmative-flag convention: only {1,true,yes,on} (case-insensitive) is ON; default/anything else OFF
    assert objectives_enabled(env={}) is False
    assert objectives_enabled(env={OBJECTIVES_ENV: ""}) is False
    assert objectives_enabled(env={OBJECTIVES_ENV: "0"}) is False
    assert objectives_enabled(env={OBJECTIVES_ENV: "maybe"}) is False
    for on in ("1", "true", "YES", "On"):
        assert objectives_enabled(env={OBJECTIVES_ENV: on}) is True
    # project() with objectives=None reads the env flag: unset ⇒ OFF ⇒ byte-identical to pre-slice
    recs = [_goal(1, "g", "OBJ", title="t")]
    monkeypatch.delenv(OBJECTIVES_ENV, raising=False)
    assert project(recs).model_dump() == project([], objectives=False).model_dump()
    assert project(recs).active_nodes(NodeLabel.OBJECTIVE) == []
    # opting in via the env flag projects the inert Goal
    monkeypatch.setenv(OBJECTIVES_ENV, "1")
    assert {n.id for n in project(recs).active_nodes(NodeLabel.OBJECTIVE)} == {"objective:OBJ"}
