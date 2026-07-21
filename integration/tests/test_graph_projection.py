"""F4 slice-1 — the attack-chain graph as a signed-spine projection. The through-line every test
defends: the graph is a DERIVED read-model that can never launder an unproven claim into a fact — a
finding is CONFIRMED only on signed oracle evidence, a lead is a distinct state that no query returns
as a fact, projection is deterministic/rebuildable, a refuted lead is retired (never deleted), and the
whole view is inert (it authorizes nothing)."""

from __future__ import annotations

from vigil_integration.agent.state import Finding
from vigil_integration.graph import (
    ConfirmationStatus,
    EdgeType,
    NodeLabel,
    SpineRecord,
    project,
    query_prior_chains,
    spine_record_from_finding,
    successful_tools,
)


def _finding_rec(seq, h, *, ref, status="lead", evidence_ref="", signature_ref="", severity="high",
                 parent_step_id="", targets=None, **props):
    return SpineRecord(seq=seq, hash=h, kind="finding", finding_ref=ref, status=status,
                       evidence_ref=evidence_ref, signature_ref=signature_ref, parent_step_id=parent_step_id,
                       props={"ref": ref, "severity": severity, **props}, targets=targets or [])


# --- the anti-trust-laundering core ----------------------------------------------------------

def test_claimed_fact_without_signed_evidence_is_a_lead():
    # a record can CLAIM status="fact" but with no signed evidence_ref/signature_ref it is a LEAD.
    recs = [
        _finding_rec(1, "h1", ref="f-claim", status="fact"),                        # no evidence, no sig
        _finding_rec(2, "h2", ref="f-evonly", status="fact", evidence_ref="cert:1"),  # evidence, NO sig
        _finding_rec(3, "h3", ref="f-sigonly", status="fact", signature_ref="sig:1"),  # sig, NO evidence
        _finding_rec(4, "h4", ref="f-real", status="fact", evidence_ref="cert:9", signature_ref="sig:9"),
    ]
    view = project(recs)
    conf = {n.props["ref"] for n in view.confirmed_findings()}
    leads = {n.props["ref"] for n in view.lead_findings()}
    assert conf == {"f-real"}                                   # ONLY the fully-signed one is confirmed
    assert leads == {"f-claim", "f-evonly", "f-sigonly"}        # every partial claim is a lead
    # the confirmed node carries the signed evidence; the leads carry none
    real = next(n for n in view.confirmed_findings())
    assert real.provenance.evidence_ref == "cert:9"
    for n in view.lead_findings():
        assert n.provenance.evidence_ref == "" and n.provenance.confirmation == ConfirmationStatus.LEAD


def test_lead_can_upgrade_to_confirmed_but_never_downgrade():
    # a finding first seen as a lead, later oracle-confirmed (same finding_ref) → the SAME node upgrades.
    view = project([
        _finding_rec(1, "h1", ref="f1", status="lead"),
        _finding_rec(2, "h2", ref="f1", status="fact", evidence_ref="cert:1", signature_ref="sig:1"),
    ])
    assert len(view.active_nodes(NodeLabel.CHAIN_FINDING)) == 1     # merged, not duplicated
    assert {n.props["ref"] for n in view.confirmed_findings()} == {"f1"}
    # a later bare lead record for the same finding cannot DOWNGRADE the signed fact
    view2 = project([
        _finding_rec(1, "h1", ref="f1", status="fact", evidence_ref="cert:1", signature_ref="sig:1"),
        _finding_rec(2, "h2", ref="f1", status="lead"),
    ])
    assert {n.props["ref"] for n in view2.confirmed_findings()} == {"f1"}   # stays confirmed


def test_query_prior_chains_never_returns_a_lead_as_confirmed():
    view = project([
        _finding_rec(1, "h1", ref="lead-1", status="lead", severity="critical", target="t"),
        _finding_rec(2, "h2", ref="fact-1", status="fact", evidence_ref="c", signature_ref="s",
                     severity="high", target="t"),
    ])
    ctx = query_prior_chains(view, target="t")
    assert ctx.authoritative is False and ctx.retrieval_only is True        # non-authoritative contract
    assert {f.ref for f in ctx.confirmed_findings} == {"fact-1"}            # confirmed only
    assert {f.ref for f in ctx.leads} == {"lead-1"}                        # leads kept separate
    assert all(f.evidence_ref for f in ctx.confirmed_findings)             # each confirmed carries proof


# --- bi-temporal: refute retires, never deletes ----------------------------------------------

def test_refute_retires_lead_but_keeps_it_for_audit():
    view = project([
        _finding_rec(1, "h1", ref="f-lead", status="lead", severity="high", target="t"),
        SpineRecord(seq=2, hash="r1", kind="refute", refutes_id="finding:f-lead"),
    ])
    node = view.get("finding:f-lead")
    assert node is not None and node.invalid_from == 2 and not node.is_active   # retired, still present
    assert view.lead_findings() == []                                          # excluded from active
    assert query_prior_chains(view, target="t").leads == []                    # and from retrieval


def test_bare_refute_cannot_demote_a_confirmed_fact():
    # RED-PEN BLOCK-1: an unauthenticated refute (no evidence/signature) must NOT drop a signed fact —
    # per the veracity firewall, demotion comes only from a re-execution failing (a signed refutation).
    v_bare = project([
        _finding_rec(1, "h1", ref="f-proven", status="fact", evidence_ref="cert:1", signature_ref="sig:1"),
        SpineRecord(seq=2, hash="r1", kind="refute", refutes_id="finding:f-proven"),   # bare opinion
    ])
    assert {n.id for n in v_bare.confirmed_findings()} == {"finding:f-proven"}   # fact survives
    # an ORACLE-GROUNDED refutation (signed evidence a re-execution failed) MAY demote the fact
    v_signed = project([
        _finding_rec(1, "h1", ref="f-proven", status="fact", evidence_ref="cert:1", signature_ref="sig:1"),
        SpineRecord(seq=2, hash="r1", kind="refute", refutes_id="finding:f-proven",
                    evidence_ref="refute-cert:9", signature_ref="sig:9"),
    ])
    assert v_signed.confirmed_findings() == [] and not v_signed.get("finding:f-proven").is_active
    # a bare refute may still retire an unproven LEAD (safe direction)
    v_lead = project([
        _finding_rec(1, "h1", ref="f-lead", status="lead"),
        SpineRecord(seq=2, hash="r1", kind="refute", refutes_id="finding:f-lead"),
    ])
    assert v_lead.lead_findings() == [] and not v_lead.get("finding:f-lead").is_active


def test_prior_chain_context_is_frozen():
    # RED-PEN BLOCK-2: the non-authoritative flags are immutable — a consumer cannot flip them.
    import pytest as _pytest
    ctx = query_prior_chains(project([]))
    assert ctx.authoritative is False and ctx.retrieval_only is True
    with _pytest.raises(Exception):
        ctx.authoritative = True
    with _pytest.raises(Exception):
        ctx.retrieval_only = False


def test_projection_deterministic_on_duplicate_seq_hash():
    # RED-PEN LOW-1: two records sharing (seq, hash) with different content must still sort to a total
    # order → byte-identical view regardless of input order.
    r1 = SpineRecord(seq=5, hash="dup", kind="finding", finding_ref="z", status="fact",
                     evidence_ref="c", signature_ref="s", props={"ref": "z", "severity": "low"})
    r2 = SpineRecord(seq=5, hash="dup", kind="finding", finding_ref="z", status="fact",
                     evidence_ref="c", signature_ref="s", props={"ref": "z", "severity": "critical"})
    assert project([r1, r2]).model_dump() == project([r2, r1]).model_dump()


def test_scope_gate_blocks_out_of_scope_host_under_any_label():
    # RED-PEN LOW-3: an out-of-scope host must not re-enter as an endpoint/port node either.
    recs = [_finding_rec(1, "h1", ref="f", status="fact", evidence_ref="c", signature_ref="s",
                         targets=[{"type": "host", "value": "evil.tld"},
                                  {"type": "endpoint", "value": "https://evil.tld/admin"},
                                  {"type": "port", "value": "evil.tld:22"},
                                  {"type": "cve", "value": "CVE-2024-1"}])]
    view = project(recs, scope_gate=lambda h: False)   # deny all hosts
    assert view.active_nodes(NodeLabel.HOST) == []
    assert view.active_nodes(NodeLabel.ENDPOINT) == []       # endpoint host gated too
    assert view.active_nodes(NodeLabel.PORT) == []           # port host gated too
    assert {n.props["value"] for n in view.active_nodes(NodeLabel.CVE)} == {"CVE-2024-1"}   # cve not host-scoped
    # an in-scope host admits all its bridges
    v2 = project(recs, scope_gate=lambda h: h == "evil.tld")
    assert {n.label for n in v2.active_nodes()} >= {NodeLabel.HOST, NodeLabel.ENDPOINT, NodeLabel.PORT}


def test_ipv6_and_backslash_endpoints_cannot_smuggle_a_host(monkeypatch):
    # RE-CHECK S1 (HIGH): a bracketed IPv6 endpoint must NOT collapse to an empty host that bypasses the
    # gate — incl. the IPv4-mapped-IPv6 metadata-smuggle. RE-CHECK S2: a backslash-authority endpoint is
    # client-independent (gated under BOTH readings).
    smuggles = [
        {"type": "endpoint", "value": "https://[::ffff:169.254.169.254]/latest/meta-data/"},
        {"type": "endpoint", "value": "https://[::1]:8080/"},
        {"type": "endpoint", "value": "https://[::]/"},
        {"type": "endpoint", "value": "https://evil.tld\\@in-scope.tld/"},   # backslash authority-confusion
        {"type": "port", "value": "[::1]:22"},
    ]
    for t in smuggles:
        v = project([_finding_rec(1, "h1", ref="f", status="fact", evidence_ref="c", signature_ref="s",
                                  targets=[t])], scope_gate=lambda h: h == "in-scope.tld")
        assert v.active_nodes(NodeLabel.ENDPOINT) == [] and v.active_nodes(NodeLabel.PORT) == [], t
    # a genuinely in-scope endpoint (incl. its IPv6 loopback) is admitted when the gate allows the host
    v_ok = project([_finding_rec(1, "h1", ref="f", status="fact", evidence_ref="c", signature_ref="s",
                                 targets=[{"type": "endpoint", "value": "https://[::1]:9/x"}])],
                   scope_gate=lambda h: h == "::1")
    assert len(v_ok.active_nodes(NodeLabel.ENDPOINT)) == 1


def test_projection_total_on_nonjson_prop_value():
    # RE-CHECK S3: a typed SpineRecord carrying a non-JSON-serializable prop must not crash the sort/rebuild.
    class Unser:
        pass
    recs = [SpineRecord(seq=1, hash="h", kind="finding", finding_ref="f", status="lead",
                        props={"x": Unser()}),
            SpineRecord(seq=2, hash="h2", kind="finding", finding_ref="g", status="fact",
                        evidence_ref="c", signature_ref="s", props={"y": b"\xff\xfe", "ref": "g"})]
    view = project(recs)     # must not raise
    assert {n.id for n in view.confirmed_findings()} == {"finding:g"}


def test_confirmation_resurrects_a_lead_retired_by_a_bare_refute():
    # RE-CHECK S4: lead → BARE refute (retires) → oracle CONFIRMS later. The proven fact must NOT stay
    # suppressed by the earlier unauthenticated opinion.
    view = project([
        _finding_rec(1, "a", ref="z", status="lead"),
        SpineRecord(seq=2, hash="r", kind="refute", refutes_id="finding:z"),           # bare opinion
        _finding_rec(3, "c", ref="z", status="fact", evidence_ref="cert", signature_ref="sig"),  # oracle proof
    ])
    assert {n.id for n in view.confirmed_findings()} == {"finding:z"}     # resurrected as a confirmed fact
    assert view.get("finding:z").is_active
    # but an ORACLE-GROUNDED refute is NOT auto-resurrected by a later confirm (contradiction stays retired)
    view2 = project([
        _finding_rec(1, "a", ref="z", status="lead"),
        SpineRecord(seq=2, hash="r", kind="refute", refutes_id="finding:z",
                    evidence_ref="rc", signature_ref="rs"),              # signed refutation
        _finding_rec(3, "c", ref="z", status="fact", evidence_ref="cert", signature_ref="sig"),
    ])
    assert view2.confirmed_findings() == [] and not view2.get("finding:z").is_active


def test_resurrected_fact_reconnects_its_edges():
    # RE-CHECK MEDIUM: a resurrected fact must be fully connected — its producing tool must reappear in
    # successful_tools (not left disconnected by the earlier refute).
    view = project([
        SpineRecord(seq=1, hash="s1", kind="step", step_id="S", props={"tool": "sqlmap"}),
        _finding_rec(2, "a", ref="z", status="lead", parent_step_id="S"),
        SpineRecord(seq=3, hash="r", kind="refute", refutes_id="finding:z"),           # bare refute
        _finding_rec(4, "c", ref="z", status="fact", evidence_ref="cert", signature_ref="sig",
                     parent_step_id="S"),                                              # oracle confirms
    ])
    assert successful_tools(view) == ["sqlmap"]     # the producing tool is not dropped


def test_refute_retires_touching_edges():
    view = project([
        SpineRecord(seq=1, hash="c1", kind="chain", chain_id="C"),
        SpineRecord(seq=2, hash="s1", kind="step", step_id="S", chain_id="C"),
        _finding_rec(3, "h1", ref="f", status="lead", parent_step_id="S"),
        SpineRecord(seq=4, hash="r1", kind="refute", refutes_id="finding:f"),
    ])
    produced = [e for e in view.edges if e.type == EdgeType.PRODUCED]
    assert produced and all(not e.is_active for e in produced)   # edges off the retired finding retired


# --- rebuildable + deterministic -------------------------------------------------------------

def test_projection_is_deterministic_regardless_of_record_order():
    recs = [
        SpineRecord(seq=3, hash="h3", kind="finding", finding_ref="f", status="fact",
                    evidence_ref="c", signature_ref="s", parent_step_id="S", props={"ref": "f"}),
        SpineRecord(seq=1, hash="h1", kind="chain", chain_id="C"),
        SpineRecord(seq=2, hash="h2", kind="step", step_id="S", chain_id="C", prev_step_id="S0"),
    ]
    a = project(recs).model_dump()
    b = project(list(reversed(recs))).model_dump()
    assert a == b        # same records, any order → byte-identical view (rebuildable from the spine)


# --- scope-gated bridges ---------------------------------------------------------------------

def test_host_bridge_respects_scope_gate():
    recs = [_finding_rec(1, "h1", ref="f", status="fact", evidence_ref="c", signature_ref="s",
                         targets=[{"type": "host", "value": "in-scope.tld"},
                                  {"type": "host", "value": "out-of-scope.tld"},
                                  {"type": "cve", "value": "CVE-2024-1"}])]
    view = project(recs, scope_gate=lambda h: h == "in-scope.tld")
    hosts = {n.props["value"] for n in view.active_nodes(NodeLabel.HOST)}
    cves = {n.props["value"] for n in view.active_nodes(NodeLabel.CVE)}
    assert hosts == {"in-scope.tld"}                 # out-of-scope host never becomes a node
    assert cves == {"CVE-2024-1"}                    # non-host bridges are not host-scoped


def test_scope_gate_error_is_fail_closed():
    def boom(_h):
        raise RuntimeError("gate down")
    view = project([_finding_rec(1, "h1", ref="f", status="fact", evidence_ref="c", signature_ref="s",
                                 targets=[{"type": "host", "value": "x.tld"}])], scope_gate=boom)
    assert view.active_nodes(NodeLabel.HOST) == []   # a gate error excludes the host (fail-closed)


# --- structural projection + idempotency -----------------------------------------------------

def test_chain_step_finding_structure_and_merge_idempotency():
    recs = [
        SpineRecord(seq=1, hash="c1", kind="chain", chain_id="C", props={"objective": "o"}),
        SpineRecord(seq=2, hash="s1", kind="step", step_id="S1", chain_id="C", props={"tool": "nmap"}),
        SpineRecord(seq=3, hash="s2", kind="step", step_id="S2", chain_id="C", prev_step_id="S1"),
        _finding_rec(4, "f1", ref="F", status="fact", evidence_ref="c", signature_ref="s",
                     parent_step_id="S2"),
        SpineRecord(seq=5, hash="x1", kind="failure", parent_step_id="S1",
                    props={"lesson_learned": "WAF blocks bulk", "tool": "hydra"}),
        SpineRecord(seq=6, hash="d1", kind="decision", parent_step_id="S2", props={"why": "pivot"}),
    ]
    view = project(recs)
    etypes = {e.type for e in view.edges}
    assert {EdgeType.HAS_STEP, EdgeType.NEXT_STEP, EdgeType.PRODUCED, EdgeType.LED_TO,
            EdgeType.FAILED_WITH, EdgeType.DECISION_PRECEDED} <= etypes
    # re-projecting the SAME spine does not duplicate nodes/edges (MERGE idempotency)
    view2 = project(recs + recs)
    assert len(view2.nodes) == len(view.nodes) and len(view2.edges) == len(view.edges)


# --- retrieval helpers -----------------------------------------------------------------------

def test_successful_tools_only_counts_confirmed():
    recs = [
        SpineRecord(seq=1, hash="s1", kind="step", step_id="S1", props={"tool": "sqlmap"}),
        SpineRecord(seq=2, hash="s2", kind="step", step_id="S2", props={"tool": "nuclei"}),
        _finding_rec(3, "f1", ref="F1", status="fact", evidence_ref="c", signature_ref="s",
                     parent_step_id="S1"),                                   # confirmed via sqlmap
        _finding_rec(4, "f2", ref="F2", status="lead", parent_step_id="S2"),  # only a lead via nuclei
    ]
    view = project(recs)
    assert successful_tools(view) == ["sqlmap"]        # nuclei produced only a lead → excluded


def test_failure_lessons_surfaced_in_retrieval():
    view = project([SpineRecord(seq=1, hash="x1", kind="failure",
                                props={"lesson_learned": "rate-limited over 5 r/s", "tool": "ffuf"})])
    ctx = query_prior_chains(view)
    assert len(ctx.failure_lessons) == 1 and "rate-limited" in ctx.failure_lessons[0].lesson


# --- F2 bridge -------------------------------------------------------------------------------

def test_f2_finding_bridge_confirms_only_with_signature():
    fact = Finding(ref="f-fact", status="fact", evidence_ref="spine:abc", severity="critical")
    lead = Finding(ref="f-lead", status="lead", severity="low")
    # a fact projected WITHOUT the spine signature is still a lead (not yet signed on the spine)
    v_unsigned = project([spine_record_from_finding(fact, seq=1, hash="h1")])
    assert v_unsigned.confirmed_findings() == [] and len(v_unsigned.lead_findings()) == 1
    # with the spine signature ref, it confirms
    v_signed = project([spine_record_from_finding(fact, seq=1, hash="h1", signature_ref="sig:1")])
    assert {n.props["ref"] for n in v_signed.confirmed_findings()} == {"f-fact"}
    # an F2 lead is always a lead
    v_lead = project([spine_record_from_finding(lead, seq=1, hash="h2", signature_ref="sig:2")])
    assert v_lead.confirmed_findings() == []


# --- totality --------------------------------------------------------------------------------

def test_projection_is_total_on_malformed_records():
    # the typed SpineRecord rejects a structurally-invalid target at CONSTRUCTION (fail-closed boundary);
    # the projector tolerates unrecognized kinds, empty/partial targets, and a dangling refute.
    recs = [
        SpineRecord(seq=1, hash="h1", kind="bogus_kind"),                       # unknown kind → nothing
        SpineRecord(seq=2, hash="h2", kind="finding", finding_ref="f", status="fact",
                    evidence_ref="c", signature_ref="s",
                    targets=[{"nope": 1}, {"type": "host"}, {"type": "", "value": "x"}]),  # partial/empty
        SpineRecord(seq=3, hash="h3", kind="refute", refutes_id="finding:does-not-exist"),  # dangling
        SpineRecord(seq=4, hash="h4", kind="refute", refutes_id=""),            # empty refute target
    ]
    # RED-PEN LOW-2: a non-SpineRecord element in the list (a torn/None row from a lossy loader) must
    # be skipped, not crash the whole rebuild.
    recs = recs + [None, "not-a-record", {"seq": 9, "hash": "h"}, 123]
    view = project(recs)     # must not raise
    assert [n.id for n in view.confirmed_findings()] == ["finding:f"]
    assert view.active_nodes(NodeLabel.HOST) == []          # no valid host target → no host node
    # query is total on a non-view
    assert query_prior_chains("not-a-view").confirmed_findings == []
    assert successful_tools(None) == []
