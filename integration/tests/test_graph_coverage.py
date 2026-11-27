"""F4 slice S5 — a NON-AUTHORITATIVE, honesty-preserving COVERAGE rollup over the combined read-model
(default-OFF behind ``VIGIL_COVERAGE_VIEW``). One deterministic, offline test per acceptance item + the
deep-check refinements. The through-line every test defends: coverage is a CONSUMER, never a producer — it
GRANTS nothing, AUTHORIZES nothing, and NEVER reports silence as CLEAN. A LEAD is never a fact; an un-tested
surface reads ``not_tested`` (not safe); ``tested_no_finding`` REQUIRES a retained benign/negative response
record; an unverified remediation never reads ``verified_fixed``; only ACTIVE (non-retired) nodes count; the
output is byte-deterministic and every label passes the F3 redactor; and with the flag off the query public
API and the projected view are byte-identical to the pre-slice read-model.

Framework-free (imports only ``vigil_integration``): runs in the sovereign CI leg exactly like
``test_graph_objectives.py`` / ``test_graph_lifecycle.py`` — no ``framework`` importorskip, no ci.yml
offense-leg registration needed. Every re-verification the lifecycle leg needs is delegated to an INJECTED
deterministic fake; no wallclock / RNG / network anywhere.
"""

from __future__ import annotations

import ast
import io
import json
import tokenize
from pathlib import Path
from typing import Optional

import pytest

from vigil_integration.graph import (
    COVERAGE_ENV,
    AssetCoverage,
    CoverageView,
    EdgeType,
    FindingCoverage,
    FindingLink,
    GoalCoverage,
    NodeLabel,
    RetestSeries,
    RetestTick,
    SpineRecord,
    coverage_view_enabled,
    project,
)
from vigil_integration.graph import query as query_mod
from vigil_integration.graph.coverage import (
    NOT_TESTED,
    REMEDIATION_ABSENT,
    REMEDIATION_PRESENT,
    RETEST_INCONCLUSIVE,
    RETEST_NONE,
    RETEST_STILL_VULNERABLE,
    RETEST_VERIFIED_FIXED,
    TESTED,
    TESTED_NO_FINDING,
    coverage,
)

_COVERAGE_SRC = Path(__file__).resolve().parents[1] / "vigil_integration" / "graph" / "coverage.py"

# The FROZEN pre-slice public surface of ``graph.query`` (the exact set of non-underscore names in the
# module namespace BEFORE S5). S5 adds ONLY a module ``__getattr__`` (dunder), so this set must be unchanged
# and must NEVER gain ``coverage`` — the coverage read is served lazily, flag-gated, not bound here.
_PRESLICE_QUERY_PUBLIC = frozenset({
    "Any", "BaseModel", "ConfigDict", "EVIDENCE_JOIN_UNRESOLVED", "EdgeType", "FailureLesson", "Field",
    "FindingSummary", "GraphView", "LifecycleContext", "NO_RETEST", "NodeLabel", "ObjectiveContext",
    "ObjectiveSummary", "Optional", "PriorChainContext", "RemediationSummary", "RetestSummary", "annotations",
    "lifecycle_chains", "model_serializer", "objectives", "query_prior_chains", "successful_tools",
})


# --- builders (all framework-free, deterministic) ------------------------------------------------

def _goal(seq, h, oid, **props):
    return SpineRecord(seq=seq, hash=h, kind="goal", objective_id=oid, status="lead", props=props)


def _step(seq, h, sid, oid="", **props):
    return SpineRecord(seq=seq, hash=h, kind="step", step_id=sid, objective_id=oid, props=props)


def _reach(seq, h, oid, targets, *, status="fact", ev="c", sig="s"):
    return SpineRecord(seq=seq, hash=h, kind="reach", objective_id=oid, status=status,
                       evidence_ref=ev, signature_ref=sig, targets=targets)


def _finding(seq, h, ref, *, targets=None, status="fact", ev="c", sig="s", parent_step_id="", **props):
    return SpineRecord(seq=seq, hash=h, kind="finding", finding_ref=ref, status=status,
                       evidence_ref=ev, signature_ref=sig, parent_step_id=parent_step_id,
                       props={"ref": ref, **props}, targets=targets or [])


def _tested(seq, h, sid, targets):
    return SpineRecord(seq=seq, hash=h, kind="tested", step_id=sid, targets=targets)


def _refute(seq, h, rid):
    return SpineRecord(seq=seq, hash=h, kind="refute", refutes_id=rid)


class FakeLifecycle:
    """The deterministic, offline injected S4 seam (same contract as test_graph_lifecycle's fake): a digest NOT
    in ``finding_map`` is ABSENT (None → no REMEDIATED_BY edge); ``verify_remediation`` keys off ``_ok``; an
    unknown log_ref is UNAUTHENTICATED (fail-closed)."""

    def __init__(self, finding_map=None, series_map=None):
        self.finding_map = finding_map or {}
        self.series_map = series_map or {}

    def resolve_finding(self, cert_digest: str) -> Optional[FindingLink]:
        return self.finding_map.get(cert_digest)

    def verify_remediation(self, remediation_cert: dict) -> bool:
        return bool(remediation_cert.get("_ok"))

    def verify_retest_series(self, log_ref: str) -> RetestSeries:
        return self.series_map.get(log_ref, RetestSeries(authenticated=False, reason="no such log"))


def _rem(seq, h, *, finding_cert_digest, remediation_id, ok=True, finding_ref="f"):
    cert = {"schema": "vigil-remediation-cert-v2", "verdict": "oracle-silent", "finding_ref": finding_ref,
            "bug_class": "sqli", "original_finding_cert_digest": finding_cert_digest, "_ok": ok}
    return SpineRecord(seq=seq, hash=h, kind="remediation",
                       props={"remediation_cert": cert, "remediation_id": remediation_id})


def _retest(seq, h, *, remediation_id, log_ref):
    return SpineRecord(seq=seq, hash=h, kind="retest",
                       props={"remediation_id": remediation_id, "retest_log_ref": log_ref})


def _series(authenticated, *states):
    ticks = tuple(RetestTick(seq=i, state=s, label="") for i, s in enumerate(states)) if authenticated else ()
    return RetestSeries(authenticated=authenticated, ticks=ticks)


@pytest.fixture(autouse=True)
def _arm_flag(monkeypatch):
    """Default the suite to coverage flag-ON (the flag-OFF test overrides this), and arm the S4 lifecycle env
    so the injected FakeLifecycle actually projects the remediation/retest kinds the per-finding tests need.
    Both are plain env reads — no framework import (the fake carries no crypto / disk / network)."""
    monkeypatch.setenv(COVERAGE_ENV, "1")
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")


# ============================================================================================================
# 1. Flag OFF — graph.query public API byte-identical to pre-slice; NO coverage function exposed.
# ============================================================================================================
def test_flag_off_query_public_api_byte_identical_and_no_coverage_exposed(monkeypatch):
    monkeypatch.delenv(COVERAGE_ENV, raising=False)
    # the module NAMESPACE public surface is UNCHANGED from pre-slice (S5 added only a dunder __getattr__).
    public = {n for n in vars(query_mod) if not n.startswith("_")}
    assert public == _PRESLICE_QUERY_PUBLIC, public ^ _PRESLICE_QUERY_PUBLIC
    assert "coverage" not in public                       # never a bound module-level symbol
    # with the flag OFF, the coverage read is NOT exposed on graph.query at all.
    assert not hasattr(query_mod, "coverage")
    with pytest.raises(AttributeError):
        _ = query_mod.coverage
    # a ``tested`` record projects NOTHING with the flag off → byte-identical to the spine without it.
    base = [_step(1, "s", "S1"), _finding(2, "f", "F", targets=[{"type": "host", "value": "a.tld"}])]
    withtested = base + [_tested(3, "t", "S1", [{"type": "host", "value": "a.tld"}])]
    off = project(withtested, coverage=False)
    assert off.model_dump() == project(base, coverage=False).model_dump()
    assert [e for e in off.edges if e.type == EdgeType.TESTED] == []


def test_flag_on_exposes_coverage_on_query():
    # with the flag armed (autouse), graph.query.coverage IS exposed and callable, and returns a CoverageView.
    assert hasattr(query_mod, "coverage")
    out = query_mod.coverage(project([_goal(1, "g", "OBJ")], objectives=True, coverage=True))
    assert isinstance(out, CoverageView)


# ============================================================================================================
# 2. Flag ON — per Goal: count of Actions that PURSUE it + whether a CONFIRMED finding AFFECTS an asset that
#    REACHES it; a Goal with ZERO actions is surfaced as uncovered.
# ============================================================================================================
def test_per_goal_actions_and_confirmed_reach_and_zero_action_uncovered():
    recs = [
        _goal(1, "g1", "COVERED"),
        _goal(2, "g2", "BARE"),                                   # zero actions → uncovered
        _step(3, "s1", "S1", oid="COVERED"),                      # PURSUES COVERED
        _step(4, "s2", "S2", oid="COVERED"),                      # a second action PURSUES COVERED
        _reach(5, "r", "COVERED", [{"type": "host", "value": "jewel.tld"}]),   # asset REACHES COVERED
        # a CONFIRMED finding AFFECTS the reaching asset.
        _finding(6, "f", "F1", parent_step_id="S1", severity="high",
                 targets=[{"type": "host", "value": "jewel.tld"}]),
    ]
    cov = coverage(project(recs, objectives=True, coverage=True))
    by = {g.goal_id: g for g in cov.goals}
    assert by["COVERED"].actions_pursuing == 2                    # two distinct ChainSteps PURSUE it
    assert by["COVERED"].confirmed_finding_reaches is True        # confirmed F1 AFFECTS jewel.tld REACHES COVERED
    assert by["COVERED"].uncovered is False
    # the Goal with no actions is surfaced as UNCOVERED (never hidden, never "100%").
    assert by["BARE"].actions_pursuing == 0 and by["BARE"].uncovered is True
    assert by["BARE"].confirmed_finding_reaches is False


# ============================================================================================================
# 3. Honesty invariant — an asset with NO finding is not_tested UNLESS a benign/negative RESULT record exists
#    for it, in which case tested_no_finding. Silence is NEVER reported as CLEAN/safe.
# ============================================================================================================
def test_no_finding_asset_is_not_tested_unless_a_benign_record_exists():
    recs = [
        _step(1, "s", "S1"),
        # SILENCE: an asset that is only REACHED, never tested, with no finding → not_tested (never CLEAN).
        _goal(2, "g", "OBJ"),
        _reach(3, "r", "OBJ", [{"type": "host", "value": "silent.tld"}]),
        # a RETAINED benign/negative response record for another asset → tested_no_finding.
        _tested(4, "t", "S1", [{"type": "host", "value": "benign.tld",
                                "result": "benign", "response_ref": "resp:1"}]),
    ]
    cov = coverage(project(recs, objectives=True, coverage=True))
    by = {a.asset_id: a for a in cov.assets}
    assert by["host:silent.tld"].coverage_state == NOT_TESTED     # silence — NOT clean/safe
    assert by["host:benign.tld"].coverage_state == TESTED_NO_FINDING
    # the honest states never say "clean"/"protected"/"safe"
    assert {a.coverage_state for a in cov.assets} <= {NOT_TESTED, TESTED, TESTED_NO_FINDING}
    assert cov.scope_note and "not_tested" in cov.scope_note


# ============================================================================================================
# 4. Flag ON — per CONFIRMED finding: remediation present|absent + retest verified_fixed|still_vulnerable|
#    inconclusive|none, DERIVED ONLY from JOIN-verified (S2/S4) nodes — an unverified remediation never
#    shows verified_fixed.
# ============================================================================================================
def test_per_finding_remediation_and_retest_only_from_join_verified_nodes():
    life = FakeLifecycle(
        finding_map={"d-ok": FindingLink(ok=True, finding_ref="F1"),       # resolves+reverifies → linked
                     "d-bad": FindingLink(ok=False, finding_ref="F2")},    # resolves but FAILS reverify → unlinked
        series_map={"log-ok": _series(True, "REMEDIATED")})                # authenticated verified_fixed
    recs = [
        _finding(1, "h1", "F1", severity="high"),
        _finding(2, "h2", "F2", severity="high"),
        # F1: JOIN-verified remediation + authenticated passing retest → present / verified_fixed.
        _rem(3, "r1", finding_cert_digest="d-ok", remediation_id="REM1", finding_ref="F1"),
        _retest(4, "t1", remediation_id="REM1", log_ref="log-ok"),
        # F2: remediation node exists + a passing retest, BUT the finding-cert link did NOT re-verify (ok=False)
        # → NO REMEDIATED_BY edge → the remediation is NEVER attributed to F2 → absent / none (never fixed).
        _rem(5, "r2", finding_cert_digest="d-bad", remediation_id="REM2", finding_ref="F2"),
        _retest(6, "t2", remediation_id="REM2", log_ref="log-ok"),
    ]
    cov = coverage(project(recs, coverage=True, lifecycle=life))
    by = {f.finding_ref: f for f in cov.findings_confirmed}
    assert by["F1"].remediation == REMEDIATION_PRESENT and by["F1"].retest == RETEST_VERIFIED_FIXED
    # the UNLINKED (unverified-link) remediation never launders a verified_fixed onto F2.
    assert by["F2"].remediation == REMEDIATION_ABSENT and by["F2"].retest == RETEST_NONE
    assert by["F2"].retest != RETEST_VERIFIED_FIXED


def test_unauthenticated_retest_reads_inconclusive_never_verified_fixed():
    life = FakeLifecycle(
        finding_map={"d": FindingLink(ok=True, finding_ref="F1")},
        series_map={"log-rb": _series(False)})           # authenticated=False → projector caps to rolled_back
    recs = [
        _finding(1, "h1", "F1", severity="high"),
        _rem(2, "r1", finding_cert_digest="d", remediation_id="REM", finding_ref="F1"),
        _retest(3, "t1", remediation_id="REM", log_ref="log-rb"),
    ]
    cov = coverage(project(recs, coverage=True, lifecycle=life))
    f1 = {f.finding_ref: f for f in cov.findings_confirmed}["F1"]
    assert f1.remediation == REMEDIATION_PRESENT               # the link re-verified
    assert f1.retest == RETEST_INCONCLUSIVE                    # but the series did NOT authenticate → not fixed
    assert f1.retest != RETEST_VERIFIED_FIXED


def test_still_vulnerable_retest_is_reported_honestly():
    life = FakeLifecycle(finding_map={"d": FindingLink(ok=True, finding_ref="F1")},
                         series_map={"log": _series(True, "STILL_VULNERABLE")})
    recs = [_finding(1, "h1", "F1"),
            _rem(2, "r", finding_cert_digest="d", remediation_id="REM", finding_ref="F1"),
            _retest(3, "t", remediation_id="REM", log_ref="log")]
    f1 = {f.finding_ref: f for f in coverage(project(recs, coverage=True, lifecycle=life)).findings_confirmed}["F1"]
    assert f1.retest == RETEST_STILL_VULNERABLE


def test_multi_remediation_verdict_fails_toward_not_safe():
    # RED-PEN MEDIUM (fail-OPEN), closed: a finding LEGITIMATELY owns >1 REMEDIATED_BY edge
    # (``_project_remediation`` draws one per re-verified remediation for the same finding_ref — no dedup). The
    # aggregate retest verdict must FAIL TOWARD NOT-SAFE: an authenticated STILL_VULNERABLE (and INCONCLUSIVE)
    # DOMINATES an optimistic verified_fixed, never the reverse — so one attempt claiming "fixed" can NEVER mask
    # another attempt's authenticated proof the finding is still exploitable.
    # (a) verified_fixed + authenticated STILL_VULNERABLE → still_vulnerable (not verified_fixed).
    life = FakeLifecycle(
        finding_map={"d1": FindingLink(ok=True, finding_ref="F1"),
                     "d2": FindingLink(ok=True, finding_ref="F1")},
        series_map={"log-fixed": _series(True, "REMEDIATED"),
                    "log-vuln": _series(True, "STILL_VULNERABLE")})
    recs = [
        _finding(1, "h1", "F1", severity="high"),
        _rem(2, "r1", finding_cert_digest="d1", remediation_id="REM1", finding_ref="F1"),
        _retest(3, "t1", remediation_id="REM1", log_ref="log-fixed"),       # attempt 1 claims fixed
        _rem(4, "r2", finding_cert_digest="d2", remediation_id="REM2", finding_ref="F1"),
        _retest(5, "t2", remediation_id="REM2", log_ref="log-vuln"),        # attempt 2 PROVES still-vulnerable
    ]
    f1 = {f.finding_ref: f for f in coverage(project(recs, coverage=True, lifecycle=life)).findings_confirmed}["F1"]
    assert f1.remediation == REMEDIATION_PRESENT
    assert f1.retest == RETEST_STILL_VULNERABLE                             # NOT masked as verified_fixed
    assert f1.retest != RETEST_VERIFIED_FIXED

    # (b) verified_fixed + INCONCLUSIVE (unauthenticated/rolled-back series) → inconclusive (not verified_fixed).
    life2 = FakeLifecycle(
        finding_map={"d1": FindingLink(ok=True, finding_ref="F2"),
                     "d2": FindingLink(ok=True, finding_ref="F2")},
        series_map={"log-fixed": _series(True, "REMEDIATED"),
                    "log-rb": _series(False)})                              # authenticated=False → rolled_back
    recs2 = [
        _finding(1, "h1", "F2", severity="high"),
        _rem(2, "r1", finding_cert_digest="d1", remediation_id="RA", finding_ref="F2"),
        _retest(3, "t1", remediation_id="RA", log_ref="log-fixed"),
        _rem(4, "r2", finding_cert_digest="d2", remediation_id="RB", finding_ref="F2"),
        _retest(5, "t2", remediation_id="RB", log_ref="log-rb"),
    ]
    f2 = {f.finding_ref: f for f in coverage(project(recs2, coverage=True, lifecycle=life2)).findings_confirmed}["F2"]
    assert f2.remediation == REMEDIATION_PRESENT
    assert f2.retest == RETEST_INCONCLUSIVE                                 # cannot conclude fixed
    assert f2.retest != RETEST_VERIFIED_FIXED

    # (c) control: when EVERY linked remediation is an authenticated pass, the finding DOES read verified_fixed.
    life3 = FakeLifecycle(
        finding_map={"d1": FindingLink(ok=True, finding_ref="F3"),
                     "d2": FindingLink(ok=True, finding_ref="F3")},
        series_map={"log-a": _series(True, "REMEDIATED"), "log-b": _series(True, "REMEDIATED")})
    recs3 = [
        _finding(1, "h1", "F3"),
        _rem(2, "r1", finding_cert_digest="d1", remediation_id="RX", finding_ref="F3"),
        _retest(3, "t1", remediation_id="RX", log_ref="log-a"),
        _rem(4, "r2", finding_cert_digest="d2", remediation_id="RY", finding_ref="F3"),
        _retest(5, "t2", remediation_id="RY", log_ref="log-b"),
    ]
    f3 = {f.finding_ref: f for f in coverage(project(recs3, coverage=True, lifecycle=life3)).findings_confirmed}["F3"]
    assert f3.retest == RETEST_VERIFIED_FIXED                               # all-pass → fixed is sound


# ============================================================================================================
# 5. Flag ON — a LEAD finding is under leads_unverified, NEVER findings_confirmed (the lead/fact split carries
#    into coverage).
# ============================================================================================================
def test_lead_finding_is_under_leads_unverified_never_findings_confirmed():
    recs = [
        _finding(1, "h1", "FACT", severity="high"),                        # confirmed (signed fact)
        _finding(2, "h2", "LEAD", status="lead", ev="", sig="", severity="low"),  # a bare lead
    ]
    cov = coverage(project(recs, coverage=True))
    assert {f.finding_ref for f in cov.findings_confirmed} == {"FACT"}      # only the fact
    assert {f.finding_ref for f in cov.leads_unverified} == {"LEAD"}        # the lead is clearly separated
    assert "LEAD" not in {f.finding_ref for f in cov.findings_confirmed}    # never masquerades as a fact


# ============================================================================================================
# 6. Flag ON — coverage counts only ACTIVE (non-retired) nodes: a refuted lead drops from the unverified
#    count (bi-temporal honored).
# ============================================================================================================
def test_refuted_lead_drops_from_coverage_bitemporal():
    recs = [
        _finding(1, "h1", "LEAD", status="lead", ev="", sig="", severity="low"),
        _refute(2, "x", "finding:LEAD"),                 # a bare refute retires the lead (never deletes)
    ]
    v = project(recs, coverage=True)
    # the node is retired but still present for audit; coverage counts ONLY active → it drops.
    assert v.get("finding:LEAD") is not None and not v.get("finding:LEAD").is_active
    cov = coverage(v)
    assert cov.leads_unverified == [] and cov.findings_confirmed == []
    # a TESTED edge off a retired step/asset likewise does not keep a surface "tested".
    recs2 = recs + [_step(3, "s", "S1"), _tested(4, "t", "S1", [{"type": "host", "value": "a.tld"}]),
                    _refute(5, "y", "host:a.tld")]
    cov2 = coverage(project(recs2, coverage=True))
    assert all(a.asset_id != "host:a.tld" for a in cov2.assets)   # retired asset excluded (active-only)


# ============================================================================================================
# 7. Non-authoritative — the result is stamped retrieval_only=True / authoritative=False and is FROZEN
#    (grants nothing, authorizes no action).
# ============================================================================================================
def test_coverage_is_non_authoritative_and_frozen():
    cov = coverage(project([_goal(1, "g", "OBJ")], objectives=True, coverage=True))
    assert cov.authoritative is False and cov.retrieval_only is True
    # FROZEN — a consumer cannot flip the flags to fabricate authority.
    with pytest.raises(Exception):
        cov.authoritative = True
    with pytest.raises(Exception):
        cov.retrieval_only = False
    # the nested summaries are frozen too.
    with pytest.raises(Exception):
        cov.goals[0].uncovered = False


# ============================================================================================================
# 8. Determinism — coverage(view) is a PURE function of the view: same view → byte-identical, SORTED JSON.
# ============================================================================================================
def test_coverage_is_deterministic_sorted_and_pure():
    recs = [
        _goal(1, "g1", "B-OBJ"), _goal(2, "g2", "A-OBJ"),
        _step(3, "s1", "S1", oid="A-OBJ"), _step(4, "s2", "S2", oid="B-OBJ"),
        _reach(5, "r", "A-OBJ", [{"type": "host", "value": "z.tld"}, {"type": "host", "value": "a.tld"}]),
        _finding(6, "f1", "Z-F", targets=[{"type": "host", "value": "z.tld"}]),
        _finding(7, "f2", "A-F", status="lead", ev="", sig=""),
        _tested(8, "t", "S1", [{"type": "host", "value": "a.tld", "result": "benign", "response_ref": "r1"}]),
    ]
    a = coverage(project(recs, objectives=True, coverage=True)).model_dump()
    b = coverage(project(list(reversed(recs)), objectives=True, coverage=True)).model_dump()
    assert json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)   # byte-identical, any input order
    # SORTED output: goals by id, assets by id, findings by node id.
    assert [g["goal_id"] for g in a["goals"]] == sorted(g["goal_id"] for g in a["goals"])
    assert [x["asset_id"] for x in a["assets"]] == sorted(x["asset_id"] for x in a["assets"])
    # no wallclock/RNG: a second projection+rollup is byte-identical.
    assert coverage(project(recs, objectives=True, coverage=True)).model_dump() == a


# ============================================================================================================
# 9. No secrets — every label/count in the export passes the F3 redactor (vigil_core.redact lineage via
#    tools.redact_tool_args) — no host-userinfo / credential / token leak.
# ============================================================================================================
def test_every_label_passes_the_f3_redactor():
    recs = [
        _goal(1, "g", "OBJ", title="exfil via Authorization: Bearer sk-live-LEAK123"),
        _step(2, "s", "S1", oid="OBJ"),
        # an endpoint asset whose value carries URL userinfo (a credential) — it must be masked in the label.
        _tested(3, "t", "S1", [{"type": "endpoint", "value": "https://admin:pw-LEAK@in.tld/db",
                                "result": "benign", "response_ref": "r1"}]),
        _finding(4, "f", "F1", targets=[{"type": "endpoint", "value": "https://admin:pw-LEAK@in.tld/db"}],
                 severity="high"),
    ]
    cov = coverage(project(recs, objectives=True, coverage=True))
    blob = json.dumps(cov.model_dump())
    for leaked in ("sk-live-LEAK123", "pw-LEAK"):
        assert leaked not in blob, leaked               # every secret masked before it can be a label
    # non-secret structure survives (the view is still useful): the goal id + a host authority remain.
    assert "OBJ" in blob and "in.tld" in blob


# ============================================================================================================
# 10. Fail-closed honesty on sparse data — an empty/partial graph never crashes and never reports 100%/CLEAN
#     for an un-scanned goal; missing data reads as unknown/not_tested.
# ============================================================================================================
def test_fail_closed_on_empty_and_partial_graphs():
    # a non-view → the empty, fail-closed-honest coverage view (never raises).
    empty = coverage("not-a-view")
    assert isinstance(empty, CoverageView) and empty.goals == [] and empty.assets == []
    assert empty.authoritative is False
    # an un-scanned goal (declared, zero actions, nothing reached/tested) is UNCOVERED — never "100%"/CLEAN.
    only_goal = coverage(project([_goal(1, "g", "UNSCANNED")], objectives=True, coverage=True))
    g = only_goal.goals[0]
    assert g.uncovered is True and g.actions_pursuing == 0 and g.confirmed_finding_reaches is False
    # a partial graph (a lone reached-but-untested asset, no finding) → the asset is not_tested, not "safe".
    partial = coverage(project([
        _goal(1, "g", "OBJ"),
        _reach(2, "r", "OBJ", [{"type": "host", "value": "reached.tld"}]),
    ], objectives=True, coverage=True))
    a = {x.asset_id: x for x in partial.assets}["host:reached.tld"]
    assert a.coverage_state == NOT_TESTED                 # reached != tested; absence-of-test != proof-of-safety


# ============================================================================================================
# REFINEMENT A — the ChainStep -[TESTED]-> asset edge is written from the PINNED, gate-authorized target,
#    keyed by an EntityRef id; the coverage STATE (tested/not_tested/tested_no_finding) is independent of any
#    finding verdict.
# ============================================================================================================
def test_tested_edge_is_pinned_scope_gated_and_keyed_by_entityref():
    gate = lambda h: h == "in.tld"                       # the gate only authorized in.tld
    recs = [
        _step(1, "s", "S1"),
        _tested(2, "t", "S1", [{"type": "host", "value": "in.tld", "entity_ref": "host:in.tld"},
                               {"type": "host", "value": "evil.tld"}]),   # out-of-scope — the gate forbids it
    ]
    v = project(recs, coverage=True, scope_gate=gate)
    tested_edges = [e for e in v.edges if e.type == EdgeType.TESTED]
    assert len(tested_edges) == 1                          # ONLY the gate-authorized target got a TESTED edge
    e = tested_edges[0]
    assert e.src == "step:S1" and e.dst == "host:in.tld"   # keyed by the EntityRef node id (kind:key)
    assert e.props["entity_ref"] == "host:in.tld"
    # the TESTED edge is INERT/LEAD — a coverage link, never a proof.
    from vigil_integration.graph import ConfirmationStatus
    assert e.provenance.confirmation == ConfirmationStatus.LEAD and e.provenance.evidence_ref == ""
    assert v.get("host:evil.tld") is None                 # the out-of-scope asset never entered


def test_coverage_state_is_independent_of_finding_verdict():
    # the SAME asset: a TESTED edge + a CONFIRMED finding vs a TESTED edge + a LEAD finding → both read
    # ``tested`` (the state reflects that it was exercised, NOT the finding's confirmed/lead verdict); the
    # confirmed/lead COUNTS differ. The verdict lives in the counts, not the coverage state.
    confirmed = [
        _step(1, "s", "S1"), _tested(2, "t", "S1", [{"type": "host", "value": "a.tld"}]),
        _finding(3, "f", "F1", targets=[{"type": "host", "value": "a.tld"}]),            # confirmed
    ]
    lead = [
        _step(1, "s", "S1"), _tested(2, "t", "S1", [{"type": "host", "value": "a.tld"}]),
        _finding(3, "f", "F1", status="lead", ev="", sig="", targets=[{"type": "host", "value": "a.tld"}]),
    ]
    ca = {x.asset_id: x for x in coverage(project(confirmed, coverage=True)).assets}["host:a.tld"]
    la = {x.asset_id: x for x in coverage(project(lead, coverage=True)).assets}["host:a.tld"]
    assert ca.coverage_state == TESTED and la.coverage_state == TESTED       # state is verdict-independent
    assert ca.confirmed_findings == 1 and ca.lead_findings == 0              # the verdict lives in the counts
    assert la.confirmed_findings == 0 and la.lead_findings == 1


# ============================================================================================================
# REFINEMENT B — tested_no_finding REQUIRES a retained benign/negative RESPONSE record (not mere absence); a
#    bare TESTED edge (test ran, no retained negative proof) is ``tested``; silence (no record) is
#    ``not_tested``.
# ============================================================================================================
def test_tested_no_finding_requires_a_retained_benign_record():
    recs = [
        _step(1, "s", "S1"),
        # (a) a bare TESTED edge — test exercised, but NO retained benign/negative response → ``tested``.
        _tested(2, "t1", "S1", [{"type": "host", "value": "bare.tld"}]),
        # (b) a TESTED edge with a result token but NO retained response_ref → still NOT a benign record.
        _tested(3, "t2", "S1", [{"type": "host", "value": "noref.tld", "result": "benign"}]),
        # (c) a TESTED edge WITH a retained benign/negative response record → ``tested_no_finding``.
        _tested(4, "t3", "S1", [{"type": "host", "value": "proven.tld",
                                 "result": "negative", "response_ref": "resp:9"}]),
    ]
    by = {a.asset_id: a for a in coverage(project(recs, coverage=True)).assets}
    assert by["host:bare.tld"].coverage_state == TESTED                   # ran, no retained negative proof
    assert by["host:noref.tld"].coverage_state == TESTED                  # a token without retained bytes ≠ benign
    assert by["host:proven.tld"].coverage_state == TESTED_NO_FINDING      # retained benign/negative record
    # and an asset with NO record at all is absent/not_tested — silence, never covered.
    assert "host:silent.tld" not in by


# ============================================================================================================
# REFINEMENT C — per asset, CONFIRMED and LEAD findings are counted SEPARATELY.
# ============================================================================================================
def test_per_asset_confirmed_and_lead_counts_are_separate():
    recs = [
        _finding(1, "f1", "C1", targets=[{"type": "host", "value": "a.tld"}]),                 # confirmed
        _finding(2, "f2", "C2", targets=[{"type": "host", "value": "a.tld"}]),                 # confirmed
        _finding(3, "f3", "L1", status="lead", ev="", sig="", targets=[{"type": "host", "value": "a.tld"}]),
    ]
    a = {x.asset_id: x for x in coverage(project(recs, coverage=True)).assets}["host:a.tld"]
    assert a.confirmed_findings == 2 and a.lead_findings == 1             # counted separately, never conflated


# ============================================================================================================
# Flag wiring — DEFAULT-OFF behind VIGIL_COVERAGE_VIEW (affirmative-flag convention).
# ============================================================================================================
def test_env_flag_default_off_truth_table(monkeypatch):
    assert coverage_view_enabled(env={}) is False
    assert coverage_view_enabled(env={COVERAGE_ENV: ""}) is False
    assert coverage_view_enabled(env={COVERAGE_ENV: "0"}) is False
    assert coverage_view_enabled(env={COVERAGE_ENV: "maybe"}) is False
    for on in ("1", "true", "YES", "On"):
        assert coverage_view_enabled(env={COVERAGE_ENV: on}) is True
    # project(coverage=None) reads the env flag: unset ⇒ OFF ⇒ a ``tested`` record adds no edge.
    monkeypatch.delenv(COVERAGE_ENV, raising=False)
    off = project([_step(1, "s", "S1"), _tested(2, "t", "S1", [{"type": "host", "value": "a.tld"}])])
    assert [e for e in off.edges if e.type == EdgeType.TESTED] == []
    monkeypatch.setenv(COVERAGE_ENV, "1")
    on = project([_step(1, "s", "S1"), _tested(2, "t", "S1", [{"type": "host", "value": "a.tld"}])])
    assert [e for e in on.edges if e.type == EdgeType.TESTED]


# ============================================================================================================
# No-offense / FATAL-2 — the coverage layer issues no traffic, runs no live test, and imports no framework at
# module scope (it is a passive CONSUMER of the projected view).
# ============================================================================================================
_FORBIDDEN_SYMBOLS = (
    "subprocess", "os.system", "os.popen", "pty.", "socket", "requests", "httpx", "urllib",
    "http.client", "ftplib", "smtplib", "telnetlib", "asyncio", "ctypes", "pickle", "marshal",
    "eval(", "exec(", "compile(", "__import__(", "os.exec", "posix_spawn",
)


def _code_only(src: str) -> str:
    buf = [list(line) for line in src.splitlines(keepends=True)]
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type not in (tokenize.STRING, tokenize.COMMENT):
            continue
        (sr, sc), (er, ec) = tok.start, tok.end
        for row in range(sr, er + 1):
            r = row - 1
            if r >= len(buf):
                continue
            c0 = sc if row == sr else 0
            c1 = ec if row == er else len(buf[r])
            for c in range(c0, min(c1, len(buf[r]))):
                if buf[r][c] != "\n":
                    buf[r][c] = " "
    return "".join("".join(row) for row in buf)


def test_coverage_module_has_no_exec_egress_and_no_module_scope_framework_import():
    raw = _COVERAGE_SRC.read_text(encoding="utf-8")
    tree = ast.parse(raw)
    code = _code_only(raw)
    hits = [sym for sym in _FORBIDDEN_SYMBOLS if sym in code]
    assert not hits, f"coverage.py carries forbidden tool/exec/egress symbol(s): {hits}"
    # FATAL-2: no ``framework`` / ``strix`` import at module scope (the redactor import is function-local).
    module_imports: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            module_imports.append(node.module)
        elif isinstance(node, ast.Import):
            module_imports.extend(a.name for a in node.names)
    assert not any(m.startswith(("framework", "strix")) for m in module_imports), module_imports
