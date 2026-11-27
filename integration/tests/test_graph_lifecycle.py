"""F4 slice S4 — the remediation/retest LIFECYCLE projection (behind VIGIL_GRAPH_LIFECYCLE, default off).

The through-line every test defends: the projector surfaces the EXISTING signed remediation/retest certs as
INERT graph nodes/edges so finding→remediation→retest is ONE traversal, WITHOUT ever laundering a 'fixed'
into a confirmed fact. A remediation links to its finding ONLY when the referenced finding cert RESOLVES (S1)
+ re-verifies (fail-closed otherwise); a retest's status comes ONLY from the SIGNED 4-state verdict on an
AUTHENTICATED series — the attestation-log authority re-derives the anti-rollback floor from the signed
durable high-water (never a producer-supplied in-band value), so a truncated/rolled-back series can never read
as 'fixed'; and the whole projection issues no traffic and runs no live retest.

Deterministic + OFFLINE: every re-verification is DELEGATED to an INJECTED fake ``LifecycleVerifier`` (the
sovereign pattern — the real framework wiring, ``make_default_lifecycle`` → S1 resolver +
``attestation_log.verify_log``, is exercised against REAL on-disk artifacts in test_graph_lifecycle_s1.py,
which importorskips ``framework``). No wallclock / RNG / network here — so this whole file runs in the
framework-FREE sovereign CI leg.
"""

from __future__ import annotations

import ast
import io
import json
import tokenize
from pathlib import Path
from typing import Optional

import pytest
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair

from vigil_integration.graph import (
    EdgeType,
    FindingLink,
    NodeLabel,
    RetestSeries,
    RetestTick,
    SpineRecord,
    lifecycle_chains,
    make_default_lifecycle,
    project,
)
from vigil_integration.graph.projector import (
    NO_RETEST,
    _STATUS_ROLLED_BACK,
    _STATUS_STILL_VULNERABLE,
    _STATUS_VERIFIED_FIXED,
)

_PROJECTOR_SRC = Path(__file__).resolve().parents[1] / "vigil_integration" / "graph" / "projector.py"
_QUERY_SRC = Path(__file__).resolve().parents[1] / "vigil_integration" / "graph" / "query.py"


# ==================================================================================================
# Fakes + builders. Fully self-contained (no framework, no disk): ``_ok`` on a remediation cert ⇒ it
# re-verifies; ``finding_map`` resolves a finding digest; ``series_map`` maps an opaque retest log_ref to
# the AUTHENTICATED series the attestation-log authority (verify_log) would return.
# ==================================================================================================
class FakeLifecycle:
    """A deterministic, offline stand-in for the injected seam. It performs NO crypto — it returns the verdicts
    a test declares — but it exercises the EXACT contract the real verifiers/authorities satisfy:
    ``resolve_finding`` returns None for an ABSENT/cross-tenant digest, a ``FindingLink(ok=...)`` otherwise
    (``ok`` True ⇔ the real resolver's ``rv.ok``: internal verify AND authenticity PINNED out-of-band — a
    bundle cannot self-authenticate); ``verify_remediation`` keys off a signed-ness marker; and
    ``verify_retest_series`` returns a ``RetestSeries`` keyed on the opaque log_ref — the real wiring gets this
    from ``attestation_log.verify_log``, so ``authenticated`` is True ONLY when the signed head + durable
    high-water floor + every tick checked out (no truncation/rollback)."""

    def __init__(self, finding_map: Optional[dict[str, Optional[FindingLink]]] = None,
                 series_map: Optional[dict[str, RetestSeries]] = None) -> None:
        self.finding_map = finding_map or {}
        self.series_map = series_map or {}
        self.resolve_calls: list[str] = []
        self.series_calls: list[str] = []

    def resolve_finding(self, cert_digest: str) -> Optional[FindingLink]:
        self.resolve_calls.append(cert_digest)
        # a digest NOT in the map is ABSENT here (incl. a cross-tenant cert that resolves only under another
        # tenant's root — the real S1 resolver returns None for it, so the fake mirrors that with None).
        return self.finding_map.get(cert_digest)

    def verify_remediation(self, remediation_cert: dict) -> bool:
        return bool(remediation_cert.get("_ok"))

    def verify_retest_series(self, log_ref: str) -> RetestSeries:
        self.series_calls.append(log_ref)
        # an unknown log_ref is UNAUTHENTICATED (the authority could not vouch for it) — fail-closed.
        return self.series_map.get(log_ref, RetestSeries(authenticated=False, reason="no such authenticated log"))


def _finding_rec(seq, h, *, ref, status="fact", evidence_ref="cert", signature_ref="sig", **props):
    return SpineRecord(seq=seq, hash=h, kind="finding", finding_ref=ref, status=status,
                       evidence_ref=evidence_ref, signature_ref=signature_ref,
                       props={"ref": ref, **props})


def _rem_cert(*, finding_cert_digest, ok=True, verdict="oracle-silent", finding_ref="f-1",
              bug_class="error_based_sqli"):
    return {"schema": "vigil-remediation-cert-v2", "verdict": verdict, "finding_ref": finding_ref,
            "bug_class": bug_class, "original_finding_cert_digest": finding_cert_digest, "_ok": ok}


def _rem_rec(seq, h, *, cert, remediation_id):
    return SpineRecord(seq=seq, hash=h, kind="remediation",
                       props={"remediation_cert": cert, "remediation_id": remediation_id})


def _series(authenticated, *states):
    """Build the RetestSeries the attestation-log authority would return: an AUTHENTICATED series carries its
    re-verified ticks; an UNAUTHENTICATED one (truncated / rolled-back / bad tick / floor unavailable) carries
    no trustworthy ticks."""
    ticks = tuple(RetestTick(seq=i, state=s, label="") for i, s in enumerate(states)) if authenticated else ()
    return RetestSeries(authenticated=authenticated, ticks=ticks)


def _retest_rec(seq, h, *, remediation_id, log_ref, **extra_props):
    props = {"remediation_id": remediation_id, "retest_log_ref": log_ref}
    props.update(extra_props)                      # e.g. a (now-ignored) forged in-band floor
    return SpineRecord(seq=seq, hash=h, kind="retest", props=props)


@pytest.fixture(autouse=True)
def _arm_flag(monkeypatch):
    """Default the suite to flag-ON; the flag-OFF tests override this explicitly."""
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")


# ==================================================================================================
# 1. Flag OFF — no remediation/retest kind projected; GraphView byte-identical to pre-slice.
# ==================================================================================================
def test_flag_off_projects_no_lifecycle_and_is_byte_identical(monkeypatch):
    monkeypatch.delenv("VIGIL_GRAPH_LIFECYCLE", raising=False)
    life = FakeLifecycle({"d1": FindingLink(ok=True, finding_ref="f-1")},
                         {"log-REM": _series(True, "REMEDIATED")})
    base = [
        SpineRecord(seq=1, hash="c1", kind="chain", chain_id="C"),
        SpineRecord(seq=2, hash="s1", kind="step", step_id="S", chain_id="C"),
        _finding_rec(3, "h1", ref="f-1", parent_step_id="S"),
    ]
    lifecycle_recs = [
        _rem_rec(4, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
        _retest_rec(5, "t1", remediation_id="REM", log_ref="log-REM"),
    ]
    # With the flag OFF: the lifecycle records (and an injected verifier) change NOTHING — the view is
    # byte-identical to the one built from the base records alone (the pre-slice behaviour).
    plain = project(base).model_dump()
    with_lifecycle_off = project(base + lifecycle_recs, lifecycle=life).model_dump()
    assert plain == with_lifecycle_off
    assert life.resolve_calls == [] and life.series_calls == []     # neither verifier was consulted
    v = project(base + lifecycle_recs, lifecycle=life)
    assert v.active_nodes(NodeLabel.REMEDIATION) == []               # no lifecycle nodes at all
    assert v.active_nodes(NodeLabel.RETEST) == []


def test_flag_off_needs_no_verifier_at_all(monkeypatch):
    # OFF ⇒ a lifecycle record projects nothing EVEN with no verifier injected (and never imports framework).
    monkeypatch.delenv("VIGIL_GRAPH_LIFECYCLE", raising=False)
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM")])
    assert len(v.nodes) == 0 and len(v.edges) == 0


# ==================================================================================================
# 2. Flag ON — a RemediationCertificate projects a REMEDIATION node + Finding-[REMEDIATED_BY]->Remediation,
#    linked by original_finding_cert_digest resolving (S1) to the finding cert; an ABSENT/UNVERIFIED finding
#    cert projects NO confirmed edge.
# ==================================================================================================
def test_remediation_links_to_finding_when_cert_resolves_and_reverifies():
    life = FakeLifecycle({"d1": FindingLink(ok=True, finding_ref="f-1")})
    recs = [
        _finding_rec(1, "h1", ref="f-1"),
        _rem_rec(2, "r1", cert=_rem_cert(finding_cert_digest="d1", finding_ref="f-1"), remediation_id="REM"),
    ]
    v = project(recs, lifecycle=life)
    rem = v.active_nodes(NodeLabel.REMEDIATION)
    assert len(rem) == 1 and rem[0].id == "remediation:REM"
    edges = [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY]
    assert len(edges) == 1
    assert edges[0].src == "finding:f-1" and edges[0].dst == "remediation:REM"     # linked by the resolved ref
    assert edges[0].props.get("link_verified") is True
    assert life.resolve_calls == ["d1"]                                            # resolved via S1 by digest


def test_remediation_with_absent_finding_cert_projects_no_edge():
    # the finding cert digest is NOT resolvable (absent) → the node projects, but NO confirmed edge.
    life = FakeLifecycle({})                                    # nothing resolves
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="gone"), remediation_id="REM")],
                lifecycle=life)
    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1              # the remediation node exists
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == []   # but it is NOT linked (fail-closed)


def test_remediation_with_unverified_finding_cert_projects_no_edge():
    # the finding cert RESOLVES but does NOT re-verify (ok=False — incl. an unpinned/self-signed bundle) → NO
    # confirmed edge (fail-closed).
    life = FakeLifecycle({"d1": FindingLink(ok=False, finding_ref="f-1")})
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM")],
                lifecycle=life)
    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == []


def test_remediation_cert_that_does_not_reverify_projects_nothing():
    # a remediation cert whose OWN signature/oracle re-verify fails projects NO node and NO edge (fail-closed).
    life = FakeLifecycle({"d1": FindingLink(ok=True, finding_ref="f-1")})
    v = project([_finding_rec(1, "h1", ref="f-1"),
                 _rem_rec(2, "r1", cert=_rem_cert(finding_cert_digest="d1", ok=False), remediation_id="REM")],
                lifecycle=life)
    assert v.active_nodes(NodeLabel.REMEDIATION) == []
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == []


# ==================================================================================================
# 3. Flag ON — a retest projects a RETEST node + Remediation-[RETESTED_BY]->Retest; status from the signed
#    4-state verdict on the AUTHENTICATED series (verify_log), never an unsigned label.
# ==================================================================================================
def test_retest_projects_node_and_edge_with_authenticated_status():
    life = FakeLifecycle(series_map={"log-REM": _series(True, "REMEDIATED")})
    recs = [
        _rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
        _retest_rec(2, "t1", remediation_id="REM", log_ref="log-REM"),
    ]
    v = project(recs, lifecycle=life)
    retests = v.active_nodes(NodeLabel.RETEST)
    assert len(retests) == 1
    assert retests[0].props["status"] == _STATUS_VERIFIED_FIXED and retests[0].props["authenticated"] is True
    edges = [e for e in v.edges if e.type == EdgeType.RETESTED_BY]
    assert len(edges) == 1 and edges[0].src == "remediation:REM" and edges[0].dst == retests[0].id
    assert life.series_calls == ["log-REM"]                  # the authority was consulted by log_ref


def test_retest_status_is_from_the_authenticated_verdict_not_a_label():
    # an UNAUTHENTICATED series (the authority could not vouch for it — bad tick / forged head / truncation)
    # must NOT read as verified_fixed whatever any raw tick 'claimed' — it caps to rolled_back (fail-closed).
    life = FakeLifecycle(series_map={"log-REM": _series(False)})     # authenticated=False
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 _retest_rec(2, "t1", remediation_id="REM", log_ref="log-REM")],
                lifecycle=life)
    rt = v.active_nodes(NodeLabel.RETEST)[0]
    assert rt.props["status"] == _STATUS_ROLLED_BACK and rt.props["status"] != _STATUS_VERIFIED_FIXED
    assert rt.props["authenticated"] is False


# ==================================================================================================
# 4. Flag ON — a REMEDIATED tick whose remediation cert does NOT re-verify → still_vulnerable/unverified, not
#    Verified Fixed. (verify_log re-runs verify_prove_certificate per tick, which re-executes the embedded
#    remediation cert; a failure makes the WHOLE series unauthenticated ⇒ no 'fixed'.)
# ==================================================================================================
def test_remediated_tick_with_bad_embedded_cert_is_not_verified_fixed():
    # a REMEDIATED tick whose embedded remediation cert does not re-execute → verify_log returns ok=False →
    # the authority yields an UNAUTHENTICATED series → the projector caps to rolled_back, never verified_fixed.
    life = FakeLifecycle(series_map={"log-REM": RetestSeries(authenticated=False,
                                                             reason="tick 0 failed re-verification")})
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 _retest_rec(2, "t1", remediation_id="REM", log_ref="log-REM")],
                lifecycle=life)
    rt = v.active_nodes(NodeLabel.RETEST)[0]
    assert rt.props["status"] != _STATUS_VERIFIED_FIXED and rt.props["status"] == _STATUS_ROLLED_BACK


def test_still_vulnerable_series_projects_still_vulnerable():
    life = FakeLifecycle(series_map={"log-REM": _series(True, "STILL_VULNERABLE")})
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 _retest_rec(2, "t1", remediation_id="REM", log_ref="log-REM")],
                lifecycle=life)
    rt = v.active_nodes(NodeLabel.RETEST)[0]
    assert rt.props["status"] == _STATUS_STILL_VULNERABLE


# ==================================================================================================
# 5. Flag ON — anti-rollback floor honored BY THE AUTHORITY (not a producer-supplied in-band value): a
#    truncated/rolled-back series cannot project 'fixed'; an in-band floor/ticks are IGNORED entirely.
# ==================================================================================================
def test_truncated_series_cannot_project_fixed():
    # The attestation-log authority (verify_log) rejects a truncated/rolled-back series (the durable high-water
    # records more ticks than survive) → authenticated=False → NO verified_fixed, only a rolled_back marker.
    life = FakeLifecycle(series_map={"log-REM": RetestSeries(authenticated=False,
                                                             reason="ROLLBACK: durable floor entry_count=3")})
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 _retest_rec(2, "t1", remediation_id="REM", log_ref="log-REM")],
                lifecycle=life)
    statuses = {n.props["status"] for n in v.active_nodes(NodeLabel.RETEST)}
    assert _STATUS_VERIFIED_FIXED not in statuses and statuses == {_STATUS_ROLLED_BACK}


def test_forged_in_band_floor_is_ignored_only_the_authority_decides():
    # RED-PEN HIGH, closed: a forged lowered in-band ``retest_floor`` (and any in-band ``retest_ticks``) on the
    # producer record is NEVER consulted — the projector keys ONLY off the opaque log_ref the authority
    # authenticates. A forged floor that would have made a truncated series 'look full' changes nothing.
    life = FakeLifecycle(series_map={"log-REM": RetestSeries(authenticated=False, reason="truncated")})
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 _retest_rec(2, "t1", remediation_id="REM", log_ref="log-REM",
                             retest_floor=1,                                    # forged, lowered — IGNORED
                             retest_ticks=[{"state": "REMEDIATED"}])],          # forged inline tick — IGNORED
                lifecycle=life)
    statuses = {n.props["status"] for n in v.active_nodes(NodeLabel.RETEST)}
    assert statuses == {_STATUS_ROLLED_BACK}            # the forged in-band floor did NOT launder a 'fixed'


def test_fail_closed_when_no_log_ref():
    # The OLD fail-open shape (inline ticks + an OMITTED floor) now carries NO authenticated log_ref → the
    # projection consults no authority → nothing is projected (never a verified_fixed off unauthenticated data).
    life = FakeLifecycle(series_map={"log-REM": _series(True, "REMEDIATED")})
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 SpineRecord(seq=2, hash="t1", kind="retest",
                             props={"remediation_id": "REM", "retest_ticks": [{"state": "REMEDIATED"}]})],
                lifecycle=life)
    assert v.active_nodes(NodeLabel.RETEST) == []       # no log_ref ⇒ no authenticated series ⇒ nothing
    assert life.series_calls == []


def test_authenticated_full_series_projects_fixed():
    # A genuine, FULL series the authority authenticated against the durable high-water → verified_fixed IS
    # sound (the floor confirms the REMEDIATED tick is the latest, not a rolled-back stale one).
    life = FakeLifecycle(series_map={"log-REM": _series(True, "STILL_VULNERABLE", "REMEDIATED")})
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 _retest_rec(2, "t1", remediation_id="REM", log_ref="log-REM")],
                lifecycle=life)
    statuses = [n.props["status"] for n in sorted(v.active_nodes(NodeLabel.RETEST),
                                                  key=lambda n: n.props["seq"])]
    assert statuses == [_STATUS_STILL_VULNERABLE, _STATUS_VERIFIED_FIXED]


# ==================================================================================================
# 5b. The REAL anti-rollback authority (make_default_lifecycle → attestation_log.verify_log), end-to-end and
#     framework-FREE for these cases: the floor is re-derived from the SIGNED durable high-water on disk, NOT a
#     producer-supplied in-band value. These exercise the production wiring, not a fake.
# ==================================================================================================
def _trust_root():
    k = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=k.public_key_b64)])
    return tr, {"gov0": k.public_key_b64}


def _real_lifecycle(base, tr, pubkeys):
    return make_default_lifecycle(signer_pubkeys=pubkeys, attest_trust_root=tr, attest_log_base=base)


def test_real_authority_rejects_rolled_back_durable_floor(tmp_path):
    # A durable high-water (highwater.json) records entry_count=3, but the tick log + head are gone (an
    # attacker truncated the signed series to hide a regression). The REAL verify_log consults the durable
    # floor and returns a ROLLBACK → the projector caps to rolled_back, never verified_fixed.
    tr, pubkeys = _trust_root()
    logdir = tmp_path / "REM"
    logdir.mkdir()
    (logdir / "highwater.json").write_text(
        json.dumps({"schema_version": 1, "entry_count": 3, "last_seq": 2}), encoding="utf-8")
    life = _real_lifecycle(tmp_path, tr, pubkeys)
    v = project([_rem_rec(1, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
                 _retest_rec(2, "t1", remediation_id="REM", log_ref="REM")], lifecycle=life)
    statuses = {n.props["status"] for n in v.active_nodes(NodeLabel.RETEST)}
    assert statuses == {_STATUS_ROLLED_BACK} and _STATUS_VERIFIED_FIXED not in statuses


def test_real_authority_fail_closed_without_attestation_anchor(tmp_path):
    # No attest_trust_root / attest_log_base ⇒ there is no authenticated durable ledger to consult ⇒
    # fail-closed (rolled_back), never verified_fixed — the whole point of the fix.
    life = make_default_lifecycle(signer_pubkeys={"gov0": "x"})     # no attestation anchor
    v = project([_retest_rec(1, "t1", remediation_id="REM", log_ref="REM")], lifecycle=life)
    rt = v.active_nodes(NodeLabel.RETEST)
    assert len(rt) == 1 and rt[0].props["status"] == _STATUS_ROLLED_BACK


def test_real_authority_confines_log_ref_to_base(tmp_path):
    # A producer-supplied log_ref that escapes the trusted base (path traversal) is refused → fail-closed.
    tr, pubkeys = _trust_root()
    (tmp_path / "base").mkdir()
    # a sibling dir outside the base carrying a (would-be) clean empty log
    (tmp_path / "outside").mkdir()
    life = _real_lifecycle(tmp_path / "base", tr, pubkeys)
    v = project([_retest_rec(1, "t1", remediation_id="REM", log_ref="../outside")], lifecycle=life)
    rt = v.active_nodes(NodeLabel.RETEST)
    assert len(rt) == 1 and rt[0].props["status"] == _STATUS_ROLLED_BACK


# ==================================================================================================
# 6. Inert — Remediation/Retest never in confirmed_findings(); cannot launder a 'fixed'/vuln.
# ==================================================================================================
def test_lifecycle_nodes_are_inert_never_confirmed_findings():
    life = FakeLifecycle({"d1": FindingLink(ok=True, finding_ref="f-1")},
                         {"log-REM": _series(True, "REMEDIATED", "STILL_VULNERABLE")})
    recs = [
        _finding_rec(1, "h1", ref="f-1"),                              # a REAL confirmed finding
        _rem_rec(2, "r1", cert=_rem_cert(finding_cert_digest="d1"), remediation_id="REM"),
        _retest_rec(3, "t1", remediation_id="REM", log_ref="log-REM"),
    ]
    v = project(recs, lifecycle=life)
    confirmed_ids = {n.id for n in v.confirmed_findings()}
    assert confirmed_ids == {"finding:f-1"}                            # ONLY the real finding — never lifecycle
    assert all(n.label == NodeLabel.CHAIN_FINDING for n in v.confirmed_findings())
    assert all(n.label == NodeLabel.CHAIN_FINDING for n in v.lead_findings())
    # a 'verified_fixed' retest did NOT mint a confirmed finding, and a 'still_vulnerable' retest did NOT mint
    # a confirmed vuln — the lifecycle nodes are structurally outside the fact set.
    assert not any(n.label in (NodeLabel.REMEDIATION, NodeLabel.RETEST) for n in v.confirmed_findings())
    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1 and len(v.active_nodes(NodeLabel.RETEST)) == 2


# ==================================================================================================
# 7. Flag ON — Finding-[REMEDIATED_BY]->Remediation-[RETESTED_BY]->Retest traversable in one query;
#    remediation-without-retest distinguishable from passing-retest.
# ==================================================================================================
def test_lifecycle_chain_is_traversable_in_one_query():
    life = FakeLifecycle({"d1": FindingLink(ok=True, finding_ref="f-1")},
                         {"log-REM": _series(True, "REMEDIATED")})
    recs = [
        _finding_rec(1, "h1", ref="f-1"),
        _rem_rec(2, "r1", cert=_rem_cert(finding_cert_digest="d1", finding_ref="f-1"), remediation_id="REM"),
        _retest_rec(3, "t1", remediation_id="REM", log_ref="log-REM"),
    ]
    v = project(recs, lifecycle=life)
    ctx = lifecycle_chains(v)
    assert ctx.authoritative is False and ctx.retrieval_only is True
    assert len(ctx.remediations) == 1
    chain = ctx.remediations[0]
    assert chain.finding_ref == "f-1"                                  # Finding -> Remediation
    assert chain.remediation_id == "REM"
    assert [r.status for r in chain.retests] == [_STATUS_VERIFIED_FIXED]   # Remediation -> Retest
    assert chain.current_status == _STATUS_VERIFIED_FIXED

    # raw one-pass traversal over the edges proves the single-query chain finding→remediation→retest.
    rem_edge = next(e for e in v.edges if e.type == EdgeType.REMEDIATED_BY)
    retest_edge = next(e for e in v.edges if e.type == EdgeType.RETESTED_BY and e.src == rem_edge.dst)
    assert rem_edge.src == "finding:f-1" and v.get(retest_edge.dst).props["status"] == _STATUS_VERIFIED_FIXED


def test_remediation_without_retest_is_distinguishable_from_passing_retest():
    life = FakeLifecycle({"d1": FindingLink(ok=True, finding_ref="f-1"),
                          "d2": FindingLink(ok=True, finding_ref="f-2")},
                         {"log-REM1": _series(True, "REMEDIATED")})
    recs = [
        _finding_rec(1, "h1", ref="f-1"), _finding_rec(2, "h2", ref="f-2"),
        # REM1: remediation WITH a passing (authenticated) retest.
        _rem_rec(3, "r1", cert=_rem_cert(finding_cert_digest="d1", finding_ref="f-1"), remediation_id="REM1"),
        _retest_rec(4, "t1", remediation_id="REM1", log_ref="log-REM1"),
        # REM2: remediation with NO retest at all.
        _rem_rec(5, "r2", cert=_rem_cert(finding_cert_digest="d2", finding_ref="f-2"), remediation_id="REM2"),
    ]
    v = project(recs, lifecycle=life)
    by_id = {c.remediation_id: c for c in lifecycle_chains(v).remediations}
    assert by_id["REM1"].current_status == _STATUS_VERIFIED_FIXED and by_id["REM1"].retests
    assert by_id["REM2"].current_status == NO_RETEST and by_id["REM2"].retests == []   # clearly distinct


# ==================================================================================================
# 8. Cross-tenant — a remediation that resolves only under another tenant is rejected (not projected onto
#    this engagement's finding). (The real S1 tenant-scoping is in test_graph_lifecycle_s1.py; here the fake
#    mirrors it: a cross-tenant digest is ABSENT → None → no edge.)
# ==================================================================================================
def test_cross_tenant_finding_cert_is_not_linked():
    # "d-other" resolves only under ANOTHER tenant's root → this engagement's resolver returns None for it.
    life = FakeLifecycle({"d-mine": FindingLink(ok=True, finding_ref="f-1")})   # only our own tenant's cert
    v = project([_finding_rec(1, "h1", ref="f-1"),
                 _rem_rec(2, "r1", cert=_rem_cert(finding_cert_digest="d-other"), remediation_id="REM")],
                lifecycle=life)
    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == []       # never linked cross-tenant


# ==================================================================================================
# 9. Determinism — ON projection is a pure fn of (spine + remediation certs + authenticated series);
#    byte-identical rebuild; no wallclock.
# ==================================================================================================
def test_lifecycle_projection_is_deterministic_regardless_of_order():
    def _life():
        return FakeLifecycle({"d1": FindingLink(ok=True, finding_ref="f-1")},
                             {"log-REM": _series(True, "STILL_VULNERABLE", "REMEDIATED")})
    recs = [
        _finding_rec(1, "h1", ref="f-1"),
        _rem_rec(2, "r1", cert=_rem_cert(finding_cert_digest="d1", finding_ref="f-1"), remediation_id="REM"),
        _retest_rec(3, "t1", remediation_id="REM", log_ref="log-REM"),
    ]
    a = project(recs, lifecycle=_life()).model_dump()
    b = project(list(reversed(recs)), lifecycle=_life()).model_dump()
    assert a == b                                            # same spine, any order → byte-identical rebuild


# ==================================================================================================
# 10. No-offense — the projection issues no traffic and runs no live retest; a symbol-grep guard confirms
#     no new exec/egress/tool symbol entered the projector (or the lifecycle query).
# ==================================================================================================
_FORBIDDEN_SYMBOLS = (
    "subprocess", "os.system", "os.popen", "pty.", "socket", "requests", "httpx", "urllib",
    "http.client", "ftplib", "smtplib", "telnetlib", "asyncio", "ctypes", "pickle", "marshal",
    "eval(", "exec(", "compile(", "__import__(", "os.exec", "posix_spawn",
)


def _code_only(src: str) -> str:
    """The source with every STRING literal + COMMENT blanked to spaces (positions preserved), so the symbol
    grep is over real CODE — a docstring/comment that merely NAMES a URL-parsing RFC (``RFC/urllib``) is not a
    capability and must not trip the guard, while a genuine ``import urllib`` / ``os.system(`` / ``exec(`` in
    code still would."""
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


def test_symbol_grep_guard_no_tool_exec_or_egress():
    for src_path in (_PROJECTOR_SRC, _QUERY_SRC):
        raw = src_path.read_text(encoding="utf-8")
        ast.parse(raw)                     # the grep is over real, parseable source (not a truncated file)
        code = _code_only(raw)             # strings + comments blanked → grep only executable code
        hits = [sym for sym in _FORBIDDEN_SYMBOLS if sym in code]
        assert not hits, f"{src_path.name} carries forbidden tool/exec/egress symbol(s): {hits}"


def test_projector_module_scope_imports_no_framework():
    # FATAL-2: the projector's MODULE SCOPE must pull no ``framework`` — every framework import is lazy
    # (function-local) inside the default lifecycle wiring. Importing the module here (in the sovereign leg,
    # where framework is NOT on the path) already proves it, but assert the source shape too for clarity.
    src = _PROJECTOR_SRC.read_text(encoding="utf-8")
    tree = ast.parse(src)
    module_level_imports: list[str] = []
    for node in tree.body:                 # ONLY top-level statements (function-local imports are excluded)
        if isinstance(node, ast.ImportFrom) and node.module:
            module_level_imports.append(node.module)
        elif isinstance(node, ast.Import):
            module_level_imports.extend(a.name for a in node.names)
    assert not any(m.startswith("framework") for m in module_level_imports), module_level_imports
