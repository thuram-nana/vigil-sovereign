"""Investigation-graph S2 — the deterministic, offline acceptance suite for the JOIN-verified CONFIRMED
boundary (``VIGIL_GRAPH_EVIDENCE_JOIN``, default OFF; DEMOTE-ONLY).

The through-line every test defends: under the flag, a finding node is CONFIRMED only if its
``evidence_ref`` DEREFERENCES (the S1 ``evidence.resolver``) to a cert that RE-VERIFIES with authenticity
ANCHORED to the engagement's OUT-OF-BAND governance fingerprint (the REUSED ``verify_certificate`` — never
a second verifier; a bundle can NEVER self-authenticate — S1's hardened ``.ok == verification.ok AND
authenticity_pinned``) AND binds to THIS finding (``finding_ref``), THIS tenant/engagement
(``engagement_slug``), and a host-in-scope that matches the finding's declared asset host. The join can
ONLY tighten — for every fixture the ON set of CONFIRMED findings is a SUBSET of the OFF set. Every test is
deterministic (no wallclock/RNG — the resolver is a pure function of on-disk contents) and offline (no
network, no live oracle; re-verification is over retained bytes via the existing verifier).

This file builds REAL on-disk PCF bundles through the evidence layer, so it imports ``framework`` — which
is only importable in CI's OFFENSE leg. It is registered in ``.github/workflows/ci.yml``'s offense-leg
run-list (guarded by ``test_ci_framework_tests_run_in_offense_leg.py``); it SKIPS in the sovereign leg.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.certify")

from framework.v2.entitlement.crypto import generate_keypair           # noqa: E402
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot    # noqa: E402
from framework.v2.evidence.audit_package import write_package          # noqa: E402
from framework.v2.evidence.certify import (                            # noqa: E402
    build_certificate,
    sign_certificate,
    trust_root_fingerprint,
)
from framework.v2.evidence.chain import build_chain, sign_head          # noqa: E402
from framework.v2.evidence.resolver import resolve_and_verify           # noqa: E402
from framework.v2.verify.adapter import FindingContext                  # noqa: E402
from framework.v2.verify.client_side_posture import ingest_response_headers  # noqa: E402
from framework.v2.verify.reverify import reverify_context               # noqa: E402

from vigil_integration.graph import (                                   # noqa: E402
    NodeLabel,
    SpineRecord,
    project,
    query_prior_chains,
)

_SPINE_SIG = "sig:spine-head"   # a non-empty spine signature_ref so slice-1 ``_is_confirmed`` holds


# --------------------------------------------------------------------------------------------------
# Builders — a genuine offline oracle re-fire + a signed on-disk PCF bundle (mirrors the S1 suite).
# --------------------------------------------------------------------------------------------------
def _cj_oc(url: str) -> dict:
    """A clickjacking posture context for ``url`` whose response ships NO framing defense — it re-fires
    OFFLINE (zero traffic) and carries a ``url`` whose authority is the finding's host."""
    return FindingContext.from_clickjacking_control(
        ingest_response_headers(url, {"content-type": "text/html"})).to_verifier_context()


def _mesh_oc() -> dict:
    """A permissive-mTLS mesh posture context — re-fires offline and carries NO host (posture, not web)."""
    return FindingContext.from_mesh_control(
        {"resource_kind": "PeerAuthentication", "provider": "istio", "name": "default",
         "namespace": "istio-system", "mtls_mode": "PERMISSIVE"}).to_verifier_context()


def _finding_from(oc: dict, check_id: str) -> dict:
    rr = reverify_context(oc, bug_class=str(oc.get("bug_class", "")))
    assert rr.ok, f"fixture context for {check_id} did not re-fire: {rr.note}"
    return {"check_id": check_id, "bug_class": str(oc.get("bug_class", "")),
            "confirmed_by": rr.confirmed_by, "confidence": rr.confidence, "oracle_context": oc}


def _trust_root(threshold: int = 2, n: int = 3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _write_bundle(out_dir: Path, findings: list[dict], signers, trust_root: TrustRoot, *, slug: str):
    signed = []
    contexts: dict[str, dict] = {}
    for i, f in enumerate(findings):
        cert = build_certificate(f, engagement_slug=slug, seq=i)
        signed.append(sign_certificate(cert, signers))
        contexts[cert.finding_ref] = f["oracle_context"]
    chain = build_chain([sc.certificate.cert_digest for sc in signed])
    head = sign_head(chain, engagement_slug=slug, signers=signers)
    write_package(out_dir, certificates=signed, chain=chain, head=head, contexts=contexts,
                  trust_root=trust_root, engagement_slug=slug)
    return signed, contexts


def _cj_bundle(root: Path, check_id: str, url: str, *, slug: str = "eng", subdir: str = "bundle"):
    """One clickjacking FACT in a signed bundle under ``root/subdir``. Returns
    (cert_digest, contexts, genuine_fingerprint) — the fingerprint is the engagement's OUT-OF-BAND anchor a
    sound caller pins against."""
    tr, signers = _trust_root()
    signed, contexts = _write_bundle(root / subdir, [_finding_from(_cj_oc(url), check_id)],
                                     signers[:2], tr, slug=slug)
    return signed[0].certificate.cert_digest, contexts, trust_root_fingerprint(tr)


def _rec(seq: int, h: str, *, ref: str, evidence_ref: str, engagement_id: str = "eng",
         targets=None, severity: str = "high") -> SpineRecord:
    """A signed-on-spine FACT finding record (slice-1 ``_is_confirmed`` holds: status=fact + non-empty
    evidence_ref + non-empty signature_ref)."""
    return SpineRecord(seq=seq, hash=h, kind="finding", finding_ref=ref, status="fact",
                       evidence_ref=evidence_ref, signature_ref=_SPINE_SIG, engagement_id=engagement_id,
                       props={"ref": ref, "severity": severity}, targets=targets or [])


def _throwaway_fp() -> str:
    """A genuine-looking out-of-band fingerprint for a scenario with NO bundle (so the demote is isolated to
    its real cause — a dangling id resolves to None before any pin matters)."""
    return trust_root_fingerprint(_trust_root()[0])


@contextlib.contextmanager
def _join(on: bool):
    """Toggle ``VIGIL_GRAPH_EVIDENCE_JOIN`` for a block (the projector reads it at call time), restoring it
    after — so OFF and ON projections can be compared inside one test."""
    old = os.environ.get("VIGIL_GRAPH_EVIDENCE_JOIN")
    if on:
        os.environ["VIGIL_GRAPH_EVIDENCE_JOIN"] = "1"
    else:
        os.environ.pop("VIGIL_GRAPH_EVIDENCE_JOIN", None)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("VIGIL_GRAPH_EVIDENCE_JOIN", None)
        else:
            os.environ["VIGIL_GRAPH_EVIDENCE_JOIN"] = old


def _confirmed_refs(view) -> set:
    return {n.props.get("ref", n.id) for n in view.confirmed_findings()}


@pytest.fixture(autouse=True)
def _arm_resolver(monkeypatch):
    # the S2 join dereferences through the S1 resolver, which is itself default-OFF. Arm it for the suite.
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    monkeypatch.setenv("VIGIL_GRAPH_EVIDENCE_JOIN", "1")


# ==================================================================================================
# ACCEPTANCE TESTS — one per S2 criterion.
# ==================================================================================================
def test_join_happy_path_host_in_scope_stays_confirmed(tmp_path):
    """Flag ON happy path: a finding whose evidence_ref resolves to a cert that re-verifies (pinned to the
    engagement's genuine out-of-band fingerprint) AND finding_ref matches AND host-in-scope stays
    CONFIRMED — unchanged from OFF for a sound finding."""
    cid, ctx, fp = _cj_bundle(tmp_path, "cj-ok", "https://api.example.com/account")
    recs = [_rec(1, "h1", ref="cj-ok", evidence_ref=cid,
                 targets=[{"type": "host", "value": "api.example.com"}])]
    view = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx,
                   scope_gate=lambda h: h == "api.example.com", trust_root_fingerprint=fp)
    assert _confirmed_refs(view) == {"cj-ok"}                       # join-verified fact stays CONFIRMED
    node = view.get("finding:cj-ok")
    assert node.is_confirmed and node.provenance.evidence_ref == cid
    assert node.props.get("evidence_join") == "confirmed"           # tagged join-confirmed (membership overlay)
    # the host bridge was admitted too (in scope).
    assert {n.props["value"] for n in view.active_nodes(NodeLabel.HOST)} == {"api.example.com"}
    # unchanged from OFF (OFF also confirms it on the non-empty check — and needs no pin).
    with _join(False):
        assert _confirmed_refs(project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx)) == {"cj-ok"}


def test_join_dangling_ref_demotes_to_unresolved_evidence(tmp_path):
    """Flag ON dangling ref: a status=fact record with a non-empty but UNRESOLVABLE evidence_ref is NOT
    CONFIRMED (degrades to unresolved_evidence), where OFF it would have been."""
    recs = [_rec(1, "h1", ref="ghost", evidence_ref="sha256:" + ("dead" * 16))]   # 64 hex, no backing
    view = project(recs, group_id="eng", evidence_root=tmp_path, contexts={},
                   trust_root_fingerprint=_throwaway_fp())
    assert view.confirmed_findings() == []                          # EXCLUDED at the confirmed boundary
    node = view.get("finding:ghost")
    assert node is not None
    assert node.props.get("evidence_join") == "unresolved_evidence"  # tagged (membership overlay)
    assert node.is_confirmed is True                                 # intrinsic status UNCHANGED by the join
    assert "finding:ghost" in {n.id for n in view.lead_findings()}   # surfaced as a lead, never lost
    # OFF: the same record WOULD be confirmed (slice-1 non-empty check).
    with _join(False):
        assert _confirmed_refs(project(recs, group_id="eng", evidence_root=tmp_path)) == {"ghost"}


def test_join_unpinned_evidence_does_not_confirm(tmp_path):
    """Flag ON, NO out-of-band pin: a genuine, internally-sound bundle still does NOT confirm when the
    engagement fingerprint is not plumbed — a bundle cannot self-authenticate (S1's hardened contract: .ok
    requires authenticity_pinned). Fail-closed demote; with the genuine pin it confirms (control)."""
    cid, ctx, fp = _cj_bundle(tmp_path, "cj-ok", "https://api.example.com/ok")
    recs = [_rec(1, "h1", ref="cj-ok", evidence_ref=cid,
                 targets=[{"type": "host", "value": "api.example.com"}])]
    gate = lambda h: h == "api.example.com"  # noqa: E731
    v_unpinned = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx, scope_gate=gate)
    assert v_unpinned.confirmed_findings() == []                    # trust_root_fingerprint omitted → demote
    assert v_unpinned.get("finding:cj-ok").props.get("evidence_join") == "unresolved_evidence"
    v_pinned = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx, scope_gate=gate,
                       trust_root_fingerprint=fp)
    assert _confirmed_refs(v_pinned) == {"cj-ok"}                   # control: with the genuine pin, confirmed


def test_join_forged_self_signed_bundle_does_not_confirm(tmp_path):
    """Flag ON forged bundle (the EXACT S1 red-pen hole): a bundle that ships its OWN governance root and a
    cert signed under it RESOLVES and INTERNALLY re-verifies — but authenticity is credited ONLY against
    the engagement's genuine out-of-band fingerprint, so the JOIN pinned to the real anchor does NOT confirm
    it."""
    cid, ctx, forged_fp = _cj_bundle(tmp_path, "forge", "https://api.example.com/f")
    genuine_fp = _throwaway_fp()    # the engagement's REAL governance anchor — a DIFFERENT root
    assert genuine_fp != forged_fp
    # the forged bundle self-authenticates under its OWN (forged) fingerprint — it is internally consistent.
    rv_self = resolve_and_verify(cid, ctx, root=tmp_path, expected_trust_root_fingerprint=forged_fp)
    assert rv_self is not None and rv_self.ok is True and rv_self.authenticity_pinned is True
    # ...yet pinned to the GENUINE engagement root the pin MISMATCHES → authenticity fails → not ok.
    rv_genuine = resolve_and_verify(cid, ctx, root=tmp_path, expected_trust_root_fingerprint=genuine_fp)
    assert rv_genuine is not None and rv_genuine.ok is False and rv_genuine.verification.authentic is False
    # the JOIN, pinned to the genuine fingerprint, does NOT confirm the node (hole stays closed).
    recs = [_rec(1, "h1", ref="forge", evidence_ref=cid,
                 targets=[{"type": "host", "value": "api.example.com"}])]
    view = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx,
                   scope_gate=lambda h: h == "api.example.com", trust_root_fingerprint=genuine_fp)
    assert view.confirmed_findings() == []
    assert view.get("finding:forge").props.get("evidence_join") == "unresolved_evidence"


def test_join_mismatched_finding_ref_does_not_confirm(tmp_path):
    """Flag ON mismatched finding: a cert that resolves+verifies but whose finding_ref is finding A,
    referenced on finding B's node, does NOT confirm B."""
    cid_a, ctx_a, fp = _cj_bundle(tmp_path, "finding-A", "https://api.example.com/a")
    recs = [_rec(1, "hB", ref="finding-B", evidence_ref=cid_a,          # B points at A's cert
                 targets=[{"type": "host", "value": "api.example.com"}])]
    view = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx_a,
                   scope_gate=lambda h: True, trust_root_fingerprint=fp)
    assert view.confirmed_findings() == []
    assert view.get("finding:finding-B").props.get("evidence_join") == "unresolved_evidence"


def test_join_cross_engagement_does_not_confirm(tmp_path):
    """Flag ON cross-engagement: a cert that resolves+verifies but whose engagement_slug is another
    engagement does not confirm this engagement's finding."""
    cid, ctx, fp = _cj_bundle(tmp_path, "cj-x", "https://api.example.com/x", slug="other-eng")
    recs = [_rec(1, "h1", ref="cj-x", evidence_ref=cid, engagement_id="eng",   # finding's engagement != cert's
                 targets=[{"type": "host", "value": "api.example.com"}])]
    view = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx,
                   scope_gate=lambda h: True, trust_root_fingerprint=fp)
    assert view.confirmed_findings() == []
    assert view.get("finding:cj-x").props.get("evidence_join") == "unresolved_evidence"


def test_join_cross_tenant_other_root_does_not_confirm(tmp_path):
    """Flag ON cross-tenant: a cert that resolves only under ANOTHER root is invisible to this tenant's
    resolver → the finding does not confirm; the SAME cert confirms under its own root (tenant isolation)."""
    root_b = tmp_path / "tenant-b"
    root_a = tmp_path / "tenant-a"
    root_a.mkdir()
    cid, ctx, fp = _cj_bundle(root_b, "cj-t", "https://api.example.com/t")
    recs = [_rec(1, "h1", ref="cj-t", evidence_ref=cid,
                 targets=[{"type": "host", "value": "api.example.com"}])]
    # resolver pointed at tenant-a (which does NOT hold the cert) → dangling → demote.
    v_wrong = project(recs, group_id="eng", evidence_root=root_a, contexts=ctx,
                      scope_gate=lambda h: True, trust_root_fingerprint=fp)
    assert v_wrong.confirmed_findings() == []
    # resolver pointed at tenant-b (the cert's own root) → resolves + confirms.
    v_right = project(recs, group_id="eng", evidence_root=root_b, contexts=ctx,
                      scope_gate=lambda h: h == "api.example.com", trust_root_fingerprint=fp)
    assert _confirmed_refs(v_right) == {"cj-t"}


def test_join_host_out_of_scope_or_mismatch_does_not_confirm(tmp_path):
    """Flag ON host-out-of-scope: a cert that resolves+verifies but whose oracle-context host != the
    finding's asset host (sub-case a), OR whose host is out of charter scope (sub-case b), does NOT
    confirm."""
    # (a) the cert's evidence is about ``evidence-host.tld`` but the finding CLAIMS ``claimed-host.tld``.
    cid_a, ctx_a, fp_a = _cj_bundle(tmp_path, "cj-a", "https://evidence-host.tld/p", subdir="a")
    recs_a = [_rec(1, "ha", ref="cj-a", evidence_ref=cid_a,
                   targets=[{"type": "host", "value": "claimed-host.tld"}])]
    v_a = project(recs_a, group_id="eng", evidence_root=tmp_path, contexts=ctx_a,
                  scope_gate=lambda h: True, trust_root_fingerprint=fp_a)  # both hosts in scope → cause is the MISMATCH
    assert v_a.confirmed_findings() == []
    assert v_a.get("finding:cj-a").props.get("evidence_join") == "unresolved_evidence"

    # (b) host matches the evidence, but the charter scope gate DENIES it → out of charter scope.
    cid_b, ctx_b, fp_b = _cj_bundle(tmp_path, "cj-b", "https://api.example.com/q", subdir="b")
    recs_b = [_rec(1, "hb", ref="cj-b", evidence_ref=cid_b,
                   targets=[{"type": "host", "value": "api.example.com"}])]
    v_b = project(recs_b, group_id="eng", evidence_root=tmp_path, contexts=ctx_b,
                  scope_gate=lambda h: False, trust_root_fingerprint=fp_b)   # deny the host → out of scope
    assert v_b.confirmed_findings() == []
    assert v_b.get("finding:cj-b").props.get("evidence_join") == "unresolved_evidence"


def _bare_refute(seq, h, ref):
    return SpineRecord(seq=seq, hash=h, kind="refute", refutes_id=f"finding:{ref}")


def _grounded_refute(seq, h, ref):
    return SpineRecord(seq=seq, hash=h, kind="refute", refutes_id=f"finding:{ref}",
                       evidence_ref="refute-cert:9", signature_ref="sig:9")


def test_join_is_demote_only_across_fixtures(tmp_path):
    """Monotone-stricter: for EVERY fixture — single-record AND multi-record spines WITH refutes — the ON
    CONFIRMED set is a SUBSET of the OFF set (the join can only demote, never promote). The refute fixtures
    are the regression surface for the red-pen MEDIUM: a per-record demotion would re-open the
    bare-refute/resurrection path and PROMOTE."""
    cid_ok, ctx_ok, fp_ok = _cj_bundle(tmp_path, "ok", "https://api.example.com/ok", subdir="ok")
    cid_eng, ctx_eng, fp_eng = _cj_bundle(tmp_path, "eng-x", "https://api.example.com/e",
                                          slug="elsewhere", subdir="e")
    cid_x, ctx_x, fp_x = _cj_bundle(tmp_path, "X", "https://api.example.com/x", subdir="x")

    def _dangling_fact(ref):
        return _rec(1, "h1", ref=ref, evidence_ref="dead" * 16,
                    targets=[{"type": "host", "value": "api.example.com"}])

    def _real_fact(seq, h, ref):
        return _rec(seq, h, ref=ref, evidence_ref=cid_x,
                    targets=[{"type": "host", "value": "api.example.com"}])

    fixtures = {
        "happy": ([_rec(1, "h1", ref="ok", evidence_ref=cid_ok,
                        targets=[{"type": "host", "value": "api.example.com"}])], ctx_ok, fp_ok),
        "dangling": ([_rec(1, "h1", ref="ghost", evidence_ref="f" * 64)], {}, fp_ok),
        "cross_engagement": ([_rec(1, "h1", ref="eng-x", evidence_ref=cid_eng,
                                   targets=[{"type": "host", "value": "api.example.com"}])], ctx_eng, fp_eng),
        "no_host_posture": ([_rec(1, "h1", ref="ok", evidence_ref=cid_ok)], ctx_ok, fp_ok),
        "unpinned": ([_rec(1, "h1", ref="ok", evidence_ref=cid_ok,
                          targets=[{"type": "host", "value": "api.example.com"}])], ctx_ok, None),
        "plain_lead": ([SpineRecord(seq=1, hash="h1", kind="finding", finding_ref="lead", status="lead",
                                    props={"ref": "lead"})], {}, fp_ok),
        # --- multi-record spines WITH refutes (the red-pen regression surface) ---
        # a bare refute of a join-DEMOTED (dangling) fact: OFF keeps it CONFIRMED (bare refute blocked on a
        # confirmed node), ON demotes it (tag) → ON ⊂ OFF, never a promotion.
        "bare_refute_on_demoted": ([_dangling_fact("X"), _bare_refute(2, "h2", "X")], ctx_x, fp_x),
        # the full cascade: dangling fact → bare refute → grounded (permanent) refute → real re-attestation.
        # OFF ends {} (grounded retirement blocks resurrection); ON must also be {} (never {X}).
        "refute_cascade": ([_dangling_fact("X"), _bare_refute(2, "h2", "X"),
                            _grounded_refute(3, "h3", "X"), _real_fact(4, "h4", "X")], ctx_x, fp_x),
        # a real pinned fact → grounded refute → real re-attestation: OFF stays retired (no resurrection of a
        # grounded retirement); ON identical (join never mutates is_confirmed).
        "grounded_then_reattest": ([_real_fact(1, "h1", "X"), _grounded_refute(2, "h2", "X"),
                                    _real_fact(3, "h3", "X")], ctx_x, fp_x),
    }
    for name, (recs, ctx, fp) in fixtures.items():
        with _join(False):
            off = _confirmed_refs(project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx,
                                          scope_gate=lambda h: h == "api.example.com",
                                          trust_root_fingerprint=fp))
        with _join(True):
            on = _confirmed_refs(project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx,
                                         scope_gate=lambda h: h == "api.example.com",
                                         trust_root_fingerprint=fp))
        assert on <= off, f"fixture {name!r} is NOT demote-only: ON={on} OFF={off}"


def test_join_multirecord_refute_resurrection_is_demote_only(tmp_path):
    """The red-pen MEDIUM, isolated: the EXACT promoting spine (same finding_ref X: dangling fact → bare
    refute → grounded refute → real pinned re-attestation). Before the membership-overlay fix, demoting the
    first fact to a LEAD let the bare refute consume the one-shot retirement slot so the re-attestation
    RESURRECTED X under ON while OFF stayed retired — ON={X} ⊄ OFF={}. The join must never mutate
    is_confirmed, so ON ⊆ OFF (both {} here)."""
    cid, ctx, fp = _cj_bundle(tmp_path, "X", "https://api.example.com/x")
    gate = lambda h: h == "api.example.com"  # noqa: E731

    def recs():
        return [
            _rec(1, "h1", ref="X", evidence_ref="dead" * 16,            # DANGLING (OFF trusts on sight)
                 targets=[{"type": "host", "value": "api.example.com"}]),
            SpineRecord(seq=2, hash="h2", kind="refute", refutes_id="finding:X"),             # bare refute
            SpineRecord(seq=3, hash="h3", kind="refute", refutes_id="finding:X",
                        evidence_ref="refute-cert:9", signature_ref="sig:9"),                  # grounded refute
            _rec(4, "h4", ref="X", evidence_ref=cid,                    # REAL pinned re-attestation
                 targets=[{"type": "host", "value": "api.example.com"}]),
        ]

    with _join(False):
        off = _confirmed_refs(project(recs(), group_id="eng", evidence_root=tmp_path, contexts=ctx,
                                      scope_gate=gate, trust_root_fingerprint=fp))
    with _join(True):
        v_on = project(recs(), group_id="eng", evidence_root=tmp_path, contexts=ctx,
                       scope_gate=gate, trust_root_fingerprint=fp)
        on = _confirmed_refs(v_on)
    assert off == set()                 # grounded retirement is permanent — no resurrection
    assert on <= off                    # demote-only: NO promotion (the bug produced ON == {"X"})
    assert on == set()
    # the node ends inactive+grounded under ON exactly as under OFF (the join did not touch is_confirmed).
    node = v_on.get("finding:X")
    assert node is not None and not node.is_active and node.invalid_grounded is True


def test_join_bare_refute_cannot_demote_but_grounded_refute_retires(tmp_path):
    """Flag ON: a bare (unsigned) refute still CANNOT demote a join-confirmed fact; a grounded (signed)
    refute still retires it — the existing demotion rule is untouched by the join."""
    cid, ctx, fp = _cj_bundle(tmp_path, "cj-r", "https://api.example.com/r")
    base = _rec(1, "h1", ref="cj-r", evidence_ref=cid,
                targets=[{"type": "host", "value": "api.example.com"}])
    gate = lambda h: h == "api.example.com"  # noqa: E731
    # bare refute → the join-confirmed fact survives (an unauthenticated opinion cannot drop a proof).
    v_bare = project([base, SpineRecord(seq=2, hash="rb", kind="refute", refutes_id="finding:cj-r")],
                     group_id="eng", evidence_root=tmp_path, contexts=ctx, scope_gate=gate,
                     trust_root_fingerprint=fp)
    assert _confirmed_refs(v_bare) == {"cj-r"} and v_bare.get("finding:cj-r").is_active
    # grounded (signed) refute → the fact is retired.
    v_grounded = project([base, SpineRecord(seq=2, hash="rg", kind="refute", refutes_id="finding:cj-r",
                                            evidence_ref="refute-cert:9", signature_ref="sig:9")],
                         group_id="eng", evidence_root=tmp_path, contexts=ctx, scope_gate=gate,
                         trust_root_fingerprint=fp)
    assert v_grounded.confirmed_findings() == [] and not v_grounded.get("finding:cj-r").is_active


def test_join_leads_never_leak_into_confirmed_findings(tmp_path):
    """Flag ON: leads — including a finding the join DEMOTED — stay in the separate ``leads`` field and
    never leak into confirmed_findings()."""
    cid, ctx, fp = _cj_bundle(tmp_path, "cj-ok", "https://api.example.com/ok")
    recs = [
        _rec(1, "h1", ref="cj-ok", evidence_ref=cid, targets=[{"type": "host", "value": "api.example.com"}]),
        _rec(2, "h2", ref="demoted", evidence_ref="a" * 64, targets=[{"type": "host", "value": "api.example.com"}]),
        SpineRecord(seq=3, hash="h3", kind="finding", finding_ref="plain-lead", status="lead",
                    props={"ref": "plain-lead", "severity": "high"}),
    ]
    view = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx,
                   scope_gate=lambda h: h == "api.example.com", trust_root_fingerprint=fp)
    assert _confirmed_refs(view) == {"cj-ok"}                       # ONLY the join-verified fact
    lead_refs = {n.props.get("ref") for n in view.lead_findings()}
    assert lead_refs == {"demoted", "plain-lead"}                   # the demoted fact is a lead now
    ctxq = query_prior_chains(view)
    assert {f.ref for f in ctxq.confirmed_findings} == {"cj-ok"}    # retrieval boundary: confirmed only
    assert "demoted" in {f.ref for f in ctxq.leads}
    demoted = next(f for f in ctxq.leads if f.ref == "demoted")
    assert demoted.unresolved_reason == "unresolved_evidence"       # surfaced at the query boundary


def test_join_projection_is_deterministic(tmp_path):
    """Determinism: ON projection is a pure function of (spine records + resolver contents + pin) —
    identical inputs yield a BYTE-IDENTICAL GraphView (no wallclock / RNG; re-verify is over retained
    bytes)."""
    cid, ctx, fp = _cj_bundle(tmp_path, "cj-ok", "https://api.example.com/ok")
    recs = [_rec(1, "h1", ref="cj-ok", evidence_ref=cid,
                 targets=[{"type": "host", "value": "api.example.com"}])]
    gate = lambda h: h == "api.example.com"  # noqa: E731
    a = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx, scope_gate=gate,
                trust_root_fingerprint=fp).model_dump()
    b = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx, scope_gate=gate,
                trust_root_fingerprint=fp).model_dump()
    assert a == b


def test_join_requires_the_resolver_armed_fail_closed(tmp_path, monkeypatch):
    """Honest limitation: the join dereferences through the S1 resolver, which is itself default-OFF. With
    the join flag ON but ``VIGIL_EVIDENCE_RESOLVER`` OFF, the evidence cannot be re-verified, so the fact
    fail-closed DEMOTES (never silently confirmed on the non-empty check) — still demote-only."""
    cid, ctx, fp = _cj_bundle(tmp_path, "cj-ok", "https://api.example.com/ok")
    monkeypatch.delenv("VIGIL_EVIDENCE_RESOLVER", raising=False)     # resolver not armed
    recs = [_rec(1, "h1", ref="cj-ok", evidence_ref=cid,
                 targets=[{"type": "host", "value": "api.example.com"}])]
    view = project(recs, group_id="eng", evidence_root=tmp_path, contexts=ctx,
                   scope_gate=lambda h: h == "api.example.com", trust_root_fingerprint=fp)
    assert view.confirmed_findings() == []
    assert view.get("finding:cj-ok").props.get("evidence_join") == "unresolved_evidence"
