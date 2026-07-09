"""
W1.5 — self-consistency wrappers for the other no-oracle bindings (severity / pivot / threat-model),
mirroring hypothesize_consistent. These prove, for each wrapper:

  * BYTE-IDENTICAL on the deterministic dry-run backend (every sample identical -> agreement 1.0,
    not abstained, n_samples preserved) — the same contract test_consistency asserts for hypothesize;
  * the key_fn clusters on the DECISION-bearing signature, not the prose (a scattered decision
    abstains, a same-decision/different-prose pair agrees);

all ADVISORY: the abstention/entropy signal never enters the oracle/SCE/calibration.
"""

from __future__ import annotations

from framework.v2.kernel import run_consistent
from framework.v2.kernel.backends.dryrun import DryRunBackend
from framework.v2.kernel.decide import _severity_signature, decide_consistent
from framework.v2.kernel.models import (
    Asset, Actor, AttackTreeNode, LateralMove, PivotProposal, SeverityDecision,
    StrideThreat, ThreatModel, TrustBoundary,
)
from framework.v2.kernel.pivot import _pivot_signature, pivot_consistent
from framework.v2.kernel.threat_model import _threat_signature, threat_model_consistent


# ---- compact model builders (required fields only) -------------------------


def _sev(severity="High", *, worth="finding", note="ctx", summary="s") -> SeverityDecision:
    return SeverityDecision(
        finding_summary=summary, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_base=8.0, severity=severity, contextual_note=note, likelihood="high",
        impact="high", worth_reporting=worth, immediate_surface_to_operator=False,
        regulator_paragraph="reg")


def _move(kind, *, suggestion="s") -> LateralMove:
    return LateralMove(kind=kind, suggestion=suggestion, rationale="r",
                       estimated_effort="hours", confidence=0.5)


def _pivot(kinds, *, suggestion="s") -> PivotProposal:
    ks = list(kinds)
    while len(ks) < 3:                      # PivotProposal requires >= 3 moves; repeats don't
        ks.append(ks[0])                    # change the DISTINCT-kind signature we cluster on
    return PivotProposal(stuck_thread="t", last_observation="o",
                         moves=[_move(k, suggestion=suggestion) for k in ks], recommended=0)


def _tm(stride_classes=("S", "T"), priorities=("P0",), *, ctx="ctx") -> ThreatModel:
    return ThreatModel(
        business_context=ctx,
        assets=[Asset(id=f"A{i}", name=f"asset{i}", rationale="r", confidentiality="high",
                      integrity="high", availability="high", priority=p)
                for i, p in enumerate(priorities)],
        actors=[Actor(id="T1", name="attacker", goal="g", skill="expert", motivation="motivated")],
        trust_boundaries=[TrustBoundary(name="b", data_crossing="d", auth_check="a", failure_mode="f")],
        stride_threats=[StrideThreat(boundary="b", stride_class=c, threat="x", realistic=True)
                        for c in stride_classes],
        attack_tree=AttackTreeNode(label="root"))


# ---- dry-run byte-stability (the anti-hallucination contract) ---------------


def test_decide_consistent_is_stable_on_the_dry_run_backend() -> None:
    r = decide_consistent("Webhook accepts arbitrary balance updates without auth",
                          impact_observed="balances drained", backend=DryRunBackend(), samples=3)
    assert r.n_samples == 3 and r.agreement == 1.0 and not r.abstained
    assert isinstance(r.modal, SeverityDecision)


def test_pivot_consistent_is_stable_on_the_dry_run_backend() -> None:
    r = pivot_consistent("SQLi thread blocked by WAF", blockers=("WAF",),
                         backend=DryRunBackend(), samples=3)
    assert r.n_samples == 3 and r.agreement == 1.0 and not r.abstained
    assert isinstance(r.modal, PivotProposal) and len(r.modal.moves) >= 3


def test_threat_model_consistent_is_stable_on_the_dry_run_backend() -> None:
    r = threat_model_consistent("acme-shop", archetype="woocommerce",
                                backend=DryRunBackend(), samples=3)
    assert r.n_samples == 3 and r.agreement == 1.0 and not r.abstained
    assert isinstance(r.modal, ThreatModel) and len(r.modal.assets) >= 1


# ---- key_fns cluster on the DECISION, not the prose ------------------------


def test_severity_signature_ignores_prose() -> None:
    # same (severity, worth_reporting) but different prose -> SAME key; different severity -> differs
    assert _severity_signature(_sev("High", note="alpha")) == _severity_signature(_sev("High", note="beta"))
    assert _severity_signature(_sev("High")) != _severity_signature(_sev("Low"))


def test_pivot_signature_ignores_prose() -> None:
    assert _pivot_signature(_pivot(["surface", "class"], suggestion="a")) == \
        _pivot_signature(_pivot(["class", "surface"], suggestion="b"))   # same kinds, order/prose differ
    assert _pivot_signature(_pivot(["surface"])) != _pivot_signature(_pivot(["adversary"]))


def test_threat_signature_is_categorical_not_prose() -> None:
    assert _threat_signature(_tm(("S", "T"), ("P0",), ctx="alpha")) == \
        _threat_signature(_tm(("T", "S"), ("P0",), ctx="beta"))         # same structure, prose differs
    assert _threat_signature(_tm(("S",), ("P0",))) != _threat_signature(_tm(("S", "E"), ("P0",)))


# ---- the abstention signal bites on genuine disagreement -------------------


def test_wrappers_abstain_when_the_decision_scatters() -> None:
    # Feed run_consistent (with the wrapper's key_fn) a run_fn whose DECISION cycles across samples:
    # agreement collapses -> abstained, exactly as the wrapper would against an unstable live backend.
    sevs = iter(["Critical", "High", "Medium", "Low", "Info"])
    r = run_consistent(lambda: (_sev(next(sevs)), None), samples=5, key_fn=_severity_signature)
    assert r.abstained and r.agreement == 0.2 and "needs_evidence" in r.reason

    kinds = iter([["surface"], ["class"], ["adversary"], ["layer"], ["time"]])
    rp = run_consistent(lambda: (_pivot(next(kinds)), None), samples=5, key_fn=_pivot_signature)
    assert rp.abstained

    strides = iter([("S",), ("T",), ("R",), ("I",), ("D",)])
    rt = run_consistent(lambda: (_tm(next(strides)), None), samples=5, key_fn=_threat_signature)
    assert rt.abstained
