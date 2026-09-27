"""
Wave 14 — cross-engagement transfer learning + guarded, eval-gated check synthesis.

Transfer: a confirmed outcome on a target archetype warm-starts the bandit for the
NEXT engagement on that archetype (and only that one). Synthesis: the SIL produces
a concrete, runnable check and it earns its place only if it confirms the real bug
AND does not false-confirm on the safe twin — the oracle still adjudicates, so a
bad check can only waste budget, never manufacture a finding.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction
from framework.v2.scanner.check_synthesis import evaluate_check, synthesize_check
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.learning import ContextualBandit, context_key
from framework.v2.scanner.self_improve import MergeGate, Verdict, CapabilityProposal
from framework.v2.verify import OracleKind


def _proposal(pid: str) -> CapabilityProposal:
    return CapabilityProposal(
        id=pid, gap_id=f"gap-{pid}", bug_class="xss",
        oracle_kind=OracleKind.REFLECTION_CONTEXT,
        insertion_point_strategy="query_value", payload_family="synth",
        payload_template_skeleton="benign vs tautology", rationale="fills a coverage gap",
    )


# --- 14A: cross-engagement transfer learning -------------------------------


def test_confirmed_outcome_transfers_to_the_same_archetype() -> None:
    archetype = context_key({"stack": "php", "db": "mysql", "waf": False})
    other = context_key({"stack": "node", "db": "postgres", "waf": True})

    # engagement A resolved a boolean_sqli finding as EXPLOITABLE (independent
    # adjudication, Wave 3) on the php/mysql archetype
    led = OutcomeLedger()
    led.add_prediction(Prediction(finding_id="A#1", raw_score=0.9, feature_hash="h",
                                  model_version="v", oracle_confirmed=True), seq=0)
    led.record_outcome(Outcome(finding_id="A#1", label=OutcomeLabel.EXPLOITABLE), seq=1)

    # engagement B warm-starts its bandit from that ledger, keyed by archetype
    bandit = ContextualBandit()
    n = bandit.seed_from_ledger(led, lambda pred, out: (archetype, "boolean_sqli"))
    assert n == 1

    # the win transferred to the SAME archetype...
    assert bandit.expected_value(archetype, "boolean_sqli") > 0.5
    # ...but not to a different archetype, nor to an untried class
    assert bandit.expected_value(other, "boolean_sqli") == 0.5
    assert bandit.expected_value(archetype, "xss") == 0.5


# --- 14B: guarded, eval-gated check synthesis ------------------------------


def _point():
    tpl = RequestTemplate(HttpRequest(method="GET", url="http://t/search?q=x"))
    return tpl.request, next(p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q")


def _vuln_send(req: HttpRequest) -> dict:
    # reflects the parameter VERBATIM into the document, so a break-out canary lands in an
    # EXECUTABLE position and the reflection-context oracle confirms — a real bug.
    q = parse_qs(urlsplit(req.url).query).get("q", [""])[0]
    return {"status": 200, "body": f"<html><body><p>results for {q}</p></body></html>"}


def _safe_send(req: HttpRequest) -> dict:
    return {"status": 200, "body": "constant page, injection ignored"}


def _mislabelled_safe_send(req: HttpRequest) -> dict:
    # A twin the operator CALLED safe that in fact reflects verbatim too: the synthesized check
    # cannot tell it from the vulnerable one, so eval must go RED rather than approving a check
    # whose "negative control" it also fires on.
    q = parse_qs(urlsplit(req.url).query).get("q", [""])[0]
    return {"status": 200, "body": f"<html><body><p>page for {q}</p></body></html>"}


def test_synthesized_check_passes_eval_on_real_bug_and_is_approved() -> None:
    check = synthesize_check("xss")
    assert check is not None
    request, point = _point()
    ev = evaluate_check(check, request=request, point=point,
                        vuln_send=_vuln_send, safe_send=_safe_send)
    assert ev.confirmed_on_vuln and not ev.confirmed_on_safe
    assert ev.eval_green

    decision = MergeGate().evaluate(_proposal("p1"), eval_green=ev.eval_green, approvals=2, threshold=2)
    assert decision.verdict == Verdict.APPROVED


def test_eval_gate_rejects_a_check_that_false_confirms() -> None:
    # evaluate the SAME synthesized check against a twin the operator labelled "safe" but which
    # behaves identically: it false-confirms there, so eval is red
    check = synthesize_check("xss")
    request, point = _point()
    ev = evaluate_check(check, request=request, point=point,
                        vuln_send=_vuln_send, safe_send=_mislabelled_safe_send)
    assert ev.confirmed_on_vuln and ev.confirmed_on_safe
    assert not ev.eval_green

    decision = MergeGate().evaluate(_proposal("p2"), eval_green=ev.eval_green, approvals=5, threshold=2)
    assert decision.verdict == Verdict.REJECTED  # eval red -> blocked even with approvals


def test_synthesis_declines_classes_needing_target_specific_specs() -> None:
    # CORS (achieved-state predicate) and SSRF (OOB) are not auto-synthesizable
    assert synthesize_check("cors") is None
    assert synthesize_check("ssrf") is None


def test_synthesis_declines_the_truth_value_attribution_classes() -> None:
    # A sound boolean/auth check is an SPRT over a clause FAMILY, which cannot be derived from a
    # class name; the synthesizer used to answer that need with a bare benign-vs-payload
    # differential, which has no attribution step and minted High FACTs against targets with no
    # database (verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES). It declines instead.
    for bc in ("boolean_sqli", "auth_bypass", "nosqli", "ldap_injection", "xpath_injection"):
        assert synthesize_check(bc) is None, bc
