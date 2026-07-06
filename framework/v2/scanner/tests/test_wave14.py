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
        id=pid, gap_id=f"gap-{pid}", bug_class="boolean_sqli",
        oracle_kind=OracleKind.DIFFERENTIAL_RESPONSE,
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
    q = parse_qs(urlsplit(req.url).query).get("q", [""])[0]
    body = "row\n" * 40 if ("'1'='1" in q or "1=1" in q) else "none"
    return {"status": 200, "body": body}


def _safe_send(req: HttpRequest) -> dict:
    return {"status": 200, "body": "constant page, injection ignored"}


def _dynamic_send(req: HttpRequest) -> dict:
    # NON-vulnerable but dynamic: every distinct input yields a distinct body, so
    # a naive differential would false-confirm — the eval gate must catch it
    q = parse_qs(urlsplit(req.url).query).get("q", [""])[0]
    return {"status": 200, "body": f"page for {q} " + "x" * (len(q) * 25)}


def test_synthesized_check_passes_eval_on_real_bug_and_is_approved() -> None:
    check = synthesize_check("boolean_sqli")
    assert check is not None
    request, point = _point()
    ev = evaluate_check(check, request=request, point=point,
                        vuln_send=_vuln_send, safe_send=_safe_send)
    assert ev.confirmed_on_vuln and not ev.confirmed_on_safe
    assert ev.eval_green

    decision = MergeGate().evaluate(_proposal("p1"), eval_green=ev.eval_green, approvals=2, threshold=2)
    assert decision.verdict == Verdict.APPROVED


def test_eval_gate_rejects_a_check_that_false_confirms() -> None:
    # evaluate the SAME synthesized check but with a dynamic (non-vulnerable) twin
    # standing in for "safe": it false-confirms there, so eval is red
    check = synthesize_check("boolean_sqli")
    request, point = _point()
    ev = evaluate_check(check, request=request, point=point,
                        vuln_send=_vuln_send, safe_send=_dynamic_send)
    assert ev.confirmed_on_vuln and ev.confirmed_on_safe
    assert not ev.eval_green

    decision = MergeGate().evaluate(_proposal("p2"), eval_green=ev.eval_green, approvals=5, threshold=2)
    assert decision.verdict == Verdict.REJECTED  # eval red -> blocked even with approvals


def test_synthesis_declines_classes_needing_target_specific_specs() -> None:
    # CORS (achieved-state predicate) and SSRF (OOB) are not auto-synthesizable
    assert synthesize_check("cors") is None
    assert synthesize_check("ssrf") is None
