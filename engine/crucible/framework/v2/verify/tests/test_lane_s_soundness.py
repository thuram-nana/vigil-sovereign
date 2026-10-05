"""Lane S — gold-standard truth-layer soundness (engine side: S1, S3, S4).

Each control pins a confirmed truth-layer hole closed TO THE CORE, with BOTH a negative control (the
degenerate / unbound / echoed / wrong-provenance input mints NOTHING end to end, including through the
offline ``framework.v2 verify`` re-execution) AND a positive control (a real captured-evidence context still
fires + signs + verifies + grades ``proven`` byte-identically).

  S1 — predicate_oracle / achieved_state_oracle: a producer-authored all-literal / self-comparison predicate
       (``{"eq":["x","x"]}``), or an expected==observed echo, adjudicates NO captured value and must REFUSE.
  S3 — verify.verifier import-time coverage guard: every known class resolves to an oracle row, so a future
       class/alias edit can never leave a "known" class rowless (falling through to the generic fallback).
  S4 — re-verifiable oracle-context PROVENANCE bound into the signed cert and re-checked offline, so an
       LLM-authored context can never be a FACT offline — and the reproduced/live_redrive path is byte-identical.

(S2 mint choke + S5 detection path are in integration/tests/test_lane_s_mint_choke.py, where the mint and
detection re-verify live.)
"""
from __future__ import annotations

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence.certify import build_certificate, sign_certificate
from framework.v2.evidence.models import _REPRODUCED_PROVENANCE
from framework.v2.evidence.pcf import _SIG_DOMAIN, _project_view, PcfExportError, to_pcf, verify_pcf
from framework.v2.report.standards import map_finding
from framework.v2.verify import verifier as V
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import achieved_state_oracle, predicate_oracle
from framework.v2.verify.reverify import reverify_finding


# A REAL captured-evidence predicate: reflected-evil-origin CORS with credentials (var-bound, non-degenerate).
_CORS_PRED = {"all": [
    {"any": [{"eq": [{"var": "acao"}, {"var": "evil_origin"}]}, {"eq": [{"var": "acao"}, "*"]}]},
    {"ieq": [{"var": "acac"}, "true"]},
]}
_CORS_OBS = {"acao": "https://evil", "acac": "true", "evil_origin": "https://evil"}

# A real ~50-byte captured body for the value-independence controls.
_REAL_BODY = "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"secret\":\"abcde\"}"

# The red-pen BYPASS-A counterexamples: each BINDS a captured var yet fires for ALL values of it (its firing
# cannot depend on the captured value), so each must be REFUSED — the exact set the counterfactual + the
# reflexive-``in`` pre-filter close.
_VALUE_INDEPENDENT = {
    "min_len>=0":    ({"body": _REAL_BODY},  {"min_len": [{"var": "body"}, 0]}),
    "min_len>=-1":   ({"body": _REAL_BODY},  {"min_len": [{"var": "body"}, -1]}),
    "in[body,body]": ({"body": _REAL_BODY},  {"in": [{"var": "body"}, {"var": "body"}]}),
    "eq[k,k]":       ({"k": "anything"},     {"eq": [{"var": "k"}, {"var": "k"}]}),
    "ge[k,'']":      ({"k": "anything"},     {"ge": [{"var": "k"}, ""]}),
}

# Genuinely value-DEPENDENT predicates that must STILL fire (each is flipped off by at least one
# perturbation family, so the counterfactual leaves it untouched).
_VALUE_DEPENDENT = {
    "min_len>=10":     ({"body": _REAL_BODY},                        {"min_len": [{"var": "body"}, 10]}),
    "eq[loc,canary]":  ({"loc_host": "canary.example"},              {"eq": [{"var": "loc_host"}, "canary.example"]}),
    "eq[a,b]/equal":   ({"a": "https://evil", "b": "https://evil"},  {"eq": [{"var": "a"}, {"var": "b"}]}),
    "all+liveness":    ({"sha": "deadbeef", "loc_host": "canary.example"},
                        {"all": [{"eq": [{"var": "sha"}, {"var": "sha"}]},
                                 {"eq": [{"var": "loc_host"}, "canary.example"]}]}),
}


def _trust():
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(schema_version=1, threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def _cors_finding(**over) -> dict:
    f = {"check_id": "cors-fact", "bug_class": "cors", "confirmed_by": "achieved_state", "confidence": 0.9,
         "oracle_context": {"predicate": _CORS_PRED, "observed_evidence": _CORS_OBS}}
    f.update(over)
    return f


def _project_pcf(signed, oc: dict) -> dict:
    """Project a signed cert to a PCF wire view WITHOUT to_pcf's reproducibility/provenance guard — the only
    way to feed verify_pcf a would-be-refused cert so we can prove verify_pcf ITSELF refuses it."""
    cert = signed.certificate
    view = _project_view(cert, oc)
    view["signature"] = {"scheme": "ed25519", "domain": _SIG_DOMAIN,
                         "signatures": [{"key_id": s.key_id, "sig": s.signature_b64} for s in signed.signatures]}
    view["_crucible"] = {"certificate": cert.model_dump(mode="json")}
    return view


# ===========================================================================
# S1 — predicate / achieved-state: bound-to-captured-evidence + no degenerate tautology
# ===========================================================================

def test_s1_degenerate_all_literal_predicate_refused():
    sig = predicate_oracle({}, {"eq": ["x", "x"]})
    assert not sig.fired and not sig.conclusive and sig.confidence == 0.0
    assert "REFUSED" in sig.evidence


def test_s1_self_comparison_predicate_refused_even_with_a_captured_var():
    # both operands are the SAME captured var — a tautology whose truth cannot depend on the value.
    sig = predicate_oracle({"k": "anything"}, {"eq": [{"var": "k"}, {"var": "k"}]})
    assert not sig.fired and not sig.conclusive
    sig_ge = predicate_oracle({"k": 5}, {"ge": [{"var": "k"}, {"var": "k"}]})
    assert not sig_ge.fired and not sig_ge.conclusive


def test_s1_predicate_with_no_resolving_var_refused():
    # the var does not resolve in observed_evidence (not a captured value) → nothing is adjudicated.
    sig = predicate_oracle({}, {"ieq": [{"var": "missing"}, "true"]})
    assert not sig.fired and not sig.conclusive
    # a var present but None is not "captured" either.
    sig_none = predicate_oracle({"x": None}, {"eq": [{"var": "x"}, "y"]})
    assert not sig_none.fired and not sig_none.conclusive


def test_s1_achieved_state_expected_observed_form_is_retired():
    # BYPASS B + its whole family: the producer-supplied expected/observed form is now NON-MINTING for
    # EVERY pair — a value-only match cannot be distinguished from a fabrication. The echo, the
    # echo-plus-junk that slipped past the old subset refusal, AND a "genuine extra keys" record all refuse.
    echo = achieved_state_oracle({"owner": "victim", "readable": True}, {"owner": "victim", "readable": True})
    junk = achieved_state_oracle({"role": "admin"}, {"role": "admin", "_pad": "x"})          # the red-pen bypass
    extra = achieved_state_oracle({"owner": "victim"}, {"owner": "victim", "id": 42, "balance": 1000})
    for sig in (echo, junk, extra):
        assert not sig.fired and not sig.conclusive and sig.confidence == 0.0
        assert "REFUSED" in sig.evidence and "predicate_oracle" in sig.evidence


def test_s1_value_independent_predicates_refused():
    # BYPASS A: each binds a captured var but fires for ALL values of it — refused (non-firing,
    # non-conclusive), whether by the reflexive-identical pre-filter or the counterfactual backstop.
    for label, (obs, pred) in _VALUE_INDEPENDENT.items():
        sig = predicate_oracle(obs, pred)
        assert not sig.fired and not sig.conclusive and sig.confidence == 0.0, label
        assert "REFUSED" in sig.evidence, label


def test_s1_positive_real_predicate_still_fires_byte_identical():
    sig = predicate_oracle(_CORS_OBS, _CORS_PRED)
    assert sig.fired and sig.conclusive and sig.confidence >= 0.9
    # every genuinely value-dependent predicate still fires at full confidence (the counterfactual leaves
    # it untouched because at least one perturbation family flips it off).
    for label, (obs, pred) in _VALUE_DEPENDENT.items():
        pos = predicate_oracle(obs, pred)
        assert pos.fired and pos.conclusive and pos.confidence >= 0.9, label


def test_s1_degenerate_does_not_reproduce_through_framework_verify():
    # the end-to-end offline re-exec (framework.v2 verify) does NOT reproduce a degenerate predicate as a FACT.
    neg = {"check_id": "deg", "bug_class": "idor", "confirmed_by": "achieved_state", "confidence": 0.9,
           "oracle_context": {"predicate": {"eq": ["x", "x"]}, "observed_evidence": {}}}
    rr = reverify_finding(neg)
    assert not rr.ok and not rr.reproduced
    # positive: the real captured-evidence CORS finding reproduces.
    assert reverify_finding(_cors_finding()).ok


def test_s1_bypasses_do_not_reproduce_through_framework_verify():
    # BYPASS A — each value-independent predicate (which signed a FACT before the fix) now fails the offline
    # re-exec; and a genuinely value-dependent predicate over the same evidence still reproduces.
    for label, (obs, pred) in _VALUE_INDEPENDENT.items():
        f = {"check_id": f"a-{label}", "bug_class": "idor", "confirmed_by": "achieved_state",
             "confidence": 0.9, "oracle_context": {"predicate": pred, "observed_evidence": obs}}
        rr = reverify_finding(f)
        assert not rr.ok and not rr.reproduced, label
    for label, (obs, pred) in _VALUE_DEPENDENT.items():
        f = {"check_id": f"p-{label}", "bug_class": "idor", "confirmed_by": "achieved_state",
             "confidence": 0.9, "oracle_context": {"predicate": pred, "observed_evidence": obs}}
        assert reverify_finding(f).ok, label
    # BYPASS B — the retired expected/observed echo-plus-junk form does not reproduce offline.
    b = {"check_id": "b-echo-junk", "bug_class": "bola", "confirmed_by": "achieved_state", "confidence": 0.9,
         "oracle_context": {"expected_state": {"role": "admin"}, "observed_state": {"role": "admin", "_pad": "x"}}}
    rr = reverify_finding(b)
    assert not rr.ok and not rr.reproduced


# ===========================================================================
# S3 — import-time vocabulary coverage guard
# ===========================================================================

def test_s3_live_vocabulary_is_fully_oracle_rowed():
    # every alias target is a real row; every KNOWN class normalises to a row or the LEAD-only set.
    assert set(V._ALIASES.values()) <= set(V.BUG_CLASS_ORACLES)
    for c in V.known_bug_classes():
        n = V.normalize_bug_class(c)
        assert n in V.BUG_CLASS_ORACLES or n in V._STATIC_RULE_LEAD_ONLY_CLASSES, c
    # the guard ran at import without raising (the module is imported) — assert the entrypoint exists.
    V._assert_vocabulary_fully_rowed(V.BUG_CLASS_ORACLES, V._ALIASES, V._STATIC_RULE_LEAD_ONLY_CLASSES)


def test_s3_guard_fires_on_a_dangling_alias_target():
    with pytest.raises(RuntimeError, match="not fully oracle-rowed"):
        V._assert_vocabulary_fully_rowed(
            {"idor": (OracleKind.ACHIEVED_STATE,)}, {"foo": "ghost_class"}, frozenset())


def test_s3_guard_fires_on_a_known_but_rowless_class():
    # an alias spelling that folds onto a canonical class which has NO row → "known" but rowless.
    with pytest.raises(RuntimeError, match="not fully oracle-rowed"):
        V._assert_vocabulary_fully_rowed(
            {"idor": (OracleKind.ACHIEVED_STATE,)},
            {"spelling": "ghost", "ghost": "ghost"}, frozenset())


def test_s3_frozen_oracle_counts_unchanged():
    assert len(V._ALL_ORACLES) == 15
    assert len(list(OracleKind)) == 49


# ===========================================================================
# S4 — re-verifiable oracle-context provenance
# ===========================================================================

def test_s4_fact_cert_provenance_is_byte_identical_for_reproduced_and_live_redrive():
    for pv in sorted(_REPRODUCED_PROVENANCE):
        cert = build_certificate(_cors_finding(), provenance=pv)
        assert "provenance" not in cert.model_dump(mode="json"), pv


def test_s4_non_fact_provenance_survives_into_signed_bytes():
    cert = build_certificate(_cors_finding(), provenance="llm")
    assert cert.model_dump(mode="json").get("provenance") == "llm"


def test_s4_framework_verify_refuses_a_non_reproduced_provenance():
    # a finding that DECLARES an LLM provenance does NOT reproduce as a FACT offline.
    assert not reverify_finding(_cors_finding(provenance="llm")).ok
    # absent (every existing finding) and reproduced/live_redrive still reproduce (byte-identical behaviour).
    assert reverify_finding(_cors_finding()).ok
    assert reverify_finding(_cors_finding(provenance="reproduced")).ok
    assert reverify_finding(_cors_finding(provenance="live_redrive")).ok


def test_s4_to_pcf_refuses_to_export_a_non_reproduced_cert():
    signers, _tr = _trust()
    signed = sign_certificate(build_certificate(_cors_finding(), provenance="llm"), signers)
    with pytest.raises(PcfExportError):
        to_pcf(signed, oracle_context=_cors_finding()["oracle_context"])


def test_s4_verify_pcf_refuses_a_non_reproduced_provenance_cert():
    signers, tr = _trust()
    oc = _cors_finding()["oracle_context"]
    signed = sign_certificate(build_certificate(_cors_finding(), provenance="llm"), signers)
    pcf = _project_pcf(signed, oc)   # past to_pcf's own guard
    r = verify_pcf(pcf, tr)
    assert not r.verified and r.step == "oracle"


def test_s4_positive_mints_signs_verifies_and_grades_proven():
    signers, tr = _trust()
    oc = _cors_finding()["oracle_context"]
    cert = build_certificate(_cors_finding(), provenance="reproduced")
    # byte-identity: the FACT cert carries NO provenance key in its signed bytes.
    assert "provenance" not in cert.model_dump(mode="json")
    signed = sign_certificate(cert, signers)
    pcf = to_pcf(signed, oracle_context=oc)
    assert pcf["claim"]["class"] == "cors"
    r = verify_pcf(pcf, tr)
    assert r.verified, f"{r.step}: {r.reason}"
    graded = map_finding({
        "finding_slug": "cors-fact", "title": "permissive CORS", "severity": "High", "bug_class": "cors",
        "surface": "/api", "summary": "reflected evil origin with credentials", "verified_by_oracle": True,
        "oracle_kind": "achieved_state", "confidence": 0.9, "critique_status": "confirmed",
        "oracle_context": oc})
    assert graded["graded"] == "fact" and graded["status"] == "proven" and graded["coverage_asserted"] is True
