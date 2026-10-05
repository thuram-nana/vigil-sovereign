"""Lane S — gold-standard truth-layer soundness at the MINT CHOKE + the detection path (S2, S5, + the
end-to-end S1/S4 mint controls).

For each hole: a NEGATIVE control (the degenerate / relabel / LLM-provenanced / detection-relabel input mints
NOTHING end to end — through confirm_and_certify AND certify_admitted, and does not reproduce offline) AND a
POSITIVE control (a real captured-evidence context still mints + signs + re-verifies, byte-identical).

  S2 — the integration mint choke (confirm_and_certify / certify_admitted) re-checks oracle_confirms_class
       (the SAME predicate verify_pcf step 5 uses) and REFUSES a fired oracle that does not prove the class.
  S5 — the detection offline re-verify re-derives the class from the resolved ORACLE INSTANCE and refuses a
       cert whose bug_class disagrees (even when the signature is re-made over the relabel).
"""
from __future__ import annotations

import pytest

from vigil_core import generate_keypair, sign
from vigil_integration import detection as d
from vigil_integration.detection import SqliStructureOracle, parse_access_log, reverify_certificate
from vigil_integration.detection.certificate import sign_certificate as _d_sign
from vigil_integration.live.verdict import Verdict, admit
from vigil_integration.oracle_adapter import certify_admitted, confirm_and_certify


def _signers():
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


# A REAL captured-evidence open-redirect predicate (var-bound, non-degenerate): a 3xx whose Location host
# equals the injected canary host.
_OR_PRED = {"all": [
    {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
    {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},
]}
_OR_OBS = {"status": 302, "location_host": "canary.test", "canary_host": "canary.test"}


def _or_finding(**over) -> dict:
    f = {"check_id": "or-fact", "bug_class": "open_redirect",
         "oracle_context": {"predicate": _OR_PRED, "observed_evidence": _OR_OBS}}
    f.update(over)
    return f


def _degenerate_finding() -> dict:
    return {"check_id": "deg", "bug_class": "open_redirect",
            "oracle_context": {"predicate": {"eq": ["x", "x"]}, "observed_evidence": {}}}


def _admit_fact():
    # a FACT admission over a real fact-capable branch (open_redirect.location_header, precondition
    # channel_established) — the only way to construct an AdmittedVerdict that reaches the mint.
    adm = admit("open_redirect.location_header", fired=True, conclusive=True,
                observed={"channel_established": True})
    assert adm.verdict is Verdict.FACT
    return adm


# ===========================================================================
# S2 — same-shape class-bind at the mint choke
# ===========================================================================

def test_s2_positive_open_redirect_mints_a_signed_fact():
    r = confirm_and_certify(_or_finding(), engagement_slug="s2", signers=_signers(), provenance="reproduced")
    assert r.is_fact and r.signed is not None and r.confirmed_by == "achieved_state"


def test_s2_confirm_and_certify_refuses_when_fired_oracle_does_not_prove_class(monkeypatch):
    # Wire proof: patch the SAME deterministic predicate the verifier/pcf use so it rejects the certified
    # class; confirm_and_certify must then REFUSE the mint (a labelled lead, signed None) — mint == verify_pcf.
    monkeypatch.setattr("framework.v2.verify.verifier.oracle_confirms_class", lambda cb, bc: False)
    r = confirm_and_certify(_or_finding(), engagement_slug="s2", signers=_signers(), provenance="reproduced")
    assert not r.is_fact and r.signed is None
    assert "not a valid confirmer" in r.reason


def test_s2_build_certificate_refuses_a_relabel_at_birth():
    from framework.v2.evidence.certify import build_certificate
    # timing does not confirm xss → the cert cannot be minted (byte-sound at birth).
    with pytest.raises(ValueError, match="not a valid confirmer"):
        build_certificate({"check_id": "x", "bug_class": "xss", "confirmed_by": "timing", "oracle_context": {}})


# ===========================================================================
# S1 — degenerate predicate mints nothing through BOTH mint entrypoints
# ===========================================================================

def test_s1_degenerate_mints_nothing_via_confirm_and_certify():
    r = confirm_and_certify(_degenerate_finding(), engagement_slug="s1", signers=_signers(),
                            provenance="reproduced")
    assert not r.is_fact and r.signed is None


def test_s1_degenerate_mints_nothing_via_certify_admitted():
    r = certify_admitted(_degenerate_finding(), _admit_fact(), engagement_slug="s1",
                         signers=_signers(), provenance="reproduced")
    assert not r.is_fact and r.signed is None


def test_s1_positive_mints_via_both_entrypoints():
    assert confirm_and_certify(_or_finding(), engagement_slug="s1", signers=_signers(),
                               provenance="reproduced").is_fact
    assert certify_admitted(_or_finding(), _admit_fact(), engagement_slug="s1",
                            signers=_signers(), provenance="reproduced").is_fact


# ===========================================================================
# S1b — the red-pen bypasses mint NOTHING through the sanctioned path:
#   A) a value-INDEPENDENT predicate that binds a captured var but fires for all its values;
#   B) the retired producer-supplied expected/observed achieved-state form (echo-plus-junk).
# ===========================================================================

# A real ~50-byte captured body (so the value-independent predicates below genuinely FIRE on it before
# the counterfactual / reflexive pre-filter refuses them — proving the refusal, not a non-fire).
_REALBODY = "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"secret\":\"abcde\"}"

_A_VALUE_INDEPENDENT = [
    ("min_len_ge_0",   {"predicate": {"min_len": [{"var": "body"}, 0]},  "observed_evidence": {"body": _REALBODY}}),
    ("min_len_ge_m1",  {"predicate": {"min_len": [{"var": "body"}, -1]}, "observed_evidence": {"body": _REALBODY}}),
    ("in_body_body",   {"predicate": {"in": [{"var": "body"}, {"var": "body"}]}, "observed_evidence": {"body": _REALBODY}}),
    ("eq_k_k",         {"predicate": {"eq": [{"var": "k"}, {"var": "k"}]}, "observed_evidence": {"k": "x"}}),
    ("ge_k_empty",     {"predicate": {"ge": [{"var": "k"}, ""]},          "observed_evidence": {"k": "anything"}}),
]


@pytest.mark.parametrize("label,oc", _A_VALUE_INDEPENDENT, ids=[x[0] for x in _A_VALUE_INDEPENDENT])
def test_s1b_value_independent_predicate_mints_nothing_via_both_entrypoints(label, oc):
    f = {"check_id": f"a-{label}", "bug_class": "open_redirect", "oracle_context": oc}
    r1 = confirm_and_certify(f, engagement_slug="s1b", signers=_signers(), provenance="reproduced")
    assert not r1.is_fact and r1.signed is None, label
    r2 = certify_admitted(f, _admit_fact(), engagement_slug="s1b", signers=_signers(), provenance="reproduced")
    assert not r2.is_fact and r2.signed is None, label


def test_s1b_achieved_state_echo_plus_junk_mints_nothing():
    # BYPASS B: one producer-planted junk key (``_pad``) made observed NOT a subset of expected, slipping
    # past the old echo-only refusal and signing a FACT. The expected/observed form is now retired.
    f = {"check_id": "b-echo-junk", "bug_class": "idor",
         "oracle_context": {"expected_state": {"role": "admin"}, "observed_state": {"role": "admin", "_pad": "x"}}}
    r = confirm_and_certify(f, engagement_slug="s1b", signers=_signers(), provenance="reproduced")
    assert not r.is_fact and r.signed is None
    from framework.v2.verify.reverify import reverify_finding
    assert not reverify_finding(f).ok   # nor does it reproduce offline


# POSITIVE: genuinely value-dependent predicates STILL mint a signed FACT (each is flipped off by at least
# one perturbation family, so the counterfactual leaves it untouched).
_P_VALUE_DEPENDENT = [
    ("min_len_ge_10", "idor",
     {"predicate": {"min_len": [{"var": "body"}, 10]}, "observed_evidence": {"body": _REALBODY}}),
    ("eq_loc_canary", "open_redirect",
     {"predicate": {"eq": [{"var": "location_host"}, "canary.test"]}, "observed_evidence": {"location_host": "canary.test"}}),
    ("eq_a_b_equal", "idor",
     {"predicate": {"eq": [{"var": "a"}, {"var": "b"}]}, "observed_evidence": {"a": "https://evil", "b": "https://evil"}}),
]


@pytest.mark.parametrize("label,bug_class,oc", _P_VALUE_DEPENDENT, ids=[x[0] for x in _P_VALUE_DEPENDENT])
def test_s1b_value_dependent_predicate_still_mints(label, bug_class, oc):
    f = {"check_id": f"p-{label}", "bug_class": bug_class, "oracle_context": oc}
    r = confirm_and_certify(f, engagement_slug="s1b", signers=_signers(), provenance="reproduced")
    assert r.is_fact and r.signed is not None, label


# ===========================================================================
# S4 — provenance re-verifiable at the mint + byte-identical FACT cert
# ===========================================================================

def test_s4_llm_provenance_mints_nothing():
    for mk in (
        lambda: confirm_and_certify(_or_finding(), engagement_slug="s4", signers=_signers(), provenance="llm"),
        lambda: certify_admitted(_or_finding(), _admit_fact(), engagement_slug="s4", signers=_signers(),
                                 provenance="llm"),
    ):
        r = mk()
        assert not r.is_fact and r.signed is None


def test_s4_reproduced_fact_cert_is_byte_identical_and_reverifies_offline():
    r = confirm_and_certify(_or_finding(), engagement_slug="s4", signers=_signers(), provenance="reproduced")
    assert r.is_fact
    cert = r.signed.certificate
    # byte-identity: the FACT cert carries NO provenance key in its signed bytes.
    assert "provenance" not in cert.model_dump(mode="json")
    # offline re-verify (framework.v2 verify path) reproduces the minted finding.
    from framework.v2.verify.reverify import reverify_finding
    rr = reverify_finding({"check_id": cert.finding_ref, "bug_class": "open_redirect",
                           "confirmed_by": r.confirmed_by, "confidence": r.confidence,
                           "oracle_context": _or_finding()["oracle_context"]})
    assert rr.ok


# ===========================================================================
# S5 — detection path re-derives the class from the resolved oracle instance
# ===========================================================================

_SQLI_TGT = "/search?q=x%27%20OR%20%271%27%3D%271"


def _detect(kp):
    wire = {"signer": (lambda b: sign(kp.private_key_b64, b)),
            "verify_key": kp.public_key_b64, "key_id": "defender-k1"}
    det = SqliStructureOracle().detect(parse_access_log(f'127.0.0.1 - - [21/Jul/2026:15:26:30 ] '
                                                        f'"GET {_SQLI_TGT} HTTP/1.1" 200 91 "-" "curl/8"'), **wire)
    assert det is not None and det.certificate is not None and det.is_fact
    return det


def test_s5_positive_detection_cert_reverifies():
    kp = generate_keypair()
    det = _detect(kp)
    assert reverify_certificate(det.certificate, kp.public_key_b64) is True


def test_s5_relabelled_bug_class_is_refused_even_when_resigned():
    kp = generate_keypair()
    det = _detect(kp)
    real_class = det.certificate.bug_class
    assert real_class != "xss"
    # Relabel the class to a higher-severity/different one AND re-sign (so the signature is VALID over the
    # relabel — the exact shape S5 closes: signature_kind still matches + the oracle re-fires, but the cert's
    # bug_class disagrees with the class the RESOLVED ORACLE INSTANCE actually produces).
    relabelled = det.certificate.model_copy(update={"bug_class": "xss"})
    resigned = _d_sign(relabelled, lambda b: sign(kp.private_key_b64, b), key_id="defender-k1")
    # the re-signed relabel has a valid signature AND a matching signature_kind, yet S5 refuses it.
    from vigil_integration.detection.certificate import verify_certificate_signature
    assert verify_certificate_signature(resigned, kp.public_key_b64) is True
    assert resigned.signature_kind == det.certificate.signature_kind
    assert reverify_certificate(resigned, kp.public_key_b64) is False


def test_s5_relabelled_verdict_is_refused_even_when_resigned():
    kp = generate_keypair()
    det = _detect(kp)
    # a certificate is only ever a FACT; a re-signed non-"fact" verdict is refused by the re-derive check.
    relabelled = det.certificate.model_copy(update={"verdict": "clean"})
    resigned = _d_sign(relabelled, lambda b: sign(kp.private_key_b64, b), key_id="defender-k1")
    assert reverify_certificate(resigned, kp.public_key_b64) is False
