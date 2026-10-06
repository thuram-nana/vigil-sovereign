"""Lane S — gold-standard truth-layer soundness at the MINT CHOKE + the detection path (S2, S5, + the
end-to-end S1/S4 mint controls).

For each hole: a NEGATIVE control (the unsound / relabel / LLM-provenanced / detection-relabel input mints
NOTHING end to end — through confirm_and_certify AND certify_admitted, and does not reproduce offline) AND a
POSITIVE control (a real captured-evidence context still mints + signs + re-verifies, byte-identical).

  S1 — the structural FACT-eligibility grammar: a predicate with no positive discriminator (a negation, a
       floor, a bare string-literal match, a differential-free boilerplate match, or a vacuous ge-at-domain-
       min) mints NOTHING through either entrypoint; the KEEP-class predicates still mint a signed FACT.
  S2 — the integration mint choke re-checks oracle_confirms_class and REFUSES a fired oracle that does not
       prove the class.
  S5 — the detection offline re-verify re-derives the class from the resolved ORACLE INSTANCE.
"""
from __future__ import annotations

import pytest

# Two-env boundary: these mint-choke controls drive oracle_adapter's lazy ``import framework`` (the offense
# verification layer), so they RUN in the offense CI leg (engine/crucible on PYTHONPATH) and SKIP cleanly in
# the keyless boundary leg where ``framework`` is intentionally absent — the control is proven in the offense
# leg, never silently skipped everywhere (see the offense-leg list in .github/workflows/ci.yml).
pytest.importorskip("framework.v2")

from vigil_core import generate_keypair, sign  # noqa: E402
from vigil_integration import detection as d  # noqa: E402
from vigil_integration.detection import (  # noqa: E402
    SqliStructureOracle,
    parse_access_log,
    reverify_certificate,
)
from vigil_integration.detection.certificate import sign_certificate as _d_sign  # noqa: E402
from vigil_integration.live.verdict import Verdict, admit  # noqa: E402
from vigil_integration.oracle_adapter import certify_admitted, confirm_and_certify  # noqa: E402


def _signers():
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


# A REAL captured-evidence open-redirect predicate (a 3xx whose Location host equals the injected canary
# host). canary_host is a VIGIL-injected canary (PD2), declared in the provenance-ref slot.
_OR_PRED = {"all": [
    {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
    {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},
]}
_OR_OBS = {"status": 302, "location_host": "canary.test", "canary_host": "canary.test"}
_OR_PREFS = {"canary_host": "canary"}

_REALBODY = "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"secret\":\"abcde\"}"


def _or_finding(**over) -> dict:
    f = {"check_id": "or-fact", "bug_class": "open_redirect",
         "oracle_context": {"predicate": _OR_PRED, "observed_evidence": _OR_OBS,
                            "provenance_refs": _OR_PREFS}}
    f.update(over)
    return f


def _degenerate_finding() -> dict:
    return {"check_id": "deg", "bug_class": "open_redirect",
            "oracle_context": {"predicate": {"eq": ["x", "x"]}, "observed_evidence": {}}}


def _admit_fact():
    adm = admit("open_redirect.location_header", fired=True, conclusive=True,
                observed={"channel_established": True})
    assert adm.verdict is Verdict.FACT
    return adm


# The structural-grammar NEGATIVE set — each carries NO positive discriminator and must mint NOTHING.
_NO_PD = [
    ("not_eq_body_0",      {"predicate": {"not": {"eq": [{"var": "body"}, 0]}}, "observed_evidence": {"body": _REALBODY}}),
    ("min_len_ge_1",       {"predicate": {"min_len": [{"var": "body"}, 1]}, "observed_evidence": {"body": _REALBODY}}),
    ("not_eq_body_empty",  {"predicate": {"not": {"eq": [{"var": "body"}, ""]}}, "observed_evidence": {"body": _REALBODY}}),
    ("ge_body_bang",       {"predicate": {"ge": [{"var": "body"}, "!"]}, "observed_evidence": {"body": _REALBODY}}),
    ("decoy",              {"predicate": {"all": [{"eq": [{"var": "body"}, "decoy-value"]},
                                                  {"not": {"eq": [{"var": "body"}, 0]}}]},
                            "observed_evidence": {"body": "decoy-value"}}),
    ("boilerplate_idor",   {"predicate": {"all": [{"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]}]},
                            "observed_evidence": {"attacker_body": "<html>Powered by Acme CMS</html>", "discriminator": "Acme CMS"}}),
    ("bare_pathprobe",     {"predicate": {"all": [{"icontains": [{"var": "body"}, "DB_PASSWORD="]}]},
                            "observed_evidence": {"body": "set DB_PASSWORD=hunter2"}}),
    ("vacuous_ge_count",   {"predicate": {"all": [{"ge": [{"var": "introspection_type_count"}, 0]}]},
                            "observed_evidence": {"introspection_type_count": 0},
                            "provenance_refs": {"introspection_type_count": "reduction"}}),
]

# The KEEP-class POSITIVE set — each real predicate mints a signed FACT through confirm_and_certify.
_KEEP = [
    ("open_redirect", _or_finding()["oracle_context"]),
    ("cors", {"predicate": {"all": [{"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
                                    {"ieq": [{"var": "acac"}, "true"]}]},
              "observed_evidence": {"acao": "https://evil", "acac": "true", "evil_origin": "https://evil"},
              "provenance_refs": {"evil_origin": "canary"}}),
    ("graphql_introspection", {"predicate": {"all": [{"eq": [{"var": "body_available"}, True]},
                                                     {"gt": [{"var": "introspection_type_count"}, 0]}]},
                               "observed_evidence": {"body_available": True, "introspection_type_count": 7},
                               "provenance_refs": {"introspection_type_count": "reduction"}}),
    ("idor", {"predicate": {"all": [{"min_len": [{"var": "discriminator"}, 6]},
                                    {"contains": [{"var": "victim_body"}, {"var": "discriminator"}]},
                                    {"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]},
                                    {"not": {"contains": [{"var": "attacker_own_body"}, {"var": "discriminator"}]}}]},
              "observed_evidence": {"discriminator": "acct-7FA91C33", "victim_body": "owner acct-7FA91C33",
                                    "attacker_body": "leaked acct-7FA91C33", "attacker_own_body": "your own"}}),
    ("exposure", {"predicate": {"all": [{"icontains": [{"var": "body"}, "DB_PASSWORD="]},
                                        {"not": {"icontains": [{"var": "control_body"}, "DB_PASSWORD="]}}]},
                  "observed_evidence": {"body": "...DB_PASSWORD=hunter2...", "control_body": "404 Not Found"}}),
]


# ===========================================================================
# S2 — same-shape class-bind at the mint choke
# ===========================================================================

def test_s2_positive_open_redirect_mints_a_signed_fact():
    r = confirm_and_certify(_or_finding(), engagement_slug="s2", signers=_signers(), provenance="reproduced")
    assert r.is_fact and r.signed is not None and r.confirmed_by == "achieved_state"


def test_s2_confirm_and_certify_refuses_when_fired_oracle_does_not_prove_class(monkeypatch):
    monkeypatch.setattr("framework.v2.verify.verifier.oracle_confirms_class", lambda cb, bc: False)
    r = confirm_and_certify(_or_finding(), engagement_slug="s2", signers=_signers(), provenance="reproduced")
    assert not r.is_fact and r.signed is None
    assert "not a valid confirmer" in r.reason


def test_s2_build_certificate_refuses_a_relabel_at_birth():
    from framework.v2.evidence.certify import build_certificate
    with pytest.raises(ValueError, match="not a valid confirmer"):
        build_certificate({"check_id": "x", "bug_class": "xss", "confirmed_by": "timing", "oracle_context": {}})


# ===========================================================================
# S1 — degenerate / no-PD predicates mint nothing through BOTH mint entrypoints
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


@pytest.mark.parametrize("label,oc", _NO_PD, ids=[x[0] for x in _NO_PD])
def test_s1_no_pd_predicate_mints_nothing_via_both_entrypoints(label, oc):
    f = {"check_id": f"n-{label}", "bug_class": "open_redirect", "oracle_context": oc}
    r1 = confirm_and_certify(f, engagement_slug="s1", signers=_signers(), provenance="reproduced")
    assert not r1.is_fact and r1.signed is None, label
    r2 = certify_admitted(f, _admit_fact(), engagement_slug="s1", signers=_signers(), provenance="reproduced")
    assert not r2.is_fact and r2.signed is None, label
    from framework.v2.verify.reverify import reverify_finding
    assert not reverify_finding(f).ok, label   # nor does it reproduce offline


def test_s1_achieved_state_echo_plus_junk_mints_nothing():
    f = {"check_id": "b-echo-junk", "bug_class": "idor",
         "oracle_context": {"expected_state": {"role": "admin"}, "observed_state": {"role": "admin", "_pad": "x"}}}
    r = confirm_and_certify(f, engagement_slug="s1b", signers=_signers(), provenance="reproduced")
    assert not r.is_fact and r.signed is None
    from framework.v2.verify.reverify import reverify_finding
    assert not reverify_finding(f).ok


@pytest.mark.parametrize("label,oc", _KEEP, ids=[x[0] for x in _KEEP])
def test_s1_keep_class_mints_a_signed_fact(label, oc):
    f = {"check_id": f"p-{label}", "bug_class": label, "oracle_context": oc}
    r = confirm_and_certify(f, engagement_slug="s1", signers=_signers(), provenance="reproduced")
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
    assert "provenance" not in cert.model_dump(mode="json")
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
    relabelled = det.certificate.model_copy(update={"bug_class": "xss"})
    resigned = _d_sign(relabelled, lambda b: sign(kp.private_key_b64, b), key_id="defender-k1")
    from vigil_integration.detection.certificate import verify_certificate_signature
    assert verify_certificate_signature(resigned, kp.public_key_b64) is True
    assert resigned.signature_kind == det.certificate.signature_kind
    assert reverify_certificate(resigned, kp.public_key_b64) is False


def test_s5_relabelled_verdict_is_refused_even_when_resigned():
    kp = generate_keypair()
    det = _detect(kp)
    relabelled = det.certificate.model_copy(update={"verdict": "clean"})
    resigned = _d_sign(relabelled, lambda b: sign(kp.private_key_b64, b), key_id="defender-k1")
    assert reverify_certificate(resigned, kp.public_key_b64) is False
