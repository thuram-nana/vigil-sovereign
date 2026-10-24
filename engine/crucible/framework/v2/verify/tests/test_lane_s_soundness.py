"""Lane S — gold-standard truth-layer soundness (engine side: S1, S3, S4).

Each control pins a confirmed truth-layer hole closed TO THE CORE, with BOTH a negative control (the
unsound / unbound / echoed / wrong-provenance input mints NOTHING end to end, including through the offline
``framework.v2 verify`` re-execution) AND a positive control (a real captured-evidence context still fires +
signs + verifies + grades ``proven`` byte-identically).

  S1 — predicate_oracle STRUCTURAL FACT-ELIGIBILITY GRAMMAR (the re-slice): the perturbation sampler is
       retired as the soundness AUTHORITY; a predicate mints only when every firing path carries a POSITIVE
       DISCRIMINATOR (PD2 canary / PD3 strict reduction floor / PD-NUM numeric achieved-comparison / PD4
       present-absent differential). A negation, a floor, a bare string-literal match against a
       captured/producer value, or a vacuous ge-at-domain-min adjudicates nothing sound and is REFUSED.
  S3 — verify.verifier import-time coverage guard: every known class resolves to an oracle row.
  S4 — re-verifiable oracle-context PROVENANCE bound into the signed cert and re-checked offline, INCLUDING
       the Lane-S provenance_refs slot (a stripped/mislabelled provenance_refs fails re-verification).

(S2 mint choke + S5 detection path are in integration/tests/test_lane_s_mint_choke.py, where the mint and
detection re-verify live.)
"""
from __future__ import annotations

import json

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


# A REAL captured-evidence predicate: reflected-evil-origin CORS with credentials. evil_origin is a
# VIGIL-injected canary (PD2); the credentials clause is a corroborator. This is the sound CorsActiveCheck
# predicate (no non-exploitable `*`+creds arm).
_CORS_PRED = {"all": [
    {"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
    {"ieq": [{"var": "acac"}, "true"]},
]}
_CORS_OBS = {"acao": "https://evil", "acac": "true", "evil_origin": "https://evil"}
_CORS_PREFS = {"evil_origin": "canary"}

# A real ~50-byte captured body for the negative controls (so each genuinely has captured evidence to
# adjudicate over — the refusal is structural, not a non-binding artefact).
_REAL_BODY = "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"secret\":\"abcde\"}"
_SENTINEL = "the-old-public-sentinel"

# The red-pen / adversary NEGATIVE set — each must be REFUSED (fired=False, conclusive=False) because it
# carries NO positive discriminator. (obs, predicate, provenance_refs).
_REFUSED: dict[str, tuple] = {
    "not(eq[body,0])":        ({"body": _REAL_BODY}, {"not": {"eq": [{"var": "body"}, 0]}}, None),
    "not(eq[body,sentinel])": ({"body": _REAL_BODY}, {"not": {"eq": [{"var": "body"}, _SENTINEL]}}, None),
    "min_len>=1":             ({"body": _REAL_BODY}, {"min_len": [{"var": "body"}, 1]}, None),
    "not(eq[body,''])":       ({"body": _REAL_BODY}, {"not": {"eq": [{"var": "body"}, ""]}}, None),
    "ge[body,'!']":           ({"body": _REAL_BODY}, {"ge": [{"var": "body"}, "!"]}, None),
    # the decoy: its only non-`not` leaf is a producer-authorable STRING-literal match.
    "decoy": ({"body": "decoy-value"},
              {"all": [{"eq": [{"var": "body"}, "decoy-value"]}, {"not": {"eq": [{"var": "body"}, 0]}}]}, None),
    # the ADVERSARY boilerplate idor: a single CV-vs-CV containment with NO present/absent differential —
    # "Acme CMS" is global boilerplate present in every page (min_len>=6 does not save an 8-char marker).
    "boilerplate_idor": ({"attacker_body": "<html>Welcome! Powered by Acme CMS v4</html>", "discriminator": "Acme CMS"},
                         {"all": [{"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]}]}, None),
    # the bare PathProbe signature match WITHOUT a control arm — a catch-all that serves the signature
    # everywhere would mint, so it needs a present/absent control differential (Option B).
    "bare_pathprobe": ({"body": "set DB_PASSWORD=hunter2 in the env"},
                       {"all": [{"icontains": [{"var": "body"}, "DB_PASSWORD="]}]}, None),
    # the vacuous ge[count,0]-as-PD3: a reduction floor at the DOMAIN MINIMUM is always true (count>=0), so
    # ge is refused — only a STRICT gt flips inside the domain.
    "vacuous_ge_count": ({"introspection_type_count": 0},
                         {"all": [{"ge": [{"var": "introspection_type_count"}, 0]}]},
                         {"introspection_type_count": "reduction"}),
}

# The KEEP-class POSITIVE set — each real predicate+evidence still mints (fired=True, conclusive=True,
# confidence=0.9). (obs, predicate, provenance_refs).
_KEEP: dict[str, tuple] = {
    "cors": (_CORS_OBS, _CORS_PRED, _CORS_PREFS),
    "host_header": ({"location_host": "crucible-evil-host.test", "evil_host": "crucible-evil-host.test",
                     "body": "", "followed_redirect": False, "body_available": True,
                     "emitted_url_hosts": []},
                    {"any": [
                        {"eq": [{"var": "location_host"}, {"var": "evil_host"}]},
                        {"all": [{"eq": [{"var": "body_available"}, True]},
                                 {"not": {"eq": [{"var": "followed_redirect"}, True]}},
                                 {"in": [{"var": "evil_host"}, {"var": "emitted_url_hosts"}]}]},
                    ]},
                    {"evil_host": "canary"}),
    "open_redirect": ({"status": 302, "location_host": "crucible-redirect-canary.test",
                       "canary_host": "crucible-redirect-canary.test", "body": "",
                       "followed_redirect": True, "body_available": True, "markup_redirect_hosts": []},
                      {"any": [
                          {"all": [{"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                                   {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]},
                          {"all": [{"eq": [{"var": "body_available"}, True]},
                                   {"not": {"eq": [{"var": "followed_redirect"}, True]}},
                                   {"min_len": [{"var": "canary_host"}, 1]},
                                   {"in": [{"var": "canary_host"}, {"var": "markup_redirect_hosts"}]}]},
                      ]},
                      {"canary_host": "canary"}),
    "graphql_introspection": ({"body_available": True, "introspection_type_count": 7},
                              {"all": [{"eq": [{"var": "body_available"}, True]},
                                       {"gt": [{"var": "introspection_type_count"}, 0]}]},
                              {"introspection_type_count": "reduction"}),
    # idor present/absent DIFFERENTIAL (PD4): marker present in the attacker cross-read, absent from the
    # attacker's own object.
    "idor": ({"discriminator": "acct-7FA91C33", "victim_body": "owner acct-7FA91C33 balance 999",
              "attacker_body": "leaked acct-7FA91C33 balance 999", "attacker_own_body": "your own account"},
             {"all": [{"min_len": [{"var": "discriminator"}, 6]},
                      {"contains": [{"var": "victim_body"}, {"var": "discriminator"}]},
                      {"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]},
                      {"not": {"contains": [{"var": "attacker_own_body"}, {"var": "discriminator"}]}}]},
             None),
    # mass_assignment present/absent DIFFERENTIAL (PD4): the privileged marker appears AFTER the write but
    # not BEFORE.
    "mass_assignment": ({"before": '{"role":"user"}', "after": '{"role":"user","is_admin":"true"}',
                         "m1": '"is_admin":"true"', "m2": '"is_admin": "true"'},
                        {"all": [{"any": [{"contains": [{"var": "after"}, {"var": "m1"}]},
                                          {"contains": [{"var": "after"}, {"var": "m2"}]}]},
                                 {"not": {"any": [{"contains": [{"var": "before"}, {"var": "m1"}]},
                                                  {"contains": [{"var": "before"}, {"var": "m2"}]}]}}]},
                        None),
    # exposure non-KEY body-vs-control DIFFERENTIAL (PD4): the signature is in the sensitive path's body,
    # absent from the benign control body (SIG floored at the distinctiveness minimum).
    "exposure": ({"body": "...DB_PASSWORD=hunter2...", "control_body": "404 Not Found"},
                 {"all": [{"icontains": [{"var": "body"}, "DB_PASSWORD="]},
                          {"not": {"icontains": [{"var": "control_body"}, "DB_PASSWORD="]}}]},
                 None),
    # PathProbe exposure WITH its new control_body absent-arm (the Option-B upgrade).
    "pathprobe": ({"status": 200, "body": '{"propertySources":[{"name":"env"}]}', "control_body": "not found"},
                  {"all": [{"icontains": [{"var": "body"}, "propertySources"]},
                           {"not": {"icontains": [{"var": "control_body"}, "propertySources"]}}]},
                  None),
    # request_race limit-overrun (PD-NUM): more successes than the permitted maximum.
    "request_race": ({"successes": 5, "max_allowed": 1},
                     {"gt": [{"var": "successes"}, {"var": "max_allowed"}]}, None),
}


def _trust():
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(schema_version=1, threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def _cors_finding(**over) -> dict:
    f = {"check_id": "cors-fact", "bug_class": "cors", "confirmed_by": "achieved_state", "confidence": 0.9,
         "oracle_context": {"predicate": _CORS_PRED, "observed_evidence": _CORS_OBS,
                            "provenance_refs": _CORS_PREFS}}
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
# S1 — structural FACT-eligibility grammar: negatives refused, KEEP classes mint
# ===========================================================================

def test_s1_degenerate_all_literal_predicate_refused():
    sig = predicate_oracle({}, {"eq": ["x", "x"]})
    assert not sig.fired and not sig.conclusive and sig.confidence == 0.0
    assert "REFUSED" in sig.evidence


def test_s1_self_comparison_predicate_refused_even_with_a_captured_var():
    sig = predicate_oracle({"k": "anything"}, {"eq": [{"var": "k"}, {"var": "k"}]})
    assert not sig.fired and not sig.conclusive
    sig_ge = predicate_oracle({"k": 5}, {"ge": [{"var": "k"}, {"var": "k"}]})
    assert not sig_ge.fired and not sig_ge.conclusive


def test_s1_predicate_with_no_resolving_var_refused():
    sig = predicate_oracle({}, {"ieq": [{"var": "missing"}, "true"]})
    assert not sig.fired and not sig.conclusive
    sig_none = predicate_oracle({"x": None}, {"eq": [{"var": "x"}, "y"]})
    assert not sig_none.fired and not sig_none.conclusive


def test_s1_achieved_state_expected_observed_form_is_retired():
    # the producer-supplied expected/observed form is NON-MINTING for EVERY pair.
    echo = achieved_state_oracle({"owner": "victim", "readable": True}, {"owner": "victim", "readable": True})
    junk = achieved_state_oracle({"role": "admin"}, {"role": "admin", "_pad": "x"})
    extra = achieved_state_oracle({"owner": "victim"}, {"owner": "victim", "id": 42, "balance": 1000})
    for sig in (echo, junk, extra):
        assert not sig.fired and not sig.conclusive and sig.confidence == 0.0
        assert "REFUSED" in sig.evidence and "predicate_oracle" in sig.evidence


@pytest.mark.parametrize("label", list(_REFUSED), ids=list(_REFUSED))
def test_s1_no_positive_discriminator_is_refused(label):
    obs, pred, prefs = _REFUSED[label]
    sig = predicate_oracle(obs, pred, provenance_refs=prefs)
    assert not sig.fired and not sig.conclusive and sig.confidence == 0.0, label
    assert "REFUSED" in sig.evidence, label


@pytest.mark.parametrize("label", list(_KEEP), ids=list(_KEEP))
def test_s1_keep_class_real_predicate_mints(label):
    obs, pred, prefs = _KEEP[label]
    sig = predicate_oracle(obs, pred, provenance_refs=prefs)
    assert sig.fired and sig.conclusive and sig.confidence == 0.9, label


def test_s1_negatives_do_not_reproduce_through_framework_verify():
    for label, (obs, pred, prefs) in _REFUSED.items():
        oc = {"predicate": pred, "observed_evidence": obs}
        if prefs is not None:
            oc["provenance_refs"] = prefs
        f = {"check_id": f"n-{label}", "bug_class": "idor", "confirmed_by": "achieved_state",
             "confidence": 0.9, "oracle_context": oc}
        rr = reverify_finding(f)
        assert not rr.ok and not rr.reproduced, label


def test_s1_keep_classes_reproduce_through_framework_verify():
    # the CORS KEEP class reproduces offline (the full mint/sign/verify is in test_s4 below and in the
    # integration mint-choke); here assert the predicate-over-evidence re-exec reproduces.
    assert reverify_finding(_cors_finding()).ok


# ===========================================================================
# S3 — import-time vocabulary coverage guard + frozen oracle counts
# ===========================================================================

def test_s3_live_vocabulary_is_fully_oracle_rowed():
    assert set(V._ALIASES.values()) <= set(V.BUG_CLASS_ORACLES)
    for c in V.known_bug_classes():
        n = V.normalize_bug_class(c)
        assert n in V.BUG_CLASS_ORACLES or n in V._STATIC_RULE_LEAD_ONLY_CLASSES, c
    V._assert_vocabulary_fully_rowed(V.BUG_CLASS_ORACLES, V._ALIASES, V._STATIC_RULE_LEAD_ONLY_CLASSES)


def test_s3_guard_fires_on_a_dangling_alias_target():
    with pytest.raises(RuntimeError, match="not fully oracle-rowed"):
        V._assert_vocabulary_fully_rowed(
            {"idor": (OracleKind.ACHIEVED_STATE,)}, {"foo": "ghost_class"}, frozenset())


def test_s3_guard_fires_on_a_known_but_rowless_class():
    with pytest.raises(RuntimeError, match="not fully oracle-rowed"):
        V._assert_vocabulary_fully_rowed(
            {"idor": (OracleKind.ACHIEVED_STATE,)},
            {"spelling": "ghost", "ghost": "ghost"}, frozenset())


def test_s3_frozen_oracle_counts_unchanged():
    assert len(V._ALL_ORACLES) == 15
    # The frozen unknown-class fallback stays EXACTLY 15; the enum grows only by ADDITIVE kinds reachable
    # solely via explicit BUG_CLASS_ORACLES rows (PATH_TRAVERSAL_BREAKOUT, the request-side traversal
    # parse-proof, took this 49 -> 50; the request-side SSRF_BREAKOUT + XXE_BREAKOUT parse-proofs took it
    # 50 -> 52). The 15-vs-enum split is what must never drift.
    assert len(list(OracleKind)) == 52


# ===========================================================================
# S4 — re-verifiable oracle-context provenance (incl. the Lane-S provenance_refs slot)
# ===========================================================================

def test_s4_fact_cert_provenance_is_byte_identical_for_reproduced_and_live_redrive():
    for pv in sorted(_REPRODUCED_PROVENANCE):
        cert = build_certificate(_cors_finding(), provenance=pv)
        assert "provenance" not in cert.model_dump(mode="json"), pv


def test_s4_non_fact_provenance_survives_into_signed_bytes():
    cert = build_certificate(_cors_finding(), provenance="llm")
    assert cert.model_dump(mode="json").get("provenance") == "llm"


def test_s4_framework_verify_refuses_a_non_reproduced_provenance():
    assert not reverify_finding(_cors_finding(provenance="llm")).ok
    assert reverify_finding(_cors_finding()).ok
    assert reverify_finding(_cors_finding(provenance="reproduced")).ok
    assert reverify_finding(_cors_finding(provenance="live_redrive")).ok


def test_s4_provenance_refs_ride_into_signed_bytes_and_tamper_fails():
    # (invariant d) the provenance-ref slot travels in the SIGNED-bound oracle_context (hash-bound into the
    # cert, carried in the PCF), so offline verify re-derives the identical grammar verdict — and a stripped
    # / mislabelled provenance_refs FAILS re-verification (the canary declaration is load-bearing).
    signers, tr = _trust()
    oc = _cors_finding()["oracle_context"]
    signed = sign_certificate(build_certificate(_cors_finding(), provenance="reproduced"), signers)
    pcf = to_pcf(signed, oracle_context=oc)
    assert "provenance_refs" in json.dumps(pcf) and verify_pcf(pcf, tr).verified
    assert reverify_finding(_cors_finding()).ok
    stripped = _cors_finding()
    stripped["oracle_context"] = {k: v for k, v in stripped["oracle_context"].items() if k != "provenance_refs"}
    assert not reverify_finding(stripped).ok   # without the canary declaration eq[acao,evil_origin] is CV-vs-CV
    mislabelled = _cors_finding()
    mislabelled["oracle_context"] = {**mislabelled["oracle_context"], "provenance_refs": {"acac": "canary"}}
    assert not reverify_finding(mislabelled).ok   # tagging the wrong key does not make the match a PD2


def test_s4_to_pcf_refuses_to_export_a_non_reproduced_cert():
    signers, _tr = _trust()
    signed = sign_certificate(build_certificate(_cors_finding(), provenance="llm"), signers)
    with pytest.raises(PcfExportError):
        to_pcf(signed, oracle_context=_cors_finding()["oracle_context"])


def test_s4_verify_pcf_refuses_a_non_reproduced_provenance_cert():
    signers, tr = _trust()
    oc = _cors_finding()["oracle_context"]
    signed = sign_certificate(build_certificate(_cors_finding(), provenance="llm"), signers)
    pcf = _project_pcf(signed, oc)
    r = verify_pcf(pcf, tr)
    assert not r.verified and r.step == "oracle"


def test_s4_positive_mints_signs_verifies_and_grades_proven():
    signers, tr = _trust()
    oc = _cors_finding()["oracle_context"]
    cert = build_certificate(_cors_finding(), provenance="reproduced")
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
