"""R1 — the reproduction -> FACT bridge (redpen.certify).

Doctrine under test (design §7.2 §4, decision O-1):
  * each reproducible poc_translate channel (request_payload / process / error_signature) builds the
    correct FindingContext and, when its O-1 oracle FIRES over the captured bytes, mints a signed FACT;
  * O-1 is AUTHORITATIVE on the FIRED oracle kind: a confirmed finding whose oracle kind is NOT in the
    offline/static FACT-eligible set is demoted to a LEAD even though confirm_and_certify signed it;
  * an unmapped class, an unreproducible channel, an LLM-provenanced reproduction, or a not-twice-fired
    reproduction is a LEAD;
  * verified_by_oracle is NEVER gated on (it is set for every DAA match by design).

Needs framework (context_from_exchanges + the oracle) → tw.sh off / offense venv.
"""

from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.verify.poc_translate")

from vigil_core import generate_keypair  # noqa: E402
from vigil_integration.redpen import LensCandidate, Reproduction, certify_candidate  # noqa: E402
from vigil_integration.redpen.certify import _FACT_ELIGIBLE_ORACLE_KINDS  # noqa: E402

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]


def _repro(stdout="", stderr="", request_value="", provenance="reproduced", fired_twice=True,
           status="reproduced"):
    return Reproduction(status=status, fired_twice=fired_twice, fires=2, runs=2, provenance=provenance,
                        stdout=stdout, stderr=stderr, request_value=request_value)


def _cand(bug_class, channel, **kw):
    return LensCandidate(lens="injection", bug_class=bug_class, channel=channel, finding_ref="rp-1", **kw)


# ---- the three reproducible channels each mint a FACT when their oracle fires -------------------------

def test_request_payload_channel_sqli_breakout_is_a_fact():
    r = certify_candidate(_cand("sqli_attempt", "request_payload", param="q"),
                          _repro(request_value="' OR '1'='1"), engagement_slug="acme", signers=SIGNERS)
    assert r.is_fact and r.confirmed_by == "sql_injection_breakout" and r.signed is not None


def test_request_payload_channel_command_injection_breakout_is_a_fact():
    r = certify_candidate(_cand("command_injection_attempt", "request_payload", param="cmd"),
                          _repro(request_value="; cat /etc/passwd"), engagement_slug="acme", signers=SIGNERS)
    assert r.is_fact and r.confirmed_by == "command_injection_breakout"


def test_process_channel_sanitizer_crash_is_a_fact():
    asan = "==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0xdeadbeef"
    r = certify_candidate(_cand("use_after_free", "process"), _repro(stderr=asan),
                          engagement_slug="acme", signers=SIGNERS)
    assert r.is_fact and r.confirmed_by == "sanitizer_signal" and r.signed is not None


def test_error_signature_channel_is_a_fact():
    err = "You have an error in your SQL syntax; check the manual for your MySQL server version"
    r = certify_candidate(_cand("error_based_sqli", "error_signature"), _repro(stdout=err),
                          engagement_slug="acme", signers=SIGNERS)
    assert r.is_fact and r.confirmed_by == "error_signature"


# ---- O-1: the authoritative gate is the FIRED oracle kind --------------------------------------------

def test_a_benign_request_value_does_not_fire_and_is_a_lead():
    r = certify_candidate(_cand("sqli_attempt", "request_payload", param="q"),
                          _repro(request_value="O'Brien"), engagement_slug="acme", signers=SIGNERS)
    assert r.status == "lead" and r.signed is None


def test_a_confirmed_but_non_eligible_oracle_kind_is_demoted_to_a_lead():
    # Inject a firewall that CONFIRMS with an oracle kind OUTSIDE the O-1 set (an achieved-state authz
    # read). O-1 demotes it to a LEAD here even though it is "confirmed + signed".
    class _Res:
        status = "fact"
        is_fact = True
        confirmed_by = "achieved_state"
        bug_class = "idor"
        finding_ref = "rp-1"
        reason = "confirmed by achieved_state and signed"
        confidence = 0.99
        outcome = "positive"
        signed = object()

    def fake_confirm(*_a, **_k):
        return _Res()

    r = certify_candidate(_cand("idor", "process"), _repro(stderr="achieved"),
                          engagement_slug="acme", signers=SIGNERS, confirm=fake_confirm)
    assert r.status == "lead" and r.signed is None and r.confirmed_by == "achieved_state"
    assert "v1 FACT-eligible" in r.reason


def test_an_eligible_oracle_kind_from_the_seam_is_a_fact():
    # The same seam, but a FACT-eligible kind -> a FACT (confirms the gate accepts the eligible set).
    sentinel = object()

    class _Res:
        status = "fact"
        is_fact = True
        confirmed_by = "sanitizer_signal"
        bug_class = "crash"
        finding_ref = "rp-1"
        reason = "confirmed"
        confidence = 0.95
        outcome = "positive"
        signed = sentinel

    r = certify_candidate(_cand("crash", "process"), _repro(stderr="panic"),
                          engagement_slug="acme", signers=SIGNERS, confirm=lambda *a, **k: _Res())
    assert r.is_fact and r.signed is sentinel


def test_the_fact_eligible_oracle_kinds_are_exactly_the_o1_set():
    # A guard the red-pen can read: the allowlist IS the O-1 offline/static oracle set, nothing more.
    assert _FACT_ELIGIBLE_ORACLE_KINDS == frozenset({
        "sql_injection_breakout", "command_injection_breakout", "nosql_injection_breakout",
        "path_traversal_breakout", "ssrf_breakout", "xxe_breakout",
        "sanitizer_signal", "error_signature", "side_effect", "static_rule",
    })


# ---- LEAD paths: unmapped class / unreproducible channel / llm / not reproduced ---------------------

def test_an_unmapped_bug_class_is_a_lead():
    r = certify_candidate(_cand("totally_unknown_class", "process"), _repro(stderr="panic: runtime error"),
                          engagement_slug="acme", signers=SIGNERS)
    assert r.status == "lead" and r.signed is None


def test_an_unreproducible_channel_is_a_lead():
    # http_differential is not reproducible from the R1 process sandbox -> LEAD (never attempts a mint).
    r = certify_candidate(_cand("boolean_sqli", "http_differential"), _repro(stdout="x"),
                          engagement_slug="acme", signers=SIGNERS)
    assert r.status == "lead" and "not in the v1 reproducible oracle set" in r.reason


def test_an_llm_provenanced_reproduction_is_a_lead():
    # Even a would-be-firing payload is a LEAD when its context is LLM-provenanced (G4 / O-1).
    r = certify_candidate(_cand("sqli_attempt", "request_payload", param="q"),
                          _repro(request_value="' OR '1'='1", provenance="llm"),
                          engagement_slug="acme", signers=SIGNERS)
    assert r.status == "lead" and r.signed is None


def test_a_not_twice_fired_reproduction_is_a_lead():
    r = certify_candidate(_cand("sqli_attempt", "request_payload", param="q"),
                          _repro(request_value="' OR '1'='1", fired_twice=False, provenance="",
                                 status="not_reproduced"),
                          engagement_slug="acme", signers=SIGNERS)
    assert r.status == "lead" and r.signed is None


def test_verified_by_oracle_truthy_does_not_make_a_nonfiring_candidate_a_fact():
    # The anti-pattern O-1 forbids: gating on verified_by_oracle (true for every DAA match). The payload
    # is benign so the oracle does not fire -> a LEAD, regardless of verified_by_oracle.
    r = certify_candidate(_cand("sqli_attempt", "request_payload", param="q", verified_by_oracle=True),
                          _repro(request_value="O'Brien"), engagement_slug="acme", signers=SIGNERS)
    assert r.status == "lead" and r.signed is None
