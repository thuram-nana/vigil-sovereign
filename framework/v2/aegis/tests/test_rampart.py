"""FORGE RAMPART slice 1 — a real signed PCF certificate for every inline BLOCK.

The differentiator: every block the AEGIS gateway makes is a re-runnable proof. A benign (ALLOWED) request
produces NO block and NO certificate; a blocked request produces a certificate a third party re-verifies
offline by RE-FIRING the same request-side oracle; any tamper class is rejected fail-closed.
"""

from __future__ import annotations

import copy

import pytest

from framework.v2.aegis.inspect import inspect_request
from framework.v2.aegis.rampart import block_pcf_certificate, certref_of, verify_block_pcf


def _trust_root_and_signers(n: int = 3, threshold: int = 2):
    from framework.v2.entitlement.crypto import generate_keypair
    from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", keys[i].private_key_b64) for i in range(threshold)]
    return tr, signers


# ---- a genuine BLOCK -> a real signed PCF certificate that re-verifies offline --------------------------

_ATTACKS = [
    ("GET", "/search?q=1' UNION SELECT password FROM users-- -", "sql_injection_breakout"),
    ("GET", "/run?cmd=x;$(cat /etc/passwd)", "command_injection_breakout"),
    ("GET", "/find?user[$ne]=x", "nosql_injection_breakout"),
]


@pytest.mark.parametrize("method,path,expect_kind", _ATTACKS)
def test_a_blocked_request_mints_a_pcf_certificate_that_verifies_offline(method, path, expect_kind):
    pytest.importorskip("cryptography")
    tr, signers = _trust_root_and_signers()
    v = inspect_request(method, path, [], None, enforce=True)
    assert v is not None and v.decision == "confirmed" and v.action == "block"
    ref = certref_of(v)
    assert ref is not None and ref.confirmed_by == expect_kind

    pcf = block_pcf_certificate(v, signers=signers, seq=1)
    assert pcf is not None
    assert pcf["oracle"]["id"] == expect_kind and pcf["oracle"]["version"]
    assert pcf["verdict"]["fired"] is True and pcf["grounding"] == "FACT"
    assert verify_block_pcf(pcf, tr).verified            # re-established offline by a third party


# ---- the mandatory benign twin: an ALLOWED request produces NO block and NO certificate -----------------

_BENIGN = [
    ("GET", "/products?q=blue+widgets&page=2", None),
    ("GET", "/files/report.2024.final.pdf", None),                 # encoded-dot look-alike in a real name
    ("GET", "/api/v1/users/42/orders", None),                       # benign deep path
    ("POST", "/search?q=affordable+laptops", None),
]


@pytest.mark.parametrize("method,path,_", _BENIGN)
def test_a_benign_request_produces_no_block_and_no_certificate(method, path, _):
    _tr, signers = _trust_root_and_signers()
    v = inspect_request(method, path, [], None, enforce=True)
    # either nothing fired (None) or a non-confirmed verdict — never a block, and never a certificate
    assert v is None or v.decision != "confirmed"
    assert block_pcf_certificate(v, signers=signers, seq=1) is None
    assert certref_of(v) is None


def test_rampart_certifies_only_blocks_never_a_lead_or_clear():
    _tr, signers = _trust_root_and_signers()
    from framework.v2.aegis.models import Verdict
    # A TYPED lead/clear Verdict — belief-raising or below-band, never a block — yields no CertRef and no
    # certificate at the certref_of / block_pcf_certificate boundary. HONEST NOTE (RED-PEN + independent
    # sweep): the LOAD-BEARING guard for this property is the Verdict MODEL INVARIANT (a non-confirmed
    # verdict cannot carry a certificate — proven directly in the next test); certref_of's
    # `decision != "confirmed"` line is REDUNDANT defense-in-depth and cannot be isolated in a unit test,
    # because pydantic refuses to build a non-confirmed Verdict holding a certificate. This asserts the
    # observable boundary behaviour; the invariant test below is what actually pins the guard.
    lead = Verdict(decision="lead", attack_class="sqli_attempt", action="observe", confidence=0.6)
    clear = Verdict(decision="clear", attack_class="sqli_attempt", action="allow")
    for v in (lead, clear):
        assert v.certificate is None
        assert certref_of(v) is None
        assert block_pcf_certificate(v, signers=signers, seq=1) is None
    # and non-Verdict junk is likewise inert (total over the `block` argument)
    for junk in (None, "not a verdict", 42, [1, 2], {"decision": "confirmed"}, b"x"):
        assert certref_of(junk) is None
        assert block_pcf_certificate(junk, signers=signers, seq=1) is None


def test_the_verdict_model_invariant_is_the_real_no_cert_on_non_block_guard():
    # The ACTUAL load-bearing guard behind "only a block carries a certificate": the Verdict model itself
    # refuses to construct a non-confirmed verdict holding one. This is the guard certref_of relies on, and
    # the one the boundary test above cannot isolate — so it is pinned here, directly.
    from framework.v2.aegis.models import CertRef, Verdict
    ref = CertRef.mint({"request_payload": "1' UNION SELECT 1-- -"}, bug_class="sqli_attempt",
                       confirmed_by="sql_injection_breakout", confidence=0.9)
    for dec in ("lead", "clear"):
        with pytest.raises(Exception):     # pydantic: "only a confirmed verdict may carry a certificate"
            Verdict(decision=dec, attack_class="sqli_attempt", certificate=ref)
    # and a confirmed verdict REQUIRES one (the invariant's other half) — so the two are strictly coupled
    with pytest.raises(Exception):
        Verdict(decision="confirmed", attack_class="sqli_attempt", certificate=None)


def test_block_pcf_certificate_is_total_over_seq():
    # RED-PEN secondary: an invalid seq yields no certificate (fail-closed), never raises.
    tr, signers = _trust_root_and_signers()
    v = inspect_request("GET", "/x?q=1' UNION SELECT 1-- -", [], None, enforce=True)
    for bad_seq in (-1, "1", 1.0, True, None):
        assert block_pcf_certificate(v, signers=signers, seq=bad_seq) is None
    # a valid seq still mints (sanity: the guard did not over-refuse)
    assert block_pcf_certificate(v, signers=signers, seq=0) is not None


# ---- fail-closed: every tamper class on a block's certificate is rejected --------------------------------

def _one_block_pcf():
    tr, signers = _trust_root_and_signers()
    v = inspect_request("GET", "/search?q=1' OR '1'='1' UNION SELECT 1-- -", [], None, enforce=True)
    return tr, block_pcf_certificate(v, signers=signers, seq=1)


def test_tamper_flip_claim_class_is_rejected():
    pytest.importorskip("cryptography")
    tr, pcf = _one_block_pcf()
    t = copy.deepcopy(pcf); t["claim"]["class"] = "command_injection_breakout"
    assert not verify_block_pcf(t, tr).verified


def test_tamper_flip_verdict_fired_is_rejected():
    pytest.importorskip("cryptography")
    tr, pcf = _one_block_pcf()
    t = copy.deepcopy(pcf); t["verdict"]["fired"] = False
    assert not verify_block_pcf(t, tr).verified


def test_untrusted_key_is_rejected():
    pytest.importorskip("cryptography")
    _tr, pcf = _one_block_pcf()
    other_tr, _ = _trust_root_and_signers()          # a DIFFERENT trust root never signed this cert
    assert not verify_block_pcf(pcf, other_tr).verified


def test_determinism_same_block_same_seq_same_certificate_bytes():
    pytest.importorskip("cryptography")
    _tr, signers = _trust_root_and_signers()
    v = inspect_request("GET", "/x?q=1' UNION SELECT 1-- -", [], None, enforce=True)
    a = block_pcf_certificate(v, signers=signers, seq=5)
    b = block_pcf_certificate(v, signers=signers, seq=5)
    # the authenticated view (everything but the signature's per-run randomness) is identical
    assert a["id"] == b["id"] and a["claim"] == b["claim"] and a["evidence"] == b["evidence"]
