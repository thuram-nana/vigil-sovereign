"""P9 — the OracleConfirmationAdapter: only an oracle-confirmed, oracle-mapped finding becomes a
signed FACT that survives CRUCIBLE's OWN verify_certificate; everything else is a labelled lead.

These tests drive the REAL OracleVerifier over a genuine firing boolean-inference context (the
SPRT oracle confirms a boolean-blind bug), so the minted certificate is exercised end-to-end
through verify_certificate (authentic + bound + REPRODUCED) — the contract the first cut of this
test green-washed by checking only the raw signature.

MUST run in its OWN pytest process (it loads framework.* = offense): sigil.governor's
assert_no_offense() refuses to co-load framework with a SIGIL module, so this file cannot share a
process with the sigil-importing tests. CI runs it separately (see the integration job).
"""

from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE not importable here")

from vigil_core import (  # noqa: E402
    AuthorizerKey,
    TrustRoot,
    evidence_signing_bytes,
    generate_keypair,
    verify_threshold,
)
from vigil_integration.oracle_adapter import confirm_and_certify  # noqa: E402

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=SIGNER.public_key_b64)])

# A genuinely firing boolean-blind SQLi context: the true clause returns the whole table, the
# false clause is a stable "no results", with a per-round dynamic-page control (false_a==false_b).
_MANY = {"status": 200, "body": "id=1\nid=2\nid=3\nid=4\nid=5 (all rows)"}
_NONE = {"status": 200, "body": "no results"}


def _firing_context(bug_class="sqli"):
    return {"bug_class": bug_class,
            "probe_rounds": [{"true": _MANY, "false_a": _NONE, "false_b": _NONE} for _ in range(24)]}


def _finding(bug_class="sqli", ctx=None):
    return {"check_id": "sqli-blind-001", "bug_class": bug_class, "insertion_point": "id",
            "oracle_context": ctx if ctx is not None else _firing_context(bug_class)}


def test_confirmed_finding_becomes_a_fact_that_passes_verify_certificate():
    from framework.v2.evidence.certify import verify_certificate

    # provenance="reproduced": the context is the real target's baseline/probe responses (the executor-
    # captured, non-LLM channel), so a firing + oracle-mapped finding mints a signed FACT (audit G4).
    res = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS,
                              provenance="reproduced")
    assert res.is_fact and res.confirmed_by == "boolean_inference"  # the .value, not the enum repr
    # THE contract: the minted cert survives CRUCIBLE's own layered verifier — authentic + bound +
    # REPRODUCED. This is what the P10 inert seam will re-check; a repr-form confirmed_by fails it.
    ver = verify_certificate(res.signed, oracle_context=_finding("sqli")["oracle_context"], trust_root=TRUST)
    assert ver.ok is True, f"cert must verify end-to-end, got: {ver}"


def test_unconfirmed_finding_is_a_lead_not_a_fact():
    res = confirm_and_certify(
        _finding("sqli", ctx={"bug_class": "sqli", "note": "inert — no probe rounds"}),
        engagement_slug="acme", signers=SIGNERS)
    # unconfirmed → LEAD, never a signed FACT (the invariant). Phase 0.1 additionally classifies WHY: an
    # inert context with no probe rounds gave no oracle a decisive channel → the typed INCONCLUSIVE outcome
    # (never CLEAN, which requires a conclusive non-firing oracle).
    assert res.status == "lead" and res.signed is None
    assert res.outcome == "inconclusive"


def test_confirmed_but_unmapped_class_stays_a_lead_honesty_invariant():
    # the boolean oracle fires (real), but a class with no deterministic oracle mapping is NOT
    # promoted to a signed fact — the invariant that keeps the system honest.
    res = confirm_and_certify(_finding("totally-made-up-class"), engagement_slug="acme", signers=SIGNERS)
    assert res.status == "lead" and res.signed is None
    assert "no deterministic oracle mapping" in res.reason


def test_finding_vs_context_class_mismatch_is_refused_not_a_false_clean():
    # audit A1 fix-of-the-fix: the oracle adjudicates the retained CONTEXT's class, so a finding whose DECLARED
    # class differs from its context class could launder a verdict. When they disagree the finding is REFUSED
    # as an UNSUPPORTED lead — and critically it must NEVER be routed to a false CLEAN ("oracle conclusively
    # did not fire"), because the oracle in fact FIRED over the context class.
    firing = {"marker": "canary-zz99xx", "observed_sink": "leaked canary-zz99xx here"}
    # KNOWN declared 'rce' + UNKNOWN context 'sovereign_rce' (side_effect fires over the context class)
    res = confirm_and_certify(
        {"check_id": "x", "bug_class": "rce", "oracle_context": {"bug_class": "sovereign_rce", **firing}},
        engagement_slug="acme", signers=SIGNERS, provenance="reproduced")
    assert res.status == "lead" and res.signed is None
    assert res.outcome == "unsupported" and res.outcome != "clean"   # the false-CLEAN regression is closed
    # two KNOWN-but-different classes (a relabel) are likewise refused, never minted under the context class
    res2 = confirm_and_certify(
        {"check_id": "x", "bug_class": "rce", "oracle_context": {"bug_class": "xss", **firing}},
        engagement_slug="acme", signers=SIGNERS, provenance="reproduced")
    assert res2.status == "lead" and res2.signed is None and res2.outcome == "unsupported"


def test_unknown_class_conclusive_nonfiring_is_unsupported_not_a_false_clean():
    # audit A1 fix-of-the-fix #3 (independent red-pen BLOCK-1): the unknown-class gate must be SYMMETRIC.
    # The earlier fix closed only the FIRING half (unknown + a fired oracle -> UNSUPPORTED). A conclusive
    # NON-firing context for an out-of-vocabulary class fell through to probe_verdict and was reported as a
    # channel-confirmed CLEAN negative — unsound, because no oracle is MAPPED to the class ("an applicable
    # oracle conclusively did not fire" is false when none is applicable). VIGIL's flagship signed negative is
    # a Certificate of Non-Exploitability, so a false CLEAN is a soundness violation in the headline claim.
    same = {"status": 200, "body": "identical body"}   # byte-identical SPRT arms => conclusive non-firing
    nonfiring = {"probe_rounds": [{"true": same, "false_a": same, "false_b": same} for _ in range(24)]}
    res = confirm_and_certify(
        {"check_id": "x", "bug_class": "sovereign_rce", "oracle_context": dict(nonfiring)},
        engagement_slug="acme", signers=SIGNERS, provenance="reproduced")
    assert res.status == "lead" and res.signed is None
    assert res.outcome == "unsupported" and res.outcome != "clean"   # the non-firing false-CLEAN half is CLOSED
    # POSITIVE CONTROL (non-vacuous + no over-correction): the SAME conclusive non-firing context with a KNOWN
    # class IS a legitimate channel-confirmed CLEAN negative — only the unknown class is suppressed, so the gate
    # is the sole thing changing the verdict and it does not demote a real clean negative.
    res_known = confirm_and_certify(
        {"check_id": "x", "bug_class": "sqli", "oracle_context": dict(nonfiring)},
        engagement_slug="acme", signers=SIGNERS, provenance="reproduced")
    assert res_known.status == "lead" and res_known.outcome == "clean"


def test_empty_signers_is_refused_fail_closed():
    # a confirmed finding with no governance signers must NOT be labelled a fact (0-signature cert).
    with pytest.raises(ValueError, match="signers"):
        confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=[])


def test_malformed_oracle_context_fails_closed():
    # a non-dict oracle_context must not yield a fact (fail-closed via raise, not a false fact).
    with pytest.raises(Exception):
        confirm_and_certify(
            {"bug_class": "sqli", "oracle_context": "not-a-dict"}, engagement_slug="acme", signers=SIGNERS)


def test_llm_provenanced_context_is_a_lead_even_when_the_oracle_fires():
    # AUDIT G4: the SAME genuinely-firing context, but declared LLM-provenanced (the default), must NOT
    # mint a signed FACT — a crafted-but-firing extracted_info is the exact route this gate closes.
    res_default = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS)
    assert res_default.status == "lead" and res_default.signed is None
    assert "LLM-provenanced" in res_default.reason
    assert res_default.confirmed_by == "boolean_inference"     # the oracle DID fire — honestly labelled
    res_llm = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS,
                                  provenance="llm")
    assert res_llm.status == "lead" and res_llm.signed is None


def test_tampering_a_signed_fact_breaks_its_signature():
    res = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS,
                              provenance="reproduced")
    forged = res.signed.certificate.model_copy(update={"bug_class": "rce"})  # relabel after signing
    msg = evidence_signing_bytes(forged.model_dump(mode="json"))
    assert verify_threshold(msg, res.signed.signatures, TRUST).satisfied is False


# --- the confirmed-fact -> SCITT bridge (offline-verifiable standards-native cert) ------------

def test_certify_to_scitt_mints_an_offline_verifiable_statement_from_a_fact():
    import base64
    import json

    from vigil_integration.oracle_adapter import certify_to_scitt
    from vigil_integration.scitt import StatementLog, verify_receipt, verify_signed_statement

    res = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS,
                              provenance="reproduced")
    assert res.is_fact
    log = StatementLog()
    ss, receipt = certify_to_scitt(res, SIGNERS, author="vigil:oracle",
                                   timestamp="2026-07-20T00:00:00Z", log=log)
    # the standards-native statement verifies m-of-n against the SAME governance root, OFFLINE, and
    # its inclusion receipt reconstructs the log root — the confirmed fact is now offline-verifiable.
    assert verify_signed_statement(ss, trust_root=TRUST) is True
    ok, _ = verify_receipt(receipt, ss, trust_root=TRUST, expected_root=log.root())
    assert ok is True
    payload = json.loads(base64.b64decode(ss.payload_b64))
    assert payload["statements"][0]["status"] == "affected"  # confirmed → affected (honesty invariant)


def test_certify_to_scitt_refuses_a_lead():
    from vigil_integration.oracle_adapter import certify_to_scitt

    # a non-firing context (true == false → no inference) yields a lead, which has no signed cert
    lead_ctx = {"bug_class": "sqli", "probe_rounds": [{"true": _NONE, "false_a": _NONE, "false_b": _NONE}]}
    res = confirm_and_certify(_finding("sqli", ctx=lead_ctx), engagement_slug="acme", signers=SIGNERS)
    assert res.status == "lead"
    with pytest.raises(ValueError, match="confirmed fact"):
        certify_to_scitt(res, SIGNERS, author="a", timestamp="t")


def test_d2_binding_threads_into_the_signed_cert_and_is_filtered():
    """D2 (Wave #4): confirm_and_certify forwards `binding=` into the SIGNED certificate, filtered to the D2
    key allowlist, so a posture FACT proves WHICH artifact/scope/when/completeness. Surfaced by
    verify_certificate.bound_identity WITHOUT gating .ok; a hostile extra key is dropped; no binding =>
    no D2 fields (the byte-identity path)."""
    from framework.v2.evidence.certify import verify_certificate
    binding = {"artifact_sha256": "c" * 64, "collector_id": "iac-parser",
               "resource_scope": {"provider": "aws", "account": "111122223333"},
               "completeness": "partial", "capture_method": "artifact:terraform-state"}
    ctx = _finding("sqli")["oracle_context"]
    res = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS,
                              provenance="reproduced", binding=binding)
    assert res.is_fact
    ver = verify_certificate(res.signed, oracle_context=ctx, trust_root=TRUST)
    assert ver.ok and ver.bound_identity == binding          # surfaced, does NOT gate .ok
    res_evil = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS,
                                   provenance="reproduced", binding={**binding, "evil": "smuggled"})
    assert "evil" not in verify_certificate(res_evil.signed, oracle_context=ctx,
                                            trust_root=TRUST).bound_identity
    res0 = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS,
                               provenance="reproduced")
    assert verify_certificate(res0.signed, oracle_context=ctx, trust_root=TRUST).bound_identity == {}
