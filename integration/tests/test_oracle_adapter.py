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

    res = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS)
    assert res.is_fact and res.confirmed_by == "boolean_inference"  # the .value, not the enum repr
    # THE contract: the minted cert survives CRUCIBLE's own layered verifier — authentic + bound +
    # REPRODUCED. This is what the P10 inert seam will re-check; a repr-form confirmed_by fails it.
    ver = verify_certificate(res.signed, oracle_context=_finding("sqli")["oracle_context"], trust_root=TRUST)
    assert ver.ok is True, f"cert must verify end-to-end, got: {ver}"


def test_unconfirmed_finding_is_a_lead_not_a_fact():
    res = confirm_and_certify(
        _finding("sqli", ctx={"bug_class": "sqli", "note": "inert — no probe rounds"}),
        engagement_slug="acme", signers=SIGNERS)
    assert res.status == "lead" and res.signed is None and "did not fire" in res.reason


def test_confirmed_but_unmapped_class_stays_a_lead_honesty_invariant():
    # the boolean oracle fires (real), but a class with no deterministic oracle mapping is NOT
    # promoted to a signed fact — the invariant that keeps the system honest.
    res = confirm_and_certify(_finding("totally-made-up-class"), engagement_slug="acme", signers=SIGNERS)
    assert res.status == "lead" and res.signed is None
    assert "no deterministic oracle mapping" in res.reason


def test_empty_signers_is_refused_fail_closed():
    # a confirmed finding with no governance signers must NOT be labelled a fact (0-signature cert).
    with pytest.raises(ValueError, match="signers"):
        confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=[])


def test_malformed_oracle_context_fails_closed():
    # a non-dict oracle_context must not yield a fact (fail-closed via raise, not a false fact).
    with pytest.raises(Exception):
        confirm_and_certify(
            {"bug_class": "sqli", "oracle_context": "not-a-dict"}, engagement_slug="acme", signers=SIGNERS)


def test_tampering_a_signed_fact_breaks_its_signature():
    res = confirm_and_certify(_finding("sqli"), engagement_slug="acme", signers=SIGNERS)
    forged = res.signed.certificate.model_copy(update={"bug_class": "rce"})  # relabel after signing
    msg = evidence_signing_bytes(forged.model_dump(mode="json"))
    assert verify_threshold(msg, res.signed.signatures, TRUST).satisfied is False
