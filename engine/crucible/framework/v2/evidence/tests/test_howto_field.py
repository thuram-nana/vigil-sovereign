"""B1 — the certificate's per-finding ``how_to_verify`` note: populated deterministically at mint, and
byte-identical (dropped from the canonical form) when empty so existing signed bundles are unchanged."""
from __future__ import annotations

from framework.v2.evidence.certify import build_certificate
from framework.v2.evidence.models import EvidenceCertificate


def _fact_finding() -> dict:
    return {
        "check_id": "sqli-1",
        "bug_class": "sql_injection",
        "insertion_point": "GET /search?q=",
        "confirmed_by": "error_signature",
        "confidence": 0.9,
        "oracle_context": {"payload": "1'", "signal": "SQL error"},
    }


def test_cert_carries_a_deterministic_how_to_verify():
    c1 = build_certificate(_fact_finding(), engagement_slug="acme")
    assert c1.how_to_verify, "a minted cert must carry a per-finding how_to_verify note"
    assert "Verify:" in c1.how_to_verify and "error_signature" in c1.how_to_verify
    assert "Fix:" in c1.how_to_verify
    # deterministic: same finding → byte-identical note (no wallclock/rng)
    assert build_certificate(_fact_finding(), engagement_slug="acme").how_to_verify == c1.how_to_verify
    # it is part of the SIGNED canonical bytes (tamper-evident, not just docs)
    assert "how_to_verify" in c1.model_dump(mode="json")


def test_empty_how_to_verify_is_dropped_for_byte_identity():
    # a certificate without the note serialises exactly as it did before the field existed → old signed
    # bundles keep verifying (the additive-drop-when-empty discipline, same as report_claims/oracle_version).
    empty = EvidenceCertificate(finding_ref="x", oracle_context_digest="sha256:deadbeef")
    dumped = empty.model_dump(mode="json")
    assert "how_to_verify" not in dumped
    assert "report_claims" not in dumped and "oracle_version" not in dumped
