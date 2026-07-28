"""A6a — the oracle-backed fix verification (remediation.fix_oracle) driving autopatch.verify_patch.

``remediated=True`` is EARNED, never asserted: the ORIGINAL exploit oracle is re-fired against the patched
build's freshly re-captured bytes, and a remediation cert is signed ONLY when it goes SILENT. Every path where
silence cannot be soundly confirmed (no re-drive, unbuildable capture, request-side channel, a re-drive on the
WRONG oracle family, no signer) is refused — the caller's verify_patch maps the raise to ``unverified``, so a
fix can never be FAKED by simply failing to re-drive or by re-driving over a mismatched oracle.

Needs framework (reverify + the oracle) → run with PYTHONPATH=integration:engine/crucible:gateway.
"""

from __future__ import annotations

import json

import pytest

from vigil_core import generate_keypair
from vigil_integration.autopatch.loop import verify_patch
from vigil_integration.remediation.fix_oracle import (
    build_fix_oracle,
    build_fix_signer,
    build_run_fix_oracle,
)

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"


def _redrive_returning(body: bytes, *, channel: str = "error_signature"):
    """A fake re-drive: the patched build's response to the original exploit as a _vigil_capture bundle."""
    def _redrive(request, patched_build):
        return {"exchanges": [{"channel": channel, "role": "mutated", "response_bytes_ref": "resp",
                               "bug_class": "error_based_sqli"}],
                "blobs": {"resp": body}}
    return _redrive


def _signer():
    return build_fix_signer(engagement_slug="acme", signers=SIGNERS)


def _oracle(body, *, channel="error_signature", expected="error_signature", signer=True):
    return build_fix_oracle(bug_class="error_based_sqli", redrive=_redrive_returning(body, channel=channel),
                            expected_channel=expected, driving_ref="errsqli-1",
                            signer=_signer() if signer else None)


def test_patched_build_silent_earns_a_signed_remediation():
    v = verify_patch(object(), "b", oracle=_oracle(_BENIGN))
    assert v.remediated and v.status == "remediated" and v.evidence_ref.startswith("remediation:")


def test_still_vulnerable_patched_build_is_not_remediated():
    v = verify_patch(object(), "b", oracle=_oracle(_SQL_ERROR))
    assert not v.remediated and v.status == "still-vulnerable"


def test_request_side_finding_is_refused_at_build():
    # a request_payload finding: the patch changes the response, not the request — not oracle-provable.
    with pytest.raises(ValueError, match="request-side"):
        build_fix_oracle(bug_class="sqli_attempt", redrive=_redrive_returning(b"' OR '1'='1"),
                         expected_channel="request_payload", driving_ref="r", signer=_signer())


def test_channel_mismatch_is_refused_not_faked():
    # ADVERSARIAL-REVIEW REGRESSION: a still-vulnerable build whose re-drive claims a DIFFERENT channel than
    # the finding's confirmed family would build a context the resolved oracle can't read (a vacuous non-fire).
    # It MUST be refused (unverified), never minted as a signed remediation.
    v = verify_patch(object(), "b", oracle=_oracle(_SQL_ERROR, channel="process", expected="error_signature"))
    assert not v.remediated and v.status == "unverified"


def test_no_redrive_capability_is_unverified_never_silent():
    oracle = build_fix_oracle(bug_class="error_based_sqli", redrive=None, expected_channel="error_signature",
                              driving_ref="x", signer=_signer())
    assert verify_patch(object(), "b", oracle=oracle).status == "unverified"


def test_empty_redrive_result_is_unverified():
    oracle = build_fix_oracle(bug_class="error_based_sqli", redrive=lambda r, b: None,
                              expected_channel="error_signature", driving_ref="x", signer=_signer())
    assert verify_patch(object(), "b", oracle=oracle).status == "unverified"


def test_unbuildable_capture_on_the_right_channel_is_unverified_not_silence():
    # matching channel but an unresolvable byte-ref → context_from_exchanges None → unbuildable, NOT silence.
    def redrive(request, patched_build):
        return {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                               "bug_class": "error_based_sqli"}], "blobs": {}}   # 'resp' does not resolve
    oracle = build_fix_oracle(bug_class="error_based_sqli", redrive=redrive, expected_channel="error_signature",
                              driving_ref="x", signer=_signer())
    assert verify_patch(object(), "b", oracle=oracle).status == "unverified"


def test_missing_expected_channel_is_refused_at_build():
    with pytest.raises(ValueError, match="channel"):
        build_fix_oracle(bug_class="error_based_sqli", redrive=_redrive_returning(_BENIGN),
                         expected_channel="", driving_ref="x", signer=_signer())


def test_silent_but_no_signer_is_unverified():
    assert verify_patch(object(), "b", oracle=_oracle(_BENIGN, signer=False)).status == "unverified"


def test_signer_refuses_empty_governance_signers():
    with pytest.raises(ValueError, match="signers"):
        build_fix_signer(engagement_slug="acme", signers=[])


def _write_reverifiable(tmp_path, **extra):
    d = tmp_path / "proofs"
    d.mkdir(parents=True, exist_ok=True)
    (d / "reverifiable.json").write_text(json.dumps({"active_findings": [
        {"check_id": "errsqli-1", "bug_class": "error_based_sqli", "oracle_context": {"x": 1}, **extra}]}),
        encoding="utf-8")


def test_run_fix_oracle_resolves_class_and_channel_from_reverifiable(tmp_path):
    # the C1 linkage: resolve the exact oracle bug_class AND channel from reverifiable.json by ref.
    _write_reverifiable(tmp_path, channel="error_signature")
    oracle = build_run_fix_oracle(run_dir=tmp_path, finding_ref="errsqli-1",
                                  redrive=_redrive_returning(_BENIGN), engagement_slug="acme", signers=SIGNERS)
    assert verify_patch(object(), "b", oracle=oracle).remediated


def test_run_fix_oracle_refuses_when_channel_unresolvable(tmp_path):
    # a finding whose retained material lacks a channel cannot be pinned to an oracle family → refuse.
    _write_reverifiable(tmp_path)              # no 'channel'
    with pytest.raises(ValueError, match="CHANNEL"):
        build_run_fix_oracle(run_dir=tmp_path, finding_ref="errsqli-1",
                             redrive=_redrive_returning(_BENIGN), engagement_slug="acme", signers=SIGNERS)


def test_run_fix_oracle_refuses_when_finding_unresolvable(tmp_path):
    (tmp_path / "proofs").mkdir(parents=True)
    with pytest.raises(ValueError, match="cannot resolve"):
        build_run_fix_oracle(run_dir=tmp_path, finding_ref="missing",
                             redrive=_redrive_returning(_BENIGN), engagement_slug="acme", signers=SIGNERS)
