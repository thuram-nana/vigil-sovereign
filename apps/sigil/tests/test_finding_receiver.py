"""P10 — sovereign-side ingest of an oracle-confirmed finding across the inert seam (two-anchor).

Anchor 1 (CRUCIBLE m-of-n governance signature) is verified HERE before the record is admitted;
a finding whose signature does not satisfy the trust root is REFUSED and never written. Anchor 2
(the owner-signed spine head) is the hash-chain the appended record joins.

The envelope is built with vigil_core alone (no framework) so this test co-loads with sigil —
the offense-free boundary means framework and sigil cannot share a process.
"""

import tempfile

import pytest

from sigil.inbound import ingest_finding
from sigil.spine.store import SpineStore
from vigil_core import (
    AuthorizerKey,
    TrustRoot,
    evidence_signing_bytes,
    generate_keypair,
    sign,
)
from vigil_integration.inert_finding import InertFindingError, build_envelope

ROOT = generate_keypair()
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=ROOT.public_key_b64)])


def _cert(**over):
    base = {
        "schema_version": 1, "engagement_slug": "acme", "finding_ref": "sqli-001",
        "bug_class": "sqli", "oracle_context_digest": "a" * 64, "confidence": 0.9,
    }
    base.update(over)
    return base


def _signed_envelope(cert=None, *, signer=ROOT, key_id="root0"):
    cert = cert or _cert()
    sig = sign(signer.private_key_b64, evidence_signing_bytes(cert))  # CRUCIBLE signing convention
    return build_envelope(cert, [{"key_id": key_id, "signature_b64": sig}])


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _findings(store):
    return [r for r in store.iter_records() if r.kind == "finding"]


def test_valid_signed_finding_is_appended_to_the_spine():
    s = _store()
    seq = ingest_finding(s, _signed_envelope(), crucible_trust_root=TRUST)
    rec = s.get(seq)
    assert rec.kind == "finding" and rec.source == "offense" and rec.actor == "ORACLE"
    assert rec.payload["finding_ref"] == "sqli-001"
    assert rec.payload["certificate"]["bug_class"] == "sqli"


def test_bad_signature_is_refused_and_nothing_is_written():
    s = _store()
    attacker = generate_keypair()
    env = _signed_envelope(signer=attacker)  # attacker-signed, verified against the ROOT trust
    with pytest.raises(InertFindingError, match="anchor 1"):
        ingest_finding(s, env, crucible_trust_root=TRUST)
    assert _findings(s) == []  # fail-closed: unverified finding never reaches the spine


def test_wrong_trust_root_is_refused():
    s = _store()
    other = TrustRoot(threshold=1, authorizers=[AuthorizerKey(
        key_id="x", name="x", public_key_b64=generate_keypair().public_key_b64)])
    with pytest.raises(InertFindingError, match="anchor 1"):
        ingest_finding(s, _signed_envelope(), crucible_trust_root=other)
    assert _findings(s) == []


def test_relabelled_after_signing_is_refused():
    # tamper the certificate's bug_class after signing → signature no longer verifies → refused
    import json
    env = json.loads(_signed_envelope())
    env["certificate"]["bug_class"] = "rce"
    s = _store()
    with pytest.raises(InertFindingError, match="anchor 1"):
        ingest_finding(s, json.dumps(env), crucible_trust_root=TRUST)
    assert _findings(s) == []


def test_malformed_envelope_is_refused():
    s = _store()
    for bad in ["{not json", b"\x80\x04pickled", "[1,2,3]", '{"schema":"evil"}']:
        with pytest.raises(InertFindingError):
            ingest_finding(s, bad, crucible_trust_root=TRUST)
    assert _findings(s) == []


def test_anchor2_the_appended_finding_is_chained():
    # the finding joins the hash-chain the owner-signed head anchors (prev_hash/entry_hash present)
    s = _store()
    seq = ingest_finding(s, _signed_envelope(), crucible_trust_root=TRUST)
    rec = s.get(seq)
    assert rec.entry_hash and rec.prev_hash is not None


def test_ingesting_a_finding_pulls_no_offense_engine():
    # sovereignty: the receiver treats a finding as inert DATA — importing/using it loads NO
    # framework.*/strix.* into the SIGIL process (assert_no_offense holds).
    import sys

    import sigil.inbound  # noqa: F401  (already imported at top; re-assert after use)
    from sigil.reuse import assert_no_offense

    ingest_finding(_store(), _signed_envelope(), crucible_trust_root=TRUST)
    assert_no_offense()  # would raise if framework/strix were loaded
    assert not any(m == "framework" or m.startswith("framework.")
                   or m == "strix" or m.startswith("strix.") for m in sys.modules)
