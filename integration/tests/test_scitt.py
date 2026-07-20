"""I2-family — SCITT/OpenVEX standards-native, offline-verifiable finding certificates.

Load-bearing: a client verifies a finding OFFLINE — DSSE m-of-n signature over an OpenVEX statement,
an RFC-6962 Merkle inclusion proof against the log root, and (anchored) the I2 witnessed checkpoint
that attests that root. A confirmed finding is 'affected'; a lead is never asserted affected."""

from __future__ import annotations

import hashlib

from vigil_core import AuthorizerKey, TrustRoot, evidence_signing_bytes, generate_keypair, sign
from vigil_integration.scitt import (
    OPENVEX_MEDIA_TYPE,
    STATUS_AFFECTED,
    STATUS_UNDER_INVESTIGATION,
    Receipt,
    SignedStatement,
    Signature,
    StatementLog,
    _audit_path,
    _mth,
    build_signed_statement,
    openvex_statement,
    statement_digest,
    verify_anchored_receipt,
    verify_inclusion,
    verify_receipt,
    verify_signed_statement,
)
from vigil_integration.transparency import Checkpoint, Witness, WitnessedCheckpoint, checkpoint_hash

G0, G1 = generate_keypair(), generate_keypair()  # governance signers
GOV = TrustRoot(threshold=2, authorizers=[
    AuthorizerKey(key_id="g0", name="g0", public_key_b64=G0.public_key_b64),
    AuthorizerKey(key_id="g1", name="g1", public_key_b64=G1.public_key_b64)])
_GOV_SIGNERS = [("g0", G0.private_key_b64), ("g1", G1.private_key_b64)]


def _cert(**over):
    base = dict(schema_version=1, engagement_slug="acme", finding_ref="sqli-001", bug_class="sqli",
                oracle_context_digest="a" * 64, confidence=0.9)
    base.update(over)
    return base


def _statement(cert=None, *, confirmed=True):
    return openvex_statement(cert or _cert(), author="vigil:oracle", timestamp="2026-07-20T00:00:00Z",
                             confirmed=confirmed)


def _signed(cert=None, *, confirmed=True, signers=None):
    return build_signed_statement(_statement(cert, confirmed=confirmed), signers or _GOV_SIGNERS)


# --- OpenVEX vocabulary ------------------------------------------------------------------------

def test_confirmed_finding_is_affected_lead_is_under_investigation():
    conf = _statement(confirmed=True)["statements"][0]
    lead = _statement(confirmed=False)["statements"][0]
    assert conf["status"] == STATUS_AFFECTED
    assert lead["status"] == STATUS_UNDER_INVESTIGATION
    assert conf["vulnerability"]["name"] == "sqli:sqli-001"
    assert conf["vigil_oracle_context_digest"] == "a" * 64


# --- DSSE signed statement ---------------------------------------------------------------------

def test_signed_statement_verifies_m_of_n_offline():
    ss = _signed()
    assert ss.payload_type == OPENVEX_MEDIA_TYPE
    assert verify_signed_statement(ss, trust_root=GOV) is True


def test_below_threshold_statement_is_refused():
    ss = _signed(signers=[("g0", G0.private_key_b64)])  # 1 of 2
    assert verify_signed_statement(ss, trust_root=GOV) is False


def test_tampered_payload_breaks_the_signature():
    ss = _signed()
    forged = SignedStatement(ss.payload_type,
                             __import__("base64").b64encode(b'{"evil":true}').decode(), ss.signatures)
    assert verify_signed_statement(forged, trust_root=GOV) is False


def test_dsse_pae_domain_separates_from_a_raw_evidence_signature():
    # a governance signature made over evidence_signing_bytes (the raw evidence domain) must NOT
    # verify as a DSSE statement — the PAE binds the payload TYPE, so the signed bytes differ.
    st = _statement()
    from vigil_integration.scitt import canonical_json  # re-exported vigil_core helper
    payload = canonical_json(st)
    ev_sigs = (Signature(key_id="g0", signature_b64=sign(G0.private_key_b64, evidence_signing_bytes(st))),
               Signature(key_id="g1", signature_b64=sign(G1.private_key_b64, evidence_signing_bytes(st))))
    forged = SignedStatement(OPENVEX_MEDIA_TYPE,
                             __import__("base64").b64encode(payload).decode(), ev_sigs)
    assert verify_signed_statement(forged, trust_root=GOV) is False


# --- RFC 6962 Merkle inclusion proofs ----------------------------------------------------------

def test_merkle_inclusion_is_exhaustively_correct():
    for n in range(1, 34):
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        root = _mth(leaves)
        for m in range(n):
            path = _audit_path(m, leaves)
            assert verify_inclusion(leaves[m], m, n, path, root) is True
            # tamper: wrong data, wrong index, wrong root, mutated path all fail
            assert verify_inclusion(b"WRONG", m, n, path, root) is False
            assert verify_inclusion(leaves[m], (m + 1) % n, n, path, root) is (n == 1 and m == 0)
            assert verify_inclusion(leaves[m], m, n, path, hashlib.sha256(b"x").digest()) is False
            if path:
                bad = list(path); bad[0] = hashlib.sha256(b"tamper").digest()
                assert verify_inclusion(leaves[m], m, n, bad, root) is False


def test_out_of_range_index_is_rejected():
    leaves = [b"a", b"b", b"c"]
    root = _mth(leaves)
    assert verify_inclusion(b"a", 5, 3, _audit_path(0, leaves), root) is False


# --- StatementLog + receipts -------------------------------------------------------------------

def test_receipt_verifies_and_does_not_bind_a_different_statement():
    log = StatementLog()
    a = _signed(_cert(finding_ref="sqli-001"))
    b = _signed(_cert(finding_ref="xss-002", bug_class="xss"))
    log.register(a)
    ib = log.register(b)
    rb = log.receipt(ib)
    ok, _ = verify_receipt(rb, b, trust_root=GOV)
    assert ok is True
    # the receipt for b does not verify statement a (digest mismatch)
    bad, reason = verify_receipt(rb, a, trust_root=GOV)
    assert bad is False and "bind" in reason


def test_receipt_with_a_broken_proof_fails():
    log = StatementLog()
    ss = _signed()
    i = log.register(ss)
    log.register(_signed(_cert(finding_ref="other")))
    r = log.receipt(i)
    tampered = Receipt(r.statement_digest, r.leaf_index, r.tree_size,
                       (hashlib.sha256(b"x").hexdigest(),) + r.audit_path[1:], r.root)
    ok, reason = verify_receipt(tampered, ss, trust_root=GOV)
    assert ok is False and "inclusion" in reason


def test_receipt_over_an_unsigned_statement_fails():
    log = StatementLog()
    ss = _signed(signers=[("g0", G0.private_key_b64)])  # below threshold
    i = log.register(ss)
    ok, reason = verify_receipt(log.receipt(i), ss, trust_root=GOV)
    assert ok is False and "signature" in reason


# --- anchored to the I2 witnessed transparency log ---------------------------------------------

def _witnesses(n):
    kps = [generate_keypair() for _ in range(n)]
    ws = [Witness(f"w{i}", kp.private_key_b64) for i, kp in enumerate(kps)]
    tr = TrustRoot(threshold=(n // 2) + 1, authorizers=[  # strict majority
        AuthorizerKey(key_id=f"w{i}", name=f"w{i}", public_key_b64=kp.public_key_b64)
        for i, kp in enumerate(kps)])
    return ws, tr


def _anchor(log, ws):
    # an I2 checkpoint whose merkle_root IS the SCITT log root, countersigned by a witness quorum
    cp = Checkpoint(last_seq=log.size(), entry_count=log.size(), head_hash="head-" + log.root()[:8],
                    merkle_root=log.root())
    return WitnessedCheckpoint(cp, tuple(w.cosign(cp) for w in ws))


def test_anchored_receipt_ties_the_statement_to_a_witnessed_checkpoint():
    ws, wtr = _witnesses(3)  # 2-of-3 strict majority
    log = StatementLog()
    ss = _signed()
    i = log.register(ss)
    log.register(_signed(_cert(finding_ref="second")))
    receipt = log.receipt(i)
    witnessed = _anchor(log, ws)
    ok, reason = verify_anchored_receipt(receipt, ss, witnessed, trust_root=GOV, witness_trust_root=wtr)
    assert ok is True and "witness-anchored" in reason


def test_anchored_receipt_rejects_a_checkpoint_over_a_different_root():
    ws, wtr = _witnesses(3)
    log = StatementLog()
    i = log.register(_signed())
    ss = _signed()  # actually register the real one
    i = log.register(ss)
    receipt = log.receipt(i)
    wrong = WitnessedCheckpoint(
        Checkpoint(last_seq=1, entry_count=1, head_hash="h", merkle_root="deadbeef" * 8),
        tuple(w.cosign(Checkpoint(last_seq=1, entry_count=1, head_hash="h", merkle_root="deadbeef" * 8))
              for w in ws))
    ok, reason = verify_anchored_receipt(receipt, ss, wrong, trust_root=GOV, witness_trust_root=wtr)
    assert ok is False and "anchor" in reason


def test_anchored_receipt_rejects_a_non_resistant_witness_quorum():
    # a genuine 1-of-3 witness root is NOT split-view-resistant (disjoint quorums possible), so even a
    # correctly-anchored, correctly-signed receipt is rejected — the anchor must be quorum-attested.
    kps = [generate_keypair() for _ in range(3)]
    wl = [Witness(f"n{i}", kp.private_key_b64) for i, kp in enumerate(kps)]
    non_resistant = TrustRoot(threshold=1, authorizers=[  # 1-of-3 → not strict majority
        AuthorizerKey(key_id=f"n{i}", name=f"n{i}", public_key_b64=kp.public_key_b64)
        for i, kp in enumerate(kps)])
    log = StatementLog()
    ss = _signed()
    i = log.register(ss)
    receipt = log.receipt(i)
    witnessed = _anchor(log, wl)
    ok, reason = verify_anchored_receipt(receipt, ss, witnessed, trust_root=GOV,
                                         witness_trust_root=non_resistant)
    assert ok is False and "resistant" in reason


def test_import_clean_no_offense_modules():
    import sys
    import vigil_integration.scitt  # noqa: F401
    assert not any(m == "framework" or m.startswith("framework.")
                   or m == "strix" or m.startswith("strix.") for m in sys.modules)
