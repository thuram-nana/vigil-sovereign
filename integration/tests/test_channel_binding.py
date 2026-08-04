"""TRUTHENOVATION Z1 — channel-binding (zkTLS) notary co-sign, deterministic + offline.

Proves the Z1 MECHANISM end-to-end without a network or a third party: a finding's response bytes are bound
to a TLS SESSION (a fixed test-vector exporter binding), a SOFTWARE notary co-signs the (session, response-
hash) tuple, and BOTH the in-tree verifier (:func:`channel_binding.verify_channel_binding_evidence`) and the
STANDALONE VIGIL-free verifier (``docs/proof-carrying-finding/verify_vf.py``) confirm it OFFLINE against the
PINNED notary key — WITHOUT trusting the producer. It asserts:

  * a session-bound, notary-cosigned finding VERIFIES offline (in-tree + standalone, byte-identical);
  * a PRODUCER-FABRICATED transcript with NO valid notary cosign is REJECTED (missing cosign; and a cosign
    from a producer key that is not the pinned notary → rejected even if the envelope asserts it);
  * a notary cosign over a DIFFERENT session or DIFFERENT bytes is REJECTED (swap the binding / the body);
  * the carried bytes must hash to the bound hash (a tampered body → rejected);
  * a wrong notary pin → rejected;
  * the exporter PARSER extracts the RFC 5705 keying material from canned ``openssl s_client`` output
    (the capture SHAPE, exercised without a live TLS session);
  * the genuine-independence path (:class:`RemoteNotary`, a real zkTLS/MPC-TLS third-party notary) is ABSENT
    and fails closed — no test pretends a software notary establishes producer-unforgeability.

Framework-FREE (vigil_core + vigil_integration.channel_binding + stdlib), so it runs in the no-framework
integration leg (``PYTHONPATH=integration:gateway``). openssl is only touched via a canned-string parser here.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
from pathlib import Path

import pytest

from vigil_core import generate_keypair
from vigil_integration.channel_binding import (
    ChannelBinding,
    ChannelBindingError,
    ChannelBoundResponse,
    LocalNotary,
    RemoteNotary,
    build_evidence,
    channel_bound_signing_bytes,
    notary_cosign,
    parse_keying_material,
    parse_tls_version,
    verify_channel_binding_evidence,
)

# --- a fixed test-vector TLS session binding (no live network) --------------------------------------------
BINDING = ChannelBinding(
    kind="test-vector",
    binding_hex="a1b2c3d4e5f60718" * 4,  # 32-byte exporter-shaped value
    host="target.example",
    port=443,
    tls_version="TLSv1.3",
    exporter_label="EXPORTER-vigil-zktls-channel-binding",
)
RESPONSE = b"HTTP/1.1 200 OK\r\n\r\n{\"balance\": 42, \"proof\": \"the-target-said-this\"}"

# --- load the STANDALONE VIGIL-free verifier by path (the option the VF spec calls out) -------------------
_PCF_DIR = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_verify_vf_z1", _PCF_DIR / "verify_vf.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VF = _load_standalone()


def _notary():
    return LocalNotary(key_id="test-notary", keypair=generate_keypair())


# ======================================= the happy path (offline, both verifiers) =========================
def test_session_bound_notary_cosigned_verifies_offline():
    n = _notary()
    ev = build_evidence(RESPONSE, BINDING, notary_keypair=n.keypair, key_id=n.key_id).to_dict()

    # in-tree verifier, pinned to the notary key → OK.
    ok, reason = verify_channel_binding_evidence(ev, notary_public_key_pin_b64=n.public_key_b64)
    assert ok, reason
    assert "MECHANISM" in reason  # honest: never claims producer-unforgeability

    # the STANDALONE VIGIL-free verifier agrees, offline, byte-identical signing bytes.
    ok_s, reason_s = VF.verify_channel_binding_evidence(ev, notary_public_key_pin_b64=n.public_key_b64)
    assert ok_s, reason_s
    assert VF.channel_bound_signing_bytes(ev["channel_bound_response"]) == \
           channel_bound_signing_bytes(ev["channel_bound_response"])

    # the carried bytes really are the ones bound (a third party recomputes the hash without the producer).
    assert hashlib.sha256(base64.b64decode(ev["response_b64"])).hexdigest() == \
           ev["channel_bound_response"]["response_sha256"]


# ======================================= producer-fabricated → REJECTED ===================================
def test_producer_fabricated_without_valid_notary_cosign_is_rejected():
    n = _notary()
    ev = build_evidence(RESPONSE, BINDING, notary_keypair=n.keypair, key_id=n.key_id).to_dict()

    # (a) NO cosign at all — a producer just asserting bytes.
    no_cosign = dict(ev)
    no_cosign["notary_cosign"] = {"notary_key_id": "x", "notary_public_key_b64": "", "signature_b64": ""}
    ok, reason = verify_channel_binding_evidence(no_cosign, notary_public_key_pin_b64=n.public_key_b64)
    assert not ok and "no notary co-signature" in reason
    assert not VF.verify_channel_binding_evidence(no_cosign, notary_public_key_pin_b64=n.public_key_b64)[0]

    # (b) a PRODUCER key self-cosigns the same (session, bytes) and asserts itself as the notary — but the
    #     verifier pins the REAL notary key, so the producer signer is rejected (not the pin).
    producer = generate_keypair()
    cbr = ChannelBoundResponse.from_dict(ev["channel_bound_response"])
    forged = dict(ev)
    forged["notary_cosign"] = notary_cosign(cbr, notary_keypair=producer, key_id="i-am-notary").to_dict()
    ok2, reason2 = verify_channel_binding_evidence(forged, notary_public_key_pin_b64=n.public_key_b64)
    assert not ok2 and "not the pinned notary key" in reason2
    assert not VF.verify_channel_binding_evidence(forged, notary_public_key_pin_b64=n.public_key_b64)[0]

    # (c) attacker sets the envelope's asserted key to the pin but signs with the producer key → sig fails.
    forged2 = dict(ev)
    cs = notary_cosign(cbr, notary_keypair=producer, key_id="spoof").to_dict()
    cs["notary_public_key_b64"] = n.public_key_b64  # claim the pin, but the signature is the producer's
    forged2["notary_cosign"] = cs
    ok3, reason3 = verify_channel_binding_evidence(forged2, notary_public_key_pin_b64=n.public_key_b64)
    assert not ok3 and "does not verify" in reason3
    assert not VF.verify_channel_binding_evidence(forged2, notary_public_key_pin_b64=n.public_key_b64)[0]


# ======================================= cosign over a DIFFERENT session/bytes → REJECTED =================
def test_cosign_over_different_session_or_bytes_is_rejected():
    n = _notary()
    ev = build_evidence(RESPONSE, BINDING, notary_keypair=n.keypair, key_id=n.key_id).to_dict()

    # (a) transplant the valid cosign onto a DIFFERENT session binding → signing bytes change → sig fails.
    other_session = dict(ev)
    other_binding = dict(ev["channel_bound_response"]["binding"], binding_hex="ffffffff" * 8)
    other_session["channel_bound_response"] = dict(ev["channel_bound_response"], binding=other_binding)
    ok, reason = verify_channel_binding_evidence(other_session, notary_public_key_pin_b64=n.public_key_b64)
    assert not ok and "does not verify" in reason
    assert not VF.verify_channel_binding_evidence(other_session, notary_public_key_pin_b64=n.public_key_b64)[0]

    # (b) swap the response bytes AND the bound hash consistently (so bytes↔hash passes) but keep the OLD
    #     cosign → the cosign was over the old hash → verify fails.
    evil_bytes = b"HTTP/1.1 200 OK\r\n\r\n{\"balance\": 999999}"
    diff_bytes = dict(ev)
    diff_bytes["response_b64"] = base64.b64encode(evil_bytes).decode("ascii")
    diff_bytes["channel_bound_response"] = dict(
        ev["channel_bound_response"], response_sha256=hashlib.sha256(evil_bytes).hexdigest())
    ok2, reason2 = verify_channel_binding_evidence(diff_bytes, notary_public_key_pin_b64=n.public_key_b64)
    assert not ok2 and "does not verify" in reason2
    assert not VF.verify_channel_binding_evidence(diff_bytes, notary_public_key_pin_b64=n.public_key_b64)[0]


def test_carried_bytes_must_match_the_bound_hash():
    n = _notary()
    ev = build_evidence(RESPONSE, BINDING, notary_keypair=n.keypair, key_id=n.key_id).to_dict()
    # tamper ONLY the carried body (leave the bound hash + cosign intact) → bytes↔hash mismatch → REJECT.
    tampered = dict(ev)
    tampered["response_b64"] = base64.b64encode(RESPONSE + b"-tampered").decode("ascii")
    ok, reason = verify_channel_binding_evidence(tampered, notary_public_key_pin_b64=n.public_key_b64)
    assert not ok and "do not hash to the bound" in reason
    assert not VF.verify_channel_binding_evidence(tampered, notary_public_key_pin_b64=n.public_key_b64)[0]


def test_wrong_notary_pin_is_rejected():
    n = _notary()
    ev = build_evidence(RESPONSE, BINDING, notary_keypair=n.keypair, key_id=n.key_id).to_dict()
    wrong = generate_keypair().public_key_b64
    ok, reason = verify_channel_binding_evidence(ev, notary_public_key_pin_b64=wrong)
    assert not ok and "not the pinned notary key" in reason
    # control: no pin at all also fails closed.
    ok2, reason2 = verify_channel_binding_evidence(ev, notary_public_key_pin_b64="")
    assert not ok2 and "no notary public-key pin" in reason2


def test_empty_or_unknown_binding_is_rejected():
    n = _notary()
    # an empty session binding is not tied to any TLS session → reject even with a valid cosign.
    empty = ChannelBinding(kind="tls-exporter", binding_hex="", host="h", port=443)
    cbr = ChannelBoundResponse(binding=empty, response_sha256=hashlib.sha256(RESPONSE).hexdigest())
    cs = notary_cosign(cbr, notary_keypair=n.keypair, key_id=n.key_id).to_dict()
    ev = {"schema": "vigil-zktls-channel-binding-v1", "channel_bound_response": cbr.to_dict(),
          "notary_cosign": cs, "response_b64": base64.b64encode(RESPONSE).decode("ascii")}
    ok, reason = verify_channel_binding_evidence(ev, notary_public_key_pin_b64=n.public_key_b64)
    assert not ok and "empty session binding" in reason


# ======================================= the exporter capture SHAPE (offline parser) ======================
def test_exporter_parser_extracts_keying_material_from_canned_output():
    canned = (
        "CONNECTED(00000003)\n"
        "---\n"
        "Protocol  : TLSv1.3\n"
        "Cipher    : TLS_AES_256_GCM_SHA384\n"
        "Keying material: 0a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
        "---\n"
    )
    assert parse_keying_material(canned) == "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    assert parse_tls_version(canned) == "TLSv1.3"
    # no exporter / odd-length hex → None (fail-closed).
    assert parse_keying_material("no exporter here") is None
    assert parse_keying_material("Keying material: abc") is None  # odd length


# ======================================= the honest residual (RemoteNotary) ===============================
def test_remote_notary_is_the_independence_path_and_is_absent_offline():
    """The genuine producer-unforgeability path is a real third-party zkTLS/MPC-TLS notary
    (:class:`RemoteNotary`). Its toolchain is ABSENT here and cannot be emulated with openssl — so calling it
    fails closed, and no test pretends a software notary establishes third-party unforgeability (the Z1
    residual, mirroring A1's RemoteTSA)."""
    remote = RemoteNotary(endpoint="mpc-tls://notary.example", notary_public_key_b64=generate_keypair().public_key_b64)
    cbr = ChannelBoundResponse(binding=BINDING, response_sha256=hashlib.sha256(RESPONSE).hexdigest())
    with pytest.raises(ChannelBindingError):
        remote.cosign(cbr)


# ======================================= bundle-level (standalone CLI shape) ==============================
def test_standalone_bundle_verifies_channel_binding_with_notary_pin():
    n = _notary()
    ev = build_evidence(RESPONSE, BINDING, notary_keypair=n.keypair, key_id=n.key_id).to_dict()
    sound, log = VF.verify_bundle({"channel_binding": ev}, notary_pin=n.public_key_b64)
    assert sound, "\n".join(log)
    # without the pin the bundle is NOT SOUND (fail-closed).
    sound2, _ = VF.verify_bundle({"channel_binding": ev}, notary_pin="")
    assert not sound2
