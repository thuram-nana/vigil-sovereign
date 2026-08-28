"""Slice 1c-iii — WebAuthn assertion verification (synthetic authenticator) + the owner passkey store.

A synthetic ES256/Ed25519 authenticator produces a real assertion; verify_assertion must ACCEPT the genuine
one and REFUSE every tamper (wrong challenge/origin/type/rpId, signCount regression, tampered authData/sig,
wrong key). The store must round-trip owner-signed credentials and fail CLOSED on a tampered/wrong-key file.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from sigil.ui import webauthn as wa

RP_ID = "127.0.0.1"
ORIGIN = "http://127.0.0.1:8770"


def _spki(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _client_data(challenge: str, *, typ="webauthn.get", origin=ORIGIN) -> bytes:
    cd = {"type": typ,
          "challenge": base64.urlsafe_b64encode(challenge.encode()).rstrip(b"=").decode("ascii"),
          "origin": origin}
    return json.dumps(cd).encode("utf-8")


def _authdata(*, rp_id=RP_ID, up=True, uv=False, sign_count=1) -> bytes:
    flags = (0x01 if up else 0x00) | (0x04 if uv else 0x00)
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", sign_count)


def _assert(key, *, challenge, alg="es256", rp_id=RP_ID, origin=ORIGIN, up=True, uv=False, sign_count=1,
            typ="webauthn.get"):
    client_data = _client_data(challenge, typ=typ, origin=origin)
    authdata = _authdata(rp_id=rp_id, up=up, uv=uv, sign_count=sign_count)
    message = authdata + hashlib.sha256(client_data).digest()
    sig = key.sign(message, ec.ECDSA(hashes.SHA256())) if alg == "es256" else key.sign(message)
    return authdata, client_data, sig


def _es_kwargs(key, authdata, client_data, sig, *, challenge, stored=0):
    return dict(spki_der=_spki(key.public_key()), cose_alg=wa.COSE_ES256, authenticator_data=authdata,
                client_data_json=client_data, signature=sig, expected_challenge=challenge,
                allowed_origins=[ORIGIN], rp_id=RP_ID, stored_sign_count=stored)


# --- happy paths -----------------------------------------------------------------

def test_es256_assertion_verifies():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "server-challenge-nonce-xyz"
    ad, cd, sig = _assert(key, challenge=ch, sign_count=5)
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge=ch, stored=0))
    assert r.ok and r.sign_count == 5


def test_ed25519_assertion_verifies():
    key = ed25519.Ed25519PrivateKey.generate()
    ch = "ed-challenge-nonce-abc"
    ad, cd, sig = _assert(key, challenge=ch, alg="ed25519", sign_count=1)
    r = wa.verify_assertion(spki_der=_spki(key.public_key()), cose_alg=wa.COSE_EDDSA, authenticator_data=ad,
                            client_data_json=cd, signature=sig, expected_challenge=ch,
                            allowed_origins=[ORIGIN], rp_id=RP_ID, stored_sign_count=0)
    assert r.ok


# --- every tamper is refused (fail-closed) ---------------------------------------

def test_wrong_challenge_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    ad, cd, sig = _assert(key, challenge="the-real-challenge")
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge="a-different-challenge"))
    assert not r.ok and r.reason == "challenge"


def test_wrong_origin_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "ch1"
    ad, cd, sig = _assert(key, challenge=ch, origin="https://evil.example.com")
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge=ch))
    assert not r.ok and r.reason == "origin"


def test_wrong_type_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "ch2"
    ad, cd, sig = _assert(key, challenge=ch, typ="webauthn.create")
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge=ch))
    assert not r.ok and r.reason == "type"


def test_wrong_rp_id_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "ch3"
    ad, cd, sig = _assert(key, challenge=ch, rp_id="attacker.example.com")
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge=ch))
    assert not r.ok and r.reason == "rp_id"


def test_signcount_regression_is_clone_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "ch4"
    ad, cd, sig = _assert(key, challenge=ch, sign_count=5)
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge=ch, stored=5))   # new(5) <= stored(5)
    assert not r.ok and r.reason == "signcount"


def test_signcount_zero_zero_accepted_noncounting_authenticator():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "ch5"
    ad, cd, sig = _assert(key, challenge=ch, sign_count=0)
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge=ch, stored=0))
    assert r.ok


def test_user_presence_required():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "ch6"
    ad, cd, sig = _assert(key, challenge=ch, up=False)
    r = wa.verify_assertion(**_es_kwargs(key, ad, cd, sig, challenge=ch))
    assert not r.ok and r.reason == "user_presence"


def test_tampered_authdata_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    ch = "ch7"
    ad, cd, sig = _assert(key, challenge=ch, sign_count=3)
    tampered = bytearray(ad); tampered[36] ^= 0xFF          # flip a signCount byte after signing
    r = wa.verify_assertion(**_es_kwargs(key, bytes(tampered), cd, sig, challenge=ch, stored=0))
    assert not r.ok and r.reason == "signature"


def test_wrong_key_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    ch = "ch8"
    ad, cd, sig = _assert(key, challenge=ch)
    # verify against a DIFFERENT public key → signature fails
    r = wa.verify_assertion(spki_der=_spki(other.public_key()), cose_alg=wa.COSE_ES256,
                            authenticator_data=ad, client_data_json=cd, signature=sig,
                            expected_challenge=ch, allowed_origins=[ORIGIN], rp_id=RP_ID, stored_sign_count=0)
    assert not r.ok and r.reason == "signature"


def test_short_authenticator_data_is_none():
    assert wa.parse_authenticator_data(b"\x00" * 36) is None
    assert wa.parse_authenticator_data(b"") is None


def test_registration_clientdata_validates():
    ch = "reg-challenge"
    assert wa.verify_registration(client_data_json=_client_data(ch, typ="webauthn.create"),
                                  expected_challenge=ch, allowed_origins=[ORIGIN]) is None
    assert wa.verify_registration(client_data_json=_client_data(ch, typ="webauthn.get"),
                                  expected_challenge=ch, allowed_origins=[ORIGIN]) == "type"
    assert wa.verify_registration(client_data_json=_client_data("wrong", typ="webauthn.create"),
                                  expected_challenge=ch, allowed_origins=[ORIGIN]) == "challenge"


# --- the owner passkey store (owner-signed, tamper-evident) ----------------------

def _store(tmp, owner):
    from sigil.ui.webauthn_store import WebAuthnStore
    return WebAuthnStore(path=Path(tmp) / ".vigil-live" / "wa.json",
                         owner_key=owner, trusted_pubkey=owner.public_key_b64)


def test_store_register_get_and_signcount_and_revoke():
    from sigil.reuse import generate_keypair
    import os
    import stat
    owner = generate_keypair()
    tmp = tempfile.mkdtemp()
    st = _store(tmp, owner)
    st.register(credential_id="credA", cose_alg=wa.COSE_ES256, public_key_spki_b64="c3BraQ==", uv=False)
    c = st.get("credA")
    assert c and c["cose_alg"] == wa.COSE_ES256 and c["sign_count"] == 0
    assert stat.S_IMODE(os.stat(st.path).st_mode) == 0o600
    st.update_sign_count("credA", 7)
    assert st.get("credA")["sign_count"] == 7
    assert st.revoke("credA") is True and st.get("credA") is None
    st.register(credential_id="c1", cose_alg=wa.COSE_ES256, public_key_spki_b64="a", uv=False)
    st.register(credential_id="c2", cose_alg=wa.COSE_ES256, public_key_spki_b64="b", uv=False)
    assert st.revoke_all() == 2 and st.credentials() == []


def test_store_fails_closed_on_a_tampered_file():
    from sigil.reuse import generate_keypair
    owner = generate_keypair()
    tmp = tempfile.mkdtemp()
    st = _store(tmp, owner)
    st.register(credential_id="credA", cose_alg=wa.COSE_ES256, public_key_spki_b64="c3BraQ==", uv=False)
    # tamper: inject a second credential without re-signing → the owner signature no longer covers it
    payload = json.loads(st.path.read_text(encoding="utf-8"))
    payload["credentials"].append({"credential_id": "evil", "cose_alg": -7,
                                   "public_key_spki_b64": "evil", "sign_count": 0, "uv": False})
    st.path.write_text(json.dumps(payload), encoding="utf-8")
    assert st.credentials() == [], "a tampered (re-signed by nobody) file must yield NO credentials"
    # a file signed by a DIFFERENT key is also rejected
    attacker = generate_keypair()
    st2 = _store(tmp, attacker)                              # attacker owns the write key here
    st2.register(credential_id="mallory", cose_alg=wa.COSE_ES256, public_key_spki_b64="m", uv=False)
    assert _store(tmp, owner).credentials() == [], "a file signed by a non-owner key must be rejected"
