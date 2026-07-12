"""
Workstream-B — the SSO/JWT structural-forgery oracle (a captured JWT -> STRUCTURALLY-FORGEABLE FACT).

A captured JWT is only a LEAD until a deterministic oracle proves it forgeable from the token ALONE,
offline, with ZERO forged traffic. The jwt-forgery oracle promotes it to a FACT ONLY on a re-runnable
proof: ``alg=none``/``None``, an HS* signature RECOMPUTABLE from a supplied/weak candidate key, or an
RS256->HS256 confusion (the HS* signature verifies with a supplied RSA public key as the HMAC secret).
A normal RS256 token with an unknown key, an HS* token whose secret is not recoverable, and a malformed
token all correctly do NOT fire — near-zero false positives. The confirmed fact re-verifies offline
from its retained context.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from framework.v2.verify import confirm_jwt_forgery, jwt_forgery_context, jwt_forgery_oracle
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier


# ---------------------------------------------------------------------------
# token minting helpers (stdlib codec, matching scanner.jwt byte-for-byte)
# ---------------------------------------------------------------------------


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _seg(obj: dict) -> str:
    return _b64(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _hs(payload: dict, secret, *, alg: str = "HS256", hasher=hashlib.sha256) -> str:
    header = _seg({"alg": alg, "typ": "JWT"})
    body = _seg(payload)
    signing_input = f"{header}.{body}".encode("ascii")
    sec = secret if isinstance(secret, bytes) else secret.encode("utf-8")
    return f"{header}.{body}." + _b64(hmac.new(sec, signing_input, hasher).digest())


def _none(payload: dict, *, alg: str = "none") -> str:
    return f"{_seg({'alg': alg, 'typ': 'JWT'})}.{_seg(payload)}."


def _rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    return priv, pub_pem


def _rs256(payload: dict, priv) -> str:
    header = _seg({"alg": "RS256", "typ": "JWT"})
    body = _seg(payload)
    sig = priv.sign(f"{header}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}." + _b64(sig)


# ---------------------------------------------------------------------------
# the oracle FIRES only on a re-runnable structural-forgery proof
# ---------------------------------------------------------------------------


def test_fires_on_alg_none() -> None:
    sig = jwt_forgery_oracle(_none({"sub": "admin", "role": "superuser"}))
    assert sig.fired and sig.kind is OracleKind.SSO_ASSERTION_FORGERY
    assert sig.confidence >= 0.7
    assert sig.observed["proof"] == "alg_none"


def test_fires_on_alg_none_case_variants() -> None:
    # the classic bypass variants (None / NONE / nOnE) all normalise to the same proof
    for variant in ("None", "NONE", "nOnE", "none"):
        assert jwt_forgery_oracle(_none({"sub": "x"}, alg=variant)).fired


def test_fires_on_hs256_recomputable_from_supplied_candidate() -> None:
    tok = _hs({"sub": "admin"}, "hunter2")
    # the true secret is in the candidate list alongside a decoy -> exact HMAC reproduces
    sig = jwt_forgery_oracle(tok, candidate_keys=["not-it", "hunter2", "also-wrong"])
    assert sig.fired
    assert sig.observed["proof"] == "hs256_weak_key"
    assert sig.observed["recovered_key"] == "hunter2"


def test_fires_on_hs256_builtin_weak_secret_without_candidates() -> None:
    # a notorious default secret is recovered even when the caller supplies NO candidates
    sig = jwt_forgery_oracle(_hs({"sub": "admin"}, "secret"))
    assert sig.fired and sig.observed["recovered_key"] == "secret"


def test_fires_on_hs384_and_hs512() -> None:
    assert jwt_forgery_oracle(_hs({"sub": "a"}, "secret", alg="HS384", hasher=hashlib.sha384)).fired
    assert jwt_forgery_oracle(_hs({"sub": "a"}, "secret", alg="HS512", hasher=hashlib.sha512)).fired


def test_fires_on_rs256_hs256_algorithm_confusion() -> None:
    # attacker re-signs an HS256 token using the RSA PUBLIC key (PEM) as the HMAC secret; given that
    # public key as a candidate, the oracle proves the confusion. Public material => anyone forges.
    _priv, pub_pem = _rsa_keypair()
    confused = _hs({"sub": "admin", "role": "admin"}, pub_pem)  # header says HS256, secret == pubkey
    sig = jwt_forgery_oracle(confused, candidate_keys=[pub_pem])
    assert sig.fired
    assert sig.observed["proof"] == "rs256_hs256_confusion"
    assert sig.observed["hmac_key_is_public_key"] is True
    assert sig.confidence >= 0.9


# ---------------------------------------------------------------------------
# the oracle does NOT fire (near-zero-FP) on an unprovable token
# ---------------------------------------------------------------------------


def test_does_not_fire_on_proper_rs256_with_unknown_key() -> None:
    priv, _pub = _rsa_keypair()
    sig = jwt_forgery_oracle(_rs256({"sub": "admin"}, priv))
    assert not sig.fired
    assert sig.observed["alg"] == "RS256"


def test_does_not_fire_on_proper_rs256_even_when_pubkey_is_a_candidate() -> None:
    # the KEY distinction from the confusion case: a genuinely RS256-signed token carries an RSA
    # signature (never an HMAC), so offering the public key as a candidate cannot reproduce it.
    priv, pub_pem = _rsa_keypair()
    assert not jwt_forgery_oracle(_rs256({"sub": "admin"}, priv), candidate_keys=[pub_pem]).fired


def test_does_not_fire_on_hs256_with_secret_outside_candidate_set() -> None:
    strong = base64.b64encode(os.urandom(32)).decode("ascii")
    tok = _hs({"sub": "admin"}, strong)
    assert not jwt_forgery_oracle(tok, candidate_keys=["wrong-1", "wrong-2"]).fired


def test_does_not_fire_on_strong_random_hs256_key_with_no_candidates() -> None:
    strong = base64.b64encode(os.urandom(48)).decode("ascii")
    assert not jwt_forgery_oracle(_hs({"sub": "admin"}, strong)).fired


def test_does_not_fire_on_malformed_or_garbage() -> None:
    for junk in (None, "", "a.b", "not-a-jwt", "a.b.c.d", 123, [], {}, "..", "x..y"):
        assert not jwt_forgery_oracle(junk).fired


# ---------------------------------------------------------------------------
# routing + the FROZEN-fallback invariant (gate safety)
# ---------------------------------------------------------------------------


def test_routes_via_verifier_and_kind_is_out_of_the_frozen_fallback() -> None:
    v = OracleVerifier()
    assert v.oracles_for("jwt_forgeable") == (OracleKind.SSO_ASSERTION_FORGERY,)
    assert v.oracles_for("jwt_forgery") == (OracleKind.SSO_ASSERTION_FORGERY,)          # alias folds
    assert v.oracles_for("jwt_algorithm_confusion") == (OracleKind.SSO_ASSERTION_FORGERY,)
    # the NEW kind is reachable ONLY via its explicit row — never the unknown-class fallback
    assert OracleKind.SSO_ASSERTION_FORGERY not in _ALL_ORACLES
    assert OracleKind.SSO_ASSERTION_FORGERY not in v.oracles_for("some_unknown_class")


def test_all_oracles_frozen_fallback_stays_fifteen() -> None:
    # the gate-safety invariant: the frozen unknown-class fallback is EXACTLY the pre-AEGIS 15.
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.SSO_ASSERTION_FORGERY not in _ALL_ORACLES


def test_existing_jwt_class_is_not_repointed() -> None:
    # the live alg:none-ACCEPTANCE 'jwt' class must stay on ACHIEVED_STATE (additive-only doctrine).
    assert OracleVerifier().oracles_for("jwt") == (OracleKind.ACHIEVED_STATE,)


# ---------------------------------------------------------------------------
# confirmation via the seam + the verifier
# ---------------------------------------------------------------------------


def test_confirm_via_seam_and_verifier() -> None:
    none_tok = _none({"sub": "admin"})
    assert confirm_jwt_forgery(none_tok).confirmed
    assert OracleVerifier().confirm(jwt_forgery_context(none_tok)).confirmed

    weak_tok = _hs({"sub": "admin"}, "hunter2")
    assert confirm_jwt_forgery(weak_tok, ["hunter2"]).confirmed

    # a strong random HS256 key is NOT confirmed (stays an honest LEAD)
    strong = base64.b64encode(os.urandom(32)).decode("ascii")
    assert not confirm_jwt_forgery(_hs({"sub": "admin"}, strong), ["wrong"]).confirmed


# ---------------------------------------------------------------------------
# offline re-verification (prove-don't-guess) + adapter retention
# ---------------------------------------------------------------------------


def test_confirmed_forgery_reverifies_offline_from_its_retained_context() -> None:
    _priv, pub_pem = _rsa_keypair()
    confused = _hs({"sub": "admin"}, pub_pem)
    oracle_context = jwt_forgery_context(confused, [pub_pem])
    # no target, no forged traffic — re-run the pure oracle over the retained token + candidate keys
    r = reverify_context(oracle_context, bug_class="jwt_forgeable")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.SSO_ASSERTION_FORGERY.value


def test_adapter_builder_emits_token_and_candidate_keys() -> None:
    ctx = FindingContext.from_jwt_token("h.p.s", candidate_keys=["k1", b"k2"])
    emitted = ctx.to_verifier_context()
    assert emitted["bug_class"] == "jwt_forgeable"
    assert emitted["jwt_token"] == "h.p.s"
    assert emitted["jwt_candidate_keys"] == ["k1", "k2"]        # bytes coerced to text


def test_adapter_builder_omits_candidate_keys_when_none_supplied() -> None:
    emitted = FindingContext.from_jwt_token(_none({"sub": "x"})).to_verifier_context()
    assert "jwt_token" in emitted
    # no candidate keys -> the key is omitted (the oracle still tries its weak-secret baseline)
    assert "jwt_candidate_keys" not in emitted
