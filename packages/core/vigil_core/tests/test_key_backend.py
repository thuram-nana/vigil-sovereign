"""Tests for vigil_core.key_backend — the pluggable OWNER-key signing backend (W9-6, issue #439).

Proves the acceptance bar for a hardware-held owner key, all WITHOUT any real token (the falsifiable core):

  * POSITIVE — the FILE backend still works and is byte-identical to the pre-W9-6 owner-signing path, so
    nothing deployed breaks (``file`` is the default).
  * NEGATIVE CONTROL — a HARDWARE backend selected while its token / module is ABSENT FAILS CLOSED
    (raises ``HardwareKeyUnavailable``); it NEVER silently falls back to a file key, even when a perfectly
    good file key is supplied. An unknown backend name is likewise fail-closed, never a default-to-file.
  * NO-PRIVATE-MATERIAL — on the hardware path the private scalar never enters the process: signing runs on
    the (faked) token, ``vigil_core.crypto.sign`` / ``Ed25519PrivateKey.from_private_bytes`` are never
    called, and the produced signature verifies under the TOKEN key, not the file key.

The real PKCS#11 opener (``open_pkcs11_signer``) needs a physical token and is the irreducible residual —
exercised only by the env-gated ``test_key_backend_live_token.py`` (SKIPPED here), never in CI.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import vigil_core.crypto as ccrypto
from vigil_core import generate_keypair, sign, verify_one
from vigil_core.key_backend import (
    BACKEND_ENV,
    FileBackend,
    HardwareKeyUnavailable,
    KeyBackendError,
    Pkcs11Backend,
    Pkcs11Config,
    describe_owner_backend,
    select_owner_backend,
)


# --------------------------------------------------------------------------------------------------
# A fake token: models a PKCS#11 device that holds the private key INTERNALLY. The backend only ever
# calls .sign()/.public_key_raw(); it never sees the scalar. The Ed25519 key object is built ONCE at
# construction so the fake still works after we forbid in-process private-key handling below.
# --------------------------------------------------------------------------------------------------
class _FakeToken:
    def __init__(self, kp) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(kp.private_key_b64))
        self._pub_raw = base64.b64decode(kp.public_key_b64)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)  # "on the token" — an instance op, not crypto.sign/from_private_bytes

    def public_key_raw(self) -> bytes:
        return self._pub_raw


def _hw_env(module: str = "/opt/pkcs11/provider.so") -> dict:
    return {BACKEND_ENV: "pkcs11", "VIGIL_PKCS11_MODULE": module, "VIGIL_PKCS11_KEY_LABEL": "owner"}


# --------------------------------------------------------------------------------------------------
# POSITIVE — the file backend is unchanged behaviour.
# --------------------------------------------------------------------------------------------------
def test_file_backend_is_byte_identical_to_the_legacy_owner_signing_path():
    kp = generate_keypair()
    b = FileBackend(kp.private_key_b64)
    msg = b"owner authorizes this exact action"
    assert b.sign(msg) == sign(kp.private_key_b64, msg)  # identical to pre-W9-6 signing
    assert b.public_key_b64 == kp.public_key_b64
    assert b.name == "file" and b.holds_private_material is True


def test_default_and_explicit_file_select_the_file_backend():
    kp = generate_keypair()
    for env in ({}, {BACKEND_ENV: "file"}, {BACKEND_ENV: "FILE"}):
        b = select_owner_backend(env=env, file_private_key_b64=kp.private_key_b64)
        assert isinstance(b, FileBackend) and b.public_key_b64 == kp.public_key_b64


def test_file_backend_without_a_key_is_fail_closed():
    with pytest.raises(KeyBackendError):
        select_owner_backend(env={}, file_private_key_b64=None)
    with pytest.raises(KeyBackendError):
        FileBackend("")


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL — hardware selected but absent must FAIL CLOSED, never fall back to a file key.
# --------------------------------------------------------------------------------------------------
def test_hardware_selected_but_token_absent_fails_closed_never_uses_file_key():
    kp = generate_keypair()  # a perfectly usable FILE key is available...

    def absent_opener(config: Pkcs11Config):
        raise RuntimeError("no PKCS#11 token present")  # ...but the token is absent

    with pytest.raises(HardwareKeyUnavailable):
        # ...and it is supplied. The selector must STILL refuse — no fallback to the file key.
        select_owner_backend(env=_hw_env(), file_private_key_b64=kp.private_key_b64, opener=absent_opener)


def test_hardware_selected_without_a_module_configured_fails_closed_before_opening():
    kp = generate_keypair()
    called = {"n": 0}

    def opener(config):
        called["n"] += 1
        return _FakeToken(kp)

    # No VIGIL_PKCS11_MODULE → refuse without even calling the opener (fail-closed, no file fallback).
    with pytest.raises(HardwareKeyUnavailable):
        select_owner_backend(env={BACKEND_ENV: "pkcs11"}, file_private_key_b64=kp.private_key_b64,
                             opener=opener)
    assert called["n"] == 0


def test_opener_returning_none_is_fail_closed():
    kp = generate_keypair()
    with pytest.raises(HardwareKeyUnavailable):
        select_owner_backend(env=_hw_env(), file_private_key_b64=kp.private_key_b64,
                             opener=lambda c: None)


def test_unknown_backend_name_is_fail_closed_not_file():
    kp = generate_keypair()
    with pytest.raises(KeyBackendError):
        select_owner_backend(env={BACKEND_ENV: "magic-cloud-kms"},
                             file_private_key_b64=kp.private_key_b64)


def test_malformed_token_signature_or_pubkey_fails_closed():
    class _BadSig:
        def sign(self, message: bytes) -> bytes:
            return b"\x00" * 63  # not 64 bytes

        def public_key_raw(self) -> bytes:
            return b"\x00" * 32

    class _BadPub:
        def sign(self, message: bytes) -> bytes:
            return b"\x00" * 64

        def public_key_raw(self) -> bytes:
            return b"\x00" * 31  # not 32 bytes

    with pytest.raises(HardwareKeyUnavailable):
        Pkcs11Backend(_BadSig()).sign(b"m")
    with pytest.raises(HardwareKeyUnavailable):
        _ = Pkcs11Backend(_BadPub()).public_key_b64


# --------------------------------------------------------------------------------------------------
# NO-PRIVATE-MATERIAL — the hardware path never reads the owner private key into the process.
# --------------------------------------------------------------------------------------------------
def test_hardware_path_never_reads_private_material_into_the_process(monkeypatch):
    token_kp = generate_keypair()
    token = _FakeToken(token_kp)  # the Ed25519 key object is captured HERE, before we forbid in-proc use
    backend = Pkcs11Backend(token, key_label="owner", module_path="/opt/pkcs11/provider.so")

    # Now forbid ANY in-process private-key handling. If the backend/sign path touched the private scalar
    # it would go through one of these and blow up — proving it does NOT.
    def _forbidden(*_a, **_k):
        raise AssertionError("in-process private-key handling on the hardware path")

    monkeypatch.setattr(ccrypto, "sign", _forbidden)
    monkeypatch.setattr(Ed25519PrivateKey, "from_private_bytes", staticmethod(_forbidden))

    msg = b"owner authorizes this action on the token"
    sig_b64 = backend.sign(msg)
    # the signature verifies under the TOKEN public key (verify uses only the public key)
    assert verify_one(token_kp.public_key_b64, msg, sig_b64)
    # the backend object holds no 32-byte private scalar anywhere in its state
    assert not any(isinstance(v, (bytes, bytearray)) and len(v) == 32 for v in vars(backend).values())
    assert backend.name == "pkcs11" and backend.holds_private_material is False


def test_hardware_backend_signs_with_the_token_key_not_the_supplied_file_key():
    token_kp = generate_keypair()
    file_kp = generate_keypair()
    backend = select_owner_backend(
        env=_hw_env(), file_private_key_b64=file_kp.private_key_b64,
        opener=lambda c: _FakeToken(token_kp),
    )
    assert isinstance(backend, Pkcs11Backend)
    msg = b"m"
    sig = backend.sign(msg)
    assert verify_one(token_kp.public_key_b64, msg, sig)        # the TOKEN key signed
    assert not verify_one(file_kp.public_key_b64, msg, sig)     # the file key did NOT (no fallback)
    assert backend.public_key_b64 == token_kp.public_key_b64


def test_opener_receives_the_env_config():
    kp = generate_keypair()
    seen: dict = {}

    def opener(config: Pkcs11Config):
        seen["cfg"] = config
        return _FakeToken(kp)

    env = {BACKEND_ENV: "hsm", "VIGIL_PKCS11_MODULE": "/x/pkcs11.so",
           "VIGIL_PKCS11_TOKEN_LABEL": "vigil-token", "VIGIL_PKCS11_KEY_LABEL": "owner",
           "VIGIL_PKCS11_PIN": "1234"}
    select_owner_backend(env=env, file_private_key_b64=kp.private_key_b64, opener=opener)
    cfg = seen["cfg"]
    assert cfg.module_path == "/x/pkcs11.so" and cfg.token_label == "vigil-token"
    assert cfg.key_label == "owner" and cfg.pin == "1234" and cfg.kind == "hsm"


# --------------------------------------------------------------------------------------------------
# doctor description — the active backend is reportable (read-only; no token open).
# --------------------------------------------------------------------------------------------------
def test_describe_owner_backend_reports_each_state(tmp_path):
    assert describe_owner_backend({})[0] == "FILE"
    assert describe_owner_backend({BACKEND_ENV: "file"})[0] == "FILE"
    assert describe_owner_backend({BACKEND_ENV: "pkcs11"})[0] == "PKCS11-UNCONFIGURED"
    assert describe_owner_backend(
        {BACKEND_ENV: "pkcs11", "VIGIL_PKCS11_MODULE": str(tmp_path / "nope.so")}
    )[0] == "PKCS11-MISSING-MODULE"
    module = tmp_path / "provider.so"
    module.write_bytes(b"\x7fELF stub")
    state, detail = describe_owner_backend({BACKEND_ENV: "pkcs11", "VIGIL_PKCS11_MODULE": str(module)})
    assert state == "PKCS11" and "never enters the process" in detail
    assert describe_owner_backend({BACKEND_ENV: "weird"})[0] == "UNKNOWN"


# --------------------------------------------------------------------------------------------------
# defensive branches
# --------------------------------------------------------------------------------------------------
def test_pkcs11_backend_requires_an_opened_signer():
    with pytest.raises(HardwareKeyUnavailable):
        Pkcs11Backend(None)  # type: ignore[arg-type]


def test_backend_describe_strings():
    kp = generate_keypair()
    assert FileBackend(kp.private_key_b64).describe() == "file"
    hw = Pkcs11Backend(_FakeToken(generate_keypair()), key_label="owner", module_path="/x.so")
    assert "pkcs11" in hw.describe() and "owner" in hw.describe()


def test_opener_raising_hardware_unavailable_propagates_unchanged():
    def opener(config: Pkcs11Config):
        raise HardwareKeyUnavailable("token yanked mid-open")

    with pytest.raises(HardwareKeyUnavailable, match="token yanked"):
        select_owner_backend(env=_hw_env(), file_private_key_b64=generate_keypair().private_key_b64,
                             opener=opener)


def test_file_backend_public_key_from_malformed_key_is_fail_closed():
    with pytest.raises(KeyBackendError):
        _ = FileBackend("not-valid-base64!!!").public_key_b64  # not base64
    short = base64.b64encode(b"0123456789").decode("ascii")  # valid base64, wrong length
    with pytest.raises(KeyBackendError):
        _ = FileBackend(short).public_key_b64
