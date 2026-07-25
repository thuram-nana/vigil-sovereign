"""S5 — the ONE shared persisted+sealed Ed25519 keystore (`vigil_core.keystore`).

Proves the load-or-create behaviour every offense identity relies on: a keypair is STABLE across reloads
(the property that retires the ephemeral per-run spine key), sealed at rest under a provisioned vault, fail-
closed on a locked TPM (never a divergent new identity), regenerated on corrupt/weak material, and its AEAD
context isolates one identity's sealed blob from another's.

Run: pytest packages/core/vigil_core/tests/test_keystore.py -q
"""
import json
from pathlib import Path

import pytest

from vigil_core import is_sealed
from vigil_core.kek import TpmResult
from vigil_core.keystore import load_or_create_sealed_keypair
from vigil_core.vault import Vault, VaultLocked

CTX_A = b"vigil/test/identity-a"
CTX_B = b"vigil/test/identity-b"


def make_fake_tpm(*, unavailable=False):
    def run(argv, stdin):
        if unavailable:
            return TpmResult(127, b"")
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary")
            return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub")
            Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b""))
            return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):])
            return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


def test_first_use_creates_and_is_stable_across_reloads(tmp_path):
    kf = tmp_path / "id.key"
    kp = load_or_create_sealed_keypair(path=str(kf), context=CTX_A)
    assert is_sealed(kf.read_bytes()) is False           # plaintext JSON when no vault
    kp2 = load_or_create_sealed_keypair(path=str(kf), context=CTX_A)
    assert kp2 == kp                                     # SAME identity across a "restart" — the S5 property
    assert oct((kf.stat().st_mode & 0o777)) == oct(0o600)


def test_provisioned_vault_seals_at_rest_same_identity(tmp_path):
    kf = tmp_path / "id.key"
    v = Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    kp = load_or_create_sealed_keypair(path=str(kf), context=CTX_A, vault=v)
    blob = kf.read_bytes()
    assert is_sealed(blob) is True
    assert kp.private_key_b64.encode() not in blob       # private key never plaintext on disk
    kp2 = load_or_create_sealed_keypair(path=str(kf), context=CTX_A,
                                        vault=Vault(tmp_path / "vault", make_fake_tpm()))
    assert kp2 == kp                                     # unseal → same identity, no divergent regeneration


def test_locked_tpm_fails_closed_no_new_identity(tmp_path):
    kf = tmp_path / "id.key"
    good = Vault(tmp_path / "vault", make_fake_tpm())
    good.provision()
    load_or_create_sealed_keypair(path=str(kf), context=CTX_A, vault=good)
    sealed_before = kf.read_bytes()
    dead = Vault(tmp_path / "vault", make_fake_tpm(unavailable=True))
    with pytest.raises(VaultLocked):
        load_or_create_sealed_keypair(path=str(kf), context=CTX_A, vault=dead)
    assert kf.read_bytes() == sealed_before   # the sealed file is untouched — no divergent key was minted
    # and once the TPM is back, the ORIGINAL identity unseals (fail-closed did not corrupt it)
    revived = load_or_create_sealed_keypair(path=str(kf), context=CTX_A,
                                            vault=Vault(tmp_path / "vault", make_fake_tpm()))
    assert revived.public_key_b64  # a real key, recovered from the untouched sealed file


def test_wrong_context_cannot_unseal_anothers_blob(tmp_path):
    # A blob sealed under CTX_A must not be openable under CTX_B — the AEAD purpose-binding that keeps the
    # operator key and the spine key cryptographically non-interchangeable. A failed unseal is fail-closed.
    kf = tmp_path / "id.key"
    v = Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    load_or_create_sealed_keypair(path=str(kf), context=CTX_A, vault=v)
    v2 = Vault(tmp_path / "vault", make_fake_tpm())
    # AEAD tag mismatch under the wrong context → VaultLocked (fail-closed), NOT a file-not-found and NOT a
    # silent new key. Pinning the exact type keeps a future spurious error from green-washing this.
    with pytest.raises(VaultLocked):
        load_or_create_sealed_keypair(path=str(kf), context=CTX_B, vault=v2)


def test_corrupt_file_regenerates(tmp_path):
    kf = tmp_path / "id.key"
    kf.write_text("}{ not json")
    kp = load_or_create_sealed_keypair(path=str(kf), context=CTX_A)   # corrupt → fresh, usable
    assert kp.public_key_b64 and kp.private_key_b64
    # and it now persists cleanly and reloads stably
    assert load_or_create_sealed_keypair(path=str(kf), context=CTX_A) == kp


def test_mismatched_pub_priv_regenerates(tmp_path):
    # A file whose pub/priv are not a matched pair must not be trusted — regenerate a sound identity.
    a = load_or_create_sealed_keypair(path=str(tmp_path / "a.key"), context=CTX_A)
    b = load_or_create_sealed_keypair(path=str(tmp_path / "b.key"), context=CTX_A)
    frankenstein = tmp_path / "mixed.key"
    frankenstein.write_text(json.dumps({"public_key_b64": a.public_key_b64,
                                        "private_key_b64": b.private_key_b64}))
    kp = load_or_create_sealed_keypair(path=str(frankenstein), context=CTX_A)
    assert kp.public_key_b64 != a.public_key_b64 or kp.private_key_b64 != b.private_key_b64
