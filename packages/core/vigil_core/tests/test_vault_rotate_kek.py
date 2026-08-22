"""Tests for Vault.rotate_kek + binary-secret sealing — KEK rotation, verify-then-swap, fail-closed (W9-2).

The TPM is a fake keyring stub (the injectable runner seam), so the seal/unseal legs run deterministically;
the LIVE tpm2 path activates on a provisioned host. Proves:
  * after rotation every secret (owner key, spine DEK, WARDEN key) still reads — under the NEW KEK — and
    the OLD KEK no longer decrypts (the acceptance-criteria negative control);
  * a re-wrap that cannot be proven rolls the WHOLE rotation back: originals stay under the old KEK, no
    staged artifacts remain (fail-closed — never a half-rotated key);
  * the crash-window prev-fallback: a file momentarily still under the old KEK during a commit is still
    readable via the `.prev` KEK;
  * the WARDEN kernel key (raw bytes) seals at rest via seal_file + read_bytes_secret.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_core.kek import (
    _SEAL_PRIV, _SEAL_PUB, TpmResult, load_kek, reseal_kek,
)
from vigil_core.rotation import RotationError
from vigil_core.sealing import is_sealed, unseal
from vigil_core.vault import Vault, VaultLocked


def make_fake_tpm(*, unavailable=False):
    """Fake tpm2-tools: seal encodes the KEK into the private blob; unseal returns it (see test_kek)."""
    def run(argv, stdin):
        if unavailable:
            return TpmResult(127, b"")
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary"); return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub")
            Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b"")); return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):]); return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


OWNER_CTX = b"sigil/owner.priv"
DEK_CTX = b"sigil/spine.dek"
WARDEN_CTX = b"sigil/warden.key"


def _provisioned(tmp_path, **kw):
    v = Vault(tmp_path / "vault", make_fake_tpm(**kw))
    v.provision()
    return v


def test_rotate_kek_new_reads_old_no_longer_decrypts(tmp_path):
    v = _provisioned(tmp_path)
    owner = tmp_path / "owner.priv"
    dek = tmp_path / "spine.dek"
    warden = tmp_path / "warden.key"
    v.write_text_secret(owner, "OWNER-PRIV-B64", context=OWNER_CTX)
    v.write_text_secret(dek, "DEK-B64", context=DEK_CTX)
    v.write_bytes_secret(warden, b"WARDEN-32-BYTE-ED25519-SEED-!!!!", context=WARDEN_CTX)

    old_kek = load_kek(tmp_path / "vault", runner=make_fake_tpm())

    res = v.rotate_kek([(owner, OWNER_CTX), (dek, DEK_CTX), (warden, WARDEN_CTX)], embedded_secrets=[])
    assert res["rotated"] == 3

    # A fresh vault instance (no cache) reads every secret — under the NEW KEK — to the exact original.
    v2 = Vault(tmp_path / "vault", make_fake_tpm())
    assert v2.read_text_secret(owner, context=OWNER_CTX) == "OWNER-PRIV-B64"
    assert v2.read_text_secret(dek, context=DEK_CTX) == "DEK-B64"
    assert v2.read_bytes_secret(warden, context=WARDEN_CTX) == b"WARDEN-32-BYTE-ED25519-SEED-!!!!"

    # the active KEK actually changed, and the OLD KEK no longer decrypts a re-wrapped file.
    new_kek_bytes = load_kek(tmp_path / "vault", runner=make_fake_tpm())
    assert new_kek_bytes != old_kek
    with pytest.raises(Exception):
        unseal(old_kek, owner.read_bytes(), context=OWNER_CTX)
    # and no staged/prev artifacts survive a clean rotation.
    assert not (tmp_path / "vault" / (_SEAL_PUB + ".prev")).exists()
    assert not (tmp_path / "vault" / (_SEAL_PUB + ".rot")).exists()
    assert not owner.with_name(owner.name + ".rot").exists()


def test_rotate_kek_rolls_back_when_a_rewrap_cannot_be_proven(tmp_path):
    v = _provisioned(tmp_path)
    good = tmp_path / "good.key"
    bad = tmp_path / "bad.key"
    v.write_text_secret(good, "GOOD", context=OWNER_CTX)
    v.write_text_secret(bad, "BAD", context=OWNER_CTX)
    good_before = good.read_bytes()
    old_kek = load_kek(tmp_path / "vault", runner=make_fake_tpm())

    # corrupt `bad` so it can no longer be opened under the KEK => rotation must fail-closed, roll back.
    corrupt = bytearray(bad.read_bytes()); corrupt[-1] ^= 0xFF
    bad.write_bytes(bytes(corrupt))

    with pytest.raises(RotationError):
        v.rotate_kek([(good, OWNER_CTX), (bad, OWNER_CTX)], embedded_secrets=[])

    # `good` is byte-identical and still opens under the ORIGINAL KEK — nothing was swapped.
    assert good.read_bytes() == good_before
    assert unseal(old_kek, good.read_bytes(), context=OWNER_CTX) == b"GOOD"
    assert load_kek(tmp_path / "vault", runner=make_fake_tpm()) == old_kek  # active KEK unchanged
    # no staged artifacts left behind
    assert not (tmp_path / "vault" / (_SEAL_PUB + ".rot")).exists()
    assert not good.with_name(good.name + ".rot").exists()


def test_prev_kek_fallback_reads_a_file_still_under_the_old_key(tmp_path):
    # Reconstruct a crash-window state by hand: the active KEK has been swapped to a NEW KEK, the OLD KEK
    # survives as `.prev`, and a secret file is still sealed under the OLD KEK (not yet re-wrapped).
    v = _provisioned(tmp_path)
    secret = tmp_path / "s.key"
    v.write_text_secret(secret, "STILL-OLD", context=OWNER_CTX)   # sealed under the OLD KEK
    vault_dir = tmp_path / "vault"

    from vigil_core.sealing import new_kek as mint
    # snapshot the OLD KEK blobs to `.prev`, then seal a fresh KEK over the active blobs.
    import shutil
    shutil.copyfile(vault_dir / _SEAL_PUB, vault_dir / (_SEAL_PUB + ".prev"))
    shutil.copyfile(vault_dir / _SEAL_PRIV, vault_dir / (_SEAL_PRIV + ".prev"))
    fresh = mint()
    reseal_kek(vault_dir, fresh, runner=make_fake_tpm(), pub_name=_SEAL_PUB, priv_name=_SEAL_PRIV)

    # a fresh vault: the active KEK is `fresh`, but the file is under the OLD KEK — the `.prev` fallback reads it.
    v2 = Vault(vault_dir, make_fake_tpm())
    assert v2.read_text_secret(secret, context=OWNER_CTX) == "STILL-OLD"

    # once `.prev` is removed (rotation completed), the old key is gone and the stale file no longer opens.
    (vault_dir / (_SEAL_PUB + ".prev")).unlink()
    (vault_dir / (_SEAL_PRIV + ".prev")).unlink()
    v3 = Vault(vault_dir, make_fake_tpm())
    with pytest.raises(VaultLocked):
        v3.read_text_secret(secret, context=OWNER_CTX)


def test_seal_file_seals_a_plaintext_warden_key_in_place(tmp_path):
    v = _provisioned(tmp_path)
    warden = tmp_path / "warden.key"
    warden.write_bytes(b"PLAINTEXT-WARDEN-KERNEL-KEY-0600")  # as the Rust kernel wrote it
    assert is_sealed(warden.read_bytes()) is False

    assert v.seal_file(warden, context=WARDEN_CTX) == "sealed"
    assert is_sealed(warden.read_bytes()) is True                       # ciphertext at rest now
    assert v.read_bytes_secret(warden, context=WARDEN_CTX) == b"PLAINTEXT-WARDEN-KERNEL-KEY-0600"
    assert v.seal_file(warden, context=WARDEN_CTX) == "already-sealed"  # idempotent


def test_seal_file_leaves_plaintext_when_vault_disabled(tmp_path):
    v = Vault(tmp_path / "vault", make_fake_tpm())   # NOT provisioned
    warden = tmp_path / "warden.key"
    warden.write_bytes(b"PLAINTEXT-WARDEN-KERNEL-KEY-0600")
    assert v.seal_file(warden, context=WARDEN_CTX) == "disabled"
    assert is_sealed(warden.read_bytes()) is False   # unchanged, non-bricking


def test_rotate_unprovisioned_vault_is_refused(tmp_path):
    v = Vault(tmp_path / "vault", make_fake_tpm())   # NOT provisioned
    with pytest.raises(RotationError):
        v.rotate_kek([], embedded_secrets=[])


# --- red-pen W9-2 regression: KEK-direct spine-embedded secrets + crash reconciliation --------------

TOTP_CTX = b"sigil/account.totp"


def test_rotate_kek_refuses_when_a_kek_direct_embedded_secret_exists(tmp_path):
    """Red-pen BLOCK: a secret sealed DIRECTLY under the KEK that rides INSIDE the immutable owner-signed
    spine (e.g. an account TOTP second factor via Vault.seal_secret) cannot be re-wrapped in place, so
    rotate_kek must DETECT it and FAIL CLOSED — never silently destroy it. Reverting the guard lets the
    rotation proceed and the TOTP secret becomes permanently unrecoverable (this test then fails)."""
    v = _provisioned(tmp_path)
    owner = tmp_path / "owner.priv"
    v.write_text_secret(owner, "OWNER-PRIV-B64", context=OWNER_CTX)
    totp_blob = v.seal_secret(b"JBSWY3DPEHPK3PXP", context=TOTP_CTX)   # rides inside a signed spine grant
    old_kek = load_kek(tmp_path / "vault", runner=make_fake_tpm())

    with pytest.raises(RotationError) as ei:
        v.rotate_kek([(owner, OWNER_CTX)], embedded_secrets=[("totp:alice", totp_blob, TOTP_CTX)])
    assert "orphan" in str(ei.value).lower()

    # nothing swapped: the active KEK is unchanged and the embedded TOTP secret still opens.
    assert load_kek(tmp_path / "vault", runner=make_fake_tpm()) == old_kek
    v2 = Vault(tmp_path / "vault", make_fake_tpm())
    assert v2.unseal_secret(totp_blob, context=TOTP_CTX) == b"JBSWY3DPEHPK3PXP"
    assert not (tmp_path / "vault" / (_SEAL_PUB + ".rot")).exists()
    assert not (tmp_path / "vault" / (_SEAL_PUB + ".prev")).exists()


def test_rotate_kek_requires_an_explicit_embedded_secrets_argument(tmp_path):
    """embedded_secrets is keyword-REQUIRED (no default) so a caller can never accidentally rotate the KEK
    without deciding about embedded secrets — a fail-closed API shape."""
    v = _provisioned(tmp_path)
    with pytest.raises(TypeError):
        v.rotate_kek([])  # type: ignore[call-arg]


def test_reconcile_finishes_interrupted_kek_commit_and_retires_old_key(tmp_path):
    """Red-pen HIGH: an interrupted KEK commit leaves the OLD KEK valid forever (.prev lingering) with some
    files still under it. reconcile_kek_rotation re-wraps the stragglers to the active KEK and drops .prev,
    after which the old KEK no longer decrypts. Reverting the reconciler leaves .prev (test fails)."""
    import shutil

    from vigil_core.sealing import new_kek as mint
    from vigil_core.sealing import seal as _seal
    v = _provisioned(tmp_path)
    vault_dir = tmp_path / "vault"
    a, b = tmp_path / "a.key", tmp_path / "b.key"
    v.write_text_secret(a, "AAA", context=OWNER_CTX)
    v.write_text_secret(b, "BBB", context=OWNER_CTX)
    old_kek = load_kek(vault_dir, runner=make_fake_tpm())

    # hand-build the crash state: active KEK swapped to `fresh`, `.prev` = old, file `a` re-wrapped to fresh,
    # file `b` STILL under the old KEK, `.prev` NOT yet dropped.
    shutil.copyfile(vault_dir / _SEAL_PUB, vault_dir / (_SEAL_PUB + ".prev"))
    shutil.copyfile(vault_dir / _SEAL_PRIV, vault_dir / (_SEAL_PRIV + ".prev"))
    fresh = mint()
    reseal_kek(vault_dir, fresh, runner=make_fake_tpm(), pub_name=_SEAL_PUB, priv_name=_SEAL_PRIV)
    a.write_bytes(_seal(fresh, b"AAA", context=OWNER_CTX))

    v2 = Vault(vault_dir, make_fake_tpm())
    assert v2.rotation_incomplete() is True
    res = v2.reconcile_kek_rotation([(a, OWNER_CTX), (b, OWNER_CTX)], embedded_secrets=[])
    assert res["status"] == "completed"
    assert v2.rotation_incomplete() is False

    v3 = Vault(vault_dir, make_fake_tpm())
    assert v3.read_text_secret(a, context=OWNER_CTX) == "AAA"
    assert v3.read_text_secret(b, context=OWNER_CTX) == "BBB"      # straggler re-wrapped to the active KEK
    with pytest.raises(Exception):
        unseal(old_kek, b.read_bytes(), context=OWNER_CTX)         # the OLD KEK is retired
    assert not (vault_dir / (_SEAL_PUB + ".prev")).exists()


def test_reconcile_keeps_prev_if_an_embedded_secret_only_opens_under_it(tmp_path):
    """Defence-in-depth (fail-closed): reconcile must refuse to retire `.prev` while an embedded secret opens
    ONLY under it — dropping it would orphan the secret."""
    import shutil

    from vigil_core.sealing import new_kek as mint
    v = _provisioned(tmp_path)
    vault_dir = tmp_path / "vault"
    totp_blob = v.seal_secret(b"SECRET-TOTP", context=TOTP_CTX)   # sealed under the OLD KEK
    shutil.copyfile(vault_dir / _SEAL_PUB, vault_dir / (_SEAL_PUB + ".prev"))
    shutil.copyfile(vault_dir / _SEAL_PRIV, vault_dir / (_SEAL_PRIV + ".prev"))
    reseal_kek(vault_dir, mint(), runner=make_fake_tpm(), pub_name=_SEAL_PUB, priv_name=_SEAL_PRIV)

    v2 = Vault(vault_dir, make_fake_tpm())
    with pytest.raises(RotationError):
        v2.reconcile_kek_rotation([], embedded_secrets=[("totp:alice", totp_blob, TOTP_CTX)])
    assert v2.rotation_incomplete() is True   # `.prev` kept — the embedded secret is still openable under it
    assert v2.unseal_secret(totp_blob, context=TOTP_CTX) == b"SECRET-TOTP"
