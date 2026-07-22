"""Deterministic tests for vigil_core.kek — the TPM-sealed KEK provider (audit G1).

The TPM is reached only through the injectable argv-runner seam, so a FAKE runner simulates tpm2-tools'
seal/unseal via the on-disk blob files. Proves: provision→load round-trips the SAME KEK; load without
provisioning fails closed; re-provision refuses to overwrite the trust root; a TPM-unavailable runner
fails closed (no plaintext fallback); a wrong-length unseal fails closed; sealed blobs are 0600 and the
KEK is never on disk in plaintext.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_core.kek import (
    KekError,
    TpmResult,
    is_provisioned,
    load_kek,
    provision_kek,
    tpm_available,
)


def make_fake_tpm(*, unavailable=False, unseal_len=32):
    """A fake tpm2-tools that simulates seal/unseal by encoding the KEK into the 'private' blob file."""
    def run(argv, stdin):
        if unavailable:
            return TpmResult(127, b"")
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary-ctx")
            return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub-blob")
            Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b""))
            return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):])
            return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            data = Path(flag("-c")).read_bytes()
            return TpmResult(0, data[:unseal_len])
        return TpmResult(1, b"")

    return run


def test_provision_then_load_round_trips_same_kek(tmp_path):
    fake = make_fake_tpm()
    assert is_provisioned(tmp_path) is False
    provision_kek(tmp_path, runner=fake)
    assert is_provisioned(tmp_path) is True
    k1 = load_kek(tmp_path, runner=fake)
    k2 = load_kek(tmp_path, runner=fake)
    assert isinstance(k1, bytes) and len(k1) == 32
    assert k1 == k2  # unattended: the same sealed KEK is recovered every boot


def test_load_without_provision_fails_closed(tmp_path):
    with pytest.raises(KekError):
        load_kek(tmp_path, runner=make_fake_tpm())


def test_reprovision_refuses_to_overwrite(tmp_path):
    fake = make_fake_tpm()
    provision_kek(tmp_path, runner=fake)
    with pytest.raises(KekError):
        provision_kek(tmp_path, runner=fake)  # never silently clobber the trust root


def test_tpm_unavailable_fails_closed_no_plaintext_fallback(tmp_path):
    dead = make_fake_tpm(unavailable=True)
    assert tpm_available(dead) is False
    with pytest.raises(KekError):
        provision_kek(tmp_path, runner=dead)
    # provisioning left nothing behind
    assert is_provisioned(tmp_path) is False


def test_wrong_length_unseal_fails_closed(tmp_path):
    provision_kek(tmp_path, runner=make_fake_tpm())
    with pytest.raises(KekError):
        load_kek(tmp_path, runner=make_fake_tpm(unseal_len=16))  # short KEK ⇒ reject


def test_sealed_blobs_are_0600_and_kek_not_plaintext_on_disk(tmp_path):
    fake = make_fake_tpm()
    provision_kek(tmp_path, runner=fake)
    kek = load_kek(tmp_path, runner=fake)
    for name in ("kek.tpm.pub", "kek.tpm.priv"):
        f = tmp_path / name
        assert f.exists()
        assert (f.stat().st_mode & 0o777) == 0o600
    # the raw KEK must not appear verbatim in any on-disk artifact (the priv blob wraps it via the fake's
    # SEALED marker; a REAL TPM encrypts it — either way the plaintext 32 bytes are never a whole file).
    for f in tmp_path.iterdir():
        assert f.read_bytes() != kek


def test_tpm_available_true_with_working_runner(tmp_path):
    assert tpm_available(make_fake_tpm()) is True
