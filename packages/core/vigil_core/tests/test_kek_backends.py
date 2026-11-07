"""Deterministic tests for vigil_core.kek_backends — pluggable KEK custody (TPM default, AWS-KMS cloud).

AWS KMS is reached only through the injectable `aws` argv-runner, so a FAKE runner simulates
`aws kms encrypt/decrypt` (and `sts get-caller-identity`) deterministically. Proves: provision→load
round-trips the SAME 32-byte KEK; the KEK is never a plaintext file; a corrupt/tampered wrap or marker
fails CLOSED (never a plaintext fallback); re-provision refuses to clobber the trust root; the wrap is
self-describing (a load uses the key the WRAP recorded, not a drifted config); the staged (.rot) names
round-trip (rotation compatibility); an unreachable CLI fails closed; both backends satisfy the protocol.
"""
from __future__ import annotations

import base64

import pytest

from pathlib import Path

from vigil_core.kek import KekError, TpmResult
from vigil_core.kek_backends import KekBackend, KmsKekBackend, TpmKekBackend

KEY_A, KEY_B, REGION = "arn:aws:kms:eu-west-1:1:key/AAA", "arn:aws:kms:eu-west-1:1:key/BBB", "eu-west-1"
_ENVELOPE = b"VIGILKMS|"


def make_fake_tpm():
    """A minimal fake tpm2-tools runner (seal/unseal via the on-disk blobs) — enough to exercise the TPM
    backend's delegation; the full tpm2 matrix lives in test_kek.py."""
    def run(argv, stdin):
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
            return TpmResult(0, Path(flag("-c")).read_bytes()[:32])
        return TpmResult(1, b"")

    return run


def make_fake_kms(*, unavailable=False, plaintext_len=None):
    """A fake `aws kms` that envelope-wraps the KEK into an opaque blob bound to the --key-id. The CLI
    returns BASE64 on stdout (as `--output text --query CiphertextBlob/Plaintext` does); decrypt rejects a
    ciphertext whose embedded key id does not match --key-id (as a real CMK would)."""
    def run(argv, stdin):
        if unavailable:
            return TpmResult(127, b"")

        def flag(name):
            return argv[argv.index(name) + 1] if name in argv else ""

        if "sts" in argv and "get-caller-identity" in argv:
            return TpmResult(0, b"123456789012\tarn:aws:iam::1:role/vigil\tAIDA\n")
        if "kms" in argv and "encrypt" in argv:
            key = flag("--key-id").encode()
            blob = _ENVELOPE + base64.b64encode(key) + b"|" + (stdin or b"")   # bind the key id
            return TpmResult(0, base64.b64encode(blob) + b"\n")                 # CLI emits base64
        if "kms" in argv and "decrypt" in argv:
            blob = stdin or b""                                                 # raw ciphertext on stdin
            if not blob.startswith(_ENVELOPE):
                return TpmResult(1, b"")                                        # tampered/foreign → reject
            try:
                keyb64, pt = blob[len(_ENVELOPE):].split(b"|", 1)
                embedded = base64.b64decode(keyb64)
            except Exception:
                return TpmResult(1, b"")
            if embedded != flag("--key-id").encode():
                return TpmResult(1, b"")                                        # wrong CMK → reject
            if plaintext_len is not None:
                pt = pt[:plaintext_len]
            return TpmResult(0, base64.b64encode(pt) + b"\n")
        return TpmResult(1, b"")

    return run


def _kms(dirless=False, **kw):
    return KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms(**kw))


# --- construction / availability ------------------------------------------------------------------
def test_kms_requires_key_and_region():
    with pytest.raises(KekError):
        KmsKekBackend(key_id="", region=REGION, runner=make_fake_kms())
    with pytest.raises(KekError):
        KmsKekBackend(key_id=KEY_A, region="  ", runner=make_fake_kms())


def test_available_reflects_the_cli():
    assert KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms()).available() is True
    assert KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms(unavailable=True)).available() is False


# --- the core custody contract --------------------------------------------------------------------
def test_provision_then_load_round_trips_same_kek(tmp_path):
    b = _kms()
    assert b.is_provisioned(tmp_path) is False
    b.provision(tmp_path)
    assert b.is_provisioned(tmp_path) is True
    k1, k2 = b.load(tmp_path), b.load(tmp_path)
    assert isinstance(k1, bytes) and len(k1) == 32 and k1 == k2   # unattended: same KEK every boot


def test_kek_is_never_plaintext_on_disk(tmp_path):
    b = _kms()
    b.provision(tmp_path)
    kek = b.load(tmp_path)
    for name in ("kek.tpm.pub", "kek.tpm.priv"):
        f = tmp_path / name
        assert f.exists() and (f.stat().st_mode & 0o777) == 0o600
    for f in tmp_path.iterdir():
        assert f.read_bytes() != kek                             # no file IS the raw 32-byte KEK


def test_load_without_provision_fails_closed(tmp_path):
    with pytest.raises(KekError):
        _kms().load(tmp_path)


def test_reprovision_refuses_to_overwrite(tmp_path):
    b = _kms()
    b.provision(tmp_path)
    with pytest.raises(KekError):
        b.provision(tmp_path)


def test_reprovision_refuses_when_only_priv_survives(tmp_path):
    """The wrapped KEK is the ciphertext in the priv file. If the non-secret pub marker is lost but priv
    survives, re-provision must STILL refuse (OR-guard, mirroring the TPM recipe) — otherwise it would
    overwrite the one surviving copy of the KEK and permanently orphan the owner key sealed under it."""
    shared = make_fake_kms()
    b = KmsKekBackend(key_id=KEY_A, region=REGION, runner=shared)
    b.provision(tmp_path)
    before = (tmp_path / "kek.tpm.priv").read_bytes()
    (tmp_path / "kek.tpm.pub").unlink()                           # lose ONLY the marker (priv survives)
    assert b.is_provisioned(tmp_path) is False                   # AND-based "fully on" now reads False ...
    with pytest.raises(KekError):                                # ... but provision must still refuse
        b.provision(tmp_path)
    assert (tmp_path / "kek.tpm.priv").read_bytes() == before    # the surviving KEK ciphertext is intact


def test_reprovision_refuses_when_only_pub_survives(tmp_path):
    b = _kms()
    b.provision(tmp_path)
    (tmp_path / "kek.tpm.priv").unlink()                          # lose only the ciphertext
    with pytest.raises(KekError):
        b.provision(tmp_path)


def test_unreachable_kms_fails_closed_no_plaintext(tmp_path):
    dead = KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms(unavailable=True))
    with pytest.raises(KekError):
        dead.provision(tmp_path)
    assert dead.is_provisioned(tmp_path) is False                # nothing left behind


def test_wrong_length_plaintext_fails_closed(tmp_path):
    KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms()).provision(tmp_path)
    short = KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms(plaintext_len=16))
    with pytest.raises(KekError):
        short.load(tmp_path)                                     # a 16-byte KEK is rejected


def test_tampered_ciphertext_fails_closed(tmp_path):
    b = _kms()
    b.provision(tmp_path)
    (tmp_path / "kek.tpm.priv").write_bytes(b"not-a-real-ciphertext")
    with pytest.raises(KekError):
        b.load(tmp_path)


def test_corrupt_marker_fails_closed(tmp_path):
    b = _kms()
    b.provision(tmp_path)
    (tmp_path / "kek.tpm.pub").write_text("}{ not json")
    with pytest.raises(KekError):
        b.load(tmp_path)
    (tmp_path / "kek.tpm.pub").write_text('{"marker":"someone-elses","key_id":"x"}')
    with pytest.raises(KekError):
        b.load(tmp_path)


# --- self-describing wrap (defends against a drifted VIGIL_KMS_KEY_ID) ----------------------------
def test_load_uses_the_key_the_wrap_recorded_not_the_configured_one(tmp_path):
    # provision under KEY_A, then load through a backend CONFIGURED for KEY_B over the SAME fake CMK store.
    shared = make_fake_kms()
    KmsKekBackend(key_id=KEY_A, region=REGION, runner=shared).provision(tmp_path)
    expected = KmsKekBackend(key_id=KEY_A, region=REGION, runner=shared).load(tmp_path)
    drifted = KmsKekBackend(key_id=KEY_B, region=REGION, runner=shared)   # config now points elsewhere
    # the marker pins KEY_A, so the load decrypts under KEY_A and still succeeds (never silently wrong-keyed)
    assert drifted.load(tmp_path) == expected


# --- rotation compatibility (staged .rot names round-trip) ----------------------------------------
def test_reseal_to_staged_names_round_trips(tmp_path):
    b = _kms()
    b.provision(tmp_path)
    fresh = bytes(range(32))
    b.reseal(tmp_path, fresh, pub_name="kek.tpm.pub.rot", priv_name="kek.tpm.priv.rot")
    assert b.load_from(tmp_path, "kek.tpm.pub.rot", "kek.tpm.priv.rot") == fresh
    assert b.reseal.__self__ is b  # sanity: bound method
    with pytest.raises(KekError):
        b.reseal(tmp_path, b"too-short", pub_name="x", priv_name="y")   # length-checked


# --- the TPM backend still works (the default) + protocol conformance ------------------------------
def test_tpm_backend_delegates_and_round_trips(tmp_path):
    b = TpmKekBackend(runner=make_fake_tpm())
    assert b.available() is True
    b.provision(tmp_path)
    assert b.is_provisioned(tmp_path) is True
    assert len(b.load(tmp_path)) == 32


def test_both_backends_satisfy_the_protocol():
    assert isinstance(TpmKekBackend(runner=make_fake_tpm()), KekBackend)
    assert isinstance(KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms()), KekBackend)


# --- the WHOLE Vault on the KMS backend (the real owner-key custody path) --------------------------
def test_full_vault_seals_and_opens_secrets_under_kms(tmp_path):
    from vigil_core.vault import Vault, VaultLocked
    vdir = tmp_path / "vault"
    v = Vault(vdir, backend=_kms())
    assert v.enabled() is False
    with pytest.raises(VaultLocked):                             # no plaintext before provisioning
        v.seal_secret(b"owner-priv", context=b"sigil/owner.priv")
    v.provision()
    assert v.enabled() is True and "KMS-wrapped KEK" in v.status()
    # the owner-key file path (write_text_secret / read_text_secret seal transparently under the KMS KEK)
    keyfile = vdir / "owner.priv"
    v.write_text_secret(keyfile, "base64-ed25519-owner-key", context=b"sigil/owner.priv")
    assert keyfile.read_bytes() != b"base64-ed25519-owner-key"  # sealed, not plaintext
    assert v.read_text_secret(keyfile, context=b"sigil/owner.priv") == "base64-ed25519-owner-key"
    # the spine-embedded (TOTP) blob path
    blob = v.seal_secret(b"totp-shared", context=b"sigil/totp")
    assert v.unseal_secret(blob, context=b"sigil/totp") == b"totp-shared"
    with pytest.raises(VaultLocked):
        v.unseal_secret(blob, context=b"sigil/wrong")           # wrong AAD context fails closed


def test_vault_on_kms_fails_closed_when_kms_unreachable(tmp_path):
    from vigil_core.vault import Vault, VaultLocked
    vdir = tmp_path / "v"
    _kms().provision(vdir)                                       # KEK wrapped while KMS was reachable
    dead = Vault(vdir, backend=KmsKekBackend(key_id=KEY_A, region=REGION, runner=make_fake_kms(unavailable=True)))
    assert dead.enabled() is True                               # the wrapped KEK is on disk...
    with pytest.raises(VaultLocked):                            # ...but cannot be unwrapped -> fail-closed
        dead.seal_secret(b"x", context=b"c")


def test_kek_rotation_is_custody_agnostic_on_kms(tmp_path):
    # the KEK-rotation verify-then-swap machinery must work identically on the KMS backend.
    from vigil_core.vault import Vault
    vdir = tmp_path / "v"
    v = Vault(vdir, backend=_kms())
    v.provision()
    keyfile = vdir / "owner.priv"
    v.write_text_secret(keyfile, "owner-key-bytes", context=b"ctx")
    before = (vdir / "kek.tpm.priv").read_bytes()
    res = v.rotate_kek([(keyfile, b"ctx")], embedded_secrets=[])
    assert res["rotated"] == 1
    assert (vdir / "kek.tpm.priv").read_bytes() != before       # the wrapped KEK moved to a fresh one
    assert v.read_text_secret(keyfile, context=b"ctx") == "owner-key-bytes"  # still opens under the new KEK
