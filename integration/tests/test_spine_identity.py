"""S5 — the STABLE offense engagement-spine identity (retires the ephemeral per-run key).

The make-or-break property: load_or_create_spine_keypair returns the SAME key across process "restarts", so
the offense {slug}.spine is verifiable across runs (before S5 each run minted a fresh key that rejected the
prior run's lines). Sealed at rest under the offense vault, fail-closed on a locked TPM, and its AEAD context
is DISTINCT from the operator key's so the two offense identities are non-interchangeable.

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_spine_identity.py -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_core import is_sealed
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault, VaultLocked
from vigil_integration.attestation.identity import (
    OPERATOR_KEYPAIR_CONTEXT,
    load_or_create_operator_keypair,
)
from vigil_integration.live.spine_identity import (
    SPINE_KEYPAIR_CONTEXT,
    load_or_create_spine_keypair,
)


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


def test_spine_key_is_stable_across_reloads(tmp_path):
    kf = tmp_path / "offense-spine.key"
    kp = load_or_create_spine_keypair(path=str(kf))
    kp2 = load_or_create_spine_keypair(path=str(kf))
    assert kp2 == kp                         # SAME identity across a restart — the whole point of S5
    assert is_sealed(kf.read_bytes()) is False


def test_spine_key_seals_at_rest_and_reloads_same(tmp_path):
    kf = tmp_path / "offense-spine.key"
    v = Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    kp = load_or_create_spine_keypair(path=str(kf), vault=v)
    blob = kf.read_bytes()
    assert is_sealed(blob) is True
    assert kp.private_key_b64.encode() not in blob
    kp2 = load_or_create_spine_keypair(path=str(kf), vault=Vault(tmp_path / "vault", make_fake_tpm()))
    assert kp2 == kp


def test_locked_tpm_fails_closed(tmp_path):
    kf = tmp_path / "offense-spine.key"
    good = Vault(tmp_path / "vault", make_fake_tpm())
    good.provision()
    load_or_create_spine_keypair(path=str(kf), vault=good)
    dead = Vault(tmp_path / "vault", make_fake_tpm(unavailable=True))
    with pytest.raises(VaultLocked):
        load_or_create_spine_keypair(path=str(kf), vault=dead)


def test_spine_and_operator_contexts_are_distinct(tmp_path):
    # The two offense identities must not share an AEAD context, else a sealed spine blob could be opened as
    # the operator key. Distinct contexts + co-located in one vault: sealing one does not yield the other.
    assert SPINE_KEYPAIR_CONTEXT != OPERATOR_KEYPAIR_CONTEXT
    v = Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    spine = load_or_create_spine_keypair(path=str(tmp_path / "offense-spine.key"), vault=v)
    op = load_or_create_operator_keypair(path=str(tmp_path / "operator.key"), vault=v)
    assert spine != op                       # two independent identities under one provisioned KEK
