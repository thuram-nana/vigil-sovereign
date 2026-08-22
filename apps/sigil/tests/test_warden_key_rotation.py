"""Tests for WARDEN kernel-key sealing + rotation with cross-signed succession (audit W9-2).

Proves: the plaintext-0600 WARDEN key seals at rest under a provisioned vault; rotation mints a fresh
keypair, records a cross-signed succession (the OUTGOING key signs the incoming pub) and swaps the key
files verify-then-swap; the succession chain verifies across rotations so history stays authenticable; and
the negative controls — a FORGED succession link (not signed by the incumbent) is refused, and rotating
with no existing key is refused. FAILS on a tree without the change (the module does not exist).
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from sigil.warden_key import (
    WARDEN_KEY_CONTEXT, WardenKeyError, _derive_pub_hex, materialize_warden_key, rotate_warden_key,
    seal_warden_key, verify_warden_succession, warden_home,
)
from vigil_core import is_sealed
from vigil_core.crypto import sign
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault


def make_fake_tpm():
    def run(argv, stdin):
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary"); return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub"); Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b""))
            return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):]); return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


def _seed_kernel_key(home: Path) -> bytes:
    """Simulate the Rust kernel having created warden.key (32-byte seed, plaintext) + warden.pub (hex)."""
    wh = warden_home(home); wh.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(32)
    (wh / "warden.key").write_bytes(seed)
    (wh / "warden.pub").write_text(_derive_pub_hex(seed), encoding="utf-8")
    return seed


def test_rotate_warden_key_succession_verifies(tmp_path):
    v = Vault(tmp_path / "vault", make_fake_tpm())   # unprovisioned => key stays plaintext (kernel-native)
    seed0 = _seed_kernel_key(tmp_path)
    pub0 = _derive_pub_hex(seed0)

    res = rotate_warden_key(tmp_path, v)
    assert res["seq"] == 1 and res["old_pub"] == pub0 and res["new_pub"] != pub0

    wh = warden_home(tmp_path)
    assert (wh / "warden.key").read_bytes() != seed0                       # a fresh seed
    assert (wh / "warden.pub").read_text().strip() == res["new_pub"]       # pub tracks the new key
    ok, why = verify_warden_succession(tmp_path)
    assert ok is True, why

    # a second rotation continues the chain
    res2 = rotate_warden_key(tmp_path, v)
    assert res2["seq"] == 2 and res2["old_pub"] == res["new_pub"]
    ok2, _ = verify_warden_succession(tmp_path)
    assert ok2 is True


def test_forged_succession_link_is_refused(tmp_path):
    v = Vault(tmp_path / "vault", make_fake_tpm())
    _seed_kernel_key(tmp_path)
    rotate_warden_key(tmp_path, v)
    assert verify_warden_succession(tmp_path)[0] is True

    # forge a link: a stranger (NOT the incumbent) signs a succession to an attacker pubkey.
    wh = warden_home(tmp_path)
    stranger = os.urandom(32)
    stranger_pub = _derive_pub_hex(stranger)
    attacker_pub = _derive_pub_hex(os.urandom(32))
    from vigil_core.canonical import canonical_json
    seq = 2
    msg = canonical_json({"d": "sigil/warden-succession/v1", "old_pub": stranger_pub,
                          "new_pub": attacker_pub, "seq": seq})
    sig = sign(base64.b64encode(stranger).decode("ascii"), msg)
    forged = {"v": 1, "kind": "warden.succession", "seq": seq, "old_pub": stranger_pub,
              "new_pub": attacker_pub, "sig": sig}
    with (wh / "warden.succession.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(forged) + "\n")

    ok, why = verify_warden_succession(tmp_path)
    assert ok is False and "continue" in why.lower()   # continuity break: forged old_pub != prior new_pub


def test_tampered_succession_signature_is_refused(tmp_path):
    v = Vault(tmp_path / "vault", make_fake_tpm())
    _seed_kernel_key(tmp_path)
    rotate_warden_key(tmp_path, v)
    wh = warden_home(tmp_path)
    path = wh / "warden.succession.jsonl"
    links = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    links[0]["new_pub"] = _derive_pub_hex(os.urandom(32))   # tamper the target pub; sig no longer matches
    path.write_text(json.dumps(links[0]) + "\n", encoding="utf-8")
    ok, why = verify_warden_succession(tmp_path)
    assert ok is False


def test_seal_warden_key_at_rest_and_rotate_from_sealed(tmp_path):
    v = Vault(tmp_path / "vault", make_fake_tpm()); v.provision()
    seed0 = _seed_kernel_key(tmp_path)
    wh = warden_home(tmp_path)

    assert seal_warden_key(tmp_path, v) == "sealed"
    assert is_sealed((wh / "warden.key").read_bytes()) is True            # ciphertext at rest now
    assert materialize_warden_key(tmp_path, v) == seed0                   # unseals to the exact kernel seed

    # rotation reads the sealed old seed, cross-signs, and seals the fresh key too.
    res = rotate_warden_key(tmp_path, v)
    assert res["old_pub"] == _derive_pub_hex(seed0)
    assert is_sealed((wh / "warden.key").read_bytes()) is True            # the new key rests sealed
    assert verify_warden_succession(tmp_path)[0] is True


def test_rotate_refuses_when_no_existing_key(tmp_path):
    v = Vault(tmp_path / "vault", make_fake_tpm())
    with pytest.raises(WardenKeyError):
        rotate_warden_key(tmp_path, v)   # no warden.key to succeed => fail-closed
