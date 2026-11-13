"""The owner key is never re-minted over an existing one.

`ensure_owner_keypair()` (governance signing) and `spine.checkpoint._owner_keys()` (the head signer, and
at the time `trust_root()` through it) used to generate a NEW owner keypair whenever the private key read back as
nothing. That covered a fresh install, but also a missing `owner.priv` next to an existing `owner.pub`, an
unreadable one, and a sealed one the vault could not unseal. In those states the old identity was silently
replaced: every pinned verifier, every grant the old key signed and every backup's trust root would stop
matching.

Both paths now share one loader. It mints ONLY when neither key file exists. Every other incomplete or
unusable state raises `OwnerKeyUnavailable` and writes nothing. Verification (`trust_root()`) no longer
goes through the loader at all: it reads only the public key and never mints.
"""
from __future__ import annotations

import os

import pytest

import sigil.governor.identity as I
import sigil.platform.vault as V
import sigil.spine.checkpoint as C
from sigil.reuse import generate_keypair


def _paths(tmp_path):
    keys = tmp_path / "keys"
    return keys / "owner.priv", keys / "owner.pub", keys


def _write_pair(priv, pub, kp):
    priv.parent.mkdir(parents=True, exist_ok=True)
    priv.write_text(kp.private_key_b64, encoding="utf-8")
    pub.write_text(kp.public_key_b64, encoding="utf-8")


def _snapshot(*paths):
    """Bytes of every path that exists (and the set that exists), to prove a refusal wrote nothing."""
    return {str(p): (p.read_bytes() if p.is_file() else None) for p in paths if os.path.lexists(p)}


class _FakeVault:
    """A vault whose reads are scripted; records every write so a refusal can prove it wrote nothing."""

    def __init__(self, read):
        self._read = read
        self.writes = []

    def read_text_secret(self, path, *, context):
        return self._read(path)

    def write_text_secret(self, path, value, *, context):
        self.writes.append(str(path))
        path.write_text(value, encoding="utf-8")


# ---- fresh install: the only state that mints ---------------------------------------------------------

def test_fresh_install_mints_once_and_then_loads_the_same_key(tmp_path):
    priv, pub, keys = _paths(tmp_path)
    kp1 = I.load_or_init_owner_keypair(priv, pub, keys)
    assert priv.is_file() and pub.is_file()
    assert pub.read_text().strip() == kp1.public_key_b64
    kp2 = I.load_or_init_owner_keypair(priv, pub, keys)
    assert kp2 == kp1                                    # stable: a second call loads, never re-mints


def test_a_complete_matching_pair_loads_unchanged(tmp_path):
    priv, pub, keys = _paths(tmp_path)
    kp = generate_keypair()
    _write_pair(priv, pub, kp)
    before = _snapshot(priv, pub)
    assert I.load_or_init_owner_keypair(priv, pub, keys) == kp
    assert _snapshot(priv, pub) == before


# ---- every partial / unusable state refuses and writes nothing ------------------------------------------

def test_pub_without_priv_refuses_and_writes_nothing(tmp_path):
    priv, pub, keys = _paths(tmp_path)
    kp = generate_keypair()
    _write_pair(priv, pub, kp)
    priv.unlink()
    before = _snapshot(priv, pub)
    with pytest.raises(I.OwnerKeyUnavailable, match="owner.priv is missing"):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert _snapshot(priv, pub) == before
    assert not priv.exists()
    assert pub.read_text().strip() == kp.public_key_b64  # the old identity is untouched


def test_empty_priv_refuses(tmp_path):
    priv, pub, keys = _paths(tmp_path)
    _write_pair(priv, pub, generate_keypair())
    priv.write_text("", encoding="utf-8")
    before = _snapshot(priv, pub)
    with pytest.raises(I.OwnerKeyUnavailable):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert _snapshot(priv, pub) == before


def test_unreadable_priv_refuses(tmp_path, monkeypatch):
    """The vault returns None on any OSError (EACCES, EIO). The file is still THERE, so this must refuse."""
    priv, pub, keys = _paths(tmp_path)
    _write_pair(priv, pub, generate_keypair())
    fake = _FakeVault(lambda path: None)
    monkeypatch.setattr(V, "owner_vault", lambda: fake)
    before = _snapshot(priv, pub)
    with pytest.raises(I.OwnerKeyUnavailable, match="unreadable"):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert fake.writes == []
    assert _snapshot(priv, pub) == before


def test_sealed_priv_that_cannot_unseal_refuses_instead_of_minting(tmp_path, monkeypatch):
    """The worst old case: a TPM unseal failure read as "no key" and the sealed owner key was overwritten."""
    priv, pub, keys = _paths(tmp_path)
    _write_pair(priv, pub, generate_keypair())

    def locked(path):
        raise V.VaultLocked("simulated unseal failure")

    fake = _FakeVault(locked)
    monkeypatch.setattr(V, "owner_vault", lambda: fake)
    before = _snapshot(priv, pub)
    with pytest.raises(I.OwnerKeyUnavailable, match="cannot be unsealed"):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert fake.writes == []
    assert _snapshot(priv, pub) == before


def test_priv_without_pub_refuses_and_keeps_priv(tmp_path):
    priv, pub, keys = _paths(tmp_path)
    kp = generate_keypair()
    _write_pair(priv, pub, kp)
    pub.unlink()
    with pytest.raises(I.OwnerKeyUnavailable, match="owner.pub is missing"):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert priv.read_text().strip() == kp.private_key_b64
    assert not pub.exists()


def test_a_public_key_that_is_not_the_private_keys_refuses(tmp_path):
    priv, pub, keys = _paths(tmp_path)
    _write_pair(priv, pub, generate_keypair())
    pub.write_text(generate_keypair().public_key_b64, encoding="utf-8")   # swapped / stale public key
    before = _snapshot(priv, pub)
    with pytest.raises(I.OwnerKeyUnavailable, match="not the public key"):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert _snapshot(priv, pub) == before


def test_a_dangling_symlink_counts_as_present(tmp_path):
    """A link whose target vanished (a moved key volume) is not a fresh install."""
    priv, pub, keys = _paths(tmp_path)
    keys.mkdir(parents=True)
    os.symlink(tmp_path / "gone" / "owner.priv", priv)
    with pytest.raises(I.OwnerKeyUnavailable):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert os.path.islink(priv) and not pub.exists()


# ---- both production signing paths use the loader ------------------------------------------------------

@pytest.fixture
def pub_only_home(tmp_path, monkeypatch):
    """Point BOTH modules' key paths at a home that has owner.pub but no owner.priv."""
    priv, pub, keys = _paths(tmp_path)
    kp = generate_keypair()
    _write_pair(priv, pub, kp)
    priv.unlink()
    for mod in (I, C):
        monkeypatch.setattr(mod, "KEYS_DIR", keys)
        monkeypatch.setattr(mod, "_PRIV", priv)
        monkeypatch.setattr(mod, "_PUB", pub)
    return priv, pub, kp


def test_ensure_owner_keypair_refuses_on_a_pub_only_home(pub_only_home):
    priv, pub, kp = pub_only_home
    with pytest.raises(I.OwnerKeyUnavailable):
        I.ensure_owner_keypair()
    assert not priv.exists() and pub.read_text().strip() == kp.public_key_b64


def test_checkpoint_signer_refuses_on_a_pub_only_home(pub_only_home):
    priv, pub, kp = pub_only_home
    with pytest.raises(I.OwnerKeyUnavailable):
        C._owner_keys()
    assert not priv.exists() and pub.read_text().strip() == kp.public_key_b64


def test_trust_root_never_mints_a_new_owner(pub_only_home, tmp_path):
    """trust_root() is a VERIFY path; through _owner_keys it used to mint a whole new owner on this home. It
    now reads only the PUBLIC key (an off-box private key is a supported layout): it anchors on the existing
    owner.pub exactly and writes nothing, while the signer above still refuses on the same home."""
    from sigil.spine.store import SpineStore
    priv, pub, kp = pub_only_home
    tr = C.trust_root(SpineStore(tmp_path / "spine" / "spine.jsonl"))
    assert [a.public_key_b64 for a in tr.authorizers] == [kp.public_key_b64]
    assert not priv.exists() and pub.read_text().strip() == kp.public_key_b64


def test_when_existence_cannot_be_determined_it_never_mints(tmp_path, monkeypatch):
    """A stat that fails for a reason other than "no such file" (EACCES on the key dir, EIO) is not proof
    of a fresh install, so it must refuse rather than mint."""
    priv, pub, keys = _paths(tmp_path)
    real_lstat = os.lstat

    def denied(p, *a, **k):
        if str(p) in (str(priv), str(pub)):
            raise PermissionError(13, "Permission denied", str(p))
        return real_lstat(p, *a, **k)

    monkeypatch.setattr(I.os, "lstat", denied)
    with pytest.raises(I.OwnerKeyUnavailable):
        I.load_or_init_owner_keypair(priv, pub, keys)
    assert not priv.exists() and not pub.exists()
