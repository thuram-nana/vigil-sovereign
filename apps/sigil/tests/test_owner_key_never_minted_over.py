"""The owner key is never re-minted over an existing one.

`ensure_owner_keypair()` (governance signing) and `spine.checkpoint._owner_keys()` (the head signer, and
at the time `trust_root()` through it) used to generate a NEW owner keypair whenever the private key read back as
nothing. That covered a fresh install, but also a missing `owner.priv` next to an existing `owner.pub`, an
unreadable one, and a sealed one the vault could not unseal. In those states the old identity was silently
replaced: every pinned verifier, every grant the old key signed and every backup's trust root would stop
matching.

Both paths now share one loader. It mints ONLY when neither key file exists. Every other incomplete or
unusable state raises `OwnerKeyUnavailable` and writes nothing. Verification (`trust_root()`) no longer
goes through the loader at all and never mints: it checks owner.pub against owner.priv when the private key is
on the box, and anchors on owner.pub alone only when it is not.
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
    """A vault whose reads are scripted (the migrating read and the read-only ``peek``); records every write so a
    refusal can prove it wrote nothing."""

    def __init__(self, read):
        self._read = read
        self.writes = []

    def read_text_secret(self, path, *, context):
        return self._read(path)

    def peek_text_secret(self, path, *, context):
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


# ---- the verify path: a present owner.priv must match owner.pub ----------------------------------------

@pytest.fixture
def signed_home(tmp_path, monkeypatch):
    """A spine home with a genuine owner pair, a signed head and an owner-signed floor, all under tmp_path."""
    import sigil.spine.floor as F
    from sigil.spine.store import SpineStore
    priv, pub, keys = _paths(tmp_path)
    monkeypatch.setattr(C, "HEAD_PATH", tmp_path / "head.json")
    monkeypatch.setattr(C, "KEYS_DIR", keys)
    monkeypatch.setattr(C, "_PRIV", priv)
    monkeypatch.setattr(C, "_PUB", pub)
    monkeypatch.setattr(F, "FLOOR_PATH", tmp_path / "floor.json")
    store = SpineStore(tmp_path / "spine.jsonl")
    for i in range(3):
        store.append(kind="event", source="t", actor="u", payload={"i": i})
    C.checkpoint(store)
    assert C.verify_checkpoint(store)[0]
    return store, priv, pub, tmp_path


def _resign_with(store, home, kp):
    """Re-sign head.json and floor.json with ``kp`` (what a writer holding only ``kp`` can produce)."""
    import sigil.spine.floor as F
    from sigil.reuse.chain import sign_head
    from sigil.config import OWNER_KEY_ID, SCOPE
    head = sign_head(store.entries(), engagement_slug=SCOPE, signers=[(OWNER_KEY_ID, kp.private_key_b64)])
    (home / "head.json").write_text(head.model_dump_json(), encoding="utf-8")
    (home / "floor.json").unlink()
    F.advance_floor(head, owner_key=kp)


def test_verify_fails_closed_when_owner_pub_is_not_the_present_privs(signed_home):
    """With owner.priv on the box, the verify path checks that owner.pub is ITS public key (the check the shared
    loader makes for signing). A replaced owner.pub, with head and floor re-signed under the new key, must not
    verify; the refusal names the mismatch and writes nothing."""
    store, priv, pub, home = signed_home
    other = generate_keypair()
    pub.write_text(other.public_key_b64, encoding="utf-8")
    _resign_with(store, home, other)
    before = _snapshot(priv, pub)
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and msg.startswith("owner.pub is not the public key of owner.priv"), msg
    assert _snapshot(priv, pub) == before
    with pytest.raises(I.OwnerKeyUnavailable, match="not the public key"):
        C.trust_root(store)


def test_verify_fails_closed_when_a_present_priv_cannot_be_read(signed_home, monkeypatch):
    """A present owner.priv that cannot be unsealed (or read) is not the off-box layout: verify refuses, as the
    loader does, rather than anchoring on owner.pub alone."""
    store, priv, pub, _home = signed_home

    def locked(path):
        raise V.VaultLocked("simulated unseal failure")

    fake = _FakeVault(locked)
    monkeypatch.setattr(V, "owner_vault", lambda: fake)
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and "cannot be unsealed" in msg, msg
    assert fake.writes == []
    fake2 = _FakeVault(lambda path: None)
    monkeypatch.setattr(V, "owner_vault", lambda: fake2)
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and "unreadable" in msg, msg
    assert fake2.writes == []


def test_verify_treats_a_dangling_priv_link_as_present(signed_home):
    """A dangling owner.priv link (a moved key volume) is not the off-box layout: verify fails closed."""
    store, priv, pub, home = signed_home
    priv.unlink()
    os.symlink(home / "gone" / "owner.priv", priv)
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and "unreadable" in msg, msg
    assert os.path.islink(priv)


def test_verify_without_priv_anchors_on_owner_pub_alone(signed_home):
    """The off-box / upgrade-drill layout (owner.pub only) still verifies the genuine head, and a head re-signed
    under another key still fails there (the anchor is owner.pub)."""
    store, priv, pub, home = signed_home
    priv.unlink()
    ok, msg = C.verify_checkpoint(store)
    assert ok is True, msg
    assert not priv.exists()
    _resign_with(store, home, generate_keypair())
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and "TAMPERING" in msg, msg


class _MemKek:
    """A provisioned in-memory KEK custody backend for a REAL ``Vault`` (``dead``: the KEK cannot be loaded)."""

    def __init__(self, *, dead=False):
        self._kek, self._dead = os.urandom(32), dead

    def is_provisioned(self, directory):
        return True

    def provision(self, directory):
        pass

    def load(self, directory):
        from vigil_core.kek import KekError
        if self._dead:
            raise KekError("simulated: the KEK cannot be loaded")
        return self._kek

    def load_from(self, directory, pub_name, priv_name):
        return self.load(directory)

    def reseal(self, directory, kek, *, pub_name, priv_name):
        raise AssertionError("a verify never reseals")

    def available(self):
        return not self._dead

    def label(self):
        return "in-memory test KEK"


def _file_state(p):
    st = os.stat(p)
    return p.read_bytes(), st.st_ino, st.st_mtime_ns, st.st_size


def test_verify_never_migrates_a_plaintext_priv_when_the_vault_is_enabled(signed_home, monkeypatch, tmp_path):
    """A plaintext owner.priv (written before the vault was provisioned) with the vault now ENABLED: the vault's
    migrating read would seal it in place, so verify reads it read-only. owner.priv stays byte-identical (bytes,
    inode, mtime) through a passing verify AND through the refusal of a swapped owner.pub."""
    from vigil_core import is_sealed
    store, priv, pub, home = signed_home
    vault = V.Vault(tmp_path / "vault-enabled", backend=_MemKek())
    assert vault.enabled()
    monkeypatch.setattr(V, "owner_vault", lambda: vault)
    assert not is_sealed(priv.read_bytes())
    before = _file_state(priv)
    ok, msg = C.verify_checkpoint(store)
    assert ok is True, msg
    assert _file_state(priv) == before
    other = generate_keypair()
    pub.write_text(other.public_key_b64, encoding="utf-8")
    _resign_with(store, home, other)
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and msg.startswith("owner.pub is not the public key of owner.priv"), msg
    with pytest.raises(I.OwnerKeyUnavailable, match="not the public key"):
        C.trust_root(store)
    assert _file_state(priv) == before
    # the hazard is real for this vault: its migrating read seals the same file in place
    vault.read_text_secret(priv, context=V.OWNER_PRIV_CONTEXT)
    assert is_sealed(priv.read_bytes())


def test_verify_unseals_a_sealed_priv_in_memory_and_writes_nothing(signed_home, monkeypatch, tmp_path):
    """A SEALED owner.priv is opened in memory: verify passes on the genuine pair, refuses a swapped owner.pub,
    and leaves the sealed file untouched either way."""
    from vigil_core import is_sealed
    store, priv, pub, home = signed_home
    vault = V.Vault(tmp_path / "vault-enabled", backend=_MemKek())
    monkeypatch.setattr(V, "owner_vault", lambda: vault)
    vault.read_text_secret(priv, context=V.OWNER_PRIV_CONTEXT)          # migrate it once (the signing path does)
    assert is_sealed(priv.read_bytes())
    before = _file_state(priv)
    ok, msg = C.verify_checkpoint(store)
    assert ok is True, msg
    other = generate_keypair()
    pub.write_text(other.public_key_b64, encoding="utf-8")
    _resign_with(store, home, other)
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and msg.startswith("owner.pub is not the public key of owner.priv"), msg
    assert _file_state(priv) == before


def test_verify_with_an_unloadable_kek_reads_a_plaintext_priv_and_refuses_a_sealed_one(signed_home, monkeypatch,
                                                                                    tmp_path):
    """The KEK is only needed to OPEN a sealed owner.priv: with it unloadable, a plaintext owner.priv is still read
    (and checked) as it is, while a sealed one fails verify closed as unsealable. Nothing is written."""
    store, priv, pub, home = signed_home
    good = V.Vault(tmp_path / "vault-enabled", backend=_MemKek())
    dead = V.Vault(tmp_path / "vault-dead", backend=_MemKek(dead=True))
    monkeypatch.setattr(V, "owner_vault", lambda: dead)
    before = _file_state(priv)
    ok, msg = C.verify_checkpoint(store)
    assert ok is True, msg
    assert _file_state(priv) == before
    good.read_text_secret(priv, context=V.OWNER_PRIV_CONTEXT)           # now sealed under a KEK `dead` cannot load
    sealed = _file_state(priv)
    ok, msg = C.verify_checkpoint(store)
    assert ok is False and "cannot be unsealed" in msg, msg
    assert _file_state(priv) == sealed
