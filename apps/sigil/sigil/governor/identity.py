"""Owner identity for governance authentication (Phase 6). The trust anchor is the SAME solo-owner
Ed25519 keypair the spine checkpoint already persists (`KEYS_DIR/owner.priv|pub`, the 1-of-1 trust
root) — governance events (promotion grants, kill release, approvals) are signed by it and verified
against it. Reads are fail-closed: a missing key returns None, so nothing forged is ever trusted.

`owner_pubkey()`/`owner_keypair()` READ the anchor (never generate — verification must not mint
trust). `ensure_owner_keypair()` is for owner-initiated SIGNING actions (CLI engage/grant/approve):
it generates+persists the anchor only on a fresh install (neither key file present) and otherwise REFUSES
an incomplete or unreadable key (`OwnerKeyUnavailable`) — it never mints a new owner over an old one. The
checkpoint's `_owner_keys()` uses the same loader."""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional

from ..config import KEYS_DIR
from ..reuse import KeyPair, generate_keypair

_PRIV = KEYS_DIR / "owner.priv"
_PUB = KEYS_DIR / "owner.pub"
# W9-1: the PINNED genesis root of the owner-key succession chain. Written once (at the first rotation, or
# repinned by a re-genesis) and thereafter the anchor a verifier walks the succession from. It is NOT
# rewritten on a routine rotation — that is the whole point of a pinned root. Absent it, `genesis_owner_pubkey`
# falls back to the CURRENT owner key (an install that has never rotated: current IS genesis).
_GENESIS_PUB = KEYS_DIR / "owner.genesis.pub"


def owner_pubkey() -> Optional[str]:
    try:
        return (_PUB.read_text(encoding="utf-8").strip() or None)
    except OSError:
        return None


def genesis_owner_pubkey() -> Optional[str]:
    """The PINNED genesis owner pubkey the succession chain is walked from, or — absent a pin — the current
    owner pubkey (an un-rotated install, where current == genesis). Read-only; never mints trust."""
    try:
        pinned = _GENESIS_PUB.read_text(encoding="utf-8").strip()
        if pinned:
            return pinned
    except OSError:
        pass
    return owner_pubkey()


def pin_genesis(pubkey: str, *, force: bool = False) -> None:
    """Pin the genesis root. Idempotent set-if-absent by default (the first rotation records the incumbent
    as the chain's root); `force=True` REPINS (a re-genesis, deliberately abandoning the old root)."""
    if not pubkey:
        raise ValueError("refusing to pin an empty genesis pubkey")
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if force or not _GENESIS_PUB.exists():
        _GENESIS_PUB.write_text(pubkey, encoding="utf-8")


def set_owner_key(new_keypair) -> None:
    """Rotate the AT-REST owner key material to `new_keypair`: write the private key through the owner vault
    (TPM-sealed once a KEK is provisioned — the live-only residual; plaintext-fallback otherwise) and the
    public key alongside it. The genesis pin is left untouched (a routine rotation keeps the same root)."""
    from ..platform.vault import OWNER_PRIV_CONTEXT, owner_vault
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    owner_vault().write_text_secret(_PRIV, new_keypair.private_key_b64, context=OWNER_PRIV_CONTEXT)
    _PUB.write_text(new_keypair.public_key_b64, encoding="utf-8")


def owner_keypair() -> Optional[KeyPair]:
    # Private key via the vault (audit G1): plaintext until a TPM-sealed KEK is provisioned, then sealed.
    from ..platform.vault import OWNER_PRIV_CONTEXT, VaultLocked, owner_vault
    try:
        pub = _PUB.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        priv = owner_vault().read_text_secret(_PRIV, context=OWNER_PRIV_CONTEXT)
    except VaultLocked:
        return None  # sealed but the TPM cannot unseal → fail-closed (nothing forged is ever trusted)
    return KeyPair(public_key_b64=pub, private_key_b64=priv) if priv and pub else None


def delegate_offense_governance(owner_key, *, authorizers, threshold: int, scope: str, not_after: int):
    """Owner-sign a delegation authorizing an offense-governance TrustRoot ``(authorizers, threshold)`` for
    ``scope`` until ``not_after`` (unix seconds) — the cryptographic tie (S4) that lets the sovereign
    finding-receiver DERIVE the governance root it trusts from the OWNER, instead of blindly trusting a
    handed-in root. Only the owner (holder of the sovereign key) can mint one. Returns a ``DelegationCert``
    (inert signed data that crosses the boundary)."""
    from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, sign_delegation
    return sign_delegation(owner_key, role=OFFENSE_GOVERNANCE_ROLE, scope=scope,
                           authorizers=authorizers, threshold=int(threshold), not_after=int(not_after))


def delegate_offense_spine(owner_key, *, authorizers, scope: str, not_after: int):
    """Owner-sign a delegation authorizing the STABLE offense engagement-spine identity (S5) for ``scope``
    until ``not_after`` — the cryptographic tie that lets a verifier chain an offense spine head back to the
    owner (offense-spine head → verify_delegation(role="offense-spine") → owner root), while the owner
    private key stays sovereign-side and the offense side holds only its own stable spine key.

    Threshold is FIXED at 1: the offense spine is SINGLE-SIGNER (one key signs every line), so a threshold>1
    delegation would be cryptographically unsatisfiable — and accepting it would let a verifier silently
    downgrade the owner's intent to 1-of-n. 1-of-n over multiple authorizers (key rotation) is the intended
    shape and is exactly what threshold=1 gives. The spine identity is distinct from the m-of-n governance
    authority so the two signing surfaces never merge. Returns a ``DelegationCert`` (inert signed data)."""
    from vigil_core.delegation import OFFENSE_SPINE_ROLE, sign_delegation
    return sign_delegation(owner_key, role=OFFENSE_SPINE_ROLE, scope=scope,
                           authorizers=authorizers, threshold=1, not_after=int(not_after))


class OwnerKeyUnavailable(RuntimeError):
    """The owner key exists but cannot be used (a half-present pair, an unreadable or unsealable private
    key, or a public key that is not the private key's). Signing REFUSES rather than minting a new owner
    identity over the old one: a silent re-mint would replace the trust root every verifier pins, orphan
    every grant the old key signed, and turn a recoverable fault (a lost TPM unseal, a permissions slip,
    a half-restored backup) into an unrecoverable identity change."""


def _path_present(p: Path) -> bool:
    """True when ANYTHING occupies ``p`` (a regular file, a directory, a dangling symlink). A stat that fails
    for any reason other than "no such file" counts as present: when we cannot tell, we must not mint."""
    try:
        os.lstat(p)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _public_of(private_key_b64: str) -> Optional[str]:
    """The base64 Ed25519 public key for ``private_key_b64``, or None when it is not a valid 32-byte key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = base64.b64decode(private_key_b64.strip(), validate=True)
        if len(raw) != 32:
            return None
        pub = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except Exception:  # noqa: BLE001 — any malformed key is simply "not a key"
        return None
    return base64.b64encode(pub).decode("ascii")


def load_or_init_owner_keypair(priv_path: Path, pub_path: Path, keys_dir: Path) -> KeyPair:
    """The ONE owner-key loader for every signing path (governance actions here, the spine checkpoint in
    ``spine/checkpoint.py``). It generates a keypair ONLY on a genuinely fresh install, when NEITHER
    ``owner.priv`` NOR ``owner.pub`` exists. Every other state that is not a complete, readable, matching
    pair raises ``OwnerKeyUnavailable`` and writes nothing:

      * ``owner.pub`` present but ``owner.priv`` missing, empty or unreadable;
      * ``owner.priv`` sealed and the vault cannot unseal it (``VaultLocked``);
      * ``owner.priv`` present but ``owner.pub`` missing or empty;
      * ``owner.pub`` is not the public key of ``owner.priv`` (a swapped or stale public key)."""
    from ..platform.vault import OWNER_PRIV_CONTEXT, VaultLocked, owner_vault
    vault = owner_vault()
    priv_present, pub_present = _path_present(priv_path), _path_present(pub_path)
    if not priv_present and not pub_present:
        keys_dir.mkdir(parents=True, exist_ok=True)
        kp = generate_keypair()
        vault.write_text_secret(priv_path, kp.private_key_b64, context=OWNER_PRIV_CONTEXT)
        pub_path.write_text(kp.public_key_b64, encoding="utf-8")
        return kp
    advice = ("refusing to create a new owner key over the existing one. Restore owner.priv and owner.pub "
              "from a backup (or fix the vault/TPM unseal), then retry; `vigil doctor` reports the state")
    try:
        pub = pub_path.read_text(encoding="utf-8").strip() if pub_present else ""
    except (OSError, UnicodeDecodeError):
        pub = ""
    try:
        priv = vault.read_text_secret(priv_path, context=OWNER_PRIV_CONTEXT) if priv_present else None
    except VaultLocked as e:
        raise OwnerKeyUnavailable(f"owner.priv is sealed and cannot be unsealed ({e}); {advice}") from e
    except (OSError, UnicodeDecodeError, ValueError):
        priv = None
    if not priv:
        raise OwnerKeyUnavailable(f"owner.priv is missing, empty or unreadable while owner.pub exists; {advice}")
    if not pub:
        raise OwnerKeyUnavailable(f"owner.pub is missing, empty or unreadable while owner.priv exists; {advice}")
    if _public_of(priv) != pub:
        raise OwnerKeyUnavailable(f"owner.pub is not the public key of owner.priv; {advice}")
    return KeyPair(public_key_b64=pub, private_key_b64=priv)


def check_owner_pub_against_priv(priv_path: Path, pub: str) -> None:
    """The VERIFY-path half of the loader's consistency check: when ``owner.priv`` is on this box, raise
    ``OwnerKeyUnavailable`` unless it can be read (unsealed) and ``pub`` is its public key. When it is absent
    (the owner key kept off-box, or the upgrade drill's keyless copy) there is nothing to check ``pub`` against
    and this returns. Like the loader, an existence check that cannot tell counts as present. Never writes and
    never mints: the private key is read through the vault's READ-ONLY accessor (``peek_text_secret``), so a
    plaintext ``owner.priv`` stays byte-identical even with the vault enabled (the signing loader migrates it)."""
    if not _path_present(priv_path):
        return
    from ..platform.vault import OWNER_PRIV_CONTEXT, VaultLocked, owner_vault
    advice = ("the signed head is not verified against it. Restore the matching owner.priv and owner.pub from a "
              "backup (or fix the vault/TPM unseal); `vigil doctor` reports the state")
    try:
        priv = owner_vault().peek_text_secret(priv_path, context=OWNER_PRIV_CONTEXT)
    except VaultLocked as e:
        raise OwnerKeyUnavailable(f"owner.priv is sealed and cannot be unsealed ({e}); {advice}") from e
    except (OSError, UnicodeDecodeError, ValueError):
        priv = None
    if not priv:
        raise OwnerKeyUnavailable(f"owner.priv is present but empty or unreadable; {advice}")
    if _public_of(priv) != pub:
        raise OwnerKeyUnavailable(f"owner.pub is not the public key of owner.priv; {advice}")


def ensure_owner_keypair() -> KeyPair:
    """Return the persisted owner keypair for an owner SIGNING action, generating+persisting it ONLY on a
    fresh install (neither key file present). A half-present, unreadable, unsealable or mismatched key
    raises ``OwnerKeyUnavailable`` instead of minting a replacement (see ``load_or_init_owner_keypair``).
    Same key material the checkpoint uses, so governance and the spine head share one owner identity. The
    private key is sealed at rest when the vault is provisioned (audit G1)."""
    return load_or_init_owner_keypair(_PRIV, _PUB, KEYS_DIR)
