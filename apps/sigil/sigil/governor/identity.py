"""Owner identity for governance authentication (Phase 6). The trust anchor is the SAME solo-owner
Ed25519 keypair the spine checkpoint already persists (`KEYS_DIR/owner.priv|pub`, the 1-of-1 trust
root) — governance events (promotion grants, kill release, approvals) are signed by it and verified
against it. Reads are fail-closed: a missing key returns None, so nothing forged is ever trusted.

`owner_pubkey()`/`owner_keypair()` READ the anchor (never generate — verification must not mint
trust). `ensure_owner_keypair()` is for owner-initiated SIGNING actions (CLI engage/grant/approve):
it generates+persists the anchor once if absent, mirroring the checkpoint's `_owner_keys()`."""
from __future__ import annotations

import os
from typing import Optional

from ..config import KEYS_DIR
from ..reuse import KeyPair, generate_keypair

_PRIV = KEYS_DIR / "owner.priv"
_PUB = KEYS_DIR / "owner.pub"


def owner_pubkey() -> Optional[str]:
    try:
        return (_PUB.read_text(encoding="utf-8").strip() or None)
    except OSError:
        return None


def owner_keypair() -> Optional[KeyPair]:
    try:
        priv = _PRIV.read_text(encoding="utf-8").strip()
        pub = _PUB.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return KeyPair(public_key_b64=pub, private_key_b64=priv) if priv and pub else None


def ensure_owner_keypair() -> KeyPair:
    """Return the persisted owner keypair, generating+persisting it once if absent (owner signing
    path only). Same key material the checkpoint uses, so governance and the spine head share one
    owner identity."""
    kp = owner_keypair()
    if kp is not None:
        return kp
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    kp = generate_keypair()
    _PRIV.write_text(kp.private_key_b64, encoding="utf-8")
    _PUB.write_text(kp.public_key_b64, encoding="utf-8")
    for f in (_PRIV,):
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    return kp
