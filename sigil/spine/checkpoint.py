"""Daily signed checkpoint of the spine head (SIGIL §6.3.6, WARDEN anchor).

Generates + persists a solo-owner Ed25519 keypair once (1-of-1 trust root), then signs
the chain head so the whole spine is anchored: rewriting history would require forging
the owner signature, and a shrunk/back-dated head is caught by the monotonic last_seq.

Note: for a personal, single-owner, local-first system the owner's signing key lives
locally (0600) — a deliberate simplification of the framework's "keys never on the
runtime host" rule, appropriate to this threat model (§1.3). A hardware co-signer can be
added later by raising the trust-root threshold.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..config import HEAD_PATH, KEYS_DIR, OWNER_KEY_ID, SCOPE
from ..reuse import (
    AuthorizerKey,
    SignedChainHead,
    TrustRoot,
    generate_keypair,
    sign_head,
    verify_head,
)
from .store import SpineStore

_PRIV = KEYS_DIR / "owner.priv"
_PUB = KEYS_DIR / "owner.pub"


def _atomic_write_text(path: Path, data: str) -> None:
    """Durably + atomically replace `path` with `data` (FIX 3): write a temp file in the SAME dir,
    fsync it, `os.replace()` over the target (atomic on POSIX — a reader sees either the old or the
    new head, never a torn one), then fsync the directory so the rename itself survives a crash. A
    crash at any point leaves the previous valid signed head intact, never a partially-written one."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".head-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:                                     # fsync the directory so the rename is durable
        dfd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:  # pragma: no cover — dir fsync unsupported on some filesystems
        pass


def _owner_keys() -> tuple[str, str]:
    if not _PRIV.exists():
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        kp = generate_keypair()
        _PRIV.write_text(kp.private_key_b64, encoding="utf-8")
        os.chmod(_PRIV, 0o600)
        _PUB.write_text(kp.public_key_b64, encoding="utf-8")
    return _PRIV.read_text(encoding="utf-8").strip(), _PUB.read_text(encoding="utf-8").strip()


def trust_root() -> TrustRoot:
    _, pub = _owner_keys()
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id=OWNER_KEY_ID, name="owner", public_key_b64=pub)])


def checkpoint(store: SpineStore | None = None) -> SignedChainHead:
    store = store or SpineStore()
    priv, _ = _owner_keys()
    head = sign_head(store.entries(), engagement_slug=SCOPE, signers=[(OWNER_KEY_ID, priv)])
    _atomic_write_text(HEAD_PATH, head.model_dump_json())   # FIX 3: never leave a torn head on a crash
    return head


def classify_head(head: SignedChainHead, entries: list, tr: TrustRoot) -> tuple[bool, str]:
    """Pure head/chain classification (no globals — testable in isolation). Distinguishes
    three cases honestly: a shrunk chain (truncation) or a mismatching prefix (history
    rewrite) are TAMPERING; a chain that merely grew past the anchor is benign — stale.
    """
    n, signed_n = len(entries), head.entry_count
    if n < signed_n:
        return False, f"TAMPERING: chain has {n} records but the signed head anchors {signed_n} (truncated/rolled back)"
    # verify the head against exactly the prefix it signed; append-only ⇒ the prefix is byte-identical.
    ok, msg = verify_head(head, entries[:signed_n], tr)
    if not ok:
        return False, f"TAMPERING: history rewritten at or below the signed head — {msg}"
    if n > signed_n:
        return True, f"anchors {signed_n} records; {n - signed_n} appended since — run `sigil sign` to re-anchor"
    return True, f"anchors all {signed_n} records (current)"


def verify_checkpoint(store: SpineStore | None = None) -> tuple[bool, str]:
    store = store or SpineStore()
    if not HEAD_PATH.exists():
        return False, "no signed head — run `sigil sign` to anchor the spine"
    head = SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8"))
    return classify_head(head, store.entries(), trust_root())
