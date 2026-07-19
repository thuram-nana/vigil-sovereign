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

import json
import os
from pathlib import Path

_MAX_HEAD_SCHEMA = 2   # head schema versions this build understands; a higher one -> "upgrade sigil"

from ..config import HEAD_PATH, KEYS_DIR, OWNER_KEY_ID, SCOPE
from ..reuse import (
    AuthorizerKey,
    SignedChainHead,
    TrustRoot,
    generate_keypair,
    sign_head,
    verify_head,
)
from .atomicio import atomic_write_text
from .store import SpineStore

_PRIV = KEYS_DIR / "owner.priv"
_PUB = KEYS_DIR / "owner.pub"


def _atomic_write_text(path: Path, data: str) -> None:
    """Durably + atomically replace `path` with `data` (FIX 3) — a reader sees either the whole old or
    the whole new head, never a torn one, and a crash leaves the previous valid head intact. Delegates to
    the one shared `spine.atomicio.atomic_write_text` so the head, the manifest, and every cutover use the
    same audited routine (no drift)."""
    atomic_write_text(path, data, prefix=".head-")


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
    """Pure head/chain classification (no globals — testable in isolation), SNAPSHOT-AWARE for the
    cold-archive hard-prune. The live window is selected BY SEQ (`seq >= base_seq`), not by array prefix, so
    every crash-cutover state verifies clean. Failures are TAMPERING (front-truncation, tail-truncation, or
    a rewrite); a chain grown past the anchor is benign-stale. entry_count stays ABSOLUTE (base_count +
    live). For a v1 head (base_seq=0, base_count=0) this is BYTE-IDENTICAL to the pre-v2 semantics."""
    base = head.base_count
    signed_live = head.entry_count - base
    live = [e for e in entries if e.seq >= head.base_seq]
    if len(live) < signed_live:
        return False, (f"TAMPERING: live window has {len(live)} records but the signed head anchors "
                       f"{signed_live} (truncated/rolled back)")
    if signed_live > 0:
        # LEFT-EDGE PIN — UNCONDITIONAL TAMPERING: the signed live window must start EXACTLY at base_seq and
        # link from base_prev_hash. This closes the false-CLEAN front-drop hole (the n<entry_count no-op
        # trap transposed to the left edge) — an attacker cannot drop the front of the live window. (Only
        # the window-SHAPE check is gated on signed_live>0; the SIGNATURE check below is not.)
        if live[0].seq != head.base_seq or live[0].prev_hash != head.base_prev_hash:
            return False, "TAMPERING: live window does not start at the signed base (front-truncated/rolled back)"
    # SIGNATURE / threshold check runs UNCONDITIONALLY — including signed_live == 0 (an empty live window, the
    # case a forged zero-anchor head presents). verify_head over an empty window still validates
    # head_hash==base_prev_hash, last_seq==base_seq, entry_count==base_count AND the owner Ed25519 signature,
    # so a forged UNSIGNED zero head is TAMPERING (the whole tamper-evidence point), while a legitimately
    # owner-signed empty spine still passes. (An earlier version gated this behind signed_live>0 and thereby
    # skipped signature verification for empty heads — a keyless tamper-alert-suppression fail-open.)
    ok, msg = verify_head(head, live[:signed_live], tr, genesis_prev=head.base_prev_hash)
    if not ok:
        return False, f"TAMPERING: history rewritten at or below the signed head — {msg}"
    if len(live) > signed_live:
        return True, f"anchors {signed_live} records; {len(live) - signed_live} appended since — run `sigil sign` to re-anchor"
    return True, f"anchors all {signed_live} records (current)"


def verify_checkpoint(store: SpineStore | None = None) -> tuple[bool, str]:
    store = store or SpineStore()
    if not HEAD_PATH.exists():
        return False, "no signed head — run `sigil sign` to anchor the spine"
    raw = HEAD_PATH.read_text(encoding="utf-8")
    try:
        head = SignedChainHead.model_validate_json(raw)     # a future-schema head fails extra="forbid" here
    except Exception:  # noqa: BLE001 — never crash + never false-clean: distinguish "too new" from "corrupt"
        try:
            sv = int(json.loads(raw).get("schema_version", 1))
        except (ValueError, TypeError, AttributeError):
            return False, "corrupt head — cannot parse (run `sigil sign` to re-anchor)"
        if sv > _MAX_HEAD_SCHEMA:
            return False, f"head schema v{sv} too new — upgrade sigil (never treated as clean)"
        return False, "corrupt head — cannot parse (run `sigil sign` to re-anchor)"
    if head.schema_version > _MAX_HEAD_SCHEMA:
        return False, f"head schema v{head.schema_version} too new — upgrade sigil (never treated as clean)"
    return classify_head(head, store.entries(), trust_root())
