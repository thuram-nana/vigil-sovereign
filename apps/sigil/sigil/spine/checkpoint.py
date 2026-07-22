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
from .floor import Floor, FloorDowngrade, advance_floor, check_floor, floor_lock, load_floor
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
    # Owner PRIVATE key routes through the vault (audit G1): plaintext-unchanged until the operator
    # provisions a TPM-sealed KEK, then transparently sealed at rest. The PUBLIC key stays plaintext.
    from ..platform.vault import OWNER_PRIV_CONTEXT, owner_vault
    vault = owner_vault()
    priv = vault.read_text_secret(_PRIV, context=OWNER_PRIV_CONTEXT)
    if priv is None:
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        kp = generate_keypair()
        vault.write_text_secret(_PRIV, kp.private_key_b64, context=OWNER_PRIV_CONTEXT)
        _PUB.write_text(kp.public_key_b64, encoding="utf-8")
        priv = kp.private_key_b64
    return priv, _PUB.read_text(encoding="utf-8").strip()


def trust_root() -> TrustRoot:
    _, pub = _owner_keys()
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id=OWNER_KEY_ID, name="owner", public_key_b64=pub)])


def _read_head_on_disk() -> SignedChainHead | None:
    """The current head.json parsed, or None (absent / unparseable). Used only as a best-effort monotonic
    race guard — never a security boundary (the floor is)."""
    try:
        if not HEAD_PATH.exists():
            return None
        return SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a corrupt/future-schema on-disk head has no comparable count
        return None


def checkpoint(store: SpineStore | None = None, *, force: bool = False) -> SignedChainHead:
    """Sign the spine head + advance the durable anti-rollback floor as one critical section under a single
    `floor_lock` (best-effort on non-POSIX / an unwritable home — see floor_lock), so two racing
    checkpoint() callers do not leave head.json and floor.json inconsistent, and neither the head nor the
    floor is rolled BACKWARDS by a stale concurrent signer. `force=True` (the `sigil floor reset` path)
    re-anchors a deliberately SHORTER spine — it skips the monotonic head guard; the caller then
    force-lowers the floor."""
    store = store or SpineStore()
    priv, _ = _owner_keys()
    head = sign_head(store.entries(), engagement_slug=SCOPE, signers=[(OWNER_KEY_ID, priv)])
    with floor_lock():                                      # serialize head+floor commit across all callers
        if not force:
            # MONOTONIC HEAD GUARD: never roll head.json back to a shorter head — a concurrent checkpoint()
            # that already committed a LONGER head (and advanced the floor to it) would otherwise be undone
            # on disk, and the (higher) floor would then spurious-TAMPER the shorter head we wrote.
            disk = _read_head_on_disk()
            if disk is not None and disk.entry_count > head.entry_count:
                return disk                                 # our sign is stale; the newer head stands
        _atomic_write_text(HEAD_PATH, head.model_dump_json())   # FIX 3: never leave a torn head on a crash
        # Advance the floor UNDER THE SAME LOCK (re-loads prior inside advance -> last-writer-monotonic).
        # BEST-EFFORT so a floor problem never bricks signing (consolidate + warden-anchor route here too),
        # AND a not-advanced floor only ever REJECTS MORE — never a false-CLEAN — so warning is fail-SAFE.
        try:
            advance_floor(head, _locked=True)
        except FloorDowngrade as e:                         # the INTENDED downward-refusal (e.g. post-reset) — benign
            import sys
            print(f"warning: durable anti-rollback floor not advanced ({e}); run `sigil floor reset` after "
                  f"a deliberate reset/restore", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — a REAL IO/write/corrupt-or-wrong-scope-load failure — surface loudly
            import sys
            print(f"ERROR: durable anti-rollback floor WRITE FAILED ({e}) — the floor may be stale; "
                  f"investigate before trusting `sigil verify`", file=sys.stderr)
    return head


def classify_head(head: SignedChainHead, entries: list, tr: TrustRoot,
                  *, floor: Floor | None = None) -> tuple[bool, str]:
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
    # DURABLE EXTERNAL FLOOR (hard-prune C1) — runs AFTER the in-band signature check, so it only ever
    # ADDS a rejection: a VALIDLY-signed but STALE head is caught here by the monotonic floor / meta-chain,
    # which the in-band signature cannot catch on its own. HONEST SCOPE (do not overclaim): this catches a
    # stale head ONLY when `floor` is a NEWER value the attacker did NOT roll back — i.e. an OUT-OF-BAND
    # verifier holding a retained floor (a paired device over WireGuard), or the routine `--reset` path
    # (the floor survives the spine-dir rmtree). It does NOT stop a same-host attacker who can also rewrite
    # the UNSIGNED floor.json: the local verify reads the floor fresh from that same attacker-controlled
    # disk, rolling head.json and floor.json back together (see floor.py HONEST LIMIT). No floor -> pass
    # (byte-identical to pre-floor).
    ok_floor, floor_msg = check_floor(head, floor)
    if not ok_floor:
        return False, f"TAMPERING: {floor_msg}"
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
    try:
        floor = load_floor()                                # None if absent -> byte-identical to pre-floor
    except Exception as e:  # noqa: BLE001 — a PRESENT-but-corrupt floor is suspicious; fail CLOSED, never clean
        return False, f"durable anti-rollback floor unreadable — refuse to certify (possible tamper): {e}"
    return classify_head(head, store.entries(), trust_root(), floor=floor)
