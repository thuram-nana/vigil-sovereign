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
    KeyPair,
    SignedChainHead,
    TrustRoot,
    generate_keypair,
    sign_head,
    verify_head,
)
from .atomicio import atomic_write_text
from .floor import (
    Floor,
    FloorDowngrade,
    advance_floor,
    check_floor,
    floor_lock,
    load_floor,
    verify_floor_signature,
)
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


def trust_root(store: SpineStore | None = None) -> TrustRoot:
    """The 1-of-1 head trust root, W9-1 SUCCESSION-AWARE. The anchor is the CURRENT owner key AS VALIDATED
    by walking the cross-signed succession chain from the pinned genesis — not the raw on-disk `owner.pub`.
    So a head (which `checkpoint()` always re-signs with the current key on every rotation) verifies under
    the succession tip, while an owner.pub swapped in WITHOUT a valid cross-signed succession record does not
    become trusted (its signer is not the succession tip). With no rotation, the tip == the on-disk key, so
    this is byte-identical to the pre-W9-1 single-key root. A forked/ambiguous succession falls back to the
    on-disk current key (the grant folds independently fail closed on a fork)."""
    _, pub = _owner_keys()                                     # current on-disk key (also ensures one exists)
    from ..governor import key_history as _kh
    st = store or SpineStore()
    # The genesis pin lives beside the owner key (`_PUB.parent`), so a test that monkeypatches this module's
    # KEYS_DIR/_PUB is respected, and prod reads the same file `identity.pin_genesis` writes. Absent a pin
    # (no rotation), the current key IS the genesis.
    genesis = pub
    try:
        txt = (_PUB.parent / "owner.genesis.pub").read_text(encoding="utf-8").strip()
        if txt:
            genesis = txt
    except OSError:
        pass
    try:
        succ = _kh.succession_from_store(st, genesis_pubkey=genesis)
        current = succ.current or pub
    except _kh.SuccessionError:
        current = pub                                         # forked → do not widen; keep the on-disk key
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id=OWNER_KEY_ID, name="owner", public_key_b64=current)])


def _read_head_on_disk() -> SignedChainHead | None:
    """The current head.json parsed, or None (absent / unparseable). Used only as a best-effort monotonic
    race guard — never a security boundary (the floor is)."""
    try:
        if not HEAD_PATH.exists():
            return None
        return SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a corrupt/future-schema on-disk head has no comparable count
        return None


class CheckpointRefused(RuntimeError):
    """`checkpoint()` refuses to sign: the live window starts above seq 0 (a hard prune dropped [0..K)) but
    no verifying owner-signed PRUNED head stands to carry the prune boundary forward. Signing a plain head
    there would anchor the retained window as if it were the whole spine and every snapshot-seeded fold
    would read the EMPTY seed (kill switch released, wallets 0) — so this fails closed instead."""


_REFUSE_HOWTO = ("Restore the spine directory (segments, manifest AND head.json) together from the latest "
                 "backup taken at or after the prune — `sigil sign` cannot re-create the owner-signed prune "
                 "boundary, and nothing should be signed until a verifying pruned head stands.")


def _head_is_pruned(head: SignedChainHead) -> bool:
    return head.base_seq > 0 or head.snapshot_seq >= 0


def _verify_standing_pruned(store: SpineStore, head: SignedChainHead, entries: list,
                            *, use_floor: bool) -> tuple[bool, str]:
    """Does the on-disk PRUNED `head` verify, so its boundary may be carried forward? The owner signature is
    checked under the current trust root, or — after a `sigil key rotate` (which re-signs right after
    appending the rotation) — under the owner key the cross-signed succession says was valid at the head's
    own `last_seq` (the same "key valid at that seq" rule every grant fold uses). `use_floor=False` is the
    `sigil floor reset` path: the floor is being deliberately re-seeded, so a stale-floor rejection must not
    block re-anchoring a legitimately restored post-prune spine — the signature and window shape still must
    hold. The snapshot record the head names must sit in its signed window and match its boundary."""
    if not (head.base_seq <= head.snapshot_seq <= head.last_seq):
        return False, f"snapshot seq {head.snapshot_seq} is outside the signed window"
    rec = store.get(head.snapshot_seq)
    if rec is None or rec.kind != "snapshot" or not isinstance(rec.payload, dict) \
            or rec.payload.get("base_seq") != head.base_seq:
        return False, f"snapshot record {head.snapshot_seq} is absent or does not match the head's boundary"
    try:
        floor = load_floor() if use_floor else None
    except Exception as e:  # noqa: BLE001 — a present-but-corrupt floor never certifies a carry-forward
        return False, f"durable floor unreadable: {e}"
    try:
        tr = trust_root(store)
        ok, why = classify_head(head, entries, tr, floor=floor)
        if ok:
            return ok, why
        from ..governor import key_history as _kh
        current = tr.authorizers[0].public_key_b64 if tr.authorizers else None
        at = _kh.key_resolver(store, current=current).at(head.last_seq)
        if at and at != current:
            tr_at = TrustRoot(threshold=1, authorizers=[
                AuthorizerKey(key_id=OWNER_KEY_ID, name="owner", public_key_b64=at)])
            return classify_head(head, entries, tr_at, floor=floor)
        return ok, why
    except Exception as e:  # noqa: BLE001 — malformed signature/key material never certifies (as verify_checkpoint)
        return False, f"head signature/key material is malformed: {e}"


def standing_pruned_head(store: SpineStore, *, use_floor: bool = True,
                         entries: list | None = None) -> SignedChainHead | None:
    """The verifying owner-signed PRUNED head whose boundary every new head must carry forward, or None for
    a spine that holds its full history from genesis. RAISES `CheckpointRefused` when the live window starts
    above seq 0 but no verifying pruned head stands (head.json missing / unparseable / a plain head / a
    pruned head that does not verify). A non-verifying pruned head over a spine that still starts at seq 0
    (e.g. a pre-prune backup restored) returns None: that spine is complete from genesis, so a plain head
    over it loses nothing — exactly today's behaviour. Callers that mutate the spine before re-signing (key
    rotation) call this FIRST, so a refusal leaves the spine untouched."""
    first = store.first_live_seq()
    disk = _read_head_on_disk()
    if disk is not None and _head_is_pruned(disk):
        ok, why = _verify_standing_pruned(store, disk, store.entries() if entries is None else entries,
                                          use_floor=use_floor)
        if ok:
            return disk
        if first is not None and first > 0:
            raise CheckpointRefused(f"refusing to sign: the live spine starts at seq {first} (records below it "
                                    f"were pruned) and the standing pruned head does not verify ({why}). "
                                    f"{_REFUSE_HOWTO}")
        return None
    if first is not None and first > 0:
        state = "no signed head is present" if disk is None and not HEAD_PATH.exists() else (
            "head.json is unreadable" if disk is None else "the signed head declares no prune")
        raise CheckpointRefused(f"refusing to sign: the live spine starts at seq {first} (records below it were "
                                f"pruned) but {state}. {_REFUSE_HOWTO}")
    return None


def _sign_v2_head(priv: str, live: list, *, base_seq: int, base_prev_hash: str, cumulative_merkle_root: str,
                  snapshot_seq: int, prev_head_hash: str) -> SignedChainHead:
    """Owner-sign a v2 (pruned) head over the retained live window `live` (records with seq >= base_seq)."""
    from vigil_core.chain import _head_payload     # defined in vigil_core (the reuse.* shims are runtime-only)

    from ..reuse import Signature, evidence_signing_bytes, sign
    head = SignedChainHead(
        schema_version=2, engagement_slug=SCOPE, last_seq=live[-1].seq,
        entry_count=base_seq + len(live), head_hash=live[-1].entry_hash,
        base_seq=base_seq, base_prev_hash=base_prev_hash, base_count=base_seq,
        cumulative_merkle_root=cumulative_merkle_root, snapshot_seq=snapshot_seq,
        prev_head_hash=prev_head_hash)
    msg = evidence_signing_bytes(_head_payload(head))
    return head.model_copy(update={"signatures": [Signature(key_id=OWNER_KEY_ID, signature_b64=sign(priv, msg))]})


def checkpoint(store: SpineStore | None = None, *, force: bool = False) -> SignedChainHead:
    """Sign the spine head + advance the durable anti-rollback floor as one critical section under a single
    `floor_lock` (best-effort on non-POSIX / an unwritable home — see floor_lock), so two racing
    checkpoint() callers do not leave head.json and floor.json inconsistent, and neither the head nor the
    floor is rolled BACKWARDS by a stale concurrent signer. `force=True` (the `sigil floor reset` path)
    re-anchors a deliberately SHORTER spine — it skips the monotonic head guard; the caller then
    force-lowers the floor.

    PRUNE-AWARE: after a hard prune the new head RE-SIGNS the standing owner-signed prune boundary
    (base_seq, base_prev_hash, cumulative Merkle root, snapshot seq) over the grown live window, so every
    snapshot-seeded fold keeps its seed. When the live window starts above seq 0 but no verifying pruned head
    stands, it RAISES `CheckpointRefused` and writes nothing (see `standing_pruned_head`). A spine that was
    never pruned signs exactly as before (a v1 head over every record)."""
    store = store or SpineStore()
    priv, pub = _owner_keys()
    owner_kp = KeyPair(public_key_b64=pub, private_key_b64=priv)   # G2: sign the durable floor too
    entries = store.entries()
    seen = _read_head_on_disk()                             # the head our decision is based on (race guard)
    standing = standing_pruned_head(store, use_floor=not force, entries=entries)
    if standing is None:
        head = sign_head(entries, engagement_slug=SCOPE, signers=[(OWNER_KEY_ID, priv)])
    with floor_lock():                                      # serialize head+floor commit across all callers
        if standing is not None:
            # meta-chain parent = the floor's recorded head, read UNDER the lock (as advance_floor re-reads it)
            try:
                prior_floor = load_floor()
            except Exception:  # noqa: BLE001 — a corrupt floor: sign unlinked; verify then fails closed on it
                prior_floor = None
            live = [e for e in entries if e.seq >= standing.base_seq]
            head = _sign_v2_head(priv, live, base_seq=standing.base_seq, base_prev_hash=standing.base_prev_hash,
                                 cumulative_merkle_root=standing.cumulative_merkle_root,
                                 snapshot_seq=standing.snapshot_seq,
                                 prev_head_hash=(prior_floor.head_sig_hash if prior_floor is not None else ""))
        disk = _read_head_on_disk()
        if disk is not None and disk != seen and disk.base_seq > head.base_seq:
            # A prune committed after we read the spine: never overwrite its pruned head with a head that
            # does not carry the boundary (that is exactly the empty-seed fail-open). The newer head stands.
            return disk
        if not force:
            # MONOTONIC HEAD GUARD: never roll head.json back to a shorter head — a concurrent checkpoint()
            # that already committed a LONGER head (and advanced the floor to it) would otherwise be undone
            # on disk, and the (higher) floor would then spurious-TAMPER the shorter head we wrote.
            if disk is not None and disk.entry_count > head.entry_count:
                return disk                                 # our sign is stale; the newer head stands
        _atomic_write_text(HEAD_PATH, head.model_dump_json())   # FIX 3: never leave a torn head on a crash
        # Advance the floor UNDER THE SAME LOCK (re-loads prior inside advance -> last-writer-monotonic).
        # BEST-EFFORT so a floor problem never bricks signing (consolidate + warden-anchor route here too),
        # AND a not-advanced floor only ever REJECTS MORE — never a false-CLEAN — so warning is fail-SAFE.
        try:
            advance_floor(head, owner_key=owner_kp, _locked=True)   # G2: owner-signed floor
        except FloorDowngrade as e:                         # the INTENDED downward-refusal (e.g. post-reset) — benign
            import sys
            print(f"warning: durable anti-rollback floor not advanced ({e}); run `sigil floor reset` after "
                  f"a deliberate reset/restore", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — a REAL IO/write/corrupt-or-wrong-scope-load failure — surface loudly
            import sys
            print(f"ERROR: durable anti-rollback floor WRITE FAILED ({e}) — the floor may be stale; "
                  f"investigate before trusting `sigil verify`", file=sys.stderr)
    return head


def sign_pruned_head(store: SpineStore, *, base_seq: int, base_prev_hash: str,
                     cumulative_merkle_root: str, snapshot_seq: int) -> SignedChainHead:
    """Sign the v2 (cold-archive hard-prune) head over the RETAINED live window [base_seq..T] — the DURABLE
    COMMIT of a prune (hard-prune Slice E). Written + floor-advanced under a single `floor_lock`, exactly
    like `checkpoint()`, so it is the crash-atomic commit instant: a crash BEFORE this leaves the un-pruned
    spine (the head still anchors [0..T]); a crash AFTER it leaves a validly-signed pruned head that
    classify_head verifies over the live window whether or not the manifest/segment GC has caught up.

    The live window is selected BY SEQ (`>= base_seq`) from the CURRENT store, so this is correct while the
    pruned prefix segments are still physically present (the manifest rebase runs AFTER this). base_count ==
    base_seq (the pruned prefix [0..base_seq) is contiguous from genesis). The meta-chain `prev_head_hash` is
    set to the durable floor's recorded head hash so `advance_floor`'s v2 meta-chain guard accepts this head
    as the parent's child. Raises if the retained window does not actually start at base_seq/base_prev_hash
    (a caller bug — never silently sign a mismatched anchor), or if a LONGER head already stands (rollback)."""
    priv, pub = _owner_keys()
    owner_kp = KeyPair(public_key_b64=pub, private_key_b64=priv)
    live = [e for e in store.entries() if e.seq >= base_seq]
    if not live or live[0].seq != base_seq or live[0].prev_hash != base_prev_hash:
        raise ValueError(
            f"pruned head anchor mismatch: retained window must start at seq {base_seq} linking from "
            f"{base_prev_hash[:12]}… (got {'<empty>' if not live else f'{live[0].seq}/{live[0].prev_hash[:12]}…'})")
    prior_floor = load_floor()
    head = _sign_v2_head(priv, live, base_seq=base_seq, base_prev_hash=base_prev_hash,
                         cumulative_merkle_root=cumulative_merkle_root, snapshot_seq=snapshot_seq,
                         prev_head_hash=(prior_floor.head_sig_hash if prior_floor is not None else ""))
    with floor_lock():                                     # head + floor commit as one critical section
        disk = _read_head_on_disk()
        if disk is not None and disk.entry_count > head.entry_count:
            raise ValueError(f"refusing to write a pruned head with entry_count {head.entry_count} < the "
                             f"on-disk head's {disk.entry_count} (would roll the spine back)")
        _atomic_write_text(HEAD_PATH, head.model_dump_json())
        advance_floor(head, owner_key=owner_kp, _locked=True)   # UPWARD (entry_count/base_seq both grow)
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
    # (the floor survives the spine-dir rmtree). Because floor.json is now owner-SIGNED (checked just below),
    # a keyless same-host attacker can no longer roll it DOWN under a valid signature — but can still STRIP
    # it to unsigned or DELETE it, reverting to a "no floor" state this purely-local verify cannot tell from
    # never-flooded (see floor.py HONEST LIMIT + floor_witness.py for the out-of-band anchor that catches
    # it). No floor -> pass (byte-identical to pre-floor).
    # G2: the floor's OWN owner-signature, verified against the SAME trust anchor (`tr`) that just verified
    # the head — a tampered SIGNED floor (content rewritten under a stale sig, or signed by a non-owner key)
    # is TAMPERING; an UNSIGNED legacy floor is accepted (warned once) so pre-signing spines still verify.
    if floor is not None:
        ok_sig, sig_msg = verify_floor_signature(floor, {a.public_key_b64 for a in tr.authorizers})
        if not ok_sig:
            return False, f"TAMPERING: {sig_msg}"
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
    try:
        return classify_head(head, store.entries(), trust_root(store), floor=floor)
    except Exception as e:  # noqa: BLE001 — malformed head sig/key material (e.g. non-base64) makes verify_one
        # raise; a PRESENT head whose signature material is malformed is TAMPER — fail CLOSED with a clean
        # head-FAIL (so `sigil verify` exits 2), never an uncaught traceback (exit 1).
        return False, f"head signature/key material is malformed — refuse to certify (possible tamper): {e}"
