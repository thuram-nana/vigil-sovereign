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
    head_sig_hash,
    load_floor,
    verify_floor_signature,
)
from .store import SpineStore

from vigil_core.models import _GENESIS_PREV  # noqa: E402  (the genesis prev_hash)

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
    # The shared loader mints ONLY on a fresh install (neither file present); a half-present, unreadable,
    # unsealable or mismatched key raises OwnerKeyUnavailable instead of replacing the owner identity.
    from ..governor.identity import load_or_init_owner_keypair
    kp = load_or_init_owner_keypair(_PRIV, _PUB, KEYS_DIR)
    return kp.private_key_b64, kp.public_key_b64


def _genesis_pin(pub: str) -> str:
    """The pinned genesis owner key (`owner.genesis.pub`, beside the owner key), or `pub` absent a pin."""
    # The genesis pin lives beside the owner key (`_PUB.parent`), so a test that monkeypatches this module's
    # KEYS_DIR/_PUB is respected, and prod reads the same file `identity.pin_genesis` writes. Absent a pin
    # (no rotation), the current key IS the genesis.
    try:
        txt = (_PUB.parent / "owner.genesis.pub").read_text(encoding="utf-8").strip()
        if txt:
            return txt
    except OSError:
        pass
    return pub


def owner_succession(store: SpineStore | None = None):
    """The validated cross-signed owner-key succession walked from the pinned genesis
    (`governor.key_history.Succession`), or None when it is forked/ambiguous (`SuccessionError`). Full scan."""
    _, pub = _owner_keys()                                     # current on-disk key (also ensures one exists)
    from ..governor import key_history as _kh
    try:
        return _kh.succession_from_store(store or SpineStore(), genesis_pubkey=_genesis_pin(pub))
    except _kh.SuccessionError:
        return None


def trust_root(store: SpineStore | None = None) -> TrustRoot:
    """The 1-of-1 head trust root, W9-1 SUCCESSION-AWARE. The anchor is the CURRENT owner key AS VALIDATED
    by walking the cross-signed succession chain from the pinned genesis — not the raw on-disk `owner.pub`.
    So a head (which `checkpoint()` always re-signs with the current key on every rotation) verifies under
    the succession tip, while an owner.pub swapped in WITHOUT a valid cross-signed succession record does not
    become trusted (its signer is not the succession tip). With no rotation, the tip == the on-disk key, so
    this is byte-identical to the pre-W9-1 single-key root. A forked/ambiguous succession falls back to the
    on-disk current key (the grant folds independently fail closed on a fork)."""
    _, pub = _owner_keys()                                     # current on-disk key (also ensures one exists)
    succ = owner_succession(store)
    current = (succ.current if succ is not None else "") or pub   # forked → do not widen; keep the on-disk key
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


def _advance_floor_best_effort(head: SignedChainHead, owner_kp: KeyPair) -> None:
    """Advance the floor UNDER THE CALLER'S `floor_lock` (re-loads prior inside advance -> last-writer-
    monotonic). BEST-EFFORT so a floor problem never bricks signing (consolidate + warden-anchor route here
    too), AND a not-advanced floor only ever REJECTS MORE — never a false-CLEAN — so warning is fail-SAFE."""
    import sys
    try:
        advance_floor(head, owner_key=owner_kp, _locked=True)   # G2: owner-signed floor
    except FloorDowngrade as e:                         # the INTENDED downward-refusal (e.g. post-reset) — benign
        print(f"warning: durable anti-rollback floor not advanced ({e}); run `sigil floor reset` after "
              f"a deliberate reset/restore", file=sys.stderr)
    except Exception as e:  # noqa: BLE001 — a REAL IO/write/corrupt-or-wrong-scope-load failure — surface loudly
        print(f"ERROR: durable anti-rollback floor WRITE FAILED ({e}) — the floor may be stale; "
              f"investigate before trusting `sigil verify`", file=sys.stderr)


def checkpoint(store: SpineStore | None = None, *, force: bool = False,
               carry: SignedChainHead | None = None, admit_incumbent: bool = False) -> SignedChainHead:
    """Sign the spine head + advance the durable anti-rollback floor as one critical section under a single
    `floor_lock` (best-effort on non-POSIX / an unwritable home — see floor_lock), so two racing
    checkpoint() callers do not leave head.json and floor.json inconsistent, and neither the head nor the
    floor is rolled BACKWARDS by a stale concurrent signer. `force=True` (the `sigil floor reset` path)
    re-anchors a deliberately SHORTER spine — it skips the monotonic head guard; the caller then
    force-lowers the floor. `carry` / `admit_incumbent`: see `standing_pruned_head` (an owner-key rotation)."""
    store = store or SpineStore()
    priv, pub = _owner_keys()
    owner_kp = KeyPair(public_key_b64=pub, private_key_b64=priv)   # G2: sign the durable floor too
    entries = store.entries()
    judged = _read_head_on_disk()
    standing = standing_pruned_head(store, entries, use_floor=not force, carry=carry,
                                    admit_incumbent=admit_incumbent)
    if standing is not None:
        # A HARD-PRUNED spine is re-anchored as a pruned (v2) head that carries the committed boundary forward.
        # A plain v1 head here would declare "no prune" over the retained window: `verify_checkpoint` then
        # reports tampering, and every seeded fold reads an EMPTY seed over a truncated window — the kill
        # switch released, wallets zero — silently.
        try:
            return sign_pruned_head(store, base_seq=standing.base_seq, base_prev_hash=standing.base_prev_hash,
                                    cumulative_merkle_root=standing.cumulative_merkle_root,
                                    snapshot_seq=standing.snapshot_seq, force=force, reanchor=True)
        except _StaleSign:
            return _read_head_on_disk() or standing        # a longer head already stands (monotonic guard)
    head = sign_head(entries, engagement_slug=SCOPE, signers=[(OWNER_KEY_ID, priv)])
    with floor_lock():                                      # serialize head+floor commit across all callers
        disk = _read_head_on_disk()
        if disk is not None and disk.snapshot_seq >= 0:
            # A prune COMMITTED after we read the spine (its pruned head landed between our read and this lock):
            # never overwrite it with a plain head — that is exactly the empty-seed fail-open. It stands. The one
            # exception is `sigil floor reset --yes` (force) over a spine that was reset to genesis: the pruned
            # head it judged no longer describes the spine, and only that very head is superseded.
            if not (force and judged is not None and head_sig_hash(disk) == head_sig_hash(judged)):
                return disk
        if not force:
            # MONOTONIC HEAD GUARD: never roll head.json back to a shorter head — a concurrent checkpoint()
            # that already committed a LONGER head (and advanced the floor to it) would otherwise be undone
            # on disk, and the (higher) floor would then spurious-TAMPER the shorter head we wrote.
            if disk is not None and disk.entry_count > head.entry_count:
                return disk                                 # our sign is stale; the newer head stands
        _atomic_write_text(HEAD_PATH, head.model_dump_json())   # FIX 3: never leave a torn head on a crash
        _advance_floor_best_effort(head, owner_kp)
    return head


class _StaleSign(ValueError):
    """A longer head already stands on disk: this sign is stale (the monotonic head guard)."""


class CheckpointRefused(ValueError):
    """`checkpoint()` refuses to sign, and writes nothing: the spine was hard-pruned (its live window starts above
    seq 0) but no verifying owner-signed pruned head stands to carry the prune boundary forward. A plain head
    there would anchor the retained window as the whole spine and every snapshot-seeded fold would read an
    EMPTY seed (the kill switch released, wallets zero). `sigil` exits 2 with the message."""


def _incumbent_key(store: SpineStore) -> "str | None":
    """The owner key the validated succession retired LAST (the tip's predecessor), or None (no rotation, or a
    forked succession)."""
    succ = owner_succession(store)
    if succ is None or len(succ.epochs) < 2:
        return None
    return succ.epochs[-2].pubkey


def _verifies_under(disk: SignedChainHead, entries: list, key: str, floor) -> "tuple[bool, str]":
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id=OWNER_KEY_ID, name="owner",
                                                           public_key_b64=key)])
    try:
        return classify_head(disk, entries, tr, floor=floor)
    except Exception as e:  # noqa: BLE001 — malformed signature material: not this key
        return False, f"malformed signature material ({type(e).__name__})"


def standing_pruned_head(store: SpineStore, entries: list | None = None, *, use_floor: bool = True,
                         carry: SignedChainHead | None = None,
                         admit_incumbent: bool = False) -> SignedChainHead | None:
    """The standing head iff it COMMITS A PRUNE that this spine still matches — signed by the owner key the trust
    root names (the validated succession tip) over a live window that starts exactly at its `base_seq` /
    `base_prev_hash`, and within the durable floor (`use_floor=False` only for `sigil floor reset`, which
    re-seeds the floor). None for an un-pruned spine. Raises `CheckpointRefused` (fail CLOSED — nothing is
    signed) when the live window does not start at genesis yet no such head stands: there is then no owner-signed
    boundary to carry forward, and a fresh head would silently un-prune the spine. Commands that MUTATE the spine
    before re-signing (`key rotate`, `warden-anchor-set`, `consolidate --sign`) call this first, so a refusal
    leaves the spine untouched.

    ONLY the tip's key. A head signed by any other key — including the key a rotation just retired — is never
    carried forward on its own say-so: the head names its own `last_seq`, so "the key valid at last_seq" is the
    signer's choice, and a holder of a retired key (often the very reason for the rotation) could otherwise sign a
    head over a forged snapshot that the next routine sign launders under the current key. A rotation re-anchors
    instead from the head it validated BEFORE rotating (`carry`: that exact head, still on disk — `sigil key
    rotate` does this in one process). A rotation interrupted before it re-signed is finished only by the owner's
    explicit `sigil key rotate --finish --yes` (`admit_incumbent`: the retired key's head, within the floor)."""
    disk = _read_head_on_disk()
    if entries is None and (disk is None or disk.snapshot_seq < 0):
        # A pre-flight on a spine whose head declares no prune: only the live window's start matters, and the
        # manifest gives it in O(1) (`checkpoint()` itself passes the real entries and re-checks on them).
        from .snapshot import live_window_start
        first = live_window_start(store)
        entries = []
    else:
        if entries is None:
            entries = store.entries()
        first = entries[0].seq if entries else 0
    if disk is None or disk.snapshot_seq < 0:
        if first != 0:
            raise CheckpointRefused(
                f"refusing to sign a head: the spine's live window starts at seq {first} (a hard-pruned spine) "
                f"but no owner-signed pruned head stands to carry its boundary forward. {_PRUNED_RECOVERY} "
                f"Re-signing cannot fix this: a fresh head would declare no prune and every seeded fold would "
                f"read an empty seed")
        return None
    if carry is not None and head_sig_hash(disk) == head_sig_hash(carry):
        return disk                                        # validated by this process before it rotated the key
    try:
        floor = load_floor() if use_floor else None
    except Exception as e:  # noqa: BLE001 — a present-but-corrupt floor never certifies a carry-forward
        raise CheckpointRefused(f"refusing to sign a head: the durable anti-rollback floor is unreadable ({e}) "
                                f"— run `sigil verify`; if the spine is genuine and only the floor is damaged, "
                                f"`sigil floor reset --yes` re-seeds it") from e
    tip_keys = [a.public_key_b64 for a in trust_root(store).authorizers]
    why = ""
    for key in tip_keys:
        ok, why = _verifies_under(disk, entries, key, floor)
        if ok:
            return disk                    # (incl. a prune's crash window: the prefix is still on disk)
    if first == 0 and (not entries or entries[0].prev_hash == _GENESIS_PREV):
        # The spine starts at GENESIS and the head that declares a prune does not match it: the spine was reset
        # or replaced (`sigil ingest --reset`, a restore). There is no boundary left to carry. Only the owner's
        # deliberate `sigil floor reset --yes` (force) re-anchors it as an un-pruned spine.
        if not use_floor:
            return None
        raise CheckpointRefused(
            f"refusing to sign a head: the spine starts at genesis but the signed head declares a prune (base_seq "
            f"{disk.base_seq}) that does not match it — the spine was reset or replaced. If that was deliberate, "
            f"re-anchor it with `sigil floor reset --yes`; otherwise run `sigil verify` and treat it as tampering")
    incumbent = _incumbent_key(store)
    if incumbent is not None and incumbent not in tip_keys:
        ok_inc, why_inc = _verifies_under(disk, entries, incumbent, floor)
        if ok_inc and admit_incumbent and floor is not None:
            return disk                                    # the owner finishes an interrupted rotation
        if ok_inc:
            raise CheckpointRefused(
                f"refusing to sign a head: the standing pruned head (base_seq {disk.base_seq}) is signed by the "
                f"PREVIOUS owner key, not the current one. If a `sigil key rotate` was interrupted before it "
                f"re-signed, finish it with `sigil key rotate --finish --yes`; otherwise the head is a forgery by "
                f"a holder of the retired key — run `sigil verify` and do not re-sign")
    if floor is not None and any(_verifies_under(disk, entries, k, None)[0] for k in tip_keys):
        raise CheckpointRefused(
            f"refusing to sign a head: the standing pruned head (base_seq {disk.base_seq}) verifies under the owner "
            f"key but not against the durable anti-rollback floor ({why}) — a rolled-back head? Run `sigil "
            f"verify`; after a deliberate restore, `sigil floor reset --yes` re-seeds the floor")
    raise CheckpointRefused(
        f"refusing to sign a head: the standing head declares a prune (base_seq {disk.base_seq}, snapshot "
        f"{disk.snapshot_seq}) but does not verify over this spine under the owner key ({why}) — its boundary "
        f"cannot be trusted or carried forward. Run `sigil verify`. {_PRUNED_RECOVERY}")


_PRUNED_RECOVERY = ("Recover by putting back the `spine/head.json` this spine was pruned under (from a file-level "
                    "copy of SIGIL_HOME), then `sigil verify`; `sigil restore` does not yet restore a hard-pruned "
                    "spine.")


def sign_pruned_head(store: SpineStore, *, base_seq: int, base_prev_hash: str,
                     cumulative_merkle_root: str, snapshot_seq: int, force: bool = False,
                     reanchor: bool = False) -> SignedChainHead:
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
    from vigil_core.chain import _head_payload     # defined in vigil_core (the reuse.* shims are runtime-only)

    from ..reuse import Signature, evidence_signing_bytes, sign
    priv, pub = _owner_keys()
    owner_kp = KeyPair(public_key_b64=pub, private_key_b64=priv)
    live = [e for e in store.entries() if e.seq >= base_seq]
    if not live or live[0].seq != base_seq or live[0].prev_hash != base_prev_hash:
        raise ValueError(
            f"pruned head anchor mismatch: retained window must start at seq {base_seq} linking from "
            f"{base_prev_hash[:12]}… (got {'<empty>' if not live else f'{live[0].seq}/{live[0].prev_hash[:12]}…'})")
    with floor_lock():                                     # head + floor commit as one critical section
        # The meta-chain parent is the floor's recorded head, read UNDER the lock (as `advance_floor` re-reads
        # it): two concurrent re-anchors would otherwise both chain from the same parent, and the second head
        # would neither be the floor's head nor its child — a META-CHAIN BREAK that `sigil verify` reports.
        try:
            prior_floor = load_floor()
        except Exception:  # noqa: BLE001 — only `sigil floor reset` (force) signs past a damaged floor: it
            if not force:   # re-seeds it right after; every other signer refuses (standing_pruned_head)
                raise
            prior_floor = None
        head = SignedChainHead(
            schema_version=2, engagement_slug=SCOPE, last_seq=live[-1].seq,
            entry_count=base_seq + len(live), head_hash=live[-1].entry_hash,
            base_seq=base_seq, base_prev_hash=base_prev_hash, base_count=base_seq,
            cumulative_merkle_root=cumulative_merkle_root, snapshot_seq=snapshot_seq,
            prev_head_hash=(prior_floor.head_sig_hash if prior_floor is not None else ""))
        msg = evidence_signing_bytes(_head_payload(head))
        head = head.model_copy(update={"signatures": [Signature(key_id=OWNER_KEY_ID,
                                                                 signature_b64=sign(priv, msg))]})
        disk = _read_head_on_disk()
        if not force and disk is not None and disk.entry_count > head.entry_count:
            raise _StaleSign(f"refusing to write a pruned head with entry_count {head.entry_count} < the "
                             f"on-disk head's {disk.entry_count} (would roll the spine back)")
        _atomic_write_text(HEAD_PATH, head.model_dump_json())
        if reanchor:                                       # `checkpoint()` of an already-pruned spine
            _advance_floor_best_effort(head, owner_kp)
        else:                                              # the prune COMMIT: the floor must move with it
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
        from .snapshot import live_window_start
        k = live_window_start(store)
        if k > 0:
            return False, (f"no signed head on a hard-pruned spine (the live window starts at seq {k}) — `sigil "
                           f"sign` cannot re-anchor a pruned spine without its head. {_PRUNED_RECOVERY}")
        return False, "no signed head — run `sigil sign` to anchor the spine"
    raw = HEAD_PATH.read_text(encoding="utf-8")
    try:
        head = SignedChainHead.model_validate_json(raw)     # a future-schema head fails extra="forbid" here
    except Exception:  # noqa: BLE001 — never crash + never false-clean: distinguish "too new" from "corrupt"
        try:
            sv = int(json.loads(raw).get("schema_version", 1))
        except (ValueError, TypeError, AttributeError):
            sv = None
        if sv is not None and sv > _MAX_HEAD_SCHEMA:
            return False, f"head schema v{sv} too new — upgrade sigil (never treated as clean)"
        from .snapshot import live_window_start
        if live_window_start(store) > 0:                   # a pruned spine: a fresh sign would un-prune it
            return False, f"corrupt head on a hard-pruned spine — cannot parse; do not re-sign. {_PRUNED_RECOVERY}"
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
