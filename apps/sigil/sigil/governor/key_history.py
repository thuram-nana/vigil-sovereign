"""Owner-key ROTATION as a signed key HISTORY with cross-signed succession (W9-1, issue #434).

THE DEFECT this closes: VIGIL had no owner-key rotation at all. Every governance fold verified against a
SINGLE owner pubkey at threshold 1, so a naive key swap ORPHANED every historical head and grant (they were
signed by the retired key and no longer verified). This module ships the operator-chosen design: an
append-only owner-key history where each new owner key is CROSS-SIGNED by the incumbent, forming a
succession chain a verifier can walk from a PINNED genesis root.

WHAT CROSS-SIGNING BUYS:
  * `sig_prev` — the INCUMBENT signs the succession statement: only the holder of the retiring private key
    can authorize the successor (a rogue cannot self-succeed the owner).
  * `sig_new`  — the SUCCESSOR signs the SAME statement (proof-of-possession): the successor key is real and
    controlled (you cannot cross-sign to a key you do not hold, nor swap in a different `new_pubkey` without
    the incumbent re-signing — the incumbent signature is over `new_pubkey`).
Both sign the identical canonical core, so the record binds prev -> new atomically.

TIME-WINDOWED VALIDITY (the anti-orphan mechanism, and why routine rotation is also protective): each owner
key is valid only for spine records in its epoch's seq window `[start, end)`. A historical grant appended
under the key valid AT THAT TIME still verifies (not orphaned); a NEW forged grant an attacker mints with a
retired-but-stolen key lands at a seq OUTSIDE that key's window and is refused. That protection is why
rotation is worth doing — but it assumes the retired key was not adversary-held when it was current. For an
ACTUAL compromise of a still-current key, continuity is not worth preserving: use `re_genesis` (below).

FAIL-CLOSED on a broken/forked succession: a record that is not validly cross-signed, or does not chain from
the current tip, DOES NOT EXTEND the chain (it is ignored — so injecting garbage cannot advance or brick
verification). But a genuine FORK — the incumbent cross-signing TWO different successors at the same epoch —
is true authority ambiguity: `build_succession` raises `SuccessionError`, and every consumer treats that as
DENY (trust nothing until a `re_genesis`). A fork can only be produced by the owner private-key holder, so it
is not a denial-of-service vector for a non-key-holder.

RE-GENESIS (the compromise fallback): mint a brand-new genesis key and REPIN the genesis root to it. The
succession walk then starts from the new root; every pre-re-genesis key falls out of every window, so every
pre-re-genesis head, grant, and history record is DELIBERATELY ABANDONED — that is the point, since a
compromised key must no longer be able to forge anything the new system trusts. The cost, stated plainly, is
that verifiable CONTINUITY of pre-compromise history is lost (an out-of-band verifier pinned to the OLD
genesis will no longer chain to the new key — they must re-pin).

LIVE-ONLY RESIDUAL: the new private key is written through the owner vault
(`identity.set_owner_key`), which TPM-seals it at rest once a KEK is provisioned. The seal-to-real-hardware
step is exercised only on a host with a TPM; here the vault runs in plaintext-fallback mode and the
succession/rotation LOGIC is fully tested with generated keypairs and a temp SIGIL_HOME.

FATAL-2: sovereign-side. Imports only `vigil_core`/`reuse` crypto primitives + sibling sovereign modules —
never `framework`/`strix`.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Optional

from ..reuse import (
    IntegrityError,
    KeyPair,
    assert_no_offense,
    canonical_json,
    generate_keypair,
    sign,
    verify_one,
)
from ..reuse.crypto import load_public_key

assert_no_offense()

# The enforced spine record kind (W5-1 vocabulary) + the payload signal that tags an owner-key-history
# record among generic `kind="event"`... note we use a DEDICATED kind so the record is unmistakable and the
# W5-1 write-path guard admits it explicitly.
KEY_HISTORY_KIND = "owner_key_history"
SUCCESSION_SIGNAL = "owner.key_history"

MODE_ROTATE = "rotate"
MODE_REGENESIS = "re-genesis"

# The signed core (built by `_core`/`_core_from_payload`) is exactly {signal, mode, epoch, prev_pubkey,
# new_pubkey, issued_at}. BOTH `sig_prev` and `sig_new` sign its canonical bytes. `epoch` is an int and
# `issued_at` a float — both round-trip byte-stably through the spine's JSON, so verify matches sign.

_INF = math.inf


class SuccessionError(Exception):
    """A genuinely ambiguous / forked owner-key succession — authority cannot be resolved. Every consumer
    treats this as fail-closed DENY (trust nothing until a re-genesis re-establishes a single root)."""


@dataclass(frozen=True)
class Epoch:
    """One owner key and the seq window over which it was the authoritative signer. `end` is exclusive;
    `math.inf` for the current (open) epoch."""
    epoch: int
    pubkey: str
    start: int          # first seq this key is authoritative for (inclusive)
    end: float          # first seq it is NO LONGER authoritative for (exclusive); inf while current


@dataclass(frozen=True)
class Succession:
    genesis: str
    current: str
    epochs: tuple[Epoch, ...]

    @property
    def pubkeys(self) -> tuple[str, ...]:
        return tuple(e.pubkey for e in self.epochs)

    def pubkey_valid_at(self, seq: int) -> Optional[str]:
        """The owner pubkey authoritative for a record at spine `seq`, or None if none covers it
        (fail-closed). Records are validated under the key valid AT THEIR TIME — a grant signed by a
        retired key still verifies for its own epoch, and a forged grant minted with a retired key at a
        later seq is refused (that seq falls in a LATER key's window)."""
        for e in self.epochs:
            if e.start <= seq < e.end:
                return e.pubkey
        return None


def _core(mode: str, epoch: int, prev_pubkey: str, new_pubkey: str, issued_at: float) -> dict:
    return {"signal": SUCCESSION_SIGNAL, "mode": mode, "epoch": int(epoch),
            "prev_pubkey": prev_pubkey or "", "new_pubkey": new_pubkey or "", "issued_at": float(issued_at)}


def _core_from_payload(p: dict) -> dict:
    # Rebuild the signed core from a stored payload EXACTLY as it was signed (same field set + types).
    return {"signal": p.get("signal"), "mode": p.get("mode"), "epoch": p.get("epoch"),
            "prev_pubkey": p.get("prev_pubkey"), "new_pubkey": p.get("new_pubkey"),
            "issued_at": p.get("issued_at")}


def _canon(core: dict) -> bytes:
    m = canonical_json(core)
    return m if isinstance(m, bytes) else m.encode("utf-8")


def cross_sign(incumbent_key: Optional[KeyPair], new_key: KeyPair, *, epoch: int,
               prev_pubkey: str, mode: str = MODE_ROTATE, issued_at: float) -> dict:
    """Build a cross-signed owner-key-history payload.

    `mode=rotate`: the incumbent (holder of `prev_pubkey`) signs `sig_prev` and the successor signs `sig_new`
    over the SAME core. `mode=re-genesis`: there is no incumbent — `prev_pubkey` is empty and only the new
    key self-signs (`sig_new`); `sig_prev` is empty. The caller persists the key material + genesis pin."""
    core = _core(mode, epoch, prev_pubkey, new_key.public_key_b64, issued_at)
    msg = _canon(core)
    sig_prev = sign(incumbent_key.private_key_b64, msg) if incumbent_key is not None else ""
    sig_new = sign(new_key.private_key_b64, msg)
    return {**core, "sig_prev": sig_prev, "sig_new": sig_new}


def _cross_signed_ok(p: dict) -> bool:
    """True iff a `rotate` payload carries a valid INCUMBENT signature over its core AND a valid SUCCESSOR
    proof-of-possession, and the successor key is a well-formed (canonical, non-low-order) Ed25519 key.
    Fail-closed on anything malformed — a hostile spine payload must never raise out of the walk."""
    prev = p.get("prev_pubkey")
    new = p.get("new_pubkey")
    sig_prev = p.get("sig_prev")
    sig_new = p.get("sig_new")
    if not prev or not new or not isinstance(prev, str) or not isinstance(new, str):
        return False
    if not isinstance(sig_prev, str) or not isinstance(sig_new, str) or not sig_prev or not sig_new:
        return False
    try:
        load_public_key(new)                          # reject a non-canonical / low-order successor key
        msg = _canon(_core_from_payload(p))
        if not verify_one(prev, msg, sig_prev):        # the incumbent AUTHORIZED this successor
            return False
        if not verify_one(new, msg, sig_new):          # the successor PROVES possession of the new key
            return False
    except (IntegrityError, TypeError, ValueError):
        return False
    return True


def _history_from_records(records: Iterable) -> list[tuple[int, dict]]:
    """(seq, payload) for every owner-key-history record, in ascending seq order. Accepts either
    `SpineRecord`s (with `.kind`/`.seq`/`.payload`) or raw dicts."""
    out: list[tuple[int, dict]] = []
    for r in records:
        kind = getattr(r, "kind", None) if not isinstance(r, dict) else r.get("kind")
        payload = getattr(r, "payload", None) if not isinstance(r, dict) else r.get("payload")
        seq = getattr(r, "seq", None) if not isinstance(r, dict) else r.get("seq")
        if kind != KEY_HISTORY_KIND or not isinstance(payload, dict):
            continue
        if payload.get("signal") != SUCCESSION_SIGNAL:
            continue
        out.append((int(seq), payload))
    out.sort(key=lambda t: t[0])
    return out


def build_succession(history: list[tuple[int, dict]], *, genesis_pubkey: Optional[str]) -> Succession:
    """Walk `history` (ascending-seq (seq, payload) of owner-key-history records) from `genesis_pubkey`.

    A `rotate` record EXTENDS the chain iff it is validly cross-signed, chains from the current tip
    (`prev_pubkey == tip`), and carries the strictly-next epoch. A validly cross-signed record whose
    `prev_pubkey` is a key we ALREADY succeeded — to a DIFFERENT successor — is a FORK -> `SuccessionError`
    (only the incumbent key-holder can produce one). Anything else (bad cross-sign, unrelated `prev`, wrong
    epoch) is IGNORED and does not extend the chain. `re-genesis` markers never extend a walk (the pinned
    genesis root is what resets trust); they are audit records only."""
    genesis = (genesis_pubkey or "").strip()
    if not genesis:
        # No anchor at all -> an empty succession. Callers fall back to their single current key.
        return Succession(genesis="", current="", epochs=())
    tip = genesis
    epoch = 0
    epochs: list[list] = [[0, genesis, 0, _INF]]       # [epoch, pubkey, start, end] — end filled on succession
    succeeded: dict[str, str] = {}                     # prev_pubkey -> the new_pubkey we took
    for seq, p in history:
        if p.get("mode") == MODE_REGENESIS:
            continue                                   # audit marker; the genesis PIN is the reset, not this
        if not _cross_signed_ok(p):
            continue                                   # forged / incomplete cross-sign -> does not extend
        prev = str(p.get("prev_pubkey") or "")
        new = str(p.get("new_pubkey") or "")
        ep = p.get("epoch")
        if prev == tip and ep == epoch + 1:
            epochs[-1][3] = seq                        # close the outgoing key's window at this rotation seq
            epochs.append([ep, new, seq, _INF])
            succeeded[prev] = new
            tip, epoch = new, ep
        elif prev in succeeded and succeeded[prev] != new:
            raise SuccessionError(
                f"forked owner-key succession at epoch {ep}: key {prev[:12]}… was already succeeded to "
                f"{succeeded[prev][:12]}… but a second validly cross-signed record hands off to {new[:12]}…")
        # else: exact-duplicate replay of a taken succession, a wrong-epoch record, or a cross-sign from an
        # unrelated key -> ignored (does not extend, is not a fork).
    return Succession(genesis=genesis, current=tip,
                      epochs=tuple(Epoch(e[0], e[1], e[2], e[3]) for e in epochs))


def succession_from_records(records: Iterable, *, genesis_pubkey: Optional[str]) -> Succession:
    return build_succession(_history_from_records(records), genesis_pubkey=genesis_pubkey)


def succession_from_store(store, *, genesis_pubkey: Optional[str]) -> Succession:
    return build_succession(_history_from_records(store.iter_records()), genesis_pubkey=genesis_pubkey)


# --- fold-facing resolver (memoized) ----------------------------------------------------------------
class KeyResolver:
    """Maps a spine record seq to the owner pubkey valid at that seq. `windows is None` means fail-closed
    (a forked/ambiguous succession) — every lookup returns None so nothing verifies until re-genesis."""

    __slots__ = ("_windows", "_fallback")

    def __init__(self, windows: Optional[list[tuple[str, int, float]]], fallback: Optional[str]) -> None:
        self._windows = windows
        self._fallback = fallback

    def at(self, seq: int) -> Optional[str]:
        if self._windows is None:
            return None
        for pk, start, end in self._windows:
            if start <= seq < end:
                return pk
        return None

    @property
    def all_pubkeys(self) -> frozenset[str]:
        if self._windows is None:
            return frozenset()
        return frozenset(pk for pk, _s, _e in self._windows if pk)


_RESOLVER_CACHE: "dict[tuple, KeyResolver]" = {}
_RESOLVER_CACHE_CAP = 128


def _single_window(current: Optional[str]) -> KeyResolver:
    return KeyResolver([(current, 0, _INF)] if current else [], current)


def key_resolver(store, *, current: Optional[str]) -> KeyResolver:
    """The succession-aware owner-key resolver for `store`. Memoized on the spine change-token so a fold
    constructed per governance decision does not re-walk every append.

    NO ROTATION HISTORY (the overwhelmingly common case, and every pre-W9-1 spine) -> a single open window
    over the caller's `current` key: BYTE-IDENTICAL to the pre-W9-1 single-key `verify_signed(p, core,
    current)`, and independent of any global on-disk key state (so a caller that passes an explicit anchor
    is honored exactly). Only once the store actually carries `owner_key_history` records do we anchor on the
    PINNED genesis and walk the cross-signed chain into seq-windowed epochs.

    Fail-closed on a forked succession: returns a resolver whose every `.at()` is None (DENY-all)."""
    try:
        token = store.change_token()
    except Exception:  # noqa: BLE001 — a store without a change token still works, just uncached
        token = None
    ck = (token, current)
    if token is not None:
        hit = _RESOLVER_CACHE.get(ck)
        if hit is not None:
            return hit
    history = _history_from_records(store.iter_records())
    if not history:
        res = _single_window(current)                  # no rotation -> byte-identical single-key behavior
    else:
        from .identity import genesis_owner_pubkey
        genesis = genesis_owner_pubkey() or current
        try:
            succ = build_succession(history, genesis_pubkey=genesis)
        except SuccessionError:
            res = KeyResolver(None, current)           # forked -> fail-closed DENY-all
        else:
            windows = ([(e.pubkey, e.start, e.end) for e in succ.epochs]
                       if succ.epochs else ([(current, 0, _INF)] if current else []))
            res = KeyResolver(windows, current)
    if token is not None:
        if len(_RESOLVER_CACHE) >= _RESOLVER_CACHE_CAP:
            _RESOLVER_CACHE.clear()                    # simple bound; walks are cheap to recompute
        _RESOLVER_CACHE[ck] = res
    return res


def clear_resolver_cache() -> None:
    """Drop the memoized resolvers (tests that relocate SIGIL_HOME / re-pin the genesis)."""
    _RESOLVER_CACHE.clear()


# --- high-level rotation orchestration (the `sigil key` verbs) ---------------------------------------
def _append_history(store, payload: dict, *, reason: str) -> int:
    envelope = {**payload, "by": "owner", "requested_by": "owner", "tier": "A0",
                "decision": "auto", "reason": reason}
    return store.append(kind=KEY_HISTORY_KIND, source="governor", actor="OWNER", payload=envelope)


def rotate(store, *, issued_at: float) -> "tuple[KeyPair, int]":
    """Rotate the owner key: cross-sign a successor into the append-only key history, then swap the at-rest
    key material to it. Returns (new_keypair, record_seq). Fail-closed at every ambiguity:

      * no incumbent key / vault locked  -> refuse (nothing to cross-sign with);
      * the on-disk owner key is not the succession tip (tampered/forked state) -> refuse;
      * a forked existing succession -> `SuccessionError` propagates (DENY).

    The successor is provably the incumbent's: `sig_prev` (incumbent authorization) + `sig_new` (successor
    proof-of-possession) over one canonical statement. Every pre-rotation head/grant keeps verifying because
    the succession walk authenticates each record under the key valid at its time (see module docstring)."""
    from .identity import genesis_owner_pubkey, owner_keypair, pin_genesis, set_owner_key
    incumbent = owner_keypair()
    if incumbent is None:
        raise ValueError("owner-key rotation requires the incumbent signing key (vault locked or no owner "
                         "identity) — cannot cross-sign a successor")
    # Establish the pinned genesis root on the FIRST rotation (the incumbent becomes the chain's root).
    pin_genesis(genesis_owner_pubkey() or incumbent.public_key_b64)
    root = genesis_owner_pubkey()
    succ = succession_from_store(store, genesis_pubkey=root)     # raises SuccessionError on a forked chain
    if succ.current != incumbent.public_key_b64:
        raise SuccessionError(
            "the on-disk owner key is not the current tip of the succession chain — refusing to rotate a "
            "tampered/inconsistent key state (recover with `sigil key re-genesis`)")
    next_epoch = succ.epochs[-1].epoch + 1
    new_kp = generate_keypair()
    payload = cross_sign(incumbent, new_kp, epoch=next_epoch, prev_pubkey=incumbent.public_key_b64,
                         mode=MODE_ROTATE, issued_at=issued_at)
    seq = _append_history(store, payload,
                          reason=f"owner key rotated to epoch {next_epoch} (cross-signed succession)")
    set_owner_key(new_kp)                                        # TPM-sealed at rest once provisioned
    clear_resolver_cache()
    return new_kp, seq


def re_genesis(store, *, issued_at: float) -> "tuple[KeyPair, int]":
    """The COMPROMISE fallback: mint a fresh genesis key, append a self-signed re-genesis marker, swap the
    at-rest key material, and REPIN the genesis root to the fresh key. Returns (new_keypair, record_seq).

    This DELIBERATELY ABANDONS continuity: every pre-re-genesis owner key falls out of every succession
    window, so every pre-re-genesis head, grant, and history record is no longer authenticated by the new
    root. Use it ONLY when a still-current key is believed compromised — where preserving continuity under an
    attacker-held key is worse than losing verifiable history. An out-of-band verifier pinned to the OLD
    genesis must RE-PIN to the fresh key printed by this call."""
    from .identity import pin_genesis, set_owner_key
    new_kp = generate_keypair()
    payload = cross_sign(None, new_kp, epoch=0, prev_pubkey="", mode=MODE_REGENESIS, issued_at=issued_at)
    seq = _append_history(store, payload,
                          reason="owner key RE-GENESIS (continuity deliberately abandoned; compromise reset)")
    set_owner_key(new_kp)
    pin_genesis(new_kp.public_key_b64, force=True)               # REPIN — the trust reset
    clear_resolver_cache()
    return new_kp, seq
