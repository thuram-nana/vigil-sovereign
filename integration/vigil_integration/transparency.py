"""
transparency — a witnessed, split-view-resistant transparency log over the signed spine (VIGIL I2).

SIGIL's spine head (``vigil_core.SignedChainHead``) is already a signed, append-only checkpoint with
a cumulative Merkle root over pruned leaves. This adds the transparency-log guarantees on top, so a
third party — a regulator, a client, a court — can trust the log without trusting its operator:

  * A WITNESS independently checks that a new checkpoint CONSISTENTLY EXTENDS the prior one
    (append-only: record count and last_seq only grow, and the checkpoint meta-chain links back),
    then COUNTERSIGNS it. An honest, single, stateful witness only ever countersigns one consistent
    extension of the chain it tracks — so it never EQUIVOCATES (never vouches for two forks).
  * Split-view resistance is a QUORUM-INTERSECTION property and is CONDITIONAL, not automatic. An
    operator is prevented from obtaining a witness quorum for two forks at the same height ONLY when
    the witness set is a STRICT MAJORITY (``2*threshold > n`` — see ``is_split_view_resistant``):
    then any two quorums must share at least one witness, and that shared honest witness refuses to
    sign the second fork. Below strict majority (in particular ``threshold == 1``, which the trust
    model blesses), two DISJOINT quorums can each countersign a different fork with NO witness
    equivocating — quorum-level prevention does NOT hold; only per-witness non-equivocation and
    DETECTION remain. ``verify_witnessed`` proves a quorum signed; ``verify_split_view_resistant``
    additionally proves the set is strict-majority; ``is_split`` lets any client that holds two
    checkpoints prove a fork after the fact.
  * Consistency proof: a client that saw checkpoint M can verify that checkpoint N (N after M) is a
    pure append-only EXTENSION of M — never a rewrite/rollback — by walking the checkpoint chain.
    (``consistent`` is a PAIRWISE check; it forbids a fork at ``old``'s exact height and any
    rollback, but the full no-fork guarantee comes from each witness's per-tip state, not from
    ``consistent`` alone.)

The checkpoint is a PUBLIC summary of the head (its identity fields), so witnessing needs no access
to the spine contents — only its signed head. OpenTimestamps Bitcoin anchoring of a checkpoint hash
is the deferred external-service refinement (it needs a live calendar server).

Import-clean: ``vigil_core`` only (no ``framework.*``/``strix.*``).
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Optional

from vigil_core import (
    IntegrityError,
    Signature,
    TrustRoot,
    canonical_json,
    sha256_hex,
    sign,
    verify_threshold,
)
from vigil_core.crypto import load_public_key

# Domain tag so a witness signature can never be replayed as a spine-head / evidence / authority sig.
_WITNESS_DOMAIN = b"vigil-transparency-checkpoint-v1\x00"
GENESIS_LINK = ""  # prev_checkpoint_hash of the first checkpoint in a log


@dataclass(frozen=True)
class Checkpoint:
    """A public, witnessable summary of a spine head + its link to the prior checkpoint.

    ``entry_count`` is the ABSOLUTE record count (pruned base + live window) and ``merkle_root`` is
    the head's cumulative Merkle root, so a checkpoint fully summarises the log state at its height.
    ``prev_checkpoint_hash`` chains this checkpoint to the previous one in the witness log.
    """

    last_seq: int
    entry_count: int
    head_hash: str
    merkle_root: str
    prev_checkpoint_hash: str = GENESIS_LINK

    def to_dict(self) -> dict:
        return {
            "last_seq": self.last_seq,
            "entry_count": self.entry_count,
            "head_hash": self.head_hash,
            "merkle_root": self.merkle_root,
            "prev_checkpoint_hash": self.prev_checkpoint_hash,
        }


def checkpoint_of(head, *, prev_checkpoint_hash: str = GENESIS_LINK) -> Checkpoint:
    """Summarise a ``SignedChainHead`` into a witnessable checkpoint, linked to the prior one."""
    return Checkpoint(
        last_seq=int(getattr(head, "last_seq", 0)),
        entry_count=int(getattr(head, "entry_count", 0)),
        head_hash=str(getattr(head, "head_hash", "")),
        merkle_root=str(getattr(head, "cumulative_merkle_root", "") or ""),
        prev_checkpoint_hash=prev_checkpoint_hash,
    )


def _signing_bytes(cp: Checkpoint) -> bytes:
    return _WITNESS_DOMAIN + canonical_json(cp.to_dict())


def checkpoint_hash(cp: Checkpoint) -> str:
    """The stable identity of a checkpoint (what the next checkpoint links to, and what witnesses
    sign). Domain-separated + canonical, so it is unambiguous and non-replayable."""
    return sha256_hex(_signing_bytes(cp))


def consistent(old: Checkpoint, new: Checkpoint) -> tuple[bool, str]:
    """Is ``new`` a valid append-only EXTENSION of ``old``? Fail-closed on record-count shrink,
    last_seq rollback, a broken checkpoint-chain link, and a same-height fork. This is a PAIRWISE
    check: two different ``new`` checkpoints at a HIGHER count both linking to ``old`` each pass it —
    forbidding that multi-height fork is the job of each witness's per-tip state, not of this check."""
    if new.entry_count < old.entry_count:
        return False, "record count shrank — rewrite/rollback, not an append-only extension"
    if new.last_seq < old.last_seq:
        return False, "last_seq went backwards — anti-rollback violated"
    if new.prev_checkpoint_hash != checkpoint_hash(old):
        return False, "checkpoint chain broken — new does not link to old (fork / split view)"
    if new.entry_count == old.entry_count and new.head_hash != old.head_hash:
        return False, "same height, different head — two forks at one size (split view)"
    return True, "consistent append-only extension"


@dataclass(frozen=True)
class WitnessedCheckpoint:
    checkpoint: Checkpoint
    witness_signatures: tuple[Signature, ...] = ()


class Witness:
    """An independent co-signer. It countersigns a checkpoint ONLY after verifying it consistently
    extends the last checkpoint it tracked — so it never vouches for a fork."""

    def __init__(self, key_id: str, private_key_b64: str):
        self.key_id = key_id
        self._priv = private_key_b64
        self._last: Optional[Checkpoint] = None
        self._last_multi: "Optional[MultiSegmentCheckpoint]" = None   # S7c: separate tip for multi-segment

    def would_accept(self, checkpoint: Checkpoint) -> tuple[bool, str]:
        """Check-only (NO mutation): would this witness co-sign ``checkpoint`` as a consistent
        extension of its tracked tip? Lets an emitter determine the willing set atomically — decide
        who signs before anyone mutates state, so a partial failure can't advance some witnesses."""
        if self._last is None:
            return True, "first checkpoint"
        return consistent(self._last, checkpoint)

    def cosign(self, checkpoint: Checkpoint) -> Signature:
        """Verify consistency against this witness's tracked tip, then sign the checkpoint. Raises
        ``ConsistencyError`` (refusing to sign) on any inconsistency — the honest-witness contract."""
        ok, reason = self.would_accept(checkpoint)
        if not ok:
            raise ConsistencyError(f"witness {self.key_id} refuses to co-sign: {reason}")
        self._last = checkpoint
        return Signature(key_id=self.key_id, signature_b64=sign(self._priv, _signing_bytes(checkpoint)))

    def would_accept_multi(self, mc: "MultiSegmentCheckpoint") -> tuple[bool, str]:
        """Check-only: would this witness co-sign the multi-segment checkpoint ``mc`` as a consistent
        extension of its tracked MULTI tip (separate from the single-segment tip)?"""
        if self._last_multi is None:
            return True, "first multi-segment checkpoint"
        return multi_consistent(self._last_multi, mc)

    def cosign_multi(self, mc: "MultiSegmentCheckpoint") -> Signature:
        """Verify consistency across ALL segments against this witness's tracked multi tip, then sign the
        composite. Raises ``ConsistencyError`` on any inconsistency (a fork/segment-set change in any
        segment) — the honest-witness contract, extended to the whole S5 view (S7c)."""
        ok, reason = self.would_accept_multi(mc)
        if not ok:
            raise ConsistencyError(f"witness {self.key_id} refuses to co-sign multi: {reason}")
        self._last_multi = mc
        return Signature(key_id=self.key_id, signature_b64=sign(self._priv, _multi_signing_bytes(mc)))


class ConsistencyError(RuntimeError):
    """A checkpoint is not an append-only extension of the tracked chain — a witness refuses it."""


class CheckpointEmitter:
    """Operational counterpart to the verifiers: turns a sequence of signed spine heads into a
    LINKED, witness-countersigned checkpoint chain. It maintains the ``prev_checkpoint_hash``
    meta-chain (first links to ``GENESIS_LINK``), refuses to emit a checkpoint that is not an
    append-only extension of the last one it emitted (so a regressed/forked head never becomes a
    checkpoint), is IDEMPOTENT on an unchanged head (a no-progress re-emit returns the existing
    witnessed checkpoint rather than minting a redundant same-height one — which would falsely trip
    ``is_split``), and gathers countersignatures ATOMICALLY: it first asks each witness whether it
    would accept (no mutation), then co-signs only the willing set. A single dissenting/desynced
    witness is skipped, never fatal, and cannot advance the others past an uncommitted checkpoint.

    The emitted ``WitnessedCheckpoint`` stream and the underlying checkpoints verify with
    ``verify_witnessed`` / ``verify_split_view_resistant`` / ``verify_log``. The CALLER must check
    the result meets its quorum (``verify_split_view_resistant``) and HALT if a dissenting quorum
    signals a fork — the emitter surfaces the witnesses that signed, it does not adjudicate quorum."""

    def __init__(self) -> None:
        self._last: Optional[Checkpoint] = None
        self._last_witnessed: Optional[WitnessedCheckpoint] = None

    @property
    def head(self) -> Optional[Checkpoint]:
        return self._last

    def emit(self, head, witnesses: "list[Witness]") -> WitnessedCheckpoint:
        """Summarise ``head`` into the next checkpoint (linked to the last) and gather witness
        countersignatures. Idempotent on an unchanged head. Raises ``ConsistencyError`` on a
        non-append-only head (emit-side guard, before asking any witness)."""
        prev = GENESIS_LINK if self._last is None else checkpoint_hash(self._last)
        cp = checkpoint_of(head, prev_checkpoint_hash=prev)
        if self._last is not None:
            # Idempotent no-op: an unchanged POSITION must NOT mint a second checkpoint. Position is
            # (last_seq, entry_count, head_hash) — the live tip; merkle_root is DELIBERATELY excluded,
            # because a prune (records move live→base) advances merkle_root at an unchanged position,
            # and minting a second same-height checkpoint for it would be redundant. Return the cached
            # one; the prune's merkle_root is captured by the next real advance (the root is monotonic).
            if (cp.entry_count == self._last.entry_count and cp.head_hash == self._last.head_hash
                    and cp.last_seq == self._last.last_seq):
                assert self._last_witnessed is not None
                return self._last_witnessed
            ok, reason = consistent(self._last, cp)
            if not ok:
                raise ConsistencyError(f"refusing to emit an inconsistent checkpoint: {reason}")
        # Atomic gather, de-duplicated by key_id: decide the willing set WITHOUT mutating any witness,
        # then co-sign exactly those once each. A witness whose tip conflicts is skipped (not fatal) —
        # no partial advance, no brick; a duplicate/aliased witness is not co-signed twice (the second
        # cosign would see its own just-committed tip and raise mid-loop).
        willing, seen = [], set()
        for w in witnesses:
            if w.key_id in seen:
                continue
            seen.add(w.key_id)
            if w.would_accept(cp)[0]:
                willing.append(w)
        signatures = tuple(w.cosign(cp) for w in willing)
        self._last = cp
        self._last_witnessed = WitnessedCheckpoint(cp, signatures)
        return self._last_witnessed


def verify_witnessed(wc: WitnessedCheckpoint, *, witness_trust_root: TrustRoot) -> bool:
    """True iff a QUORUM of trusted witnesses (m-of-n) countersigned THIS EXACT checkpoint.
    Fail-closed. NOTE: this proves a quorum signed — it does NOT by itself prove the operator did
    not equivocate. At a sub-majority threshold (``2*threshold <= n``) two disjoint quorums can each
    sign a different fork; use ``verify_split_view_resistant`` for the full transparency guarantee."""
    return verify_threshold(
        _signing_bytes(wc.checkpoint), list(wc.witness_signatures), witness_trust_root
    ).satisfied


def is_split_view_resistant(witness_trust_root: TrustRoot) -> bool:
    """True iff the witness set is a STRICT MAJORITY quorum of INDEPENDENT (distinctly-keyed)
    witnesses (``2*threshold > n`` over ``n`` distinct public keys) — the condition under which
    split-view PREVENTION holds: any two quorums must then share >=1 witness, and an honest stateful
    witness refuses to countersign a second, conflicting fork. Below this (incl. the trust model's
    blessed ``threshold == 1`` with n>1) disjoint quorums make prevention impossible — only detection
    (``is_split``) and per-witness non-equivocation remain.

    Fail-closed on an EMPTY set and, crucially, on any DUPLICATE authorizer public key: quorum
    intersection is a property of distinct keys, but ``TrustRoot`` dedups key_ids only (two key_ids
    can share one public key), so the same operator key registered twice would otherwise forge a
    'strict majority' by itself. Deduplication is over the DECODED 32-byte key (not the base64
    string): Ed25519 base64 is malleable in its trailing bits, so one key has several base64
    encodings — comparing decoded keys collapses them. ``load_public_key`` additionally rejects
    non-canonical (y >= p) and low-order Ed25519 points (a low-order key admits a keyless signature
    forgery), so every accepted key here is a canonical, distinct point; any such weak/malformed key
    fails closed."""
    try:
        distinct_keys = {
            load_public_key(a.public_key_b64).public_bytes_raw()
            for a in witness_trust_root.authorizers
        }
    except IntegrityError:
        return False  # non-canonical / low-order / malformed authorizer key — fail closed
    n = len(distinct_keys)
    if n != len(witness_trust_root.authorizers):
        return False  # a duplicate/shared witness key (any encoding) defeats intersection — fail closed
    return n > 0 and 2 * witness_trust_root.threshold > n


def verify_split_view_resistant(wc: WitnessedCheckpoint, *, witness_trust_root: TrustRoot) -> bool:
    """The full transparency guarantee, fail-closed: a trusted quorum signed THIS checkpoint AND the
    witness set is a strict-majority of DISTINCTLY-KEYED witnesses, so the operator cannot have
    obtained a competing same-height quorum without a witness equivocating. Returns False if either
    condition fails. TRUST ASSUMPTION (uncheckable by code): the distinct keys are held by INDEPENDENT
    parties — if one party custodies a majority of witness keys, split-view resistance is void by
    definition, as in any threshold-witness scheme."""
    return is_split_view_resistant(witness_trust_root) and verify_witnessed(
        wc, witness_trust_root=witness_trust_root
    )


def verify_log(checkpoints: "list[Checkpoint]") -> tuple[bool, str]:
    """Verify a full chain of checkpoints is append-only and correctly linked (consistency proof for
    a client walking from the first checkpoint it saw to the latest). First checkpoint links to
    GENESIS_LINK."""
    if not checkpoints:
        return True, "empty log"
    if checkpoints[0].prev_checkpoint_hash != GENESIS_LINK:
        return False, "first checkpoint does not link to genesis"
    for old, new in zip(checkpoints, checkpoints[1:]):
        ok, reason = consistent(old, new)
        if not ok:
            return False, f"break at entry_count {new.entry_count}: {reason}"
    return True, "consistent append-only checkpoint chain"


def is_split(a: Checkpoint, b: Checkpoint) -> bool:
    """True iff ``a`` and ``b`` are a SPLIT VIEW: the SAME height (``entry_count``) but a DIFFERENT
    HEAD. A client that obtains two (witnessed) checkpoints compares them with this — a positive is
    cryptographic proof the log presented two forks, even if each was individually witness-signed.

    Keyed on ``head_hash`` (the live tip), NOT the whole checkpoint identity: ``head_hash`` is the
    authoritative fork commitment — it hash-links the entire ordered entry chain, so two genuinely
    different logs at the same ``entry_count`` MUST differ in ``head_hash``. A differing
    ``merkle_root`` at the same head is NOT a fork this primitive adjudicates: it is un-decidable from
    the 5-field summary alone (an honest re-prune boundary looks identical to a fabricated root), and
    the ``cumulative_merkle_root`` is authenticated elsewhere — by the owner-signed head and the
    archive-anchored chain verification — not here. Keying on the full hash would flag a benign prune
    as equivocation (a false accusation), so a fork requires a different head."""
    return a.entry_count == b.entry_count and a.head_hash != b.head_hash


# ---------------------------------------------------------------------------------------------------
# Multi-segment transparency (unification S7c) — witness the WHOLE S5 spine-domain view at once.
#
# S5 presents the fused system as ONE spine-VIEW over per-domain SEGMENTS (the sovereign spine, the
# offense spine, …). A single-segment Checkpoint witnesses one head; a MultiSegmentCheckpoint composes
# the tip of EVERY segment into ONE witnessable object, so a witness quorum co-signs the entire control
# plane's state in one signature and split-view resistance covers the whole view: a fork in ANY segment,
# or a segment silently added/dropped between checkpoints, breaks consistency. It is pure DATA over the
# public per-segment Checkpoint summaries (head_hash/entry_count/…) — no private key, no cross-domain code
# co-load; an offense-side or neutral witness composes it from the public heads it can read.
# ---------------------------------------------------------------------------------------------------

_MULTI_MARK = "vigil.multi-segment-checkpoint.v1"


def _segment_extends(old: Checkpoint, new: Checkpoint) -> tuple[bool, str]:
    """The append-only monotonicity of one Checkpoint over another — count/seq non-rollback + no
    same-height fork — WITHOUT the per-checkpoint chain-link check (used per-segment inside a composite,
    where chaining lives at the composite level). Mirrors :func:`consistent` minus its prev-link clause."""
    if new.entry_count < old.entry_count:
        return False, "record count shrank — rewrite/rollback, not an append-only extension"
    if new.last_seq < old.last_seq:
        return False, "last_seq went backwards — anti-rollback violated"
    if new.entry_count == old.entry_count and new.head_hash != old.head_hash:
        return False, "same height, different head — two forks at one size (split view)"
    return True, "append-only extension"


@dataclass(frozen=True)
class MultiSegmentCheckpoint:
    """A witnessable summary of EVERY S5 spine segment's tip at one moment: ``segments`` maps each
    segment name (see ``vigil_core.spine_domains``) to that segment's :class:`Checkpoint`, chained to the
    prior multi-checkpoint. Its signing bytes carry a distinct type marker so a multi-checkpoint witness
    signature can never be replayed as a single-segment one (or vice-versa)."""

    segments: dict          # segment_name -> Checkpoint  (stored as a read-only MappingProxyType)
    prev_checkpoint_hash: str = GENESIS_LINK

    def __post_init__(self) -> None:
        # Defensive immutability (LOW): copy + freeze the mapping so an in-place `segments[k] = …` can never
        # silently change this tamper-evidence object's hash after a witness has tracked/signed it — matching
        # the deeply-immutable scalar Checkpoint. object.__setattr__ is the frozen-dataclass idiom.
        object.__setattr__(self, "segments", MappingProxyType(dict(self.segments)))

    def to_dict(self) -> dict:
        # sorted by segment name → deterministic bytes regardless of insertion order.
        return {
            "type": _MULTI_MARK,
            "segments": {name: self.segments[name].to_dict() for name in sorted(self.segments)},
            "prev_checkpoint_hash": self.prev_checkpoint_hash,
        }


def multi_checkpoint_of(heads: dict, *, prev_checkpoint_hash: str = GENESIS_LINK) -> MultiSegmentCheckpoint:
    """Compose a multi-segment checkpoint from ``{segment_name: SignedChainHead}`` (typically the S5
    file-backed segments the verifier can read). Each head is summarised via :func:`checkpoint_of`."""
    return MultiSegmentCheckpoint(
        segments={name: checkpoint_of(head) for name, head in heads.items()},
        prev_checkpoint_hash=prev_checkpoint_hash,
    )


def _multi_signing_bytes(mc: MultiSegmentCheckpoint) -> bytes:
    return _WITNESS_DOMAIN + canonical_json(mc.to_dict())


def multi_checkpoint_hash(mc: MultiSegmentCheckpoint) -> str:
    """The stable identity of a multi-segment checkpoint (what the next one links to, what witnesses sign)."""
    return sha256_hex(_multi_signing_bytes(mc))


def multi_consistent(old: MultiSegmentCheckpoint, new: MultiSegmentCheckpoint) -> tuple[bool, str]:
    """Is ``new`` a valid append-only extension of ``old`` ACROSS ALL segments? Fail-closed on: a changed
    segment SET (a segment silently added or dropped is a control-plane split view), any segment that is
    not itself a consistent append-only extension (:func:`consistent`), or a broken composite-chain link."""
    if set(old.segments) != set(new.segments):
        return False, (f"segment set changed ({sorted(old.segments)} -> {sorted(new.segments)}) — "
                       f"a segment added/dropped is a control-plane split view")
    if new.prev_checkpoint_hash != multi_checkpoint_hash(old):
        return False, "multi-checkpoint chain broken — new does not link to old (fork / split view)"
    # The COMPOSITE is the chained unit (its prev links composites); each segment Checkpoint is a tip
    # SNAPSHOT, so per-segment we require append-only monotonicity (no count/seq rollback, no same-height
    # fork) but NOT a per-segment chain link (that would double-chain — the fix for the composite design).
    for name in sorted(old.segments):
        ok, reason = _segment_extends(old.segments[name], new.segments[name])
        if not ok:
            return False, f"segment {name!r}: {reason}"
    return True, "consistent append-only extension across all segments"


def is_multi_split(a: MultiSegmentCheckpoint, b: MultiSegmentCheckpoint) -> bool:
    """True iff ``a`` and ``b`` are a SPLIT VIEW in ANY shared segment — cryptographic proof the control
    plane presented two forks, even if each composite was individually witness-signed."""
    return any(is_split(a.segments[name], b.segments[name]) for name in (set(a.segments) & set(b.segments)))


@dataclass(frozen=True)
class MultiWitnessedCheckpoint:
    checkpoint: MultiSegmentCheckpoint
    witness_signatures: tuple = ()


def verify_witnessed_multi(mwc: MultiWitnessedCheckpoint, *, witness_trust_root: TrustRoot) -> bool:
    """True iff a QUORUM of trusted witnesses (m-of-n) countersigned THIS EXACT multi-segment checkpoint.
    Fail-closed. As with the single-segment case, quorum ≠ non-equivocation below a strict majority — use
    :func:`verify_split_view_resistant_multi` for the full guarantee."""
    return verify_threshold(
        _multi_signing_bytes(mwc.checkpoint), list(mwc.witness_signatures), witness_trust_root
    ).satisfied


def verify_split_view_resistant_multi(mwc: MultiWitnessedCheckpoint, *, witness_trust_root: TrustRoot) -> bool:
    """The full transparency guarantee over the whole S5 multi-segment view, fail-closed: a trusted quorum
    signed THIS composite AND the witness set is a strict-majority of distinctly-keyed witnesses (reuses
    :func:`is_split_view_resistant`), so the operator cannot have obtained a competing same-height quorum
    for ANY segment without a witness equivocating."""
    return is_split_view_resistant(witness_trust_root) and verify_witnessed_multi(
        mwc, witness_trust_root=witness_trust_root
    )
