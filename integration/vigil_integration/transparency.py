"""
transparency — a witnessed, split-view-resistant transparency log over the signed spine (VIGIL I2).

SIGIL's spine head (``vigil_core.SignedChainHead``) is already a signed, append-only checkpoint with
a cumulative Merkle root over pruned leaves. This adds the transparency-log guarantees on top, so a
third party — a regulator, a client, a court — can trust the log without trusting its operator:

  * A WITNESS independently checks that a new checkpoint CONSISTENTLY EXTENDS the prior one
    (append-only: record count and last_seq only grow, and the checkpoint meta-chain links back),
    then COUNTERSIGNS it. A QUORUM of independent witnesses over a checkpoint makes a split view —
    showing head A to one party and a different head B (at the same size) to another — detectable:
    an honest witness only ever countersigns one consistent extension of the chain it tracks, so the
    operator cannot obtain a quorum for two forks at the same height.
  * Consistency proof: a client that saw checkpoint M can verify that checkpoint N (N after M) is a
    pure append-only EXTENSION of M — never a rewrite/rollback — by walking the checkpoint chain.

The checkpoint is a PUBLIC summary of the head (its identity fields), so witnessing needs no access
to the spine contents — only its signed head. OpenTimestamps Bitcoin anchoring of a checkpoint hash
is the deferred external-service refinement (it needs a live calendar server).

Import-clean: ``vigil_core`` only (no ``framework.*``/``strix.*``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from vigil_core import (
    Signature,
    TrustRoot,
    canonical_json,
    sha256_hex,
    sign,
    verify_threshold,
)

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
    """Is ``new`` a valid append-only EXTENSION of ``old``? Fail-closed on any rollback/fork."""
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

    def cosign(self, checkpoint: Checkpoint) -> Signature:
        """Verify consistency against this witness's tracked tip, then sign the checkpoint. Raises
        ``ConsistencyError`` (refusing to sign) on any inconsistency — the honest-witness contract."""
        if self._last is not None:
            ok, reason = consistent(self._last, checkpoint)
            if not ok:
                raise ConsistencyError(f"witness {self.key_id} refuses to co-sign: {reason}")
        self._last = checkpoint
        return Signature(key_id=self.key_id, signature_b64=sign(self._priv, _signing_bytes(checkpoint)))


class ConsistencyError(RuntimeError):
    """A checkpoint is not an append-only extension of the tracked chain — a witness refuses it."""


def verify_witnessed(wc: WitnessedCheckpoint, *, witness_trust_root: TrustRoot) -> bool:
    """True iff a QUORUM of trusted witnesses (m-of-n) countersigned this exact checkpoint. That
    quorum is what makes a split view detectable. Fail-closed."""
    return verify_threshold(
        _signing_bytes(wc.checkpoint), list(wc.witness_signatures), witness_trust_root
    ).satisfied


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
    """True iff ``a`` and ``b`` are a SPLIT VIEW: the SAME height (entry_count) but different content.
    A client that obtains two (witnessed) checkpoints compares them with this — a positive is
    cryptographic proof the log presented two forks, even if each was individually witness-signed."""
    return a.entry_count == b.entry_count and checkpoint_hash(a) != checkpoint_hash(b)
