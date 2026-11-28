"""aegis.receipts — AS-5d: the gateway ENFORCEMENT-OUTCOME RECEIPT ledger (append-only, hash-linked).

The AS-5a capacity plane decides admit/shed and the gateway's prove-don't-guess gate decides allow/block, but
each of those decisions is TRANSIENT — once the response is sent the gateway keeps no verifiable record of WHAT
enforcement actually did to a request. AS-5c surfaced the LIVE operational state (effective mode + capacity
snapshot) read-only; AS-5d is its sibling for HISTORY: an append-only, hash-linked ledger that records the
OUTCOME of each enforced request as a tamper-evident RECEIPT, surfaced read-only (the same address-free,
metadata-only snapshot discipline AS-5c and AS-5a serve, now carrying the outcome tally + the chain head).

A receipt is the data-plane analog of the engine's evidence chain (``evidence/chain.py``): a cheap, local,
hash-linked record whose integrity an operator/auditor can re-verify offline. It answers "did the firewall shed,
allow, or block this stream of requests, and has that record been edited?" — the enforcement-side counterpart to
the capacity snapshot's "how loaded is it right now?".

The three canonical ENFORCEMENT dispositions it records (see :class:`Outcome`):
  * ``allowed`` — a request AEGIS INSPECTED and let through to the upstream (relayed) — enforcement acted and
    chose not to block.
  * ``shed``    — a request the AS-5a capacity plane shed (soft, retryable 503) — availability-first, BEFORE
    inspection. Never a block.
  * ``blocked`` — a request a FIRED ORACLE blocked (a confirmed verdict + a re-runnable certificate). This is
    the ONLY disposition that denies traffic, and it rides exclusively on prove-don't-guess, never on this
    ledger. A transport refusal (411/413/421), an upstream fault (502), an un-inspected pass-through (no valid
    authority) and a belief-driven soft throttle (429) are NOT enforcement dispositions and mint no receipt —
    the ledger records what ENFORCEMENT did, not every HTTP status.

Doctrine (non-negotiable, enforced here and tested):
  * A RECEIPT RECORDS, IT NEVER BLOCKS. Appending a receipt mints no certificate and no verdict and takes no
    response action — it is pure after-the-fact telemetry, exactly like the AS-5c probe answer and the AS-5a
    capacity signal. Only a fired oracle blocks. A receipt for a ``blocked`` outcome is a record THAT a block
    happened, never the cause of one.
  * APPEND-ONLY, HASH-LINKED, NEVER EDITED. Each receipt carries the SHA-256 of the previous receipt's hash
    (``prev_hash``), so any edit, reorder, or drop of an interior receipt is detectable: re-hashing the chain
    no longer reproduces the head. Receipts are frozen (immutable) once minted; the running ``head`` hash is
    the commitment over the WHOLE history, including receipts aged out of the bounded read-back window.
  * DETERMINISM. No wall-clock and no RNG anywhere in the receipt math: the monotonic clock is INJECTED (the
    same clock the AS-2c/AS-5a/AS-5c planes use), and the hash is a pure function of the canonical receipt
    fields. A fixed outcome sequence over a fixed clock yields byte-identical receipts (and an identical head),
    so the ledger is reproducible in tests and in audit.
  * METADATA ONLY. A receipt carries the outcome kind, a short machine reason/category, the injected-clock
    reading, and the chain links — NEVER a raw caller address, NEVER request/response bytes, NEVER a secret.
    The snapshot is address-free (counts + the head), safe for an operator status surface.
  * TOTAL + FAIL-SAFE. Recording is best-effort: a receipt fault must NEVER touch the data path. The gateway
    wraps every ``record`` call, and this module coerces its own inputs defensively so a bad argument degrades
    to a recorded-but-sanitized receipt rather than raising.
  * BOUNDED MEMORY. The read-back window retains only the last ``max_retained`` receipts; older ones are
    forgotten for re-READ (not edited — they already contributed to the head). ``count`` (total ever recorded)
    and ``head`` keep advancing, so a long-running gateway cannot grow this state without bound.

DEFAULT-OFF: nothing here runs unless the strict, fail-closed ``VIGIL_AEGIS_RECEIPTS`` flag is set. OFF ⇒ the
gateway never builds a ledger, records nothing, and its data path (and the AS-5c probe snapshot) are
byte-identical to a gateway built without the feature.

FATAL-2: engine leg — imports ONLY the stdlib. No ``vigil_core`` (nothing here needs the shared contracts),
no ``sigil``/``governor``/``strix``, nothing on the scan/engage/benchmark gate path. It adds NO OracleKind and
registers NO vocabulary, so the make-gate byte-identity is structurally untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

__all__ = [
    "RECEIPTS_ENV",
    "GENESIS_LINK",
    "Outcome",
    "Receipt",
    "ReceiptLedger",
    "receipts_enabled",
]

# The default-OFF switch for the receipt ledger — strict, fail-closed, read when the gateway is built (so a
# deployment that does not opt in never builds a ledger and records nothing). Only an explicit affirmative token
# turns it on; anything else (unset, typo, "0", "false") keeps receipts OFF — mirrors ``capacity.capacity_enabled``
# / ``probe_socket.probe_socket_enabled`` exactly.
RECEIPTS_ENV = "VIGIL_AEGIS_RECEIPTS"

# The ``prev_hash`` of the very first receipt — a fixed, public sentinel (NOT a secret, NOT a key). 64 hex zeros
# so it is the same shape as a real link and a verifier can special-case the genesis boundary by value.
GENESIS_LINK = "0" * 64

# Bound the per-receipt ``reason`` so a pathological caller-influenced category string cannot bloat the ledger.
_MAX_REASON_LEN = 200

# The read-back window: retain at most this many most-recent receipts for re-READ. The running ``head`` is the
# commitment over the WHOLE history regardless, so forgetting older receipts bounds memory without weakening the
# head's tamper-evidence.
_DEFAULT_MAX_RETAINED = 4096


class Outcome:
    """The three canonical ENFORCEMENT dispositions a receipt records. A tiny value namespace (not an enum, to
    stay dependency-free and keep the recorded value a plain ``str``)."""

    ALLOWED = "allowed"
    SHED = "shed"
    BLOCKED = "blocked"


#: The canonical disposition set — the counts snapshot is always keyed by exactly these (an unknown kind still
#: records honestly, but is tallied under its own key so nothing is silently dropped).
CANONICAL_OUTCOMES = frozenset({Outcome.ALLOWED, Outcome.SHED, Outcome.BLOCKED})


def receipts_enabled() -> bool:
    """Is the receipt ledger armed? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative token arms it
    (mirrors ``capacity.capacity_enabled`` / ``probe_socket.probe_socket_enabled``). The gateway still builds a
    ledger only when this is True at construction."""
    return (os.environ.get(RECEIPTS_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _digest(seq: int, outcome: str, reason: str, mono: float, prev_hash: str) -> str:
    """The SHA-256 over the CANONICAL serialization of a receipt's fields. Canonical (sorted keys, no spaces) so
    the hash is a pure, reproducible function of the fields — no wall-clock, no RNG, no dict-ordering ambiguity.
    Chaining in ``prev_hash`` makes the digest a commitment over the whole prefix, not just this receipt."""
    canonical = json.dumps(
        {"seq": seq, "outcome": outcome, "reason": reason, "mono": mono, "prev": prev_hash},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Receipt:
    """ONE immutable, hash-linked enforcement-outcome record. Frozen: a minted receipt is never edited (the
    append-only guarantee is structural, not merely a convention).

    * ``seq``       — 0-based position in the ledger (monotonic; NOT a wall-clock).
    * ``outcome``   — the disposition (``allowed`` / ``shed`` / ``blocked``; see :class:`Outcome`).
    * ``reason``    — a short machine category (e.g. the shed reason, or the blocked attack-class). Metadata only.
    * ``mono``      — the INJECTED monotonic-clock reading when recorded (deterministic; reproducible in audit).
    * ``prev_hash`` — the ``hash`` of the previous receipt (``GENESIS_LINK`` for ``seq == 0``).
    * ``hash``      — SHA-256 over this receipt's canonical fields incl. ``prev_hash`` (the chain link)."""

    seq: int
    outcome: str
    reason: str
    mono: float
    prev_hash: str
    hash: str

    def to_dict(self) -> "dict[str, object]":
        """A plain-dict view (for a read-only status surface / an offline verifier). Metadata only."""
        return {
            "seq": self.seq,
            "outcome": self.outcome,
            "reason": self.reason,
            "mono": self.mono,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    def recompute_hash(self) -> str:
        """Re-derive this receipt's ``hash`` from its own fields — the per-receipt integrity check. A receipt
        whose stored ``hash`` != ``recompute_hash()`` has been tampered with."""
        return _digest(self.seq, self.outcome, self.reason, self.mono, self.prev_hash)


class ReceiptLedger:
    """The append-only, hash-linked ledger of enforcement outcomes. Thread-safe (the gateway server is threaded):
    every mutation and read of the shared state is serialised under one lock. Deterministic given an injected
    monotonic clock — the hash is a pure function of the receipt fields, no wall-clock and no RNG. Bounded: only
    the last ``max_retained`` receipts are kept for re-read, while ``count`` and ``head`` commit over the whole
    history.

    The ledger NEVER blocks and NEVER mints a verdict: :meth:`record` appends a record of a decision the gateway
    already made and returns. A receipt fault is contained by the caller (the gateway wraps every record) and by
    this class's own defensive input coercion."""

    def __init__(self, *, monotonic: Callable[[], float] = time.monotonic,
                 max_retained: int = _DEFAULT_MAX_RETAINED) -> None:
        self._now = monotonic
        self._max = max(1, int(max_retained))
        self._lock = threading.Lock()
        self._seq = 0                                  # total receipts EVER recorded (next seq to assign)
        self._head = GENESIS_LINK                      # the running chain head (commitment over all receipts)
        self._tail: "list[Receipt]" = []               # bounded read-back window (most-recent receipts)
        self._counts: "dict[str, int]" = {Outcome.ALLOWED: 0, Outcome.SHED: 0, Outcome.BLOCKED: 0}

    # -- recording (append-only) -------------------------------------------------------------------------

    def record(self, outcome: str, reason: str = "", *, now: "Optional[float]" = None) -> Receipt:
        """Append ONE receipt for ``outcome`` (optionally a short machine ``reason``) and return it. Append-only:
        it links to the current head, advances the head and seq, and NEVER edits a prior receipt. Deterministic:
        the timestamp is the INJECTED clock (or an explicit ``now`` for a reproducible test). Defensive: the
        arguments are coerced (a non-str outcome/reason, a non-finite clock) so a bad input degrades to a
        sanitized receipt rather than raising — recording must never fault the data path."""
        try:
            kind = str(outcome)
        except Exception:
            kind = "unknown"
        try:
            why = str(reason)[:_MAX_REASON_LEN]
        except Exception:
            why = ""
        try:
            t = float(self._now()) if now is None else float(now)
        except Exception:
            t = 0.0
        with self._lock:
            seq = self._seq
            prev = self._head
            h = _digest(seq, kind, why, t, prev)
            receipt = Receipt(seq=seq, outcome=kind, reason=why, mono=t, prev_hash=prev, hash=h)
            self._seq = seq + 1
            self._head = h
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._tail.append(receipt)
            if len(self._tail) > self._max:
                # Forget the OLDEST retained receipt for re-read only — it already contributed to the head, so the
                # chain commitment is unchanged. Dropping (not editing) a read-back entry is not an append-only
                # violation: a Receipt is frozen and no minted receipt is ever mutated.
                del self._tail[0:len(self._tail) - self._max]
            return receipt

    # -- introspection (read-only; for an operator status probe / tests / an offline verifier) -----------

    def snapshot(self) -> "dict[str, object]":
        """A read-only, metadata-only snapshot of the ledger: the total ``count`` ever recorded, the chain
        ``head`` (the commitment over the whole history), how many receipts are ``retained`` for re-read, and the
        per-disposition ``outcomes`` tally. Carries NO caller address and NO secret — safe for the AS-5c probe
        surface, mirroring the AS-5a capacity snapshot."""
        with self._lock:
            return {
                "count": self._seq,
                "head": self._head,
                "retained": len(self._tail),
                "outcomes": dict(self._counts),
            }

    @property
    def head(self) -> str:
        """The current chain head (the hash of the most-recent receipt, or ``GENESIS_LINK`` when empty)."""
        with self._lock:
            return self._head

    @property
    def count(self) -> int:
        """Total receipts ever recorded (independent of the bounded read-back window)."""
        with self._lock:
            return self._seq

    def receipts(self) -> "tuple[Receipt, ...]":
        """A read-only snapshot copy of the retained (most-recent) receipts, oldest-first. The Receipts are
        frozen, so the caller cannot mutate the ledger through them."""
        with self._lock:
            return tuple(self._tail)

    def verify(self) -> bool:
        """Re-verify the RETAINED window's integrity end-to-end: every retained receipt re-hashes to its stored
        ``hash``, each links to its predecessor, the seqs are contiguous, and the last retained ``hash`` equals
        the live ``head``. (History aged out of the window cannot be re-read, but it is committed by the head,
        which this confirms the retained tail chains up to.) Returns False on any tamper."""
        with self._lock:
            tail = tuple(self._tail)
            head = self._head
        if not tail:
            return head == GENESIS_LINK
        if not self.verify_chain(tail):
            return False
        return tail[-1].hash == head

    @staticmethod
    def verify_chain(receipts: "tuple[Receipt, ...] | list[Receipt]") -> bool:
        """Re-verify a sequence of receipts is internally consistent and properly hash-linked: each receipt
        re-hashes to its stored ``hash``, each (after the first) carries its predecessor's ``hash`` as
        ``prev_hash`` and the next contiguous ``seq``, and a first receipt at ``seq == 0`` links to
        ``GENESIS_LINK``. Pure/static so an offline auditor can run it over an exported chain. Any edit,
        reorder, or interior drop breaks it."""
        prev: "Optional[Receipt]" = None
        for r in receipts:
            if r.recompute_hash() != r.hash:
                return False
            if prev is None:
                if r.seq == 0 and r.prev_hash != GENESIS_LINK:
                    return False
            else:
                if r.prev_hash != prev.hash:
                    return False
                if r.seq != prev.seq + 1:
                    return False
            prev = r
        return True
