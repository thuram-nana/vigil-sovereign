"""witnessed_anchor — the retained off-box witnessed-checkpoint ANTI-ROLLBACK anchor (Claim 6, C-S4).

The signed anti-rollback FLOOR (``apps/sigil/sigil/spine/floor.py`` on the sovereign side, the signed
``vigil_core.highwater`` on the offense side) records a LOCAL, on-disk watermark. Both modules state the
same HONEST LIMIT: a SAME-HOST attacker with the owner/root UID rewrites the head AND the floor together
(or strips a signed floor back to unsigned), and a purely LOCAL verify re-reads BOTH from that same
attacker-controlled disk — so it cannot catch the rollback. That residual is explicitly deferred by C-S2/
C-S3.

This module closes it OUT-OF-BAND for any verifier that RETAINED an off-box, witness-cosigned checkpoint
of the head at height N: it REQUIRES the local head/floor to be consistent with the HIGHEST retained
witnessed checkpoint. A local head/floor rolled back below N (a co-rewrite), or forked at N (same height,
different head), or a floor stripped/removed below N, is caught — the anchor is a copy the attacker never
touched (it lives off-box), so it is not re-read from the rolled-back disk.

The witnessed checkpoint is a public :class:`transparency.Checkpoint` summary (last_seq / entry_count /
head_hash / merkle_root + the C-S1 prune boundary base_seq / base_count), so it commits the same boundary
fields the floor does and re-uses :func:`transparency.consistent` / :func:`transparency.is_split` semantics
for the rollback/fork verdict. It is persisted as INERT JSON bytes a public-key-only verifier reads
out-of-band — never a cross-plane in-process co-load.

PLANE-NEUTRAL + boundary-clean: imports ``vigil_core`` and ``vigil_integration.transparency`` ONLY (no
``apps.sigil``/``sigil``, no ``framework``/``strix``). BOTH planes call it — the sovereign floor via
``sigil.spine.floor_witness`` (owner-signed witness), the offense high-water floor via
``vigil_integration.floor_witness`` (offense GOVERNANCE-signed witness, FATAL-2: NEVER an owner key). One
implementation, one envelope format, so the sovereign and offense witnessed checkpoints are the same inert
artifact an out-of-band verifier reads.

HONEST LIMIT (LOAD-BEARING — do NOT overclaim; mirrors ``transparency`` §, ``witness.guarantee_label``,
and the ``reprove`` self-witness label): the anchor is retention-based DETECTION. A ``threshold == 1`` /
solo / owner-or-governance-only self-witness is NOT independence — the producer signs its OWN anchor. It
closes the same-host head+floor co-rewrite / strip-to-unsigned case FOR A VERIFIER THAT RETAINED AN
OFF-BOX COPY, and nothing more. Only INDEPENDENT witnesses (a strict majority of distinctly-keyed
witnesses, held by independent parties) upgrade this to (conditional) split-view PREVENTION, and that is a
DEPLOYMENT property code cannot verify. A fully-dishonest producer that ALSO controls the witness quorum
is NOT closed by this. :func:`guarantee_label` NEVER prints 'independent' / 'split-view-resistant' /
'prevention' for a solo self-witness.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Optional

from vigil_core import Signature, TrustRoot

from .transparency import (
    GENESIS_LINK,
    Checkpoint,
    Witness,
    WitnessedCheckpoint,
    checkpoint_hash,
    checkpoint_of,
    consistent,
    is_split_view_resistant,
    verify_witnessed,
)

# Envelope schema — kept byte-compatible with ``apps/sigil/sigil/spine/witness.py``'s ``dump_witnessed`` so
# a sovereign ``sigil checkpoint emit`` / ``sigil floor witness`` retained envelope is readable here (and
# vice-versa): one on-disk witnessed-checkpoint artifact for both planes.
_ENVELOPE_SCHEMA = 1


class AnchorError(Exception):
    """A witnessed-checkpoint envelope could not be parsed/verified, or no retained envelope is usable as
    an anchor. Fail-closed: every load/select path RAISES rather than silently treating a bad anchor as
    absent — a bad anchor supplied to the verifier must REFUSE, never pass."""


# ------------------------------------------------------------------- envelope (de)serialisation ----------

def dump_witnessed_envelope(wc: WitnessedCheckpoint, *, scope: str) -> str:
    """Serialise a :class:`WitnessedCheckpoint` to the portable JSON envelope, bound to ``scope`` so a
    checkpoint from a different store is not accepted on verify. Byte-format-compatible with the sovereign
    ``witness.dump_witnessed`` (schema / scope / checkpoint / witness_signatures, sorted, compact)."""
    return json.dumps({
        "schema": _ENVELOPE_SCHEMA,
        "scope": scope,
        "checkpoint": wc.checkpoint.to_dict(),
        "witness_signatures": [{"key_id": s.key_id, "signature_b64": s.signature_b64}
                               for s in wc.witness_signatures],
    }, sort_keys=True, separators=(",", ":"))


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise AnchorError(msg)


def load_witnessed_envelope(data: str) -> tuple[WitnessedCheckpoint, str]:
    """Parse + strictly validate a witnessed-checkpoint envelope. Returns ``(WitnessedCheckpoint, scope)``.
    Fail-closed on ANY malformed shape — never a bare exception from a crafted file. The C-S1 prune boundary
    (base_seq/base_count) round-trips (optional-with-default so a pre-C-S1 envelope reconstructs as base_*=0,
    byte-identical)."""
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as e:
        raise AnchorError(f"corrupt witnessed-checkpoint envelope: {e}") from e
    _require(isinstance(obj, dict), "witnessed-checkpoint envelope is not a JSON object")
    scope = obj.get("scope")
    cp_raw = obj.get("checkpoint")
    sigs_raw = obj.get("witness_signatures")
    _require(isinstance(scope, str), "envelope is missing its scope")
    _require(isinstance(cp_raw, dict), "envelope is missing its checkpoint")
    _require(isinstance(sigs_raw, list), "envelope is missing its witness_signatures")
    try:
        cp = Checkpoint(
            last_seq=int(cp_raw["last_seq"]),
            entry_count=int(cp_raw["entry_count"]),
            head_hash=str(cp_raw["head_hash"]),
            merkle_root=str(cp_raw["merkle_root"]),
            prev_checkpoint_hash=str(cp_raw["prev_checkpoint_hash"]),
            base_seq=int(cp_raw.get("base_seq", 0)),
            base_count=int(cp_raw.get("base_count", 0)),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise AnchorError(f"malformed checkpoint fields: {e}") from e
    sigs = []
    for s in sigs_raw:
        _require(isinstance(s, dict), "a witness signature is not an object")
        kid, sig = s.get("key_id"), s.get("signature_b64")
        _require(isinstance(kid, str) and isinstance(sig, str), "a witness signature is malformed")
        sigs.append(Signature(key_id=kid, signature_b64=sig))
    return WitnessedCheckpoint(cp, tuple(sigs)), scope


# --------------------------------------------------------------------------------- honesty label ---------

def guarantee_label(tr: TrustRoot) -> str:
    """The HONEST guarantee for a witness set — IDENTICAL wording to ``witness.guarantee_label`` so both
    planes speak with one voice. Detection (via off-box retention) is the baseline and always holds.
    Prevention is claimed — and only CONDITIONALLY — ONLY for a strict-majority set of at least two
    DISTINCT keys held by independent parties: a single owner/governance-only witness is arithmetic
    'strict-majority' (2*1>1) but is the head signer ITSELF, so it provides NO independence and is labelled
    DETECTION. This function NEVER returns 'independent' / 'split-view-resistant' / 'prevention' for a solo
    self-witness (C-S4 risk #13)."""
    if is_split_view_resistant(tr) and len(tr.authorizers) >= 2:
        return ("split-view prevention IF the witness keys are held by independent parties "
                "(strict-majority set; independence is not checkable here)")
    return ("rollback DETECTION only (the off-box retained copy is the anchor; add independent witnesses "
            "at strict majority for prevention)")


# ------------------------------------------------------------------------------ persist / emit -----------

def _atomic_write_0600(p: Path, text: str) -> None:
    """Crash-safe, owner-only write: temp → fsync → os.replace → dir-fsync, 0600 throughout (mirrors the
    floor writers). A partial write can only leave the ``.tmp-*`` file, never a torn envelope."""
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.parent / f".{p.name}.tmp-{os.getpid()}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover — non-POSIX / unusual fs; content is non-secret, mode is best-effort
        pass
    try:
        dfd = os.open(str(p.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:  # pragma: no cover — dir fsync unsupported; os.replace already committed the name
        pass


def read_tip(retain_path: os.PathLike | str) -> Optional[WitnessedCheckpoint]:
    """The persisted retained witnessed checkpoint at ``retain_path``, or None if absent. Raises
    :class:`AnchorError` on a present-but-corrupt envelope (fail-closed)."""
    p = Path(retain_path)
    if not p.exists():
        return None
    try:
        wc, _scope = load_witnessed_envelope(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise AnchorError(f"retained witnessed checkpoint {p} is unreadable: {e}") from e
    return wc


def emit_witnessed(head, witnesses: "list[Witness]", *, retain_path: os.PathLike | str,
                   scope: str) -> WitnessedCheckpoint:
    """Emit-on-advance: summarise ``head`` into the next checkpoint (LINKED to the retained tip so the
    meta-chain survives restarts), gather witness co-signatures, PERSIST the new tip off-box at
    ``retain_path``, and return the :class:`WitnessedCheckpoint`. Mirrors ``witness.emit_checkpoint`` /
    ``transparency.CheckpointEmitter.emit``: idempotent on an unchanged POSITION *and* prune BOUNDARY — a
    prune that advances ``base_seq``/``base_count`` at an idle tip IS witness-worthy (since C-S1 the boundary
    is part of the checkpoint's SIGNED identity), so it re-mints and re-persists the off-box tip; else a
    prune-then-idle system would keep a stale off-box witness (base_seq=0) and an un-prune back to it would
    pass the anchor. (``merkle_root`` stays excluded — a schedule-dependent fold, so a same-boundary root-only
    change still dedups.) Refuses a non-append-only head (``consistent``), and gathers the willing witnesses
    ATOMICALLY (decide who signs before any state mutates). ``retain_path`` is a stable path the verifier
    RETAINS OFF-BOX — a copy kept
    only alongside the spine is rolled back with it and adds NOTHING over the local floor (the anti-rollback
    comes from EXTERNAL retention, not a local sidecar)."""
    if not witnesses:
        raise AnchorError("emit needs at least one witness to co-sign the checkpoint")
    tip = read_tip(retain_path)
    prev = GENESIS_LINK if tip is None else checkpoint_hash(tip.checkpoint)
    cp = checkpoint_of(head, prev_checkpoint_hash=prev)
    if tip is not None:
        last = tip.checkpoint
        if (cp.entry_count, cp.last_seq, cp.head_hash, cp.base_seq, cp.base_count) == (
                last.entry_count, last.last_seq, last.head_hash, last.base_seq, last.base_count):
            return tip                                     # idempotent: unchanged position AND boundary
        ok, why = consistent(last, cp)
        if not ok:
            raise AnchorError(f"refusing to emit an inconsistent witnessed checkpoint: {why}")
    willing, seen = [], set()                              # atomic gather: pick the willing set, then co-sign
    for w in witnesses:
        if w.key_id in seen:
            continue
        seen.add(w.key_id)
        if w.would_accept(cp)[0]:
            willing.append(w)
    wc = WitnessedCheckpoint(cp, tuple(w.cosign(cp) for w in willing))
    _atomic_write_0600(Path(retain_path), dump_witnessed_envelope(wc, scope=scope))
    return wc


# ------------------------------------------------------------------------------- verify / anchor ---------

def select_highest_witnessed(sources: Iterable[str], *, scope: str,
                             trust_root: TrustRoot) -> Optional[WitnessedCheckpoint]:
    """From a set of retained witnessed-checkpoint ENVELOPES (JSON strings), pick the HIGHEST (by
    entry_count, then last_seq) that (a) parses, (b) is bound to ``scope``, and (c) carries a trusted
    witness QUORUM signature (``verify_witnessed``). A malformed / wrong-scope / unsigned / forged envelope
    is not usable and is dropped.

    FAIL-CLOSED: if any sources were supplied but NONE is usable, RAISE :class:`AnchorError` — a verifier
    that was handed an anchor and found it forged must REFUSE, never fall through to 'no anchor -> pass'. An
    EMPTY ``sources`` returns None (the caller then skips the anchor: a verifier that retained nothing gets
    exactly today's local-only guarantee, no better, no worse)."""
    sources = list(sources)
    valid: list[WitnessedCheckpoint] = []
    for data in sources:
        try:
            wc, wc_scope = load_witnessed_envelope(data)
        except AnchorError:
            continue                                       # malformed → not a usable anchor
        if wc_scope != scope:
            continue                                       # a checkpoint for a different store
        if not verify_witnessed(wc, witness_trust_root=trust_root):
            continue                                       # forged / unsigned / not a trusted quorum
        valid.append(wc)
    if sources and not valid:
        raise AnchorError(
            "no retained witnessed checkpoint is usable as an anchor (all supplied were malformed, "
            "wrong-scope, or not signed by a trusted witness quorum) — refusing to certify (fail-closed)")
    if not valid:
        return None
    return max(valid, key=lambda wc: (wc.checkpoint.entry_count, wc.checkpoint.last_seq))


def anchor_head(head, *, retained: Checkpoint) -> tuple[bool, str]:
    """Is the LOCAL ``head`` consistent with the ``retained`` witnessed checkpoint — i.e. NOT rolled back
    below it and NOT forked at its height? Builds the current checkpoint LINKED to ``retained`` and reuses
    :func:`transparency.consistent`, so it inherits the C-S1 prune-boundary monotonic guards (base_seq /
    base_count may not shrink = un-prune) AND the :func:`transparency.is_split` same-height/different-head
    fork rule. A rollback (entry_count / last_seq below), an un-prune, or a same-height fork → ``(False, …)``.

    This is the LIGHT head+floor-height anchor (it needs only the head SUMMARY, not the live entries). The
    sovereign ``witness.verify_against_external`` is the COMPLEMENTARY heavy check that additionally proves
    byte-identity of the retained prefix via the hash-chained live entries; both anchor to the same retained
    checkpoint."""
    cur = checkpoint_of(head, prev_checkpoint_hash=checkpoint_hash(retained))
    ok, why = consistent(retained, cur)
    if not ok:
        return False, (f"ROLLBACK/FORK vs the retained witnessed checkpoint (count {retained.entry_count}, "
                       f"last_seq {retained.last_seq}) — {why}")
    return True, (f"local head (count {cur.entry_count}, last_seq {cur.last_seq}) is at/above the retained "
                  f"witnessed checkpoint (count {retained.entry_count}, last_seq {retained.last_seq}) — "
                  f"no rollback below it, no fork at its height")
