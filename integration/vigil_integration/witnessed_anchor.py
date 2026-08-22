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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

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

def dump_witnessed_envelope(wc: WitnessedCheckpoint, *, scope: str,
                            emitted_at: Optional[int] = None) -> str:
    """Serialise a :class:`WitnessedCheckpoint` to the portable JSON envelope, bound to ``scope`` so a
    checkpoint from a different store is not accepted on verify. Byte-format-compatible with the sovereign
    ``witness.dump_witnessed`` (schema / scope / checkpoint / witness_signatures, sorted, compact).

    ``emitted_at`` (W7-5, #463) is the UNSIGNED emission timestamp (unix seconds) a SCHEDULED emitter stamps
    so a verifier can REFUSE a stale anchor. It is deliberately NOT part of the signed ``checkpoint`` (adding
    it would change the checkpoint's signed identity and break cross-plane byte-compat + re-verify); it is
    top-level metadata. When None it is OMITTED entirely, so a hand-emitted / legacy envelope is byte-identical
    to the pre-W7-5 format (and a freshness gate then treats it as 'age unknown' → fail-closed refuse). An
    unsigned timestamp is sound for its purpose: staleness is an OPERATIONAL-drift signal (the emitter stopped),
    and a same-host owner/governance attacker who could forward-date it already defeats the whole local floor
    (the documented irreducible all-keys limit) — the anchor's SIGNATURE + the anti-rollback consistency checks
    remain the tamper controls."""
    obj = {
        "schema": _ENVELOPE_SCHEMA,
        "scope": scope,
        "checkpoint": wc.checkpoint.to_dict(),
        "witness_signatures": [{"key_id": s.key_id, "signature_b64": s.signature_b64}
                               for s in wc.witness_signatures],
    }
    if emitted_at is not None:
        obj["emitted_at"] = int(emitted_at)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


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
    # REFUSE-NEWER (W5-3 #447): this integration-plane reader is byte-compatible with the sovereign
    # ``spine.witness`` envelope, so it must apply the SAME ceiling — else a schema>1 envelope (written by a
    # newer build) is parsed as v1 here: any checkpoint delta silently mislabelled a signature-mismatch
    # "not a usable anchor", any additive envelope field dropped-and-accepted (a silent downgrade on the
    # verify/reprove path). Fail closed with the honest "upgrade" message instead. An uncoercible schema is
    # itself too-new (fail closed). Kept inline — the integration plane must not import the sovereign guard.
    try:
        _env_schema = int(obj.get("schema", 1))
    except (TypeError, ValueError):
        _env_schema = _ENVELOPE_SCHEMA + 1
    _require(_env_schema <= _ENVELOPE_SCHEMA,
             f"witnessed-checkpoint envelope schema {obj.get('schema')!r} is newer than this build "
             f"understands (max {_ENVELOPE_SCHEMA}) — upgrade VIGIL to read it")
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


# ------------------------------------------------------------------------------ freshness (W7-5) ---------
# The witnessed anchor is emitted on a CADENCE (a scheduled off-box push). If that emitter stops, the anchor
# ages and the anti-rollback window it bounds silently WIDENS to the last successful emit. A verifier must
# therefore REFUSE an anchor older than a documented bound (fail-closed), and a monitor must ALERT before the
# refusal bound is crossed. These are the plane-neutral primitives both planes share (offense governance
# witness AND sovereign owner witness), so the bound and its wording cannot drift between them.

FRESH = "fresh"
STALE_WARN = "stale-warn"
STALE_REFUSE = "stale-refuse"
UNKNOWN_AGE = "unknown-age"     # the envelope carries no emitted_at — cannot be proven fresh (fail-closed)
FUTURE_SKEW = "future-skew"     # dated in the future beyond tolerance — a skewed clock corrupts the bound

_WARN_AFTER_S_ENV = "VIGIL_ANCHOR_WARN_AFTER_S"
_REFUSE_AFTER_S_ENV = "VIGIL_ANCHOR_REFUSE_AFTER_S"
# Documented default freshness bounds. The scheduled emitter (below) should run WELL under WARN so a healthy
# system never trips it; WARN is the "the emitter looks unhealthy" alert, REFUSE the fail-closed floor.
DEFAULT_WARN_AFTER_S = 6 * 3600        # 6h — alert
DEFAULT_REFUSE_AFTER_S = 24 * 3600     # 24h — refuse to anchor a promotion off an anchor older than this
DEFAULT_FUTURE_SKEW_S = 300            # 5m — tolerate benign clock skew; beyond it, fail-closed


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    return v if v > 0 else default


@dataclass(frozen=True)
class FreshnessVerdict:
    """The freshness decision for a witnessed anchor. ``refuse`` is what a GUARD gates on (fail-closed);
    ``alert`` is what a MONITOR raises (so staleness is surfaced BEFORE the guard would refuse)."""
    status: str
    detail: str
    age_s: Optional[float] = None
    emitted_at: Optional[int] = None
    warn_after_s: Optional[int] = None
    refuse_after_s: Optional[int] = None

    @property
    def fresh(self) -> bool:
        return self.status == FRESH

    @property
    def refuse(self) -> bool:
        # UNKNOWN_AGE and FUTURE_SKEW are fail-closed refusals: an anchor whose age cannot be trusted must
        # not be relied on for a promotion (a missing/forward-dated timestamp cannot be proven fresh).
        return self.status in (STALE_REFUSE, UNKNOWN_AGE, FUTURE_SKEW)

    @property
    def alert(self) -> bool:
        return self.status in (STALE_WARN, STALE_REFUSE, UNKNOWN_AGE, FUTURE_SKEW)

    @property
    def severity(self) -> str:
        if self.refuse:
            return "critical"
        return "warning" if self.status == STALE_WARN else "ok"


def freshness_verdict(emitted_at: Optional[int], *, now: float, warn_after_s: Optional[int] = None,
                      refuse_after_s: Optional[int] = None,
                      future_skew_s: int = DEFAULT_FUTURE_SKEW_S) -> FreshnessVerdict:
    """Classify a witnessed anchor's freshness given its ``emitted_at`` and the current ``now`` (both unix
    seconds; ``now`` is injectable for deterministic tests). Fail-closed: a MISSING timestamp
    (``emitted_at is None``) is UNKNOWN_AGE (refuse — an un-timestamped anchor cannot be proven fresh), and a
    FUTURE-dated anchor beyond ``future_skew_s`` is FUTURE_SKEW (refuse — a skewed clock corrupts the bound).
    Otherwise: age > refuse_after ⇒ STALE_REFUSE, age > warn_after ⇒ STALE_WARN, else FRESH."""
    wa = _env_int(_WARN_AFTER_S_ENV, DEFAULT_WARN_AFTER_S) if warn_after_s is None else int(warn_after_s)
    ra = _env_int(_REFUSE_AFTER_S_ENV, DEFAULT_REFUSE_AFTER_S) if refuse_after_s is None else int(refuse_after_s)
    if wa >= ra:                       # never "warn AFTER refuse" — clamp a misconfiguration to warn==refuse
        wa = ra
    if emitted_at is None:
        return FreshnessVerdict(UNKNOWN_AGE,
                                "the witnessed anchor carries NO emission timestamp — it cannot be proven "
                                "fresh (re-emit it with the scheduled emitter). Refusing fail-closed.",
                                None, None, wa, ra)
    age = float(now) - float(emitted_at)
    if age < -float(future_skew_s):
        return FreshnessVerdict(FUTURE_SKEW,
                                f"the witnessed anchor is dated {-age:.0f}s in the FUTURE (> {future_skew_s}s "
                                f"skew tolerance) — a skewed clock corrupts every freshness bound; refusing "
                                f"fail-closed.", age, int(emitted_at), wa, ra)
    if age > ra:
        return FreshnessVerdict(STALE_REFUSE,
                                f"the witnessed anchor is {age:.0f}s old (> {ra}s refusal bound) — the "
                                f"scheduled off-box emitter has stopped and the rollback window is silently "
                                f"widening. Refusing to anchor a promotion (fail-closed).",
                                age, int(emitted_at), wa, ra)
    if age > wa:
        return FreshnessVerdict(STALE_WARN,
                                f"the witnessed anchor is {age:.0f}s old (> {wa}s warn bound, < {ra}s refusal "
                                f"bound) — the scheduled off-box emitter looks unhealthy; refresh it before it "
                                f"crosses the refusal bound.", age, int(emitted_at), wa, ra)
    return FreshnessVerdict(FRESH, f"the witnessed anchor is {age:.0f}s old (< {wa}s warn bound) — fresh.",
                            age, int(emitted_at), wa, ra)


def envelope_emitted_at(data: str) -> Optional[int]:
    """The UNSIGNED emission timestamp (unix seconds) stamped into a witnessed-checkpoint envelope by a
    scheduled emitter, or None when the envelope carries none (a legacy / hand-emitted anchor). Fail-soft
    parse: a malformed/absent/non-numeric value returns None, and :func:`freshness_verdict` then treats None
    as 'age unknown' and, when freshness is enforced, REFUSES fail-closed. Plane-neutral — reads either
    plane's envelope, since both stamp the same top-level ``emitted_at`` key."""
    try:
        obj = json.loads(data)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    v = obj.get("emitted_at")
    if isinstance(v, bool):            # bool is an int subclass — a JSON true/false is not a timestamp
        return None
    if isinstance(v, (int, float)):
        return int(v)
    return None


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
                   scope: str, now: Optional[float] = None) -> WitnessedCheckpoint:
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
    stamp = None if now is None else int(now)
    tip = read_tip(retain_path)
    prev = GENESIS_LINK if tip is None else checkpoint_hash(tip.checkpoint)
    cp = checkpoint_of(head, prev_checkpoint_hash=prev)
    if tip is not None:
        last = tip.checkpoint
        if (cp.entry_count, cp.last_seq, cp.head_hash, cp.base_seq, cp.base_count) == (
                last.entry_count, last.last_seq, last.head_hash, last.base_seq, last.base_count):
            # Unchanged position AND boundary. W7-5 LIVENESS REFRESH: a SCHEDULED emitter (``now`` given)
            # re-stamps the off-box anchor's emitted_at so its FRESHNESS advances even on an idle spine —
            # proving the emit pipeline is alive — while the signed checkpoint + witness signatures stay
            # byte-identical (emitted_at is unsigned metadata, so the retained copy still verifies). A
            # library caller that passes no ``now`` keeps the exact pre-W7-5 behaviour (return tip, no write).
            if now is None:
                return tip                                 # idempotent: unchanged position AND boundary
            _atomic_write_0600(Path(retain_path), dump_witnessed_envelope(tip, scope=scope, emitted_at=stamp))
            return tip
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
    _atomic_write_0600(Path(retain_path), dump_witnessed_envelope(wc, scope=scope, emitted_at=stamp))
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
    picked = select_highest_witnessed_with_age(sources, scope=scope, trust_root=trust_root)
    return None if picked is None else picked[0]


def select_highest_witnessed_with_age(
        sources: Iterable[str], *, scope: str,
        trust_root: TrustRoot) -> Optional[tuple[WitnessedCheckpoint, Optional[int]]]:
    """Like :func:`select_highest_witnessed`, but also returns the SELECTED (highest) anchor's UNSIGNED
    emission timestamp (``emitted_at``, unix seconds, or None if that envelope carried none). A freshness
    gate MUST enforce on the anchor it will actually RELY ON — the highest — so a mixed batch of one
    fresh-but-low and one stale-but-high anchor is judged on the high (stale) one it would use, never the
    freshest present. Same fail-closed contract as :func:`select_highest_witnessed`: empty sources → None;
    sources supplied but none usable → RAISE."""
    sources = list(sources)
    valid: list[tuple[WitnessedCheckpoint, Optional[int]]] = []
    for data in sources:
        try:
            wc, wc_scope = load_witnessed_envelope(data)
        except AnchorError:
            continue                                       # malformed → not a usable anchor
        if wc_scope != scope:
            continue                                       # a checkpoint for a different store
        if not verify_witnessed(wc, witness_trust_root=trust_root):
            continue                                       # forged / unsigned / not a trusted quorum
        valid.append((wc, envelope_emitted_at(data)))
    if sources and not valid:
        raise AnchorError(
            "no retained witnessed checkpoint is usable as an anchor (all supplied were malformed, "
            "wrong-scope, or not signed by a trusted witness quorum) — refusing to certify (fail-closed)")
    if not valid:
        return None
    return max(valid, key=lambda t: (t[0].checkpoint.entry_count, t[0].checkpoint.last_seq))


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


# ---------------------------------------------------------- the scheduled off-box emitter (W7-5) ---------
# The active writer must PERIODICALLY emit + push the witnessed checkpoint OFF-BOX; an anchor that is emitted
# by hand ages between manual runs and silently widens the rollback window (the W7-5 defect). This is the
# scheduler: one cycle emits (refreshing the off-box anchor's emitted_at), writes a dead-man heartbeat, and —
# BEFORE re-emitting — ALARMS if the anchor it is about to refresh was already stale (so staleness is surfaced
# WHILE it is still a warning, before the guard's refusal bound is crossed). Plane-neutral: the caller passes
# an ``emit_fn`` closure (offense governance witness OR sovereign owner witness) that takes ``now`` and returns
# the WitnessedCheckpoint; the loop owns cadence/clock/heartbeat/alarm so both planes share one implementation.

def _default_emit_heartbeat_path(retain_path: os.PathLike | str) -> Path:
    p = Path(retain_path)
    return p.parent / (p.name + ".emit-heartbeat.json")


def _default_emit_alarm_log(retain_path: os.PathLike | str) -> Path:
    p = Path(retain_path)
    return p.parent / (p.name + ".emit-alarms.jsonl")


def run_checkpoint_once(emit_fn: Callable[[float], WitnessedCheckpoint], *, retain_path: os.PathLike | str,
                        now: float, sink=None, heartbeat_path: Optional[os.PathLike | str] = None,
                        warn_after_s: Optional[int] = None, refuse_after_s: Optional[int] = None,
                        seq: int = 0) -> WitnessedCheckpoint:
    """One scheduled-emitter cycle. (1) BEFORE re-emitting, read the CURRENT off-box anchor and — if it is
    already STALE — raise a ``warning`` (approaching the refusal bound) or ``critical`` (past it / undated)
    alarm: this is the 'alert before the guard refuses' signal. (2) Call ``emit_fn(now)`` to refresh the
    anchor off-box (its emitted_at advances to ``now``). (3) Write a dead-man heartbeat. A crash in
    ``emit_fn`` raises a ``critical`` emit-error alarm, writes a FAILING heartbeat, and re-raises. Returns
    the freshly-emitted :class:`WitnessedCheckpoint`.

    The alarm sink + heartbeat reuse the integration integrity-monitor plumbing via a FUNCTION-LOCAL import,
    so this module's top-level import graph stays exactly {vigil_core, .transparency} (the sovereign failover
    guard imports it and must not pull the wider integration surface at import time)."""
    from .integrity_verifier import Alarm, AlarmSink, write_heartbeat  # noqa: PLC0415 — keep top-level graph lean
    from datetime import datetime, timezone

    rp = Path(retain_path)
    sink = sink or AlarmSink(log_path=str(_default_emit_alarm_log(rp)))
    hb = Path(heartbeat_path) if heartbeat_path else _default_emit_heartbeat_path(rp)
    ts = datetime.fromtimestamp(now, timezone.utc).isoformat()

    # (1) alarm on the PRE-EXISTING anchor's staleness (before we refresh it). A first-ever emit (no prior
    # anchor on disk) is NOT stale — there is nothing to be stale.
    if rp.exists():
        prior_at: Optional[int]
        try:
            prior_at = envelope_emitted_at(rp.read_text(encoding="utf-8"))
        except OSError:
            prior_at = None
        fv = freshness_verdict(prior_at, now=now, warn_after_s=warn_after_s, refuse_after_s=refuse_after_s)
        if fv.alert:
            sink.emit(Alarm(ts=ts, severity=("critical" if fv.refuse else "warning"), kind="anchor-stale",
                            home=str(rp), detail=fv.detail))

    # (2) refresh the anchor off-box
    try:
        wc = emit_fn(now)
    except Exception as exc:  # noqa: BLE001 — the emitter failing is itself an alarmable condition
        sink.emit(Alarm(ts=ts, severity="error", kind="anchor-emit-error", home=str(rp),
                        detail=f"the scheduled witnessed-checkpoint emitter failed to run: "
                               f"{type(exc).__name__}: {exc}"))
        write_heartbeat(hb, now=now, ok=False, report=None, seq=seq)
        raise

    # (3) dead-man heartbeat: an absent/old heartbeat means the scheduler itself stopped running.
    write_heartbeat(hb, now=now, ok=True, report=None, seq=seq)
    return wc


def run_checkpoint_monitor(emit_fn: Callable[[float], WitnessedCheckpoint], *,
                           retain_path: os.PathLike | str, cycles: int = 1, interval: float = 0.0,
                           sleep: Callable[[float], object] = time.sleep,
                           now_fn: Callable[[], float] = time.time, sink=None,
                           heartbeat_path: Optional[os.PathLike | str] = None,
                           warn_after_s: Optional[int] = None,
                           refuse_after_s: Optional[int] = None) -> dict:
    """Run ``cycles`` emitter cycles (``cycles<=0`` ⇒ forever) with an INJECTABLE cadence (``sleep`` /
    ``interval``) and clock (``now_fn``) — deterministic in tests. Each cycle runs :func:`run_checkpoint_once`.
    An emit failure is alarmed inside the cycle and the loop CONTINUES (the next cycle retries), but the
    heartbeat it wrote is a FAILING one, so a persistent outage still trips the dead-man. Returns a summary
    ``{cycles_run, emits, errors, stale_alerts}``."""
    from .integrity_verifier import AlarmSink  # noqa: PLC0415

    rp = Path(retain_path)
    sink = sink or AlarmSink(log_path=str(_default_emit_alarm_log(rp)))
    emits = errors = 0
    i = 0
    forever = cycles <= 0
    while forever or i < cycles:
        now = now_fn()
        try:
            run_checkpoint_once(emit_fn, retain_path=rp, now=now, sink=sink, heartbeat_path=heartbeat_path,
                                warn_after_s=warn_after_s, refuse_after_s=refuse_after_s, seq=i)
            emits += 1
        except Exception:  # noqa: BLE001 — already alarmed inside run_checkpoint_once; keep the loop alive
            errors += 1
        i += 1
        if forever or i < cycles:
            sleep(interval)
    return {"cycles_run": i, "emits": emits, "errors": errors, "retain_path": str(rp)}


def emit_heartbeat_is_stale(retain_path: os.PathLike | str, *, now: Optional[float] = None,
                            max_staleness_s: Optional[int] = None) -> tuple[bool, str]:
    """Dead-man check for the scheduled EMITTER (distinct from the integrity-verifier heartbeat): is the
    off-box emitter failing to run? Returns ``(stale, detail)``, fail-closed (absent/undated ⇒ stale).
    Defaults ``max_staleness_s`` to the anchor REFUSE bound — if the emitter has been silent that long, the
    guard would already refuse the anchor, so the operator must be alarmed by then at the latest."""
    from .integrity_verifier import heartbeat_is_stale  # noqa: PLC0415
    max_staleness_s = (_env_int(_REFUSE_AFTER_S_ENV, DEFAULT_REFUSE_AFTER_S)
                       if max_staleness_s is None else max_staleness_s)
    return heartbeat_is_stale(_default_emit_heartbeat_path(retain_path), now=now,
                              max_staleness_s=max_staleness_s)
