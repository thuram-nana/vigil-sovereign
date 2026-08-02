"""remediation.attestation_log — the VIGIL Continuous Attestation Log (VF-1b).

A signed, hash-chained, anti-rollback **monotonic series of remediation re-proof ticks**. Each tick is one
signed four-state prove-certificate minted by :func:`prove_driver.prove_remediation` (REMEDIATED /
STILL_VULNERABLE / INCONCLUSIVE / REFUSED). The log turns a point-in-time "we proved it fixed" into
continuous, provable assurance (VISION.md § *Continuous proof / drift watch*): a finding is no longer proven
"as of the report date" but "as of the last re-proof", and the whole series is offline-re-verifiable and
un-rolled-back.

It composes the merged VF foundation WITHOUT re-implementing any crypto — every primitive is IMPORTED:

  * ADMISSION       — :func:`prove_driver.verify_prove_certificate` (whole-cert Ed25519 + verdict/state
                       agreement + for REMEDIATED the embedded remediation cert re-executes). An unauthentic
                       tick is REFUSED at the door; it never enters the chain.
  * CHAIN + HEAD    — :func:`vigil_core.build_chain` over the tick digests + :func:`vigil_core.sign_head`
                       (governance m-of-n), verified by :func:`vigil_core.verify_head` (chain integrity,
                       head↔chain binding, signature, and the ``last_seq`` anti-rollback).
  * DURABLE FLOOR   — :mod:`vigil_core.highwater` (``entry_count`` PRIMARY monotonic guard + ``last_seq``),
                       advanced UPWARD-ONLY under a cross-process lock. This is what refuses a stale,
                       validly-signed SMALLER log (a truncated series / suppressed regression) that the
                       in-band signature alone cannot catch (that old head was validly signed).

Anti-rollback, exactly (all enforced BEFORE any bytes are persisted, and again in :func:`verify_log`):
  1. ``verify_head(prev_highwater=<floor.last_seq>)`` rejects ``head.last_seq < floor.last_seq``  AND rebinds
     the head to the rebuilt-from-ticks chain (a truncated/reordered/tampered tick → head_hash / last_seq /
     entry_count mismatch → "log truncated or head rewritten").
  2. ``check_highwater`` rejects ``head.entry_count < floor.entry_count`` — the PRIMARY guard, because
     ``last_seq`` is 0-indexed (0 for BOTH an empty and a 1-tick log), so a 1→0 truncation slips a
     ``last_seq``-only check but never the ``entry_count`` guard.
  3. ``advance_highwater`` is UPWARD-ONLY under a lock, re-loads inside the lock, and raises
     :class:`vigil_core.HighWaterDowngrade` on any downgrade.

FATAL-2: the module scope pulls ONLY stdlib + ``vigil_core`` + ``.prove_driver`` (all import-clean — no
``framework.v2``); ``verify_prove_certificate`` does its framework re-execute in a FUNCTION-LOCAL import at
call time, so importing this module in the sovereign env never co-loads the offense engine.

Determinism: no wallclock / rng in the signed math — the prove-cert already carries the caller-supplied
``now`` / ``run_id`` / nonces; ``seq`` is the tick index; the chain + head are pure functions of the ticks.

HONEST LIMIT (do NOT overclaim, mirrors :mod:`vigil_core.highwater`): the durable floor is a LOCAL, unsigned
0600 file. A SAME-HOST attacker with the owner's UID (or root) who rewrites the tick log, the head, AND the
floor together defeats the LOCAL :func:`verify_log` path (it re-reads the floor from that same
attacker-controlled disk). The sound anti-rollback guarantee therefore holds against (i) an attacker who can
overwrite the log/head but NOT the floor, and (ii) an OUT-OF-BAND verifier that retained a newer floor. A
fully-dishonest producer is closed only by the independent out-of-band witness (VF-1c), not by this file.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from vigil_core import (
    SignedChainHead,
    advance_highwater,
    build_chain,
    check_highwater,
    digest_payload,
    highwater_lock,
    load_highwater,
    sign_head,
    verify_head,
)

# prove_driver's module scope is stdlib + vigil_core only (its framework re-execute is function-local), so
# importing these here is FATAL-2 safe — the framework loads only when verify_prove_certificate adjudicates
# a REMEDIATED tick, at call time, in its own lazy import.
from .prove_driver import State, verify_prove_certificate

_PathLike = Union[str, os.PathLike]

_TICKS_FILE = "ticks.jsonl"
_HEAD_FILE = "head.json"
_HIGHWATER_FILE = "highwater.json"


# --------------------------------------------------------------------------------------------------------
# Drift vocabulary (VISION.md § Continuous proof / drift watch) — the monotonic state-series labels.
# --------------------------------------------------------------------------------------------------------
LABEL_PRESENT = "present"            # STILL_VULNERABLE with no proven baseline yet (the vuln is present)
LABEL_PROVEN_FIXED = "proven-fixed"  # the FIRST REMEDIATED — a proven fix is established (VISION "newly-fixed")
LABEL_STILL_PROVEN = "still-proven"  # a consecutive REMEDIATED — the fix still holds
LABEL_REGRESSED = "regressed"        # REMEDIATED -> STILL_VULNERABLE — the proven fix regressed
LABEL_INCONCLUSIVE = "inconclusive"  # recorded, but does NOT advance OR reset the proven baseline
LABEL_REFUSED = "refused"            # recorded; testing did not begin — no baseline change
LABEL_UNKNOWN = "unknown"


class AttestationError(RuntimeError):
    """A fail-closed refusal to APPEND or a fail-closed :func:`verify_log` failure that is not a bad-signer
    admission refusal (a corrupt persisted log, a head that does not verify, a rollback)."""


class AttestationRefused(AttestationError):
    """ADMISSION refusal: the tick's prove-certificate is not authentic (bad/forged signature, verdict/state
    disagreement, or — for REMEDIATED — the embedded remediation cert does not re-execute). It never enters
    the chain."""


@dataclass(frozen=True)
class TickStatus:
    """One tick's place in the monotonic series: its 0-indexed ``seq``, the four-state ``state`` it carries,
    the derived drift ``label`` (the VISION vocabulary above), and the prove-cert's ``reason_code``."""
    seq: int
    state: str
    label: str
    reason_code: str = ""


@dataclass
class AppendResult:
    """The outcome of :func:`append_tick`: the appended tick's ``state``/``seq``, the new governance-signed
    ``head`` that now anchors the whole series, the running ``series`` (drift labels for every tick so far),
    and the appended tick's ``reason_code``."""
    state: str
    seq: int
    head: SignedChainHead
    series: list[TickStatus] = field(default_factory=list)
    reason_code: str = ""


# --------------------------------------------------------------------------------------------------------
# persistence helpers (stdlib only; atomic + 0600; whole-file rewrite so a crash never leaves a torn line)
# --------------------------------------------------------------------------------------------------------
def _ticks_path(log_dir: Path) -> Path:
    return log_dir / _TICKS_FILE


def _head_path(log_dir: Path) -> Path:
    return log_dir / _HEAD_FILE


def _highwater_path(log_dir: _PathLike) -> Path:
    return Path(log_dir) / _HIGHWATER_FILE


def _atomic_write_0600(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.parent / (f".{p.name}.tmp-{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover — non-POSIX; content is signed/inert, mode is best-effort
        pass


def _load_ticks(log_dir: Path) -> list[dict]:
    """Read the persisted tick certificates in seq order. ``[]`` if absent. RAISES :class:`AttestationError`
    on a corrupt/partial line (fail-closed — a torn tick must never be silently dropped, which would look
    like a shorter, 'valid' log)."""
    p = _ticks_path(log_dir)
    if not p.exists():
        return []
    ticks: list[dict] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as e:
            raise AttestationError(f"tick log line {lineno} is corrupt/partial (possible tamper/torn write): {e}")
        if not isinstance(obj, dict):
            raise AttestationError(f"tick log line {lineno} is not a JSON object (possible tamper)")
        ticks.append(obj)
    return ticks


def _write_ticks(log_dir: Path, ticks: list[dict]) -> None:
    # Whole-file atomic rewrite (one compact line per tick, key-sorted for stable bytes). The whole file is
    # replaced atomically, so a crash leaves either the complete OLD set or the complete NEW set — never a
    # torn last line. digest_payload re-canonicalises on read, so this on-disk form does not affect digests.
    body = "".join(json.dumps(t, sort_keys=True, separators=(",", ":")) + "\n" for t in ticks)
    _atomic_write_0600(_ticks_path(log_dir), body)


def _load_head(log_dir: Path) -> Optional[SignedChainHead]:
    p = _head_path(log_dir)
    if not p.exists():
        return None
    return SignedChainHead.model_validate_json(p.read_text(encoding="utf-8"))


def _write_head(log_dir: Path, head: SignedChainHead) -> None:
    _atomic_write_0600(_head_path(log_dir), head.model_dump_json())


def _reason_of(cert: dict) -> str:
    verdict = cert.get("verdict") if isinstance(cert, dict) else None
    return str((verdict or {}).get("reason_code") or "")


# --------------------------------------------------------------------------------------------------------
# the monotonic drift series
# --------------------------------------------------------------------------------------------------------
def _derive_series(ticks: list[dict]) -> list[TickStatus]:
    """Fold the consecutive tick STATES into the VISION drift vocabulary. ``proven`` tracks whether a proven
    fix currently holds: a REMEDIATED establishes it (first: 'proven-fixed'; consecutive: 'still-proven'); a
    STILL_VULNERABLE clears it ('regressed' if it was proven, else 'present'); INCONCLUSIVE/REFUSED are
    recorded but neither advance NOR reset the baseline (an inconclusive re-proof must not silently promote a
    finding to 'proven', nor demote a standing proof)."""
    series: list[TickStatus] = []
    proven = False
    for i, t in enumerate(ticks):
        state = str(t.get("state") or "")
        if state == State.REMEDIATED:
            label = LABEL_STILL_PROVEN if proven else LABEL_PROVEN_FIXED
            proven = True
        elif state == State.STILL_VULNERABLE:
            label = LABEL_REGRESSED if proven else LABEL_PRESENT
            proven = False
        elif state == State.INCONCLUSIVE:
            label = LABEL_INCONCLUSIVE            # baseline unchanged
        elif state == State.REFUSED:
            label = LABEL_REFUSED                 # baseline unchanged
        else:
            label = LABEL_UNKNOWN
        series.append(TickStatus(seq=i, state=state, label=label, reason_code=_reason_of(t)))
    return series


# --------------------------------------------------------------------------------------------------------
# append + verify
# --------------------------------------------------------------------------------------------------------
def append_tick(
    log_dir: _PathLike,
    cert: dict,
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    trust_root,
    signer_pubkeys: "dict[str, str]",
) -> AppendResult:
    """Admit + append one remediation re-proof tick to the log at ``log_dir`` and return an
    :class:`AppendResult`. FAIL-CLOSED at every step — if any check fails, NOTHING is persisted:

      a. ADMISSION: ``verify_prove_certificate(cert, signer_pubkeys)`` must pass, else
         :class:`AttestationRefused` (an unauthentic/forged tick never enters the chain).
      b. Load the persisted ticks + the durable high-water — INSIDE the cross-process lock (a consistent
         snapshot; the whole append critical section is serialized so concurrent appends are
         last-writer-MONOTONIC, never last-writer-wins).
      c. digest each tick (``digest_payload(cert)`` — the prove-cert has no top-level ``cert_digest``),
         rebuild the chain over ALL tick digests, and governance-sign the head.
      d. ``verify_head(prev_highwater=<floor.last_seq>)`` AND ``check_highwater`` (PRIMARY entry_count guard)
         must both pass BEFORE persisting.
      e. Persist ticks + head, then ``advance_highwater`` UPWARD-ONLY (raises on downgrade). Ordered so the
         floor is advanced LAST — only after ticks + head are durable.

    ``signers`` signs the chain head (governance m-of-n); ``trust_root`` verifies it; ``signer_pubkeys`` pins
    the prove-cert admission key. (In production all three derive from one governance authority — see
    ``live/wiring.py:provision_authority``.)"""
    if not signers:
        raise AttestationError("append_tick: governance signers are required (never an unsigned head)")

    # a. ADMISSION — before touching any persisted state.
    ok, reason = verify_prove_certificate(cert, signer_pubkeys=signer_pubkeys)
    if not ok:
        raise AttestationRefused(f"tick refused at admission (unauthentic prove-cert): {reason}")

    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    hw_path = _highwater_path(log_dir)

    # The whole critical section under the floor lock → the load→verify→persist→advance quintuple is atomic
    # and last-writer-monotonic (a racing append cannot slip a stale floor past the downgrade guard).
    with highwater_lock(hw_path):
        # b. consistent snapshot of the persisted ticks + durable floor.
        prior_ticks = _load_ticks(log_dir)
        hw = load_highwater(hw_path)

        # c. digest + rebuild the chain over ALL tick digests, sign the new head.
        new_ticks = prior_ticks + [cert]
        digests = [digest_payload(t) for t in new_ticks]
        entries = build_chain(digests)
        head = sign_head(entries, engagement_slug=engagement_slug, signers=signers)

        # d. anti-rollback + integrity BEFORE persisting anything.
        prev_seq = hw["last_seq"] if hw else None
        vok, vreason = verify_head(head, entries, trust_root, prev_highwater=prev_seq)
        if not vok:
            raise AttestationError(f"refusing to persist tick: head verify failed: {vreason}")
        cok, creason = check_highwater(head, hw)   # entry_count PRIMARY guard (verify_head only checks last_seq)
        if not cok:
            raise AttestationError(f"refusing to persist tick: {creason}")

        # e. persist ticks + head, then advance the floor UPWARD-ONLY — all under the held lock (atomic).
        _write_ticks(log_dir, new_ticks)
        _write_head(log_dir, head)
        advance_highwater(hw_path, head, _locked=True)   # re-checks under the lock; raises on any downgrade

    series = _derive_series(new_ticks)
    return AppendResult(state=str(cert.get("state") or ""), seq=int(head.last_seq), head=head,
                        series=series, reason_code=_reason_of(cert))


def verify_log(
    log_dir: _PathLike,
    *,
    trust_root,
    signer_pubkeys: "dict[str, str]",
) -> tuple[bool, str, list[TickStatus]]:
    """Offline-verify the whole log and derive its monotonic drift series. Returns
    ``(authentic_unbroken_unrolledback, reason, series)``. FAIL-CLOSED on any failure (returns
    ``(False, reason, [])``):

      1. rebuild the chain from the persisted tick certs; ``verify_head`` binds the PERSISTED head to that
         rebuilt chain (integrity + head↔chain + signature) with ``prev_highwater=<persisted floor last_seq>``
         (rejects a rolled-back head), and ``check_highwater`` enforces the PRIMARY ``entry_count`` floor;
      2. re-run ``verify_prove_certificate`` on EVERY tick (a tampered / forged tick is rejected — this also
         re-executes each REMEDIATED tick's embedded remediation cert);
      3. only then derive + return the drift series.

    ``trust_root`` (head signature) and ``signer_pubkeys`` (prove-cert admission) are CALLER-PINNED — pin
    them out-of-band exactly like the client-verifiable proof bundle; the log ships no trust root of its own."""
    log_dir = Path(log_dir)
    try:
        ticks = _load_ticks(log_dir)
    except AttestationError as e:
        return False, f"tick log unreadable: {e}", []

    head = _load_head(log_dir)
    if not ticks and head is None:
        return True, "empty attestation log (no ticks)", []
    if head is None:
        return False, "tick log has entries but no signed head (truncated/removed head — fail closed)", []

    try:
        hw = load_highwater(_highwater_path(log_dir))
    except Exception as e:  # noqa: BLE001 — a corrupt floor fails closed, never reads as absent
        return False, f"durable high-water unreadable: {e}", []

    # 1. bind the persisted head to the rebuilt-from-ticks chain + enforce the anti-rollback floor.
    digests = [digest_payload(t) for t in ticks]
    entries = build_chain(digests)
    prev_seq = hw["last_seq"] if hw else None
    ok, reason = verify_head(head, entries, trust_root, prev_highwater=prev_seq)
    if not ok:
        return False, f"chain/head not authentic or rolled back: {reason}", []
    ok_hw, hw_reason = check_highwater(head, hw)   # PRIMARY entry_count anti-rollback guard
    if not ok_hw:
        return False, hw_reason, []

    # 2. re-run the prove-cert admission on EVERY tick (tampered/forged → rejected; REMEDIATED re-executes).
    for i, t in enumerate(ticks):
        vok, vreason = verify_prove_certificate(t, signer_pubkeys=signer_pubkeys)
        if not vok:
            return False, f"tick {i} failed re-verification (tampered/forged): {vreason}", []

    # 3. the log is authentic, unbroken, and un-rolled-back — derive the monotonic drift series.
    series = _derive_series(ticks)
    return True, (f"{len(ticks)} tick(s) authentic, chain unbroken, head signed, un-rolled-back "
                  f"(floor entry_count={hw['entry_count'] if hw else 0})"), series
