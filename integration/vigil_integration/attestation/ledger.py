"""
attestation.ledger — the always-on usage-attestation ledger core (VIGIL WS6).

The operator's "deep core that can always determine when this tool was used and by whom, tied to a
ledger." Before any engagement/gated action the engine calls :func:`require_attestation`; it mints a
signed :class:`UsageAttestation` FIRST and returns a fail-closed verdict — no attestation can be minted
(no signer, an unbound operator, malformed input, or a durable-write failure) ⇒ the engine gets a DENY
and cannot proceed. The minted record binds:

  * WHO — the :class:`OperatorIdentity` (OS login + git name/email + operator key fingerprint + hostname);
  * WHEN — the wall ``at`` (an injected DATA field) plus a MONOTONIC anchor (TPM or persisted software
    counter) that never decreases, so a record can never be back-dated;
  * WHAT — ``action`` / ``target`` / ``phase`` — and every free string bound above, including the WHEN
    string ``at``, is secret-redacted at mint time through the one F3 vocabulary, so no credential is
    ever committed to the signed record.

The ledger is append-only + hash-chained + Ed25519-signed. :func:`verify_ledger` re-checks the whole
PRESENTED chain — contiguity, each record hash, the non-decreasing monotonic anchor, the operator
binding, and every signature against an injected trust anchor — so a tampered, reordered, interior-
deleted, or forged entry FAILS. It proves the internal consistency of the presented records; because a
valid PREFIX of the chain is itself internally consistent, that check alone CANNOT detect that the TAIL
was truncated (the most-recent records dropped) or the whole file WIPED. To catch a dropped tail / total
wipe the caller pins an external anchor it persists out-of-band — ``verify_ledger(..., expected_head=,
expected_count=)`` — so a truncated/wiped ledger fails against the known head/count. :func:`ledger_who` /
:func:`ledger_when` replay it for non-repudiation.

Sovereign rules held here: the chain order is ``(seq, prev_hash)`` alone — ``at``/``monotonic`` are
signed DATA, never ordering keys, so no wallclock/RNG touches the chain math (Ed25519 signing is itself
deterministic). The signer/anchor/writer/key-resolver are all INJECTED callables, so the whole module is
unit-testable without a live kernel/TPM. Every public function is total: malformed / attacker-influenced
input degrades to "no attestation" / "not verified", never an exception.

Import-clean: pydantic + stdlib + ``vigil_core`` (crypto/canonical/chain seam) + the F3 redactor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Union

from vigil_core.canonical import canonical_json, evidence_signing_bytes, sha256_hex
from vigil_core.crypto import verify_one
from vigil_core.models import Signature

from ..tools.mcp_registry import _redact_str
from .anchor import read_monotonic_anchor
from .identity import ResolveKeyFn, SignerFn
from .models import (
    GENESIS_PREV,
    MonotonicAnchor,
    OperatorIdentity,
    UsageAttestation,
    WhenEntry,
    WhoEntry,
)

# Domain-separates an attestation's signing payload from every other record type sharing the vigil_core
# signing-bytes seam — a signature over an attestation can never be replayed as (say) a chain-head sig.
_KIND = "vigil-usage-attestation-v1"


# --- canonical signed content (the pure, shared basis for mint AND verify) --------------------------


def _content(
    *, seq: int, prev_hash: str, operator: OperatorIdentity, action: str, target: str, phase: str,
    at: str, monotonic: int, grounded: str,
) -> dict:
    """The exact signed content of a record — a pure function of its fields. ``canonical_json`` sorts
    keys, so both mint and verify derive byte-identical bytes from the same field values."""
    return {
        "action": action,
        "at": at,
        "grounded": grounded,
        "kind": _KIND,
        "monotonic": monotonic,
        "operator": operator.model_dump(mode="json"),
        "phase": phase,
        "prev_hash": prev_hash,
        "seq": seq,
        "target": target,
    }


def _record_hash(content: dict) -> str:
    return sha256_hex(canonical_json(content))


def _signing_bytes(content: dict) -> bytes:
    return evidence_signing_bytes(content)


def _as_seq(value: Any) -> int:
    """Coerce the injected seq to a non-negative int, total (bool excluded — not a sequence number)."""
    if isinstance(value, bool):
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    return n if n >= 0 else 0


def _coerce_operator(operator: Any) -> Optional[OperatorIdentity]:
    """Coerce to an :class:`OperatorIdentity`, total. A model passes through; a dict is validated
    (``extra="forbid"`` rejects smuggled fields); anything else → None (no operator ⇒ no attestation)."""
    if isinstance(operator, OperatorIdentity):
        return operator
    if isinstance(operator, Mapping):
        try:
            return OperatorIdentity.model_validate(dict(operator))
        except Exception:  # noqa: BLE001 — a malformed operator blob cannot mint
            return None
    return None


def _coerce_anchor(anchor: Any) -> Optional[MonotonicAnchor]:
    if isinstance(anchor, MonotonicAnchor):
        return anchor
    if isinstance(anchor, Mapping):
        try:
            return MonotonicAnchor.model_validate(dict(anchor))
        except Exception:  # noqa: BLE001
            return None
    return None


# --- minting ---------------------------------------------------------------------------------------


def record_usage(
    *,
    operator: Any,
    action: Any,
    target: Any,
    phase: Any,
    at: Any,
    prev_hash: Any,
    signer: Optional[SignerFn],
    seq: Any = 0,
    anchor: Optional[MonotonicAnchor] = None,
    anchor_state_path: Optional[str] = None,
) -> Optional[UsageAttestation]:
    """Mint one signed, hash-chained :class:`UsageAttestation`, or return None if one cannot be minted.

    Fail-closed / total. Returns None (no attestation — the caller must NOT proceed) when: ``signer`` is
    None or errors or returns a non-``Signature`` / a ``key_id`` that is not the bound operator's
    fingerprint; the operator is unresolvable or unbound; or any step raises. On success the record binds
    WHO/WHEN/WHAT, is content-hashed (the chain link), and is signed over the domain-tagged content.

    Determinism / spine-safety: ``seq`` and ``prev_hash`` are the injected ordering coordinates; ``at`` is
    an injected DATA field (never the clock); ``monotonic`` comes from the injected/persisted anchor
    (never decreases). Every free string committed to the ledger (``action``/``target``/``phase``/``at``)
    is redacted through the one F3 vocabulary so no credential lands in the ledger. No wallclock/RNG
    touches the chain (Ed25519 signing is deterministic)."""
    if signer is None:
        return None
    op = _coerce_operator(operator)
    if op is None or not op.is_bound():
        return None
    try:
        seq_n = _as_seq(seq)
        prev = prev_hash if isinstance(prev_hash, str) else GENESIS_PREV
        # Redact EVERY free-string field committed to the signed, append-only ledger through the ONE F3
        # vocabulary — action/target (WHAT) AND phase (WHAT) AND at (WHEN). Whichever field a credential
        # rides on, it never lands in the record. Redaction is deterministic (a pure string transform: no
        # wallclock/RNG) and runs BEFORE hashing/signing, so a redacted record still verifies.
        act = _redact_str(action) if isinstance(action, str) else ""
        tgt = _redact_str(target) if isinstance(target, str) else ""
        ph = _redact_str(phase) if isinstance(phase, str) else ""
        at_s = _redact_str(at) if isinstance(at, str) else ""
        anc = _coerce_anchor(anchor)
        if anc is None:
            anc = read_monotonic_anchor(state_path=anchor_state_path)
        content = _content(seq=seq_n, prev_hash=prev, operator=op, action=act, target=tgt, phase=ph,
                           at=at_s, monotonic=anc.value, grounded=anc.grounded)
        rec_hash = _record_hash(content)
        sig = signer(_signing_bytes(content))
    except Exception:  # noqa: BLE001 — any mint failure (incl. a raising signer) ⇒ no attestation
        return None
    # The signer must return a genuine Signature whose key_id is the bound operator's fingerprint — the
    # identity ↔ signature binding. A mismatch/None/wrong-type is fail-closed (no attestation).
    if not isinstance(sig, Signature) or sig.key_id != op.key_fingerprint:
        return None
    try:
        return UsageAttestation(
            seq=seq_n, prev_hash=prev, operator=op, action=act, target=tgt, phase=ph,
            at=at_s, monotonic=anc.value, grounded=anc.grounded, record_hash=rec_hash, signature=sig,
        )
    except Exception:  # noqa: BLE001 — a model that will not construct is no attestation, never a crash
        return None


# --- the fail-closed engagement gate ---------------------------------------------------------------


@dataclass(frozen=True)
class AttestationVerdict:
    """The verdict :func:`require_attestation` hands the engine. ``allowed``/``outcome`` are the gate
    decision; ``attestation`` is the minted record (present iff allowed)."""

    allowed: bool
    outcome: str            # "allow" | "deny"
    reason: str
    attestation: Optional[UsageAttestation] = None


# writer(att) -> append the record to the durable append-only ledger. Its ABSENCE (at the gate) or its
# failure ⇒ DENY (fail-closed on durability: the engine must not proceed with an action whose attestation
# was not durably recorded).
WriterFn = Callable[[UsageAttestation], Any]


def require_attestation(
    *,
    operator: Any,
    action: Any,
    target: Any,
    phase: Any,
    at: Any,
    prev_hash: Any,
    signer: Optional[SignerFn],
    seq: Any = 0,
    anchor: Optional[MonotonicAnchor] = None,
    anchor_state_path: Optional[str] = None,
    writer: Optional[WriterFn] = None,
) -> AttestationVerdict:
    """The gate the engine calls BEFORE any engagement/gated action. Mints an attestation FIRST; DENY if
    one cannot be minted (no signer / unbound operator / malformed input), if NO durable ``writer`` is
    wired, or if the durable append fails. ALLOW only once a signed record exists AND is durably recorded.
    The ledger is always-on, so the gate is fail-closed on durability: a ``writer`` is MANDATORY here (a
    gated action must never proceed on an attestation that was never persisted) — use :func:`record_usage`
    for the writer-less in-memory mint primitive. Total: never raises — every failure path is a DENY,
    never a silent proceed."""
    att = record_usage(
        operator=operator, action=action, target=target, phase=phase, at=at, prev_hash=prev_hash,
        signer=signer, seq=seq, anchor=anchor, anchor_state_path=anchor_state_path,
    )
    if att is None:
        return AttestationVerdict(
            False, "deny",
            "no attestation could be minted (no signer / unbound operator / malformed input) — "
            "fail-closed DENY", None,
        )
    if writer is None:
        return AttestationVerdict(
            False, "deny",
            "no durable ledger writer wired — the engagement gate will not authorize an action whose "
            "attestation is not durably recorded (fail-closed DENY); record_usage is the writer-less "
            "in-memory mint primitive", None,
        )
    try:
        writer(att)
    except Exception as exc:  # noqa: BLE001 — an un-recorded attestation must not authorize the action
        return AttestationVerdict(
            False, "deny", f"attestation minted but could not be durably recorded: {exc} — "
            "fail-closed DENY", None,
        )
    return AttestationVerdict(True, "allow", "usage attested and recorded", att)


# --- verification ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class LedgerVerification:
    """The result of :func:`verify_ledger`. ``ok`` is the whole-ledger verdict; ``operators`` is the set
    of distinct operator fingerprints that signed valid records (the non-repudiation roster)."""

    ok: bool
    reason: str
    count: int = 0
    operators: tuple[str, ...] = ()


ResolveKeyArg = Union[ResolveKeyFn, Mapping[str, str], None]


def _normalize_resolver(resolve_key: ResolveKeyArg) -> Optional[ResolveKeyFn]:
    """Accept a mapping OR a callable OR None; return a total callable (or None). A mapping becomes a
    ``.get`` lookup; a callable is wrapped so a raising resolver reads as 'untrusted', never a crash."""
    if resolve_key is None:
        return None
    if isinstance(resolve_key, Mapping):
        try:
            mapping = dict(resolve_key)
        except Exception:  # noqa: BLE001 — a pathological Mapping whose iteration/keys raises ⇒ no trusted
            return None    # resolver wired (fail-closed DENY on verify), never a propagated exception
        return lambda k: mapping.get(k)

    def _safe(k: str) -> Optional[str]:
        try:
            v = resolve_key(k)
        except Exception:  # noqa: BLE001 — a misbehaving resolver denies (fail-closed), never raises
            return None
        return v if isinstance(v, str) and v else None

    return _safe


def _coerce_record(row: Any) -> Optional[UsageAttestation]:
    """Coerce one ledger row to a :class:`UsageAttestation`, total. A model passes through; a dict is
    validated; anything else → None."""
    if isinstance(row, UsageAttestation):
        return row
    if isinstance(row, Mapping):
        try:
            return UsageAttestation.model_validate(dict(row))
        except Exception:  # noqa: BLE001
            return None
    return None


def _iter_rows(records: Any) -> list[Any]:
    """Materialize an (attacker-influenceable, possibly-lazy) record source into a list, total. A
    non-iterable / a reader whose iteration raises yields ``[]`` (no signal), never a crash."""
    if records is None:
        return []
    if isinstance(records, (str, bytes, Mapping)):
        return [records]
    try:
        return list(records)
    except Exception:  # noqa: BLE001 — a lazy/broken iterable degrades to no records
        return []


def _as_expected_count(value: Any) -> Optional[int]:
    """Coerce a caller-pinned expected record count to a non-negative int, total. ``None`` / a malformed
    value ⇒ no pin (``None``); ``bool`` is excluded (it is not a count). A negative int is not a valid
    count and also reads as no pin."""
    if value is None or isinstance(value, bool):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def verify_ledger(
    records: Any,
    *,
    resolve_key: ResolveKeyArg = None,
    expected_head: Optional[str] = None,
    expected_count: Optional[int] = None,
) -> LedgerVerification:
    """Verify the presented ledger: append-only contiguity + each record hash + non-decreasing monotonic
    anchor + operator binding + every Ed25519 signature. Total — never raises.

    DENY-BY-DEFAULT on trust: without a ``resolve_key`` trust anchor the signatures cannot be checked, so
    a non-empty ledger is NOT ``ok``. STRICT: any row that does not coerce, a hash that does not
    recompute, a broken ``prev_hash`` link or ``seq`` gap, a monotonic value that decreases, an unbound
    operator, a ``key_id`` that is not the operator's fingerprint, an untrusted ``key_id``, or an invalid
    signature — ANY of these fails the whole ledger (a tampered / reordered / interior-deleted / forged
    entry is caught). Ordered by ``seq`` (with ``prev_hash`` linkage), so verification is independent of
    the input list's order.

    SCOPE — what internal consistency alone CANNOT catch: this function proves the presented records are a
    self-consistent chain rooted at genesis. Because a valid PREFIX of a chain is itself a self-consistent
    chain rooted at genesis, this cannot by itself detect that the TAIL was truncated (the most-recent
    records dropped) or that the whole ledger was WIPED (an empty ledger is vacuously consistent). To catch
    a dropped tail / total wipe the caller pins an EXTERNAL anchor it persists out-of-band:

      * ``expected_head`` — the ``record_hash`` the ledger's most-recent (highest-``seq``) record must
        carry. A truncated tail (or a wipe → no head) no longer matches ⇒ FAIL.
      * ``expected_count`` — the number of records the ledger must contain. Any dropped record ⇒ FAIL.

    A pin against an empty ledger fails unless it is exactly ``expected_count=0`` with no ``expected_head``
    (an explicitly-expected-empty ledger). Both pins are optional and total: a malformed pin is ignored
    (no anchor), never a crash."""
    exp_count = _as_expected_count(expected_count)
    exp_head = expected_head if isinstance(expected_head, str) and expected_head else None
    rows = _iter_rows(records)
    if not rows:
        # Empty ledger. A pinned head, or a pinned positive count, is a total-wipe / tail-truncated-to-
        # nothing ⇒ FAIL. ``expected_count=0`` with no head is the one pin an empty ledger satisfies.
        if exp_head is not None:
            return LedgerVerification(False, "empty ledger does not match the caller-pinned head "
                                      "(total wipe / tail truncated to nothing)", 0, ())
        if exp_count is not None and exp_count != 0:
            return LedgerVerification(False, f"empty ledger has 0 records, not the caller-pinned "
                                      f"{exp_count} (records dropped / total wipe)", 0, ())
        reason = ("empty ledger satisfies the pinned count of 0" if exp_count == 0 else
                  "empty ledger (vacuously consistent — internal-consistency only; pin expected_head/"
                  "expected_count to detect a truncated tail or total wipe)")
        return LedgerVerification(True, reason, 0, ())
    resolver = _normalize_resolver(resolve_key)
    if resolver is None:
        return LedgerVerification(False, "no trusted operator key resolver wired — cannot verify "
                                  "signatures (fail-closed)", 0, ())
    coerced: list[UsageAttestation] = []
    for row in rows:
        rec = _coerce_record(row)
        if rec is None:
            return LedgerVerification(False, "ledger contains a malformed/forged record", 0, ())
        coerced.append(rec)
    ordered = sorted(coerced, key=lambda r: (r.seq, r.record_hash))
    prev_hash = GENESIS_PREV
    prev_seq: Optional[int] = None
    prev_monotonic: Optional[int] = None
    operators: list[str] = []
    for rec in ordered:
        content = _content(seq=rec.seq, prev_hash=rec.prev_hash, operator=rec.operator, action=rec.action,
                           target=rec.target, phase=rec.phase, at=rec.at, monotonic=rec.monotonic,
                           grounded=rec.grounded)
        if _record_hash(content) != rec.record_hash:
            return LedgerVerification(False, f"record hash mismatch at seq {rec.seq} (tampered)", 0, ())
        if rec.prev_hash != prev_hash:
            return LedgerVerification(False, f"chain break at seq {rec.seq}: prev_hash mismatch "
                                      "(entry deleted/reordered)", 0, ())
        if prev_seq is not None and rec.seq != prev_seq + 1:
            return LedgerVerification(False, f"chain break: seq gap at {rec.seq}", 0, ())
        if prev_monotonic is not None and rec.monotonic < prev_monotonic:
            return LedgerVerification(False, f"monotonic anchor decreased at seq {rec.seq} "
                                      "(back-dating rejected)", 0, ())
        if not rec.operator.is_bound():
            return LedgerVerification(False, f"unbound operator at seq {rec.seq} (missing operator)", 0, ())
        if rec.signature.key_id != rec.operator.key_fingerprint:
            return LedgerVerification(False, f"signature key_id does not bind the operator at seq "
                                      f"{rec.seq}", 0, ())
        try:
            pub = resolver(rec.operator.key_fingerprint)
        except Exception:  # noqa: BLE001 — a raising resolver is a verification FAILURE, never a crash
            return LedgerVerification(False, f"key resolver failed at seq {rec.seq} (fail-closed)", 0, ())
        if pub is None:
            return LedgerVerification(False, f"untrusted operator key at seq {rec.seq} (unknown "
                                      "fingerprint)", 0, ())
        # verify_one/load_public_key RAISE (IntegrityError) on a malformed key or a non-canonical /
        # wrong-length signature_b64 — a FORGED/malformed entry is a verification FAILURE, never a crash.
        try:
            sig_ok = verify_one(pub, _signing_bytes(content), rec.signature.signature_b64)
        except Exception:  # noqa: BLE001 — total: malformed key/signature ⇒ ok=False, never raise
            return LedgerVerification(False, f"invalid signature at seq {rec.seq} (malformed/forged)", 0, ())
        if not sig_ok:
            return LedgerVerification(False, f"invalid signature at seq {rec.seq} (forged)", 0, ())
        prev_hash = rec.record_hash
        prev_seq = rec.seq
        prev_monotonic = rec.monotonic
        if rec.operator.key_fingerprint not in operators:
            operators.append(rec.operator.key_fingerprint)
    # External-anchor pins (optional): the presented chain is internally consistent, but a valid PREFIX is
    # too — so a caller-pinned head/count is what catches a truncated tail / dropped records. ``prev_hash``
    # now holds the highest-seq record's hash (the chain head); ``len(ordered)`` is the record count.
    if exp_count is not None and len(ordered) != exp_count:
        return LedgerVerification(False, f"ledger has {len(ordered)} record(s), not the caller-pinned "
                                  f"{exp_count} (tail truncated / records dropped)", 0, ())
    if exp_head is not None and prev_hash != exp_head:
        return LedgerVerification(False, "ledger head does not match the caller-pinned head "
                                  "(tail truncated / records dropped)", 0, ())
    return LedgerVerification(True, f"{len(ordered)} record(s) link, sign, and never back-date "
                              "(monotonic non-decreasing)", len(ordered), tuple(operators))


# --- replay (non-repudiation read models) ----------------------------------------------------------


def _ordered_records(records: Any) -> list[UsageAttestation]:
    """Coerce + order the ledger by ``(seq, record_hash)``, skipping malformed rows. Total. This is a
    read model — callers wanting a trust guarantee run :func:`verify_ledger` first."""
    out: list[UsageAttestation] = []
    for row in _iter_rows(records):
        rec = _coerce_record(row)
        if rec is not None:
            out.append(rec)
    return sorted(out, key=lambda r: (r.seq, r.record_hash))


def ledger_who(records: Any) -> list[WhoEntry]:
    """Replay WHO did WHAT, in chain order — the non-repudiation roster. Total on malformed input."""
    return [WhoEntry(seq=r.seq, action=r.action, target=r.target, phase=r.phase, operator=r.operator)
            for r in _ordered_records(records)]


def ledger_when(records: Any) -> list[WhenEntry]:
    """Replay WHEN each action happened (wall ``at`` + monotonic anchor), in chain order. Total."""
    return [WhenEntry(seq=r.seq, at=r.at, monotonic=r.monotonic, grounded=r.grounded)
            for r in _ordered_records(records)]


# --- durable append-only ledger persistence (JSONL) ------------------------------------------------


def append_attestation(path: Union[str, Path], att: UsageAttestation) -> None:
    """Append one record to the durable JSONL ledger (one canonical-JSON object per line). Append-only:
    it never rewrites or truncates existing lines. Raises on an I/O failure so :func:`require_attestation`
    converts it to a fail-closed DENY (an un-recorded attestation must not authorize an action)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = canonical_json(att.model_dump(mode="json")).decode("utf-8")
    with p.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read_ledger(path: Union[str, Path]) -> list[UsageAttestation]:
    """Read the durable JSONL ledger back into records, total. A missing file yields ``[]``; a torn/
    malformed line is skipped (append-only torn-tail tolerance), never a crash. Verify the result with
    :func:`verify_ledger` before trusting it."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001 — no ledger file / unreadable → no records
        return []
    out: list[UsageAttestation] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:  # noqa: BLE001 — a torn JSONL line is skipped
            continue
        rec = _coerce_record(obj)
        if rec is not None:
            out.append(rec)
    return out


def make_ledger_writer(path: Union[str, Path]) -> WriterFn:
    """A convenience :data:`WriterFn` bound to a JSONL ledger file, for wiring into
    :func:`require_attestation`."""
    def _writer(att: UsageAttestation) -> None:
        append_attestation(path, att)
    return _writer


__all__: Iterable[str] = (
    "record_usage",
    "require_attestation",
    "AttestationVerdict",
    "verify_ledger",
    "LedgerVerification",
    "ledger_who",
    "ledger_when",
    "append_attestation",
    "read_ledger",
    "make_ledger_writer",
    "WriterFn",
)
