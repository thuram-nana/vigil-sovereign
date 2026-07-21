"""
agent.checkpoint — spine-snapshot checkpointing of the ReAct ``AgentState`` (VIGIL-FUSION F2, §5 C1).

redamon's orchestrator persists the mutable ``AgentState`` across turns with a LangGraph ``MemorySaver``
or ``AsyncPostgresSaver`` — a MUTABLE, un-provable store the LLM's run reads and writes freely. VIGIL
forbids that trust model. This module replaces the checkpointer with an **append-only signed spine
snapshot**: each turn serialises the whole ``AgentState`` into a typed, content-hashed, signed record,
and the run is rebuilt deterministically by replaying those records from the spine. Nothing here makes
anything true — it is a faithful *serialisation* of state that the oracle/gate already governed.

The one guarantee this module must never break — the SOVEREIGN INVARIANT the red-pen attacks — is:

  * A ``Finding`` in ``AgentState.facts`` survives serialise → rebuild **only with its signed
    ``evidence_ref`` intact**. A fact can NEVER be reconstructed without its evidence reference, and a
    lead can NEVER be upgraded into the facts store. This is not enforced by trust here. On every rebuilt
    record ``_load_state`` runs TWO checks: the ``Finding`` model validator (``_fact_needs_evidence``),
    AND a facts-store soundness re-check (``_facts_store_is_sound``) that every member of
    ``AgentState.facts`` is a genuine fact — ``status`` **exactly** ``"fact"`` with a non-empty/whitespace
    ``evidence_ref``. The soundness re-check is load-bearing because the type validator only fires on the
    exact string ``self.status == "fact"``: a snapshot whose ``state_json`` smuggles a case/whitespace
    status variant (``"Fact"``/``"FACT"``/``"fact "``/``" fact"``) or a non-fact status
    (``"lead"``/``"confirmed"``) with an empty ``evidence_ref`` into ``facts[]`` slips past the validator
    but FAILS the soundness re-check, so the WHOLE record is skipped and the forged/laundered fact is never
    rebuilt. A genuine round-tripped fact always serialises as ``status="fact"`` with a signed evidence
    ref, so the strict check never rejects a legitimate snapshot. A lead rebuilds as a lead.

Design rules (all load-bearing):

  * **Injected callables, no live kernel.** The signer, the spine writer, the spine reader, and an
    optional signature verifier are all passed in as thunks, so the whole module is testable without a
    framework. In production the signer wraps the SIGIL signed-head signer and the writer/reader wrap the
    single-writer append-only spine; a Postgres/in-memory cache is OUT OF SCOPE here — it is only ever a
    rebuildable cache, and the spine is the source of truth (see §5 C1).
  * **Deterministic + spine-safe.** No wallclock, no RNG, no ``uuid`` — the temporal coordinate is the
    INJECTED ``seq``. The content hash is a pure function of ``(seq, engagement, prev_hash, state_json)``
    over canonical JSON, so the same state at the same seq yields a byte-identical record, and rebuild is
    a pure function of its input (latest valid snapshot wins under a total ``(seq, hash)`` order).
  * **Append-only.** A snapshot is never mutated or deleted; a later turn appends a new record whose
    ``prev_hash`` chains to the previous one. Rebuild reads; it never rewrites.
  * **Fail-closed / total / deny-by-default.** The record list handed to rebuild comes off the spine and
    is attacker-influenceable (torn tails, forged rows, a lossy loader's ``None``s). Every public function
    degrades a malformed input to "no signal" (a skipped record / a fresh empty ``AgentState``) and never
    raises. No signer wired or a signer error → an UNSIGNED record (``signature_ref=""``), never a crash;
    with a verifier wired at rebuild, an unsigned/forged record is skipped. Verification is NOT optional on
    the read path: ``rebuild``/``rebuild_from`` refuse to reconstruct any state unless a ``verify`` thunk is
    wired, OR the caller EXPLICITLY opts into trusting an unauthenticated spine with
    ``trust_unverified=True``. With neither, rebuild returns a fresh empty ``AgentState`` (no gate wired →
    never a fact) — the read path is as fail-closed as the write path, which forces ``signer``. Production
    rebuild MUST wire a verifier; ``trust_unverified`` exists only for tests and a caller that has already
    authenticated the record source out of band.
  * **Secret-free.** The snapshot serialises ``AgentState``, whose fields are already
    oracle/gate-governed and redacted upstream (F3 ``redact_tool_args`` scrubs tool args before they land
    in the trace); this module adds no new secret sink — it hashes and signs, it does not log payloads.

Import-clean: pydantic + stdlib + ``.state`` only (no ``framework.*``/``strix.*``/network/``vigil_core``).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Iterator, Optional

from pydantic import BaseModel

from .state import AgentState

# The ``prev_hash`` of the first (genesis) snapshot in an engagement's chain.
GENESIS_PREV = ""

# --- injected-callable contracts (thunks; nothing here holds a live key/socket) ---------------------
#
# signer(content_hash)         -> a signature reference (signed-head hash / cert id); "" ⇒ unsigned.
#                                 Fail-closed: a None signer / an exception / a non-str-or-empty return
#                                 all produce an UNSIGNED record (never a crash, never a fake signature).
# verify(content_hash, sig_ref) -> True iff the signature is valid for the (recomputed) content hash.
#                                 Injected at rebuild to reject unsigned/forged records; fail-closed.
# writer(record)               -> append the signed record to the single-writer append-only spine.
# reader()                     -> yield the engagement's snapshot records back (any iterable / dicts ok).
SignerFn = Callable[[str], Any]
VerifyFn = Callable[[str, str], Any]
WriterFn = Callable[["SnapshotRecord"], Any]
ReaderFn = Callable[[], Any]


class SnapshotRecord(BaseModel):
    """One append-only spine snapshot of the whole ``AgentState`` at a single turn.

    ``hash`` is the content hash over ``(seq, engagement, prev_hash, state_json)`` (canonical JSON, sha256)
    — it is recomputed on rebuild and a mismatch means a torn/tampered record. ``signature_ref`` is what
    the injected signer returned over that hash (``""`` ⇒ unsigned). ``prev_hash`` chains this record to
    the previous snapshot so the whole run is an append-only, offline-verifiable chain. ``state_json`` is
    the canonical serialisation of ``AgentState`` — the fact/lead split and each ``Finding``'s
    evidence-ref invariant are re-validated when it is deserialised, never trusted from the record."""

    seq: int
    hash: str
    engagement: str = ""
    state_json: str = ""
    prev_hash: str = GENESIS_PREV
    signature_ref: str = ""


# --- canonical, deterministic hashing (no wallclock / RNG) ------------------------------------------


def _canonical(obj: Any) -> str:
    """Canonical JSON: sorted keys, tight separators, unicode preserved. ``default=str`` is a totality
    net so an exotic ``Any`` value in the trace can never crash serialisation (it is not expected to
    fire — the trace/leads originate as parsed JSON — but a snapshot must never be a denial-of-cognition)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _content_hash(seq: int, engagement: str, prev_hash: str, state_json: str) -> str:
    """The record identity: a pure hash of the signed content. Excludes ``signature_ref`` (the signature
    is *over* this hash, so it cannot be part of it). Deterministic — the same inputs always hash equal."""
    return _sha256_hex(_canonical({
        "seq": seq,
        "engagement": engagement,
        "prev_hash": prev_hash,
        "state_json": state_json,
    }))


def _as_int(value: Any) -> int:
    """Coerce the injected seq to an int, total. The seq is the caller's trusted deterministic sequence;
    a non-int is coerced (bool excluded — ``True`` is not a sequence number) and falls back to 0."""
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _dump_state(state: Any) -> str:
    """Serialise ``state`` to canonical JSON, total. A real ``AgentState`` dumps directly; anything else
    is validated through ``AgentState`` first (so it obeys the same type invariants). On any failure the
    snapshot degrades to the empty state — a state that cannot be validated/serialised must not be
    persisted as if it were trusted, and must not crash the loop."""
    try:
        obj = state if isinstance(state, AgentState) else AgentState.model_validate(state)
        return _canonical(obj.model_dump(mode="json"))
    except Exception:  # noqa: BLE001 — a non-serialisable/invalid state degrades to empty, never crashes
        return _canonical(AgentState().model_dump(mode="json"))


def _sign(signer: Optional[SignerFn], content_hash: str) -> str:
    """Invoke the injected signer, fail-closed. No signer, a signer exception, or a non-str/empty return
    all yield ``""`` (an UNSIGNED record) — never a fabricated signature, never a raised exception."""
    if signer is None:
        return ""
    try:
        ref = signer(content_hash)
    except Exception:  # noqa: BLE001 — a signer outage yields an unsigned record, never a crash
        return ""
    return ref if isinstance(ref, str) and ref.strip() else ""


def serialize(
    state: AgentState,
    *,
    seq: int,
    signer: Optional[SignerFn],
    prev_hash: str = GENESIS_PREV,
    engagement: Optional[str] = None,
) -> SnapshotRecord:
    """Serialise ``state`` into an append-only, content-hashed, signed ``SnapshotRecord`` for turn ``seq``.

    Deterministic and total: ``seq`` is the injected temporal coordinate (no wallclock/RNG), the content
    hash is a pure function of the state, and any serialisation problem degrades to an empty-state snapshot
    rather than raising. The signer is injected and fail-closed — a missing/erroring signer produces an
    UNSIGNED record (``signature_ref=""``) so the append-only chain is never broken by a signer outage;
    rebuild's optional verifier is where an unsigned/forged record is rejected. ``engagement`` defaults to
    the state's own slug, keeping snapshots namespaced to their charter scope (no cross-engagement mixing)."""
    slug = engagement if isinstance(engagement, str) else str(getattr(state, "engagement_slug", "") or "")
    prev = prev_hash if isinstance(prev_hash, str) else GENESIS_PREV
    n = _as_int(seq)
    state_json = _dump_state(state)
    content_hash = _content_hash(n, slug, prev, state_json)
    signature_ref = _sign(signer, content_hash)
    return SnapshotRecord(seq=n, hash=content_hash, engagement=slug, state_json=state_json,
                          prev_hash=prev, signature_ref=signature_ref)


def write_checkpoint(
    state: AgentState,
    *,
    seq: int,
    signer: Optional[SignerFn],
    writer: Optional[WriterFn],
    prev_hash: str = GENESIS_PREV,
    engagement: Optional[str] = None,
) -> SnapshotRecord:
    """Serialise the turn and append it to the spine via the injected single-writer ``writer``.

    Returns the record (whose ``hash`` the caller threads into the next turn's ``prev_hash`` — see
    :func:`head_hash`). Serialisation is total; the writer is an infrastructure sink and its errors are
    NOT swallowed — a failed durable append must surface to the caller rather than be silently treated as
    persisted (swallowing it would be fail-open on durability). With ``writer=None`` the record is returned
    without being written (the caller owns persistence)."""
    record = serialize(state, seq=seq, signer=signer, prev_hash=prev_hash, engagement=engagement)
    if writer is not None:
        writer(record)
    return record


# --- deterministic, total rebuild -------------------------------------------------------------------


def _as_snapshot(row: Any) -> Optional[SnapshotRecord]:
    """Coerce one spine row into a ``SnapshotRecord``, total. A ``SnapshotRecord`` passes through; a dict
    (a JSON-spine read) is validated; anything else (``None``, a torn string, an int) is dropped."""
    if isinstance(row, SnapshotRecord):
        return row
    if isinstance(row, dict):
        try:
            return SnapshotRecord.model_validate(row)
        except Exception:  # noqa: BLE001 — a malformed row is skipped, not fatal
            return None
    return None


def _iter_snapshots(records: Any) -> Iterator[SnapshotRecord]:
    """Yield the coercible snapshots from a (possibly garbage/None/LAZY) record source, skipping the rest.
    The ENTIRE iteration surface is guarded — the truthiness check, obtaining the iterator, AND advancing
    it — so a custom-iterable reader whose ``__bool__``/``__len__``/``__iter__``/``__next__`` raises ANY
    exception (a lazy file-backed reader that fails to open the spine in ``__iter__`` with an ``OSError``,
    a torn-tail ``JSONDecodeError`` — a ``ValueError`` — at ``next()``) stops the walk at the last good
    record (append-only torn-tail semantics) and NEVER propagates. Total: every consumer (rebuild /
    rebuild_from / head_hash / verify_chain) funnels through here, so none can crash on a raising reader.
    The reader is assumed FINITE (the append-only spine is finite by construction; latest-wins / full
    audit reads the whole finite chain)."""
    try:
        if not records:            # __bool__/__len__ may raise on a custom iterable
            return
        it = iter(records)         # __iter__ may raise (e.g. a lazy reader that opens the spine here)
    except Exception:  # noqa: BLE001 — non-iterable / a reader whose __bool__/__iter__ raised → no signal
        return
    while True:
        try:
            row = next(it)
        except StopIteration:
            return
        except Exception:  # noqa: BLE001 — a lazy reader raised (torn tail) → keep the good prefix, stop
            return
        rec = _as_snapshot(row)
        if rec is not None:
            yield rec


def _verify_sig(verify: VerifyFn, content_hash: str, signature_ref: str) -> bool:
    """Run the injected signature verifier, fail-closed — any non-``True`` return or exception rejects."""
    try:
        return verify(content_hash, signature_ref) is True
    except Exception:  # noqa: BLE001 — a verifier error rejects the record (fail-closed)
        return False


def _facts_store_is_sound(state: AgentState) -> bool:
    """The ``facts`` store is oracle-confirmed ground truth — downstream consumers treat membership as
    proof. Every member MUST be a GENUINE fact: ``status`` exactly ``"fact"`` AND a non-empty/whitespace
    ``evidence_ref``. This is the class-level guard the ``Finding`` type validator cannot provide: that
    validator only fires on the exact string ``self.status == "fact"``, so a case/whitespace status variant
    (``"Fact"``/``"FACT"``/``"fact "``) or a non-fact status (``"lead"``/``"confirmed"``) with an empty
    evidence ref slips past it into ``facts[]``. Here we re-check STORE MEMBERSHIP, not the literal, so no
    status spelling can launder an evidence-less finding into the facts store. Total: any member that is
    not exactly a signed fact makes the whole store unsound → the record is rejected upstream."""
    for f in state.facts:
        if f.status != "fact" or not (f.evidence_ref or "").strip():
            return False
    return True


def _load_state(state_json: str) -> Optional[AgentState]:
    """Deserialise ``state_json`` back into an ``AgentState``, total and INVARIANT-ENFORCING.

    This is the load-bearing line of the whole module. It enforces the sovereign invariant with TWO gates,
    because the ``Finding`` type validator alone is not enough:

      1. ``AgentState.model_validate`` runs the ``Finding`` model validator on every rebuilt finding, so a
         record carrying an exact-``status="fact"`` finding with an empty/whitespace ``evidence_ref`` RAISES
         and the record is skipped.
      2. ``_facts_store_is_sound`` then re-checks that EVERY member of ``AgentState.facts`` is a genuine
         fact (status exactly ``"fact"`` + non-empty evidence). This catches what gate 1 misses: a
         case/whitespace status variant (``"Fact"``/``"fact "``) or a non-fact status (``"lead"``) with an
         empty evidence ref, smuggled into ``facts[]`` — the validator's exact-string match lets those
         through, but they are not genuine facts, so the whole record is rejected.

    A fact can never be rebuilt without its signed evidence reference, and a lead can never be upgraded into
    the facts store, regardless of status spelling. Torn JSON, a non-object payload, or any validation
    failure all return ``None`` (the record is skipped), never an exception."""
    try:
        data = json.loads(state_json)
    except (ValueError, TypeError, RecursionError):
        # RecursionError (a RuntimeError, not a ValueError) fires on deeply-nested JSON — a single torn
        # spine row must SKIP the record, never crash the whole rebuild (fail-closed).
        return None
    if not isinstance(data, dict):
        return None
    try:
        state = AgentState.model_validate(data)
        if not _facts_store_is_sound(state):
            return None
        # normalise the leads store: a lead is DEFINITIONALLY unproven, so force every leads member back
        # to status="lead"/no-evidence (mirror AgentState.record_lead). A genuine round-trip is a no-op;
        # a forged status="fact" smuggled into leads[] is neutralised so a downstream consumer that trusts
        # lead.status can never be misled (it never entered facts[], but must not masquerade as a fact).
        for lead in state.leads:
            lead.status = "lead"
            lead.evidence_ref = ""
        return state
    except Exception:  # noqa: BLE001 — any invalid/forged state (incl. an evidence-less fact) is skipped
        return None


def _is_intact(rec: SnapshotRecord, verify: Optional[VerifyFn]) -> bool:
    """A record is usable iff its content hash recomputes to its stored ``hash`` (untorn/untampered) and,
    when a verifier is wired, its signature verifies over that hash (unsigned/forged records rejected)."""
    if _content_hash(rec.seq, rec.engagement, rec.prev_hash, rec.state_json) != rec.hash:
        return False
    if verify is not None and not _verify_sig(verify, rec.hash, rec.signature_ref):
        return False
    return True


def rebuild(
    records: Any,
    *,
    engagement: Optional[str] = None,
    verify: Optional[VerifyFn] = None,
    trust_unverified: bool = False,
) -> AgentState:
    """Rebuild the current ``AgentState`` from a list of spine snapshot records — deterministic and total.

    DENY-BY-DEFAULT: verification is NOT optional on the read path. If no ``verify`` thunk is wired and the
    caller has not EXPLICITLY set ``trust_unverified=True``, rebuild refuses to reconstruct any state and
    returns a fresh empty ``AgentState`` (no gate wired → never a fact). This mirrors the write path, where
    ``serialize``/``write_checkpoint`` force ``signer`` as a required kwarg: a caller can no longer silently
    rebuild forged facts off an unauthenticated spine. Production MUST wire ``verify``; ``trust_unverified``
    exists only for tests and callers that authenticated the record source out of band.

    Semantics: each snapshot is a FULL state, so the latest valid snapshot is the current state. Records
    are filtered to the valid set — a coercible ``SnapshotRecord``, whose content hash recomputes
    (untorn), whose signature verifies (if a verifier is wired), and whose ``state_json`` deserialises
    into a valid ``AgentState`` (the ``Finding`` validator + ``_facts_store_is_sound`` enforce the
    sovereign invariant) — and the highest ``(seq, hash)`` survivor wins. This is order-independent (a
    total key), so any permutation of the same records rebuilds a byte-identical state; it is
    append-only-safe (a torn tail is skipped and the last good snapshot is used, i.e. crash-recovery
    truncation); and it is total (a garbage/None list yields a fresh empty ``AgentState``, never a crash).
    ``engagement`` filters to one charter scope so a mixed spine can never contaminate one run's rebuild
    with another's snapshots."""
    if verify is None and not trust_unverified:
        return AgentState()  # deny-by-default: no verifier wired and no explicit opt-out → no signal
    best_key: Optional[tuple[int, str]] = None
    best_state: Optional[AgentState] = None
    for rec in _iter_snapshots(records):
        if engagement is not None and rec.engagement != engagement:
            continue
        if not _is_intact(rec, verify):
            continue
        state = _load_state(rec.state_json)
        if state is None:
            continue
        key = (rec.seq, rec.hash)
        if best_key is None or key > best_key:
            best_key, best_state = key, state
    return best_state if best_state is not None else AgentState()


def rebuild_from(
    reader: Optional[ReaderFn],
    *,
    engagement: Optional[str] = None,
    verify: Optional[VerifyFn] = None,
    trust_unverified: bool = False,
) -> AgentState:
    """Read the engagement's snapshots via the injected ``reader`` and rebuild — total on a reader outage.

    A ``None`` reader, a reader exception, a ``None`` result, or a non-iterable result all degrade to a
    fresh empty ``AgentState`` (fail-closed: an unreadable spine yields no state, never a crash). Inherits
    :func:`rebuild`'s DENY-BY-DEFAULT posture: ``verify``/``trust_unverified`` are threaded through, so
    without a verifier and without an explicit opt-out no state is ever reconstructed."""
    if reader is None:
        return AgentState()
    try:
        records = reader()
    except Exception:  # noqa: BLE001 — a spine-read outage yields the empty state, never a crash
        return AgentState()
    if records is None:
        return AgentState()
    return rebuild(records, engagement=engagement, verify=verify, trust_unverified=trust_unverified)


def head_hash(
    records: Any,
    *,
    engagement: Optional[str] = None,
    verify: Optional[VerifyFn] = None,
) -> str:
    """The ``hash`` of the latest VALID snapshot (or ``GENESIS_PREV`` if none) — thread it into the next
    turn's ``serialize(prev_hash=...)`` so the chain stays contiguous. Same validity/order rules as
    :func:`rebuild`; total (never raises)."""
    best_key: Optional[tuple[int, str]] = None
    best_hash = GENESIS_PREV
    for rec in _iter_snapshots(records):
        if engagement is not None and rec.engagement != engagement:
            continue
        if not _is_intact(rec, verify):
            continue
        key = (rec.seq, rec.hash)
        if best_key is None or key > best_key:
            best_key, best_hash = key, rec.hash
    return best_hash


def verify_chain(records: Any, *, engagement: Optional[str] = None) -> bool:
    """Audit helper: are the coercible snapshots a consistent, append-only ``prev_hash`` chain?

    Sorts the (optionally engagement-filtered) valid-shaped snapshots by ``(seq, hash)`` and checks that
    each record's content hash recomputes and that its ``prev_hash`` links to the previous record's hash
    (the first must be ``GENESIS_PREV``). This is a STRICT contiguity check for auditors — unlike
    :func:`rebuild` it does not tolerate gaps — so a fork, a rollback, or a tampered record returns
    ``False``. Total (never raises); an empty chain is vacuously consistent (``True``)."""
    recs = sorted(_iter_snapshots(records),
                  key=lambda r: (r.seq, r.hash)) if records is not None else []
    prev = GENESIS_PREV
    for rec in recs:
        if engagement is not None and rec.engagement != engagement:
            continue
        if _content_hash(rec.seq, rec.engagement, rec.prev_hash, rec.state_json) != rec.hash:
            return False
        if rec.prev_hash != prev:
            return False
        prev = rec.hash
    return True
