"""
live.spine_vigilcore — the REAL signed-spine binder for ReAct checkpointing (VIGIL-LIVE §12 WS-1f).

The F2 checkpoint layer (:mod:`vigil_integration.agent.checkpoint`) is a pure, framework-free
serialiser: it turns an ``AgentState`` into a content-hashed, signed ``SnapshotRecord`` and rebuilds the
state deterministically from a stream of records — but it holds no key and touches no disk. Every one of
its trust seams (the ``signer``, the signature ``verify`` thunk, the ``writer`` sink, the ``reader``
source) is an INJECTED callable so the whole layer is unit-testable without a live kernel. This module is
the LIVE drop-in for those seams: it binds them to a real Ed25519 keypair (``vigil_core.crypto``) and a
real append-only spine FILE (one canonical-JSON record per line), hash-chained with ``vigil_core.chain``.

Going live changes NOTHING about the sovereign contract. This binder does not make anything true and does
not authorise anything — it is a faithful, tamper-evident *persistence* of state the oracle and gate
already governed. The one guarantee it must never break — the SOVEREIGN INVARIANT the red-pen attacks — is
enforced not here but in the checkpoint layer, and it survives going to a real file byte-for-byte:

  * A ``Finding`` in ``AgentState.facts`` round-trips off the real spine ONLY with its signed
    ``evidence_ref`` intact. An adversary who can write the spine file AND holds the signing key still
    cannot launder an evidence-less "fact": :func:`checkpoint.rebuild_from` re-runs the ``Finding``
    validator and ``_facts_store_is_sound`` on every rebuilt record, so a forged snapshot (however validly
    signed) that smuggles a ``status="fact"`` finding with an empty/whitespace ``evidence_ref`` — under ANY
    status spelling — is SKIPPED and never materialises, in neither ``facts`` nor ``leads``.
  * A torn tail (a partial last line from a crash mid-append) is DROPPED; the good prefix survives and
    rebuild falls back to the last intact snapshot (append-only crash-recovery). This reuses the F2b
    totality on the reader side: a malformed line is degraded to "no signal", never a raise.
  * A TAMPERED record — a bad record signature, a broken hash-chain link (a deleted/reordered line), a
    forged entry, a record whose bytes no longer match the signed digest — is DETECTED and never silently
    trusted: on the rebuild path by the injected :meth:`verify_record`, and on the whole-file audit path by
    :meth:`verify` (the ``vigil_core`` chain + an Ed25519 signature over every chain link). Honest scope
    limit: a bare append-only file cannot by itself distinguish a TAIL truncation (a rollback to an earlier
    state) from "not yet written" — anti-rollback belongs to a signed head high-water mark
    (``vigil_core.sign_head`` / the checkpoint ``head_hash`` threading), out of this binder's scope. A
    rollback only REMOVES records; it can never add an evidence-less fact, so the sovereign fact/evidence
    invariant holds under it regardless.
  * Deterministic + spine-safe: no wallclock, no RNG, no ``uuid`` anywhere on the write/decision path —
    the temporal coordinate is the injected checkpoint ``seq`` and the monotonic ``vigil_core`` chain seq.
    Append-only: a recorded line is never mutated or deleted.
  * Fail-closed / deny-by-default: a malformed keypair, a signer outage, an unreadable/absent file, or a
    non-``str`` argument all degrade to no-signature / no-record / no-rebuild — never a fabricated
    signature, never a silently-persisted unsigned line, never a crash.
  * Secret-free: the private key is held only in process memory to sign; it is NEVER written to the spine,
    an exception message, or a log. Only the public key material ever appears in a persisted signature.

Two Ed25519 signatures are produced per line, with distinct, non-redundant jobs (both via
``vigil_core.crypto.sign``):

  1. the RECORD signature (``SnapshotRecord.signature_ref``, produced by :meth:`signer` inside
     ``checkpoint.serialize``) authenticates the ``AgentState`` snapshot for offline rebuild — this is the
     signature the sovereign rebuild path verifies via :meth:`verify_record`;
  2. the ENTRY signature (over the ``vigil_core`` chain-link ``entry_hash``) authenticates the append-only
     FILE chain itself, so a deletion/reorder cannot be hidden by recomputing the (otherwise unsigned)
     hash links — an attacker without the key cannot re-sign a relinked entry, and :meth:`verify` rejects.

Import-clean: pydantic + stdlib + ``vigil_core`` + the sibling ``agent.checkpoint``/``agent.state`` seam.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterator, Optional

from pydantic import BaseModel, ConfigDict, Field

from vigil_core import ChainEntry, append_entry, digest_payload, sign, verify_one
from vigil_core.chain import verify_chain as vc_verify_chain

from ..agent.checkpoint import (
    GENESIS_PREV,
    SnapshotRecord,
    head_hash,
    rebuild_from,
    serialize,
)
from ..agent.state import AgentState


class SpineWriteError(RuntimeError):
    """A record could NOT be durably signed-and-appended to the spine. Raised (never swallowed) so a
    failed integrity-critical append surfaces to the caller rather than being treated as persisted —
    swallowing it would be fail-OPEN on durability. Its message NEVER contains key material."""


class SpineLine(BaseModel):
    """One persisted line of the append-only spine file: a ``vigil_core`` chain link over a checkpoint
    ``SnapshotRecord``.

    ``seq``/``prev_hash``/``entry_hash`` are the ``vigil_core.ChainEntry`` fields linking this line to the
    previous one at the FILE level (independent of the checkpoint record's own ``prev_hash``). ``cert_digest``
    is the canonical digest of ``record`` — it BINDS the signed chain link to the exact record bytes, so any
    edit to the record forces a new digest, a new ``entry_hash``, and thus a fresh (unforgeable) signature.
    ``signature`` is the Ed25519 signature over ``entry_hash``. ``record`` is the checkpoint
    ``SnapshotRecord`` dump (itself carrying the record-level ``signature_ref``). ``extra='forbid'`` so a
    persisted line carrying an unexpected field is rejected by :meth:`VigilCoreSpine.verify` as tampered."""

    model_config = ConfigDict(extra="forbid")

    seq: int
    prev_hash: str = GENESIS_PREV
    cert_digest: str
    entry_hash: str
    signature: str = ""
    record: dict[str, Any] = Field(default_factory=dict)


def _canonical_line(line: SpineLine) -> str:
    """One spine line as canonical JSON (sorted keys, tight separators) — deterministic, no wallclock/RNG,
    so the same line always serialises to identical bytes."""
    return json.dumps(line.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _coerce_snapshot(row: Any) -> Optional[SnapshotRecord]:
    """Coerce a persisted ``record`` dict into a ``SnapshotRecord``, total: a malformed row → ``None``."""
    if isinstance(row, SnapshotRecord):
        return row
    if isinstance(row, dict):
        try:
            return SnapshotRecord.model_validate(row)
        except Exception:  # noqa: BLE001 — a malformed persisted record is dropped, never fatal
            return None
    return None


class VigilCoreSpine:
    """A real Ed25519-signed, hash-chained, append-only spine file bound to the F2 checkpoint seams.

    Construct with a ``vigil_core.KeyPair`` (or anything exposing ``public_key_b64``/``private_key_b64``)
    and a filesystem ``path``. The four injected-callable seams the checkpoint layer expects are exposed as
    bound methods so they wire directly::

        spine = VigilCoreSpine(keypair, "/var/lib/vigil/eng-a.spine")
        rec   = checkpoint.serialize(state, seq=1, signer=spine.signer)   # record-signed
        spine.writer(rec)                                                 # hash-chained + file-signed
        state = checkpoint.rebuild_from(reader=spine.reader, verify=spine.verify_record)  # offline-verified

    or, ergonomically, via :meth:`write_state` (auto-threads the checkpoint ``prev_hash``) and
    :meth:`rebuild` (wires the reader + record verifier). :meth:`verify` audits the WHOLE file.

    Deny-by-default: a malformed keypair yields an empty key, so :meth:`signer` produces no signature,
    :meth:`verify_record` rejects everything, and :meth:`writer` refuses to persist (fail-closed) — no
    unsigned line is ever written. Single-writer append-only: concurrent writers are out of scope (the
    sovereign spine is a single-writer log); this binder assumes it owns the file."""

    def __init__(self, keypair: Any, path: Any, *, readonly: bool = False) -> None:
        # Extract key material defensively; never log or persist the private key. A missing/short key just
        # means signing/verification will fail-closed (no fabricated signature, no trusted record).
        self._pub = str(getattr(keypair, "public_key_b64", "") or "")
        self._priv = str(getattr(keypair, "private_key_b64", "") or "")
        self._path = os.fspath(path) if hasattr(path, "__fspath__") else str(path)
        self._readonly = bool(readonly)
        # Crash recovery: a torn tail (a partial last line with no trailing newline, from a write that
        # crashed before its fsync completed) is TRUNCATED before any new append. Without this, the next
        # append would glue onto the partial bytes and corrupt the new record — the SIGIL write-repair
        # lesson. A complete ack'd record is always newline-terminated + fsync'd, so a non-newline tail is
        # by definition an un-acknowledged partial write and is safe to drop (append-only: no ack'd record
        # is ever mutated). A ``readonly`` binder (a pure verifier, S5b) NEVER mutates the file it audits —
        # verify()/_read_lines are already torn-tail tolerant (they drop the partial final line), so a
        # read-only audit needs no repair and must not write to a spine it does not own.
        if not self._readonly:
            self._repair_torn_tail()
        # Recover the append point from the (repaired) file, so a restart continues the same chain rather
        # than forking a new genesis.
        self._last_entry, self._last_record_hash = self._load_tail()

    # --- injected-callable seams (bound methods passed straight to the checkpoint layer) --------------

    def signer(self, content_hash: str) -> str:
        """SignerFn for ``checkpoint.serialize``: Ed25519-sign the record's content hash → a base64 sig.

        Fail-closed: a non-``str``/empty hash, a malformed key, or any signing error yields ``""`` — an
        UNSIGNED record, never a fabricated signature and never a crash. The checkpoint layer then persists
        it as ``signature_ref=""``, and :meth:`verify_record` rejects it on rebuild (deny-by-default)."""
        if not isinstance(content_hash, str) or not content_hash:
            return ""
        try:
            return sign(self._priv, content_hash.encode("utf-8"))
        except Exception:  # noqa: BLE001 — a signing outage / bad key → unsigned record, never a crash
            return ""

    def verify_record(self, content_hash: str, signature_ref: str) -> bool:
        """VerifyFn for ``checkpoint.rebuild_from``: True iff ``signature_ref`` is a valid Ed25519 signature
        by our public key over ``content_hash``. Fail-closed: a non-``str``/empty argument, a malformed
        signature (wrong length/base64), a bad key, or any error → ``False`` (the record is rejected)."""
        if not isinstance(content_hash, str) or not isinstance(signature_ref, str) or not signature_ref:
            return False
        try:
            return verify_one(self._pub, content_hash.encode("utf-8"), signature_ref)
        except Exception:  # noqa: BLE001 — malformed material / bad key rejects the record (fail-closed)
            return False

    def writer(self, record: Any) -> None:
        """WriterFn for ``checkpoint.write_checkpoint``: hash-chain ``record`` into the ``vigil_core`` file
        chain, Ed25519-sign the chain link, and durably append it as one canonical-JSON line.

        FAIL-CLOSED on integrity: if the chain link cannot be signed (bad key / signing outage) the append
        is REFUSED with :class:`SpineWriteError` — an unsigned line is never persisted. Append-only: the
        line is appended and ``fsync``'d; nothing existing is mutated. Errors are NOT swallowed (durability
        must surface). The record's own ``signature_ref`` is produced upstream by :meth:`signer`; here we
        add the FILE-chain signature that makes a deletion/reorder unforgeable."""
        if self._readonly:
            raise SpineWriteError("refusing to write: this is a READ-ONLY spine binder (a verifier); it "
                                  "must never mutate a spine it does not own")
        rec = _coerce_snapshot(record)
        if rec is None:
            raise SpineWriteError("refusing to persist a malformed snapshot record (not a SnapshotRecord)")
        record_json = rec.model_dump(mode="json")
        cert_digest = digest_payload(record_json)
        prior = [self._last_entry] if self._last_entry is not None else []
        entry = append_entry(prior, cert_digest)  # vigil_core.chain: monotonic seq + prev_hash linkage
        signature = self._sign_entry(entry.entry_hash)
        if not signature:
            raise SpineWriteError("refusing to persist an unsigned spine append (chain link could not be signed)")
        line = SpineLine(seq=entry.seq, prev_hash=entry.prev_hash, cert_digest=cert_digest,
                         entry_hash=entry.entry_hash, signature=signature, record=record_json)
        self._append_line(line)
        # advance the append point only after a successful durable write
        self._last_entry = entry
        self._last_record_hash = rec.hash

    def reader(self) -> Iterator[dict[str, Any]]:
        """ReaderFn for ``checkpoint.rebuild_from``: yield each persisted ``SnapshotRecord`` (as a dict) in
        append order, torn-tail tolerant. A partial last line (a crash mid-append) is dropped; a malformed
        middle line is skipped. Lenient by design — the sovereign rebuild path re-verifies every record's
        signature via :meth:`verify_record` and re-enforces the fact/evidence invariant, so a forged record
        that slips through here is still rejected there. Total: an absent/unreadable file yields nothing."""
        for obj in self._read_lines():
            rec = obj.get("record")
            if isinstance(rec, dict):
                yield rec

    # --- whole-file audit ----------------------------------------------------------------------------

    def verify(self) -> bool:
        """Audit the WHOLE spine file: is it an intact, Ed25519-signed, append-only ``vigil_core`` chain?

        For each persisted line: its shape is strict (``SpineLine`` with ``extra='forbid'``), the Ed25519
        signature over its ``entry_hash`` verifies by our key, its ``cert_digest`` binds the exact record
        bytes, and the record carries a valid record-level signature. Then the ``vigil_core`` chain must
        link cleanly (``prev_hash`` linkage + ``entry_hash`` recompute + no seq gap) from genesis. Any
        failure — a tampered record, a bad/forged signature, a deleted or reordered line, an unexpected
        field — returns ``False``. Total (never raises); an empty spine is vacuously intact (``True``).

        A tampered record cannot pass: editing the record changes ``cert_digest`` → ``entry_hash`` → the
        (unforgeable) entry signature; deleting/reordering a line breaks the chain linkage; and neither can
        be re-signed without the private key. This is the ``bad sig / broken chain`` detection the sovereign
        invariant requires, on the audit path."""
        try:
            return self._verify_impl()
        except Exception:  # noqa: BLE001 — an audit that cannot complete cannot attest integrity → False
            return False

    def _verify_impl(self) -> bool:
        entries: list[ChainEntry] = []
        for obj in self._read_lines():
            try:
                line = SpineLine.model_validate(obj)
            except Exception:  # noqa: BLE001 — a malformed persisted line cannot be attested → not verified
                return False
            if not self._verify_entry_sig(line.entry_hash, line.signature):
                return False
            if line.cert_digest != digest_payload(line.record):
                return False
            rec = _coerce_snapshot(line.record)
            if rec is None or not self.verify_record(rec.hash, rec.signature_ref):
                return False
            entries.append(ChainEntry(seq=line.seq, prev_hash=line.prev_hash,
                                      cert_digest=line.cert_digest, entry_hash=line.entry_hash))
        ok, _reason = vc_verify_chain(entries)
        return ok

    # --- ergonomic helpers (thin wrappers over the checkpoint layer) ---------------------------------

    def write_state(self, state: AgentState, *, seq: int, engagement: Optional[str] = None) -> SnapshotRecord:
        """Serialise ``state`` (signed by :meth:`signer`), auto-thread the checkpoint ``prev_hash`` from the
        last written record, and durably append it. Returns the record. Fail-closed: a signing/append
        failure raises :class:`SpineWriteError` (via :meth:`writer`); nothing partial is persisted."""
        rec = serialize(state, seq=seq, signer=self.signer,
                        prev_hash=self._last_record_hash, engagement=engagement)
        self.writer(rec)
        return rec

    def rebuild(self, *, engagement: Optional[str] = None) -> AgentState:
        """Reconstruct the current ``AgentState`` from the real spine, offline-verified: reads via
        :meth:`reader` and rejects any unsigned/forged/torn record via :meth:`verify_record`. Total on an
        empty/unreadable spine (a fresh ``AgentState``). Optionally filtered to one ``engagement`` scope."""
        return rebuild_from(reader=self.reader, engagement=engagement, verify=self.verify_record)

    def head_hash(self, *, engagement: Optional[str] = None) -> str:
        """The checkpoint ``hash`` of the latest VALID snapshot on the spine (or ``GENESIS_PREV`` if none) —
        the value the next turn threads into ``serialize(prev_hash=...)``. Verifier-gated and total."""
        return head_hash(self.reader(), engagement=engagement, verify=self.verify_record)

    # --- internals -----------------------------------------------------------------------------------

    def _sign_entry(self, entry_hash: str) -> str:
        """Ed25519-sign the ``vigil_core`` chain-link hash. Fail-closed to ``""`` (a bad key / signing
        outage), which :meth:`writer` maps to a refusal — never a fabricated signature."""
        if not isinstance(entry_hash, str) or not entry_hash:
            return ""
        try:
            return sign(self._priv, entry_hash.encode("utf-8"))
        except Exception:  # noqa: BLE001 — signing outage → no signature → writer refuses (fail-closed)
            return ""

    def _verify_entry_sig(self, entry_hash: str, signature: str) -> bool:
        """True iff ``signature`` is a valid Ed25519 signature by our key over the chain-link ``entry_hash``.
        Fail-closed on malformed material / bad key."""
        if not isinstance(entry_hash, str) or not isinstance(signature, str) or not signature:
            return False
        try:
            return verify_one(self._pub, entry_hash.encode("utf-8"), signature)
        except Exception:  # noqa: BLE001 — malformed material / bad key → reject (fail-closed)
            return False

    def _append_line(self, line: SpineLine) -> None:
        """Durably append one canonical-JSON line (newline-terminated) and ``fsync`` it. Append-only: the
        file is opened in append mode; no existing byte is touched."""
        data = _canonical_line(line)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(data + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _repair_torn_tail(self) -> None:
        """Truncate a crash-torn final line (bytes after the last newline) so the next append lands on a
        clean record boundary. Total: an absent/unreadable file is a no-op. Reads/writes bytes to be exact
        about the trailing newline. Only ever removes an un-acknowledged partial write — never a complete
        (newline-terminated, fsync'd) record."""
        try:
            with open(self._path, "rb") as fh:
                data = fh.read()
        except OSError:
            return
        if not data or data.endswith(b"\n"):
            return  # empty, or the last record is complete — nothing to repair
        keep = data.rfind(b"\n") + 1  # bytes through the last newline (0 if none → drop the whole torn line)
        try:
            with open(self._path, "rb+") as fh:
                fh.truncate(keep)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            return  # a read-only spine cannot be repaired here; the reader/verify paths still drop the tail

    def _read_all(self) -> str:
        """Read the whole spine file, total: an absent/unreadable file yields ``""`` (no records), never a
        crash. The append-only spine is finite by construction."""
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    def _read_lines(self) -> Iterator[dict[str, Any]]:
        """Yield each COMPLETE line as a parsed dict, in append order — torn-tail tolerant (F2b totality).

        A clean append ends every record with ``"\\n"``, so splitting on ``"\\n"`` yields a trailing ``""``
        that is dropped; a crash mid-append leaves a partial final line with no trailing newline, which is
        the last split element and is likewise dropped. A malformed middle line (bad JSON / not an object)
        is skipped. Total: never raises."""
        content = self._read_all()
        if not content:
            return
        parts = content.split("\n")
        # the final element is either "" (clean, trailing newline) or a partial torn line — drop it either way
        for chunk in parts[:-1]:
            if not chunk:
                continue
            try:
                obj = json.loads(chunk)
            except (ValueError, TypeError):
                continue  # a corrupted line is skipped; a resulting chain gap is caught by verify()
            if isinstance(obj, dict):
                yield obj

    def _load_tail(self) -> tuple[Optional[ChainEntry], str]:
        """Recover the append point from an existing file: the last valid chain entry (for ``prev_hash``
        linkage) and the last record's checkpoint hash (for checkpoint ``prev_hash`` threading). Torn-tail
        tolerant; a fresh/absent file yields ``(None, GENESIS_PREV)``."""
        last_entry: Optional[ChainEntry] = None
        last_hash = GENESIS_PREV
        for obj in self._read_lines():
            try:
                line = SpineLine.model_validate(obj)
            except Exception:  # noqa: BLE001 — a malformed line does not advance the append point
                continue
            last_entry = ChainEntry(seq=line.seq, prev_hash=line.prev_hash,
                                    cert_digest=line.cert_digest, entry_hash=line.entry_hash)
            rec_hash = line.record.get("hash")
            if isinstance(rec_hash, str) and rec_hash:
                last_hash = rec_hash
        return last_entry, last_hash
