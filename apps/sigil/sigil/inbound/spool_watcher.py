"""spool_watcher — the SOVEREIGN-side consumer of the inert-finding filesystem seam (VIGIL COMMAND P5b).

It drains ``<spool>/incoming/*.json`` written by the offense producer (``vigil_integration.finding_spool``),
verifies each envelope's anchor-1 signature under an OWNER-SIGNED delegation, and ingests it onto the spine
— from where the cockpit governance feed (``SpineTailer`` → ``/api/stream``) surfaces it automatically.

The boundary invariants (this is the ONE inert seam — treat every byte as hostile):
  * SOVEREIGN OFFENSE-FREE: this module imports NO ``framework`` / ``strix``. Verification is ``vigil_core``
    only (via ``FindingReceiver`` / ``inert_finding``). It never executes or imports offense code.
  * OWNER-TIED, never blind: findings verify under an ``OFFENSE_GOVERNANCE_ROLE`` delegation, detection FACTs
    under an ``OFFENSE_SPINE_ROLE`` delegation — both owner-signed. The needed delegation MUST be configured
    for a kind, else every envelope of that kind is REJECTED (fail-closed).
  * FAIL-CLOSED: any validation / signature / scope / role / IO failure moves the file to ``rejected/`` with
    a ``.reason`` sidecar and appends NOTHING. Only a structurally-valid, owner-anchored, in-scope envelope
    is spined; on success the file moves to ``processed/``.
  * TRUSTED CLOCK: delegation expiry is checked against a LOCAL clock (``int(time.time())``), never anything
    derived from the envelope.
"""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Callable, Optional

from vigil_integration.inert_finding import InertFindingError

from ..spine.store import SpineStore
from .finding_receiver import FindingReceiver

_MAX_BYTES = 256 * 1024  # mirror the validator's envelope cap; a larger file is rejected unread


class SpoolWatcher:
    """Drains an offense→sovereign inert-finding spool onto the owner-signed spine, fail-closed."""

    def __init__(self, store: SpineStore, *, spool_dir: str | os.PathLike, owner_pubkey: str,
                 scope: str = "*", governance_delegation=None, spine_delegation=None,
                 now_fn: Callable[[], int] = lambda: int(time.time())) -> None:
        if not owner_pubkey:
            raise ValueError("owner_pubkey is required — a spool cannot be drained without the owner root")
        self.store = store
        self.owner_pubkey = owner_pubkey
        self.scope = scope
        self.governance_delegation = governance_delegation
        self.spine_delegation = spine_delegation
        self._now = now_fn
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"       # a file is CLAIMED here (out of incoming) before append
        self.processed = self.spool / "processed"   # doubles as the dedup ledger: <name> present ⇒ ingested
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    # -- ingest one file (fail-closed) -------------------------------------------------------------
    def _ingest_text(self, text: str) -> int:
        """Route by kind to an owner-delegated receiver and ingest. Raises InertFindingError on any
        refusal (nothing is written). A missing delegation for the file's kind is itself a refusal."""
        try:
            obj = json.loads(text)
        except ValueError as exc:
            raise InertFindingError(f"not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise InertFindingError("envelope is not a JSON object")
        kind = obj.get("kind")
        now = int(self._now())
        if kind == "detection":
            if self.spine_delegation is None:
                raise InertFindingError("no offense-spine delegation configured — refusing detection FACTs")
            recv = FindingReceiver.from_spine_delegation(
                self.store, owner_pubkey=self.owner_pubkey, delegation=self.spine_delegation,
                now=now, scope=self.scope)
            return recv.ingest_detection(text)
        # a finding (or anything without kind=="detection") goes through the governance path
        if self.governance_delegation is None:
            raise InertFindingError("no offense-governance delegation configured — refusing findings")
        recv = FindingReceiver.from_delegation(
            self.store, owner_pubkey=self.owner_pubkey, delegation=self.governance_delegation,
            now=now, scope=self.scope)
        return recv.ingest(text)

    def _quarantine(self, path: Path, reason: str) -> None:
        dest = self.rejected / path.name
        try:
            os.replace(path, dest)
        except OSError:
            dest = self.rejected / (path.name + ".orphan")
        try:
            (self.rejected / (dest.name + ".reason")).write_text(reason[:2000], encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _read_regular(path: Path) -> str:
        """Read a REGULAR file without following a symlink or blocking on a FIFO. A compromised producer
        that plants a symlink / named pipe / device in the spool must never hang the ingest or make us
        read/follow an arbitrary path. O_NOFOLLOW rejects a symlink at open; O_NONBLOCK returns instead of
        blocking on a writer-less FIFO; then S_ISREG + the size cap reject anything that is not a bounded
        regular file. Raises OSError on any of these (→ the caller quarantines)."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file (symlink/FIFO/device refused)")
            if st.st_size > _MAX_BYTES:
                raise OSError(f"file exceeds {_MAX_BYTES} bytes")
            chunks, remaining = [], _MAX_BYTES + 1
            while remaining > 0:
                b = os.read(fd, remaining)
                if not b:
                    break
                chunks.append(b)
                remaining -= len(b)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if len(data) > _MAX_BYTES:
            raise OSError(f"file exceeds {_MAX_BYTES} bytes")
        return data.decode("utf-8")

    def drain(self) -> dict:
        """Process every file currently in ``incoming/`` once. Returns {ingested, rejected, deduped, seqs}.

        For each file: CLAIM it out of ``incoming/`` (atomic rename into ``working/``) BEFORE anything else,
        so a failed archive or a re-run can never re-read it from ``incoming/`` and double-append. If an
        identical envelope was already ingested (its content-named marker exists in ``processed/``), the
        claimed copy is a re-spool and is archived WITHOUT re-appending (idempotent). Otherwise read it as a
        bounded regular file, ingest, and archive to ``processed/<name>`` (the dedup marker). ANY failure →
        ``rejected/``, nothing appended. Never raises on one bad file; never blocks on a hostile one."""
        ingested, rejected, deduped, seqs = 0, 0, 0, []
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue  # a producer's in-flight temp; skip until it is atomically renamed in
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)   # atomic CLAIM: the file leaves incoming/ before we act on it
            except OSError:
                continue                    # gone / raced away — nothing to do
            marker = self.processed / src.name
            if marker.exists():
                # a byte-identical envelope already crossed onto the spine — do NOT re-append (idempotent)
                try:
                    os.replace(claimed, marker)   # archive the duplicate over its identical marker
                except OSError:
                    self._safe_unlink(claimed)
                deduped += 1
                continue
            try:
                text = self._read_regular(claimed)
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular file: {exc}")
                rejected += 1
                continue
            try:
                seq = self._ingest_text(text)
            except InertFindingError as exc:
                self._quarantine(claimed, f"rejected (fail-closed): {exc}")
                rejected += 1
                continue
            except Exception as exc:  # noqa: BLE001 — any unexpected error is still a refusal, never an append
                self._quarantine(claimed, f"rejected (unexpected {type(exc).__name__}): {exc}")
                rejected += 1
                continue
            # appended. Archive to the dedup marker. If this fails the record is already spined AND the file
            # is in working/ (NOT incoming/), so it is never re-drained → no double-ingest either way.
            try:
                os.replace(claimed, marker)
            except OSError:
                self._safe_unlink(claimed)
            ingested += 1
            seqs.append(seq)
        return {"ingested": ingested, "rejected": rejected, "deduped": deduped, "seqs": seqs}

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def watch(self, *, interval: float = 2.0, stop: Optional["object"] = None) -> None:
        """Drain in a loop until ``stop`` (a threading.Event) is set. Each round is a fresh ``drain()``
        (delegations are re-verified against the current clock, so an expired delegation stops admitting)."""
        while True:
            self.drain()
            if stop is not None and getattr(stop, "wait", None) is not None:
                if stop.wait(interval):
                    return
            else:
                time.sleep(interval)
